//go:build !js

package tailcat

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	webtransport "github.com/quic-go/webtransport-go"
	"github.com/quic-go/quic-go/http3"
	"tailscale.com/types/key"
)

const (
	// masqueBrowserWebTransportPath is appended to the configured relay base
	// path by the browser client. A relay URL with a prefix such as
	// https://example.com/masquecat therefore uses
	// /masquecat/.well-known/masquecat/webtransport.
	masqueBrowserWebTransportPath = "/.well-known/masquecat/webtransport"
	masqueBrowserControlMax       = 8 << 10
	masqueBrowserAuthTimeout      = 15 * time.Second
	masqueBrowserProtocolVersion  = 1
)

type masqueBrowserControl struct {
	Type      string `json:"type"`
	Version   int    `json:"version,omitempty"`
	Source    string `json:"source,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	Verifier  string `json:"verifier,omitempty"`
	Proof     string `json:"proof,omitempty"`
	Error     string `json:"error,omitempty"`
}

func readMasqueBrowserControl(r *bufio.Reader) (masqueBrowserControl, error) {
	var msg masqueBrowserControl
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return msg, errors.New("masquecat: browser control message too large")
	}
	if err != nil {
		return msg, err
	}
	if len(line) > masqueBrowserControlMax {
		return msg, errors.New("masquecat: browser control message too large")
	}
	if err := json.Unmarshal(bytes.TrimSpace(line), &msg); err != nil {
		return msg, fmt.Errorf("masquecat: decode browser control message: %w", err)
	}
	return msg, nil
}

func writeMasqueBrowserControl(w *bufio.Writer, msg masqueBrowserControl) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(b)+1 > masqueBrowserControlMax {
		return errors.New("masquecat: browser control message too large")
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	if err := w.WriteByte('\n'); err != nil {
		return err
	}
	return w.Flush()
}

type browserWebTransportForwarder struct {
	session *webtransport.Session
	mu      sync.Mutex
}

func (f *browserWebTransportForwarder) ForwardPacket(src, dst key.NodePublic, payload []byte) error {
	if bytes.HasPrefix(payload, discoMagicBytes) {
		return nil
	}
	packet := encodeMasquePacket(src, dst, payload)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.session.SendDatagram(packet)
}

func (*browserWebTransportForwarder) String() string { return "masquecat-webtransport" }

func (r *MasqueRelay) serveBrowserWebTransport(w http.ResponseWriter, req *http.Request, wt *webtransport.Server) {
	logf := r.logf()
	session, err := wt.Upgrade(w, req)
	if err != nil {
		logf("upgrade browser WebTransport: %v", err)
		return
	}
	defer func() { _ = session.CloseWithError(0, "") }()

	authCtx, cancel := context.WithTimeout(session.Context(), masqueBrowserAuthTimeout)
	defer cancel()
	stream, err := session.AcceptStream(authCtx)
	if err != nil {
		logf("accept browser WebTransport control stream: %v", err)
		return
	}
	defer func() { _ = stream.Close() }()
	br := bufio.NewReaderSize(stream, masqueBrowserControlMax)
	bw := bufio.NewWriterSize(stream, 1024)

	hello, err := readMasqueBrowserControl(br)
	if err != nil || hello.Type != "hello" || hello.Version != masqueBrowserProtocolVersion {
		_ = writeMasqueBrowserControl(bw, masqueBrowserControl{Type: "error", Error: "invalid MasqueCat browser hello"})
		return
	}
	var src key.NodePublic
	if err := src.UnmarshalText([]byte(hello.Source)); err != nil || src.IsZero() {
		_ = writeMasqueBrowserControl(bw, masqueBrowserControl{Type: "error", Error: "invalid MasqueCat node identity"})
		return
	}

	auth := r.authenticator()
	challenge, err := auth.issue(src, src, masqueModeRelay, session.RemoteAddr().String())
	if err != nil {
		_ = writeMasqueBrowserControl(bw, masqueBrowserControl{Type: "error", Error: "failed to issue MasqueCat authentication challenge"})
		return
	}
	if err := writeMasqueBrowserControl(bw, masqueBrowserControl{
		Type:      "challenge",
		Challenge: challenge,
		Verifier:  auth.priv.Public().String(),
	}); err != nil {
		return
	}

	proof, err := readMasqueBrowserControl(br)
	if err != nil || proof.Type != "proof" || !auth.verify(proof.Proof, src, src, masqueModeRelay) {
		_ = writeMasqueBrowserControl(bw, masqueBrowserControl{Type: "error", Error: "MasqueCat node-key proof rejected"})
		return
	}

	peer, ok := r.reserve(src)
	if !ok {
		_ = writeMasqueBrowserControl(bw, masqueBrowserControl{Type: "error", Error: "MasqueCat peer is already registered"})
		return
	}
	defer r.unregister(peer)
	fwd := &browserWebTransportForwarder{session: session}
	if !r.activate(peer, fwd) {
		return
	}
	if err := writeMasqueBrowserControl(bw, masqueBrowserControl{Type: "ready", Version: masqueBrowserProtocolVersion}); err != nil {
		return
	}
	logf("MasqueCat browser peer registered over WebTransport: %v", src.ShortString())

	for {
		b, err := session.ReceiveDatagram(session.Context())
		if err != nil {
			if session.Context().Err() == nil {
				logf("MasqueCat browser peer %v closed: %v", src.ShortString(), err)
			}
			return
		}
		pkt, err := decodeMasquePacket(b)
		if err != nil {
			logf("dropping malformed browser MasqueCat datagram: %v", err)
			continue
		}
		if pkt.src != src {
			logf("dropping browser MasqueCat datagram with spoofed source %v", pkt.src.ShortString())
			continue
		}
		if bytes.HasPrefix(pkt.payload, discoMagicBytes) {
			continue
		}
		dst := r.lookup(pkt.dst)
		if dst == nil {
			continue
		}
		if err := dst.fwd.ForwardPacket(pkt.src, pkt.dst, pkt.payload); err != nil {
			logf("browser relay %v -> %v: %v", pkt.src.ShortString(), pkt.dst.ShortString(), err)
		}
	}
}

func sameOriginBrowserRequest(req *http.Request) bool {
	origin := req.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, req.Host)
}

func browserOriginChecker(allowedOrigin string) func(*http.Request) bool {
	allowedOrigin = strings.TrimSuffix(strings.TrimSpace(allowedOrigin), "/")
	return func(req *http.Request) bool {
		if allowedOrigin == "" {
			return sameOriginBrowserRequest(req)
		}
		if allowedOrigin == "*" {
			return true
		}
		return strings.TrimSuffix(req.Header.Get("Origin"), "/") == allowedOrigin
	}
}

func isMasqueBrowserWebTransportPath(path string) bool {
	return strings.HasSuffix(strings.TrimSuffix(path, "/"), masqueBrowserWebTransportPath)
}

// ServeMasqueRelay serves native MasqueCat peers over CONNECT-UDP (HTTP/3 with
// HTTP/2 fallback) and browser peers over WebTransport on the same UDP/TCP port.
// allowedBrowserOrigin is the exact Origin permitted for cross-origin browser
// sessions. An empty value keeps same-origin protection; "*" explicitly allows
// any origin. Node-key challenge/response authentication is still required for
// every WebTransport registration.
func ServeMasqueRelay(addr string, tlsConfig *tls.Config, relay *MasqueRelay, allowedBrowserOrigin string) error {
	if relay == nil {
		return errors.New("masquecat: nil relay")
	}
	if !hasMasqueServerCertificate(tlsConfig) {
		return errors.New("MASQUE relay requires a TLS certificate")
	}

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("listen for HTTP/3 MASQUE relay: %w", err)
	}
	defer func() { _ = pc.Close() }()

	h2Addr, err := masqueHTTP2CompanionAddr(addr, pc.LocalAddr())
	if err != nil {
		return fmt.Errorf("derive HTTP/2 MASQUE relay listen address: %w", err)
	}
	legacyHandler := relay.Handler()
	h2, err := newMasqueHTTP2Server(tlsConfig, legacyHandler)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", h2Addr)
	if err != nil {
		return fmt.Errorf("listen for HTTP/2 MASQUE relay: %w", err)
	}
	defer func() { _ = ln.Close() }()

	h3TLS := http3.ConfigureTLSConfig(tlsConfig.Clone())
	h3TLS.MinVersion = tls.VersionTLS13
	h3 := &http3.Server{TLSConfig: h3TLS}
	wt := &webtransport.Server{
		H3:          h3,
		CheckOrigin: browserOriginChecker(allowedBrowserOrigin),
	}
	webtransport.ConfigureHTTP3Server(h3)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if isMasqueBrowserWebTransportPath(req.URL.Path) {
			relay.serveBrowserWebTransport(w, req, wt)
			return
		}
		legacyHandler.ServeHTTP(w, req)
	})
	h3.Handler = mux

	defer func() { _ = wt.Close() }()
	defer func() { _ = h2.Close() }()

	errCh := make(chan error, 2)
	go func() { errCh <- wt.Serve(pc) }()
	go func() { errCh <- h2.Serve(tls.NewListener(ln, h2.TLSConfig)) }()
	err = <-errCh
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
