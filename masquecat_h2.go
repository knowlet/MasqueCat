//go:build !js

package tailcat

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
	_ "unsafe"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	masqueConnectUDPProtocol = "connect-udp"
	masqueDatagramCapsule    = uint64(0)
	maxMasqueCapsuleSize     = 64 << 10
)

// x/net/http2 has full RFC 8441 Extended CONNECT support, but currently keeps
// it behind GODEBUG=http2xconnect=1 because enabling it for arbitrary HTTP
// servers can change WebSocket behavior. MasqueCat owns the HTTP/2 servers it
// creates and needs Extended CONNECT unconditionally for RFC 9298.
//
// Keep this workaround isolated here so it can be deleted as soon as x/net
// exposes a per-server switch. It affects only x/net/http2, not net/http's
// bundled HTTP/2 implementation.
//go:linkname http2DisableExtendedConnectProtocol golang.org/x/net/http2.disableExtendedConnectProtocol
var http2DisableExtendedConnectProtocol bool

var masqueH2ExtendedConnectOnce sync.Once

func enableMasqueH2ExtendedConnect() {
	masqueH2ExtendedConnectOnce.Do(func() {
		http2DisableExtendedConnectProtocol = false
	})
}

type masqueCapsuleStream struct {
	r io.ReadCloser
	w io.Writer

	closeWriter func() error
	flush       func()

	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

func (s *masqueCapsuleStream) Read(p []byte) (int, error) {
	return s.r.Read(p)
}

func (s *masqueCapsuleStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	n, err := s.w.Write(p)
	if err == nil && s.flush != nil {
		s.flush()
	}
	return n, err
}

func (s *masqueCapsuleStream) Close() error {
	s.closeOnce.Do(func() {
		var errs []error
		if s.closeWriter != nil {
			errs = append(errs, s.closeWriter())
		}
		if s.r != nil {
			errs = append(errs, s.r.Close())
		}
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

func (s *masqueCapsuleStream) SendDatagram(b []byte) error {
	frame := quicvarint.Append(nil, masqueDatagramCapsule)
	frame = quicvarint.Append(frame, uint64(len(b)))
	frame = append(frame, b...)
	_, err := s.Write(frame)
	return err
}

func (s *masqueCapsuleStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		capsuleType, err := readMasqueQUICVarint(s.r)
		if err != nil {
			return nil, err
		}
		capsuleLen, err := readMasqueQUICVarint(s.r)
		if err != nil {
			return nil, err
		}
		if capsuleType != masqueDatagramCapsule {
			if _, err := io.CopyN(io.Discard, s.r, int64(capsuleLen)); err != nil {
				return nil, err
			}
			continue
		}
		if capsuleLen > maxMasqueCapsuleSize {
			return nil, fmt.Errorf("masquecat: HTTP/2 DATAGRAM capsule too large: %d", capsuleLen)
		}
		b := make([]byte, int(capsuleLen))
		if _, err := io.ReadFull(s.r, b); err != nil {
			return nil, err
		}
		return b, nil
	}
}

func readMasqueQUICVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	n := 1 << (first[0] >> 6)
	buf := make([]byte, n)
	buf[0] = first[0]
	if n > 1 {
		if _, err := io.ReadFull(r, buf[1:]); err != nil {
			return 0, err
		}
	}
	v, _, err := quicvarint.Parse(buf)
	return v, err
}

type masqueH2PacketConn struct {
	ctx       context.Context
	str       *masqueCapsuleStream
	transport *http2.Transport
}

func (c *masqueH2PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	b, err := receiveStreamDatagram(c.ctx, c.str)
	if err != nil {
		return 0, nil, err
	}
	if len(b) > len(p) {
		return 0, nil, io.ErrShortBuffer
	}
	copy(p, b)
	return len(b), masqueH2Addr{}, nil
}

func (c *masqueH2PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	b := make([]byte, 0, len(contextIDZero)+len(p))
	b = append(b, contextIDZero...)
	b = append(b, p...)
	if err := c.str.SendDatagram(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *masqueH2PacketConn) Close() error {
	err := c.str.Close()
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	return err
}

func (*masqueH2PacketConn) LocalAddr() net.Addr              { return masqueH2Addr{} }
func (*masqueH2PacketConn) SetDeadline(time.Time) error      { return nil }
func (*masqueH2PacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*masqueH2PacketConn) SetWriteDeadline(time.Time) error { return nil }

type masqueH2Addr struct{}

func (masqueH2Addr) Network() string { return "masque-h2" }
func (masqueH2Addr) String() string  { return "masque-h2" }

// newMasquePathWithFallback keeps HTTP/3 as the preferred carrier and retries
// the exact same authenticated CONNECT-UDP exchange over HTTP/2 when QUIC is
// unavailable. The dial function is retained on masquePath so reconnects also
// re-evaluate H3 first and can recover back to it automatically.
func newMasquePathWithFallback(
	ctx context.Context,
	rawURL string,
	target key.NodePublic,
	local key.NodePrivate,
	mode string,
	insecureSkipVerify bool,
	logf logger.Logf,
) (*masquePath, error) {
	if local.IsZero() {
		return nil, errors.New("masquecat: zero local node private key")
	}
	if target.IsZero() {
		return nil, errors.New("masquecat: zero MASQUE target node key")
	}
	tmpl, err := masqueTemplateFor(rawURL)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := masqueTLSClientConfig(rawURL, insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	if insecureSkipVerify && logf != nil {
		logf("WARNING: MASQUE TLS verification disabled for %s", rawURL)
	} else if tlsConfig.InsecureSkipVerify && len(tlsConfig.Certificates) == 0 && logf != nil {
		logf("MASQUE TLS certificate pinning enabled for %s", rawURL)
	}

	dial := func(dialCtx context.Context) (net.PacketConn, error) {
		h3, h3Err := dialMasquePacketConn(dialCtx, tmpl, target, local, mode, tlsConfig)
		if h3Err == nil {
			return h3, nil
		}
		h2, h2Err := dialMasqueH2PacketConn(dialCtx, tmpl, target, local, mode, tlsConfig)
		if h2Err == nil {
			if logf != nil {
				logf("MASQUE HTTP/3 unavailable; using HTTP/2 CONNECT-UDP fallback for %s: %v", rawURL, h3Err)
			}
			return h2, nil
		}
		return nil, errors.Join(
			fmt.Errorf("HTTP/3 CONNECT-UDP: %w", h3Err),
			fmt.Errorf("HTTP/2 CONNECT-UDP: %w", h2Err),
		)
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	return &masquePath{local: local.Public(), logf: logf, dial: dial, pc: conn}, nil
}

func dialMasqueH2PacketConn(
	ctx context.Context,
	tmpl *uritemplate.Template,
	target key.NodePublic,
	local key.NodePrivate,
	mode string,
	tlsConfig *tls.Config,
) (net.PacketConn, error) {
	expandedURL, err := expandMasqueTargetURL(tmpl, masqueTarget(target))
	if err != nil {
		return nil, err
	}
	h2TLS := tlsConfig.Clone()
	h2TLS.NextProtos = []string{http2.NextProtoTLS}
	tr := &http2.Transport{TLSClientConfig: h2TLS}

	dial := func(proof string) (*masqueH2PacketConn, *http.Response, error) {
		pr, pw := io.Pipe()
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, expandedURL, pr)
		if err != nil {
			_ = pr.Close()
			_ = pw.Close()
			return nil, nil, err
		}
		req.Host = req.URL.Host
		req.Header.Set(":protocol", masqueConnectUDPProtocol)
		req.Header.Set(http3.CapsuleProtocolHeader, "?1")
		req.Header.Set(masqueSourceHeader, local.Public().String())
		req.Header.Set(masqueModeHeader, mode)
		if proof != "" {
			req.Header.Set(masqueProofHeader, proof)
		}

		resp, err := tr.RoundTrip(req)
		if err != nil {
			_ = pw.CloseWithError(err)
			_ = pr.CloseWithError(err)
			return nil, nil, err
		}
		if resp.ProtoMajor != 2 {
			_ = pw.Close()
			_ = resp.Body.Close()
			return nil, resp, fmt.Errorf("masquecat: CONNECT-UDP fallback negotiated %s instead of HTTP/2", resp.Proto)
		}
		str := &masqueCapsuleStream{
			r:           resp.Body,
			w:           pw,
			closeWriter: pw.Close,
		}
		return &masqueH2PacketConn{ctx: ctx, str: str, transport: tr}, resp, nil
	}

	conn, resp, err := dial("")
	if err != nil {
		tr.CloseIdleConnections()
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get(masqueChallengeHeader)
		verifierText := resp.Header.Get(masqueVerifierHeader)
		_ = conn.Close()
		proof, proofErr := masqueProofForChallenge(local, challenge, verifierText, target, mode)
		if proofErr != nil {
			return nil, fmt.Errorf("masquecat: authenticate HTTP/2 CONNECT-UDP: %w", proofErr)
		}
		tr = &http2.Transport{TLSClientConfig: h2TLS}
		conn, resp, err = dial(proof)
		if err != nil {
			tr.CloseIdleConnections()
			return nil, err
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status := resp.Status
		_ = conn.Close()
		return nil, fmt.Errorf("masquecat: HTTP/2 CONNECT-UDP failed: %s", status)
	}
	return conn, nil
}

func expandMasqueTargetURL(tmpl *uritemplate.Template, target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("masquecat: parse CONNECT-UDP target: %w", err)
	}
	u, err := tmpl.Expand(uritemplate.Values{
		"target_host": uritemplate.String(host),
		"target_port": uritemplate.String(port),
	})
	if err != nil {
		return "", fmt.Errorf("masquecat: expand CONNECT-UDP template: %w", err)
	}
	return u, nil
}

// parseConnectUDPRequestAny normalizes HTTP/2's :protocol pseudo-header into
// the representation masque-go expects for HTTP/3 before reusing the existing
// path-template validation logic.
func parseConnectUDPRequestAny(w http.ResponseWriter, r *http.Request, tmpl *uritemplate.Template) (*masque.ProxyRequest, bool) {
	if r.ProtoMajor != 2 {
		return parseConnectUDPRequest(w, r, tmpl)
	}
	if r.Method != http.MethodConnect || r.Header.Get(":protocol") != masqueConnectUDPProtocol {
		http.Error(w, "expected HTTP/2 extended CONNECT-UDP", http.StatusNotImplemented)
		return nil, false
	}
	clone := r.Clone(r.Context())
	clone.Proto = masqueConnectUDPProtocol
	return parseConnectUDPRequest(w, clone, tmpl)
}

func acceptMasqueAnyStream(w http.ResponseWriter, r *http.Request) (masqueDatagramStream, error) {
	if r.ProtoMajor == 2 {
		return acceptMasqueH2Stream(w, r)
	}
	return acceptMasqueStream(w)
}

func acceptMasqueH2Stream(w http.ResponseWriter, r *http.Request) (masqueDatagramStream, error) {
	if r.ProtoMajor != 2 || r.Header.Get(":protocol") != masqueConnectUDPProtocol {
		return nil, errors.New("masquecat: request is not HTTP/2 CONNECT-UDP")
	}
	if r.Body == nil {
		return nil, errors.New("masquecat: HTTP/2 CONNECT-UDP request has no stream body")
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, errors.New("masquecat: HTTP/2 response writer does not support flushing")
	}
	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	return &masqueCapsuleStream{
		r:     r.Body,
		w:     w,
		flush: flusher.Flush,
	}, nil
}

func newMasqueHTTP2Server(tlsConfig *tls.Config, handler http.Handler) (*http.Server, error) {
	if tlsConfig == nil {
		return nil, errors.New("masquecat: nil HTTP/2 TLS config")
	}
	enableMasqueH2ExtendedConnect()
	conf := tlsConfig.Clone()
	conf.MinVersion = tls.VersionTLS13
	srv := &http.Server{TLSConfig: conf, Handler: handler}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		return nil, fmt.Errorf("masquecat: configure HTTP/2 server: %w", err)
	}
	// This listener is specifically for the RFC 9298 fallback. Do not silently
	// downgrade the fallback socket to HTTP/1.1.
	srv.TLSConfig.NextProtos = []string{http2.NextProtoTLS}
	return srv, nil
}

func masqueHTTP2CompanionAddr(configured string, udpAddr net.Addr) (string, error) {
	host, port, err := net.SplitHostPort(configured)
	if err != nil {
		return "", err
	}
	if port != "0" {
		return configured, nil
	}
	_, actualPort, err := net.SplitHostPort(udpAddr.String())
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, actualPort), nil
}

func startMasqueHTTP2(
	ctx context.Context,
	addr string,
	tlsConfig *tls.Config,
	handler http.Handler,
	logf logger.Logf,
) error {
	srv, err := newMasqueHTTP2Server(tlsConfig, handler)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen for HTTP/2 MASQUE: %w", err)
	}
	tlsLn := tls.NewListener(ln, srv.TLSConfig)
	go func() {
		if err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil && logf != nil {
			logf("HTTP/2 MASQUE listener stopped: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
		_ = ln.Close()
	}()
	return nil
}

// ServeMasque serves the same CONNECT-UDP handler on UDP/HTTP/3 and
// TCP/HTTP/2. HTTP/3 remains the preferred client path; HTTP/2 exists for
// networks and intermediaries that block or fail QUIC.
func ServeMasque(addr string, tlsConfig *tls.Config, handler http.Handler) error {
	if !hasMasqueServerCertificate(tlsConfig) {
		return fmt.Errorf("MASQUE server requires a TLS certificate")
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("listen for HTTP/3 MASQUE: %w", err)
	}
	defer pc.Close()

	h2Addr, err := masqueHTTP2CompanionAddr(addr, pc.LocalAddr())
	if err != nil {
		return fmt.Errorf("derive HTTP/2 MASQUE listen address: %w", err)
	}
	h2, err := newMasqueHTTP2Server(tlsConfig, handler)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", h2Addr)
	if err != nil {
		return fmt.Errorf("listen for HTTP/2 MASQUE: %w", err)
	}
	defer ln.Close()

	h3TLS := http3.ConfigureTLSConfig(tlsConfig.Clone())
	h3TLS.MinVersion = tls.VersionTLS13
	h3 := &http3.Server{
		TLSConfig:       h3TLS,
		Handler:         handler,
		EnableDatagrams: true,
	}
	defer h3.Close()
	defer h2.Close()

	errCh := make(chan error, 2)
	go func() { errCh <- h3.Serve(pc) }()
	go func() { errCh <- h2.Serve(tls.NewListener(ln, h2.TLSConfig)) }()
	err = <-errCh
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
