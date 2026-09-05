//go:build !js

package tailcat

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go/http3"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// MasqueRelay is a paired CONNECT-UDP relay. It only forwards opaque
// MasqueCat datagrams between registered node keys; it is intentionally not a
// generic UDP proxy.
type MasqueRelay struct {
	Logf logger.Logf

	mu    sync.Mutex
	peers map[key.NodePublic]*relayPeer

	authOnce sync.Once
	auth     *masqueAuthenticator
}

type relayPeer struct {
	key key.NodePublic
	fwd *streamForwarder
}

func (r *MasqueRelay) logf() logger.Logf {
	if r.Logf != nil {
		return r.Logf
	}
	return func(format string, args ...any) {}
}

func (r *MasqueRelay) authenticator() *masqueAuthenticator {
	r.authOnce.Do(func() {
		r.auth = newMasqueAuthenticator(key.NewNode())
	})
	return r.auth
}

// Handler returns the HTTP handler for a MasqueCat relay. The same handler is
// used by both the preferred HTTP/3 carrier and the HTTP/2 fallback.
func (r *MasqueRelay) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		logf := r.logf()
		tmpl, err := masqueTemplateFor("https://" + req.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		proxyReq, ok := parseConnectUDPRequestAny(w, req, tmpl)
		if !ok {
			return
		}
		if req.Header.Get(masqueModeHeader) != masqueModeRelay {
			http.Error(w, "expected relay MasqueCat path", http.StatusBadRequest)
			return
		}
		registeredKey, err := parseMasqueTarget(proxyReq.Target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		src, err := parseMasqueSource(req)
		if err != nil || src != registeredKey {
			http.Error(w, "MasqueCat source does not match registered target", http.StatusUnauthorized)
			return
		}
		if !r.authenticator().authorize(w, req, src, registeredKey, masqueModeRelay) {
			return
		}

		// Reserve the node key before acceptMasqueStream writes the 200 response.
		// That makes same-key races fail with 409 before either client can mistake
		// an immediately closed stream for a successful registration.
		peer, ok := r.reserve(registeredKey)
		if !ok {
			http.Error(w, "MasqueCat peer is already registered", http.StatusConflict)
			return
		}
		defer r.unregister(peer)

		str, err := acceptMasqueAnyStream(w, req)
		if err != nil {
			logf("accept relay MASQUE stream: %v", err)
			return
		}
		defer func() { _ = str.Close() }()
		if !r.activate(peer, &streamForwarder{str: str}) {
			logf("MASQUE relay reservation disappeared before activation: %v", peer.key.ShortString())
			return
		}
		logf("MASQUE relay peer registered: %v", peer.key.ShortString())

		ctx := req.Context()
		for {
			b, err := receiveStreamDatagram(ctx, str)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					logf("MASQUE relay peer %v closed: %v", peer.key.ShortString(), err)
				}
				return
			}
			pkt, err := decodeMasquePacket(b)
			if err != nil {
				logf("dropping malformed relay datagram: %v", err)
				continue
			}
			if pkt.src != peer.key {
				logf("dropping relay datagram with spoofed source %v", pkt.src.ShortString())
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
				logf("relay %v -> %v: %v", pkt.src.ShortString(), pkt.dst.ShortString(), err)
			}
		}
	})
}

// reserve atomically claims a node key without making it routable yet. The
// caller must unregister the returned peer if stream acceptance fails.
func (r *MasqueRelay) reserve(k key.NodePublic) (*relayPeer, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers == nil {
		r.peers = make(map[key.NodePublic]*relayPeer)
	}
	if r.peers[k] != nil {
		return nil, false
	}
	p := &relayPeer{key: k}
	r.peers[k] = p
	return p, true
}

// activate publishes a successfully accepted stream for a previously reserved
// peer. Reserved peers with a nil forwarder remain invisible to lookup.
func (r *MasqueRelay) activate(p *relayPeer, fwd *streamForwarder) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p == nil || fwd == nil || r.peers[p.key] != p || p.fwd != nil {
		return false
	}
	p.fwd = fwd
	return true
}

// register is retained as a small atomic helper for registry-level tests and
// callers that already have an accepted forwarder. Production registration in
// Handler uses reserve -> accept -> activate so success is not sent too early.
func (r *MasqueRelay) register(p *relayPeer) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p == nil || p.fwd == nil {
		return false
	}
	if r.peers == nil {
		r.peers = make(map[key.NodePublic]*relayPeer)
	}
	if old := r.peers[p.key]; old != nil && old != p {
		return false
	}
	r.peers[p.key] = p
	return true
}

func (r *MasqueRelay) unregister(p *relayPeer) {
	if p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers[p.key] == p {
		delete(r.peers, p.key)
	}
}

func (r *MasqueRelay) lookup(k key.NodePublic) *relayPeer {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.peers[k]
	if p == nil || p.fwd == nil {
		return nil
	}
	return p
}

// ServeMasqueHTTP3 serves handler over HTTP/3 with CONNECT-UDP datagrams.
// It blocks until the server stops. New deployments should prefer ServeMasque,
// which also exposes the RFC 9298 HTTP/2 fallback on the same port number.
func ServeMasqueHTTP3(addr string, tlsConfig *tls.Config, handler http.Handler) error {
	if !hasMasqueServerCertificate(tlsConfig) {
		return fmt.Errorf("MASQUE HTTP/3 server requires a TLS certificate")
	}
	conf := http3.ConfigureTLSConfig(tlsConfig.Clone())
	conf.MinVersion = tls.VersionTLS13
	s := &http3.Server{
		Addr:            addr,
		TLSConfig:       conf,
		Handler:         handler,
		EnableDatagrams: true,
	}
	return s.ListenAndServe()
}
