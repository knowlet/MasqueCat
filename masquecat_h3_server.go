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

func requestMasqueTemplate(r *http.Request) (*masqueRequestTemplate, error) {
	t, err := masqueTemplateFor("https://" + r.Host)
	if err != nil {
		return nil, err
	}
	return &masqueRequestTemplate{template: t}, nil
}

type masqueRequestTemplate struct {
	template interfaceTemplate
}

// interfaceTemplate exists only to keep construction localized; the concrete
// URI-template value is unwrapped immediately by the handlers below.
type interfaceTemplate interface{}

func directMasqueHandler(local key.NodePublic, bridge *localDERPBridge, logf logger.Logf) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := masqueTemplateFor("https://" + r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, ok := parseConnectUDPRequest(w, r, tmpl)
		if !ok {
			return
		}
		if r.Header.Get(masqueModeHeader) != masqueModeDirect {
			http.Error(w, "expected direct MasqueCat path", http.StatusBadRequest)
			return
		}
		target, err := parseMasqueTarget(req.Target)
		if err != nil || target != local {
			http.Error(w, "CONNECT-UDP target is not this MasqueCat peer", http.StatusNotFound)
			return
		}
		src, err := parseMasqueSource(r)
		if err != nil || src.IsZero() {
			http.Error(w, "invalid MasqueCat source", http.StatusUnauthorized)
			return
		}
		str, err := acceptMasqueStream(w)
		if err != nil {
			logf("accept direct MASQUE stream: %v", err)
			return
		}
		defer str.Close()
		fwd := &streamForwarder{str: str}
		bridge.AddForwarder(src, fwd)
		defer bridge.RemoveForwarder(src, fwd)
		logf("direct MASQUE peer connected: %v", src.ShortString())

		ctx := r.Context()
		for {
			b, err := receiveStreamDatagram(ctx, str)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					logf("direct MASQUE peer %v closed: %v", src.ShortString(), err)
				}
				return
			}
			pkt, err := decodeMasquePacket(b)
			if err != nil {
				logf("dropping malformed direct MASQUE datagram: %v", err)
				continue
			}
			if pkt.src != src || pkt.dst != local {
				logf("dropping direct MASQUE datagram with mismatched peer identity")
				continue
			}
			if bytes.HasPrefix(pkt.payload, discoMagicBytes) {
				continue
			}
			if err := bridge.Inject(pkt.src, pkt.dst, pkt.payload); err != nil {
				logf("inject direct MASQUE datagram: %v", err)
				return
			}
		}
	})
}

// MasqueRelay is a paired CONNECT-UDP relay. It only forwards opaque
// MasqueCat datagrams between registered node keys; it is intentionally not a
// generic UDP proxy.
type MasqueRelay struct {
	Logf logger.Logf

	mu    sync.Mutex
	peers map[key.NodePublic]*relayPeer
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

// Handler returns the HTTP/3 handler for a MasqueCat relay.
func (r *MasqueRelay) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		logf := r.logf()
		tmpl, err := masqueTemplateFor("https://" + req.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		proxyReq, ok := parseConnectUDPRequest(w, req, tmpl)
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
		str, err := acceptMasqueStream(w)
		if err != nil {
			logf("accept relay MASQUE stream: %v", err)
			return
		}
		defer str.Close()
		peer := &relayPeer{key: registeredKey, fwd: &streamForwarder{str: str}}
		r.register(peer)
		defer r.unregister(peer)
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

func (r *MasqueRelay) register(p *relayPeer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers == nil {
		r.peers = make(map[key.NodePublic]*relayPeer)
	}
	if old := r.peers[p.key]; old != nil && old != p {
		old.fwd.str.Close()
	}
	r.peers[p.key] = p
}

func (r *MasqueRelay) unregister(p *relayPeer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers[p.key] == p {
		delete(r.peers, p.key)
	}
}

func (r *MasqueRelay) lookup(k key.NodePublic) *relayPeer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peers[k]
}

// ServeMasqueHTTP3 serves handler over HTTP/3 with CONNECT-UDP datagrams.
// It blocks until the server stops.
func ServeMasqueHTTP3(addr string, tlsConfig *tls.Config, handler http.Handler) error {
	if tlsConfig == nil || len(tlsConfig.Certificates) == 0 {
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
