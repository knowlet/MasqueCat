//go:build !js

package tailcat

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// directMasqueCoreHandler terminates a direct CONNECT-UDP carrier and feeds its
// opaque WireGuard datagrams directly into masqueCore. It deliberately bypasses
// the legacy loopback DERP bridge.
func directMasqueCoreHandler(localPriv key.NodePrivate, core *masqueCore, logf logger.Logf) http.Handler {
	local := localPriv.Public()
	auth := newMasqueAuthenticator(localPriv)
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
		if !auth.authorize(w, r, src, target, masqueModeDirect) {
			return
		}
		if !core.peerAllowed(src) {
			http.Error(w, "MasqueCat peer is not allowed", http.StatusForbidden)
			return
		}
		str, err := acceptMasqueStream(w)
		if err != nil {
			logf("accept direct MASQUE stream: %v", err)
			return
		}
		defer func() { _ = str.Close() }()
		fwd := &streamForwarder{str: str}
		if err := core.SetPath(src, fwd); err != nil {
			logf("register direct MASQUE peer %v: %v", src.ShortString(), err)
			return
		}
		defer core.RemovePath(src, fwd)
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
			// Compatibility with old peers: never feed legacy disco frames into
			// WireGuard. New MasqueCat cores never generate such frames.
			if bytes.HasPrefix(pkt.payload, discoMagicBytes) {
				continue
			}
			if err := core.Inject(src, pkt.payload); err != nil {
				logf("inject direct MASQUE datagram: %v", err)
				return
			}
		}
	})
}
