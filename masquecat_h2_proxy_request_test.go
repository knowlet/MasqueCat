//go:build !js

package tailcat

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/types/key"
)

func TestMasqueRelayH2RequestRestoresAuthorityForTemplateMatch(t *testing.T) {
	peer := key.NewNode().Public()
	tmpl, err := masqueTemplateFor("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := expandMasqueTargetURL(tmpl, masqueTarget(peer))
	if err != nil {
		t.Fatal(err)
	}

	// Reproduce the request shape emitted by masqueHTTP2Server: :authority is
	// represented by Request.Host, while URL.Host is empty like a normal Go
	// server request. masque-go v0.4.0 matches the full URI template against
	// r.URL.String(), so passing this shape through unchanged used to fail with
	// 400 "expected target_host and target_port" before authentication ran.
	//
	// Build the absolute URL as a normal request first. httptest.NewRequest has
	// special CONNECT request-target parsing that would otherwise treat the
	// scheme as an authority and would not model masqueH2RequestFromFields.
	req := httptest.NewRequest(http.MethodGet, expanded, nil)
	req.Method = http.MethodConnect
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Host = "relay.example"
	req.RequestURI = req.URL.RequestURI()
	req.URL.Host = ""
	req.Header.Set(":protocol", masqueConnectUDPProtocol)
	req.Header.Set(masqueModeHeader, masqueModeRelay)
	req.Header.Set(masqueSourceHeader, peer.String())

	rr := httptest.NewRecorder()
	(&MasqueRelay{}).Handler().ServeHTTP(rr, req)

	// Reaching the authentication challenge proves CONNECT-UDP target parsing
	// succeeded. Before the fix this request was rejected by ParseProxyRequest
	// with StatusBadRequest instead.
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %q", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
	if got := rr.Header().Get(masqueChallengeHeader); got == "" {
		t.Fatal("missing MasqueCat authentication challenge after successful H2 target parsing")
	}
	if req.URL.Host != "" {
		t.Fatalf("handler mutated original request URL host to %q", req.URL.Host)
	}
}

func TestMasqueRelayH2AuthenticatedConnectEndToEnd(t *testing.T) {
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	cert := seed.TLS.Certificates[0]
	seed.Close()

	relay := &MasqueRelay{}
	srv, err := newMasqueHTTP2Server(&tls.Config{Certificates: []tls.Certificate{cert}}, relay.Handler())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = srv.Serve(tls.NewListener(ln, srv.TLSConfig)) }()
	defer func() { _ = srv.Close() }()

	tmpl, err := masqueTemplateFor("https://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	local := key.NewNode()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pc, err := dialMasqueH2PacketConnRFC8441(
		ctx,
		tmpl,
		local.Public(),
		local,
		masqueModeRelay,
		&tls.Config{InsecureSkipVerify: true}, // test-only ephemeral certificate
	)
	if err != nil {
		t.Fatalf("authenticated HTTP/2 CONNECT-UDP dial failed: %v", err)
	}
	defer func() { _ = pc.Close() }()
}
