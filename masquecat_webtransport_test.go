//go:build !js

package tailcat

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"tailscale.com/types/key"
)

// Exercise the real QUIC/WebTransport server with normal certificate and host
// verification. The httptest certificate is trusted only by this test client.
func browserRelayTestClient(t *testing.T) (*webtransport.Dialer, string, *MasqueRelay) {
	t.Helper()
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	cert := seed.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(seed.Certificate())
	seed.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &MasqueRelay{Logf: t.Logf}
	h3 := &http3.Server{TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}})}
	wt := &webtransport.Server{H3: h3, CheckOrigin: browserOriginChecker("")}
	webtransport.ConfigureHTTP3Server(h3)
	h3.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { relay.serveBrowserWebTransport(w, r, wt) })
	done := make(chan error, 1)
	go func() { done <- wt.Serve(pc) }()
	t.Cleanup(func() { _ = wt.Close(); _ = pc.Close(); <-done })
	d := &webtransport.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	t.Cleanup(func() { _ = d.Close() })
	return d, "https://" + pc.LocalAddr().String() + masqueBrowserWebTransportPath, relay
}

func dialBrowserTestSession(t *testing.T, d *webtransport.Dialer, url string) *webtransport.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, s, err := d.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.CloseWithError(0, "") })
	return s
}

func authenticateBrowserTestSession(t *testing.T, s *webtransport.Session, priv key.NodePrivate) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := s.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	r, w := bufio.NewReader(stream), bufio.NewWriter(stream)
	if err := writeMasqueBrowserControl(w, masqueBrowserControl{Type: "hello", Version: masqueBrowserProtocolVersion, Source: priv.Public().String()}); err != nil {
		t.Fatal(err)
	}
	challenge, err := readMasqueBrowserControl(r)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Type != "challenge" {
		t.Fatalf("got %#v, want challenge", challenge)
	}
	var verifier key.NodePublic
	if err := verifier.UnmarshalText([]byte(challenge.Verifier)); err != nil {
		t.Fatal(err)
	}
	proof := base64.RawURLEncoding.EncodeToString(priv.SealTo(verifier, []byte(challenge.Challenge)))
	if err := writeMasqueBrowserControl(w, masqueBrowserControl{Type: "proof", Proof: proof}); err != nil {
		t.Fatal(err)
	}
	ready, err := readMasqueBrowserControl(r)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Type != "ready" || ready.Version != masqueBrowserProtocolVersion {
		t.Fatalf("got %#v, want ready", ready)
	}
}

func TestMasqueBrowserWebTransportAuthenticatedDatagrams(t *testing.T) {
	t.Parallel()
	d, url, relay := browserRelayTestClient(t)
	a, b := dialBrowserTestSession(t, d, url), dialBrowserTestSession(t, d, url)
	ka, kb := key.NewNode(), key.NewNode()
	authenticateBrowserTestSession(t, a, ka)
	authenticateBrowserTestSession(t, b, kb)
	for i, direction := range []struct {
		from, to *webtransport.Session
		src, dst key.NodePublic
	}{{a, b, ka.Public(), kb.Public()}, {b, a, kb.Public(), ka.Public()}} {
		if i == 1 {
			// Expiry of the completed control handshake must not terminate an
			// authenticated session or its bidirectional datagram path.
			time.Sleep(masqueBrowserAuthTimeout + 100*time.Millisecond)
		}
		payload := bytes.Repeat([]byte("webtransport-round-trip"), 16)
		if err := direction.from.SendDatagram(encodeMasquePacket(direction.src, direction.dst, payload)); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		got, err := direction.to.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		packet, err := decodeMasquePacket(got)
		if err != nil {
			t.Fatal(err)
		}
		if packet.src != direction.src || packet.dst != direction.dst || !bytes.Equal(packet.payload, payload) {
			t.Fatal("forwarded datagram changed")
		}
	}
	_ = a.CloseWithError(0, "")
	deadline := time.Now().Add(5 * time.Second)
	for relay.lookup(ka.Public()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("closed session retained its relay registration")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMasqueBrowserWebTransportAuthDeadline(t *testing.T) {
	for _, stage := range []string{"partial-hello", "partial-proof"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			d, url, _ := browserRelayTestClient(t)
			s := dialBrowserTestSession(t, d, url)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, err := s.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if stage == "partial-proof" {
				w := bufio.NewWriter(stream)
				if err := writeMasqueBrowserControl(w, masqueBrowserControl{Type: "hello", Version: masqueBrowserProtocolVersion, Source: key.NewNode().Public().String()}); err != nil {
					t.Fatal(err)
				}
				_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
				challenge, err := readMasqueBrowserControl(bufio.NewReader(stream))
				if err != nil || challenge.Type != "challenge" {
					t.Fatalf("challenge: %#v, %v", challenge, err)
				}
			}
			// An incomplete JSON line makes the stream visible to AcceptStream but
			// leaves the server blocked in its control-message read.
			if _, err := stream.Write([]byte("{")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-s.Context().Done():
			case <-time.After(masqueBrowserAuthTimeout + 3*time.Second):
				t.Fatal("unauthenticated partial control message outlived authentication deadline")
			}
		})
	}
}
