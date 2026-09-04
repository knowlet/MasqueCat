//go:build !js

package tailcat

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMasqueServerStartRequiresPath(t *testing.T) {
	s := new(MasqueServer)
	err := s.Start()
	if err == nil || !strings.Contains(err.Error(), "direct or relay") {
		t.Fatalf("Start error = %v, want missing path error", err)
	}
}

func TestMasqueServerDirectRequiresListen(t *testing.T) {
	s := &MasqueServer{DirectURL: "https://peer.example"}
	err := s.Start()
	if err == nil || !strings.Contains(err.Error(), "DirectListen") {
		t.Fatalf("Start error = %v, want DirectListen error", err)
	}
}

func TestMasqueServerDirectRequiresTLSCertificate(t *testing.T) {
	s := &MasqueServer{
		DirectURL:    "https://peer.example",
		DirectListen: ":0",
	}
	err := s.Start()
	if err == nil || !strings.Contains(err.Error(), "TLS certificate") {
		t.Fatalf("Start error = %v, want TLS certificate error", err)
	}
}

func TestMasqueServerRejectsInvalidRelayURLBeforeNetworking(t *testing.T) {
	s := &MasqueServer{RelayURL: "http://relay.example"}
	err := s.Start()
	if err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("Start error = %v, want https validation error", err)
	}
}

func TestMasqueServerStartCanRetryAfterPostCoreFailure(t *testing.T) {
	tlsServer := httptest.NewTLSServer(nil)
	cert := tlsServer.Certificate()
	tlsServer.Close()
	s := &MasqueServer{
		DirectURL:    "https://127.0.0.1:443",
		DirectListen: "bad-listen-address",
		DirectTLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{cert.Raw},
			}},
		},
	}
	if err := s.Start(); err == nil || !strings.Contains(err.Error(), "listen for direct MASQUE") {
		t.Fatalf("first Start error = %v, want direct listen failure", err)
	}
	s.DirectListen = "127.0.0.1:0"
	if err := s.Start(); err != nil {
		t.Fatalf("second Start after cleanup: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close after retry: %v", err)
	}
}

func TestMasqueServerConnBlobBeforeStartIsEmpty(t *testing.T) {
	if got := new(MasqueServer).ConnBlob(); got != "" {
		t.Fatalf("ConnBlob before Start = %q, want empty", got)
	}
}

func TestMasqueServerCloseBeforeStart(t *testing.T) {
	if err := new(MasqueServer).Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
}

func TestMasqueDialContextDetachesOperationAfterSuccess(t *testing.T) {
	lifecycleCtx, cancelLifecycle := context.WithCancel(context.Background())
	opCtx, cancelOperation := context.WithCancel(context.Background())
	dialCtx, finishDial := masqueDialContext(lifecycleCtx, opCtx)
	if !finishDial(true) {
		t.Fatal("finishDial reported an operation cancellation before success")
	}

	cancelOperation()
	if err := dialCtx.Err(); err != nil {
		t.Fatalf("operation cancellation leaked into established transport: %v", err)
	}

	cancelLifecycle()
	if err := dialCtx.Err(); err == nil {
		t.Fatal("lifecycle cancellation did not stop established transport context")
	}
}

func TestMasqueDialContextHonorsOperationCancellationDuringDial(t *testing.T) {
	lifecycleCtx, cancelLifecycle := context.WithCancel(context.Background())
	defer cancelLifecycle()
	opCtx, cancelOperation := context.WithCancel(context.Background())
	dialCtx, finishDial := masqueDialContext(lifecycleCtx, opCtx)

	cancelOperation()
	if finishDial(true) {
		t.Fatal("finishDial detached an operation that was already canceled")
	}
	if err := dialCtx.Err(); err == nil {
		t.Fatal("operation cancellation did not cancel in-flight dial context")
	}
}

func TestMasqueClientPublicKeyStable(t *testing.T) {
	c := NewMasqueClient("")
	first := c.PublicKey()
	second := c.PublicKey()
	if first.IsZero() {
		t.Fatal("PublicKey returned zero key")
	}
	if first != second {
		t.Fatalf("PublicKey changed: %v != %v", first, second)
	}
}

func TestMasqueClientCloseBeforeStart(t *testing.T) {
	c := NewMasqueClient("")
	if err := c.Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
	if got := c.Path(); got != "" {
		t.Fatalf("Path before Start = %q, want empty", got)
	}
}

func TestMasqueClientRejectsInvalidTokenBeforeNetworking(t *testing.T) {
	c := NewMasqueClient("not-a-token")
	defer func() { _ = c.Close() }()
	_, err := c.DialTCPPort(context.Background(), 22)
	if err == nil || !strings.Contains(err.Error(), "doesn't start") {
		t.Fatalf("DialTCPPort error = %v, want token validation error", err)
	}
}
