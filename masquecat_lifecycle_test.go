//go:build !js

package tailcat

import (
	"context"
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
