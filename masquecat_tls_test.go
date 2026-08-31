//go:build !js

package tailcat

import (
	"testing"

	"github.com/quic-go/quic-go/http3"
)

func TestMasqueTLSClientConfigSecureByDefault(t *testing.T) {
	cfg, err := masqueTLSClientConfig("https://relay.example.com:443", false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify enabled by default")
	}
	if cfg.ServerName != "relay.example.com" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != http3.NextProtoH3 {
		t.Fatalf("NextProtos = %v", cfg.NextProtos)
	}
}

func TestMasqueTLSClientConfigInsecureOptIn(t *testing.T) {
	cfg, err := masqueTLSClientConfig("https://127.0.0.1:8443", true)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("explicit InsecureSkipVerify was not propagated")
	}
	if cfg.ServerName != "127.0.0.1" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
}
