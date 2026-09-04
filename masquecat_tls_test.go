//go:build !js

package tailcat

import (
	"crypto/tls"
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

func TestHasMasqueServerCertificate(t *testing.T) {
	tests := []struct {
		name string
		conf *tls.Config
		want bool
	}{
		{name: "nil", conf: nil, want: false},
		{name: "empty", conf: &tls.Config{}, want: false},
		{name: "certificate", conf: &tls.Config{Certificates: []tls.Certificate{{}}}, want: true},
		{name: "get-certificate", conf: &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }}, want: true},
		{name: "get-config-for-client", conf: &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasMasqueServerCertificate(tt.conf); got != tt.want {
				t.Fatalf("hasMasqueServerCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}
