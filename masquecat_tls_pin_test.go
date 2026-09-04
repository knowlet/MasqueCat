//go:build !js

package tailcat

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

func TestMasqueTLSClientConfigPinnedCertificate(t *testing.T) {
	leaf := []byte("expected automatic direct leaf certificate")
	sum := sha256.Sum256(leaf)
	rawURL := "https://192.0.2.10:4433#sha256=" + base64.RawURLEncoding.EncodeToString(sum[:])

	cfg, err := masqueTLSClientConfig(rawURL, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("pinned endpoint has no VerifyConnection callback")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Raw: leaf}},
	}); err != nil {
		t.Fatalf("matching pinned certificate rejected: %v", err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Raw: []byte("different certificate")}},
	}); err == nil || !strings.Contains(err.Error(), "pin mismatch") {
		t.Fatalf("mismatched pinned certificate error = %v, want pin mismatch", err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Fatalf("missing certificate error = %v, want no certificate", err)
	}
}
