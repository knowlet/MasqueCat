//go:build !js

package main

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestLoadOrGenerateCertificateRequiresPair(t *testing.T) {
	if _, _, err := loadOrGenerateCertificate("cert.pem", "", strings.NewReader("yes\n"), &bytes.Buffer{}, true); err == nil {
		t.Fatal("expected mismatched -cert/-key to fail")
	}
}

func TestLoadOrGenerateCertificateNonInteractiveFailsClosed(t *testing.T) {
	if _, _, err := loadOrGenerateCertificate("", "", strings.NewReader("yes\n"), &bytes.Buffer{}, false); err == nil {
		t.Fatal("expected non-interactive missing certificate to fail")
	}
}

func TestLoadOrGenerateCertificatePromptDeclined(t *testing.T) {
	var out bytes.Buffer
	if _, _, err := loadOrGenerateCertificate("", "", strings.NewReader("n\n"), &out, true); err == nil {
		t.Fatal("expected declined certificate generation to fail")
	}
	if !strings.Contains(out.String(), "Generate an ephemeral self-signed certificate") {
		t.Fatalf("prompt = %q", out.String())
	}
}

func TestLoadOrGenerateCertificatePromptAcceptsYes(t *testing.T) {
	cert, generated, err := loadOrGenerateCertificate("", "", strings.NewReader("yes\n"), &bytes.Buffer{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !generated {
		t.Fatal("expected generated certificate")
	}
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatal("generated certificate is incomplete")
	}
	leaf := cert.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	if !containsString(leaf.DNSNames, "localhost") {
		t.Fatalf("DNSNames = %v; want localhost", leaf.DNSNames)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got < selfSignedValidity || got > selfSignedValidity+2*time.Minute {
		t.Fatalf("certificate validity = %v", got)
	}
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
