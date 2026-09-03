package main

import (
	"crypto/tls"
	"path/filepath"
	"sync"
	"testing"
)

func clearAutoMasqueEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"MASQUECAT_RELAY_URL",
		"MASQUECAT_DIRECT_URL",
		"MASQUECAT_DIRECT_LISTEN",
		"MASQUECAT_TLS_CERT",
		"MASQUECAT_TLS_KEY",
	} {
		t.Setenv(name, "")
	}
}

func TestShouldConfigureAutoMasqueDirect(t *testing.T) {
	clearAutoMasqueEnv(t)

	for _, args := range [][]string{
		{"tailcat"},
		{"tailcat", "serve", "22"},
		{"tailcat", "recv", "."},
		{"tailcat", "--serve=22"},
		{"tailcat", "--serve", "22"},
	} {
		if !shouldConfigureAutoMasqueDirect(args) {
			t.Fatalf("shouldConfigureAutoMasqueDirect(%q) = false", args)
		}
	}

	for _, args := range [][]string{
		{"tailcat", "serve", "22", "--relay-url=https://relay.example.test"},
		{"tailcat", "--direct-url", "https://server.example.test", "serve", "22"},
		{"tailcat", "ping", "mc-invalid"},
		{"tailcat", "--help"},
		{"tailcat", "serve", "--help"},
		{"tailcat", "--serve", "--help"},
		{"tailcat", "--serve"},
	} {
		if shouldConfigureAutoMasqueDirect(args) {
			t.Fatalf("shouldConfigureAutoMasqueDirect(%q) = true", args)
		}
	}
}

func TestShouldConfigureAutoMasqueDirectHonorsAnyDirectEnvironment(t *testing.T) {
	for _, name := range []string{
		"MASQUECAT_RELAY_URL",
		"MASQUECAT_DIRECT_URL",
		"MASQUECAT_DIRECT_LISTEN",
		"MASQUECAT_TLS_CERT",
		"MASQUECAT_TLS_KEY",
	} {
		t.Run(name, func(t *testing.T) {
			clearAutoMasqueEnv(t)
			t.Setenv(name, "configured")
			if shouldConfigureAutoMasqueDirect([]string{"tailcat"}) {
				t.Fatalf("%s should disable automatic direct mode", name)
			}
		})
	}
}

func TestIsPublicMasqueDirectAddr(t *testing.T) {
	for _, ip := range []string{
		"8.8.8.8",
		"2606:4700:4700::1111",
	} {
		if !isPublicMasqueDirectAddr(mustParseAddr(t, ip)) {
			t.Fatalf("%s should be considered public", ip)
		}
	}
	for _, ip := range []string{
		"10.0.0.1",
		"100.64.0.1",
		"192.0.2.1",
		"198.18.0.1",
		"203.0.113.1",
		"2001:db8::1",
	} {
		if isPublicMasqueDirectAddr(mustParseAddr(t, ip)) {
			t.Fatalf("%s should not be considered publicly reachable", ip)
		}
	}
}

func mustParseAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestEnsureAutoMasqueCertificateConcurrent(t *testing.T) {
	configRoot := t.TempDir()
	// os.UserConfigDir uses different environment variables by platform. Set
	// all relevant roots so this test remains hermetic on Linux, macOS, Windows.
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	t.Setenv("HOME", configRoot)
	t.Setenv("APPDATA", configRoot)

	const workers = 8
	type result struct {
		cert string
		key  string
		err  error
	}
	results := make(chan result, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cert, key, err := ensureAutoMasqueCertificate()
			results <- result{cert: cert, key: key, err: err}
		}()
	}
	wg.Wait()
	close(results)

	var bundle string
	for r := range results {
		if r.err != nil {
			t.Fatalf("ensureAutoMasqueCertificate: %v", r.err)
		}
		if r.cert != r.key {
			t.Fatalf("certificate/key paths differ: %q != %q", r.cert, r.key)
		}
		if bundle == "" {
			bundle = r.cert
		} else if r.cert != bundle {
			t.Fatalf("workers returned different bundle paths: %q != %q", r.cert, bundle)
		}
	}
	if filepath.Base(bundle) != "tls.pem" {
		t.Fatalf("bundle path = %q, want tls.pem", bundle)
	}
	if _, err := tls.LoadX509KeyPair(bundle, bundle); err != nil {
		t.Fatalf("final automatic TLS bundle is not a matched key pair: %v", err)
	}
}
