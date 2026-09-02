package main

import (
	"os"
	"testing"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
)

func TestShouldConfigureAutoMasqueDirect(t *testing.T) {
	t.Setenv("MASQUECAT_RELAY_URL", "")
	t.Setenv("MASQUECAT_DIRECT_URL", "")

	for _, args := range [][]string{
		{"tailcat"},
		{"tailcat", "serve", "22"},
		{"tailcat", "recv", "."},
		{"tailcat", "--serve=22"},
	} {
		if !shouldConfigureAutoMasqueDirect(args) {
			t.Fatalf("shouldConfigureAutoMasqueDirect(%q) = false", args)
		}
	}

	for _, args := range [][]string{
		{"tailcat", "serve", "22", "--relay-url=https://relay.example.test"},
		{"tailcat", "--direct-url", "https://server.example.test", "serve", "22"},
		{"tailcat", "ping", "mc-invalid"},
	} {
		if shouldConfigureAutoMasqueDirect(args) {
			t.Fatalf("shouldConfigureAutoMasqueDirect(%q) = true", args)
		}
	}
}

func TestShouldConfigureAutoMasqueDirectHonorsEnvironment(t *testing.T) {
	t.Setenv("MASQUECAT_DIRECT_URL", "")
	t.Setenv("MASQUECAT_RELAY_URL", "https://relay.example.test")
	if shouldConfigureAutoMasqueDirect([]string{"tailcat"}) {
		t.Fatal("relay environment setting should disable automatic direct mode")
	}

	t.Setenv("MASQUECAT_RELAY_URL", "")
	t.Setenv("MASQUECAT_DIRECT_URL", "https://server.example.test")
	if shouldConfigureAutoMasqueDirect([]string{"tailcat"}) {
		t.Fatal("direct environment setting should disable automatic direct mode")
	}
}

func TestAutomaticDirectOnlyTokenDetection(t *testing.T) {
	priv := key.NewNode()
	base := tailcat.MasqueConnInfo{
		Version:           1,
		ServerPublic:      priv.Public(),
		ServerDiscoPublic: tailcat.DiscoPublicForNode(priv).DiscoPublic,
		DirectURL:         "https://192.0.2.10:" + autoMasqueDirectPort,
	}
	if !isAutomaticDirectOnlyToken(base) {
		t.Fatal("automatic direct-only token was not recognized")
	}

	withRelay := base
	withRelay.RelayURL = "https://relay.example.test"
	if isAutomaticDirectOnlyToken(withRelay) {
		t.Fatal("mixed direct+relay token must not disable relay TLS verification")
	}

	customPort := base
	customPort.DirectURL = "https://192.0.2.10:443"
	if isAutomaticDirectOnlyToken(customPort) {
		t.Fatal("explicit direct endpoint on a different port must not be treated as automatic")
	}

	hostname := base
	hostname.DirectURL = "https://server.example.test:" + autoMasqueDirectPort
	if isAutomaticDirectOnlyToken(hostname) {
		t.Fatal("hostname-based explicit endpoint must not be treated as automatic")
	}
}

func TestConfigureAutoMasqueDirectClient(t *testing.T) {
	priv := key.NewNode()
	blob, err := (tailcat.MasqueConnInfo{
		Version:           1,
		ServerPublic:      priv.Public(),
		ServerDiscoPublic: tailcat.DiscoPublicForNode(priv).DiscoPublic,
		DirectURL:         "https://192.0.2.10:" + autoMasqueDirectPort,
	}).ConnBlob()
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("MASQUECAT_INSECURE_SKIP_VERIFY", "")
	configureAutoMasqueDirectClient([]string{"tailcat", string(blob)})
	if got := os.Getenv("MASQUECAT_INSECURE_SKIP_VERIFY"); got != "1" {
		t.Fatalf("MASQUECAT_INSECURE_SKIP_VERIFY = %q, want 1", got)
	}
}
