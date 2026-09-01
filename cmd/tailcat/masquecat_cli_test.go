package main

import (
	"strings"
	"testing"

	"tailscale.com/types/logger"
)

func TestMasqueCLIIsDefaultServerTransport(t *testing.T) {
	t.Setenv("TAILCAT_LEGACY_DERP", "")
	newRootCommand()
	if *flagLegacyDERP {
		t.Fatal("legacy DERP unexpectedly enabled by default")
	}
}

func TestMasqueCLIFlagsReadEnvironment(t *testing.T) {
	t.Setenv("MASQUECAT_RELAY_URL", "https://relay.example.test")
	t.Setenv("MASQUECAT_DIRECT_URL", "https://server.example.test")
	t.Setenv("MASQUECAT_DIRECT_LISTEN", ":443")
	newRootCommand()
	if got := *flagMasqueRelayURL; got != "https://relay.example.test" {
		t.Fatalf("relay URL = %q", got)
	}
	if got := *flagMasqueDirectURL; got != "https://server.example.test" {
		t.Fatalf("direct URL = %q", got)
	}
	if got := *flagMasqueDirectListen; got != ":443" {
		t.Fatalf("direct listen = %q", got)
	}
}

func TestMasqueServerWithoutEndpointFailsClosed(t *testing.T) {
	t.Setenv("MASQUECAT_RELAY_URL", "")
	t.Setenv("MASQUECAT_DIRECT_URL", "")
	newRootCommand()
	err := masqueServer(logger.Discard, "")
	if err == nil {
		t.Fatal("expected endpoint configuration error")
	}
	if !strings.Contains(err.Error(), "MASQUECAT_RELAY_URL") {
		t.Fatalf("error %q does not explain how to configure a relay", err)
	}
}

func TestAddrBlobArgAcceptsMasquePrefix(t *testing.T) {
	newRootCommand()
	const blob = "mc-test-token"
	if got := string(addrBlobArg(blob)); got != blob {
		t.Fatalf("addrBlobArg(%q) = %q", blob, got)
	}
}
