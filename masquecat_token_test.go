package tailcat

import (
	"strings"
	"testing"

	"tailscale.com/types/key"
)

func TestMasqueConnBlobRoundTrip(t *testing.T) {
	priv := key.NewNode()
	ci := MasqueConnInfo{
		Version:           1,
		ServerPublic:      priv.Public(),
		ServerDiscoPublic: DiscoPublicForNode(priv).DiscoPublic,
		DirectURL:         "https://server.example:443",
		RelayURL:          "https://relay.example:443",
	}
	blob, err := ci.ConnBlob()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(blob), "mc") {
		t.Fatalf("token = %q, want mc prefix", blob)
	}
	got, err := ParseMasqueConnBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != ci.Version || got.ServerPublic != ci.ServerPublic || got.ServerDiscoPublic != ci.ServerDiscoPublic || got.DirectURL != ci.DirectURL || got.RelayURL != ci.RelayURL {
		t.Fatalf("round trip mismatch: got %#v, want %#v", got, ci)
	}
}

func TestMasqueConnBlobRejectsTailcatToken(t *testing.T) {
	_, err := ParseMasqueConnBlob("tcdeadbeef")
	if err == nil || !strings.Contains(err.Error(), "Tailcat token") {
		t.Fatalf("error = %v, want Tailcat token error", err)
	}
}

func TestMasqueConnBlobRequiresHTTPS(t *testing.T) {
	priv := key.NewNode()
	_, err := (MasqueConnInfo{
		Version:           1,
		ServerPublic:      priv.Public(),
		ServerDiscoPublic: DiscoPublicForNode(priv).DiscoPublic,
		RelayURL:          "http://relay.example",
	}).ConnBlob()
	if err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("error = %v, want https validation error", err)
	}
}
