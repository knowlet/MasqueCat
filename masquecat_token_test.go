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
	if got != ci {
		t.Fatalf("round trip mismatch: got %#v, want %#v", got, ci)
	}
}

func TestMasqueConnBlobAutomaticDirectMarker(t *testing.T) {
	priv := key.NewNode()
	ci := MasqueConnInfo{
		Version:           1,
		ServerPublic:      priv.Public(),
		ServerDiscoPublic: DiscoPublicForNode(priv).DiscoPublic,
		DirectURL:         "https://192.0.2.10:4433#sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		AutomaticDirect:   true,
	}
	blob, err := ci.ConnBlob()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMasqueConnBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got != ci {
		t.Fatalf("automatic-direct marker did not round trip: got %#v, want %#v", got, ci)
	}

	ci.RelayURL = "https://relay.example:443"
	if _, err := ci.ConnBlob(); err == nil || !strings.Contains(err.Error(), "direct-only") {
		t.Fatalf("automatic direct + relay error = %v, want direct-only validation error", err)
	}
}

func TestMasqueConnBlobAutomaticDirectRequiresCertificatePin(t *testing.T) {
	priv := key.NewNode()
	base := MasqueConnInfo{
		Version:           1,
		ServerPublic:      priv.Public(),
		ServerDiscoPublic: DiscoPublicForNode(priv).DiscoPublic,
		AutomaticDirect:   true,
	}

	ci := base
	ci.DirectURL = "https://192.0.2.10:4433"
	if _, err := ci.ConnBlob(); err == nil || !strings.Contains(err.Error(), "certificate pin") {
		t.Fatalf("missing-pin error = %v, want certificate pin validation error", err)
	}

	ci.DirectURL = "https://192.0.2.10:4433#sha256=too-short"
	if _, err := ci.ConnBlob(); err == nil || !strings.Contains(err.Error(), "certificate pin") {
		t.Fatalf("bad-pin error = %v, want certificate pin validation error", err)
	}
}

func TestMasqueConnBlobExplicit4433IsNotAutomatic(t *testing.T) {
	priv := key.NewNode()
	ci := MasqueConnInfo{
		Version:           1,
		ServerPublic:      priv.Public(),
		ServerDiscoPublic: DiscoPublicForNode(priv).DiscoPublic,
		DirectURL:         "https://192.0.2.10:4433",
	}
	blob, err := ci.ConnBlob()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMasqueConnBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.AutomaticDirect {
		t.Fatal("explicit IP:4433 endpoint must not be inferred to be automatic")
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
