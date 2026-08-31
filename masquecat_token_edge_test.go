package tailcat

import (
	"encoding/base64"
	"strings"
	"testing"

	"tailscale.com/types/key"
)

func validMasqueConnInfoForTest() MasqueConnInfo {
	priv := key.NewNode()
	return MasqueConnInfo{
		Version:           1,
		ServerPublic:      priv.Public(),
		ServerDiscoPublic: DiscoPublicForNode(priv).DiscoPublic,
		RelayURL:          "https://relay.example:443",
	}
}

func TestMasqueConnBlobDefaultsVersion(t *testing.T) {
	ci := validMasqueConnInfoForTest()
	ci.Version = 0
	blob, err := ci.ConnBlob()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMasqueConnBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 {
		t.Fatalf("version = %d, want 1", got.Version)
	}
}

func TestMasqueConnInfoValidationFailures(t *testing.T) {
	base := validMasqueConnInfoForTest()
	tests := []struct {
		name string
		edit func(*MasqueConnInfo)
		want string
	}{
		{name: "unsupported version", edit: func(ci *MasqueConnInfo) { ci.Version = 2 }, want: "unsupported"},
		{name: "missing node key", edit: func(ci *MasqueConnInfo) { ci.ServerPublic = key.NodePublic{} }, want: "no server node key"},
		{name: "missing disco key", edit: func(ci *MasqueConnInfo) { ci.ServerDiscoPublic = key.DiscoPublic{} }, want: "no server disco key"},
		{name: "no paths", edit: func(ci *MasqueConnInfo) { ci.DirectURL, ci.RelayURL = "", "" }, want: "neither"},
		{name: "direct http", edit: func(ci *MasqueConnInfo) { ci.DirectURL = "http://peer.example" }, want: "must use https"},
		{name: "relay no host", edit: func(ci *MasqueConnInfo) { ci.RelayURL = "https:///path" }, want: "no hostname"},
		{name: "relay empty hostname", edit: func(ci *MasqueConnInfo) { ci.RelayURL = "https://:443" }, want: "no hostname"},
		{name: "userinfo", edit: func(ci *MasqueConnInfo) { ci.RelayURL = "https://user:pass@relay.example" }, want: "userinfo"},
		{name: "query", edit: func(ci *MasqueConnInfo) { ci.RelayURL = "https://relay.example?q=1" }, want: "query or fragment"},
		{name: "fragment", edit: func(ci *MasqueConnInfo) { ci.RelayURL = "https://relay.example/#x" }, want: "query or fragment"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ci := base
			tt.edit(&ci)
			_, err := ci.ConnBlob()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestParseMasqueConnBlobMalformed(t *testing.T) {
	if _, err := ParseMasqueConnBlob(MasqueConnBlob("mc" + strings.Repeat("A", maxMasqueConnBlobLen))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized token error = %v, want size-limit rejection", err)
	}

	valid := validMasqueConnInfoForTest()
	blob, err := valid.ConnBlob()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMasqueConnBlob(""); err == nil {
		t.Fatal("empty token unexpectedly accepted")
	}
	if _, err := ParseMasqueConnBlob("mcn%%%invalid-base64"); err == nil {
		t.Fatal("invalid base64 unexpectedly accepted")
	}
	badJSON := MasqueConnBlob("mc" + base64.RawURLEncoding.EncodeToString([]byte("not-json")))
	if _, err := ParseMasqueConnBlob(badJSON); err == nil {
		t.Fatal("invalid JSON unexpectedly accepted")
	}

	// Truncation should fail rather than silently decoding partial state.
	for i := len(blob) - 1; i > 2 && i > len(blob)-12; i-- {
		if _, err := ParseMasqueConnBlob(blob[:i]); err == nil {
			t.Fatalf("truncated token at %d unexpectedly accepted", i)
		}
	}
}

func TestValidateMasqueURLAcceptsExplicitPortAndPath(t *testing.T) {
	for _, raw := range []string{
		"https://relay.example",
		"https://relay.example:8443",
		"https://relay.example/base/path",
		"https://[2001:db8::1]:443",
	} {
		if err := validateMasqueURL("relay", raw); err != nil {
			t.Errorf("validateMasqueURL(%q): %v", raw, err)
		}
	}
}
