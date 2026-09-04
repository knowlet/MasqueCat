//go:build !js

package tailcat

import (
	"net/url"
	"testing"
)

func TestMasqueTemplateURLPreservesBasePath(t *testing.T) {
	raw, err := masqueTemplateURL("https://relay.example/base/path/?ignored=1#fragment")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if want := "/base/path" + masquePathTemplate; u.Path != want {
		t.Fatalf("template path = %q, want %q", u.Path, want)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		t.Fatalf("template retained query/fragment: query=%q fragment=%q", u.RawQuery, u.Fragment)
	}
}

func TestMasqueTemplateURLRootPathUnchanged(t *testing.T) {
	raw, err := masqueTemplateURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != masquePathTemplate {
		t.Fatalf("root template path = %q, want %q", u.Path, masquePathTemplate)
	}
}
