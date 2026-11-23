//go:build js

package tailcat

import (
	"strings"
	"syscall/js"
	"testing"
)

func TestJSConstructorExceptionBecomesError(t *testing.T) {
	ctor := js.Global().Get("URL")
	if ctor.Type() != js.TypeFunction {
		t.Fatal("URL constructor missing")
	}
	_, err := callJSConstructor(ctor, "https://999.999.999.999")
	if err == nil {
		t.Fatal("expected constructor exception to become an error")
	}
	if strings.Contains(err.Error(), "999.999.999.999") {
		t.Fatalf("constructor error echoes URL: %v", err)
	}
	v, err := callJSConstructor(ctor, "https://example.com")
	if err != nil || v.Type() != js.TypeObject {
		t.Fatalf("valid URL: value=%v err=%v", v.Type(), err)
	}

	for _, raw := range []string{
		"https://999.999.999.999/.well-known/masquecat/webtransport",
		"https://[gggg::1]/.well-known/masquecat/webtransport",
		"https://a\u200cb.example/.well-known/masquecat/webtransport",
	} {
		_, err := newWebTransport(ctor, raw)
		if err == nil || strings.Contains(err.Error(), "999") || strings.Contains(err.Error(), "gggg") || strings.Contains(err.Error(), "example") {
			t.Fatalf("newWebTransport(%q) = %v", raw, err)
		}
	}
}
