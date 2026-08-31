//go:build !js

package tailcat

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/types/key"
)

func TestParseConnectUDPRequestAcceptsConfiguredPathPrefix(t *testing.T) {
	target := key.NewNode().Public()
	targetHost, targetPort, err := net.SplitHostPort(masqueTarget(target))
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate, err := masqueTemplateFor("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}

	for _, prefix := range []string{"", "/base/path"} {
		t.Run(prefix, func(t *testing.T) {
			requestURL := "https://relay.example" + prefix + "/.well-known/masque/udp/" + targetHost + "/" + targetPort + "/"
			req, err := http.NewRequest(http.MethodConnect, requestURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Proto = "connect-udp"
			req.Host = req.URL.Host

			rw := httptest.NewRecorder()
			got, ok := parseConnectUDPRequest(rw, req, rootTemplate)
			if !ok {
				t.Fatalf("parseConnectUDPRequest(%q) rejected prefixed request: status=%d body=%q", prefix, rw.Code, rw.Body.String())
			}
			if got.Target != masqueTarget(target) {
				t.Fatalf("target = %q, want %q", got.Target, masqueTarget(target))
			}
		})
	}
}
