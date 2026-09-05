//go:build !js

package tailcat

import (
	"crypto/tls"
	"net/http"
	"testing"

	"golang.org/x/net/http2"
)

// A nil GetConfigForClient result means crypto/tls keeps using the parent
// config, which must already carry the MASQUE H2 ALPN and TLS 1.3 floor.
func TestMasqueHTTP2DynamicTLSNilSelectionUsesH2Parent(t *testing.T) {
	base := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return nil, nil
		},
	}
	srv, err := newMasqueHTTP2Server(base, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := srv.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if selected != nil {
		t.Fatalf("GetConfigForClient = %#v, want nil to retain parent config", selected)
	}
	if srv.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("parent MinVersion = %x, want TLS 1.3", srv.TLSConfig.MinVersion)
	}
	if len(srv.TLSConfig.NextProtos) != 1 || srv.TLSConfig.NextProtos[0] != http2.NextProtoTLS {
		t.Fatalf("parent NextProtos = %v, want [%s]", srv.TLSConfig.NextProtos, http2.NextProtoTLS)
	}
}
