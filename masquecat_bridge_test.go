//go:build !js

package tailcat

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestLocalDERPBridgeCertificateMatchesAdvertisedHostname(t *testing.T) {
	bridge, err := newLocalDERPBridge(t.Logf)
	if err != nil {
		t.Fatalf("newLocalDERPBridge: %v", err)
	}
	t.Cleanup(func() {
		if err := bridge.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	region := bridge.Region()
	if region == nil || len(region.Nodes) != 1 {
		t.Fatalf("unexpected local DERP region: %#v", region)
	}
	node := region.Nodes[0]
	cert := bridge.http.Certificate()
	if cert == nil {
		t.Fatal("local DERP TLS server has no certificate")
	}
	if err := cert.VerifyHostname(node.HostName); err != nil {
		t.Fatalf("local DERP certificate does not match advertised hostname %q: %v", node.HostName, err)
	}

	certHash := sha256.Sum256(cert.Raw)
	wantPin := "sha256-raw:" + hex.EncodeToString(certHash[:])
	if node.CertName != wantPin {
		t.Fatalf("CertName = %q, want %q", node.CertName, wantPin)
	}
}
