//go:build !js

package tailcat

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/types/key"
)

func TestMasqueAuthenticatorRejectsZeroIdentityWithoutPanic(t *testing.T) {
	auth := newMasqueAuthenticator(key.NewNode())
	req := httptest.NewRequest(http.MethodConnect, "https://relay.example/", nil)
	req.Header.Set(masqueProofHeader, "AA")
	rec := httptest.NewRecorder()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero node identity caused panic: %v", r)
		}
	}()
	if auth.authorize(rec, req, key.NodePublic{}, key.NodePublic{}, masqueModeRelay) {
		t.Fatal("zero node identity unexpectedly authorized")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := len(auth.pending); got != 0 {
		t.Fatalf("zero identity allocated %d pending challenges, want 0", got)
	}
}
