//go:build !js

package tailcat

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/types/key"
)

func TestMasqueAuthenticatorProofOfPossession(t *testing.T) {
	verifierPriv := key.NewNode()
	clientPriv := key.NewNode()
	src := clientPriv.Public()
	target := key.NewNode().Public()
	auth := newMasqueAuthenticator(verifierPriv)

	challengeReq := httptest.NewRequest(http.MethodConnect, "https://relay.example/", nil)
	challengeRec := httptest.NewRecorder()
	if auth.authorize(challengeRec, challengeReq, src, target, masqueModeRelay) {
		t.Fatal("request without proof unexpectedly authorized")
	}
	if challengeRec.Code != http.StatusUnauthorized {
		t.Fatalf("challenge status = %d, want %d", challengeRec.Code, http.StatusUnauthorized)
	}
	challenge := challengeRec.Header().Get(masqueChallengeHeader)
	if challenge == "" {
		t.Fatal("challenge header is empty")
	}
	var verifier key.NodePublic
	if err := verifier.UnmarshalText([]byte(challengeRec.Header().Get(masqueVerifierHeader))); err != nil {
		t.Fatalf("parse verifier: %v", err)
	}
	if verifier != verifierPriv.Public() {
		t.Fatalf("verifier = %v, want %v", verifier, verifierPriv.Public())
	}

	proof := base64.RawURLEncoding.EncodeToString(clientPriv.SealTo(verifier, []byte(challenge)))
	proofReq := httptest.NewRequest(http.MethodConnect, "https://relay.example/", nil)
	proofReq.Header.Set(masqueProofHeader, proof)
	proofRec := httptest.NewRecorder()
	if !auth.authorize(proofRec, proofReq, src, target, masqueModeRelay) {
		t.Fatalf("valid node-key proof rejected with status %d", proofRec.Code)
	}

	replayReq := httptest.NewRequest(http.MethodConnect, "https://relay.example/", nil)
	replayReq.Header.Set(masqueProofHeader, proof)
	replayRec := httptest.NewRecorder()
	if auth.authorize(replayRec, replayReq, src, target, masqueModeRelay) {
		t.Fatal("one-time proof replay unexpectedly authorized")
	}

	freshChallenge := replayRec.Header().Get(masqueChallengeHeader)
	if freshChallenge == "" {
		t.Fatal("rejected replay did not issue a fresh challenge")
	}
	attackerPriv := key.NewNode()
	attackerProof := base64.RawURLEncoding.EncodeToString(attackerPriv.SealTo(verifier, []byte(freshChallenge)))
	attackerReq := httptest.NewRequest(http.MethodConnect, "https://relay.example/", nil)
	attackerReq.Header.Set(masqueProofHeader, attackerProof)
	attackerRec := httptest.NewRecorder()
	if auth.authorize(attackerRec, attackerReq, src, target, masqueModeRelay) {
		t.Fatal("proof made with a different private key unexpectedly authorized")
	}
}

func TestMasqueAuthenticatorReusesIdenticalPendingChallenge(t *testing.T) {
	auth := newMasqueAuthenticator(key.NewNode())
	src := key.NewNode().Public()
	target := key.NewNode().Public()

	first, err := auth.issue(src, target, masqueModeDirect, "198.51.100.10")
	if err != nil {
		t.Fatal(err)
	}
	second, err := auth.issue(src, target, masqueModeDirect, "198.51.100.10")
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("identical retry got a new challenge: %q != %q", second, first)
	}
	if got := len(auth.pending); got != 1 {
		t.Fatalf("pending challenges = %d, want 1", got)
	}
}

func TestMasqueAuthenticatorPerSourceLimitReturns429(t *testing.T) {
	auth := newMasqueAuthenticator(key.NewNode())
	src := key.NewNode().Public()

	for i := 0; i <= masqueMaxPendingPerSource; i++ {
		req := httptest.NewRequest(http.MethodConnect, "https://relay.example/", nil)
		req.RemoteAddr = "203.0.113.10:4242"
		rec := httptest.NewRecorder()
		authorized := auth.authorize(rec, req, src, key.NewNode().Public(), masqueModeDirect)
		if authorized {
			t.Fatalf("request %d unexpectedly authorized", i)
		}
		if i < masqueMaxPendingPerSource {
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("request %d status = %d, want %d", i, rec.Code, http.StatusUnauthorized)
			}
			continue
		}
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("rate-limited status = %d, want %d", rec.Code, http.StatusTooManyRequests)
		}
		if got := rec.Header().Get("Retry-After"); got == "" {
			t.Fatal("rate-limited response is missing Retry-After")
		}
	}
}

func TestMasqueAuthenticatorPerRemoteAddressLimit(t *testing.T) {
	auth := newMasqueAuthenticator(key.NewNode())
	const clientID = "198.51.100.20"

	for i := 0; i < masqueMaxPendingPerRemoteAddr; i++ {
		src := key.NewNode().Public()
		if _, err := auth.issue(src, src, masqueModeRelay, clientID); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	src := key.NewNode().Public()
	if _, err := auth.issue(src, src, masqueModeRelay, clientID); !errors.Is(err, errMasqueChallengeLimit) {
		t.Fatalf("overflow error = %v, want %v", err, errMasqueChallengeLimit)
	}
}

func TestMasqueAuthenticatorCapacityNeverEvictsLiveChallenge(t *testing.T) {
	verifierPriv := key.NewNode()
	auth := newMasqueAuthenticator(verifierPriv)
	victimPriv := key.NewNode()
	victimSrc := victimPriv.Public()
	victimTarget := key.NewNode().Public()
	victimToken, err := auth.issue(victimSrc, victimTarget, masqueModeDirect, "victim")
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i < masqueMaxPendingChallenges; i++ {
		src := key.NewNode().Public()
		if _, err := auth.issue(src, src, masqueModeRelay, fmt.Sprintf("client-%d", i)); err != nil {
			t.Fatalf("fill challenge %d: %v", i, err)
		}
	}
	if got := len(auth.pending); got != masqueMaxPendingChallenges {
		t.Fatalf("pending challenges = %d, want %d", got, masqueMaxPendingChallenges)
	}

	overflowSrc := key.NewNode().Public()
	if _, err := auth.issue(overflowSrc, overflowSrc, masqueModeRelay, "overflow"); !errors.Is(err, errMasqueChallengeLimit) {
		t.Fatalf("overflow error = %v, want %v", err, errMasqueChallengeLimit)
	}
	if got := len(auth.pending); got != masqueMaxPendingChallenges {
		t.Fatalf("overflow changed pending size to %d", got)
	}

	proof := base64.RawURLEncoding.EncodeToString(victimPriv.SealTo(verifierPriv.Public(), []byte(victimToken)))
	if !auth.verify(proof, victimSrc, victimTarget, masqueModeDirect) {
		t.Fatal("victim challenge was evicted or otherwise invalidated by capacity pressure")
	}
}
