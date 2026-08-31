//go:build !js

package tailcat

import (
	"encoding/base64"
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
