//go:build !js

package tailcat

import (
	"encoding/base64"
	"strings"
	"testing"

	"tailscale.com/types/key"
)

func TestMasqueProofForChallengeRejectsZeroVerifier(t *testing.T) {
	local := key.NewNode()
	target := key.NewNode().Public()
	zeroVerifier := nodePublicTextPrefix + strings.Repeat("0", 2*key.NodePublicRawLen)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero verifier caused panic: %v", r)
		}
	}()
	_, err := masqueProofForChallenge(local, "challenge", zeroVerifier, target, masqueModeRelay)
	if err == nil || !strings.Contains(err.Error(), "verifier is zero") {
		t.Fatalf("zero verifier error = %v, want explicit rejection", err)
	}
}

func TestMasqueProofForChallengeRelayRoundTrip(t *testing.T) {
	local := key.NewNode()
	verifierPriv := key.NewNode()
	challenge := "challenge-token"

	encoded, err := masqueProofForChallenge(local, challenge, verifierPriv.Public().String(), local.Public(), masqueModeRelay)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	cleartext, ok := verifierPriv.OpenFrom(local.Public(), proof)
	if !ok {
		t.Fatal("verifier could not open generated proof")
	}
	if got := string(cleartext); got != challenge {
		t.Fatalf("proof cleartext = %q, want %q", got, challenge)
	}
}

func TestMasqueProofForChallengeRejectsDirectVerifierMismatch(t *testing.T) {
	local := key.NewNode()
	target := key.NewNode().Public()
	other := key.NewNode().Public()
	_, err := masqueProofForChallenge(local, "challenge", other.String(), target, masqueModeDirect)
	if err == nil || !strings.Contains(err.Error(), "does not match target") {
		t.Fatalf("mismatched verifier error = %v, want target mismatch", err)
	}
}
