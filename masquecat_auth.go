//go:build !js

package tailcat

import (
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"tailscale.com/types/key"
)

const (
	masqueChallengeHeader      = "Masquecat-Challenge"
	masqueVerifierHeader       = "Masquecat-Verifier"
	masqueProofHeader          = "Masquecat-Proof"
	masqueChallengeTTL         = 30 * time.Second
	masqueMaxPendingChallenges = 1024
)

type masqueChallenge struct {
	src     key.NodePublic
	target  key.NodePublic
	mode    string
	expires time.Time
}

type masqueAuthenticator struct {
	priv key.NodePrivate

	mu      sync.Mutex
	pending map[string]masqueChallenge
}

func newMasqueAuthenticator(priv key.NodePrivate) *masqueAuthenticator {
	if priv.IsZero() {
		priv = key.NewNode()
	}
	return &masqueAuthenticator{
		priv:    priv,
		pending: make(map[string]masqueChallenge),
	}
}

func (a *masqueAuthenticator) authorize(w http.ResponseWriter, r *http.Request, src, target key.NodePublic, mode string) bool {
	if proof := r.Header.Get(masqueProofHeader); proof != "" && a.verify(proof, src, target, mode) {
		return true
	}
	challenge, err := a.issue(src, target, mode)
	if err != nil {
		http.Error(w, "failed to create MasqueCat authentication challenge", http.StatusInternalServerError)
		return false
	}
	w.Header().Set(masqueChallengeHeader, challenge)
	w.Header().Set(masqueVerifierHeader, a.priv.Public().String())
	http.Error(w, "MasqueCat node-key proof required", http.StatusUnauthorized)
	return false
}

func (a *masqueAuthenticator) issue(src, target key.NodePublic, mode string) (string, error) {
	var nonce [32]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate MasqueCat challenge: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(nonce[:])
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range a.pending {
		if !v.expires.After(now) {
			delete(a.pending, k)
		}
	}
	if len(a.pending) >= masqueMaxPendingChallenges {
		for k := range a.pending {
			delete(a.pending, k)
			break
		}
	}
	a.pending[token] = masqueChallenge{
		src:     src,
		target:  target,
		mode:    mode,
		expires: now.Add(masqueChallengeTTL),
	}
	return token, nil
}

func (a *masqueAuthenticator) verify(encodedProof string, src, target key.NodePublic, mode string) bool {
	proof, err := base64.RawURLEncoding.DecodeString(encodedProof)
	if err != nil {
		return false
	}
	cleartext, ok := a.priv.OpenFrom(src, proof)
	if !ok {
		return false
	}
	token := string(cleartext)
	now := time.Now()

	a.mu.Lock()
	challenge, ok := a.pending[token]
	if ok {
		delete(a.pending, token)
	}
	a.mu.Unlock()
	if !ok || !challenge.expires.After(now) {
		return false
	}
	return challenge.src == src && challenge.target == target && challenge.mode == mode
}
