//go:build !js

package tailcat

import (
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"tailscale.com/types/key"
)

const (
	masqueChallengeHeader         = "Masquecat-Challenge"
	masqueVerifierHeader          = "Masquecat-Verifier"
	masqueProofHeader             = "Masquecat-Proof"
	masqueChallengeTTL            = 30 * time.Second
	masqueMaxPendingChallenges    = 1024
	masqueMaxPendingPerSource     = 4
	masqueMaxPendingPerRemoteAddr = 64
)

var errMasqueChallengeLimit = errors.New("MasqueCat authentication challenge limit reached")

type masqueChallenge struct {
	src      key.NodePublic
	target   key.NodePublic
	mode     string
	clientID string
	expires  time.Time
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
	// Tailscale's NodePrivate.OpenFrom panics for a zero peer public key. Zero
	// source/target identities are never valid MasqueCat peers, so reject them
	// before challenge allocation or proof verification.
	if src.IsZero() || target.IsZero() {
		http.Error(w, "invalid MasqueCat node identity", http.StatusUnauthorized)
		return false
	}
	if proof := r.Header.Get(masqueProofHeader); proof != "" && a.verify(proof, src, target, mode) {
		return true
	}
	challenge, err := a.issue(src, target, mode, masqueChallengeClientID(r))
	if err != nil {
		if errors.Is(err, errMasqueChallengeLimit) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many pending MasqueCat authentication challenges", http.StatusTooManyRequests)
			return false
		}
		http.Error(w, "failed to create MasqueCat authentication challenge", http.StatusInternalServerError)
		return false
	}
	w.Header().Set(masqueChallengeHeader, challenge)
	w.Header().Set(masqueVerifierHeader, a.priv.Public().String())
	http.Error(w, "MasqueCat node-key proof required", http.StatusUnauthorized)
	return false
}

func masqueChallengeClientID(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return "<unknown>"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func (a *masqueAuthenticator) issue(src, target key.NodePublic, mode, clientID string) (string, error) {
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	var sourcePending, addressPending int
	for token, challenge := range a.pending {
		if !challenge.expires.After(now) {
			delete(a.pending, token)
			continue
		}
		if challenge.src == src && challenge.target == target && challenge.mode == mode && challenge.clientID == clientID {
			// Reuse the outstanding challenge for an identical unauthenticated
			// request instead of letting retries consume additional capacity.
			return token, nil
		}
		if challenge.src == src {
			sourcePending++
		}
		if challenge.clientID == clientID {
			addressPending++
		}
	}
	if sourcePending >= masqueMaxPendingPerSource ||
		addressPending >= masqueMaxPendingPerRemoteAddr ||
		len(a.pending) >= masqueMaxPendingChallenges {
		// Never evict a live challenge to make room for an unauthenticated
		// request. The caller can retry after outstanding challenges expire.
		return "", errMasqueChallengeLimit
	}

	var nonce [32]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate MasqueCat challenge: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(nonce[:])
	if _, exists := a.pending[token]; exists {
		// A 256-bit random collision is not expected in practice; fail closed
		// rather than overwrite an unrelated live challenge.
		return "", errors.New("generated duplicate MasqueCat challenge")
	}
	a.pending[token] = masqueChallenge{
		src:      src,
		target:   target,
		mode:     mode,
		clientID: clientID,
		expires:  now.Add(masqueChallengeTTL),
	}
	return token, nil
}

func (a *masqueAuthenticator) verify(encodedProof string, src, target key.NodePublic, mode string) bool {
	if src.IsZero() || target.IsZero() {
		return false
	}
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
