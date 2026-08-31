from pathlib import Path

def replace_once(path, old, new):
    p = Path(path)
    s = p.read_text()
    count = s.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}")
    p.write_text(s.replace(old, new, 1))

# 1) Node-key proof of possession for direct and relay MASQUE handlers,
#    and duplicate relay registration rejection.
Path("masquecat_auth.go").write_text(r'''//go:build !js

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
	masqueChallengeHeader       = "Masquecat-Challenge"
	masqueVerifierHeader        = "Masquecat-Verifier"
	masqueProofHeader           = "Masquecat-Proof"
	masqueChallengeTTL          = 30 * time.Second
	masqueMaxPendingChallenges  = 1024
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
''')

Path("masquecat_auth_test.go").write_text(r'''//go:build !js

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
''')

replace_once("masquecat_h3_server.go",
'''func directMasqueHandler(local key.NodePublic, bridge *localDERPBridge, logf logger.Logf) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {''',
'''func directMasqueHandler(localPriv key.NodePrivate, bridge *localDERPBridge, logf logger.Logf) http.Handler {
	local := localPriv.Public()
	auth := newMasqueAuthenticator(localPriv)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {''')

replace_once("masquecat_h3_server.go",
'''		src, err := parseMasqueSource(r)
		if err != nil || src.IsZero() {
			http.Error(w, "invalid MasqueCat source", http.StatusUnauthorized)
			return
		}
		str, err := acceptMasqueStream(w)''',
'''		src, err := parseMasqueSource(r)
		if err != nil || src.IsZero() {
			http.Error(w, "invalid MasqueCat source", http.StatusUnauthorized)
			return
		}
		if !auth.authorize(w, r, src, target, masqueModeDirect) {
			return
		}
		str, err := acceptMasqueStream(w)''')

replace_once("masquecat_h3_server.go",
'''	mu    sync.Mutex
	peers map[key.NodePublic]*relayPeer''',
'''	mu    sync.Mutex
	peers map[key.NodePublic]*relayPeer

	authOnce sync.Once
	auth     *masqueAuthenticator''')

replace_once("masquecat_h3_server.go",
'''func (r *MasqueRelay) logf() logger.Logf {
	if r.Logf != nil {
		return r.Logf
	}
	return func(format string, args ...any) {}
}

// Handler returns the HTTP/3 handler for a MasqueCat relay.''',
'''func (r *MasqueRelay) logf() logger.Logf {
	if r.Logf != nil {
		return r.Logf
	}
	return func(format string, args ...any) {}
}

func (r *MasqueRelay) authenticator() *masqueAuthenticator {
	r.authOnce.Do(func() {
		r.auth = newMasqueAuthenticator(key.NewNode())
	})
	return r.auth
}

// Handler returns the HTTP/3 handler for a MasqueCat relay.''')

replace_once("masquecat_h3_server.go",
'''		src, err := parseMasqueSource(req)
		if err != nil || src != registeredKey {
			http.Error(w, "MasqueCat source does not match registered target", http.StatusUnauthorized)
			return
		}
		str, err := acceptMasqueStream(w)''',
'''		src, err := parseMasqueSource(req)
		if err != nil || src != registeredKey {
			http.Error(w, "MasqueCat source does not match registered target", http.StatusUnauthorized)
			return
		}
		if !r.authenticator().authorize(w, req, src, registeredKey, masqueModeRelay) {
			return
		}
		if r.lookup(registeredKey) != nil {
			http.Error(w, "MasqueCat peer is already registered", http.StatusConflict)
			return
		}
		str, err := acceptMasqueStream(w)''')

replace_once("masquecat_h3_server.go",
'''		peer := &relayPeer{key: registeredKey, fwd: &streamForwarder{str: str}}
		r.register(peer)
		defer r.unregister(peer)''',
'''		peer := &relayPeer{key: registeredKey, fwd: &streamForwarder{str: str}}
		if !r.register(peer) {
			logf("MASQUE relay duplicate registration rejected: %v", peer.key.ShortString())
			return
		}
		defer r.unregister(peer)''')

replace_once("masquecat_h3_server.go",
'''func (r *MasqueRelay) register(p *relayPeer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers == nil {
		r.peers = make(map[key.NodePublic]*relayPeer)
	}
	if old := r.peers[p.key]; old != nil && old != p {
		_ = old.fwd.str.Close()
	}
	r.peers[p.key] = p
}''',
'''func (r *MasqueRelay) register(p *relayPeer) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers == nil {
		r.peers = make(map[key.NodePublic]*relayPeer)
	}
	if old := r.peers[p.key]; old != nil && old != p {
		return false
	}
	r.peers[p.key] = p
	return true
}''')

# 2) HTTP/3 ALPN plus auth challenge/retry using the client's node private key.
replace_once("masquecat_transport.go",
'''import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"''',
'''import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"''')

old_new_path = '''func newMasquePath(ctx context.Context, rawURL string, requestTarget, local key.NodePublic, mode string, logf logger.Logf) (*masquePath, error) {
	tmpl, err := masqueTemplateFor(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := masque.NewRequest(ctx, tmpl, masqueTarget(requestTarget))
	if err != nil {
		return nil, fmt.Errorf("create CONNECT-UDP request: %w", err)
	}
	req.Header().Set(masqueSourceHeader, local.String())
	req.Header().Set(masqueModeHeader, mode)

	u, _ := url.Parse(rawURL)
	tr := &masque.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: u.Hostname(),
		},
		QUICConfig: &quic.Config{EnableDatagrams: true},
	}
	conn, resp, err := tr.Dial(req)
	if err != nil {
		return nil, fmt.Errorf("dial MASQUE endpoint %s: %w", rawURL, err)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		if resp == nil {
			return nil, errors.New("MASQUE endpoint returned no HTTP response")
		}
		return nil, fmt.Errorf("MASQUE endpoint returned %s", resp.Status)
	}
	return &masquePath{local: local, pc: conn, logf: logf}, nil
}'''
new_new_path = '''func newMasquePath(ctx context.Context, rawURL string, requestTarget key.NodePublic, local key.NodePrivate, mode string, logf logger.Logf) (*masquePath, error) {
	tmpl, err := masqueTemplateFor(rawURL)
	if err != nil {
		return nil, err
	}
	localPublic := local.Public()
	newRequest := func(proof string) (*masque.Request, error) {
		req, err := masque.NewRequest(ctx, tmpl, masqueTarget(requestTarget))
		if err != nil {
			return nil, fmt.Errorf("create CONNECT-UDP request: %w", err)
		}
		req.Header().Set(masqueSourceHeader, localPublic.String())
		req.Header().Set(masqueModeHeader, mode)
		if proof != "" {
			req.Header().Set(masqueProofHeader, proof)
		}
		return req, nil
	}

	req, err := newRequest("")
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(rawURL)
	tr := &masque.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: u.Hostname(),
			NextProtos: []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{EnableDatagrams: true},
	}
	conn, resp, err := tr.Dial(req)
	if err != nil && resp != nil && resp.StatusCode == http.StatusUnauthorized {
		if conn != nil {
			_ = conn.Close()
			conn = nil
		}
		challenge := resp.Header.Get(masqueChallengeHeader)
		verifierText := resp.Header.Get(masqueVerifierHeader)
		if challenge == "" || verifierText == "" {
			return nil, errors.New("MASQUE endpoint requested authentication without a challenge")
		}
		var verifier key.NodePublic
		if err := verifier.UnmarshalText([]byte(verifierText)); err != nil {
			return nil, fmt.Errorf("parse MASQUE authentication verifier: %w", err)
		}
		if mode == masqueModeDirect && verifier != requestTarget {
			return nil, errors.New("direct MASQUE authentication verifier does not match target node key")
		}
		proof := base64.RawURLEncoding.EncodeToString(local.SealTo(verifier, []byte(challenge)))
		req, err = newRequest(proof)
		if err != nil {
			return nil, err
		}
		conn, resp, err = tr.Dial(req)
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, fmt.Errorf("dial MASQUE endpoint %s: %w", rawURL, err)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		if conn != nil {
			_ = conn.Close()
		}
		if resp == nil {
			return nil, errors.New("MASQUE endpoint returned no HTTP response")
		}
		return nil, fmt.Errorf("MASQUE endpoint returned %s", resp.Status)
	}
	return &masquePath{local: localPublic, pc: conn, logf: logf}, nil
}'''
replace_once("masquecat_transport.go", old_new_path, new_new_path)

# 3) MasqueServer cleanup/retry and client lifecycle synchronization.
replace_once("masquecat.go",
'''		_ = bridge.Close()
		s.bridge = nil
	}''',
'''		_ = bridge.Close()
		s.cancel = nil
		s.directHTTP = nil
		s.directPC = nil
		s.relayPath = nil
		s.bridge = nil
		s.lb = nil
		s.blob = ""
	}''')

replace_once("masquecat.go",
'''			Handler:         directMasqueHandler(local, bridge, logf),''',
'''			Handler:         directMasqueHandler(priv, bridge, logf),''')

replace_once("masquecat.go",
'''		path, err := newMasquePath(ctx, s.RelayURL, local, local, masqueModeRelay, logf)''',
'''		path, err := newMasquePath(ctx, s.RelayURL, local, priv, masqueModeRelay, logf)''')

replace_once("masquecat.go",
'''	if s.cancel != nil {
		s.cancel()
	}
	var errs []error''',
'''	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	var errs []error''')

replace_once("masquecat.go",
'''	if s.lb != nil {
		errs = append(errs, s.Server.Close())
	}
	if s.bridge != nil {''',
'''	if s.lb != nil {
		errs = append(errs, s.Server.Close())
		s.lb = nil
	}
	if s.bridge != nil {''')

replace_once("masquecat.go",
'''		s.bridge = nil
	}
	return errors.Join(errs...)
}''',
'''		s.bridge = nil
	}
	s.blob = ""
	return errors.Join(errs...)
}''')

replace_once("masquecat.go",
'''func (c *MasqueClient) ensureStarted(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {''',
'''func (c *MasqueClient) ensureStarted(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensureStartedLocked(ctx)
}

func (c *MasqueClient) ensureStartedLocked(ctx context.Context) error {
	if c.started {''')

replace_once("masquecat.go",
'''		path, directErr = newMasquePath(ctx, ci.DirectURL, ci.ServerPublic, local, masqueModeDirect, logf)''',
'''		path, directErr = newMasquePath(ctx, ci.DirectURL, ci.ServerPublic, priv, masqueModeDirect, logf)''')

replace_once("masquecat.go",
'''		path, err = newMasquePath(ctx, ci.RelayURL, local, local, masqueModeRelay, logf)''',
'''		path, err = newMasquePath(ctx, ci.RelayURL, local, priv, masqueModeRelay, logf)''')

old_ops = '''func (c *MasqueClient) Ping(ctx context.Context) (PingResult, error) {
	if err := c.ensureStarted(ctx); err != nil {
		return PingResult{}, err
	}
	return c.base.Ping(ctx)
}

func (c *MasqueClient) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := c.ensureStarted(ctx); err != nil {
		return nil, err
	}
	return c.base.Dial(ctx, network, addr)
}

func (c *MasqueClient) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	if err := c.ensureStarted(ctx); err != nil {
		return nil, err
	}
	return c.base.DialTCPPort(ctx, port)
}

func (c *MasqueClient) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if err := c.ensureStarted(ctx); err != nil {
		return nil, err
	}
	return c.base.DialTCP(ctx, dst)
}

func (c *MasqueClient) DrainTCP(ctx context.Context) error {
	c.mu.Lock()
	base := c.base
	c.mu.Unlock()
	if base == nil {
		return nil
	}
	return base.DrainTCP(ctx)
}

func (c *MasqueClient) Status() *ipnstate.Status {
	c.mu.Lock()
	base := c.base
	c.mu.Unlock()
	if base == nil || base.lb == nil {
		return nil
	}
	return base.lb.Status()
}'''
new_ops = '''func (c *MasqueClient) lockBase(ctx context.Context) (*Client, error) {
	c.mu.Lock()
	if err := c.ensureStartedLocked(ctx); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if c.base == nil {
		c.mu.Unlock()
		return nil, errors.New("masquecat: client closed during startup")
	}
	return c.base, nil
}

func (c *MasqueClient) Ping(ctx context.Context) (PingResult, error) {
	base, err := c.lockBase(ctx)
	if err != nil {
		return PingResult{}, err
	}
	defer c.mu.Unlock()
	return base.Ping(ctx)
}

func (c *MasqueClient) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	base, err := c.lockBase(ctx)
	if err != nil {
		return nil, err
	}
	defer c.mu.Unlock()
	return base.Dial(ctx, network, addr)
}

func (c *MasqueClient) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	base, err := c.lockBase(ctx)
	if err != nil {
		return nil, err
	}
	defer c.mu.Unlock()
	return base.DialTCPPort(ctx, port)
}

func (c *MasqueClient) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	base, err := c.lockBase(ctx)
	if err != nil {
		return nil, err
	}
	defer c.mu.Unlock()
	return base.DialTCP(ctx, dst)
}

func (c *MasqueClient) DrainTCP(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.base == nil {
		return nil
	}
	return c.base.DrainTCP(ctx)
}

func (c *MasqueClient) Status() *ipnstate.Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.base == nil || c.base.lb == nil {
		return nil
	}
	return c.base.lb.Status()
}'''
replace_once("masquecat.go", old_ops, new_ops)

replace_once("masquecat.go",
'''	if c.cancel != nil {
		c.cancel()
	}
	var errs []error''',
'''	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	var errs []error''')

replace_once("masquecat.go",
'''	c.started = false
	return errors.Join(errs...)
}''',
'''	c.pathType = ""
	c.started = false
	return errors.Join(errs...)
}''')

# 4) Token resource bounds and URL validation.
replace_once("masquecat_token.go",
'''const masqueConnBlobPrefix = "mc"''',
'''const (
	masqueConnBlobPrefix = "mc"
	maxMasqueConnBlobLen = 8 << 10
)''')

replace_once("masquecat_token.go",
'''	return MasqueConnBlob(masqueConnBlobPrefix + base64.RawURLEncoding.EncodeToString(b)), nil''',
'''	blob := MasqueConnBlob(masqueConnBlobPrefix + base64.RawURLEncoding.EncodeToString(b))
	if len(blob) > maxMasqueConnBlobLen {
		return "", fmt.Errorf("MasqueCat token exceeds %d-byte limit", maxMasqueConnBlobLen)
	}
	return blob, nil''')

replace_once("masquecat_token.go",
'''func ParseMasqueConnBlob(blob MasqueConnBlob) (MasqueConnInfo, error) {
	var zero MasqueConnInfo
	rest, ok := strings.CutPrefix(string(blob), masqueConnBlobPrefix)''',
'''func ParseMasqueConnBlob(blob MasqueConnBlob) (MasqueConnInfo, error) {
	var zero MasqueConnInfo
	if len(blob) > maxMasqueConnBlobLen {
		return zero, fmt.Errorf("MasqueCat token exceeds %d-byte limit", maxMasqueConnBlobLen)
	}
	rest, ok := strings.CutPrefix(string(blob), masqueConnBlobPrefix)''')

replace_once("masquecat_token.go",
'''	if u.Host == "" {
		return fmt.Errorf("%s MASQUE URL has no host", kind)
	}
	if u.User != nil {''',
'''	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%s MASQUE URL has no hostname", kind)
	}
	if u.User != nil {''')

# 5) Explicit DERP map configuration and compatibility mode headers.
replace_once("cmd/tailcat-web/tailcat-web.go",
'''func main() {
	flag.Parse()

	distDir, err := os.MkdirTemp("", "tailcat-web")''',
'''func main() {
	flag.Parse()
	if *flagDERPMapURL == "" {
		log.Fatal("-derpmap-url is required; tailcat-web has no built-in hosted DERP map default")
	}
	mapReq, err := http.NewRequest(http.MethodGet, *flagDERPMapURL, nil)
	if err != nil || mapReq.URL.Hostname() == "" || (mapReq.URL.Scheme != "http" && mapReq.URL.Scheme != "https") {
		log.Fatalf("invalid -derpmap-url %q: must be an absolute http(s) URL", *flagDERPMapURL)
	}

	distDir, err := os.MkdirTemp("", "tailcat-web")''')

replace_once("cmd/tailcat-web/tailcat-web.go",
'''		req.Header.Set("Tailcat-Mode", r.Header.Get("Tailcat-Mode"))
		res, err := http.DefaultClient.Do(req)''',
'''		if mode := r.Header.Get("Tailcat-Mode"); mode != "" {
			req.Header.Set("Tailcat-Mode", mode)
		}
		if mode := r.Header.Get("MasqueCat-Mode"); mode != "" {
			req.Header.Set("MasqueCat-Mode", mode)
		}
		res, err := http.DefaultClient.Do(req)''')

replace_once("tailcat.go",
'''	req.Header.Set("MasqueCat-Mode", mode)
	if cachedETag != "" {''',
'''	req.Header.Set("MasqueCat-Mode", mode)
	req.Header.Set("Tailcat-Mode", mode)
	if cachedETag != "" {''')

old_web = '''// canonicalDERPMapURL is the public tailcat DERP map, which allows
// cross-origin fetches with CORS headers.
const canonicalDERPMapURL = "https://tailcat.dev/derpmap.json";

// pickDERPMapURL returns the DERP map URL to hand to
// tailcatListen/tailcatDial: the ?derpmap= query parameter if given,
// and the canonical public map when hosted on GitHub Pages, which
// serves no map of its own. Anywhere else (cmd/tailcat-web, the
// integration tests, or this page copied onto some other site), it
// prefers a same-origin derpmap.json if the host serves one and
// otherwise falls back to the canonical map.
async function pickDERPMapURL() {
  if (params.get("derpmap")) {
    return new URL(params.get("derpmap"), location.href).toString();
  }
  if (location.hostname.endsWith(".github.io")) {
    return canonicalDERPMapURL;
  }
  const sameOrigin = new URL("derpmap.json", location.href).toString();
  try {
    const resp = await fetch(sameOrigin, { method: "HEAD" });
    if (resp.ok) {
      return sameOrigin;
    }
  } catch (e) {}
  return canonicalDERPMapURL;
}'''
new_web = '''// pickDERPMapURL returns the explicitly configured DERP map URL, or a
// same-origin map served by cmd/tailcat-web / an embedding application.
// There is intentionally no hosted-service fallback.
async function pickDERPMapURL() {
  if (params.get("derpmap")) {
    return new URL(params.get("derpmap"), location.href).toString();
  }
  const sameOrigin = new URL("derpmap.json", location.href).toString();
  try {
    const resp = await fetch(sameOrigin, { method: "HEAD" });
    if (resp.ok) {
      return sameOrigin;
    }
  } catch (e) {}
  throw new Error("No DERP map configured; provide ?derpmap=https://... or serve /derpmap.json on the same origin");
}'''
replace_once("web/app.js", old_web, new_web)

# 6) Ground-truth wire-format assertions for fuzz seed formats.
replace_once("masquecat_fuzz_test.go",
'''import (
	"bytes"
	"testing"

	"tailscale.com/types/key"
)''',
'''import (
	"bytes"
	"testing"

	"go4.org/mem"
	"tailscale.com/types/key"
)''')

replace_once("masquecat_fuzz_test.go",
'''func FuzzDecodeMasquePacket(f *testing.F) {
	src := key.NewNode().Public()''',
'''func FuzzDecodeMasquePacket(f *testing.F) {
	var srcRaw, dstRaw [key.NodePublicRawLen]byte
	for i := range srcRaw {
		srcRaw[i] = 0x11
		dstRaw[i] = 0x22
	}
	src := key.NodePublicFromRaw32(mem.B(srcRaw[:]))
	dst := key.NodePublicFromRaw32(mem.B(dstRaw[:]))
	groundTruth := append([]byte{masquePacketVersion}, srcRaw[:]...)
	groundTruth = append(groundTruth, dstRaw[:]...)
	groundTruth = append(groundTruth, []byte("wire")...)
	if got := encodeMasquePacket(src, dst, []byte("wire")); !bytes.Equal(got, groundTruth) {
		f.Fatalf("canonical packet encoding changed:\n got %x\nwant %x", got, groundTruth)
	}
	decoded, err := decodeMasquePacket(groundTruth)
	if err != nil {
		f.Fatalf("canonical packet rejected: %v", err)
	}
	if decoded.src != src || decoded.dst != dst || string(decoded.payload) != "wire" {
		f.Fatalf("canonical packet decoded incorrectly: %#v", decoded)
	}

	src = key.NewNode().Public()''')

replace_once("masquecat_fuzz_test.go",
'''func FuzzParseMasqueConnBlob(f *testing.F) {
	priv := key.NewNode()
	valid, err := (MasqueConnInfo{''',
'''func FuzzParseMasqueConnBlob(f *testing.F) {
	var nodeRaw, discoRaw [32]byte
	for i := range nodeRaw {
		nodeRaw[i] = 0x11
		discoRaw[i] = 0x22
	}
	canonicalInfo := MasqueConnInfo{
		Version:           1,
		ServerPublic:      key.NodePublicFromRaw32(mem.B(nodeRaw[:])),
		ServerDiscoPublic: key.DiscoPublicFromRaw32(mem.B(discoRaw[:])),
		DirectURL:         "https://peer.example:443",
		RelayURL:          "https://relay.example:443",
	}
	const canonicalToken = "mceyJ2IjoxLCJrIjoibm9kZWtleToxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwiZCI6ImRpc2Nva2V5OjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLCJwIjoiaHR0cHM6Ly9wZWVyLmV4YW1wbGU6NDQzIiwiciI6Imh0dHBzOi8vcmVsYXkuZXhhbXBsZTo0NDMifQ"
	canonical, err := canonicalInfo.ConnBlob()
	if err != nil {
		f.Fatal(err)
	}
	if canonical != canonicalToken {
		f.Fatalf("canonical token encoding changed:\n got %s\nwant %s", canonical, canonicalToken)
	}
	parsedCanonical, err := ParseMasqueConnBlob(canonicalToken)
	if err != nil {
		f.Fatalf("canonical token rejected: %v", err)
	}
	if parsedCanonical != canonicalInfo {
		f.Fatalf("canonical token decoded incorrectly: got %#v, want %#v", parsedCanonical, canonicalInfo)
	}

	priv := key.NewNode()
	valid, err := (MasqueConnInfo{''')

# 7) Registry behavior test, lifecycle retry test, token edge cases.
replace_once("masquecat_transport_test.go",
'''func TestMasqueRelayRegistryReplacement(t *testing.T) {
	r := new(MasqueRelay)
	k := key.NewNode().Public()
	oldStream := newFakeMasqueDatagramStream()
	newStream := newFakeMasqueDatagramStream()
	oldPeer := &relayPeer{key: k, fwd: &streamForwarder{str: oldStream}}
	newPeer := &relayPeer{key: k, fwd: &streamForwarder{str: newStream}}

	r.register(oldPeer)
	if got := r.lookup(k); got != oldPeer {
		t.Fatalf("lookup after first register = %p, want %p", got, oldPeer)
	}
	r.register(newPeer)
	if got := r.lookup(k); got != newPeer {
		t.Fatalf("lookup after replacement = %p, want %p", got, newPeer)
	}
	oldStream.mu.Lock()
	closed := oldStream.closed
	oldStream.mu.Unlock()
	if closed != 1 {
		t.Fatalf("old stream close count = %d, want 1", closed)
	}

	// Unregistering a stale peer must not remove its replacement.
	r.unregister(oldPeer)
	if got := r.lookup(k); got != newPeer {
		t.Fatalf("stale unregister removed replacement: got %p, want %p", got, newPeer)
	}
	r.unregister(newPeer)
	if got := r.lookup(k); got != nil {
		t.Fatalf("lookup after unregister = %p, want nil", got)
	}
}''',
'''func TestMasqueRelayRegistryRejectsDuplicate(t *testing.T) {
	r := new(MasqueRelay)
	k := key.NewNode().Public()
	oldStream := newFakeMasqueDatagramStream()
	newStream := newFakeMasqueDatagramStream()
	oldPeer := &relayPeer{key: k, fwd: &streamForwarder{str: oldStream}}
	newPeer := &relayPeer{key: k, fwd: &streamForwarder{str: newStream}}

	if !r.register(oldPeer) {
		t.Fatal("first registration rejected")
	}
	if got := r.lookup(k); got != oldPeer {
		t.Fatalf("lookup after first register = %p, want %p", got, oldPeer)
	}
	if r.register(newPeer) {
		t.Fatal("duplicate live registration unexpectedly replaced existing peer")
	}
	if got := r.lookup(k); got != oldPeer {
		t.Fatalf("lookup after duplicate = %p, want original %p", got, oldPeer)
	}
	oldStream.mu.Lock()
	closed := oldStream.closed
	oldStream.mu.Unlock()
	if closed != 0 {
		t.Fatalf("original stream close count = %d, want 0", closed)
	}

	r.unregister(newPeer)
	if got := r.lookup(k); got != oldPeer {
		t.Fatalf("stale unregister removed original: got %p, want %p", got, oldPeer)
	}
	r.unregister(oldPeer)
	if got := r.lookup(k); got != nil {
		t.Fatalf("lookup after unregister = %p, want nil", got)
	}
}''')

replace_once("masquecat_lifecycle_test.go",
'''import (
	"context"
	"strings"
	"testing"
)''',
'''import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"testing"
)''')

replace_once("masquecat_lifecycle_test.go",
'''func TestMasqueServerConnBlobBeforeStartIsEmpty(t *testing.T) {''',
'''func TestMasqueServerStartCanRetryAfterPostCoreFailure(t *testing.T) {
	tlsServer := httptest.NewTLSServer(nil)
	cert := tlsServer.Certificate()
	tlsServer.Close()
	s := &MasqueServer{
		DirectURL:    "https://127.0.0.1:443",
		DirectListen: "bad-listen-address",
		DirectTLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{cert.Raw},
			}},
		},
	}
	if err := s.Start(); err == nil || !strings.Contains(err.Error(), "listen for direct MASQUE") {
		t.Fatalf("first Start error = %v, want direct listen failure", err)
	}
	s.DirectListen = "127.0.0.1:0"
	if err := s.Start(); err != nil {
		t.Fatalf("second Start after cleanup: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close after retry: %v", err)
	}
}

func TestMasqueServerConnBlobBeforeStartIsEmpty(t *testing.T) {''')

replace_once("masquecat_token_edge_test.go",
'''		{name: "relay no host", edit: func(ci *MasqueConnInfo) { ci.RelayURL = "https:///path" }, want: "no host"},''',
'''		{name: "relay no host", edit: func(ci *MasqueConnInfo) { ci.RelayURL = "https:///path" }, want: "no hostname"},
		{name: "relay empty hostname", edit: func(ci *MasqueConnInfo) { ci.RelayURL = "https://:443" }, want: "no hostname"},''')

replace_once("masquecat_token_edge_test.go",
'''func TestParseMasqueConnBlobMalformed(t *testing.T) {
	valid := validMasqueConnInfoForTest()''',
'''func TestParseMasqueConnBlobMalformed(t *testing.T) {
	if _, err := ParseMasqueConnBlob(MasqueConnBlob("mc" + strings.Repeat("A", maxMasqueConnBlobLen))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized token error = %v, want size-limit rejection", err)
	}

	valid := validMasqueConnInfoForTest()''')

# 8) Replace the overbroad/missing runtime-default guard.
Path("upstream_defaults_test.go").write_text(r'''package tailcat

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestNoImplicitDERPMapService(t *testing.T) {
	if DefaultDERPMapURL != "" {
		t.Fatalf("DefaultDERPMapURL must be empty, got %q", DefaultDERPMapURL)
	}
	_, err := FetchDERPMap(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no DERP map URL configured") {
		t.Fatalf("FetchDERPMap without an explicit URL = %v; want explicit-source error", err)
	}

	ci := &ConnInfo{RegionID: 1}
	err = ci.Expand(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no DERP map source configured") {
		t.Fatalf("ConnInfo.Expand without an explicit map source = %v; want explicit-source error", err)
	}
}

// TestNoLegacyServiceDomainHardcodes guards only the runtime surfaces that can
// supply DERP-map defaults. It deliberately does not ban ordinary mentions of
// the upstream Go module and does not scan documentation or test fixtures.
func TestNoLegacyServiceDomainHardcodes(t *testing.T) {
	hostedDomain := "tailcat" + ".dev"
	var violations []string

	isRuntimeSurface := func(path string) bool {
		path = filepath.ToSlash(path)
		switch path {
		case "tailcat.go", "pickregion.go", "pickregion_js.go":
			return true
		}
		return strings.HasPrefix(path, "cmd/") ||
			strings.HasPrefix(path, "web/") ||
			strings.HasPrefix(path, "webdemo/")
	}

	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".github", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !isRuntimeSurface(path) || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		switch strings.ToLower(filepath.Ext(path)) {
		case ".js", ".html":
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(b), hostedDomain) {
				violations = append(violations, path+" contains forbidden hosted-service domain "+hostedDomain)
			}
		case ".go":
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			imports := map[*ast.BasicLit]bool{}
			for _, imp := range f.Imports {
				imports[imp.Path] = true
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || imports[lit] {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err == nil && strings.Contains(s, hostedDomain) {
					pos := fset.Position(lit.Pos())
					violations = append(violations, pos.String()+" contains forbidden hosted-service domain "+hostedDomain)
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		sort.Strings(violations)
		t.Fatalf("hosted-service runtime defaults found:\n%s", strings.Join(violations, "\n"))
	}
}
''')

# 9) CI: full race matrix and the token scope required by only-new-issues.
replace_once(".github/workflows/test.yml",
'''permissions:
  contents: read''',
'''permissions:
  contents: read
  pull-requests: read''')

replace_once(".github/workflows/test.yml",
'''  race:
    needs: module-tidy
    runs-on: ubuntu-latest
    steps:''',
'''  race:
    needs: module-tidy
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:''')

print("review fixes applied")
