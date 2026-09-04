package tailcat

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"tailscale.com/types/key"
)

const (
	masqueConnBlobPrefix           = "mc"
	maxMasqueConnBlobLen           = 8 << 10
	masqueTLSCertPinFragmentPrefix = "sha256="
)

type masqueTLSCertPin [sha256.Size]byte

func (pin masqueTLSCertPin) matchesCertificate(raw []byte) bool {
	return sha256.Sum256(raw) == pin
}

// MasqueConnBlob is a self-contained MasqueCat server address.
// It carries the server's WireGuard identity and the explicitly configured
// MASQUE paths that a client may use. It intentionally contains no discovered
// NAT endpoints.
type MasqueConnBlob string

// MasqueConnInfo describes the public information required to reach a
// MasqueCat server. At least one of DirectURL or RelayURL must be set.
type MasqueConnInfo struct {
	Version           uint8
	ServerPublic      key.NodePublic
	ServerDiscoPublic key.DiscoPublic
	DirectURL         string
	RelayURL          string

	// AutomaticDirect marks the direct-only endpoint as one synthesized by the
	// tailcat CLI with its local self-signed carrier certificate. Automatic
	// direct URLs must carry an exact SHA-256 certificate pin in their fragment;
	// the marker alone never authorizes generic TLS verification bypass.
	AutomaticDirect bool
}

type masqueWireConnInfo struct {
	Version           uint8           `json:"v"`
	ServerPublic      key.NodePublic  `json:"k"`
	ServerDiscoPublic key.DiscoPublic `json:"d"`
	DirectURL         string          `json:"p,omitempty"`
	RelayURL          string          `json:"r,omitempty"`
	AutomaticDirect   bool            `json:"a,omitempty"`
}

// ConnBlob serializes ci to the compact mc-prefixed token used by MasqueCat.
func (ci MasqueConnInfo) ConnBlob() (MasqueConnBlob, error) {
	if ci.Version == 0 {
		ci.Version = 1
	}
	if err := ci.validate(); err != nil {
		return "", err
	}
	w := masqueWireConnInfo(ci)
	b, err := json.Marshal(w)
	if err != nil {
		return "", fmt.Errorf("marshal MasqueCat connection info: %w", err)
	}
	blob := MasqueConnBlob(masqueConnBlobPrefix + base64.RawURLEncoding.EncodeToString(b))
	if len(blob) > maxMasqueConnBlobLen {
		return "", fmt.Errorf("MasqueCat token exceeds %d-byte limit", maxMasqueConnBlobLen)
	}
	return blob, nil
}

// ParseMasqueConnBlob parses a MasqueCat connection token.
func ParseMasqueConnBlob(blob MasqueConnBlob) (MasqueConnInfo, error) {
	var zero MasqueConnInfo
	if len(blob) > maxMasqueConnBlobLen {
		return zero, fmt.Errorf("MasqueCat token exceeds %d-byte limit", maxMasqueConnBlobLen)
	}
	rest, ok := strings.CutPrefix(string(blob), masqueConnBlobPrefix)
	if !ok {
		if strings.HasPrefix(string(blob), "tc") {
			return zero, errors.New("this is a Tailcat token, not a MasqueCat token")
		}
		return zero, errors.New("server address doesn't start with \"mc\"")
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return zero, fmt.Errorf("decode MasqueCat token: %w", err)
	}
	var w masqueWireConnInfo
	if err := json.Unmarshal(b, &w); err != nil {
		return zero, fmt.Errorf("decode MasqueCat connection info: %w", err)
	}
	ci := MasqueConnInfo(w)
	if err := ci.validate(); err != nil {
		return zero, err
	}
	return ci, nil
}

func (ci MasqueConnInfo) validate() error {
	if ci.Version != 1 {
		return fmt.Errorf("unsupported MasqueCat token version %d", ci.Version)
	}
	if ci.ServerPublic.IsZero() {
		return errors.New("MasqueCat token has no server node key")
	}
	if ci.ServerDiscoPublic.IsZero() {
		return errors.New("MasqueCat token has no server disco key")
	}
	if ci.DirectURL == "" && ci.RelayURL == "" {
		return errors.New("MasqueCat token has neither a direct nor relay endpoint")
	}
	if ci.AutomaticDirect && (ci.DirectURL == "" || ci.RelayURL != "") {
		return errors.New("MasqueCat automatic-direct marker requires a direct-only endpoint")
	}
	if ci.DirectURL != "" {
		if err := validateMasqueURL("direct", ci.DirectURL); err != nil {
			return err
		}
	}
	if ci.RelayURL != "" {
		if err := validateMasqueURL("relay", ci.RelayURL); err != nil {
			return err
		}
	}
	if ci.AutomaticDirect {
		_, pinned, err := masqueTLSCertPinFromURL(ci.DirectURL)
		if err != nil {
			return fmt.Errorf("MasqueCat automatic-direct TLS pin: %w", err)
		}
		if !pinned {
			return errors.New("MasqueCat automatic-direct endpoint requires a SHA-256 TLS certificate pin")
		}
	}
	return nil
}

func validateMasqueURL(kind, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid %s MASQUE URL: %w", kind, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s MASQUE URL must use https", kind)
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%s MASQUE URL has no hostname", kind)
	}
	if u.User != nil {
		return fmt.Errorf("%s MASQUE URL must not contain userinfo", kind)
	}
	if u.RawQuery != "" {
		return fmt.Errorf("%s MASQUE URL must not contain query", kind)
	}
	if u.Fragment != "" {
		if kind != "direct" {
			return fmt.Errorf("%s MASQUE URL must not contain fragment", kind)
		}
		if _, ok, err := masqueTLSCertPinFromURL(raw); err != nil {
			return fmt.Errorf("direct MASQUE URL has invalid TLS certificate pin: %w", err)
		} else if !ok {
			return errors.New("direct MASQUE URL fragment must contain a SHA-256 TLS certificate pin")
		}
	}
	return nil
}

func masqueTLSCertPinFromURL(raw string) (pin masqueTLSCertPin, ok bool, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return pin, false, err
	}
	if u.Fragment == "" {
		return pin, false, nil
	}
	encoded, found := strings.CutPrefix(u.Fragment, masqueTLSCertPinFragmentPrefix)
	if !found || encoded == "" {
		return pin, false, fmt.Errorf("fragment must be %s<base64url-sha256>", masqueTLSCertPinFragmentPrefix)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return pin, false, fmt.Errorf("decode SHA-256 certificate pin: %w", err)
	}
	if len(decoded) != len(pin) {
		return pin, false, fmt.Errorf("SHA-256 certificate pin is %d bytes, want %d", len(decoded), len(pin))
	}
	copy(pin[:], decoded)
	return pin, true, nil
}
