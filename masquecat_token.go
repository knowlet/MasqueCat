package tailcat

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"tailscale.com/types/key"
)

const masqueConnBlobPrefix = "mc"

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
}

type masqueWireConnInfo struct {
	Version           uint8           `json:"v"`
	ServerPublic      key.NodePublic  `json:"k"`
	ServerDiscoPublic key.DiscoPublic `json:"d"`
	DirectURL         string          `json:"p,omitempty"`
	RelayURL          string          `json:"r,omitempty"`
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
	return MasqueConnBlob(masqueConnBlobPrefix + base64.RawURLEncoding.EncodeToString(b)), nil
}

// ParseMasqueConnBlob parses a MasqueCat connection token.
func ParseMasqueConnBlob(blob MasqueConnBlob) (MasqueConnInfo, error) {
	var zero MasqueConnInfo
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
	if u.Host == "" {
		return fmt.Errorf("%s MASQUE URL has no host", kind)
	}
	if u.User != nil {
		return fmt.Errorf("%s MASQUE URL must not contain userinfo", kind)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s MASQUE URL must not contain query or fragment", kind)
	}
	return nil
}
