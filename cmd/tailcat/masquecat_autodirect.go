// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tailscale/tailcat"
)

const autoMasqueDirectPort = "4433"

// initMasqueAutoDirect restores the original Tailcat zero-argument UX for the
// MasqueCat transport: a server can be started without first provisioning a
// relay. In that case we synthesize a direct-only HTTP/3 endpoint from a local
// interface address and a locally generated outer TLS certificate.
//
// The self-signed certificate is deliberately only an outer QUIC carrier
// credential. Direct-only CLI clients authenticate the actual peer end-to-end
// with the node key embedded in the mc token, so they may skip verification of
// this automatically generated outer certificate. Relay and mixed
// direct+relay tokens keep normal TLS verification unless the user explicitly
// opts out with --insecure-skip-verify.
func init() {
	if shouldConfigureAutoMasqueDirect(os.Args) {
		if err := configureAutoMasqueDirect(); err != nil {
			fmt.Fprintf(os.Stderr, "# MasqueCat automatic direct-only setup unavailable: %v\n", err)
		}
	}
	configureAutoMasqueDirectClient(os.Args)
}

func shouldConfigureAutoMasqueDirect(args []string) bool {
	if hasExplicitMasqueEndpoint(args) || os.Getenv("MASQUECAT_RELAY_URL") != "" || os.Getenv("MASQUECAT_DIRECT_URL") != "" {
		return false
	}
	if len(args) == 1 {
		return true
	}
	for _, arg := range args[1:] {
		if arg == "serve" || arg == "recv" || arg == "--serve" || strings.HasPrefix(arg, "--serve=") {
			return true
		}
	}
	return false
}

func hasExplicitMasqueEndpoint(args []string) bool {
	for _, arg := range args[1:] {
		switch arg {
		case "--relay-url", "--direct-url":
			return true
		}
		if strings.HasPrefix(arg, "--relay-url=") || strings.HasPrefix(arg, "--direct-url=") {
			return true
		}
	}
	return false
}

func configureAutoMasqueDirect() error {
	addr, err := preferredMasqueDirectAddr()
	if err != nil {
		return err
	}
	certPath, keyPath, err := ensureAutoMasqueCertificate()
	if err != nil {
		return err
	}

	directURL := "https://" + net.JoinHostPort(addr.String(), autoMasqueDirectPort)
	_ = os.Setenv("MASQUECAT_DIRECT_URL", directURL)
	_ = os.Setenv("MASQUECAT_DIRECT_LISTEN", ":"+autoMasqueDirectPort)
	_ = os.Setenv("MASQUECAT_TLS_CERT", certPath)
	_ = os.Setenv("MASQUECAT_TLS_KEY", keyPath)

	fmt.Fprintf(os.Stderr, "# No MASQUE relay URL configured; starting direct-only mode at %s (UDP %s).\n", directURL, autoMasqueDirectPort)
	if addr.IsPrivate() {
		fmt.Fprintln(os.Stderr, "# The automatic endpoint is a private/local address. It is reachable only on a network that can route to it; for Internet/NAT/CGNAT use an explicit --direct-url with a reachable UDP endpoint or configure --relay-url.")
	} else {
		fmt.Fprintln(os.Stderr, "# Direct-only mode has no relay fallback. Ensure inbound UDP reaches this host/port; configure --relay-url if you want relay fallback.")
	}
	return nil
}

func preferredMasqueDirectAddr() (netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("list network interfaces: %w", err)
	}
	var private netip.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
				continue
			}
			if !addr.IsPrivate() {
				return addr, nil
			}
			if !private.IsValid() {
				private = addr
			}
		}
	}
	if private.IsValid() {
		return private, nil
	}
	return netip.Addr{}, fmt.Errorf("no non-loopback unicast address found; configure --direct-url or --relay-url explicitly")
}

func ensureAutoMasqueCertificate() (certPath, keyPath string, err error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", "", fmt.Errorf("find user config directory: %w", err)
	}
	dir := filepath.Join(configDir, "tailcat", "auto-direct")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("create automatic direct TLS directory: %w", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if fileExists(certPath) && fileExists(keyPath) {
		return certPath, keyPath, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate automatic direct TLS key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", fmt.Errorf("generate automatic direct TLS serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "MasqueCat automatic direct endpoint"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return "", "", fmt.Errorf("create automatic direct TLS certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal automatic direct TLS key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return "", "", fmt.Errorf("write automatic direct TLS certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		_ = os.Remove(certPath)
		return "", "", fmt.Errorf("write automatic direct TLS key: %w", err)
	}
	return certPath, keyPath, nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func configureAutoMasqueDirectClient(args []string) {
	if os.Getenv("MASQUECAT_INSECURE_SKIP_VERIFY") != "" {
		return
	}
	for _, arg := range args[1:] {
		if !strings.HasPrefix(arg, "mc") {
			continue
		}
		ci, err := tailcat.ParseMasqueConnBlob(tailcat.MasqueConnBlob(arg))
		if err != nil || !isAutomaticDirectOnlyToken(ci) {
			continue
		}
		// The inner WireGuard node key from the mc token is the end-to-end peer
		// identity. This opt-out applies only to the automatic direct-only outer
		// carrier; there is no relay TLS connection in this token to weaken.
		_ = os.Setenv("MASQUECAT_INSECURE_SKIP_VERIFY", "1")
		return
	}
}

func isAutomaticDirectOnlyToken(ci tailcat.MasqueConnInfo) bool {
	if ci.DirectURL == "" || ci.RelayURL != "" {
		return false
	}
	u, err := url.Parse(ci.DirectURL)
	if err != nil || u.Scheme != "https" || u.Port() != autoMasqueDirectPort {
		return false
	}
	_, err = netip.ParseAddr(u.Hostname())
	return err == nil
}
