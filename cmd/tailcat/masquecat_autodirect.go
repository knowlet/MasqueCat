// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	autoMasqueDirectPort      = "4433"
	autoMasqueDirectMarkerEnv = "MASQUECAT_AUTO_DIRECT"
)

var nonPublicMasqueDirectPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),  // RFC 6598 shared address space
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),   // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"), // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved
	netip.MustParsePrefix("2001:db8::/32"),  // IPv6 documentation
}

// initMasqueAutoDirect restores the original Tailcat zero-argument UX for the
// MasqueCat transport: a server can be started without first provisioning a
// relay. In that case we synthesize a direct-only HTTP/3 endpoint from a local
// interface address and a locally generated outer TLS certificate.
//
// The self-signed certificate is deliberately only an outer QUIC carrier
// credential. Automatic direct-only tokens carry an explicit marker so clients
// can distinguish this generated endpoint from an explicitly configured
// self-signed endpoint before relaxing outer TLS verification.
func init() {
	if shouldConfigureAutoMasqueDirect(os.Args) {
		if err := configureAutoMasqueDirect(); err != nil {
			fmt.Fprintf(os.Stderr, "# MasqueCat automatic direct-only setup unavailable: %v\n", err)
		}
	}
}

func shouldConfigureAutoMasqueDirect(args []string) bool {
	if hasExplicitMasqueEndpoint(args) || hasExplicitMasqueEnvironment() || isHelpInvocation(args) {
		return false
	}
	if len(args) == 1 {
		return true
	}

	// Automatic direct setup follows the command's parsed behavior, not merely
	// raw argument count. Global flags alone still select the implicit server
	// path (for example `tailcat --json` or `tailcat --key=new`). Stop as soon as
	// a positional client subcommand/address is present, while skipping values of
	// global flags that take a separate argument.
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "serve" || arg == "recv" || strings.HasPrefix(arg, "--serve="):
			return true
		case arg == "--serve":
			return i+1 < len(args)
		case !strings.HasPrefix(arg, "--"):
			return false
		case strings.Contains(arg, "="):
			continue
		}

		switch arg {
		case "--key", "--derpmap-url", "--direct-listen", "--tls-cert", "--tls-key":
			if i+1 >= len(args) {
				return false
			}
			i++
		case "--verbose", "--json", "--legacy-derp", "--insecure-skip-verify":
			// Boolean global flags consume no following argument.
		default:
			// Unknown options should be left for ff to reject rather than causing
			// automatic network/TLS setup as a side effect of a parse error.
			return false
		}
	}
	return true
}

func hasExplicitMasqueEnvironment() bool {
	for _, name := range []string{
		"MASQUECAT_RELAY_URL",
		"MASQUECAT_DIRECT_URL",
		"MASQUECAT_DIRECT_LISTEN",
		"MASQUECAT_TLS_CERT",
		"MASQUECAT_TLS_KEY",
	} {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

func isHelpInvocation(args []string) bool {
	for _, arg := range args[1:] {
		if arg == "help" || arg == "-h" || arg == "--help" {
			return true
		}
	}
	// A trailing --serve has no value. main treats that parse error as a help
	// request, so automatic setup must stay silent here as well.
	return len(args) > 1 && args[len(args)-1] == "--serve"
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

	baseURL := "https://" + net.JoinHostPort(addr.String(), autoMasqueDirectPort)
	directURL, err := autoMasqueDirectURLWithPin(baseURL, certPath, keyPath)
	if err != nil {
		return err
	}
	_ = os.Setenv("MASQUECAT_DIRECT_URL", directURL)
	_ = os.Setenv("MASQUECAT_DIRECT_LISTEN", ":"+autoMasqueDirectPort)
	_ = os.Setenv("MASQUECAT_TLS_CERT", certPath)
	_ = os.Setenv("MASQUECAT_TLS_KEY", keyPath)
	_ = os.Setenv(autoMasqueDirectMarkerEnv, "1")

	fmt.Fprintf(os.Stderr, "# No MASQUE relay URL configured; starting direct-only mode at %s (UDP %s).\n", baseURL, autoMasqueDirectPort)
	if addr.IsPrivate() {
		fmt.Fprintln(os.Stderr, "# The automatic endpoint is a private/local address. It is reachable only on a network that can route to it; for Internet/NAT use an explicit --direct-url with a reachable UDP endpoint or configure --relay-url.")
	} else {
		fmt.Fprintln(os.Stderr, "# Direct-only mode has no relay fallback. Ensure inbound UDP reaches this host/port; configure --relay-url if you want relay fallback.")
	}
	return nil
}

func isPublicMasqueDirectAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, pfx := range nonPublicMasqueDirectPrefixes {
		if pfx.Contains(addr) {
			return false
		}
	}
	return true
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
			if isPublicMasqueDirectAddr(addr) {
				return addr, nil
			}
			// RFC1918/ULA addresses remain useful for the original same-LAN
			// zero-config workflow. Shared, documentation, benchmark and other
			// reserved ranges are deliberately not advertised automatically.
			if addr.IsPrivate() && !private.IsValid() {
				private = addr
			}
		}
	}
	if private.IsValid() {
		return private, nil
	}
	return netip.Addr{}, fmt.Errorf("no public or private LAN address found; CGNAT/shared/reserved addresses require an explicit --direct-url or --relay-url")
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

	// Keep the certificate and private key in one PEM bundle. Replacing one file
	// atomically means concurrent processes can never observe a certificate from
	// one generation paired with a key from another.
	bundlePath := filepath.Join(dir, "tls.pem")
	if _, err := tls.LoadX509KeyPair(bundlePath, bundlePath); err == nil {
		return bundlePath, bundlePath, nil
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
	bundle := append(certPEM, keyPEM...)
	if err := writeAutoMasqueBundle(dir, bundlePath, bundle); err != nil {
		// On Windows another process may have won the rename race. Accept its
		// complete bundle rather than failing merely because our rename lost.
		if _, loadErr := tls.LoadX509KeyPair(bundlePath, bundlePath); loadErr == nil {
			return bundlePath, bundlePath, nil
		}
		return "", "", fmt.Errorf("write automatic direct TLS bundle: %w", err)
	}
	return bundlePath, bundlePath, nil
}

func writeAutoMasqueBundle(dir, path string, data []byte) error {
	f, err := os.CreateTemp(dir, ".tls-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	defer func() { _ = f.Close() }()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
