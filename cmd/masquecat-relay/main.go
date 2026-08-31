//go:build !js

package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/tailscale/tailcat"
)

const selfSignedValidity = 24 * time.Hour

func main() {
	listen := flag.String("listen", ":443", "UDP address for HTTP/3 MASQUE")
	certFile := flag.String("cert", "", "TLS certificate PEM file")
	keyFile := flag.String("key", "", "TLS private key PEM file")
	flag.Parse()

	cert, generated, err := loadOrGenerateCertificate(*certFile, *keyFile, os.Stdin, os.Stderr, stdinIsTerminal())
	if err != nil {
		log.Fatal(err)
	}
	if generated {
		log.Printf("WARNING: using an ephemeral self-signed TLS certificate valid for %s; clients must explicitly trust it or enable InsecureSkipVerify", selfSignedValidity)
	}

	relay := &tailcat.MasqueRelay{Logf: log.Printf}
	if err := tailcat.ServeMasqueHTTP3(*listen, &tls.Config{Certificates: []tls.Certificate{cert}}, relay.Handler()); err != nil {
		log.Fatal(err)
	}
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func loadOrGenerateCertificate(certFile, keyFile string, in io.Reader, out io.Writer, interactive bool) (tls.Certificate, bool, error) {
	if (certFile == "") != (keyFile == "") {
		return tls.Certificate{}, false, errors.New("-cert and -key must be provided together")
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return tls.Certificate{}, false, fmt.Errorf("load TLS certificate: %w", err)
		}
		return cert, false, nil
	}
	if !interactive {
		return tls.Certificate{}, false, errors.New("-cert and -key are required in non-interactive mode; run interactively to generate an ephemeral self-signed certificate")
	}

	if out == nil {
		out = io.Discard
	}
	if in == nil {
		return tls.Certificate{}, false, errors.New("cannot prompt for self-signed certificate without stdin")
	}
	_, _ = fmt.Fprint(out, "No TLS certificate configured. Generate an ephemeral self-signed certificate for this run? [y/N] ")
	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return tls.Certificate{}, false, fmt.Errorf("read certificate prompt: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		cert, err := generateSelfSignedCertificate(time.Now())
		if err != nil {
			return tls.Certificate{}, false, err
		}
		return cert, true, nil
	default:
		return tls.Certificate{}, false, errors.New("TLS certificate required; provide -cert and -key")
	}
}

func generateSelfSignedCertificate(now time.Time) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate self-signed key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate certificate serial: %w", err)
	}

	dnsNames := []string{"localhost"}
	if hostname, err := os.Hostname(); err == nil && hostname != "" && hostname != "localhost" {
		dnsNames = append(dnsNames, hostname)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "MasqueCat ephemeral relay"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(selfSignedValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create self-signed certificate: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal self-signed private key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load generated self-signed certificate: %w", err)
	}
	cert.Leaf, _ = x509.ParseCertificate(der)
	return cert, nil
}
