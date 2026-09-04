package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
)

func autoMasqueDirectURLWithPin(baseURL, certPath, keyPath string) (string, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return "", fmt.Errorf("load automatic direct TLS certificate for pinning: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return "", fmt.Errorf("automatic direct TLS certificate has no leaf certificate")
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return baseURL + "#sha256=" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
