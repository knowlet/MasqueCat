//go:build !js

package main

import (
	"crypto/tls"
	"flag"
	"log"

	"github.com/tailscale/tailcat"
)

func main() {
	listen := flag.String("listen", ":443", "UDP address for HTTP/3 MASQUE")
	certFile := flag.String("cert", "", "TLS certificate PEM file")
	keyFile := flag.String("key", "", "TLS private key PEM file")
	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		log.Fatal("-cert and -key are required")
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load TLS certificate: %v", err)
	}
	relay := &tailcat.MasqueRelay{Logf: log.Printf}
	if err := tailcat.ServeMasqueHTTP3(*listen, &tls.Config{Certificates: []tls.Certificate{cert}}, relay.Handler()); err != nil {
		log.Fatal(err)
	}
}
