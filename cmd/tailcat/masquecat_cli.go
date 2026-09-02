// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v4"
	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

var (
	flagLegacyDERP               *bool
	flagMasqueRelayURL           *string
	flagMasqueDirectURL          *string
	flagMasqueDirectListen       *string
	flagMasqueTLSCert            *string
	flagMasqueTLSKey             *string
	flagMasqueInsecureSkipVerify *bool
)

func registerMasqueCLIFlags(fs *ff.FlagSet) {
	flagLegacyDERP = fs.BoolLong("legacy-derp", "use the original Tailcat DERP/STUN/disco transport for server and genkey modes; tc... client tokens remain supported without this flag")
	flagMasqueRelayURL = fs.StringLong("relay-url", os.Getenv("MASQUECAT_RELAY_URL"), "MasqueCat relay HTTPS URL; also read from MASQUECAT_RELAY_URL")
	flagMasqueDirectURL = fs.StringLong("direct-url", os.Getenv("MASQUECAT_DIRECT_URL"), "public HTTPS URL of this server's direct MASQUE endpoint; also read from MASQUECAT_DIRECT_URL")
	flagMasqueDirectListen = fs.StringLong("direct-listen", os.Getenv("MASQUECAT_DIRECT_LISTEN"), "UDP listen address for direct MASQUE, for example :443; also read from MASQUECAT_DIRECT_LISTEN")
	flagMasqueTLSCert = fs.StringLong("tls-cert", os.Getenv("MASQUECAT_TLS_CERT"), "TLS certificate PEM for direct MASQUE; also read from MASQUECAT_TLS_CERT")
	flagMasqueTLSKey = fs.StringLong("tls-key", os.Getenv("MASQUECAT_TLS_KEY"), "TLS private key PEM for direct MASQUE; also read from MASQUECAT_TLS_KEY")
	flagMasqueInsecureSkipVerify = fs.BoolLong("insecure-skip-verify", "disable outer MASQUE TLS certificate verification (development only); MASQUECAT_INSECURE_SKIP_VERIFY=1 does the same")
	if envTruthy("TAILCAT_LEGACY_DERP") {
		*flagLegacyDERP = true
	}
	if envTruthy("MASQUECAT_INSECURE_SKIP_VERIFY") {
		*flagMasqueInsecureSkipVerify = true
	}
}

func envTruthy(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	default:
		return false
	}
}

func isMasqueBlob(blob string) bool { return strings.HasPrefix(blob, "mc") }

func newMasqueCLIClient(logf logger.Logf, blob string, priv key.NodePrivate) *tailcat.MasqueClient {
	return &tailcat.MasqueClient{
		Server:             tailcat.MasqueConnBlob(blob),
		Key:                priv,
		Logf:               logf,
		InsecureSkipVerify: *flagMasqueInsecureSkipVerify,
	}
}

func masqueClientMode(logf logger.Logf, connStr, optDest string) error {
	priv := clientKey()
	cl := newMasqueCLIClient(logf, connStr, priv)
	defer cl.Close()

	var dial func(context.Context) (net.Conn, error)
	switch {
	case optDest == "":
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCPPort(ctx, 1) }
	case !strings.Contains(optDest, ":"):
		port, err := net.LookupPort("tcp", optDest)
		if err != nil {
			return usagef("invalid port number %q", optDest)
		}
		if port < 0 || port > 65535 {
			return usagef("invalid port number %q", optDest)
		}
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCPPort(ctx, uint16(port)) }
	default:
		addrPort, err := netip.ParseAddrPort(optDest)
		if err != nil {
			return usagef("invalid IP:port %q", optDest)
		}
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCP(ctx, addrPort) }
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
	pi, err := cl.Ping(pingCtx)
	pingCancel()
	if err != nil {
		return fmt.Errorf("MasqueCat ping: %w", err)
	}
	if *flagVerbose {
		logf("got ping over %s: %+v", cl.Path(), pi)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dial(ctx)
	if err != nil {
		return fmt.Errorf("Dial: %w", err)
	}
	defer c.Close()
	go func() {
		if _, err := io.Copy(c, os.Stdin); err != nil {
			log.Printf("stdin copy: %v", err)
			return
		}
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			if err := cw.CloseWrite(); err != nil {
				log.Printf("CloseWrite: %v", err)
			}
		}
	}()

	if _, err := io.Copy(os.Stdout, c); err != nil {
		return err
	}
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer drainCancel()
	_ = cl.DrainTCP(drainCtx)
	return nil
}

func masqueClientPingMode(logf logger.Logf, untilDirect bool, timeout time.Duration, blob string) error {
	priv := clientKey()
	deadline := time.Now().Add(timeout)
	for {
		t0 := time.Now()
		cl := newMasqueCLIClient(logf, blob, priv)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		res, err := cl.Ping(ctx)
		path := cl.Path()
		cancel()
		_ = cl.Close()
		if err != nil {
			if untilDirect && time.Now().After(deadline) {
				return fmt.Errorf("no direct MASQUE path to the server after %v: %w", timeout, err)
			}
			return fmt.Errorf("ping: %w", err)
		}
		fmt.Printf("pong in %v via %v\n", res.Latency.Round(10*time.Microsecond), path)
		if !untilDirect || path == tailcat.MasquePathDirect {
			return nil
		}
		if time.Until(deadline) < time.Second/2 {
			return fmt.Errorf("no direct MASQUE path to the server after %v", timeout)
		}
		time.Sleep(max(0, time.Second-time.Since(t0)))
	}
}

func masqueClientParseMode(blob string) error {
	v, err := tailcat.ParseMasqueConnBlob(tailcat.MasqueConnBlob(blob))
	if err != nil {
		return err
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "    ")
	return e.Encode(v)
}

func masqueClientResolveMode(blob string) error {
	if _, err := tailcat.ParseMasqueConnBlob(tailcat.MasqueConnBlob(blob)); err != nil {
		return err
	}
	// mc tokens are already self-contained: they carry the exact direct and/or
	// relay URL and never need a DERP-map expansion step.
	fmt.Println(blob)
	return nil
}

func loadMasqueServerKey() (priv key.NodePrivate, keyName string, err error) {
	if *flagKey == "" {
		if _, statErr := os.Stat(keyPath("default")); statErr == nil {
			*flagKey = "default"
		} else if os.IsNotExist(statErr) {
			*flagKey = "new"
		} else {
			return key.NodePrivate{}, "", fmt.Errorf("stat default key: %w", statErr)
		}
	}
	if *flagKey == "new" {
		return key.NewNode(), "new", nil
	}
	path := keyPath(*flagKey)
	j, err := os.ReadFile(path)
	if err != nil {
		return key.NodePrivate{}, "", err
	}
	var conf tailcat.PrivateKey
	if err := json.Unmarshal(j, &conf); err != nil {
		return key.NodePrivate{}, "", fmt.Errorf("parse %v: %w", path, err)
	}
	if conf.Private.IsZero() {
		return key.NodePrivate{}, "", fmt.Errorf("key file %v contains a zero node key", path)
	}
	return conf.Private, *flagKey, nil
}

func masqueServer(logf logger.Logf, serveSpec string) error {
	if *flagMasqueRelayURL == "" && *flagMasqueDirectURL == "" {
		return fmt.Errorf("MasqueCat server needs an explicit endpoint: set MASQUECAT_RELAY_URL or --relay-url, or configure --direct-url/--direct-listen/--tls-cert/--tls-key; use --legacy-derp for the original Tailcat transport")
	}
	if *flagMasqueDirectURL == "" && (*flagMasqueDirectListen != "" || *flagMasqueTLSCert != "" || *flagMasqueTLSKey != "") {
		return fmt.Errorf("--direct-listen/--tls-cert/--tls-key require --direct-url")
	}
	if *flagMasqueDirectURL != "" {
		if *flagMasqueDirectListen == "" {
			return fmt.Errorf("--direct-url requires --direct-listen")
		}
		if *flagMasqueTLSCert == "" || *flagMasqueTLSKey == "" {
			return fmt.Errorf("--direct-url requires --tls-cert and --tls-key")
		}
	}

	portSet, services, err := parsePortSet(serveSpec)
	if err != nil {
		return fmt.Errorf("invalid port or service to serve: %w", err)
	}
	if *flagFiles != "" {
		if !tailCatSSHEnabled {
			return fmt.Errorf("--files requires SSH support, not included in binary per build tags")
		}
		if services == nil {
			services = set.Set[string]{}
		}
		services.Add("files")
	}
	oneShotStdout := len(portSet) == 0 && len(services) == 0

	priv, keyName, err := loadMasqueServerKey()
	if err != nil {
		return err
	}

	var directTLS *tls.Config
	if *flagMasqueDirectURL != "" {
		cert, err := tls.LoadX509KeyPair(*flagMasqueTLSCert, *flagMasqueTLSKey)
		if err != nil {
			return fmt.Errorf("load direct MASQUE TLS certificate: %w", err)
		}
		directTLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	}

	s := &tailcat.MasqueServer{
		Server: tailcat.Server{
			Key:  priv,
			Logf: logf,
		},
		DirectListen:       *flagMasqueDirectListen,
		DirectURL:          *flagMasqueDirectURL,
		DirectTLSConfig:    directTLS,
		RelayURL:           *flagMasqueRelayURL,
		InsecureSkipVerify: *flagMasqueInsecureSkipVerify,
	}

	sshServices := services.Contains("no-auth-ssh") || services.Contains("files")
	if sshServices && !tailcat.SupportsSSHServer() {
		return fmt.Errorf("Tailscale SSH server not supported on this platform")
	}
	if !oneShotStdout && !services.Contains("exit-node") {
		ports := slices.Sorted(maps.Keys(portSet))
		if sshServices && !portSet.Contains(22) {
			ports = append([]uint16{22}, ports...)
		}
		s.ServedTCPPorts = portRanges(ports)
	}
	if *flagAllow != "" {
		for _, ks := range strings.Split(*flagAllow, ",") {
			if ks == "none" {
				s.AddAllowedClient(key.NodePublic{})
				continue
			}
			var k key.NodePublic
			if err := k.UnmarshalText([]byte(ks)); err != nil {
				return fmt.Errorf("invalid key %q in --allow: %w", ks, err)
			}
			s.AddAllowedClient(k)
		}
	}

	tcpForwardTo := func(ipPortStr string) func(net.Conn) {
		return func(c net.Conn) {
			localConn, err := net.Dial("tcp", ipPortStr)
			if err != nil {
				logf("error proxying to %v: %v", ipPortStr, err)
				_ = c.Close()
				return
			}
			tailcat.ProxyConns(c, localConn)
		}
	}
	if services.Contains("exit-node") {
		s.OnTCPForward = func(dst netip.AddrPort) func(net.Conn) { return tcpForwardTo(dst.String()) }
	}

	var sshHandler func(net.Conn)
	if sshServices {
		opts := tailcat.SSHOptions{Shell: services.Contains("no-auth-ssh")}
		if services.Contains("files") {
			fsrv, modeName, err := parseFilesFlag(*flagFiles)
			if err != nil {
				return err
			}
			opts.Files = fsrv
			fmt.Fprintf(os.Stderr, "# Serving files from %v (%v)\n", fsrv.Dir, modeName)
		}
		sshHandler = s.SSHConnHandler(opts)
	}

	s.OnTCP = func(port uint16) func(net.Conn) {
		if port == 22 && sshHandler != nil {
			return sshHandler
		}
		if services.Contains("exit-node") {
			return tcpForwardTo(fmt.Sprintf("localhost:%v", port))
		}
		if oneShotStdout {
			return func(c net.Conn) {
				if _, err := io.Copy(os.Stdout, c); err != nil {
					log.Printf("stdout copy: %v", err)
				}
				_ = os.Stdout.Close()
				_ = c.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = s.DrainTCP(ctx)
				os.Exit(0)
			}
		}
		if !portSet.Contains(port) {
			return nil
		}
		return tcpForwardTo(fmt.Sprintf("localhost:%v", port))
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("MasqueServer.Start: %w", err)
	}
	defer s.Close()
	if *flagMasqueRelayURL != "" {
		fmt.Fprintf(os.Stderr, "# MASQUE relay server: %v\n", *flagMasqueRelayURL)
	}
	if *flagMasqueDirectURL != "" {
		fmt.Fprintf(os.Stderr, "# MASQUE direct endpoint: %v (UDP listen %v)\n", *flagMasqueDirectURL, *flagMasqueDirectListen)
	}
	connStr := s.ConnBlob()
	if keyName == "new" {
		fmt.Fprintf(os.Stderr, "# 🐈 Server listening with new address: %v\n", connStr)
	} else {
		fmt.Fprintf(os.Stderr, "# 🐈 Server listening with saved key %q: %v\n", keyName, connStr)
	}
	if *flagJSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"listenAddr": string(connStr)})
	}
	if v := os.Getenv("TAILCAT_ADDR_FILE"); v != "" {
		if tcpAddr, ok := strings.CutPrefix(v, "tcp:"); ok {
			c, err := net.Dial("tcp", tcpAddr)
			if err != nil {
				return fmt.Errorf("TAILCAT_ADDR_FILE tcp dial %q: %w", tcpAddr, err)
			}
			_, _ = fmt.Fprintln(c, connStr)
			_ = c.Close()
		} else if err := os.WriteFile(v, []byte(connStr), 0600); err != nil {
			return err
		}
	}
	if os.Getenv("TAILCAT_STATUS_LOOP") == "1" {
		go func() {
			for {
				log.Printf("status = %v", logger.AsJSON(s.Status()))
				time.Sleep(5 * time.Second)
			}
		}()
	}
	select {}
}

func masqueGenKey(args []string) error {
	if len(args) > 0 {
		return usagef("genkey takes no positional arguments")
	}
	confDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	if *genkeyList {
		ents, err := os.ReadDir(filepath.Join(confDir, "tailcat", "keys"))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, e := range ents {
			if name, ok := strings.CutSuffix(e.Name(), ".private.json"); ok {
				fmt.Println(name)
			}
		}
		return nil
	}
	if *genkeyDelete {
		if *genkeyKey == "" {
			return usagef("genkey --delete requires --key=<name>")
		}
		if keyIsPath(*genkeyKey) {
			return usagef("can't delete key %q; it's a path", *genkeyKey)
		}
		return os.Remove(keyPath(*genkeyKey))
	}
	if *genkeyKey == "" {
		return usagef("genkey requires --key=<name>; use \"default\" for server mode or \"client-default\" for client mode")
	}
	for _, name := range []string{"region", "fixed-region", "embed-derp-map"} {
		if f, ok := genkeyFS.GetFlag(name); ok && f.IsSet() {
			return usagef("genkey --%s is a legacy DERP option; use --legacy-derp if you need it", name)
		}
	}
	if *genkeyClient && *genkeyKey == "default" {
		return usagef("genkey --client with --key=default is probably a mistake; use --key=client-default for the automatic client key")
	}

	path := *genkeyKey
	if !keyIsPath(path) {
		path = keyPath(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil && !*genkeyForce {
		return fmt.Errorf("%v already exists; use --force to overwrite", path)
	}
	priv := tailcat.NewPrivateKey()
	j, err := json.MarshalIndent(priv, "", "\t")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, j, 0600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "# wrote file to %v\n", path)
	if *genkeyClient {
		fmt.Println(priv.Private.Public().String())
		return nil
	}
	if *flagMasqueRelayURL == "" && *flagMasqueDirectURL == "" {
		fmt.Fprintln(os.Stderr, "# no MASQUE endpoint is configured, so no mc token can be generated yet; start tailcat with --relay-url or --direct-url and it will print the token")
		return nil
	}
	blob, err := (tailcat.MasqueConnInfo{
		Version:           1,
		ServerPublic:      priv.Private.Public(),
		ServerDiscoPublic: tailcat.DiscoPublicForNode(priv.Private).DiscoPublic,
		DirectURL:         *flagMasqueDirectURL,
		RelayURL:          *flagMasqueRelayURL,
	}).ConnBlob()
	if err != nil {
		return err
	}
	fmt.Println(blob)
	return nil
}
