//go:build !js

package tailcat

import (
	"bufio"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"strconv"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// localDERPRegionID is deliberately in Tailscale's user-reserved DERP range.
// This DERP node exists only on loopback; it is a compatibility seam between
// Tailcat's existing magicsock-backed wgengine and the external MASQUE paths.
const localDERPRegionID tailcfg.DERPRegionID = 999

const localDERPHostName = "masquecat-loopback.invalid"

type localDERPBridge struct {
	server *derpserver.Server
	http   *httptest.Server
	region *tailcfg.DERPRegion
	mesh   *derp.Client
	pipe   net.Conn
	logf   logger.Logf

	closeOnce sync.Once
}

func newLocalDERPBridge(logf logger.Logf) (*localDERPBridge, error) {
	if logf == nil {
		return nil, errors.New("nil logf")
	}
	b := &localDERPBridge{logf: logf}
	s := derpserver.New(key.NewNode(), logf)
	b.server = s

	var meshRaw [32]byte
	if _, err := crand.Read(meshRaw[:]); err != nil {
		return nil, fmt.Errorf("generate local DERP mesh key: %w", err)
	}
	meshHex := hex.EncodeToString(meshRaw[:])
	if err := s.SetMeshKey(meshHex); err != nil {
		return nil, fmt.Errorf("set local DERP mesh key: %w", err)
	}
	meshKey, err := key.ParseDERPMesh(meshHex)
	if err != nil {
		return nil, fmt.Errorf("parse local DERP mesh key: %w", err)
	}

	// A private in-memory mesh client is used to inject packets received from
	// MASQUE back into DERP's normal receive path. FrameForwardPacket preserves
	// the remote NodePublic, so magicsock sees the same source identity it would
	// see from a real DERP relay.
	serverPipe, clientPipe := net.Pipe()
	b.pipe = clientPipe
	go s.Accept(
		context.Background(),
		serverPipe,
		bufio.NewReadWriter(bufio.NewReader(serverPipe), bufio.NewWriter(serverPipe)),
		"127.0.0.1:1",
	)
	meshClient, err := derp.NewClient(
		key.NewNode(),
		clientPipe,
		bufio.NewReadWriter(bufio.NewReader(clientPipe), bufio.NewWriter(clientPipe)),
		logf,
		derp.MeshKey(meshKey),
		derp.AppName("masquecat-mesh"),
	)
	if err != nil {
		_ = clientPipe.Close()
		return nil, fmt.Errorf("create local DERP mesh client: %w", err)
	}
	msg, err := meshClient.Recv()
	if err != nil {
		_ = clientPipe.Close()
		return nil, fmt.Errorf("complete local DERP mesh handshake: %w", err)
	}
	if _, ok := msg.(derp.ServerInfoMessage); !ok {
		_ = clientPipe.Close()
		return nil, fmt.Errorf("unexpected local DERP handshake message %T", msg)
	}
	b.mesh = meshClient

	// Use a loopback TLS DERP server for magicsock itself. CertName's
	// sha256-raw pin lets magicsock authenticate the ephemeral self-signed cert
	// without disabling TLS verification. tlsdial still verifies the advertised
	// hostname after checking the pin, so the certificate must carry that name.
	derpCert, err := generateLoopbackDERPCert()
	if err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("generate local DERP TLS certificate: %w", err)
	}
	ts := httptest.NewUnstartedServer(derpserver.Handler(s))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{derpCert}}
	ts.StartTLS()
	b.http = ts

	_, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("parse local DERP listener: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("parse local DERP port: %w", err)
	}
	cert := ts.Certificate()
	if cert == nil {
		_ = b.Close()
		return nil, errors.New("local DERP TLS server has no certificate")
	}
	certHash := sha256.Sum256(cert.Raw)
	b.region = &tailcfg.DERPRegion{
		RegionID:   localDERPRegionID,
		RegionCode: "mc-local",
		RegionName: "MasqueCat loopback bridge",
		Nodes: []*tailcfg.DERPNode{{
			Name:     "mc-local-1",
			RegionID: localDERPRegionID,
			HostName: localDERPHostName,
			CertName: "sha256-raw:" + hex.EncodeToString(certHash[:]),
			IPv4:     "127.0.0.1",
			IPv6:     "none",
			STUNPort: -1,
			DERPPort: port,
		}},
	}
	return b, nil
}

func generateLoopbackDERPCert() (tls.Certificate, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: localDERPHostName,
		},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{localDERPHostName, "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(crand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}, nil
}

func (b *localDERPBridge) Region() *tailcfg.DERPRegion { return b.region }

func (b *localDERPBridge) AddForwarder(dst key.NodePublic, fwd derpserver.PacketForwarder) {
	b.server.AddPacketForwarder(dst, fwd)
}

func (b *localDERPBridge) RemoveForwarder(dst key.NodePublic, fwd derpserver.PacketForwarder) {
	b.server.RemovePacketForwarder(dst, fwd)
}

func (b *localDERPBridge) Inject(src, dst key.NodePublic, payload []byte) error {
	return b.mesh.ForwardPacket(src, dst, payload)
}

func (b *localDERPBridge) Close() error {
	var err error
	b.closeOnce.Do(func() {
		if b.http != nil {
			b.http.Close()
		}
		if b.pipe != nil {
			err = b.pipe.Close()
		}
	})
	return err
}
