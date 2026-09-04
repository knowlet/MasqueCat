//go:build !js

package tailcat

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

type recordingMasqueForwarder struct {
	src     key.NodePublic
	dst     key.NodePublic
	payload []byte
}

func (f *recordingMasqueForwarder) ForwardPacket(src, dst key.NodePublic, payload []byte) error {
	f.src = src
	f.dst = dst
	f.payload = append(f.payload[:0], payload...)
	return nil
}

func TestMasqueBindSendUsesExplicitPeerPath(t *testing.T) {
	local := key.NewNode().Public()
	peer := key.NewNode().Public()
	b := newMasqueBind(local)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	fwd := new(recordingMasqueForwarder)
	b.SetPath(peer, fwd)
	ep, err := b.ParseEndpoint(peer.String())
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	buf := append([]byte{0xaa, 0xbb}, []byte("wireguard-ciphertext")...)
	if err := b.Send([][]byte{buf}, ep, 2); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if fwd.src != local || fwd.dst != peer {
		t.Fatalf("forwarded identity = %v -> %v, want %v -> %v", fwd.src, fwd.dst, local, peer)
	}
	if got, want := fwd.payload, []byte("wireguard-ciphertext"); !bytes.Equal(got, want) {
		t.Fatalf("forwarded payload = %x, want %x", got, want)
	}
}

func TestMasqueBindRemovePathDoesNotRetireReplacement(t *testing.T) {
	local := key.NewNode().Public()
	peer := key.NewNode().Public()
	b := newMasqueBind(local)
	oldPath := new(recordingMasqueForwarder)
	newPath := new(recordingMasqueForwarder)

	b.SetPath(peer, oldPath)
	b.SetPath(peer, newPath)
	if b.RemovePath(peer, oldPath) {
		t.Fatal("stale path removal retired the replacement path")
	}
	if !b.RemovePath(peer, newPath) {
		t.Fatal("current path removal was not recognized")
	}
	b.mu.RLock()
	_, ok := b.paths[peer]
	b.mu.RUnlock()
	if ok {
		t.Fatal("current path still present after removal")
	}
}

func TestMasqueBindInjectFeedsWireGuardReceive(t *testing.T) {
	local := key.NewNode().Public()
	peer := key.NewNode().Public()
	b := newMasqueBind(local)
	receive, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if len(receive) != 1 {
		t.Fatalf("receive funcs = %d, want 1", len(receive))
	}

	want := []byte("encrypted-wireguard-packet")
	if err := b.Inject(peer, want); err != nil {
		t.Fatalf("Inject: %v", err)
	}
	packets := [][]byte{make([]byte, 2048)}
	sizes := make([]int, 1)
	wireEndpoints := make([]conn.Endpoint, 1)
	n, err := receive[0](packets, sizes, wireEndpoints)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 1 || sizes[0] != len(want) {
		t.Fatalf("receive = n:%d size:%d, want n:1 size:%d", n, sizes[0], len(want))
	}
	if !bytes.Equal(packets[0][:sizes[0]], want) {
		t.Fatalf("received payload = %x, want %x", packets[0][:sizes[0]], want)
	}
	mep, ok := wireEndpoints[0].(*masqueEndpoint)
	if !ok || mep.peer != peer {
		t.Fatalf("received endpoint = %#v, want peer %v", wireEndpoints[0], peer)
	}
}

func TestMasqueCoreAddAllowedClientTightensLivePolicy(t *testing.T) {
	allowed := key.NewNode().Public()
	other := key.NewNode().Public()
	c := &masqueCore{isServer: true}
	if !c.peerAllowed(other) {
		t.Fatal("nil allowlist should initially allow all clients")
	}
	c.AddAllowedClient(allowed)
	if !c.peerAllowed(allowed) {
		t.Fatal("newly allowed client was rejected")
	}
	if c.peerAllowed(other) {
		t.Fatal("first live allowlist addition must switch the server to explicit admission")
	}
}

func TestMasqueCoreExistingPeerSurvivesAllowlistTightening(t *testing.T) {
	existing := key.NewNode().Public()
	allowed := key.NewNode().Public()
	c := &masqueCore{
		isServer:       true,
		peers:          map[key.NodePublic]bool{existing: true},
		allowedClients: map[key.NodePublic]bool{allowed: true},
	}
	if c.peerAllowed(existing) {
		t.Fatal("existing peer should not satisfy the tightened admission policy")
	}
	if err := c.AddPeer(existing); err != nil {
		t.Fatalf("existing admitted peer was evicted by runtime policy tightening: %v", err)
	}
}

func TestMasqueCoreServedTCPPortsNilVersusEmpty(t *testing.T) {
	unrestricted := &masqueCore{servedTCPPorts: nil}
	if !unrestricted.localPortAllowed(1234) || !unrestricted.localPortAllowed(65535) {
		t.Fatal("nil ServedTCPPorts should admit every local application port")
	}

	none := &masqueCore{servedTCPPorts: []filter.PortRange{}}
	if none.localPortAllowed(1234) || none.localPortAllowed(65535) {
		t.Fatal("non-nil empty ServedTCPPorts should admit no application ports, including 65535")
	}

	only443 := &masqueCore{servedTCPPorts: []filter.PortRange{{First: 443, Last: 443}}}
	if !only443.localPortAllowed(443) || only443.localPortAllowed(80) || only443.localPortAllowed(65535) {
		t.Fatal("explicit ServedTCPPorts range was not enforced")
	}

	only65535 := &masqueCore{servedTCPPorts: []filter.PortRange{{First: 65535, Last: 65535}}}
	if !only65535.localPortAllowed(65535) {
		t.Fatal("TCP port 65535 must remain available to applications")
	}
}

type injectingMasqueForwarder struct {
	dst *masqueCore
}

func (f *injectingMasqueForwarder) ForwardPacket(src, _ key.NodePublic, payload []byte) error {
	return f.dst.Inject(src, payload)
}

// Regression: the shared ping control address must be local only on the server.
// If the client owns it too, gVisor can route the ping back to itself instead of
// sending the SYN through WireGuard to the peer.
func TestMasqueCorePingControlAddress(t *testing.T) {
	client, err := newMasqueCore(key.NewNode(), masqueCoreOptions{}, t.Logf)
	if err != nil {
		t.Fatalf("new client core: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	server, err := newMasqueCore(key.NewNode(), masqueCoreOptions{IsServer: true}, t.Logf)
	if err != nil {
		t.Fatalf("new server core: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	if err := client.SetPath(server.pub, &injectingMasqueForwarder{dst: server}); err != nil {
		t.Fatalf("set client path: %v", err)
	}
	if err := server.SetPath(client.pub, &injectingMasqueForwarder{dst: client}); err != nil {
		t.Fatalf("set server path: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Ping(ctx, server.pub); err != nil {
		t.Fatalf("Ping over internal control address: %v", err)
	}
}
