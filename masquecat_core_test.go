//go:build !js

package tailcat

import (
	"bytes"
	"net"
	"testing"

	"tailscale.com/types/key"
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
	eps := make([]interfaceEndpoint, 0)
	_ = eps

	wireEndpoints := makeEndpointSlice(1)
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

// Keep conn.Endpoint imports out of the production-facing test declarations
// above so the assertions stay focused on MasqueCat semantics.
type interfaceEndpoint = interface {
	ClearSrc()
	SrcToString() string
	DstToString() string
	DstToBytes() []byte
	DstIP() net.IP
	SrcIP() net.IP
}

func makeEndpointSlice(n int) []interfaceEndpoint { return make([]interfaceEndpoint, n) }
