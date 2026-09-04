//go:build !js

package tailcat

import (
	"bytes"
	"testing"

	wgconn "github.com/tailscale/wireguard-go/conn"
	"tailscale.com/types/key"
)

type fragmentRecordingMasqueForwarder struct {
	packets [][]byte
}

func (f *fragmentRecordingMasqueForwarder) ForwardPacket(_, _ key.NodePublic, payload []byte) error {
	f.packets = append(f.packets, append([]byte(nil), payload...))
	return nil
}

func TestMasqueBindLeavesSmallWireGuardPacketUnfragmented(t *testing.T) {
	local := key.NewNode().Public()
	peer := key.NewNode().Public()
	forwarder := new(fragmentRecordingMasqueForwarder)
	bind := newMasqueBind(local)
	bind.SetPath(peer, forwarder)

	payload := bytes.Repeat([]byte{0x42}, 512)
	if err := bind.Send([][]byte{payload}, &masqueEndpoint{peer: peer}, 0); err != nil {
		t.Fatal(err)
	}
	if len(forwarder.packets) != 1 {
		t.Fatalf("forwarded packets = %d, want 1", len(forwarder.packets))
	}
	if !bytes.Equal(forwarder.packets[0], payload) {
		t.Fatal("small WireGuard packet changed in transit")
	}
}

func TestMasqueBindFragmentsLargeWireGuardPacketWithinQUICBudget(t *testing.T) {
	local := key.NewNode().Public()
	peer := key.NewNode().Public()
	forwarder := new(fragmentRecordingMasqueForwarder)
	bind := newMasqueBind(local)
	bind.SetPath(peer, forwarder)

	// 1280-byte inner MTU plus WireGuard's 32-byte transport-data overhead is
	// the boundary that previously produced a roughly 1378-byte HTTP Datagram
	// after MasqueCat framing and triggered quic.DatagramTooLargeError.
	payload := bytes.Repeat([]byte{0x5a}, 1312)
	buf := append(make([]byte, 16), payload...)
	if err := bind.Send([][]byte{buf}, &masqueEndpoint{peer: peer}, 16); err != nil {
		t.Fatal(err)
	}
	if len(forwarder.packets) != 2 {
		t.Fatalf("forwarded fragments = %d, want 2", len(forwarder.packets))
	}

	const masquePacketHeaderLen = 1 + 2*key.NodePublicRawLen
	for i, fragment := range forwarder.packets {
		if !bytes.HasPrefix(fragment, masqueWGFragmentMagic[:]) {
			t.Fatalf("fragment %d is missing MasqueCat fragment marker", i)
		}
		// masque-go prepends one-byte HTTP Datagram context ID before calling
		// quic-go. Keep the resulting H3 DATAGRAM payload <= 1086 bytes, well
		// below the QUIC 1200-byte minimum path packet size.
		httpDatagramPayload := 1 + masquePacketHeaderLen + len(fragment)
		if httpDatagramPayload > 1086 {
			t.Fatalf("fragment %d H3 datagram payload = %d, want <= 1086", i, httpDatagramPayload)
		}
	}
}

func TestMasqueBindReassemblesOutOfOrderWireGuardFragments(t *testing.T) {
	sender := key.NewNode().Public()
	receiver := key.NewNode().Public()
	forwarder := new(fragmentRecordingMasqueForwarder)
	sendBind := newMasqueBind(sender)
	sendBind.SetPath(receiver, forwarder)

	payload := make([]byte, 1312)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := sendBind.Send([][]byte{payload}, &masqueEndpoint{peer: receiver}, 0); err != nil {
		t.Fatal(err)
	}
	if len(forwarder.packets) != 2 {
		t.Fatalf("forwarded fragments = %d, want 2", len(forwarder.packets))
	}

	recvBind := newMasqueBind(receiver)
	receive, _, err := recvBind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer recvBind.Close()

	if err := recvBind.Inject(sender, forwarder.packets[1]); err != nil {
		t.Fatal(err)
	}
	if got := len(recvBind.recv); got != 0 {
		t.Fatalf("incomplete assembly queued %d WireGuard packets, want 0", got)
	}
	if err := recvBind.Inject(sender, forwarder.packets[0]); err != nil {
		t.Fatal(err)
	}
	if got := len(recvBind.recv); got != 1 {
		t.Fatalf("completed assembly queued %d WireGuard packets, want 1", got)
	}

	packetBuf := make([]byte, 2048)
	sizes := make([]int, 1)
	endpoints := make([]wgconn.Endpoint, 1)
	n, err := receive[0]([][]byte{packetBuf}, sizes, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || sizes[0] != len(payload) {
		t.Fatalf("receive = (%d packets, %d bytes), want (1, %d)", n, sizes[0], len(payload))
	}
	if !bytes.Equal(packetBuf[:sizes[0]], payload) {
		t.Fatal("reassembled WireGuard packet differs from original")
	}
	ep, ok := endpoints[0].(*masqueEndpoint)
	if !ok || ep.peer != sender {
		t.Fatalf("reassembled endpoint = %#v, want sender %v", endpoints[0], sender.ShortString())
	}
}

func TestMasqueWGReassemblerRejectsConflictingDuplicate(t *testing.T) {
	src := key.NewNode().Public()
	payload := bytes.Repeat([]byte{0x77}, 1312)
	fragments, err := fragmentMasqueWireGuardPacket(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragments) != 2 {
		t.Fatalf("fragments = %d, want 2", len(fragments))
	}

	var r masqueWGReassembler
	if _, ready, err := r.Push(src, fragments[0]); err != nil || ready {
		t.Fatalf("first fragment = ready %v, err %v; want incomplete", ready, err)
	}
	conflict := append([]byte(nil), fragments[0]...)
	conflict[len(conflict)-1] ^= 0xff
	if _, _, err := r.Push(src, conflict); err == nil {
		t.Fatal("conflicting duplicate fragment unexpectedly accepted")
	}
}

func TestMasqueWGReassemblerLimitsAssembliesPerSource(t *testing.T) {
	noisy := key.NewNode().Public()
	other := key.NewNode().Public()
	payload := bytes.Repeat([]byte{0x33}, 1312)
	var r masqueWGReassembler

	for i := 0; i < masqueWGMaxAssembliesPerSource; i++ {
		fragments, err := fragmentMasqueWireGuardPacket(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, ready, err := r.Push(noisy, fragments[0]); err != nil || ready {
			t.Fatalf("noisy source assembly %d = ready %v, err %v; want incomplete", i, ready, err)
		}
	}

	overLimit, err := fragmentMasqueWireGuardPacket(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Push(noisy, overLimit[0]); err == nil {
		t.Fatal("source exceeded per-source fragment assembly quota")
	}

	otherFragments, err := fragmentMasqueWireGuardPacket(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, ready, err := r.Push(other, otherFragments[0]); err != nil || ready {
		t.Fatalf("other source first assembly = ready %v, err %v; want incomplete", ready, err)
	}
}
