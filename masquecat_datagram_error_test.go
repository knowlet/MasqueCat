//go:build !js

package tailcat

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"tailscale.com/types/key"
)

type failingMasquePacketConn struct {
	writeErr error
	closed   bool
}

func (*failingMasquePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *failingMasquePacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, c.writeErr
}

func (c *failingMasquePacketConn) Close() error {
	c.closed = true
	return nil
}

func (*failingMasquePacketConn) LocalAddr() net.Addr                { return nil }
func (*failingMasquePacketConn) SetDeadline(time.Time) error        { return nil }
func (*failingMasquePacketConn) SetReadDeadline(time.Time) error    { return nil }
func (*failingMasquePacketConn) SetWriteDeadline(time.Time) error   { return nil }

func TestMasquePathDatagramTooLargeDoesNotRetireCarrier(t *testing.T) {
	local := key.NewNode().Public()
	peer := key.NewNode().Public()
	pc := &failingMasquePacketConn{
		writeErr: &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1100},
	}
	path := &masquePath{local: local, pc: pc}

	err := path.ForwardPacket(local, peer, []byte("oversized-packet"))
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("ForwardPacket error = %v, want DatagramTooLargeError", err)
	}
	if pc.closed {
		t.Fatal("DATAGRAM size error closed a healthy MASQUE carrier")
	}
	got, err := path.packetConn()
	if err != nil {
		t.Fatalf("packetConn after DATAGRAM size error: %v", err)
	}
	if got != pc {
		t.Fatalf("packetConn after DATAGRAM size error = %T %p, want original %T %p", got, got, pc, pc)
	}
}

func TestMasquePathTransportWriteErrorStillRetiresCarrier(t *testing.T) {
	local := key.NewNode().Public()
	peer := key.NewNode().Public()
	writeErr := errors.New("transport unavailable")
	pc := &failingMasquePacketConn{writeErr: writeErr}
	path := &masquePath{local: local, pc: pc}

	err := path.ForwardPacket(local, peer, []byte("packet"))
	if !errors.Is(err, writeErr) {
		t.Fatalf("ForwardPacket error = %v, want %v", err, writeErr)
	}
	if !pc.closed {
		t.Fatal("transport write error did not retire MASQUE carrier")
	}
	if _, err := path.packetConn(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("packetConn after transport failure = %v, want net.ErrClosed", err)
	}
}
