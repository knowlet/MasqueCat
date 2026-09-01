//go:build !js

package tailcat

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"tailscale.com/types/key"
)

type fakeReconnectPacketConn struct {
	reads chan fakeReconnectRead
	done  chan struct{}
	once  sync.Once

	mu     sync.Mutex
	writes [][]byte
}

type fakeReconnectRead struct {
	b   []byte
	err error
}

type fakeReconnectAddr string

func (a fakeReconnectAddr) Network() string { return "udp" }
func (a fakeReconnectAddr) String() string  { return string(a) }

func newFakeReconnectPacketConn() *fakeReconnectPacketConn {
	return &fakeReconnectPacketConn{
		reads: make(chan fakeReconnectRead, 8),
		done:  make(chan struct{}),
	}
}

func (f *fakeReconnectPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-f.done:
		return 0, nil, net.ErrClosed
	case r := <-f.reads:
		if r.err != nil {
			return 0, nil, r.err
		}
		return copy(p, r.b), fakeReconnectAddr("peer"), nil
	}
}

func (f *fakeReconnectPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-f.done:
		return 0, net.ErrClosed
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (f *fakeReconnectPacketConn) Close() error {
	f.once.Do(func() { close(f.done) })
	return nil
}

func (f *fakeReconnectPacketConn) LocalAddr() net.Addr              { return fakeReconnectAddr("local") }
func (f *fakeReconnectPacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeReconnectPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeReconnectPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestMasqueQUICConfigEnablesKeepalive(t *testing.T) {
	cfg := masqueQUICConfig()
	if !cfg.EnableDatagrams {
		t.Fatal("QUIC datagrams disabled")
	}
	if cfg.KeepAlivePeriod != masqueKeepAlivePeriod {
		t.Fatalf("KeepAlivePeriod = %v, want %v", cfg.KeepAlivePeriod, masqueKeepAlivePeriod)
	}
	if cfg.MaxIdleTimeout != masqueMaxIdleTimeout {
		t.Fatalf("MaxIdleTimeout = %v, want %v", cfg.MaxIdleTimeout, masqueMaxIdleTimeout)
	}
	if cfg.KeepAlivePeriod <= 0 || cfg.MaxIdleTimeout <= cfg.KeepAlivePeriod {
		t.Fatalf("invalid keepalive/idle relationship: keepalive=%v idle=%v", cfg.KeepAlivePeriod, cfg.MaxIdleTimeout)
	}
}

func TestMasquePathRunReconnectsAndKeepsStableForwarder(t *testing.T) {
	local := key.NewNode().Public()
	remote := key.NewNode().Public()
	first := newFakeReconnectPacketConn()
	second := newFakeReconnectPacketConn()

	var dialMu sync.Mutex
	dialCalls := 0
	p := &masquePath{
		local: local,
		pc:    first,
		logf:  t.Logf,
		reconnectBackoff: func(int) time.Duration {
			return 0
		},
	}
	p.dial = func(context.Context) (net.PacketConn, error) {
		dialMu.Lock()
		defer dialMu.Unlock()
		dialCalls++
		if dialCalls == 1 {
			return nil, errors.New("temporary reconnect failure")
		}
		return second, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gotPacket := make(chan []byte, 1)
	runDone := make(chan error, 1)
	go func() {
		runDone <- p.run(ctx, local, func(src key.NodePublic, payload []byte) error {
			if src != remote {
				return errors.New("unexpected source")
			}
			gotPacket <- append([]byte(nil), payload...)
			return nil
		})
	}()

	first.reads <- fakeReconnectRead{err: errors.New("old QUIC connection lost")}
	wantPayload := []byte("after-reconnect")
	second.reads <- fakeReconnectRead{b: encodeMasquePacket(remote, local, wantPayload)}

	select {
	case got := <-gotPacket:
		if !bytes.Equal(got, wantPayload) {
			t.Fatalf("received payload = %q, want %q", got, wantPayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for packet after reconnect")
	}

	dialMu.Lock()
	calls := dialCalls
	dialMu.Unlock()
	if calls != 2 {
		t.Fatalf("reconnect dial calls = %d, want 2", calls)
	}

	outbound := []byte("outbound-after-reconnect")
	if err := p.ForwardPacket(local, remote, outbound); err != nil {
		t.Fatalf("ForwardPacket after reconnect: %v", err)
	}
	second.mu.Lock()
	if len(second.writes) != 1 {
		second.mu.Unlock()
		t.Fatalf("writes on replacement connection = %d, want 1", len(second.writes))
	}
	written := append([]byte(nil), second.writes[0]...)
	second.mu.Unlock()
	pkt, err := decodeMasquePacket(written)
	if err != nil {
		t.Fatalf("decode forwarded packet: %v", err)
	}
	if pkt.src != local || pkt.dst != remote || !bytes.Equal(pkt.payload, outbound) {
		t.Fatalf("forwarded packet after reconnect = %#v", pkt)
	}

	cancel()
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("run error after shutdown = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop after shutdown")
	}
}

func TestMasqueReconnectBackoffCaps(t *testing.T) {
	if got := masqueReconnectBackoff(0); got != 0 {
		t.Fatalf("attempt 0 backoff = %v, want 0", got)
	}
	if got := masqueReconnectBackoff(1); got != masqueReconnectInitialBackoff {
		t.Fatalf("attempt 1 backoff = %v, want %v", got, masqueReconnectInitialBackoff)
	}
	if got := masqueReconnectBackoff(100); got != masqueReconnectMaxBackoff {
		t.Fatalf("large attempt backoff = %v, want %v", got, masqueReconnectMaxBackoff)
	}
}
