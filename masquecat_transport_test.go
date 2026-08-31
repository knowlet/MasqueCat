//go:build !js

package tailcat

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/quic-go/quic-go/quicvarint"
	"tailscale.com/types/key"
)

type fakeMasqueDatagramStream struct {
	mu     sync.Mutex
	recv   chan fakeMasqueRecv
	sent   [][]byte
	closed int
}

type fakeMasqueRecv struct {
	b   []byte
	err error
}

func newFakeMasqueDatagramStream() *fakeMasqueDatagramStream {
	return &fakeMasqueDatagramStream{recv: make(chan fakeMasqueRecv, 16)}
}

func (f *fakeMasqueDatagramStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (f *fakeMasqueDatagramStream) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeMasqueDatagramStream) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}
func (f *fakeMasqueDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-f.recv:
		return r.b, r.err
	}
}
func (f *fakeMasqueDatagramStream) SendDatagram(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, append([]byte(nil), b...))
	return nil
}

func TestMasquePacketRoundTrip(t *testing.T) {
	src := key.NewNode().Public()
	dst := key.NewNode().Public()
	payload := bytes.Repeat([]byte{0x5a}, 1200)

	encoded := encodeMasquePacket(src, dst, payload)
	got, err := decodeMasquePacket(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.src != src || got.dst != dst {
		t.Fatalf("peer keys changed: got %v -> %v, want %v -> %v", got.src, got.dst, src, dst)
	}
	if !bytes.Equal(got.payload, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got.payload), len(payload))
	}
}

func TestDecodeMasquePacketRejectsMalformed(t *testing.T) {
	src := key.NewNode().Public()
	dst := key.NewNode().Public()
	valid := encodeMasquePacket(src, dst, []byte("payload"))

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "empty", in: nil},
		{name: "short header", in: valid[:10]},
		{name: "unsupported version", in: append([]byte{99}, valid[1:]...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeMasquePacket(tt.in); err == nil {
				t.Fatalf("decodeMasquePacket(%d bytes) unexpectedly succeeded", len(tt.in))
			}
		})
	}
}

func TestMasqueTargetRoundTrip(t *testing.T) {
	want := key.NewNode().Public()
	target := masqueTarget(want)
	got, err := parseMasqueTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("parseMasqueTarget(%q) = %v, want %v", target, got, want)
	}
}

func TestParseMasqueTargetRejectsInvalidTargets(t *testing.T) {
	k := key.NewNode().Public()
	hexKey := strings.TrimPrefix(k.String(), nodePublicTextPrefix)
	tests := []string{
		"missing-port",
		hexKey + masquePeerSuffix + ":2",
		hexKey + ".example.invalid:1",
		"not-a-key" + masquePeerSuffix + ":1",
	}
	for _, target := range tests {
		if _, err := parseMasqueTarget(target); err == nil {
			t.Errorf("parseMasqueTarget(%q) unexpectedly succeeded", target)
		}
	}
}

func TestMasqueTemplateValidation(t *testing.T) {
	if _, err := masqueTemplateFor("https://relay.example:8443"); err != nil {
		t.Fatalf("valid endpoint rejected: %v", err)
	}
	for _, raw := range []string{"http://relay.example", "https://", "://bad"} {
		if _, err := masqueTemplateFor(raw); err == nil {
			t.Errorf("masqueTemplateFor(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestParseMasqueSource(t *testing.T) {
	want := key.NewNode().Public()
	r, err := http.NewRequest(http.MethodConnect, "https://relay.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseMasqueSource(r); err == nil {
		t.Fatal("missing source header unexpectedly accepted")
	}
	r.Header.Set(masqueSourceHeader, want.String())
	got, err := parseMasqueSource(r)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("source = %v, want %v", got, want)
	}
	r.Header.Set(masqueSourceHeader, "invalid")
	if _, err := parseMasqueSource(r); err == nil {
		t.Fatal("invalid source header unexpectedly accepted")
	}
}

func TestReceiveStreamDatagramSkipsUnknownContext(t *testing.T) {
	f := newFakeMasqueDatagramStream()
	unknown := quicvarint.Append(nil, 7)
	unknown = append(unknown, []byte("ignore")...)
	valid := quicvarint.Append(nil, 0)
	valid = append(valid, []byte("payload")...)
	f.recv <- fakeMasqueRecv{b: unknown}
	f.recv <- fakeMasqueRecv{b: valid}

	got, err := receiveStreamDatagram(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" {
		t.Fatalf("payload = %q, want payload", got)
	}
}

func TestReceiveStreamDatagramRejectsMalformedContextID(t *testing.T) {
	f := newFakeMasqueDatagramStream()
	f.recv <- fakeMasqueRecv{b: []byte{0xff}}
	if _, err := receiveStreamDatagram(context.Background(), f); err == nil {
		t.Fatal("malformed context ID unexpectedly accepted")
	}
}

func TestReceiveStreamDatagramPropagatesError(t *testing.T) {
	f := newFakeMasqueDatagramStream()
	want := errors.New("boom")
	f.recv <- fakeMasqueRecv{err: want}
	_, err := receiveStreamDatagram(context.Background(), f)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestStreamForwarderFramesPacket(t *testing.T) {
	f := newFakeMasqueDatagramStream()
	forwarder := &streamForwarder{str: f}
	src := key.NewNode().Public()
	dst := key.NewNode().Public()
	payload := []byte("wireguard-ciphertext")

	if err := forwarder.ForwardPacket(src, dst, payload); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != 1 {
		t.Fatalf("sent datagrams = %d, want 1", len(f.sent))
	}
	contextID, n, err := quicvarint.Parse(f.sent[0])
	if err != nil {
		t.Fatal(err)
	}
	if contextID != 0 {
		t.Fatalf("context ID = %d, want 0", contextID)
	}
	pkt, err := decodeMasquePacket(f.sent[0][n:])
	if err != nil {
		t.Fatal(err)
	}
	if pkt.src != src || pkt.dst != dst || !bytes.Equal(pkt.payload, payload) {
		t.Fatalf("forwarded packet mismatch: %#v", pkt)
	}
}

func TestStreamForwarderDropsDisco(t *testing.T) {
	f := newFakeMasqueDatagramStream()
	forwarder := &streamForwarder{str: f}
	payload := append(append([]byte(nil), discoMagicBytes...), []byte("should-not-leave-process")...)
	if err := forwarder.ForwardPacket(key.NewNode().Public(), key.NewNode().Public(), payload); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != 0 {
		t.Fatalf("disco packet escaped MASQUE boundary: %d sends", len(f.sent))
	}
}

func TestStreamForwarderConcurrentSendsAreIndependent(t *testing.T) {
	f := newFakeMasqueDatagramStream()
	forwarder := &streamForwarder{str: f}
	src := key.NewNode().Public()
	dst := key.NewNode().Public()

	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			payload := bytes.Repeat([]byte{byte(i)}, 128+i)
			if err := forwarder.ForwardPacket(src, dst, payload); err != nil {
				t.Errorf("ForwardPacket: %v", err)
			}
		}()
	}
	wg.Wait()
	if len(f.sent) != goroutines {
		t.Fatalf("sent datagrams = %d, want %d", len(f.sent), goroutines)
	}
	for i, b := range f.sent {
		contextID, n, err := quicvarint.Parse(b)
		if err != nil || contextID != 0 {
			t.Fatalf("datagram %d has invalid context: id=%d err=%v", i, contextID, err)
		}
		if _, err := decodeMasquePacket(b[n:]); err != nil {
			t.Fatalf("datagram %d decode failed: %v", i, err)
		}
	}
}

func TestMasqueRelayRegistryReplacement(t *testing.T) {
	r := new(MasqueRelay)
	k := key.NewNode().Public()
	oldStream := newFakeMasqueDatagramStream()
	newStream := newFakeMasqueDatagramStream()
	oldPeer := &relayPeer{key: k, fwd: &streamForwarder{str: oldStream}}
	newPeer := &relayPeer{key: k, fwd: &streamForwarder{str: newStream}}

	r.register(oldPeer)
	if got := r.lookup(k); got != oldPeer {
		t.Fatalf("lookup after first register = %p, want %p", got, oldPeer)
	}
	r.register(newPeer)
	if got := r.lookup(k); got != newPeer {
		t.Fatalf("lookup after replacement = %p, want %p", got, newPeer)
	}
	oldStream.mu.Lock()
	closed := oldStream.closed
	oldStream.mu.Unlock()
	if closed != 1 {
		t.Fatalf("old stream close count = %d, want 1", closed)
	}

	// Unregistering a stale peer must not remove its replacement.
	r.unregister(oldPeer)
	if got := r.lookup(k); got != newPeer {
		t.Fatalf("stale unregister removed replacement: got %p, want %p", got, newPeer)
	}
	r.unregister(newPeer)
	if got := r.lookup(k); got != nil {
		t.Fatalf("lookup after unregister = %p, want nil", got)
	}
}
