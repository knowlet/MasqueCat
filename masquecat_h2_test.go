//go:build !js

package tailcat

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

func TestMasqueCapsuleStreamRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	writer := &masqueCapsuleStream{r: io.NopCloser(bytes.NewReader(nil)), w: &wire}
	payload := []byte("masquecat-h2")
	if err := writer.SendDatagram(payload); err != nil {
		t.Fatal(err)
	}

	reader := &masqueCapsuleStream{r: io.NopCloser(bytes.NewReader(wire.Bytes())), w: io.Discard}
	got, err := reader.ReceiveDatagram(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestMasqueCapsuleStreamSkipsUnknownCapsules(t *testing.T) {
	var wire []byte
	wire = quicvarint.Append(wire, 0x2a)
	wire = quicvarint.Append(wire, 3)
	wire = append(wire, "old"...)
	wire = quicvarint.Append(wire, masqueDatagramCapsule)
	wire = quicvarint.Append(wire, 4)
	wire = append(wire, "keep"...)

	stream := &masqueCapsuleStream{r: io.NopCloser(bytes.NewReader(wire)), w: io.Discard}
	got, err := stream.ReceiveDatagram(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("payload = %q, want keep", got)
	}
}

func TestMasqueHTTP2ExtendedConnectDatagram(t *testing.T) {
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	cert := seed.TLS.Certificates[0]
	seed.Close()

	handlerErr := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			handlerErr <- fmt.Errorf("method = %s, want CONNECT", r.Method)
			return
		}
		if r.Header.Get(":protocol") != masqueConnectUDPProtocol {
			handlerErr <- fmt.Errorf(":protocol = %q", r.Header.Get(":protocol"))
			return
		}
		str, err := acceptMasqueH2Stream(w, r)
		if err != nil {
			handlerErr <- err
			return
		}
		defer func() { _ = str.Close() }()
		got, err := receiveStreamDatagram(r.Context(), str)
		if err != nil {
			handlerErr <- err
			return
		}
		if string(got) != "hello" {
			handlerErr <- fmt.Errorf("request datagram = %q, want hello", got)
			return
		}
		out := append(append([]byte(nil), contextIDZero...), []byte("world")...)
		if err := str.SendDatagram(out); err != nil {
			handlerErr <- err
			return
		}
		handlerErr <- nil
	})

	srv, err := newMasqueHTTP2Server(&tls.Config{Certificates: []tls.Certificate{cert}}, handler)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = srv.Serve(tls.NewListener(ln, srv.TLSConfig)) }()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+ln.Addr().String()+"/.well-known/masque/udp/test.invalid/1/", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(":protocol", masqueConnectUDPProtocol)
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")
	tr := &http2.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // test-only ephemeral certificate
		NextProtos:         []string{http2.NextProtoTLS},
	}}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("response = %s over %s", resp.Status, resp.Proto)
	}
	if got := resp.Header.Get(http3.CapsuleProtocolHeader); got != "?1" {
		t.Fatalf("Capsule-Protocol = %q, want ?1", got)
	}

	client := &masqueCapsuleStream{r: resp.Body, w: pw, closeWriter: pw.Close}
	requestDatagram := append(append([]byte(nil), contextIDZero...), []byte("hello")...)
	if err := client.SendDatagram(requestDatagram); err != nil {
		t.Fatal(err)
	}
	got, err := receiveStreamDatagram(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Fatalf("response datagram = %q, want world", got)
	}
	if err := <-handlerErr; err != nil {
		t.Fatal(err)
	}
}

func TestMasqueHTTP2CompanionAddrUsesUDPPortForEphemeralListen(t *testing.T) {
	got, err := masqueHTTP2CompanionAddr("127.0.0.1:0", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43210})
	if err != nil {
		t.Fatal(err)
	}
	if got != "127.0.0.1:43210" {
		t.Fatalf("companion address = %q, want 127.0.0.1:43210", got)
	}
}
