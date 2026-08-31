//go:build !js

package tailcat

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
	"go4.org/mem"
	"tailscale.com/disco"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	masquePathTemplate = "/.well-known/masque/udp/{target_host}/{target_port}/"
	masqueSourceHeader = "Masquecat-Source"
	masqueModeHeader   = "Masquecat-Mode"

	masqueModeDirect = "direct"
	masqueModeRelay  = "relay"

	masquePacketVersion = byte(1)
	masqueVirtualPort   = "1"
	masquePeerSuffix    = ".peer.masquecat.invalid"
	nodePublicTextPrefix = "nodekey:"
)

var (
	contextIDZero   = quicvarint.Append(nil, 0)
	discoMagicBytes = []byte(disco.Magic)
)

type masqueDatagramStream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
}

type masquePacket struct {
	src     key.NodePublic
	dst     key.NodePublic
	payload []byte
}

func encodeMasquePacket(src, dst key.NodePublic, payload []byte) []byte {
	b := make([]byte, 0, 1+2*key.NodePublicRawLen+len(payload))
	b = append(b, masquePacketVersion)
	b = src.AppendTo(b)
	b = dst.AppendTo(b)
	b = append(b, payload...)
	return b
}

func decodeMasquePacket(b []byte) (masquePacket, error) {
	var p masquePacket
	const headerLen = 1 + 2*key.NodePublicRawLen
	if len(b) < headerLen {
		return p, fmt.Errorf("short MasqueCat datagram: %d bytes", len(b))
	}
	if b[0] != masquePacketVersion {
		return p, fmt.Errorf("unsupported MasqueCat datagram version %d", b[0])
	}
	p.src = key.NodePublicFromRaw32(mem.B(b[1 : 1+key.NodePublicRawLen]))
	p.dst = key.NodePublicFromRaw32(mem.B(b[1+key.NodePublicRawLen : headerLen]))
	p.payload = b[headerLen:]
	return p, nil
}

func masqueTarget(k key.NodePublic) string {
	keyText := strings.TrimPrefix(k.String(), nodePublicTextPrefix)
	return keyText + masquePeerSuffix + ":" + masqueVirtualPort
}

func parseMasqueTarget(target string) (key.NodePublic, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return key.NodePublic{}, fmt.Errorf("parse MASQUE target %q: %w", target, err)
	}
	if port != masqueVirtualPort {
		return key.NodePublic{}, fmt.Errorf("unexpected MASQUE virtual port %q", port)
	}
	hexKey, ok := strings.CutSuffix(host, masquePeerSuffix)
	if !ok {
		return key.NodePublic{}, fmt.Errorf("unexpected MASQUE target host %q", host)
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(nodePublicTextPrefix + hexKey)); err != nil {
		return key.NodePublic{}, fmt.Errorf("parse MASQUE peer key: %w", err)
	}
	return k, nil
}

func parseMasqueSource(r *http.Request) (key.NodePublic, error) {
	s := r.Header.Get(masqueSourceHeader)
	if s == "" {
		return key.NodePublic{}, errors.New("missing Masquecat-Source header")
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(s)); err != nil {
		return key.NodePublic{}, fmt.Errorf("invalid Masquecat-Source header: %w", err)
	}
	return k, nil
}

func masqueTemplateFor(rawBaseURL string) (*uritemplate.Template, error) {
	u, err := url.Parse(rawBaseURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("MASQUE endpoint must be an https URL with a host")
	}
	u.Path = masquePathTemplate
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return uritemplate.New(u.String())
}

// masquePath is the external MASQUE transport used by the loopback DERP
// compatibility bridge. It deliberately drops Tailscale disco packets: MASQUE
// paths are explicit, so CallMeMaybe/disco path discovery must never leave the
// process.
type masquePath struct {
	local key.NodePublic
	pc    net.PacketConn
	logf  logger.Logf

	writeMu sync.Mutex
}

func newMasquePath(ctx context.Context, rawURL string, requestTarget, local key.NodePublic, mode string, logf logger.Logf) (*masquePath, error) {
	tmpl, err := masqueTemplateFor(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := masque.NewRequest(ctx, tmpl, masqueTarget(requestTarget))
	if err != nil {
		return nil, fmt.Errorf("create CONNECT-UDP request: %w", err)
	}
	req.Header().Set(masqueSourceHeader, local.String())
	req.Header().Set(masqueModeHeader, mode)

	u, _ := url.Parse(rawURL)
	tr := &masque.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: u.Hostname(),
		},
		QUICConfig: &quic.Config{EnableDatagrams: true},
	}
	conn, resp, err := tr.Dial(req)
	if err != nil {
		return nil, fmt.Errorf("dial MASQUE endpoint %s: %w", rawURL, err)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		if resp == nil {
			return nil, errors.New("MASQUE endpoint returned no HTTP response")
		}
		return nil, fmt.Errorf("MASQUE endpoint returned %s", resp.Status)
	}
	return &masquePath{local: local, pc: conn, logf: logf}, nil
}

func (p *masquePath) ForwardPacket(src, dst key.NodePublic, payload []byte) error {
	if bytes.HasPrefix(payload, discoMagicBytes) {
		// This is the invariant that keeps Tailcat's legacy CallMeMaybe/disco
		// machinery inside the compatibility layer. MasqueCat never forwards
		// those packets to the network.
		return nil
	}
	b := encodeMasquePacket(src, dst, payload)
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_, err := p.pc.WriteTo(b, nil)
	return err
}

func (p *masquePath) String() string { return "masquecat-masque" }

func (p *masquePath) Close() error { return p.pc.Close() }

func (p *masquePath) run(ctx context.Context, local key.NodePublic, onPacket func(src key.NodePublic, payload []byte) error) error {
	buf := make([]byte, 64<<10)
	for {
		_ = p.pc.SetReadDeadline(noDeadline)
		n, _, err := p.pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		pkt, err := decodeMasquePacket(buf[:n])
		if err != nil {
			p.logf("dropping malformed MASQUE datagram: %v", err)
			continue
		}
		if pkt.dst != local {
			p.logf("dropping MASQUE datagram for unexpected destination %v", pkt.dst.ShortString())
			continue
		}
		if bytes.HasPrefix(pkt.payload, discoMagicBytes) {
			continue
		}
		if err := onPacket(pkt.src, pkt.payload); err != nil {
			return err
		}
	}
}

// streamForwarder adapts a server-side HTTP/3 CONNECT-UDP stream to the DERP
// server's PacketForwarder interface.
type streamForwarder struct {
	str masqueDatagramStream
	mu  sync.Mutex
}

func (f *streamForwarder) ForwardPacket(src, dst key.NodePublic, payload []byte) error {
	if bytes.HasPrefix(payload, discoMagicBytes) {
		return nil
	}
	packet := encodeMasquePacket(src, dst, payload)
	// HTTP/3 datagrams carry a QUIC varint context ID before the application
	// payload. Build a fresh slice for every send: contextIDZero is immutable
	// shared state and must never be used as append's destination backing array.
	b := make([]byte, 0, len(contextIDZero)+len(packet))
	b = append(b, contextIDZero...)
	b = append(b, packet...)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.str.SendDatagram(b)
}

func (f *streamForwarder) String() string { return "masquecat-h3-stream" }

func receiveStreamDatagram(ctx context.Context, str masqueDatagramStream) ([]byte, error) {
	for {
		b, err := str.ReceiveDatagram(ctx)
		if err != nil {
			return nil, err
		}
		contextID, n, err := quicvarint.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("malformed HTTP datagram: %w", err)
		}
		if contextID != 0 {
			continue
		}
		return b[n:], nil
	}
}

func acceptMasqueStream(w http.ResponseWriter) (masqueDatagramStream, error) {
	settingser, ok := w.(http3.Settingser)
	if !ok {
		return nil, errors.New("HTTP/3 response writer has no settings")
	}
	select {
	case <-settingser.ReceivedSettings():
		if !settingser.Settings().EnableDatagrams {
			return nil, errors.New("peer did not enable HTTP/3 datagrams")
		}
	default:
		// The settings are normally available before a request handler runs.
		// Avoid blocking a handler indefinitely if a non-conforming client is
		// used; Send/ReceiveDatagram will still surface a protocol error.
	}
	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.WriteHeader(http.StatusOK)
	hs, ok := w.(http3.HTTPStreamer)
	if !ok {
		return nil, errors.New("HTTP/3 response writer has no stream")
	}
	str := hs.HTTPStream()
	go func() {
		_, _ = io.Copy(io.Discard, str)
	}()
	return str, nil
}

func parseConnectUDPRequest(w http.ResponseWriter, r *http.Request, tmpl *uritemplate.Template) (*masque.ProxyRequest, bool) {
	req, err := masque.ParseProxyRequest(r, tmpl)
	if err == nil {
		return req, true
	}
	var perr *masque.ProxyRequestParseError
	if errors.As(err, &perr) {
		http.Error(w, perr.Error(), perr.HTTPStatus)
	} else {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	return nil, false
}

// noDeadline is used for net.PacketConn implementations where context
// cancellation closes the connection instead of using per-read deadlines.
var noDeadline = zeroTime
