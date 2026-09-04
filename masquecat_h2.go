//go:build !js

package tailcat

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
	_ "unsafe"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"tailscale.com/types/key"
)

const (
	masqueConnectUDPProtocol = "connect-udp"
	masqueDatagramCapsule    = uint64(0)
	maxMasqueCapsuleSize     = 1 << 20
)

// x/net/http2 has full RFC 8441 Extended CONNECT support, but currently keeps
// it behind GODEBUG=http2xconnect=1 because enabling it for arbitrary HTTP
// servers can change WebSocket behavior. MasqueCat owns the HTTP/2 server it
// creates and needs Extended CONNECT unconditionally for RFC 9298.
//
// Keep this workaround isolated here so it can be deleted as soon as x/net
// exposes a per-server switch. It affects only x/net/http2, not net/http's
// bundled HTTP/2 implementation.
//go:linkname http2DisableExtendedConnectProtocol golang.org/x/net/http2.disableExtendedConnectProtocol
var http2DisableExtendedConnectProtocol bool

func enableMasqueH2ExtendedConnect() {
	http2DisableExtendedConnectProtocol = false
}

type masqueCapsuleStream struct {
	ctx context.Context
	r   io.ReadCloser
	w   io.Writer

	closeWriter func() error
	flush       func()

	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

func (s *masqueCapsuleStream) Read(p []byte) (int, error) {
	return s.r.Read(p)
}

func (s *masqueCapsuleStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	n, err := s.w.Write(p)
	if err == nil && s.flush != nil {
		s.flush()
	}
	return n, err
}

func (s *masqueCapsuleStream) Close() error {
	s.closeOnce.Do(func() {
		var errs []error
		if s.closeWriter != nil {
			errs = append(errs, s.closeWriter())
		}
		if s.r != nil {
			errs = append(errs, s.r.Close())
		}
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

func (s *masqueCapsuleStream) SendDatagram(b []byte) error {
	frame := quicvarint.Append(nil, masqueDatagramCapsule)
	frame = quicvarint.Append(frame, uint64(len(b)))
	frame = append(frame, b...)
	_, err := s.Write(frame)
	return err
}

func (s *masqueCapsuleStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		capsuleType, err := readMasqueQUICVarint(s.r)
		if err != nil {
			return nil, err
		}
		capsuleLen, err := readMasqueQUICVarint(s.r)
		if err != nil {
			return nil, err
		}
		if capsuleType != masqueDatagramCapsule {
			if _, err := io.CopyN(io.Discard, s.r, int64(capsuleLen)); err != nil {
				return nil, err
			}
			continue
		}
		if capsuleLen > maxMasqueCapsuleSize {
			return nil, fmt.Errorf("masquecat: HTTP/2 DATAGRAM capsule too large: %d", capsuleLen)
		}
		b := make([]byte, int(capsuleLen))
		if _, err := io.ReadFull(s.r, b); err != nil {
			return nil, err
		}
		return b, nil
	}
}

func readMasqueQUICVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	n := 1 << (first[0] >> 6)
	buf := make([]byte, n)
	buf[0] = first[0]
	if n > 1 {
		if _, err := io.ReadFull(r, buf[1:]); err != nil {
			return 0, err
		}
	}
	v, _, err := quicvarint.Parse(buf)
	return v, err
}

type masqueH2PacketConn struct {
	ctx       context.Context
	str       *masqueCapsuleStream
	transport *http2.Transport
}

func (c *masqueH2PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	b, err := receiveStreamDatagram(c.ctx, c.str)
	if err != nil {
		return 0, nil, err
	}
	if len(b) > len(p) {
		return 0, nil, io.ErrShortBuffer
	}
	copy(p, b)
	return len(b), masqueH2Addr{}, nil
}

func (c *masqueH2PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	b := make([]byte, 0, len(contextIDZero)+len(p))
	b = append(b, contextIDZero...)
	b = append(b, p...)
	if err := c.str.SendDatagram(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *masqueH2PacketConn) Close() error {
	err := c.str.Close()
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	return err
}

func (*masqueH2PacketConn) LocalAddr() net.Addr                { return masqueH2Addr{} }
func (*masqueH2PacketConn) SetDeadline(time.Time) error        { return nil }
func (*masqueH2PacketConn) SetReadDeadline(time.Time) error    { return nil }
func (*masqueH2PacketConn) SetWriteDeadline(time.Time) error   { return nil }

type masqueH2Addr struct{}

func (masqueH2Addr) Network() string { return "masque-h2" }
func (masqueH2Addr) String() string  { return "masque-h2" }

func dialMasqueH2PacketConn(
	ctx context.Context,
	tmpl *uritemplate.Template,
	target key.NodePublic,
	local key.NodePrivate,
	mode string,
	tlsConfig *tls.Config,
) (net.PacketConn, error) {
	expandedURL, err := expandMasqueTargetURL(tmpl, masqueTarget(target))
	if err != nil {
		return nil, err
	}
	h2TLS := tlsConfig.Clone()
	h2TLS.NextProtos = []string{http2.NextProtoTLS}
	tr := &http2.Transport{TLSClientConfig: h2TLS}

	dial := func(proof string) (*masqueH2PacketConn, *http.Response, error) {
		pr, pw := io.Pipe()
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, expandedURL, pr)
		if err != nil {
			_ = pr.Close()
			_ = pw.Close()
			return nil, nil, err
		}
		req.Host = req.URL.Host
		req.Header.Set(":protocol", masqueConnectUDPProtocol)
		req.Header.Set(http3.CapsuleProtocolHeader, "?1")
		req.Header.Set(masqueSourceHeader, local.Public().String())
		req.Header.Set(masqueModeHeader, mode)
		if proof != "" {
			req.Header.Set(masqueProofHeader, proof)
		}

		resp, err := tr.RoundTrip(req)
		if err != nil {
			_ = pw.CloseWithError(err)
			_ = pr.CloseWithError(err)
			return nil, nil, err
		}
		if resp.ProtoMajor != 2 {
			_ = pw.Close()
			_ = resp.Body.Close()
			return nil, resp, fmt.Errorf("masquecat: CONNECT-UDP fallback negotiated %s instead of HTTP/2", resp.Proto)
		}
		str := &masqueCapsuleStream{
			ctx:         ctx,
			r:           resp.Body,
			w:           pw,
			closeWriter: pw.Close,
		}
		return &masqueH2PacketConn{ctx: ctx, str: str, transport: tr}, resp, nil
	}

	conn, resp, err := dial("")
	if err != nil {
		tr.CloseIdleConnections()
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get(masqueChallengeHeader)
		_ = conn.Close()
		proof, proofErr := masqueProofForChallenge(local, challenge, target, mode)
		if proofErr != nil {
			return nil, fmt.Errorf("masquecat: authenticate HTTP/2 CONNECT-UDP: %w", proofErr)
		}
		tr = &http2.Transport{TLSClientConfig: h2TLS}
		conn, resp, err = dial(proof)
		if err != nil {
			tr.CloseIdleConnections()
			return nil, err
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status := resp.Status
		_ = conn.Close()
		return nil, fmt.Errorf("masquecat: HTTP/2 CONNECT-UDP failed: %s", status)
	}
	return conn, nil
}

func expandMasqueTargetURL(tmpl *uritemplate.Template, target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("masquecat: parse CONNECT-UDP target: %w", err)
	}
	u, err := tmpl.Expand(uritemplate.Values{
		"target_host": uritemplate.String(host),
		"target_port": uritemplate.String(port),
	})
	if err != nil {
		return "", fmt.Errorf("masquecat: expand CONNECT-UDP template: %w", err)
	}
	return u, nil
}

func acceptMasqueH2Stream(w http.ResponseWriter, r *http.Request) (masqueDatagramStream, error) {
	if r.ProtoMajor != 2 || r.Header.Get(":protocol") != masqueConnectUDPProtocol {
		return nil, errors.New("masquecat: request is not HTTP/2 CONNECT-UDP")
	}
	if r.Body == nil {
		return nil, errors.New("masquecat: HTTP/2 CONNECT-UDP request has no stream body")
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, errors.New("masquecat: HTTP/2 response writer does not support flushing")
	}
	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	return &masqueCapsuleStream{
		ctx:   r.Context(),
		r:     r.Body,
		w:     w,
		flush: flusher.Flush,
	}, nil
}

func newMasqueHTTP2Server(tlsConfig *tls.Config, handler http.Handler) (*http.Server, error) {
	if tlsConfig == nil {
		return nil, errors.New("masquecat: nil HTTP/2 TLS config")
	}
	enableMasqueH2ExtendedConnect()
	conf := tlsConfig.Clone()
	conf.MinVersion = tls.VersionTLS13
	srv := &http.Server{TLSConfig: conf, Handler: handler}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		return nil, fmt.Errorf("masquecat: configure HTTP/2 server: %w", err)
	}
	// This listener is specifically for the RFC 9298 fallback. Do not silently
	// downgrade the fallback socket to HTTP/1.1.
	srv.TLSConfig.NextProtos = []string{http2.NextProtoTLS}
	return srv, nil
}
