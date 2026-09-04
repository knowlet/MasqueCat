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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	masqueConnectUDPProtocol = "connect-udp"
	masqueDatagramCapsule    = uint64(0)
	maxMasqueCapsuleSize     = 64 << 10

	masqueH2InitialWindow   = uint32(1 << 20)
	masqueH2ReadIdleTimeout = 30 * time.Second
	masqueH2PingTimeout     = 15 * time.Second
	masqueH2WriteTimeout    = 30 * time.Second
)

type masqueCapsuleStream struct {
	r io.ReadCloser
	w io.Writer

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
			if capsuleLen > maxMasqueCapsuleSize {
				return nil, fmt.Errorf("masquecat: HTTP/2 capsule too large: %d", capsuleLen)
			}
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

func (*masqueH2PacketConn) LocalAddr() net.Addr              { return masqueH2Addr{} }
func (*masqueH2PacketConn) SetDeadline(time.Time) error      { return nil }
func (*masqueH2PacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*masqueH2PacketConn) SetWriteDeadline(time.Time) error { return nil }

type masqueH2Addr struct{}

func (masqueH2Addr) Network() string { return "masque-h2" }
func (masqueH2Addr) String() string  { return "masque-h2" }

func newMasqueHTTP2Transport(tlsConfig *tls.Config) *http2.Transport {
	h2TLS := tlsConfig.Clone()
	h2TLS.NextProtos = []string{http2.NextProtoTLS}
	return &http2.Transport{
		TLSClientConfig: h2TLS,
		ReadIdleTimeout: masqueH2ReadIdleTimeout,
		PingTimeout:     masqueH2PingTimeout,
		WriteByteTimeout: masqueH2WriteTimeout,
	}
}

// newMasquePathWithFallback keeps HTTP/3 as the preferred carrier and retries
// the exact same authenticated CONNECT-UDP exchange over HTTP/2 when QUIC is
// unavailable. The dial function is retained on masquePath so reconnects also
// re-evaluate H3 first and can recover back to it automatically.
func newMasquePathWithFallback(
	ctx context.Context,
	rawURL string,
	target key.NodePublic,
	local key.NodePrivate,
	mode string,
	insecureSkipVerify bool,
	logf logger.Logf,
) (*masquePath, error) {
	if local.IsZero() {
		return nil, errors.New("masquecat: zero local node private key")
	}
	if target.IsZero() {
		return nil, errors.New("masquecat: zero MASQUE target node key")
	}
	tmpl, err := masqueTemplateFor(rawURL)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := masqueTLSClientConfig(rawURL, insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	if insecureSkipVerify && logf != nil {
		logf("WARNING: MASQUE TLS verification disabled for %s", rawURL)
	} else if tlsConfig.InsecureSkipVerify && len(tlsConfig.Certificates) == 0 && logf != nil {
		logf("MASQUE TLS certificate pinning enabled for %s", rawURL)
	}

	dial := func(dialCtx context.Context) (net.PacketConn, error) {
		h3, h3Err := dialMasquePacketConn(dialCtx, tmpl, rawURL, target, local, mode, tlsConfig)
		if h3Err == nil {
			return h3, nil
		}
		h2, h2Err := dialMasqueH2PacketConn(dialCtx, tmpl, target, local, mode, tlsConfig)
		if h2Err == nil {
			if logf != nil {
				logf("MASQUE HTTP/3 unavailable; using HTTP/2 CONNECT-UDP fallback for %s: %v", rawURL, h3Err)
			}
			return h2, nil
		}
		return nil, errors.Join(
			fmt.Errorf("HTTP/3 CONNECT-UDP: %w", h3Err),
			fmt.Errorf("HTTP/2 CONNECT-UDP: %w", h2Err),
		)
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	return &masquePath{local: local.Public(), logf: logf, dial: dial, pc: conn}, nil
}

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
	tr := newMasqueHTTP2Transport(tlsConfig)

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
		verifierText := resp.Header.Get(masqueVerifierHeader)
		_ = conn.Close()
		proof, proofErr := masqueProofForChallenge(local, challenge, verifierText, target, mode)
		if proofErr != nil {
			return nil, fmt.Errorf("masquecat: authenticate HTTP/2 CONNECT-UDP: %w", proofErr)
		}
		tr = newMasqueHTTP2Transport(tlsConfig)
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

// parseConnectUDPRequestAny normalizes HTTP/2's :protocol pseudo-header into
// the representation masque-go expects for HTTP/3 before reusing the existing
// path-template validation logic. Go exposes RFC 8441's :protocol value to
// handlers through Request.Header[":protocol"].
func parseConnectUDPRequestAny(w http.ResponseWriter, r *http.Request, tmpl *uritemplate.Template) (*masque.ProxyRequest, bool) {
	if r.ProtoMajor != 2 {
		return parseConnectUDPRequest(w, r, tmpl)
	}
	if r.Method != http.MethodConnect || r.Header.Get(":protocol") != masqueConnectUDPProtocol {
		http.Error(w, "expected HTTP/2 extended CONNECT-UDP", http.StatusNotImplemented)
		return nil, false
	}
	clone := r.Clone(r.Context())
	clone.Proto = masqueConnectUDPProtocol
	return parseConnectUDPRequest(w, clone, tmpl)
}

func acceptMasqueAnyStream(w http.ResponseWriter, r *http.Request) (masqueDatagramStream, error) {
	if r.ProtoMajor == 2 {
		return acceptMasqueH2Stream(w, r)
	}
	return acceptMasqueStream(w)
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
		r:     r.Body,
		w:     w,
		flush: flusher.Flush,
	}, nil
}

// masqueHTTP2Server is a deliberately small HTTP/2 server dedicated to the
// long-lived RFC 8441 Extended CONNECT stream used by CONNECT-UDP. Go 1.27
// does not yet expose a per-server EnableConnectProtocol switch, so using the
// standard net/http HTTP/2 server would require mutating a package-global
// GODEBUG-controlled flag. Owning this narrow frontend lets MasqueCat advertise
// SETTINGS_ENABLE_CONNECT_PROTOCOL without affecting unrelated HTTP/2 servers
// in the same process.
type masqueHTTP2Server struct {
	TLSConfig *tls.Config
	Handler   http.Handler

	mu        sync.Mutex
	closed    bool
	listeners map[net.Listener]struct{}
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
}

func newMasqueHTTP2Server(tlsConfig *tls.Config, handler http.Handler) (*masqueHTTP2Server, error) {
	if tlsConfig == nil {
		return nil, errors.New("masquecat: nil HTTP/2 TLS config")
	}
	if handler == nil {
		return nil, errors.New("masquecat: nil HTTP/2 handler")
	}
	conf := tlsConfig.Clone()
	conf.MinVersion = tls.VersionTLS13
	conf.NextProtos = []string{http2.NextProtoTLS}
	return &masqueHTTP2Server{
		TLSConfig: conf,
		Handler:   handler,
		listeners: make(map[net.Listener]struct{}),
		conns:     make(map[net.Conn]struct{}),
	}, nil
}

func (s *masqueHTTP2Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return http.ErrServerClosed
	}
	s.listeners[ln] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, ln)
		s.mu.Unlock()
		s.wg.Done()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return http.ErrServerClosed
			}
			return err
		}

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return http.ErrServerClosed
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func(c net.Conn) {
			defer func() {
				_ = c.Close()
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
				s.wg.Done()
			}()
			_ = s.serveConn(c)
		}(conn)
	}
}

func (s *masqueHTTP2Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.wg.Wait()
		return nil
	}
	s.closed = true
	listeners := make([]net.Listener, 0, len(s.listeners))
	for ln := range s.listeners {
		listeners = append(listeners, ln)
	}
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()

	var errs []error
	for _, ln := range listeners {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	for _, conn := range conns {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	s.wg.Wait()
	return errors.Join(errs...)
}

type masqueHTTP2Conn struct {
	conn    net.Conn
	fr      *http2.Framer
	handler http.Handler

	ctx    context.Context
	cancel context.CancelFunc

	writeMu sync.Mutex
	flowMu  sync.Mutex
	flowCh  chan struct{}
	done    chan struct{}
	doneOnce sync.Once

	peerConnWindow     int64
	peerStreamWindow   int64
	peerInitialWindow  int64
	peerMaxFrameSize   uint32
	streamID           uint32
	bodyW              *io.PipeWriter
}

func (s *masqueHTTP2Server) serveConn(conn net.Conn) error {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return errors.New("masquecat: HTTP/2 listener accepted a non-TLS connection")
	}
	handshakeCtx, cancelHandshake := context.WithTimeout(context.Background(), masqueH2WriteTimeout)
	err := tlsConn.HandshakeContext(handshakeCtx)
	cancelHandshake()
	if err != nil {
		return err
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
		return fmt.Errorf("masquecat: HTTP/2 listener negotiated %q", tlsConn.ConnectionState().NegotiatedProtocol)
	}

	var preface [len(http2.ClientPreface)]byte
	if _, err := io.ReadFull(conn, preface[:]); err != nil {
		return err
	}
	if string(preface[:]) != http2.ClientPreface {
		return errors.New("masquecat: invalid HTTP/2 client preface")
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &masqueHTTP2Conn{
		conn:               conn,
		handler:            s.Handler,
		ctx:                ctx,
		cancel:             cancel,
		flowCh:             make(chan struct{}, 1),
		done:               make(chan struct{}),
		peerConnWindow:     65535,
		peerStreamWindow:   65535,
		peerInitialWindow:  65535,
		peerMaxFrameSize:   16384,
	}
	defer c.close()
	c.fr = http2.NewFramer(conn, conn)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	if err := c.writeSettings(); err != nil {
		return err
	}
	return c.readLoop(tlsConn)
}

func (c *masqueHTTP2Conn) close() {
	c.doneOnce.Do(func() {
		close(c.done)
		c.cancel()
		if c.bodyW != nil {
			_ = c.bodyW.CloseWithError(net.ErrClosed)
		}
		select {
		case c.flowCh <- struct{}{}:
		default:
		}
	})
}

func (c *masqueHTTP2Conn) writeFrame(fn func() error) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.conn.SetWriteDeadline(time.Now().Add(masqueH2WriteTimeout)); err != nil {
		return err
	}
	err := fn()
	_ = c.conn.SetWriteDeadline(time.Time{})
	return err
}

func (c *masqueHTTP2Conn) writeSettings() error {
	if err := c.writeFrame(func() error {
		return c.fr.WriteSettings(
			http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1},
			http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: masqueH2InitialWindow},
		)
	}); err != nil {
		return err
	}
	return c.writeFrame(func() error {
		return c.fr.WriteWindowUpdate(0, masqueH2InitialWindow-65535)
	})
}

func (c *masqueHTTP2Conn) readLoop(tlsConn *tls.Conn) error {
	for {
		frame, err := c.fr.ReadFrame()
		if err != nil {
			return err
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if err := c.handleSettings(f); err != nil {
				return err
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				if err := c.writeFrame(func() error { return c.fr.WritePing(true, f.Data) }); err != nil {
					return err
				}
			}
		case *http2.WindowUpdateFrame:
			if err := c.handleWindowUpdate(f); err != nil {
				return err
			}
		case *http2.MetaHeadersFrame:
			if c.streamID != 0 {
				if f.StreamID != c.streamID {
					_ = c.writeFrame(func() error { return c.fr.WriteRSTStream(f.StreamID, http2.ErrCodeRefusedStream) })
					continue
				}
				if f.StreamEnded() && c.bodyW != nil {
					_ = c.bodyW.Close()
				}
				continue
			}
			if err := c.startRequest(tlsConn, f); err != nil {
				return err
			}
		case *http2.DataFrame:
			if f.StreamID != c.streamID || c.bodyW == nil {
				continue
			}
			data := f.Data()
			if len(data) != 0 {
				if _, err := c.bodyW.Write(data); err != nil {
					return err
				}
				inc := uint32(len(data))
				if err := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(0, inc) }); err != nil {
					return err
				}
				if err := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(c.streamID, inc) }); err != nil {
					return err
				}
			}
			if f.StreamEnded() {
				_ = c.bodyW.Close()
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == c.streamID {
				return fmt.Errorf("masquecat: HTTP/2 CONNECT stream reset: %s", f.ErrCode)
			}
		case *http2.GoAwayFrame:
			return io.EOF
		}
	}
}

func (c *masqueHTTP2Conn) handleSettings(f *http2.SettingsFrame) error {
	if f.IsAck() {
		return nil
	}
	if err := f.ForeachSetting(func(s http2.Setting) error {
		c.flowMu.Lock()
		defer c.flowMu.Unlock()
		switch s.ID {
		case http2.SettingInitialWindowSize:
			delta := int64(s.Val) - c.peerInitialWindow
			c.peerInitialWindow = int64(s.Val)
			if c.streamID != 0 {
				c.peerStreamWindow += delta
			}
		case http2.SettingMaxFrameSize:
			c.peerMaxFrameSize = s.Val
		}
		return nil
	}); err != nil {
		return err
	}
	select {
	case c.flowCh <- struct{}{}:
	default:
	}
	return c.writeFrame(c.fr.WriteSettingsAck)
}

func (c *masqueHTTP2Conn) handleWindowUpdate(f *http2.WindowUpdateFrame) error {
	c.flowMu.Lock()
	defer c.flowMu.Unlock()
	if f.StreamID == 0 {
		c.peerConnWindow += int64(f.Increment)
	} else if f.StreamID == c.streamID {
		c.peerStreamWindow += int64(f.Increment)
	}
	if c.peerConnWindow > (1<<31)-1 || c.peerStreamWindow > (1<<31)-1 {
		return errors.New("masquecat: HTTP/2 flow-control window overflow")
	}
	select {
	case c.flowCh <- struct{}{}:
	default:
	}
	return nil
}

func (c *masqueHTTP2Conn) startRequest(tlsConn *tls.Conn, f *http2.MetaHeadersFrame) error {
	if f.StreamID == 0 || f.StreamID%2 == 0 {
		return errors.New("masquecat: invalid HTTP/2 CONNECT stream id")
	}
	bodyR, bodyW := io.Pipe()
	req, err := masqueH2RequestFromFields(c.ctx, tlsConn, bodyR, f.Fields)
	if err != nil {
		_ = bodyR.Close()
		_ = bodyW.Close()
		return err
	}
	c.flowMu.Lock()
	c.streamID = f.StreamID
	c.peerStreamWindow = c.peerInitialWindow
	c.flowMu.Unlock()
	c.bodyW = bodyW
	if f.StreamEnded() {
		_ = bodyW.Close()
	}

	rw := &masqueH2ResponseWriter{
		conn:     c,
		streamID: f.StreamID,
		header:   make(http.Header),
	}
	go func() {
		defer func() {
			if recover() != nil {
				_ = rw.finish()
			}
			_ = rw.finish()
			_ = bodyW.Close()
			c.cancel()
			_ = c.conn.Close()
		}()
		c.handler.ServeHTTP(rw, req)
	}()
	return nil
}

func masqueH2RequestFromFields(ctx context.Context, tlsConn *tls.Conn, body io.ReadCloser, fields []hpack.HeaderField) (*http.Request, error) {
	var method, scheme, authority, path, protocol string
	hdr := make(http.Header)
	for _, field := range fields {
		switch field.Name {
		case ":method":
			method = field.Value
		case ":scheme":
			scheme = field.Value
		case ":authority":
			authority = field.Value
		case ":path":
			path = field.Value
		case ":protocol":
			protocol = field.Value
		default:
			if !strings.HasPrefix(field.Name, ":") {
				hdr.Add(http.CanonicalHeaderKey(field.Name), field.Value)
			}
		}
	}
	if method == "" || authority == "" || path == "" {
		return nil, errors.New("masquecat: incomplete HTTP/2 request pseudo-headers")
	}
	if protocol != "" {
		hdr.Set(":protocol", protocol)
	}
	u, err := url.ParseRequestURI(path)
	if err != nil {
		return nil, fmt.Errorf("masquecat: parse HTTP/2 :path: %w", err)
	}
	if scheme != "" {
		u.Scheme = scheme
	}
	state := tlsConn.ConnectionState()
	return &http.Request{
		Method:        method,
		URL:           u,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        hdr,
		Body:          body,
		ContentLength: -1,
		Host:          authority,
		RemoteAddr:    tlsConn.RemoteAddr().String(),
		RequestURI:    path,
		TLS:           &state,
	}.WithContext(ctx), nil
}

type masqueH2ResponseWriter struct {
	conn     *masqueHTTP2Conn
	streamID uint32
	header   http.Header

	mu          sync.Mutex
	wroteHeader bool
	ended       bool
}

func (w *masqueH2ResponseWriter) Header() http.Header { return w.header }

func (w *masqueH2ResponseWriter) WriteHeader(statusCode int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.writeHeaderLocked(statusCode)
}

func (w *masqueH2ResponseWriter) writeHeaderLocked(statusCode int) error {
	if w.wroteHeader || w.ended {
		return nil
	}
	block, err := encodeMasqueH2ResponseHeaders(statusCode, w.header)
	if err != nil {
		return err
	}
	if err := w.conn.writeFrame(func() error {
		return w.conn.fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      w.streamID,
			BlockFragment: block,
			EndHeaders:    true,
		})
	}); err != nil {
		return err
	}
	w.wroteHeader = true
	return nil
}

func (w *masqueH2ResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ended {
		return 0, net.ErrClosed
	}
	if err := w.writeHeaderLocked(http.StatusOK); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := w.conn.writeData(w.streamID, p, false); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *masqueH2ResponseWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.writeHeaderLocked(http.StatusOK)
}

func (w *masqueH2ResponseWriter) finish() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ended {
		return nil
	}
	if err := w.writeHeaderLocked(http.StatusOK); err != nil {
		return err
	}
	w.ended = true
	return w.conn.writeData(w.streamID, nil, true)
}

func encodeMasqueH2ResponseHeaders(statusCode int, header http.Header) ([]byte, error) {
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	if err := enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(statusCode)}); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		name := strings.ToLower(key)
		if strings.HasPrefix(name, ":") || name == "connection" || name == "keep-alive" || name == "proxy-connection" || name == "transfer-encoding" || name == "upgrade" {
			continue
		}
		for _, value := range header[key] {
			if err := enc.WriteField(hpack.HeaderField{Name: name, Value: value}); err != nil {
				return nil, err
			}
		}
	}
	return block.Bytes(), nil
}

func (c *masqueHTTP2Conn) reserveWriteWindow(want int) (int, error) {
	deadline := time.NewTimer(masqueH2WriteTimeout)
	defer deadline.Stop()
	for {
		c.flowMu.Lock()
		available := c.peerConnWindow
		if c.peerStreamWindow < available {
			available = c.peerStreamWindow
		}
		maxFrame := int64(c.peerMaxFrameSize)
		if maxFrame < available {
			available = maxFrame
		}
		if int64(want) < available {
			available = int64(want)
		}
		if available > 0 {
			c.peerConnWindow -= available
			c.peerStreamWindow -= available
			c.flowMu.Unlock()
			return int(available), nil
		}
		c.flowMu.Unlock()

		select {
		case <-c.flowCh:
			continue
		case <-c.done:
			return 0, net.ErrClosed
		case <-deadline.C:
			return 0, errors.New("masquecat: HTTP/2 flow-control write timeout")
		}
	}
}

func (c *masqueHTTP2Conn) writeData(streamID uint32, p []byte, endStream bool) error {
	if len(p) == 0 {
		return c.writeFrame(func() error { return c.fr.WriteData(streamID, endStream, nil) })
	}
	for len(p) != 0 {
		n, err := c.reserveWriteWindow(len(p))
		if err != nil {
			return err
		}
		last := n == len(p)
		chunk := p[:n]
		if err := c.writeFrame(func() error { return c.fr.WriteData(streamID, endStream && last, chunk) }); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func masqueHTTP2CompanionAddr(configured string, udpAddr net.Addr) (string, error) {
	host, port, err := net.SplitHostPort(configured)
	if err != nil {
		return "", err
	}
	if port != "0" {
		return configured, nil
	}
	_, actualPort, err := net.SplitHostPort(udpAddr.String())
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, actualPort), nil
}

func startMasqueHTTP2(
	ctx context.Context,
	addr string,
	tlsConfig *tls.Config,
	handler http.Handler,
	logf logger.Logf,
) error {
	srv, err := newMasqueHTTP2Server(tlsConfig, handler)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen for HTTP/2 MASQUE: %w", err)
	}
	tlsLn := tls.NewListener(ln, srv.TLSConfig)
	go func() {
		if err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil && logf != nil {
			logf("HTTP/2 MASQUE listener stopped: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	return nil
}

// ServeMasque serves the same CONNECT-UDP handler on UDP/HTTP/3 and
// TCP/HTTP/2. HTTP/3 remains the preferred client path; HTTP/2 exists for
// networks and intermediaries that block or fail QUIC.
func ServeMasque(addr string, tlsConfig *tls.Config, handler http.Handler) error {
	if !hasMasqueServerCertificate(tlsConfig) {
		return fmt.Errorf("MASQUE server requires a TLS certificate")
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("listen for HTTP/3 MASQUE: %w", err)
	}
	defer pc.Close()

	h2Addr, err := masqueHTTP2CompanionAddr(addr, pc.LocalAddr())
	if err != nil {
		return fmt.Errorf("derive HTTP/2 MASQUE listen address: %w", err)
	}
	h2, err := newMasqueHTTP2Server(tlsConfig, handler)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", h2Addr)
	if err != nil {
		return fmt.Errorf("listen for HTTP/2 MASQUE: %w", err)
	}
	defer ln.Close()

	h3TLS := http3.ConfigureTLSConfig(tlsConfig.Clone())
	h3TLS.MinVersion = tls.VersionTLS13
	h3 := &http3.Server{
		TLSConfig:       h3TLS,
		Handler:         handler,
		EnableDatagrams: true,
	}
	defer h3.Close()
	defer h2.Close()

	errCh := make(chan error, 2)
	go func() { errCh <- h3.Serve(pc) }()
	go func() { errCh <- h2.Serve(tls.NewListener(ln, h2.TLSConfig)) }()
	err = <-errCh
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
