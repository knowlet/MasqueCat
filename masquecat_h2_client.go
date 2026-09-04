//go:build !js

package tailcat

import (
	"bytes"
	"context"
	"crypto/rand"
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

	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"tailscale.com/types/key"
)

type masqueH2ClientResult struct {
	resp *http.Response
	err  error
}

type masqueH2ClientConn struct {
	conn net.Conn
	fr   *http2.Framer

	ctx    context.Context
	cancel context.CancelFunc

	writeMu sync.Mutex
	flowMu  sync.Mutex
	flowCh  chan struct{}

	done      chan struct{}
	closeOnce sync.Once

	peerConnWindow    int64
	peerStreamWindow  int64
	peerInitialWindow int64
	peerMaxFrameSize  uint32

	streamID uint32
	bodyR    *io.PipeReader
	bodyW    *io.PipeWriter

	settingsOnce           sync.Once
	settingsCh             chan error
	extendedConnectAllowed bool

	responseOnce sync.Once
	responseCh   chan masqueH2ClientResult
}

func dialMasqueH2PacketConnRFC8441(
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

	dial := func(proof string) (*masqueH2PacketConn, *http.Response, error) {
		headers := make(http.Header)
		headers.Set(http3.CapsuleProtocolHeader, "?1")
		headers.Set(masqueSourceHeader, local.Public().String())
		headers.Set(masqueModeHeader, mode)
		if proof != "" {
			headers.Set(masqueProofHeader, proof)
		}
		cc, resp, err := dialMasqueH2ExtendedConnect(ctx, expandedURL, headers, tlsConfig)
		if err != nil {
			return nil, nil, err
		}
		str := &masqueCapsuleStream{
			r: resp.Body,
			w: &masqueH2ClientBodyWriter{conn: cc},
			closeWriter: func() error {
				return cc.closeRequestStream()
			},
		}
		return &masqueH2PacketConn{ctx: ctx, str: str}, resp, nil
	}

	conn, resp, err := dial("")
	if err != nil {
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
		conn, resp, err = dial(proof)
		if err != nil {
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

func dialMasqueH2ExtendedConnect(
	ctx context.Context,
	rawURL string,
	headers http.Header,
	tlsConfig *tls.Config,
) (*masqueH2ClientConn, *http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("masquecat: parse HTTP/2 CONNECT-UDP URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, nil, fmt.Errorf("masquecat: invalid HTTP/2 CONNECT-UDP URL %q", rawURL)
	}

	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	h2TLS := tlsConfig.Clone()
	h2TLS.NextProtos = []string{http2.NextProtoTLS}
	dialer := &tls.Dialer{Config: h2TLS}
	nc, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("masquecat: dial HTTP/2 CONNECT-UDP: %w", err)
	}

	childCtx, cancel := context.WithCancel(ctx)
	bodyR, bodyW := io.Pipe()
	cc := &masqueH2ClientConn{
		conn:              nc,
		ctx:               childCtx,
		cancel:            cancel,
		flowCh:            make(chan struct{}, 1),
		done:              make(chan struct{}),
		peerConnWindow:    65535,
		peerStreamWindow:  65535,
		peerInitialWindow: 65535,
		peerMaxFrameSize:  16384,
		bodyR:             bodyR,
		bodyW:             bodyW,
		settingsCh:        make(chan error, 1),
		responseCh:        make(chan masqueH2ClientResult, 1),
	}
	cc.fr = http2.NewFramer(nc, nc)
	cc.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	if err := cc.writeClientPrefaceAndSettings(); err != nil {
		cc.closeWithError(err)
		return nil, nil, err
	}
	go cc.readLoop()
	go func() {
		<-childCtx.Done()
		cc.closeWithError(childCtx.Err())
	}()

	select {
	case err := <-cc.settingsCh:
		if err != nil {
			cc.closeWithError(err)
			return nil, nil, err
		}
	case <-ctx.Done():
		cc.closeWithError(ctx.Err())
		return nil, nil, ctx.Err()
	}

	if err := cc.writeExtendedConnectHeaders(u, headers); err != nil {
		cc.closeWithError(err)
		return nil, nil, err
	}

	select {
	case result := <-cc.responseCh:
		if result.err != nil {
			cc.closeWithError(result.err)
			return nil, nil, result.err
		}
		return cc, result.resp, nil
	case <-ctx.Done():
		cc.closeWithError(ctx.Err())
		return nil, nil, ctx.Err()
	}
}

func (c *masqueH2ClientConn) writeClientPrefaceAndSettings() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.conn.SetWriteDeadline(time.Now().Add(masqueH2WriteTimeout)); err != nil {
		return err
	}
	defer c.conn.SetWriteDeadline(time.Time{})
	if _, err := io.WriteString(c.conn, http2.ClientPreface); err != nil {
		return err
	}
	if err := c.fr.WriteSettings(
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: masqueH2InitialWindow},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1},
	); err != nil {
		return err
	}
	return c.fr.WriteWindowUpdate(0, masqueH2InitialWindow-65535)
}

func (c *masqueH2ClientConn) writeFrame(fn func() error) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(masqueH2WriteTimeout)); err != nil {
		return err
	}
	err := fn()
	_ = c.conn.SetWriteDeadline(time.Time{})
	return err
}

func (c *masqueH2ClientConn) writeExtendedConnectHeaders(u *url.URL, headers http.Header) error {
	block, err := encodeMasqueH2RequestHeaders(u, headers)
	if err != nil {
		return err
	}
	c.flowMu.Lock()
	c.streamID = 1
	c.peerStreamWindow = c.peerInitialWindow
	c.flowMu.Unlock()
	return c.writeFrame(func() error {
		return c.fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      c.streamID,
			BlockFragment: block,
			EndHeaders:    true,
			EndStream:     false,
		})
	})
}

func encodeMasqueH2RequestHeaders(u *url.URL, headers http.Header) ([]byte, error) {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	pseudo := []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: masqueConnectUDPProtocol},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: u.Host},
		{Name: ":path", Value: path},
	}
	for _, field := range pseudo {
		if err := enc.WriteField(field); err != nil {
			return nil, err
		}
	}

	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		name := strings.ToLower(key)
		if strings.HasPrefix(name, ":") || isMasqueH2HopByHopHeader(name) {
			continue
		}
		for _, value := range headers[key] {
			if err := enc.WriteField(hpack.HeaderField{Name: name, Value: value}); err != nil {
				return nil, err
			}
		}
	}
	return block.Bytes(), nil
}

func isMasqueH2HopByHopHeader(name string) bool {
	switch name {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func (c *masqueH2ClientConn) readLoop() {
	var err error
	defer func() { c.closeWithError(err) }()
	pingOutstanding := false
	var pingData [8]byte
	for {
		timeout := masqueH2ReadIdleTimeout
		if pingOutstanding {
			timeout = masqueH2PingTimeout
		}
		if deadlineErr := c.conn.SetReadDeadline(time.Now().Add(timeout)); deadlineErr != nil {
			err = deadlineErr
			return
		}
		frame, readErr := c.fr.ReadFrame()
		if readErr != nil {
			var netErr net.Error
			if errors.As(readErr, &netErr) && netErr.Timeout() {
				if pingOutstanding {
					err = fmt.Errorf("masquecat: HTTP/2 peer did not answer PING within %s", masqueH2PingTimeout)
					return
				}
				if _, randErr := rand.Read(pingData[:]); randErr != nil {
					err = randErr
					return
				}
				if pingErr := c.writeFrame(func() error { return c.fr.WritePing(false, pingData) }); pingErr != nil {
					err = pingErr
					return
				}
				pingOutstanding = true
				continue
			}
			err = readErr
			return
		}
		pingOutstanding = false

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if handleErr := c.handleSettings(f); handleErr != nil {
				err = handleErr
				return
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				if pingErr := c.writeFrame(func() error { return c.fr.WritePing(true, f.Data) }); pingErr != nil {
					err = pingErr
					return
				}
			}
		case *http2.WindowUpdateFrame:
			if windowErr := c.handleWindowUpdate(f); windowErr != nil {
				err = windowErr
				return
			}
		case *http2.MetaHeadersFrame:
			if f.StreamID != c.streamID || c.streamID == 0 {
				continue
			}
			if responseErr := c.handleResponseHeaders(f); responseErr != nil {
				err = responseErr
				return
			}
		case *http2.DataFrame:
			if f.StreamID != c.streamID || c.streamID == 0 {
				continue
			}
			data := f.Data()
			if len(data) != 0 {
				if _, pipeErr := c.bodyW.Write(data); pipeErr != nil {
					err = pipeErr
					return
				}
				increment := uint32(len(data))
				if windowErr := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(0, increment) }); windowErr != nil {
					err = windowErr
					return
				}
				if windowErr := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(c.streamID, increment) }); windowErr != nil {
					err = windowErr
					return
				}
			}
			if f.StreamEnded() {
				_ = c.bodyW.Close()
				return
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == c.streamID {
				err = fmt.Errorf("masquecat: HTTP/2 CONNECT stream reset: %s", f.ErrCode)
				return
			}
		case *http2.GoAwayFrame:
			err = io.EOF
			return
		}
	}
}

func (c *masqueH2ClientConn) handleSettings(f *http2.SettingsFrame) error {
	if f.IsAck() {
		return nil
	}
	firstSettings := false
	c.settingsOnce.Do(func() { firstSettings = true })
	if err := f.ForeachSetting(func(setting http2.Setting) error {
		c.flowMu.Lock()
		defer c.flowMu.Unlock()
		switch setting.ID {
		case http2.SettingEnableConnectProtocol:
			if setting.Val > 1 {
				return fmt.Errorf("masquecat: invalid SETTINGS_ENABLE_CONNECT_PROTOCOL=%d", setting.Val)
			}
			c.extendedConnectAllowed = setting.Val == 1
		case http2.SettingInitialWindowSize:
			delta := int64(setting.Val) - c.peerInitialWindow
			c.peerInitialWindow = int64(setting.Val)
			if c.streamID != 0 {
				c.peerStreamWindow += delta
			}
		case http2.SettingMaxFrameSize:
			c.peerMaxFrameSize = setting.Val
		}
		return nil
	}); err != nil {
		if firstSettings {
			c.settingsCh <- err
		}
		return err
	}
	if err := c.writeFrame(c.fr.WriteSettingsAck); err != nil {
		if firstSettings {
			c.settingsCh <- err
		}
		return err
	}
	select {
	case c.flowCh <- struct{}{}:
	default:
	}
	if firstSettings {
		if !c.extendedConnectAllowed {
			c.settingsCh <- errors.New("masquecat: HTTP/2 peer did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL")
		} else {
			c.settingsCh <- nil
		}
	}
	return nil
}

func (c *masqueH2ClientConn) handleWindowUpdate(f *http2.WindowUpdateFrame) error {
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

func (c *masqueH2ClientConn) handleResponseHeaders(f *http2.MetaHeadersFrame) error {
	statusCode := 0
	headers := make(http.Header)
	for _, field := range f.Fields {
		if field.Name == ":status" {
			code, err := strconv.Atoi(field.Value)
			if err != nil {
				return fmt.Errorf("masquecat: invalid HTTP/2 :status %q", field.Value)
			}
			statusCode = code
			continue
		}
		if !strings.HasPrefix(field.Name, ":") {
			headers.Add(http.CanonicalHeaderKey(field.Name), field.Value)
		}
	}
	if statusCode == 0 {
		return errors.New("masquecat: HTTP/2 response missing :status")
	}
	statusText := http.StatusText(statusCode)
	status := strconv.Itoa(statusCode)
	if statusText != "" {
		status += " " + statusText
	}
	response := &http.Response{
		Status:        status,
		StatusCode:    statusCode,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        headers,
		Body:          c.bodyR,
		ContentLength: -1,
	}
	c.responseOnce.Do(func() {
		c.responseCh <- masqueH2ClientResult{resp: response}
	})
	if f.StreamEnded() {
		_ = c.bodyW.Close()
	}
	return nil
}

func (c *masqueH2ClientConn) reserveWriteWindow(want int) (int, error) {
	timer := time.NewTimer(masqueH2WriteTimeout)
	defer timer.Stop()
	for {
		c.flowMu.Lock()
		available := c.peerConnWindow
		if c.peerStreamWindow < available {
			available = c.peerStreamWindow
		}
		if int64(c.peerMaxFrameSize) < available {
			available = int64(c.peerMaxFrameSize)
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
		case <-c.ctx.Done():
			return 0, c.ctx.Err()
		case <-timer.C:
			return 0, errors.New("masquecat: HTTP/2 flow-control write timeout")
		}
	}
}

func (c *masqueH2ClientConn) writeData(p []byte, endStream bool) error {
	if c.streamID == 0 {
		return errors.New("masquecat: HTTP/2 CONNECT stream is not established")
	}
	if len(p) == 0 {
		return c.writeFrame(func() error { return c.fr.WriteData(c.streamID, endStream, nil) })
	}
	for len(p) != 0 {
		n, err := c.reserveWriteWindow(len(p))
		if err != nil {
			return err
		}
		last := n == len(p)
		chunk := p[:n]
		if err := c.writeFrame(func() error { return c.fr.WriteData(c.streamID, endStream && last, chunk) }); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func (c *masqueH2ClientConn) closeRequestStream() error {
	var errs []error
	if c.streamID != 0 {
		errs = append(errs, c.writeData(nil, true))
	}
	c.closeWithError(net.ErrClosed)
	return errors.Join(errs...)
}

func (c *masqueH2ClientConn) closeWithError(err error) {
	if err == nil {
		err = io.EOF
	}
	c.closeOnce.Do(func() {
		c.cancel()
		close(c.done)
		_ = c.conn.Close()
		_ = c.bodyW.CloseWithError(err)
		c.settingsOnce.Do(func() {
			c.settingsCh <- err
		})
		c.responseOnce.Do(func() {
			c.responseCh <- masqueH2ClientResult{err: err}
		})
		select {
		case c.flowCh <- struct{}{}:
		default:
		}
	})
}

type masqueH2ClientBodyWriter struct {
	conn *masqueH2ClientConn
}

func (w *masqueH2ClientBodyWriter) Write(p []byte) (int, error) {
	if err := w.conn.writeData(p, false); err != nil {
		return 0, err
	}
	return len(p), nil
}
