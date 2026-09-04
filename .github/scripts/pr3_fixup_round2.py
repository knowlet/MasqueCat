from pathlib import Path
import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"missing expected text for {label}")
    return text.replace(old, new, 1)


# Wire the RFC 8441 framer client into fallback, remove the broken net/http
# client path, bound the server preface/header wait, fix flow-control accounting,
# and register companion listeners synchronously.
p = Path("masquecat_h2.go")
s = p.read_text()

s = replace_once(
    s,
    "type masqueH2PacketConn struct {\n\tctx       context.Context\n\tstr       *masqueCapsuleStream\n\ttransport *http2.Transport\n}",
    "type masqueH2PacketConn struct {\n\tctx context.Context\n\tstr *masqueCapsuleStream\n}",
    "packet conn legacy transport field",
)
s = replace_once(
    s,
    "func (c *masqueH2PacketConn) Close() error {\n\terr := c.str.Close()\n\tif c.transport != nil {\n\t\tc.transport.CloseIdleConnections()\n\t}\n\treturn err\n}",
    "func (c *masqueH2PacketConn) Close() error { return c.str.Close() }",
    "packet conn legacy transport close",
)

s, n = re.subn(
    r"\nfunc newMasqueHTTP2Transport\(tlsConfig \*tls\.Config\) \*http2\.Transport \{.*?\n\}\n\n// newMasquePathWithFallback",
    "\n// newMasquePathWithFallback",
    s,
    count=1,
    flags=re.S,
)
if n != 1:
    raise SystemExit("failed to remove legacy HTTP/2 transport helper")

s = replace_once(
    s,
    "\t\th2, h2Err := dialMasqueH2PacketConn(dialCtx, tmpl, target, local, mode, tlsConfig)",
    "\t\th2, h2Err := dialMasqueH2PacketConnRFC8441(dialCtx, tmpl, target, local, mode, tlsConfig)",
    "wire raw RFC8441 client",
)

s, n = re.subn(
    r"\nfunc dialMasqueH2PacketConn\(.*?\n\}\n\nfunc expandMasqueTargetURL",
    "\nfunc expandMasqueTargetURL",
    s,
    count=1,
    flags=re.S,
)
if n != 1:
    raise SystemExit("failed to remove legacy dialMasqueH2PacketConn")

old_serve = '''func (s *masqueHTTP2Server) Serve(ln net.Listener) error {
\ts.mu.Lock()
\tif s.closed {
\t\ts.mu.Unlock()
\t\treturn http.ErrServerClosed
\t}
\ts.listeners[ln] = struct{}{}
\ts.wg.Add(1)
\ts.mu.Unlock()
\tdefer func() {
\t\ts.mu.Lock()
\t\tdelete(s.listeners, ln)
\t\ts.mu.Unlock()
\t\ts.wg.Done()
\t}()

\tfor {'''
new_serve = '''func (s *masqueHTTP2Server) registerListener(ln net.Listener) error {
\ts.mu.Lock()
\tdefer s.mu.Unlock()
\tif s.closed {
\t\treturn http.ErrServerClosed
\t}
\ts.listeners[ln] = struct{}{}
\ts.wg.Add(1)
\treturn nil
}

func (s *masqueHTTP2Server) Serve(ln net.Listener) error {
\tif err := s.registerListener(ln); err != nil {
\t\treturn err
\t}
\treturn s.serveRegistered(ln)
}

func (s *masqueHTTP2Server) serveRegistered(ln net.Listener) error {
\tdefer func() {
\t\ts.mu.Lock()
\t\tdelete(s.listeners, ln)
\t\ts.mu.Unlock()
\t\ts.wg.Done()
\t}()

\tfor {'''
s = replace_once(s, old_serve, new_serve, "synchronous H2 listener registration")

s = replace_once(
    s,
    '''\tvar preface [len(http2.ClientPreface)]byte
\tif _, err := io.ReadFull(conn, preface[:]); err != nil {
\t\treturn err
\t}
\tif string(preface[:]) != http2.ClientPreface {
\t\treturn errors.New("masquecat: invalid HTTP/2 client preface")
\t}
''',
    '''\t// Keep a bounded read deadline from the end of TLS negotiation through
\t// the first valid Extended CONNECT request. This prevents unauthenticated
\t// peers from pinning one fd/goroutine forever by stalling on the preface or
\t// request headers.
\tif err := conn.SetReadDeadline(time.Now().Add(masqueH2WriteTimeout)); err != nil {
\t\treturn err
\t}
\tvar preface [len(http2.ClientPreface)]byte
\tif _, err := io.ReadFull(conn, preface[:]); err != nil {
\t\treturn err
\t}
\tif string(preface[:]) != http2.ClientPreface {
\t\treturn errors.New("masquecat: invalid HTTP/2 client preface")
\t}
''',
    "H2 preface deadline",
)

s = replace_once(
    s,
    '''\treq, err := masqueH2RequestFromFields(c.ctx, tlsConn, bodyR, f.Fields)
\tif err != nil {
\t\t_ = bodyR.Close()
\t\t_ = bodyW.Close()
\t\treturn err
\t}
\tc.flowMu.Lock()
''',
    '''\treq, err := masqueH2RequestFromFields(c.ctx, tlsConn, bodyR, f.Fields)
\tif err != nil {
\t\t_ = bodyR.Close()
\t\t_ = bodyW.Close()
\t\treturn err
\t}
\tif req.Method != http.MethodConnect || req.Header.Get(":protocol") != masqueConnectUDPProtocol {
\t\t_ = bodyR.Close()
\t\t_ = bodyW.Close()
\t\treturn errors.New("masquecat: expected HTTP/2 extended CONNECT-UDP")
\t}
\tif err := c.conn.SetReadDeadline(time.Time{}); err != nil {
\t\t_ = bodyR.Close()
\t\t_ = bodyW.Close()
\t\treturn err
\t}
\tc.flowMu.Lock()
''',
    "clear H2 initial read deadline",
)

old_data = '''\t\tcase *http2.DataFrame:
\t\t\tif f.StreamID != c.streamID || c.bodyW == nil {
\t\t\t\tcontinue
\t\t\t}
\t\t\tdata := f.Data()
\t\t\tif len(data) != 0 {
\t\t\t\tif _, err := c.bodyW.Write(data); err != nil {
\t\t\t\t\treturn err
\t\t\t\t}
\t\t\t\tinc := uint32(len(data))
\t\t\t\tif err := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(0, inc) }); err != nil {
\t\t\t\t\treturn err
\t\t\t\t}
\t\t\t\tif err := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(c.streamID, inc) }); err != nil {
\t\t\t\t\treturn err
\t\t\t\t}
\t\t\t}
'''
new_data = '''\t\tcase *http2.DataFrame:
\t\t\tif f.StreamID != c.streamID || c.bodyW == nil {
\t\t\t\tcontinue
\t\t\t}
\t\t\tdata := f.Data()
\t\t\tif len(data) != 0 {
\t\t\t\tif _, err := c.bodyW.Write(data); err != nil {
\t\t\t\t\treturn err
\t\t\t\t}
\t\t\t}
\t\t\t// HTTP/2 flow control charges the complete DATA payload, including
\t\t\t// Pad Length and padding bytes, not just f.Data().
\t\t\tif inc := f.Header().Length; inc != 0 {
\t\t\t\tif err := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(0, inc) }); err != nil {
\t\t\t\t\treturn err
\t\t\t\t}
\t\t\t\tif err := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(c.streamID, inc) }); err != nil {
\t\t\t\t\treturn err
\t\t\t\t}
\t\t\t}
'''
s = replace_once(s, old_data, new_data, "server padded DATA flow credit")

s = replace_once(
    s,
    '''\tif f.StreamID == 0 {
\t\tc.peerConnWindow += int64(f.Increment)
\t} else if f.StreamID == c.streamID {
\t\tc.peerStreamWindow += int64(f.Increment)
\t}
''',
    '''\tswitch f.StreamID {
\tcase 0:
\t\tc.peerConnWindow += int64(f.Increment)
\tcase c.streamID:
\t\tc.peerStreamWindow += int64(f.Increment)
\t}
''',
    "server window update tagged switch",
)
s = s.replace('hdr.Add(http.CanonicalHeaderKey(field.Name), field.Value)', 'hdr.Add(field.Name, field.Value)', 1)

old_start = '''\ttlsLn := tls.NewListener(ln, srv.TLSConfig)
\tgo func() {
\t\tif err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil && logf != nil {
\t\t\tlogf("HTTP/2 MASQUE listener stopped: %v", err)
\t\t}
\t}()
'''
new_start = '''\ttlsLn := tls.NewListener(ln, srv.TLSConfig)
\t// Register synchronously so Close immediately after Start cannot miss the
\t// listener and return while the TCP port is still bound.
\tif err := srv.registerListener(tlsLn); err != nil {
\t\t_ = tlsLn.Close()
\t\treturn nil, err
\t}
\tgo func() {
\t\tif err := srv.serveRegistered(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil && logf != nil {
\t\t\tlogf("HTTP/2 MASQUE listener stopped: %v", err)
\t\t}
\t}()
'''
s = replace_once(s, old_start, new_start, "register companion listener before return")

s = replace_once(s, '\tdefer pc.Close()\n', '\tdefer func() { _ = pc.Close() }()\n', "ServeMasque pc Close errcheck")
s = replace_once(s, '\tdefer ln.Close()\n', '\tdefer func() { _ = ln.Close() }()\n', "ServeMasque ln Close errcheck")
s = replace_once(s, '\tdefer h3.Close()\n', '\tdefer func() { _ = h3.Close() }()\n', "ServeMasque h3 Close errcheck")
s = replace_once(s, '\tdefer h2.Close()\n', '\tdefer func() { _ = h2.Close() }()\n', "ServeMasque h2 Close errcheck")
p.write_text(s)

# Preserve backwards-compatible H3-only direct deployments when another TCP
# service already owns the companion port.
p = Path("masquecat.go")
s = p.read_text()
s = replace_once(
    s,
    '''\t\th2, err := startMasqueHTTP2(ctx, h2Addr, s.DirectTLSConfig, handler, logf)
\t\tif err != nil {
\t\t\t_ = pc.Close()
\t\t\tcleanup()
\t\t\treturn fmt.Errorf("start direct HTTP/2 MASQUE: %w", err)
\t\t}
\t\ts.directH2 = h2
''',
    '''\t\th2, err := startMasqueHTTP2(ctx, h2Addr, s.DirectTLSConfig, handler, logf)
\t\tif err != nil {
\t\t\t// DirectListen was historically UDP-only. Do not regress existing
\t\t\t// deployments that intentionally share the numeric port with a TCP
\t\t\t// service such as nginx; keep H3 available and disable only fallback.
\t\t\tlogf("direct MASQUE HTTP/2 fallback disabled on %s: %v", h2Addr, err)
\t\t} else {
\t\t\ts.directH2 = h2
\t\t}
''',
    "direct H3 survives occupied TCP port",
)
p.write_text(s)

# Fix client-side lint and symmetric padded DATA flow-control accounting.
p = Path("masquecat_h2_client.go")
s = p.read_text()
s = replace_once(
    s,
    '\tdefer c.conn.SetWriteDeadline(time.Time{})\n',
    '\tdefer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()\n',
    "client write deadline errcheck",
)
old_client_data = '''\t\tcase *http2.DataFrame:
\t\t\tif f.StreamID != c.streamID || c.streamID == 0 {
\t\t\t\tcontinue
\t\t\t}
\t\t\tdata := f.Data()
\t\t\tif len(data) != 0 {
\t\t\t\tif _, pipeErr := c.bodyW.Write(data); pipeErr != nil {
\t\t\t\t\terr = pipeErr
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t\tincrement := uint32(len(data))
\t\t\t\tif windowErr := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(0, increment) }); windowErr != nil {
\t\t\t\t\terr = windowErr
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t\tif windowErr := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(c.streamID, increment) }); windowErr != nil {
\t\t\t\t\terr = windowErr
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t}
'''
new_client_data = '''\t\tcase *http2.DataFrame:
\t\t\tif f.StreamID != c.streamID || c.streamID == 0 {
\t\t\t\tcontinue
\t\t\t}
\t\t\tdata := f.Data()
\t\t\tif len(data) != 0 {
\t\t\t\tif _, pipeErr := c.bodyW.Write(data); pipeErr != nil {
\t\t\t\t\terr = pipeErr
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t}
\t\t\tif increment := f.Header().Length; increment != 0 {
\t\t\t\tif windowErr := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(0, increment) }); windowErr != nil {
\t\t\t\t\terr = windowErr
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t\tif windowErr := c.writeFrame(func() error { return c.fr.WriteWindowUpdate(c.streamID, increment) }); windowErr != nil {
\t\t\t\t\terr = windowErr
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t}
'''
s = replace_once(s, old_client_data, new_client_data, "client padded DATA flow credit")
s = replace_once(
    s,
    '''\tif f.StreamID == 0 {
\t\tc.peerConnWindow += int64(f.Increment)
\t} else if f.StreamID == c.streamID {
\t\tc.peerStreamWindow += int64(f.Increment)
\t}
''',
    '''\tswitch f.StreamID {
\tcase 0:
\t\tc.peerConnWindow += int64(f.Increment)
\tcase c.streamID:
\t\tc.peerStreamWindow += int64(f.Increment)
\t}
''',
    "client window update tagged switch",
)
s = s.replace('headers.Add(http.CanonicalHeaderKey(field.Name), field.Value)', 'headers.Add(field.Name, field.Value)', 1)
p.write_text(s)

# Exercise the actual raw RFC 8441 client instead of x/net/http2.Transport,
# which rejects pseudo-header names in http.Header on Go 1.27.
p = Path("masquecat_h2_test.go")
s = p.read_text()
s = s.replace('\n\t"golang.org/x/net/http2"\n', '\n', 1)
s = replace_once(s, '\tdefer ln.Close()\n', '\tdefer func() { _ = ln.Close() }()\n', "test ln Close errcheck")
s = replace_once(s, '\tdefer srv.Close()\n', '\tdefer func() { _ = srv.Close() }()\n', "test srv Close errcheck")
old_test_client = '''\tpr, pw := io.Pipe()
\treq, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+ln.Addr().String()+"/.well-known/masque/udp/test.invalid/1/", pr)
\tif err != nil {
\t\tt.Fatal(err)
\t}
\treq.Header.Set(":protocol", masqueConnectUDPProtocol)
\treq.Header.Set(http3.CapsuleProtocolHeader, "?1")
\ttr := &http2.Transport{TLSClientConfig: &tls.Config{
\t\tInsecureSkipVerify: true, // test-only ephemeral certificate
\t\tNextProtos:         []string{http2.NextProtoTLS},
\t}}
\tdefer tr.CloseIdleConnections()
\tresp, err := tr.RoundTrip(req)
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tdefer resp.Body.Close()
'''
new_test_client = '''\theaders := make(http.Header)
\theaders.Set(http3.CapsuleProtocolHeader, "?1")
\tcc, resp, err := dialMasqueH2ExtendedConnect(
\t\tctx,
\t\t"https://"+ln.Addr().String()+"/.well-known/masque/udp/test.invalid/1/",
\t\theaders,
\t\t&tls.Config{InsecureSkipVerify: true}, // test-only ephemeral certificate
\t)
\tif err != nil {
\t\tt.Fatal(err)
\t}
'''
s = replace_once(s, old_test_client, new_test_client, "raw RFC8441 integration test")
s = replace_once(
    s,
    '\tclient := &masqueCapsuleStream{r: resp.Body, w: pw, closeWriter: pw.Close}\n',
    '''\tclient := &masqueCapsuleStream{
\t\tr:           resp.Body,
\t\tw:           &masqueH2ClientBodyWriter{conn: cc},
\t\tcloseWriter: cc.closeRequestStream,
\t}
\tdefer func() { _ = client.Close() }()
''',
    "test capsule stream raw client",
)
p.write_text(s)
