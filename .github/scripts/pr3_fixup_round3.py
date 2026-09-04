from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"missing expected text for {label}")
    return text.replace(old, new, 1)


p = Path("masquecat_h2.go")
s = p.read_text()

s = replace_once(
    s,
    '\t"context"\n\t"crypto/tls"\n',
    '\t"context"\n\t"crypto/rand"\n\t"crypto/tls"\n',
    "crypto/rand import",
)

s = replace_once(
    s,
    '''\t// Keep a bounded read deadline from the end of TLS negotiation through
\t// the first valid Extended CONNECT request. This prevents unauthenticated
\t// peers from pinning one fd/goroutine forever by stalling on the preface or
\t// request headers.
''',
    '''\t// Keep a bounded absolute read deadline from the end of TLS negotiation
\t// through the first valid Extended CONNECT request. This prevents
\t// unauthenticated peers from extending their lifetime indefinitely with
\t// partial preface/settings/header traffic. After CONNECT is accepted,
\t// readLoop switches to idle PING-based liveness detection.
''',
    "initial request deadline comment",
)

old_loop = '''func (c *masqueHTTP2Conn) readLoop(tlsConn *tls.Conn) error {
\tfor {
\t\tframe, err := c.fr.ReadFrame()
\t\tif err != nil {
\t\t\treturn err
\t\t}
\t\tswitch f := frame.(type) {
'''
new_loop = '''func (c *masqueHTTP2Conn) readLoop(tlsConn *tls.Conn) error {
\tpingOutstanding := false
\tvar pingData [8]byte
\tfor {
\t\t// Before a CONNECT stream exists, preserve the absolute deadline that
\t\t// serveConn installed. Once authenticated/session traffic can be long
\t\t// lived, switch to an idle timeout and probe a silent peer with PING.
\t\tif c.streamID != 0 {
\t\t\ttimeout := masqueH2ReadIdleTimeout
\t\t\tif pingOutstanding {
\t\t\t\ttimeout = masqueH2PingTimeout
\t\t\t}
\t\t\tif err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
\t\t\t\treturn err
\t\t\t}
\t\t}

\t\tframe, err := c.fr.ReadFrame()
\t\tif err != nil {
\t\t\tvar netErr net.Error
\t\t\tif c.streamID != 0 && errors.As(err, &netErr) && netErr.Timeout() {
\t\t\t\tif pingOutstanding {
\t\t\t\t\treturn fmt.Errorf("masquecat: HTTP/2 client did not answer PING within %s", masqueH2PingTimeout)
\t\t\t\t}
\t\t\t\tif _, randErr := rand.Read(pingData[:]); randErr != nil {
\t\t\t\t\treturn randErr
\t\t\t\t}
\t\t\t\tif pingErr := c.writeFrame(func() error { return c.fr.WritePing(false, pingData) }); pingErr != nil {
\t\t\t\t\treturn pingErr
\t\t\t\t}
\t\t\t\tpingOutstanding = true
\t\t\t\tcontinue
\t\t\t}
\t\t\treturn err
\t\t}
\t\tif c.streamID != 0 {
\t\t\t// Any successfully received frame proves the peer is alive. A PING
\t\t\t// ACK is ideal, but normal DATA/WINDOW_UPDATE traffic is equally
\t\t\t// sufficient to avoid declaring a live session dead.
\t\t\tpingOutstanding = false
\t\t}
\t\tswitch f := frame.(type) {
'''
s = replace_once(s, old_loop, new_loop, "server read-loop liveness")

s = replace_once(
    s,
    '''\tif err := c.conn.SetReadDeadline(time.Time{}); err != nil {
\t\t_ = bodyR.Close()
\t\t_ = bodyW.Close()
\t\treturn err
\t}
\tc.flowMu.Lock()
''',
    '''\t// Do not clear the read deadline permanently here. The next read-loop
\t// iteration replaces the initial absolute deadline with idle/PING liveness
\t// deadlines for this established CONNECT stream.
\tc.flowMu.Lock()
''',
    "remove permanent server deadline clear",
)

p.write_text(s)
