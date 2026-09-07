//go:build js

package tailcat

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall/js"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/mem"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"tailscale.com/disco"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	browserMasqueMTU                                  = 1000
	browserMasqueQueueSize                            = 512
	browserMasqueNIC                      tcpip.NICID = 1
	browserMasquePingPort                 uint16      = 65535
	browserMasquePacketVersion                        = byte(1)
	browserNodePublicTextPrefix                       = "nodekey:"
	browserWebTransportRoute                          = "/.well-known/masquecat/webtransport"
	browserControlMax                                 = 8 << 10
	browserProtocolVersion                            = 1
	browserFragmentHeaderLen                          = 20
	browserFragmentMaxSize                            = 64 << 10
	browserFragmentChunkSize                          = 1000
	browserFragmentTTL                                = 30 * time.Second
	browserFragmentMaxIncompleteSets                  = 256
	browserFragmentMaxIncompletePerSource             = 32
)

var (
	browserMasquePingAddr = netip.MustParseAddr("fd00:7461:696c:6361:7400:7069:6e67:1")
	browserDiscoMagic     = []byte(disco.Magic)
	browserFragmentMagic  = [4]byte{'M', 'C', 'F', 1}
	browserFragmentSeq    atomic.Uint64
)

type browserMasquePacket struct {
	src     key.NodePublic
	dst     key.NodePublic
	payload []byte
}

func encodeBrowserMasquePacket(src, dst key.NodePublic, payload []byte) []byte {
	b := make([]byte, 0, 1+2*key.NodePublicRawLen+len(payload))
	b = append(b, browserMasquePacketVersion)
	b = src.AppendTo(b)
	b = dst.AppendTo(b)
	b = append(b, payload...)
	return b
}

func decodeBrowserMasquePacket(b []byte) (browserMasquePacket, error) {
	var p browserMasquePacket
	const headerLen = 1 + 2*key.NodePublicRawLen
	if len(b) < headerLen {
		return p, fmt.Errorf("short MasqueCat datagram: %d bytes", len(b))
	}
	if b[0] != browserMasquePacketVersion {
		return p, fmt.Errorf("unsupported MasqueCat datagram version %d", b[0])
	}
	p.src = key.NodePublicFromRaw32(mem.B(b[1 : 1+key.NodePublicRawLen]))
	p.dst = key.NodePublicFromRaw32(mem.B(b[1+key.NodePublicRawLen : headerLen]))
	p.payload = b[headerLen:]
	return p, nil
}

type browserFragmentKey struct {
	src key.NodePublic
	id  uint64
}

type browserFragmentSet struct {
	count    uint16
	total    uint32
	parts    [][]byte
	received int
	updated  time.Time
}

type browserReassembler struct {
	mu   sync.Mutex
	sets map[browserFragmentKey]*browserFragmentSet
}

func nextBrowserFragmentID() uint64 {
	return uint64(time.Now().UnixNano()) + browserFragmentSeq.Add(1)
}

func fragmentBrowserWireGuardPacket(payload []byte) ([][]byte, error) {
	if len(payload) <= browserFragmentChunkSize {
		return nil, nil
	}
	if len(payload) > browserFragmentMaxSize {
		return nil, fmt.Errorf("masquecat: browser WireGuard packet too large to fragment: %d bytes", len(payload))
	}
	count := (len(payload) + browserFragmentChunkSize - 1) / browserFragmentChunkSize
	if count > int(^uint16(0)) {
		return nil, fmt.Errorf("masquecat: browser WireGuard packet needs too many fragments: %d", count)
	}
	id := nextBrowserFragmentID()
	fragments := make([][]byte, 0, count)
	for i, off := 0, 0; off < len(payload); i, off = i+1, off+browserFragmentChunkSize {
		end := off + browserFragmentChunkSize
		if end > len(payload) {
			end = len(payload)
		}
		fragment := make([]byte, browserFragmentHeaderLen+end-off)
		copy(fragment[:4], browserFragmentMagic[:])
		binary.BigEndian.PutUint64(fragment[4:12], id)
		binary.BigEndian.PutUint16(fragment[12:14], uint16(i))
		binary.BigEndian.PutUint16(fragment[14:16], uint16(count))
		binary.BigEndian.PutUint32(fragment[16:20], uint32(len(payload)))
		copy(fragment[browserFragmentHeaderLen:], payload[off:end])
		fragments = append(fragments, fragment)
	}
	return fragments, nil
}

func (r *browserReassembler) cleanupLocked(now time.Time) {
	for k, set := range r.sets {
		if now.Sub(set.updated) >= browserFragmentTTL {
			delete(r.sets, k)
		}
	}
}

func (r *browserReassembler) sourceAssemblyCountLocked(src key.NodePublic) int {
	count := 0
	for k := range r.sets {
		if k.src == src {
			count++
		}
	}
	return count
}

func (r *browserReassembler) Push(src key.NodePublic, payload []byte) ([]byte, bool, error) {
	if !bytes.HasPrefix(payload, browserFragmentMagic[:]) {
		return payload, true, nil
	}
	if len(payload) < browserFragmentHeaderLen {
		return nil, false, errors.New("masquecat: short browser WireGuard fragment")
	}
	id := binary.BigEndian.Uint64(payload[4:12])
	index := binary.BigEndian.Uint16(payload[12:14])
	count := binary.BigEndian.Uint16(payload[14:16])
	total := binary.BigEndian.Uint32(payload[16:20])
	chunk := payload[browserFragmentHeaderLen:]
	if count < 2 || index >= count || total > browserFragmentMaxSize {
		return nil, false, errors.New("masquecat: invalid browser WireGuard fragment")
	}
	expectedCount := (int(total) + browserFragmentChunkSize - 1) / browserFragmentChunkSize
	if int(count) != expectedCount {
		return nil, false, errors.New("masquecat: inconsistent browser WireGuard fragment count")
	}

	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sets == nil {
		r.sets = make(map[browserFragmentKey]*browserFragmentSet)
	}
	r.cleanupLocked(now)
	k := browserFragmentKey{src: src, id: id}
	set := r.sets[k]
	if set == nil {
		if r.sourceAssemblyCountLocked(src) >= browserFragmentMaxIncompletePerSource {
			return nil, false, errors.New("masquecat: too many incomplete browser WireGuard fragments for source")
		}
		if len(r.sets) >= browserFragmentMaxIncompleteSets {
			return nil, false, errors.New("masquecat: too many incomplete browser WireGuard fragments")
		}
		set = &browserFragmentSet{count: count, total: total, parts: make([][]byte, count), updated: now}
		r.sets[k] = set
	}
	if set.count != count || set.total != total {
		delete(r.sets, k)
		return nil, false, errors.New("masquecat: inconsistent browser WireGuard fragment metadata")
	}
	expectedChunkLen := browserFragmentChunkSize
	if int(index) == expectedCount-1 {
		expectedChunkLen = int(total) - (expectedCount-1)*browserFragmentChunkSize
	}
	if len(chunk) != expectedChunkLen {
		delete(r.sets, k)
		return nil, false, errors.New("masquecat: invalid browser WireGuard fragment length")
	}
	if old := set.parts[index]; old != nil {
		if bytes.Equal(old, chunk) {
			return nil, false, nil
		}
		delete(r.sets, k)
		return nil, false, errors.New("masquecat: conflicting duplicate browser WireGuard fragment")
	}
	set.parts[index] = append([]byte(nil), chunk...)
	set.received++
	set.updated = now
	if set.received != int(count) {
		return nil, false, nil
	}
	out := make([]byte, 0, int(total))
	for _, part := range set.parts {
		if part == nil {
			return nil, false, nil
		}
		out = append(out, part...)
	}
	delete(r.sets, k)
	if len(out) != int(total) {
		return nil, false, errors.New("masquecat: browser WireGuard reassembly size mismatch")
	}
	return out, true, nil
}

type browserPacketForwarder interface {
	ForwardPacket(src, dst key.NodePublic, payload []byte) error
}

type browserEndpoint struct{ peer key.NodePublic }

func (*browserEndpoint) ClearSrc()           {}
func (*browserEndpoint) SrcToString() string { return "masquecat-browser" }
func (e *browserEndpoint) DstToString() string {
	return strings.TrimPrefix(e.peer.String(), browserNodePublicTextPrefix)
}
func (e *browserEndpoint) DstToBytes() []byte { return e.peer.AppendTo(nil) }
func (*browserEndpoint) DstIP() netip.Addr    { return netip.Addr{} }
func (*browserEndpoint) SrcIP() netip.Addr    { return netip.Addr{} }

type browserInboundPacket struct {
	src     key.NodePublic
	payload []byte
}

type browserBind struct {
	local key.NodePublic
	mu    sync.RWMutex
	open  bool
	recv  chan browserInboundPacket
	close chan struct{}
	path  browserPacketForwarder
	peer  key.NodePublic
	frag  browserReassembler
}

func (b *browserBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.recv = make(chan browserInboundPacket, browserMasqueQueueSize)
	b.close = make(chan struct{})
	b.open = true
	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-b.close:
			return 0, net.ErrClosed
		case p := <-b.recv:
			if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 || len(p.payload) > len(packets[0]) {
				return 0, errors.New("masquecat: invalid browser WireGuard receive buffer")
			}
			copy(packets[0], p.payload)
			sizes[0] = len(p.payload)
			eps[0] = &browserEndpoint{peer: p.src}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{fn}, 0, nil
}

func (b *browserBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		close(b.close)
		b.open = false
	}
	return nil
}

func (*browserBind) SetMark(uint32) error { return nil }
func (*browserBind) BatchSize() int       { return 1 }

func (b *browserBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	s = strings.TrimPrefix(s, browserNodePublicTextPrefix)
	if _, err := hex.DecodeString(s); err != nil || len(s) != key.NodePublicRawLen*2 {
		return nil, errors.New("masquecat: invalid browser peer endpoint")
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(browserNodePublicTextPrefix + s)); err != nil {
		return nil, err
	}
	return &browserEndpoint{peer: k}, nil
}

func (b *browserBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	bep, ok := ep.(*browserEndpoint)
	if !ok || bep == nil {
		return conn.ErrWrongEndpointType
	}
	b.mu.RLock()
	path, peer := b.path, b.peer
	b.mu.RUnlock()
	if path == nil || bep.peer != peer {
		return errors.New("masquecat: browser transport path unavailable")
	}
	for _, buf := range bufs {
		if offset < 0 || offset > len(buf) {
			return errors.New("masquecat: invalid browser WireGuard packet offset")
		}
		payload := buf[offset:]
		fragments, err := fragmentBrowserWireGuardPacket(payload)
		if err != nil {
			return err
		}
		if len(fragments) == 0 {
			if err := path.ForwardPacket(b.local, peer, payload); err != nil {
				return err
			}
			continue
		}
		for _, fragment := range fragments {
			if err := path.ForwardPacket(b.local, peer, fragment); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *browserBind) SetPath(peer key.NodePublic, path browserPacketForwarder) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.peer, b.path = peer, path
}

func (b *browserBind) Inject(src key.NodePublic, payload []byte) error {
	reassembled, ready, err := b.frag.Push(src, payload)
	// Match the native carrier's behavior: malformed or incomplete fragment
	// traffic is dropped rather than tearing down the entire WebTransport path.
	if err != nil || !ready {
		return nil
	}
	b.mu.RLock()
	if !b.open || b.recv == nil || b.close == nil {
		b.mu.RUnlock()
		return net.ErrClosed
	}
	recv, closed := b.recv, b.close
	b.mu.RUnlock()
	pkt := browserInboundPacket{src: src, payload: append([]byte(nil), reassembled...)}
	select {
	case <-closed:
		return net.ErrClosed
	case recv <- pkt:
		return nil
	}
}

type browserTun struct {
	ctx    context.Context
	cancel context.CancelFunc
	link   *channel.Endpoint
	events chan tun.Event
	once   sync.Once
}

func newBrowserTun(link *channel.Endpoint) *browserTun {
	ctx, cancel := context.WithCancel(context.Background())
	return &browserTun{ctx: ctx, cancel: cancel, link: link, events: make(chan tun.Event)}
}

func (*browserTun) File() *os.File             { return nil }
func (*browserTun) MTU() (int, error)          { return browserMasqueMTU, nil }
func (*browserTun) Name() (string, error)      { return "masquecat-browser", nil }
func (t *browserTun) Events() <-chan tun.Event { return t.events }
func (*browserTun) BatchSize() int             { return 1 }
func (t *browserTun) Close() error {
	t.once.Do(func() { t.cancel(); close(t.events) })
	return nil
}

func (t *browserTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt := t.link.ReadContext(t.ctx)
	if pkt == nil {
		return 0, os.ErrClosed
	}
	defer pkt.DecRef()
	raw := stack.PayloadSince(pkt.NetworkHeader()).AsSlice()
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset+len(raw) > len(bufs[0]) {
		return 0, errors.New("masquecat: browser TUN receive buffer too small")
	}
	copy(bufs[0][offset:], raw)
	sizes[0] = len(raw)
	return 1, nil
}

func (t *browserTun) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, buf := range bufs {
		if offset < 0 || offset >= len(buf) {
			return written, errors.New("masquecat: invalid browser TUN offset")
		}
		raw := buf[offset:]
		if len(raw) == 0 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch raw[0] >> 4 {
		case 4:
			proto = ipv4.ProtocolNumber
		case 6:
			proto = ipv6.ProtocolNumber
		default:
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
		pkt.NetworkProtocolNumber = proto
		t.link.InjectInbound(proto, pkt)
		pkt.DecRef()
		written++
	}
	return written, nil
}

type browserCore struct {
	pub   key.NodePublic
	stack *stack.Stack
	link  *channel.Endpoint
	tun   *browserTun
	bind  *browserBind
	wg    *device.Device
}

func newBrowserCore(priv key.NodePrivate, server key.NodePublic, path browserPacketForwarder, logf logger.Logf) (*browserCore, error) {
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	link := channel.New(browserMasqueQueueSize, browserMasqueMTU, "")
	if err := st.CreateNIC(browserMasqueNIC, link); err != nil {
		st.Close()
		return nil, fmt.Errorf("masquecat: create browser NIC: %v", err)
	}
	if err := st.SetPromiscuousMode(browserMasqueNIC, true); err != nil {
		st.Close()
		return nil, fmt.Errorf("masquecat: browser promiscuous mode: %v", err)
	}
	if err := st.SetSpoofing(browserMasqueNIC, true); err != nil {
		st.Close()
		return nil, fmt.Errorf("masquecat: browser spoofing mode: %v", err)
	}
	v4, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 4)), tcpip.MaskFromBytes(make([]byte, 4)))
	v6, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 16)), tcpip.MaskFromBytes(make([]byte, 16)))
	st.SetRouteTable([]tcpip.Route{{Destination: v4, NIC: browserMasqueNIC}, {Destination: v6, NIC: browserMasqueNIC}})

	pub := priv.Public()
	addr := tcAddrForKey(pub)
	if err := st.AddProtocolAddress(browserMasqueNIC, tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr.AsSlice()),
			PrefixLen: addr.BitLen(),
		},
	}, stack.AddressProperties{}); err != nil {
		st.Close()
		return nil, fmt.Errorf("masquecat: add browser address: %v", err)
	}

	btun := newBrowserTun(link)
	bind := &browserBind{local: pub}
	bind.SetPath(server, path)
	wglog := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   func(format string, args ...any) { logf("wireguard: "+format, args...) },
	}
	wg := device.NewDevice(btun, bind, wglog)
	privRaw := priv.Raw32()
	if err := wg.IpcSet("private_key=" + hex.EncodeToString(privRaw[:]) + "\n\n"); err != nil {
		wg.Close()
		st.Close()
		return nil, err
	}
	serverRaw := server.AppendTo(nil)
	conf := "public_key=" + hex.EncodeToString(serverRaw) + "\n" +
		"endpoint=" + hex.EncodeToString(serverRaw) + "\n" +
		"replace_allowed_ips=true\nallowed_ip=::/0\n\n"
	if err := wg.IpcSet(conf); err != nil {
		wg.Close()
		st.Close()
		return nil, err
	}
	if err := wg.Up(); err != nil {
		wg.Close()
		st.Close()
		return nil, err
	}
	return &browserCore{pub: pub, stack: st, link: link, tun: btun, bind: bind, wg: wg}, nil
}

func (c *browserCore) Inject(src key.NodePublic, payload []byte) error {
	return c.bind.Inject(src, payload)
}

func (c *browserCore) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, c.stack, tcpip.FullAddress{
		NIC:  browserMasqueNIC,
		Addr: tcpip.AddrFromSlice(dst.Addr().AsSlice()),
		Port: dst.Port(),
	}, ipv6.ProtocolNumber)
}

func (c *browserCore) DialTCPPort(ctx context.Context, server key.NodePublic, port uint16) (net.Conn, error) {
	return c.DialTCP(ctx, netip.AddrPortFrom(tcAddrForKey(server), port))
}

func (c *browserCore) Ping(ctx context.Context) (PingResult, error) {
	start := time.Now()
	conn, err := c.DialTCP(ctx, netip.AddrPortFrom(browserMasquePingAddr, browserMasquePingPort))
	if err != nil {
		return PingResult{}, err
	}
	_ = conn.Close()
	return PingResult{Latency: time.Since(start)}, nil
}

func (c *browserCore) Close() error {
	if c.wg != nil {
		c.wg.Close()
	}
	if c.link != nil {
		c.link.Close()
	}
	if c.stack != nil {
		c.stack.Close()
		c.stack.Wait()
	}
	return nil
}

type browserControl struct {
	Type      string `json:"type"`
	Version   int    `json:"version,omitempty"`
	Source    string `json:"source,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	Verifier  string `json:"verifier,omitempty"`
	Proof     string `json:"proof,omitempty"`
	Error     string `json:"error,omitempty"`
}

type jsPromiseResult struct {
	value js.Value
	err   error
}

func jsError(v js.Value) error {
	if v.Type() == js.TypeObject {
		if m := v.Get("message"); m.Type() == js.TypeString {
			return errors.New(m.String())
		}
	}
	return errors.New(js.Global().Get("String").Invoke(v).String())
}

func awaitJSPromise(ctx context.Context, promise js.Value) (js.Value, error) {
	ch := make(chan jsPromiseResult, 1)
	then := js.FuncOf(func(this js.Value, args []js.Value) any {
		v := js.Undefined()
		if len(args) != 0 {
			v = args[0]
		}
		select {
		case ch <- jsPromiseResult{value: v}:
		default:
		}
		return nil
	})
	catch := js.FuncOf(func(this js.Value, args []js.Value) any {
		err := errors.New("JavaScript promise rejected")
		if len(args) != 0 {
			err = jsError(args[0])
		}
		select {
		case ch <- jsPromiseResult{err: err}:
		default:
		}
		return nil
	})
	promise.Call("then", then).Call("catch", catch)
	select {
	case r := <-ch:
		then.Release()
		catch.Release()
		return r.value, r.err
	case <-ctx.Done():
		// The browser Promise itself is not cancelable. Keep the callbacks alive
		// until it eventually settles, then release both JS functions so repeated
		// timed-out attempts don't retain Go channels and callback closures.
		go func() {
			<-ch
			then.Release()
			catch.Release()
		}()
		return js.Undefined(), ctx.Err()
	}
}

func bytesToJS(b []byte) js.Value {
	u8 := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u8, b)
	return u8
}

func writeJSBytes(ctx context.Context, writer js.Value, b []byte) error {
	_, err := awaitJSPromise(ctx, writer.Call("write", bytesToJS(b)))
	return err
}

type jsLineReader struct {
	reader  js.Value
	pending []byte
}

func (r *jsLineReader) readLine(ctx context.Context) ([]byte, error) {
	for {
		if i := bytes.IndexByte(r.pending, '\n'); i >= 0 {
			line := append([]byte(nil), r.pending[:i]...)
			r.pending = append([]byte(nil), r.pending[i+1:]...)
			return line, nil
		}
		if len(r.pending) > browserControlMax {
			return nil, errors.New("masquecat: browser control message too large")
		}
		res, err := awaitJSPromise(ctx, r.reader.Call("read"))
		if err != nil {
			return nil, err
		}
		if res.Get("done").Bool() {
			return nil, io.EOF
		}
		v := res.Get("value")
		chunk := make([]byte, v.Get("byteLength").Int())
		js.CopyBytesToGo(chunk, v)
		r.pending = append(r.pending, chunk...)
	}
}

type browserWebTransportPath struct {
	local     key.NodePublic
	wt        js.Value
	writer    js.Value
	reader    js.Value
	writeMu   sync.Mutex
	closeOnce sync.Once
}

func browserWebTransportURL(relayURL string) (string, error) {
	u, err := url.Parse(relayURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", errors.New("MasqueCat browser relay must be an https URL")
	}
	u.RawQuery, u.Fragment = "", ""
	u.Path = strings.TrimSuffix(u.Path, "/") + browserWebTransportRoute
	return u.String(), nil
}

func newBrowserWebTransportPath(ctx context.Context, relayURL string, local key.NodePrivate) (*browserWebTransportPath, error) {
	ctor := js.Global().Get("WebTransport")
	if ctor.Type() != js.TypeFunction {
		return nil, errors.New("this browser does not support WebTransport")
	}
	wtURL, err := browserWebTransportURL(relayURL)
	if err != nil {
		return nil, err
	}
	wt := ctor.New(wtURL)
	if _, err := awaitJSPromise(ctx, wt.Get("ready")); err != nil {
		return nil, fmt.Errorf("WebTransport ready: %w", err)
	}
	stream, err := awaitJSPromise(ctx, wt.Call("createBidirectionalStream"))
	if err != nil {
		wt.Call("close")
		return nil, fmt.Errorf("WebTransport control stream: %w", err)
	}
	controlWriter := stream.Get("writable").Call("getWriter")
	controlReader := &jsLineReader{reader: stream.Get("readable").Call("getReader")}

	sendControl := func(msg browserControl) error {
		b, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		b = append(b, '\n')
		return writeJSBytes(ctx, controlWriter, b)
	}
	readControl := func() (browserControl, error) {
		var msg browserControl
		b, err := controlReader.readLine(ctx)
		if err != nil {
			return msg, err
		}
		if err := json.Unmarshal(b, &msg); err != nil {
			return msg, err
		}
		if msg.Type == "error" {
			return msg, errors.New(msg.Error)
		}
		return msg, nil
	}

	if err := sendControl(browserControl{Type: "hello", Version: browserProtocolVersion, Source: local.Public().String()}); err != nil {
		wt.Call("close")
		return nil, err
	}
	challenge, err := readControl()
	if err != nil {
		wt.Call("close")
		return nil, err
	}
	if challenge.Type != "challenge" || challenge.Challenge == "" || challenge.Verifier == "" {
		wt.Call("close")
		return nil, errors.New("invalid MasqueCat browser challenge")
	}
	var verifier key.NodePublic
	if err := verifier.UnmarshalText([]byte(challenge.Verifier)); err != nil || verifier.IsZero() {
		wt.Call("close")
		return nil, errors.New("invalid MasqueCat browser verifier")
	}
	sealed := local.SealTo(verifier, []byte(challenge.Challenge))
	proof := base64.RawURLEncoding.EncodeToString(sealed)
	if err := sendControl(browserControl{Type: "proof", Proof: proof}); err != nil {
		wt.Call("close")
		return nil, err
	}
	ready, err := readControl()
	if err != nil {
		wt.Call("close")
		return nil, err
	}
	if ready.Type != "ready" || ready.Version != browserProtocolVersion {
		wt.Call("close")
		return nil, errors.New("MasqueCat browser relay did not become ready")
	}

	datagrams := wt.Get("datagrams")
	return &browserWebTransportPath{
		local:  local.Public(),
		wt:     wt,
		writer: datagrams.Get("writable").Call("getWriter"),
		reader: datagrams.Get("readable").Call("getReader"),
	}, nil
}

func (p *browserWebTransportPath) ForwardPacket(src, dst key.NodePublic, payload []byte) error {
	if bytes.HasPrefix(payload, browserDiscoMagic) {
		return nil
	}
	b := encodeBrowserMasquePacket(src, dst, payload)
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_, err := awaitJSPromise(context.Background(), p.writer.Call("write", bytesToJS(b)))
	return err
}

func (p *browserWebTransportPath) run(ctx context.Context, local key.NodePublic, onPacket func(key.NodePublic, []byte) error) error {
	for {
		res, err := awaitJSPromise(ctx, p.reader.Call("read"))
		if err != nil {
			return err
		}
		if res.Get("done").Bool() {
			return io.EOF
		}
		v := res.Get("value")
		b := make([]byte, v.Get("byteLength").Int())
		js.CopyBytesToGo(b, v)
		pkt, err := decodeBrowserMasquePacket(b)
		if err != nil || pkt.dst != local || bytes.HasPrefix(pkt.payload, browserDiscoMagic) {
			continue
		}
		if err := onPacket(pkt.src, pkt.payload); err != nil {
			return err
		}
	}
}

func (p *browserWebTransportPath) Close() error {
	p.closeOnce.Do(func() {
		if p.reader.Truthy() {
			p.reader.Call("cancel")
		}
		if p.writer.Truthy() {
			p.writer.Call("close")
		}
		if p.wt.Truthy() {
			p.wt.Call("close")
		}
	})
	return nil
}

// BrowserMasqueClient is the js/wasm MasqueCat client. Browsers cannot emit an
// arbitrary HTTP/3 CONNECT-UDP request, so the browser joins the same relay peer
// registry through authenticated WebTransport datagrams instead. From the
// WireGuard/gVisor core upward, the data plane is the normal MasqueCat path.
type BrowserMasqueClient struct {
	Server MasqueConnBlob
	Key    key.NodePrivate
	Logf   logger.Logf

	mu           sync.Mutex
	started      bool
	serverPublic key.NodePublic
	core         *browserCore
	path         *browserWebTransportPath
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewBrowserMasqueClient(server MasqueConnBlob, priv key.NodePrivate, logf logger.Logf) *BrowserMasqueClient {
	return &BrowserMasqueClient{Server: server, Key: priv, Logf: logf}
}

func (c *BrowserMasqueClient) ensureStarted(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return nil
	}
	ci, err := ParseMasqueConnBlob(c.Server)
	if err != nil {
		return err
	}
	if ci.RelayURL == "" {
		return errors.New("MasqueCat browser client currently requires an mc... token with a relay URL")
	}
	if c.Key.IsZero() {
		c.Key = key.NewNode()
	}
	logf := c.Logf
	if logf == nil {
		logf = logger.Discard
	}
	path, err := newBrowserWebTransportPath(ctx, ci.RelayURL, c.Key)
	if err != nil {
		return err
	}
	core, err := newBrowserCore(c.Key, ci.ServerPublic, path, logf)
	if err != nil {
		_ = path.Close()
		return err
	}
	child, cancel := context.WithCancel(context.Background())
	localPublic := c.Key.Public()
	c.serverPublic, c.path, c.core, c.ctx, c.cancel, c.started = ci.ServerPublic, path, core, child, cancel, true
	go func() {
		err := path.run(child, localPublic, func(src key.NodePublic, payload []byte) error {
			if src != ci.ServerPublic {
				return nil
			}
			return core.Inject(src, payload)
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			logf("MasqueCat browser WebTransport receive loop ended: %v", err)
		}
		c.mu.Lock()
		if c.path != path || c.core != core {
			c.mu.Unlock()
			return
		}
		c.started = false
		c.serverPublic = key.NodePublic{}
		c.path = nil
		c.core = nil
		c.ctx = nil
		c.cancel = nil
		c.mu.Unlock()
		cancel()
		_ = path.Close()
		_ = core.Close()
	}()
	return nil
}

func (c *BrowserMasqueClient) Ping(ctx context.Context) (PingResult, error) {
	if err := c.ensureStarted(ctx); err != nil {
		return PingResult{}, err
	}
	c.mu.Lock()
	core := c.core
	c.mu.Unlock()
	return core.Ping(ctx)
}

func (c *BrowserMasqueClient) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	if err := c.ensureStarted(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	core, server := c.core, c.serverPublic
	c.mu.Unlock()
	return core.DialTCPPort(ctx, server, port)
}

func (c *BrowserMasqueClient) Close() error {
	c.mu.Lock()
	cancel, path, core := c.cancel, c.path, c.core
	c.started = false
	c.serverPublic = key.NodePublic{}
	c.cancel = nil
	c.path = nil
	c.core = nil
	c.ctx = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if path != nil {
		_ = path.Close()
	}
	if core != nil {
		_ = core.Close()
	}
	return nil
}
