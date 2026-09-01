//go:build !js

package tailcat

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
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
	"gvisor.dev/gvisor/pkg/waiter"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

const (
	masqueCoreNIC            tcpip.NICID = 1
	masqueCoreMTU                        = 1280
	masqueCoreQueueSize                  = 512
	masqueCoreTCPMaxInFlight             = 4096
	masqueCorePingPort       uint16      = 65535
)

type masquePacketForwarder interface {
	ForwardPacket(src, dst key.NodePublic, payload []byte) error
}

type masqueInboundPacket struct {
	src     key.NodePublic
	payload []byte
}

// masqueEndpoint is a logical WireGuard endpoint. There is intentionally no
// IP:port here: peer identity is the WireGuard node key and transport selection
// happens in masqueBind.
type masqueEndpoint struct {
	peer key.NodePublic
}

func (*masqueEndpoint) ClearSrc()           {}
func (*masqueEndpoint) SrcToString() string { return "masquecat" }
func (e *masqueEndpoint) DstToString() string {
	return strings.TrimPrefix(e.peer.String(), nodePublicTextPrefix)
}
func (e *masqueEndpoint) DstToBytes() []byte { return e.peer.AppendTo(nil) }
func (*masqueEndpoint) DstIP() netip.Addr    { return netip.Addr{} }
func (*masqueEndpoint) SrcIP() netip.Addr    { return netip.Addr{} }

// masqueBind is wireguard-go's network Bind implemented directly on top of
// explicit MASQUE paths. It never opens a UDP WireGuard socket and never invokes
// magicsock, STUN, disco, netcheck, DERP, or endpoint discovery.
type masqueBind struct {
	local key.NodePublic

	mu     sync.RWMutex
	open   bool
	recv   chan masqueInboundPacket
	closed chan struct{}
	paths  map[key.NodePublic]masquePacketForwarder
}

func newMasqueBind(local key.NodePublic) *masqueBind {
	return &masqueBind{
		local: local,
		paths: make(map[key.NodePublic]masquePacketForwarder),
	}
}

func (b *masqueBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	recv := make(chan masqueInboundPacket, masqueCoreQueueSize)
	closed := make(chan struct{})
	b.recv = recv
	b.closed = closed
	b.open = true
	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-closed:
			return 0, net.ErrClosed
		case p := <-recv:
			if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
				return 0, errors.New("masquecat: WireGuard receive batch has no buffers")
			}
			if len(p.payload) > len(packets[0]) {
				return 0, fmt.Errorf("masquecat: WireGuard receive buffer too small: have %d, need %d", len(packets[0]), len(p.payload))
			}
			copy(packets[0], p.payload)
			sizes[0] = len(p.payload)
			eps[0] = &masqueEndpoint{peer: p.src}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{fn}, 0, nil
}

func (b *masqueBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return nil
	}
	close(b.closed)
	b.open = false
	b.recv = nil
	b.closed = nil
	return nil
}

func (*masqueBind) SetMark(mark uint32) error { return nil }

func (b *masqueBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	mep, ok := ep.(*masqueEndpoint)
	if !ok || mep == nil || mep.peer.IsZero() {
		return conn.ErrWrongEndpointType
	}
	b.mu.RLock()
	path := b.paths[mep.peer]
	b.mu.RUnlock()
	if path == nil {
		return fmt.Errorf("masquecat: no MASQUE path for peer %v", mep.peer.ShortString())
	}
	for _, buf := range bufs {
		if offset < 0 || offset > len(buf) {
			return fmt.Errorf("masquecat: invalid WireGuard packet offset %d for %d-byte buffer", offset, len(buf))
		}
		if err := path.ForwardPacket(b.local, mep.peer, buf[offset:]); err != nil {
			return err
		}
	}
	return nil
}

func (*masqueBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	s = strings.TrimPrefix(s, nodePublicTextPrefix)
	if len(s) != key.NodePublicRawLen*2 {
		return nil, fmt.Errorf("masquecat: invalid peer endpoint %q", s)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return nil, fmt.Errorf("masquecat: invalid peer endpoint: %w", err)
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(nodePublicTextPrefix + s)); err != nil {
		return nil, fmt.Errorf("masquecat: parse peer endpoint: %w", err)
	}
	return &masqueEndpoint{peer: k}, nil
}

func (*masqueBind) BatchSize() int { return 1 }

func (b *masqueBind) SetPath(peer key.NodePublic, path masquePacketForwarder) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if path == nil {
		delete(b.paths, peer)
		return
	}
	b.paths[peer] = path
}

func (b *masqueBind) RemovePath(peer key.NodePublic, path masquePacketForwarder) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if current := b.paths[peer]; current == path {
		delete(b.paths, peer)
	}
}

func (b *masqueBind) Inject(src key.NodePublic, payload []byte) error {
	b.mu.RLock()
	if !b.open || b.recv == nil || b.closed == nil {
		b.mu.RUnlock()
		return net.ErrClosed
	}
	recv, closed := b.recv, b.closed
	b.mu.RUnlock()
	pkt := masqueInboundPacket{src: src, payload: append([]byte(nil), payload...)}
	select {
	case <-closed:
		return net.ErrClosed
	case recv <- pkt:
		return nil
	}
}

// masqueTun connects gVisor directly to wireguard-go. gVisor outbound IP
// packets are read by WireGuard; decrypted WireGuard packets are injected back
// into gVisor. No OS TUN interface is created.
type masqueTun struct {
	ctx    context.Context
	cancel context.CancelFunc
	link   *channel.Endpoint
	events chan tun.Event
	once   sync.Once
}

func newMasqueTun(link *channel.Endpoint) *masqueTun {
	ctx, cancel := context.WithCancel(context.Background())
	return &masqueTun{ctx: ctx, cancel: cancel, link: link, events: make(chan tun.Event)}
}

func (*masqueTun) File() *os.File { return nil }

func (t *masqueTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt := t.link.ReadContext(t.ctx)
	if pkt == nil {
		return 0, os.ErrClosed
	}
	defer pkt.DecRef()
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, errors.New("masquecat: WireGuard TUN read has no buffers")
	}
	raw := stack.PayloadSince(pkt.NetworkHeader()).AsSlice()
	if offset < 0 || offset+len(raw) > len(bufs[0]) {
		return 0, fmt.Errorf("masquecat: WireGuard TUN buffer too small for %d-byte packet at offset %d", len(raw), offset)
	}
	copy(bufs[0][offset:], raw)
	sizes[0] = len(raw)
	return 1, nil
}

func (t *masqueTun) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, buf := range bufs {
		if offset < 0 || offset >= len(buf) {
			return written, fmt.Errorf("masquecat: invalid TUN write offset %d for %d-byte buffer", offset, len(buf))
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

func (*masqueTun) MTU() (int, error)          { return masqueCoreMTU, nil }
func (*masqueTun) Name() (string, error)      { return "masquecat", nil }
func (t *masqueTun) Events() <-chan tun.Event { return t.events }
func (*masqueTun) BatchSize() int             { return 1 }

func (t *masqueTun) Close() error {
	t.once.Do(func() {
		t.cancel()
		close(t.events)
	})
	return nil
}

type masqueCore struct {
	priv key.NodePrivate
	pub  key.NodePublic
	addr netip.Addr
	logf logger.Logf

	stack *stack.Stack
	link  *channel.Endpoint
	tun   *masqueTun
	bind  *masqueBind
	wg    *device.Device

	isServer       bool
	allowedClients map[key.NodePublic]bool
	onTCP          func(uint16) func(net.Conn)
	onTCPForward   func(netip.AddrPort) func(net.Conn)
	servedTCPPorts []filter.PortRange

	mu        sync.Mutex
	peers     map[key.NodePublic]bool
	closeOnce sync.Once
	closeErr  error
}

type masqueCoreOptions struct {
	IsServer       bool
	AllowedClients []key.NodePublic
	OnTCP          func(uint16) func(net.Conn)
	OnTCPForward   func(netip.AddrPort) func(net.Conn)
	ServedTCPPorts []filter.PortRange
}

func newMasqueCore(priv key.NodePrivate, opts masqueCoreOptions, logf logger.Logf) (*masqueCore, error) {
	if priv.IsZero() {
		return nil, errors.New("masquecat: zero WireGuard private key")
	}
	if logf == nil {
		return nil, errors.New("masquecat: nil logger")
	}
	pub := priv.Public()
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	link := channel.New(masqueCoreQueueSize, masqueCoreMTU, "")
	if err := st.CreateNIC(masqueCoreNIC, link); err != nil {
		st.Close()
		return nil, fmt.Errorf("masquecat: create gVisor NIC: %v", err)
	}
	if err := st.SetPromiscuousMode(masqueCoreNIC, true); err != nil {
		st.Close()
		return nil, fmt.Errorf("masquecat: enable gVisor promiscuous mode: %v", err)
	}
	if err := st.SetSpoofing(masqueCoreNIC, true); err != nil {
		st.Close()
		return nil, fmt.Errorf("masquecat: enable gVisor spoofing mode: %v", err)
	}
	v4Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 4)), tcpip.MaskFromBytes(make([]byte, 4)))
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("masquecat: create IPv4 default route: %v", err)
	}
	v6Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 16)), tcpip.MaskFromBytes(make([]byte, 16)))
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("masquecat: create IPv6 default route: %v", err)
	}
	st.SetRouteTable([]tcpip.Route{{Destination: v4Subnet, NIC: masqueCoreNIC}, {Destination: v6Subnet, NIC: masqueCoreNIC}})

	addr := tcAddrForKey(pub)
	if err := st.AddProtocolAddress(masqueCoreNIC, tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr.AsSlice()),
			PrefixLen: addr.BitLen(),
		},
	}, stack.AddressProperties{}); err != nil {
		st.Close()
		return nil, fmt.Errorf("masquecat: add local gVisor address: %v", err)
	}

	mtun := newMasqueTun(link)
	bind := newMasqueBind(pub)
	wglog := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   func(format string, args ...any) { logf("wireguard: "+format, args...) },
	}
	wg := device.NewDevice(mtun, bind, wglog)
	c := &masqueCore{
		priv:           priv,
		pub:            pub,
		addr:           addr,
		logf:           logf,
		stack:          st,
		link:           link,
		tun:            mtun,
		bind:           bind,
		wg:             wg,
		isServer:       opts.IsServer,
		onTCP:          opts.OnTCP,
		onTCPForward:   opts.OnTCPForward,
		servedTCPPorts: append([]filter.PortRange(nil), opts.ServedTCPPorts...),
		peers:          make(map[key.NodePublic]bool),
		allowedClients: nil,
	}
	if len(opts.AllowedClients) != 0 {
		c.allowedClients = make(map[key.NodePublic]bool, len(opts.AllowedClients))
		for _, k := range opts.AllowedClients {
			c.allowedClients[k] = true
		}
	}

	privRaw := priv.Raw32()
	if err := wg.IpcSet("private_key=" + hex.EncodeToString(privRaw[:]) + "\n\n"); err != nil {
		wg.Close()
		st.Close()
		return nil, fmt.Errorf("masquecat: configure WireGuard private key: %w", err)
	}
	if opts.IsServer {
		fwd := tcp.NewForwarder(st, 0, masqueCoreTCPMaxInFlight, c.handleTCPForward)
		st.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	}
	if err := wg.Up(); err != nil {
		wg.Close()
		st.Close()
		return nil, fmt.Errorf("masquecat: start WireGuard device: %w", err)
	}
	return c, nil
}

func (c *masqueCore) Addr() netip.Addr { return c.addr }

func (c *masqueCore) peerAllowed(peer key.NodePublic) bool {
	return !c.isServer || c.allowedClients == nil || c.allowedClients[peer]
}

func nodePublicHex(k key.NodePublic) string { return hex.EncodeToString(k.AppendTo(nil)) }

func (c *masqueCore) AddPeer(peer key.NodePublic) error {
	if peer.IsZero() {
		return errors.New("masquecat: zero peer key")
	}
	if !c.peerAllowed(peer) {
		return fmt.Errorf("masquecat: peer %v is not allowed", peer.ShortString())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peers[peer] {
		return nil
	}
	allowed := pfxOf(tcAddrForKey(peer)).String()
	if !c.isServer {
		allowed = "::/0"
	}
	peerHex := nodePublicHex(peer)
	conf := "public_key=" + peerHex + "\n" +
		"endpoint=" + peerHex + "\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=" + allowed + "\n\n"
	if err := c.wg.IpcSet(conf); err != nil {
		return fmt.Errorf("masquecat: configure WireGuard peer %v: %w", peer.ShortString(), err)
	}
	c.peers[peer] = true
	return nil
}

func (c *masqueCore) SetPath(peer key.NodePublic, path masquePacketForwarder) error {
	if err := c.AddPeer(peer); err != nil {
		return err
	}
	c.bind.SetPath(peer, path)
	return nil
}

func (c *masqueCore) RemovePath(peer key.NodePublic, path masquePacketForwarder) {
	c.bind.RemovePath(peer, path)
}

func (c *masqueCore) Inject(src key.NodePublic, payload []byte) error {
	if err := c.AddPeer(src); err != nil {
		return err
	}
	return c.bind.Inject(src, payload)
}

func (c *masqueCore) localPortAllowed(port uint16) bool {
	if port == masqueCorePingPort {
		return true
	}
	if len(c.servedTCPPorts) == 0 {
		return true
	}
	for _, pr := range c.servedTCPPorts {
		if pr.Contains(port) {
			return true
		}
	}
	return false
}

func (c *masqueCore) handleTCPForward(r *tcp.ForwarderRequest) {
	id := r.ID()
	dstAddr, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		r.Complete(true)
		return
	}
	dst := netip.AddrPortFrom(dstAddr.Unmap(), id.LocalPort)
	var handler func(net.Conn)
	if dst.Addr() == c.addr {
		if dst.Port() == masqueCorePingPort {
			handler = func(conn net.Conn) { _ = conn.Close() }
		} else if c.localPortAllowed(dst.Port()) && c.onTCP != nil {
			handler = c.onTCP(dst.Port())
		}
	} else if c.onTCPForward != nil {
		if nat64Prefix.Contains(dst.Addr()) {
			var a4 [4]byte
			d6 := dst.Addr().As16()
			copy(a4[:], d6[12:16])
			dst = netip.AddrPortFrom(netip.AddrFrom4(a4), dst.Port())
		}
		handler = c.onTCPForward(dst)
	}
	if handler == nil {
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		c.logf("masquecat: accept TCP %v failed: %v", dst, terr)
		return
	}
	r.Complete(false)
	conn := gonet.NewTCPConn(&wq, ep)
	go handler(conn)
}

func (c *masqueCore) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if dst.Addr().Is4() {
		a := nat64PrefixBytes
		a4 := dst.Addr().As4()
		copy(a[12:], a4[:])
		dst = netip.AddrPortFrom(netip.AddrFrom16(a), dst.Port())
	}
	proto := ipv6.ProtocolNumber
	if dst.Addr().Is4() {
		proto = ipv4.ProtocolNumber
	}
	return gonet.DialContextTCP(ctx, c.stack, tcpip.FullAddress{
		NIC:  masqueCoreNIC,
		Addr: tcpip.AddrFromSlice(dst.Addr().AsSlice()),
		Port: dst.Port(),
	}, proto)
}

func resolveMasqueTCPAddrs(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		switch network {
		case "tcp4":
			if !ip.Is4() {
				return nil, fmt.Errorf("masquecat: %q is not an IPv4 address", host)
			}
		case "tcp6":
			if !ip.Is6() || ip.Is4In6() {
				return nil, fmt.Errorf("masquecat: %q is not an IPv6 address", host)
			}
		}
		return []netip.Addr{ip.Unmap()}, nil
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("masquecat: resolve %q: %w", host, err)
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		switch network {
		case "tcp4":
			if !ip.Is4() {
				continue
			}
		case "tcp6":
			if !ip.Is6() || ip.Is4() {
				continue
			}
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("masquecat: no addresses for %q match network %q", host, network)
	}
	return out, nil
}

func (c *masqueCore) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("masquecat: network %q is not supported; only TCP is available", network)
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		return nil, err
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("masquecat: invalid TCP port %d", port)
	}
	ips, err := resolveMasqueTCPAddrs(ctx, network, host)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, ip := range ips {
		conn, err := c.DialTCP(ctx, netip.AddrPortFrom(ip, uint16(port)))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", ip, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("masquecat: dial %s: %w", addr, errors.Join(errs...))
}

func (c *masqueCore) Ping(ctx context.Context, peer key.NodePublic) (PingResult, error) {
	start := time.Now()
	conn, err := c.DialTCP(ctx, netip.AddrPortFrom(tcAddrForKey(peer), masqueCorePingPort))
	if err != nil {
		return PingResult{}, err
	}
	_ = conn.Close()
	return PingResult{Latency: time.Since(start)}, nil
}

func masqueTCPStateNeedsDrain(state tcp.EndpointState) bool {
	switch state {
	case tcp.StateConnecting,
		tcp.StateSynSent,
		tcp.StateSynRecv,
		tcp.StateEstablished,
		tcp.StateFinWait1,
		tcp.StateFinWait2,
		tcp.StateClosing,
		tcp.StateCloseWait,
		tcp.StateLastAck:
		return true
	default:
		// LISTEN sockets and TIME_WAIT endpoints don't carry application data;
		// initial/bound/closed/error states likewise don't need graceful drain.
		return false
	}
}

func (c *masqueCore) DrainTCP(ctx context.Context) error {
	for {
		var active bool
		for _, tep := range c.stack.RegisteredEndpoints() {
			ep, ok := tep.(interface{ State() uint32 })
			if ok && masqueTCPStateNeedsDrain(tcp.EndpointState(ep.State())) {
				active = true
				break
			}
		}
		if !active {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (c *masqueCore) Status() *ipnstate.Status {
	c.mu.Lock()
	peers := make([]key.NodePublic, 0, len(c.peers))
	for peer := range c.peers {
		peers = append(peers, peer)
	}
	c.mu.Unlock()

	st := &ipnstate.Status{
		TUN:          false,
		BackendState: "Running",
		HaveNodeKey:  true,
		TailscaleIPs: []netip.Addr{c.addr},
		Self: &ipnstate.PeerStatus{
			PublicKey:    c.pub,
			TailscaleIPs: []netip.Addr{c.addr},
			InEngine:     true,
		},
		Peer: make(map[key.NodePublic]*ipnstate.PeerStatus, len(peers)),
	}
	for _, peer := range peers {
		st.Peer[peer] = &ipnstate.PeerStatus{
			PublicKey:    peer,
			TailscaleIPs: []netip.Addr{tcAddrForKey(peer)},
			InEngine:     true,
		}
	}
	return st
}

func (c *masqueCore) Close() error {
	c.closeOnce.Do(func() {
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
	})
	return c.closeErr
}