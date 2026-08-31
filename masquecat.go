//go:build !js

package tailcat

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"

	"github.com/quic-go/quic-go/http3"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/mak"
)

// MasquePathType identifies the external path carrying WireGuard datagrams.
type MasquePathType string

const (
	MasquePathDirect MasquePathType = "direct-masque"
	MasquePathRelay  MasquePathType = "relay-masque"
)

// MasqueServer preserves Tailcat's userspace WireGuard/netstack server while
// replacing externally visible DERP, STUN, disco path discovery and raw direct
// WireGuard with MASQUE CONNECT-UDP paths.
type MasqueServer struct {
	Server

	// DirectListen enables a peer-to-peer MASQUE listener, for example ":443".
	// DirectURL is the https URL embedded in the mc token and must identify the
	// same listener from the client's point of view.
	DirectListen    string
	DirectURL       string
	DirectTLSConfig *tls.Config

	// RelayURL, when set, is a MasqueCat relay reached over HTTP/3 CONNECT-UDP.
	RelayURL string

	mu         sync.Mutex
	bridge     *localDERPBridge
	relayPath  *masquePath
	directHTTP *http3.Server
	directPC   net.PacketConn
	cancel     context.CancelFunc
	blob       MasqueConnBlob
}

// Start brings up the Tailcat userspace stack and the configured MASQUE paths.
// At least one of DirectURL or RelayURL must be configured.
func (s *MasqueServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Server.lb != nil || s.bridge != nil {
		return errors.New("masquecat: MasqueServer.Start called twice")
	}
	if s.DirectURL == "" && s.RelayURL == "" {
		return errors.New("masquecat: configure a direct or relay MASQUE endpoint")
	}
	if s.DirectURL != "" {
		if err := validateMasqueURL("direct", s.DirectURL); err != nil {
			return err
		}
		if s.DirectListen == "" {
			return errors.New("masquecat: DirectURL requires DirectListen")
		}
		if s.DirectTLSConfig == nil || len(s.DirectTLSConfig.Certificates) == 0 {
			return errors.New("masquecat: direct MASQUE requires a TLS certificate")
		}
	}
	if s.RelayURL != "" {
		if err := validateMasqueURL("relay", s.RelayURL); err != nil {
			return err
		}
	}

	logf := s.Logf
	if logf == nil {
		logf = log.Printf
	}
	priv := s.Key
	if priv.IsZero() {
		priv = key.NewNode()
	}
	s.Key = priv

	bridge, err := newLocalDERPBridge(logf)
	if err != nil {
		return fmt.Errorf("start loopback DERP compatibility bridge: %w", err)
	}
	s.bridge = bridge
	cleanup := func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.directHTTP != nil {
			s.directHTTP.Close()
		}
		if s.directPC != nil {
			s.directPC.Close()
		}
		if s.relayPath != nil {
			s.relayPath.Close()
		}
		if s.Server.lb != nil {
			s.Server.Close()
		}
		bridge.Close()
		s.bridge = nil
	}

	if err := s.startTailcatCore(priv, bridge.Region(), logf); err != nil {
		cleanup()
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	local := priv.Public()

	if s.DirectURL != "" {
		pc, err := net.ListenPacket("udp", s.DirectListen)
		if err != nil {
			cleanup()
			return fmt.Errorf("listen for direct MASQUE: %w", err)
		}
		conf := http3.ConfigureTLSConfig(s.DirectTLSConfig.Clone())
		conf.MinVersion = tls.VersionTLS13
		h3 := &http3.Server{
			TLSConfig:       conf,
			Handler:         directMasqueHandler(local, bridge, logf),
			EnableDatagrams: true,
		}
		s.directPC, s.directHTTP = pc, h3
		go func() {
			if err := h3.Serve(pc); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
				logf("direct MASQUE listener stopped: %v", err)
			}
		}()
	}

	if s.RelayURL != "" {
		path, err := newMasquePath(ctx, s.RelayURL, local, local, masqueModeRelay, logf)
		if err != nil {
			cleanup()
			return fmt.Errorf("connect MASQUE relay: %w", err)
		}
		s.relayPath = path
		go func() {
			err := path.run(ctx, local, func(src key.NodePublic, payload []byte) error {
				bridge.AddForwarder(src, path)
				return bridge.Inject(src, local, payload)
			})
			if err != nil && ctx.Err() == nil {
				logf("MASQUE relay receive loop stopped: %v", err)
			}
		}()
	}

	blob, err := (MasqueConnInfo{
		Version:           1,
		ServerPublic:      local,
		ServerDiscoPublic: DiscoPublicForNode(priv).DiscoPublic,
		DirectURL:         s.DirectURL,
		RelayURL:          s.RelayURL,
	}).ConnBlob()
	if err != nil {
		cleanup()
		return err
	}
	s.blob = blob
	return nil
}

// ConnBlob returns the mc-prefixed connection token. Start must have succeeded.
func (s *MasqueServer) ConnBlob() MasqueConnBlob {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blob
}

// Close shuts down the MASQUE paths, loopback compatibility bridge and Tailcat
// userspace networking stack.
func (s *MasqueServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	var errs []error
	if s.directHTTP != nil {
		errs = append(errs, s.directHTTP.Close())
		s.directHTTP = nil
	}
	if s.directPC != nil {
		errs = append(errs, s.directPC.Close())
		s.directPC = nil
	}
	if s.relayPath != nil {
		errs = append(errs, s.relayPath.Close())
		s.relayPath = nil
	}
	if s.Server.lb != nil {
		errs = append(errs, s.Server.Close())
	}
	if s.bridge != nil {
		errs = append(errs, s.bridge.Close())
		s.bridge = nil
	}
	return errors.Join(errs...)
}

// startTailcatCore is intentionally close to Server.Start. The key difference
// is that magicsock is switched to TCP443-only mode before NetworkUp, which
// prevents its own UDP/STUN discovery while leaving the independent QUIC/UDP
// sockets used by MasqueCat untouched.
func (s *MasqueServer) startTailcatCore(priv key.NodePrivate, reg *tailcfg.DERPRegion, logf logger.Logf) error {
	lb := newLocoBackend(priv)
	lb.logf = logf
	lb.dm = &tailcfg.DERPMap{}
	mak.Set(&lb.dm.Regions, reg.RegionID, reg)
	for _, k := range s.AllowedClients {
		mak.Set(&lb.allowedClients, k, true)
	}

	sys := &lb.sys
	bus := eventbus.New()
	sys.Set(bus)
	sys.Set(health.NewTracker(bus))
	netMon, err := netmon.New(bus, func(format string, args ...any) { logf(format, args...) })
	if err != nil {
		lb.Close()
		return fmt.Errorf("netmon.New: %w", err)
	}
	sys.Set(netMon)
	dialer := &tsdial.Dialer{Logf: logf}
	sys.Set(dialer)
	var store ipn.StateStore = new(mem.Store)
	sys.Set(store)

	lb.isServer = true
	lb.onDERPRecv = func(regionID tailcfg.DERPRegionID, src key.NodePublic, pkt []byte) bool {
		if !IsMeowPacket(pkt) {
			return false
		}
		if IsMeowedPacket(pkt) {
			return true
		}
		if _, discoPub, ok := ParseMeowPing(pkt); ok {
			mc := lb.sys.MagicSock.Get()
			go func() {
				if lb.onMasqueMeow(src, discoPub) {
					mc.SendDERPPacketTo(src, regionID, EncodeMeowed())
				}
			}()
			return true
		}
		return false
	}

	if err := createEngine(logf, lb); err != nil {
		lb.Close()
		return fmt.Errorf("createEngine: %w", err)
	}
	// This switch applies only to magicsock. MasqueCat's QUIC sockets are
	// independent, so they remain free to use UDP/443.
	sys.MagicSock.Get().SetOnlyTCP443(true)

	ns, err := newNetstack(logf, sys)
	if err != nil {
		lb.Close()
		return fmt.Errorf("newNetstack: %w", err)
	}
	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true
	ns.GetTCPHandlerForFlow = func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
		if dst.Addr() == lb.addr {
			if s.OnTCP == nil {
				return nil, true
			}
			return s.OnTCP(dst.Port()), true
		}
		if s.OnTCPForward == nil {
			return nil, true
		}
		if nat64Prefix.Contains(dst.Addr()) {
			var a4 [4]byte
			d6 := dst.Addr().As16()
			copy(a4[:], d6[12:16])
			dst = netip.AddrPortFrom(netip.AddrFrom4(a4), dst.Port())
		}
		return s.OnTCPForward(dst), true
	}
	lb.ns = ns
	sys.Set(ns)
	dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := lb.peerByIP(ip)
		return ok
	}
	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}
	dialer.NetstackDialUDP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		panic("unreachable from masquecat")
	}
	sys.Tun.Get().Start()

	s.Server.lb = lb
	sys.Engine.Get().SetFilter(s.Server.buildFilter())
	if err := lb.Start(); err != nil {
		s.Server.lb = nil
		lb.Close()
		return err
	}
	return nil
}

// onMasqueMeow is Tailcat's onMeow peer admission logic without the endpoint
// advertisement side effect. Direct MasqueCat paths are configured explicitly;
// relay paths are registered with the relay, so CallMeMaybe is never needed.
func (b *locoBackend) onMasqueMeow(src key.NodePublic, discoPub key.DiscoPublic) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.logf("got MasqueCat meow from %v", src.String())
	if b.allowedClients != nil && !b.allowedClients[src] {
		b.logf("ignoring meow from %v: not in allowedClients", src.String())
		return false
	}
	if _, ok := b.clients[src]; ok {
		return true
	}
	id := len(b.clients) + 2
	derpRegion := b.derpRegionID()
	mak.Set(&b.clients, src, &tailcfg.Node{
		ID:         tailcfg.NodeID(id),
		StableID:   tailcfg.StableNodeID(fmt.Sprint(id)),
		Name:       fmt.Sprintf("client%d.masquecat.", id),
		User:       100,
		Key:        src,
		DiscoKey:   discoPub,
		Addresses:  []netip.Prefix{pfxOf(tcAddrForKey(src))},
		AllowedIPs: []netip.Prefix{pfxOf(tcAddrForKey(src))},
		HomeDERP:   derpRegion,
	})
	nm := &netmap.NetworkMap{
		NodeKey: b.pub,
		SelfNode: (&tailcfg.Node{
			ID:         1,
			StableID:   "1",
			Name:       "server.masquecat.",
			User:       100,
			Key:        b.pub,
			DiscoKey:   b.discoPublic(),
			Addresses:  []netip.Prefix{b.addrPrefix},
			AllowedIPs: []netip.Prefix{b.addrPrefix, allIPv6},
			HomeDERP:   derpRegion,
		}).View(),
	}
	for _, n := range b.clients {
		nm.Peers = append(nm.Peers, n.View())
	}
	slices.SortFunc(nm.Peers, func(a, b tailcfg.NodeView) int { return cmp.Compare(a.ID(), b.ID()) })
	b.nm = nm
	mc := b.sys.MagicSock.Get()
	mc.SetNetworkMap(nm.SelfNode, nm.Peers)
	b.sys.Netstack.Get().UpdateNetstackIPs(nm)
	return true
}

// MasqueClient is the Tailcat client API with deterministic MASQUE path
// selection. It attempts DirectURL once, then falls back to RelayURL. It never
// invokes Tailcat's endpoint discovery or raw direct WireGuard path.
type MasqueClient struct {
	Server MasqueConnBlob
	Key    key.NodePrivate
	Logf   logger.Logf

	mu       sync.Mutex
	base     *Client
	bridge   *localDERPBridge
	path     *masquePath
	pathType MasquePathType
	cancel   context.CancelFunc
	started  bool
}

func NewMasqueClient(server MasqueConnBlob) *MasqueClient { return &MasqueClient{Server: server} }

func (c *MasqueClient) ensureStarted(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return nil
	}
	ci, err := ParseMasqueConnBlob(c.Server)
	if err != nil {
		return err
	}
	logf := c.Logf
	if logf == nil {
		logf = log.Printf
	}
	priv := c.Key
	if priv.IsZero() {
		priv = key.NewNode()
		c.Key = priv
	}
	bridge, err := newLocalDERPBridge(logf)
	if err != nil {
		return fmt.Errorf("start loopback DERP compatibility bridge: %w", err)
	}

	internalBlob := (&ConnInfo{
		ServerPublic:      NodePublic{ci.ServerPublic},
		ServerDiscoPublic: DiscoPublic{ci.ServerDiscoPublic},
		Region:            []*tailcfg.DERPRegion{bridge.Region()},
	}).ConnBlob()
	base := NewClient(internalBlob)
	base.Key = priv
	base.Logf = logf
	base.startMu.Lock()
	if err := base.initLocked(); err != nil {
		base.startMu.Unlock()
		bridge.Close()
		return err
	}
	base.lb.sys.MagicSock.Get().SetOnlyTCP443(true)
	for _, r := range base.ci.Region {
		mak.Set(&base.lb.dm.Regions, r.RegionID, r)
	}
	if err := base.lb.Start(); err != nil {
		base.startMu.Unlock()
		base.Close()
		bridge.Close()
		return err
	}
	base.started = true
	base.startMu.Unlock()

	childCtx, cancel := context.WithCancel(context.Background())
	local := priv.Public()
	var directErr error
	var path *masquePath
	var pathType MasquePathType
	if ci.DirectURL != "" {
		path, directErr = newMasquePath(ctx, ci.DirectURL, ci.ServerPublic, local, masqueModeDirect, logf)
		if directErr == nil {
			pathType = MasquePathDirect
		}
	}
	if path == nil && ci.RelayURL != "" {
		path, err = newMasquePath(ctx, ci.RelayURL, local, local, masqueModeRelay, logf)
		if err != nil {
			cancel()
			base.Close()
			bridge.Close()
			if directErr != nil {
				return errors.Join(fmt.Errorf("direct MASQUE: %w", directErr), fmt.Errorf("relay MASQUE: %w", err))
			}
			return fmt.Errorf("relay MASQUE: %w", err)
		}
		pathType = MasquePathRelay
	}
	if path == nil {
		cancel()
		base.Close()
		bridge.Close()
		if directErr != nil {
			return fmt.Errorf("direct MASQUE: %w", directErr)
		}
		return errors.New("no usable MASQUE path")
	}

	c.cancel = cancel
	c.base, c.bridge, c.path, c.pathType = base, bridge, path, pathType
	bridge.AddForwarder(ci.ServerPublic, path)
	go func() {
		err := path.run(childCtx, local, func(src key.NodePublic, payload []byte) error {
			bridge.AddForwarder(src, path)
			return bridge.Inject(src, local, payload)
		})
		if err != nil && childCtx.Err() == nil {
			logf("MASQUE receive loop stopped: %v", err)
		}
	}()
	c.started = true
	return nil
}

func (c *MasqueClient) Path() MasquePathType {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pathType
}

func (c *MasqueClient) PublicKey() key.NodePublic {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Key.IsZero() {
		c.Key = key.NewNode()
	}
	return c.Key.Public()
}

func (c *MasqueClient) Ping(ctx context.Context) (PingResult, error) {
	if err := c.ensureStarted(ctx); err != nil {
		return PingResult{}, err
	}
	return c.base.Ping(ctx)
}

func (c *MasqueClient) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := c.ensureStarted(ctx); err != nil {
		return nil, err
	}
	return c.base.Dial(ctx, network, addr)
}

func (c *MasqueClient) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	if err := c.ensureStarted(ctx); err != nil {
		return nil, err
	}
	return c.base.DialTCPPort(ctx, port)
}

func (c *MasqueClient) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if err := c.ensureStarted(ctx); err != nil {
		return nil, err
	}
	return c.base.DialTCP(ctx, dst)
}

func (c *MasqueClient) DrainTCP(ctx context.Context) error {
	c.mu.Lock()
	base := c.base
	c.mu.Unlock()
	if base == nil {
		return nil
	}
	return base.DrainTCP(ctx)
}

func (c *MasqueClient) Status() *ipnstate.Status {
	c.mu.Lock()
	base := c.base
	c.mu.Unlock()
	if base == nil || base.lb == nil {
		return nil
	}
	return base.lb.Status()
}

func (c *MasqueClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	var errs []error
	if c.path != nil {
		errs = append(errs, c.path.Close())
		c.path = nil
	}
	if c.base != nil {
		errs = append(errs, c.base.Close())
		c.base = nil
	}
	if c.bridge != nil {
		errs = append(errs, c.bridge.Close())
		c.bridge = nil
	}
	c.started = false
	return errors.Join(errs...)
}
