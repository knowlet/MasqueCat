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

	// InsecureSkipVerify disables TLS certificate and hostname verification for
	// outbound MASQUE connections. It is intended only for development with
	// explicitly trusted self-signed endpoints and is false by default.
	InsecureSkipVerify bool

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
	if s.lb != nil || s.bridge != nil {
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
			_ = s.directHTTP.Close()
		}
		if s.directPC != nil {
			_ = s.directPC.Close()
		}
		if s.relayPath != nil {
			_ = s.relayPath.Close()
		}
		if s.lb != nil {
			_ = s.Server.Close()
		}
		_ = bridge.Close()
		s.cancel = nil
		s.directHTTP = nil
		s.directPC = nil
		s.relayPath = nil
		s.bridge = nil
		s.lb = nil
		s.blob = ""
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
			Handler:         directMasqueHandler(priv, bridge, logf),
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
		path, err := newMasquePathWithTLS(ctx, s.RelayURL, local, priv, masqueModeRelay, s.InsecureSkipVerify, logf)
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
		s.cancel = nil
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
	if s.lb != nil {
		errs = append(errs, s.Server.Close())
		s.lb = nil
	}
	if s.bridge != nil {
		errs = append(errs, s.bridge.Close())
		s.bridge = nil
	}
	s.blob = ""
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
		_ = lb.Close()
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
					if _, err := mc.SendDERPPacketTo(src, regionID, EncodeMeowed()); err != nil {
						logf("send MasqueCat meowed response to %v: %v", src.ShortString(), err)
					}
				}
			}()
			return true
		}
		return false
	}

	if err := createEngine(logf, lb); err != nil {
		_ = lb.Close()
		return fmt.Errorf("createEngine: %w", err)
	}
	// This switch applies only to magicsock. MasqueCat's QUIC sockets are
	// independent, so they remain free to use UDP/443.
	sys.MagicSock.Get().SetOnlyTCP443(true)

	ns, err := newNetstack(logf, sys)
	if err != nil {
		_ = lb.Close()
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

	s.lb = lb
	sys.Engine.Get().SetFilter(s.buildFilter())
	if err := lb.Start(); err != nil {
		s.lb = nil
		_ = lb.Close()
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

	// InsecureSkipVerify disables TLS certificate and hostname verification for
	// direct and relay MASQUE connections. It is false by default and should
	// only be used for explicitly trusted development endpoints.
	InsecureSkipVerify bool

	mu           sync.Mutex
	activeOps    sync.WaitGroup
	base         *Client
	bridge       *localDERPBridge
	path         *masquePath
	pathType     MasquePathType
	lifecycleCtx context.Context
	cancel       context.CancelFunc
	started      bool
}

func NewMasqueClient(server MasqueConnBlob) *MasqueClient { return &MasqueClient{Server: server} }

func (c *MasqueClient) ensureStarted(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensureStartedLocked(ctx)
}

// masqueDialContext makes an in-flight CONNECT-UDP establishment
// cancelable by the caller without letting that one-shot operation context
// own the established transport. Calling finish(true) is the detach point:
// after it succeeds, only lifecycleCtx can cancel the returned context.
func masqueDialContext(lifecycleCtx, operationCtx context.Context) (context.Context, func(bool) bool) {
	dialCtx, cancelDial := context.WithCancel(lifecycleCtx)
	stopOperationCancel := context.AfterFunc(operationCtx, cancelDial)
	return dialCtx, func(keep bool) bool {
		operationActive := stopOperationCancel()
		if !keep || !operationActive {
			cancelDial()
		}
		return operationActive
	}
}

// masqueOperationContext combines a caller's operation context with the
// client's lifecycle. The returned context is canceled by either source. The
// stop function detaches the lifecycle callback and releases local resources.
func masqueOperationContext(operationCtx, lifecycleCtx context.Context) (context.Context, func()) {
	opCtx, cancel := context.WithCancel(operationCtx)
	stopLifecycleCancel := context.AfterFunc(lifecycleCtx, cancel)
	return opCtx, func() {
		stopLifecycleCancel()
		cancel()
	}
}

func (c *MasqueClient) ensureStartedLocked(ctx context.Context) error {
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
		_ = bridge.Close()
		return err
	}
	base.lb.sys.MagicSock.Get().SetOnlyTCP443(true)
	for _, r := range base.ci.Region {
		mak.Set(&base.lb.dm.Regions, r.RegionID, r)
	}
	if err := base.lb.Start(); err != nil {
		base.startMu.Unlock()
		_ = base.Close()
		_ = bridge.Close()
		return err
	}
	base.started = true
	base.startMu.Unlock()

	childCtx, cancel := context.WithCancel(context.Background())
	local := priv.Public()
	dialPath := func(rawURL string, target key.NodePublic, mode string) (*masquePath, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dialCtx, finishDial := masqueDialContext(childCtx, ctx)
		p, err := newMasquePathWithTLS(dialCtx, rawURL, target, priv, mode, c.InsecureSkipVerify, logf)
		operationActive := finishDial(err == nil)
		if !operationActive {
			if p != nil {
				_ = p.Close()
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			if err == nil {
				return nil, context.Canceled
			}
		}
		return p, err
	}

	var directErr error
	var path *masquePath
	var pathType MasquePathType
	if ci.DirectURL != "" {
		path, directErr = dialPath(ci.DirectURL, ci.ServerPublic, masqueModeDirect)
		if directErr == nil {
			pathType = MasquePathDirect
		}
	}
	if path == nil && ci.RelayURL != "" {
		path, err = dialPath(ci.RelayURL, local, masqueModeRelay)
		if err != nil {
			cancel()
			_ = base.Close()
			_ = bridge.Close()
			if directErr != nil {
				return errors.Join(fmt.Errorf("direct MASQUE: %w", directErr), fmt.Errorf("relay MASQUE: %w", err))
			}
			return fmt.Errorf("relay MASQUE: %w", err)
		}
		pathType = MasquePathRelay
	}
	if path == nil {
		cancel()
		_ = base.Close()
		_ = bridge.Close()
		if directErr != nil {
			return fmt.Errorf("direct MASQUE: %w", directErr)
		}
		return errors.New("no usable MASQUE path")
	}

	c.lifecycleCtx = childCtx
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

// acquireBase ensures startup first, then takes a lifecycle lease under c.mu
// and releases the mutex before any potentially blocking base operation. Close
// holds c.mu while canceling the lifecycle and waiting for existing leases, so
// teardown cannot race a captured base pointer. If Close wins between startup
// and lease acquisition, the nil/lifecycle check fails closed.
func (c *MasqueClient) acquireBase(ctx context.Context) (*Client, context.Context, func(), error) {
	if err := c.ensureStarted(ctx); err != nil {
		return nil, nil, nil, err
	}

	c.mu.Lock()
	if c.base == nil || c.lifecycleCtx == nil || !c.started {
		c.mu.Unlock()
		return nil, nil, nil, errors.New("masquecat: client closed during startup")
	}
	base := c.base
	lifecycleCtx := c.lifecycleCtx
	c.activeOps.Add(1)
	c.mu.Unlock()

	opCtx, stopContext := masqueOperationContext(ctx, lifecycleCtx)
	release := func() {
		stopContext()
		c.activeOps.Done()
	}
	return base, opCtx, release, nil
}

func (c *MasqueClient) Ping(ctx context.Context) (PingResult, error) {
	base, opCtx, release, err := c.acquireBase(ctx)
	if err != nil {
		return PingResult{}, err
	}
	defer release()
	return base.Ping(opCtx)
}

func (c *MasqueClient) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	base, opCtx, release, err := c.acquireBase(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return base.Dial(opCtx, network, addr)
}

func (c *MasqueClient) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	base, opCtx, release, err := c.acquireBase(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return base.DialTCPPort(opCtx, port)
}

func (c *MasqueClient) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	base, opCtx, release, err := c.acquireBase(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return base.DialTCP(opCtx, dst)
}

func (c *MasqueClient) DrainTCP(ctx context.Context) error {
	c.mu.Lock()
	if c.base == nil || c.lifecycleCtx == nil {
		c.mu.Unlock()
		return nil
	}
	base := c.base
	lifecycleCtx := c.lifecycleCtx
	c.activeOps.Add(1)
	c.mu.Unlock()

	opCtx, stopContext := masqueOperationContext(ctx, lifecycleCtx)
	defer func() {
		stopContext()
		c.activeOps.Done()
	}()
	return base.DrainTCP(opCtx)
}

func (c *MasqueClient) Status() *ipnstate.Status {
	c.mu.Lock()
	if c.base == nil || c.base.lb == nil {
		c.mu.Unlock()
		return nil
	}
	base := c.base
	c.activeOps.Add(1)
	c.mu.Unlock()
	defer c.activeOps.Done()
	return base.lb.Status()
}

func (c *MasqueClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// No new operation can acquire a lease while c.mu is held. Cancel first so
	// blocking base calls receive context cancellation, then wait for every
	// already-acquired lease before tearing down base/path/bridge pointers.
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	c.activeOps.Wait()

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
	c.lifecycleCtx = nil
	c.pathType = ""
	c.started = false
	return errors.Join(errs...)
}
