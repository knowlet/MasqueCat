//go:build !js

package tailcat

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/quic-go/quic-go/http3"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// MasquePathType identifies the external path carrying WireGuard datagrams.
type MasquePathType string

const (
	MasquePathDirect MasquePathType = "direct-masque"
	MasquePathRelay  MasquePathType = "relay-masque"
)

// MasqueServer is a userspace WireGuard + gVisor server whose only external
// transport is MASQUE CONNECT-UDP. Unlike legacy Server it does not construct a
// Tailscale wgengine, magicsock.Conn, DERP client, netcheck client, STUN socket,
// disco endpoint, or hole-punching state machine.
type MasqueServer struct {
	// Embed Server to keep the existing configuration surface (Key, Logf,
	// AllowedClients, OnTCP, OnTCPForward, ServedTCPPorts) source-compatible.
	// MasqueServer does not call Server.Start and does not use Server.lb.
	Server

	DirectListen    string
	DirectURL       string
	DirectTLSConfig *tls.Config
	RelayURL        string

	// AutomaticDirect marks DirectURL as the CLI-synthesized direct-only
	// endpoint. It is serialized into the connection token so clients can relax
	// only this generated endpoint's outer TLS verification without guessing
	// from its URL shape.
	AutomaticDirect bool

	// InsecureSkipVerify disables TLS certificate and hostname verification for
	// the outbound relay connection. It is intended only for development.
	InsecureSkipVerify bool

	mu         sync.Mutex
	core       *masqueCore
	relayPath  *masquePath
	directHTTP *http3.Server
	directPC   net.PacketConn
	cancel     context.CancelFunc
	blob       MasqueConnBlob
}

func hasMasqueServerCertificate(conf *tls.Config) bool {
	return conf != nil && (len(conf.Certificates) != 0 || conf.GetCertificate != nil || conf.GetConfigForClient != nil)
}

func (s *MasqueServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.core != nil {
		return errors.New("masquecat: MasqueServer.Start called twice")
	}
	if s.DirectURL == "" && s.RelayURL == "" {
		return errors.New("masquecat: configure a direct or relay MASQUE endpoint")
	}
	if s.AutomaticDirect && (s.DirectURL == "" || s.RelayURL != "") {
		return errors.New("masquecat: AutomaticDirect requires a direct-only endpoint")
	}
	if s.DirectURL != "" {
		if err := validateMasqueURL("direct", s.DirectURL); err != nil {
			return err
		}
		if s.DirectListen == "" {
			return errors.New("masquecat: DirectURL requires DirectListen")
		}
		if !hasMasqueServerCertificate(s.DirectTLSConfig) {
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

	core, err := newMasqueCore(priv, masqueCoreOptions{
		IsServer:       true,
		AllowedClients: s.AllowedClients,
		OnTCP:          s.OnTCP,
		OnTCPForward:   s.OnTCPForward,
		ServedTCPPorts: s.ServedTCPPorts,
	}, logf)
	if err != nil {
		return err
	}
	s.core = core
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	cleanup := func() {
		cancel()
		if s.directHTTP != nil {
			_ = s.directHTTP.Close()
		}
		if s.directPC != nil {
			_ = s.directPC.Close()
		}
		if s.relayPath != nil {
			_ = s.relayPath.Close()
		}
		_ = core.Close()
		s.cancel = nil
		s.directHTTP = nil
		s.directPC = nil
		s.relayPath = nil
		s.core = nil
		s.blob = ""
	}

	local := priv.Public()
	if s.DirectURL != "" {
		pc, err := net.ListenPacket("udp", s.DirectListen)
		if err != nil {
			cleanup()
			return fmt.Errorf("listen for direct MASQUE: %w", err)
		}
		handler := directMasqueCoreHandler(priv, core, logf)
		h2Addr, err := masqueHTTP2CompanionAddr(s.DirectListen, pc.LocalAddr())
		if err != nil {
			_ = pc.Close()
			cleanup()
			return fmt.Errorf("derive direct HTTP/2 MASQUE listen address: %w", err)
		}
		if err := startMasqueHTTP2(ctx, h2Addr, s.DirectTLSConfig, handler, logf); err != nil {
			_ = pc.Close()
			cleanup()
			return fmt.Errorf("start direct HTTP/2 MASQUE: %w", err)
		}
		conf := http3.ConfigureTLSConfig(s.DirectTLSConfig.Clone())
		conf.MinVersion = tls.VersionTLS13
		h3 := &http3.Server{
			TLSConfig:       conf,
			Handler:         handler,
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
		path, err := newMasquePathWithFallback(ctx, s.RelayURL, local, priv, masqueModeRelay, s.InsecureSkipVerify, logf)
		if err != nil {
			cleanup()
			return fmt.Errorf("connect MASQUE relay: %w", err)
		}
		s.relayPath = path
		go func() {
			err := path.run(ctx, local, func(src key.NodePublic, payload []byte) error {
				if err := core.SetPath(src, path); err != nil {
					logf("dropping relay packet from rejected peer %v: %v", src.ShortString(), err)
					return nil
				}
				return core.Inject(src, payload)
			})
			if err != nil && ctx.Err() == nil {
				logf("MASQUE relay receive loop stopped: %v", err)
			}
		}()
	}

	// ServerDiscoPublic remains in v1 tokens for backward token-format
	// compatibility only. MasqueServer never creates or transmits disco traffic.
	blob, err := (MasqueConnInfo{
		Version:           1,
		ServerPublic:      local,
		ServerDiscoPublic: DiscoPublicForNode(priv).DiscoPublic,
		DirectURL:         s.DirectURL,
		RelayURL:          s.RelayURL,
		AutomaticDirect:   s.AutomaticDirect,
	}).ConnBlob()
	if err != nil {
		cleanup()
		return err
	}
	s.blob = blob
	return nil
}

// AddAllowedClient adds k to the admission policy used by both future starts
// and the currently running MASQUE core. This intentionally overrides the
// promoted Server method: MasqueServer never initializes the legacy Server.lb.
func (s *MasqueServer) AddAllowedClient(k key.NodePublic) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Server.AddAllowedClient(k)
	if s.core != nil {
		s.core.AddAllowedClient(k)
	}
}

func (s *MasqueServer) ConnBlob() MasqueConnBlob {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blob
}

func (s *MasqueServer) Addr() netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.core == nil {
		if !s.Key.IsZero() {
			return tcAddrForKey(s.Key.Public())
		}
		return netip.Addr{}
	}
	return s.core.Addr()
}

func (s *MasqueServer) Status() *ipnstate.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.core == nil {
		return nil
	}
	return s.core.Status()
}

func (s *MasqueServer) DrainTCP(ctx context.Context) error {
	s.mu.Lock()
	core := s.core
	s.mu.Unlock()
	if core == nil {
		return nil
	}
	return core.DrainTCP(ctx)
}

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
	if s.core != nil {
		errs = append(errs, s.core.Close())
		s.core = nil
	}
	s.blob = ""
	return errors.Join(errs...)
}

// MasqueClient is the Tailcat client-facing API with deterministic MASQUE path
// selection. Its WireGuard device uses masqueBind directly; no Tailscale
// networking engine is initialized.
type MasqueClient struct {
	Server MasqueConnBlob
	Key    key.NodePrivate
	Logf   logger.Logf

	InsecureSkipVerify bool

	mu           sync.Mutex
	activeOps    sync.WaitGroup
	core         *masqueCore
	serverPublic key.NodePublic
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

// masqueDialContext makes an in-flight CONNECT-UDP establishment cancelable by
// the caller without letting that one-shot operation context own the established
// transport. Calling finish(true) detaches the caller and leaves lifecycleCtx
// as the owner of the transport.
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

	childCtx, cancel := context.WithCancel(context.Background())
	local := priv.Public()
	insecureSkipVerify := c.InsecureSkipVerify || ci.AutomaticDirect
	dialPath := func(rawURL string, target key.NodePublic, mode string) (*masquePath, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dialCtx, finishDial := masqueDialContext(childCtx, ctx)
		p, err := newMasquePathWithFallback(dialCtx, rawURL, target, priv, mode, insecureSkipVerify, logf)
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
			if directErr != nil {
				return errors.Join(fmt.Errorf("direct MASQUE: %w", directErr), fmt.Errorf("relay MASQUE: %w", err))
			}
			return fmt.Errorf("relay MASQUE: %w", err)
		}
		pathType = MasquePathRelay
	}
	if path == nil {
		cancel()
		if directErr != nil {
			return fmt.Errorf("direct MASQUE: %w", directErr)
		}
		return errors.New("no usable MASQUE path")
	}

	core, err := newMasqueCore(priv, masqueCoreOptions{}, logf)
	if err != nil {
		cancel()
		_ = path.Close()
		return err
	}
	if err := core.SetPath(ci.ServerPublic, path); err != nil {
		cancel()
		_ = path.Close()
		_ = core.Close()
		return err
	}

	c.lifecycleCtx = childCtx
	c.cancel = cancel
	c.core = core
	c.serverPublic = ci.ServerPublic
	c.path = path
	c.pathType = pathType
	c.started = true
	go func() {
		err := path.run(childCtx, local, func(src key.NodePublic, payload []byte) error {
			if src != ci.ServerPublic {
				logf("dropping MASQUE packet from unexpected peer %v", src.ShortString())
				return nil
			}
			return core.Inject(src, payload)
		})
		if err != nil && childCtx.Err() == nil {
			logf("MASQUE receive loop stopped: %v", err)
		}
	}()
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

func (c *MasqueClient) acquireCore(ctx context.Context) (*masqueCore, key.NodePublic, context.Context, func(), error) {
	if err := c.ensureStarted(ctx); err != nil {
		return nil, key.NodePublic{}, nil, nil, err
	}
	c.mu.Lock()
	if c.core == nil || c.lifecycleCtx == nil || !c.started {
		c.mu.Unlock()
		return nil, key.NodePublic{}, nil, nil, errors.New("masquecat: client closed during startup")
	}
	core := c.core
	server := c.serverPublic
	lifecycleCtx := c.lifecycleCtx
	c.activeOps.Add(1)
	c.mu.Unlock()

	opCtx, stopContext := masqueOperationContext(ctx, lifecycleCtx)
	release := func() {
		stopContext()
		c.activeOps.Done()
	}
	return core, server, opCtx, release, nil
}

func (c *MasqueClient) Ping(ctx context.Context) (PingResult, error) {
	core, server, opCtx, release, err := c.acquireCore(ctx)
	if err != nil {
		return PingResult{}, err
	}
	defer release()
	return core.Ping(opCtx, server)
}

func (c *MasqueClient) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	core, _, opCtx, release, err := c.acquireCore(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return core.Dial(opCtx, network, addr)
}

func (c *MasqueClient) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	core, server, opCtx, release, err := c.acquireCore(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return core.DialTCP(opCtx, netip.AddrPortFrom(tcAddrForKey(server), port))
}

func (c *MasqueClient) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	core, _, opCtx, release, err := c.acquireCore(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return core.DialTCP(opCtx, dst)
}

func (c *MasqueClient) DrainTCP(ctx context.Context) error {
	core, _, opCtx, release, err := c.acquireCore(ctx)
	if err != nil {
		return err
	}
	defer release()
	return core.DrainTCP(opCtx)
}

func (c *MasqueClient) Status() *ipnstate.Status {
	c.mu.Lock()
	if c.core == nil {
		c.mu.Unlock()
		return nil
	}
	core := c.core
	c.activeOps.Add(1)
	c.mu.Unlock()
	defer c.activeOps.Done()
	return core.Status()
}

func (c *MasqueClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	if c.core != nil {
		errs = append(errs, c.core.Close())
		c.core = nil
	}
	c.lifecycleCtx = nil
	c.serverPublic = key.NodePublic{}
	c.pathType = ""
	c.started = false
	return errors.Join(errs...)
}
