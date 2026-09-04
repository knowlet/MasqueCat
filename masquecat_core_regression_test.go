//go:build !js

package tailcat

import (
	"context"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"tailscale.com/types/key"
)

func TestMasqueTCPStateNeedsDrain(t *testing.T) {
	tests := []struct {
		name string
		state tcp.EndpointState
		want bool
	}{
		{"connecting", tcp.StateConnecting, true},
		{"syn-sent", tcp.StateSynSent, true},
		{"syn-recv", tcp.StateSynRecv, true},
		{"established", tcp.StateEstablished, true},
		{"fin-wait-1", tcp.StateFinWait1, true},
		{"fin-wait-2", tcp.StateFinWait2, true},
		{"closing", tcp.StateClosing, true},
		{"close-wait", tcp.StateCloseWait, true},
		{"last-ack", tcp.StateLastAck, true},
		{"time-wait", tcp.StateTimeWait, false},
		{"listen", tcp.StateListen, false},
		{"closed", tcp.StateClose, false},
		{"error", tcp.StateError, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := masqueTCPStateNeedsDrain(tt.state); got != tt.want {
				t.Fatalf("masqueTCPStateNeedsDrain(%v) = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestResolveMasqueTCPAddrsHostname(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := resolveMasqueTCPAddrs(ctx, "tcp", "localhost")
	if err != nil {
		t.Fatalf("resolve localhost: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("resolve localhost returned no addresses")
	}
	for _, ip := range ips {
		if !ip.IsValid() {
			t.Fatalf("resolver returned invalid IP %v", ip)
		}
	}
}

func TestResolveMasqueTCPAddrsRespectsNetworkFamily(t *testing.T) {
	ctx := context.Background()
	if _, err := resolveMasqueTCPAddrs(ctx, "tcp4", "::1"); err == nil {
		t.Fatal("tcp4 unexpectedly accepted IPv6 literal")
	}
	if _, err := resolveMasqueTCPAddrs(ctx, "tcp6", "127.0.0.1"); err == nil {
		t.Fatal("tcp6 unexpectedly accepted IPv4 literal")
	}
}

func TestMasqueCoreStatusIncludesSelfAndPeers(t *testing.T) {
	priv := key.NewNode()
	pub := priv.Public()
	peer := key.NewNode().Public()
	core := &masqueCore{
		pub:   pub,
		addr:  tcAddrForKey(pub),
		peers: map[key.NodePublic]bool{peer: true},
	}

	st := core.Status()
	if st == nil {
		t.Fatal("Status returned nil")
	}
	if st.BackendState != "Running" || !st.HaveNodeKey || st.TUN {
		t.Fatalf("unexpected core status: %+v", st)
	}
	if st.Self == nil || st.Self.PublicKey != pub {
		t.Fatalf("self status = %+v, want key %v", st.Self, pub)
	}
	if len(st.TailscaleIPs) != 1 || st.TailscaleIPs[0] != core.addr {
		t.Fatalf("self IPs = %v, want [%v]", st.TailscaleIPs, core.addr)
	}
	ps := st.Peer[peer]
	if ps == nil || ps.PublicKey != peer || !ps.InEngine {
		t.Fatalf("peer status = %+v, want peer %v in engine", ps, peer)
	}
	wantPeerIP := tcAddrForKey(peer)
	if len(ps.TailscaleIPs) != 1 || ps.TailscaleIPs[0] != wantPeerIP {
		t.Fatalf("peer IPs = %v, want [%v]", ps.TailscaleIPs, wantPeerIP)
	}
}

func TestMasqueClientStatusPreservesCoreStatus(t *testing.T) {
	priv := key.NewNode()
	pub := priv.Public()
	peer := key.NewNode().Public()
	core := &masqueCore{
		pub:   pub,
		addr:  tcAddrForKey(pub),
		peers: map[key.NodePublic]bool{peer: true},
	}
	client := &MasqueClient{core: core}
	st := client.Status()
	if st == nil || st.Self == nil || st.Self.PublicKey != pub || st.Peer[peer] == nil {
		t.Fatalf("MasqueClient.Status lost core status: %+v", st)
	}
}
