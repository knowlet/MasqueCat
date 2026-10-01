//go:build !js

package tailcat

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"tailscale.com/types/key"
)

// TestBrowserStackEmitsIPv6 is a regression test for the browser
// "ping: context deadline exceeded" failure. The browser (js/wasm) stack
// once used an MTU of 1000, below the IPv6 minimum link MTU of 1280
// (RFC 8200); gVisor's calculateNetworkMTU then rejected every outbound
// IPv6 packet with ErrInvalidEndpointState, so zero datagrams ever left
// the browser while WebTransport registration itself succeeded.
//
// The test rebuilds the browser-equivalent gVisor stack natively (the
// js-tagged browser core cannot run under go test) using the exact
// browserMasqueMTU value, then verifies a TCP SYN is actually emitted.
// There is no peer, so the dial itself is expected to time out; the
// assertion is on the stack counters.
func TestBrowserStackEmitsIPv6(t *testing.T) {
	if browserMasqueMTU < 1280 {
		t.Fatalf("browserMasqueMTU = %d, must be >= 1280 (IPv6 minimum link MTU)", browserMasqueMTU)
	}
	priv := key.NewNode()
	pub := priv.Public()
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	link := channel.New(browserMasqueQueueSize, uint32(browserMasqueMTU), "")
	if err := st.CreateNIC(browserMasqueNIC, link); err != nil {
		t.Fatal(err)
	}
	if err := st.SetPromiscuousMode(browserMasqueNIC, true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSpoofing(browserMasqueNIC, true); err != nil {
		t.Fatal(err)
	}
	v4, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 4)), tcpip.MaskFromBytes(make([]byte, 4)))
	v6, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 16)), tcpip.MaskFromBytes(make([]byte, 16)))
	st.SetRouteTable([]tcpip.Route{{Destination: v4, NIC: browserMasqueNIC}, {Destination: v6, NIC: browserMasqueNIC}})
	addr := tcAddrForKey(pub)
	if err := st.AddProtocolAddress(browserMasqueNIC, tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr.AsSlice()),
			PrefixLen: addr.BitLen(),
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}

	pingAddr := netip.MustParseAddr("fd00:7461:696c:6361:7400:7069:6e67:1")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, st, tcpip.FullAddress{
		NIC:  browserMasqueNIC,
		Addr: tcpip.AddrFromSlice(pingAddr.AsSlice()),
		Port: 65535,
	}, ipv6.ProtocolNumber)
	if err == nil {
		conn.Close()
	}
	s := st.Stats()
	t.Logf("dial err=%v ipSent=%d ipOutErr=%d tcpSegsSent=%d tcpSegSendErr=%d",
		err, s.IP.PacketsSent.Value(), s.IP.OutgoingPacketErrors.Value(),
		s.TCP.SegmentsSent.Value(), s.TCP.SegmentSendErrors.Value())
	if got := s.IP.OutgoingPacketErrors.Value(); got != 0 {
		t.Fatalf("IP.OutgoingPacketErrors = %d, want 0 (SYN never left the stack)", got)
	}
	if got := s.TCP.SegmentsSent.Value(); got == 0 {
		t.Fatalf("TCP.SegmentsSent = 0, want > 0 (no SYN emitted)")
	}
}
