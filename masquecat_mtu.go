package tailcat

import "gvisor.dev/gvisor/pkg/tcpip"

// browserMasqueNIC is the gVisor NIC ID for the browser (js/wasm) stack.
// Shared with native tests (see browserMasqueMTU).
const browserMasqueNIC tcpip.NICID = 1

// browserMasqueQueueSize is the gVisor channel endpoint queue depth for the
// browser (js/wasm) stack. Shared with native tests.
const browserMasqueQueueSize = 512

// browserMasqueMTU is the gVisor NIC/TUN MTU for the browser (js/wasm)
// stack. It lives in this untagged file (instead of
// masquecat_browser_js.go) so native regression tests can reference the
// exact value the browser build uses.
//
// It must be >= 1280 (IPv6 minimum link MTU, RFC 8200): gVisor's
// calculateNetworkMTU rejects every IPv6 packet with
// ErrInvalidEndpointState when the link MTU is smaller. A smaller value
// here once surfaced as "ping: context deadline exceeded" with zero
// datagrams ever leaving the browser. Small WebTransport datagrams are
// ensured by browserFragmentChunkSize, not by this MTU.
const browserMasqueMTU = 1280
