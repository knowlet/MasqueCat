# MasqueCat architecture and deployment

MasqueCat is an experimental transport mode built on top of Tailcat's existing
userspace WireGuard and gVisor netstack. It replaces Tailcat's externally visible
DERP/STUN/disco/direct-WireGuard transport behavior with explicit
[MASQUE CONNECT-UDP](https://www.rfc-editor.org/rfc/rfc9298) sessions over
HTTP/3 and QUIC.

MasqueCat is intentionally an **in-place extension of Tailcat**, not a second VPN
implementation. The application-facing TCP behavior, WireGuard peer encryption,
and userspace netstack remain Tailcat. The part that changes is how encrypted
WireGuard datagrams leave the process.

> [!IMPORTANT]
> MasqueCat is experimental in this branch. The `mc...` token format, Go API,
> relay protocol, and deployment model may change. The existing `tailcat` CLI
> still primarily implements the original `tc...` Tailcat flow; the MasqueCat
> server/client path is currently exposed through the Go API, while
> `cmd/masquecat-relay` is directly runnable.

## Why MasqueCat exists

Normal Tailcat intentionally inherits Tailscale data-plane behavior:

```text
application
    |
gVisor netstack
    |
WireGuard
    |
magicsock
    |------------------------|
    |                        |
direct UDP               DERP relay
(STUN/disco/hole punch)   (HTTPS/TCP)
```

That is excellent for connectivity, but it produces the same broad transport
families a network observer would expect from Tailscale: STUN, disco/path
probing, direct WireGuard-like UDP flows, and DERP.

MasqueCat keeps WireGuard as the end-to-end security layer but deliberately
constrains the **external carrier** to configured MASQUE endpoints:

```text
application / SSH / forwarded TCP
              |
        gVisor netstack
              |
     WireGuard end-to-end
              |
      wgengine / magicsock
              |
  loopback-only DERP compatibility bridge
              |
      MasqueCat datagram framing
              |
      HTTP/3 CONNECT-UDP
              |
          QUIC / UDP
              |
          UDP port 443
        /             \
explicit direct       MasqueCat relay
MASQUE endpoint       MASQUE endpoint
```

The loopback DERP component is an implementation adapter only. It lets
MasqueCat reuse Tailcat's existing `wgengine`, WireGuard device, peer mapping,
and netstack without exposing DERP on the network.

## External network behavior

When the MasqueCat APIs are used:

- magicsock is put into `SetOnlyTCP443(true)` mode before the network is marked
  up, suppressing its own UDP/STUN discovery behavior;
- the only intended Internet-facing data path is MasqueCat's independent QUIC
  socket using HTTP/3 CONNECT-UDP;
- Tailscale disco / CallMeMaybe packets are discarded at the MASQUE boundary and
  are not forwarded onto the external path;
- no discovered NAT candidate is put into an `mc...` token;
- direct connectivity is attempted only when an explicit `DirectURL` was
  configured by the server;
- relay connectivity is attempted only when an explicit `RelayURL` was
  configured.

This is a transport-shaping goal, **not an anonymity guarantee**. A passive
observer can still see QUIC/UDP traffic, destination IPs, packet sizes, timing,
and usually the DNS name used to reach an endpoint. MasqueCat does not attempt
browser fingerprint cloning, padding, traffic morphing, domain fronting, ECH,
or resistance to active probing.

## Encryption and trust boundaries

There are two encryption layers on an external MasqueCat path:

1. **WireGuard** encrypts the actual Tailcat tunnel traffic end-to-end between
   the MasqueCat client and server.
2. **QUIC/TLS 1.3** protects the outer HTTP/3 session between a peer and the
   direct endpoint or relay.

For a relay path, TLS terminates at the relay, but the relay only receives an
already encrypted WireGuard payload. The relay can observe routing metadata and
traffic metadata, but it cannot decrypt the inner WireGuard session.

The current relay protocol carries the source and destination Tailcat node
public keys so the relay can pair sessions. Therefore a relay operator can
observe, at minimum:

- source network address of each QUIC connection;
- the registered Tailcat node public key for each connection;
- source/destination node public keys on forwarded MasqueCat datagrams;
- packet sizes, timing, lifetime, and traffic volume.

It cannot recover application plaintext from those datagrams without also
breaking the end-to-end WireGuard session.

> [!WARNING]
> The current first-cut relay registration checks that the declared source key
> matches the key in the CONNECT-UDP target/header, but it does **not yet perform
> a cryptographic proof-of-possession challenge for that node key at the MASQUE
> registration layer**. WireGuard still authenticates the actual tunnel, but a
> hardened public relay should add registration PoP to prevent node-key slot
> hijacking / denial-of-service. Treat `cmd/masquecat-relay` as experimental
> until that is implemented.

## Connection tokens

MasqueCat uses a distinct `mc...` token. It is deliberately not compatible with
Tailcat's `tc...` token.

An `mc...` token contains:

- protocol version;
- server WireGuard/Tailcat node public key;
- server disco public key, retained for compatibility with the reused Tailcat
  engine;
- optional `DirectURL`;
- optional `RelayURL`.

At least one path URL is required. URLs must use `https://` and may not contain
userinfo, query strings, or fragments.

Unlike a normal Tailcat token, an `mc...` token contains no DERP region and no
STUN-discovered endpoint candidates.

## Path selection

`MasqueClient` currently performs deterministic startup-time path selection:

```text
DirectURL configured?
    |
    +-- yes --> try direct MASQUE once
    |              |
    |              +-- success --> use direct-masque
    |              |
    |              +-- failure --+
    |                            |
    +-- no ----------------------+--> RelayURL configured?
                                      |
                                      +-- yes --> connect relay-masque
                                      |
                                      +-- no --> fail startup
```

There is currently no continuous path racing, STUN candidate search, automatic
path migration, or reconnect/failover after the selected MASQUE session later
dies. Those are separate reliability features that can be added without
reintroducing external disco/STUN behavior.

`MasqueClient.Path()` reports the selected path as `direct-masque` or
`relay-masque` after startup.

## Deployment patterns

### Relay-only

Use relay-only when the MasqueCat server should require **no inbound Internet
port**.

```text
client -- outbound UDP/443 --> relay <-- outbound UDP/443 -- server
            \_____________________________________________/
                         WireGuard E2E
```

Configure the server with only:

```go
RelayURL: "https://relay.example.com"
```

The resulting token contains only the relay URL. Both peers establish outbound
QUIC sessions to the relay.

This is the simplest topology for machines behind NAT, CGNAT, or firewalls where
opening UDP/443 on the MasqueCat server is not possible.

### Direct-only

Use direct-only when the server has a stable, reachable UDP endpoint and you do
not want a relay fallback.

```text
client -- QUIC / UDP 443 --> server
           HTTP/3 CONNECT-UDP
           WireGuard inside
```

The server needs:

- a DNS name such as `mc.example.com`;
- a publicly trusted TLS certificate for that name;
- inbound UDP/443 (or another explicitly encoded port) reaching the
  `MasqueServer` process;
- `DirectListen`, `DirectURL`, and `DirectTLSConfig` configured.

MasqueCat direct mode does **not** perform NAT hole punching. If the server sits
behind NAT, configure a static UDP port-forward or a UDP/QUIC-capable load
balancer. A normal TCP-only HTTP reverse proxy is not sufficient.

### Direct with relay fallback

Configure both URLs to get an explicit direct attempt with a relay fallback:

```go
DirectURL: "https://mc.example.com",
RelayURL:  "https://relay.example.com",
```

The client tries the direct endpoint once. If establishing the direct
CONNECT-UDP session fails, it connects to the relay. This preserves predictable
network behavior: MasqueCat does not probe arbitrary candidates to find a path.

## Network requirements

| Component | Inbound | Outbound | Notes |
| --- | --- | --- | --- |
| Relay-only client | none | UDP/443 to relay | QUIC + HTTP/3 |
| Relay-only server | none | UDP/443 to relay | No public listener required |
| Direct MasqueCat server | UDP/443 | normal application egress; UDP/443 to relay if configured | Needs reachable DNS/TLS endpoint |
| MasqueCat relay | UDP/443 | responses on established QUIC sessions | Does not proxy to arbitrary UDP targets |

Port 443 is conventional, not hard-coded into the URL parser. A development
endpoint can use `https://relay.example.com:8443`, but clients must be able to
send UDP to that port.

There is currently **no HTTP/2 or TCP fallback** for a network that blocks QUIC
or UDP/443.

## TLS requirements

MasqueCat's external transport is HTTP/3, so TLS 1.3 is used by QUIC.

The current client uses the operating system's normal root trust and verifies
the endpoint hostname from `DirectURL` / `RelayURL`. Consequently:

- a publicly trusted certificate is the easiest production setup;
- an internal CA works only if that CA is already trusted by the host OS;
- an arbitrary self-signed certificate will fail verification unless its CA is
  installed in the host trust store;
- an IP-literal URL needs a certificate whose SAN matches that IP.

Custom per-client root CA configuration is not exposed by the first-cut
`MasqueClient` API yet.

## Build from this branch

MasqueCat is not part of an existing Tailcat release artifact yet. Build the PR
branch from source:

```sh
git clone https://github.com/knowlet/tailcat.git
cd tailcat
git checkout feat/masquecat-masque-transport

go build ./cmd/masquecat-relay
```

The repository still declares the upstream module path
`github.com/tailscale/tailcat`, so code built *inside this checkout* imports the
package with that module path. Until the fork/module naming strategy is decided,
external projects should use a local `replace` to this checkout rather than
assuming `github.com/knowlet/tailcat` is a valid Go module import path.

Example:

```go
replace github.com/tailscale/tailcat => ../tailcat
```

## Deploy the relay

### 1. DNS and firewall

Point a hostname at the relay host:

```text
relay.example.com  A     203.0.113.10
relay.example.com  AAAA  2001:db8::10   # optional
```

Permit inbound UDP/443 in both the host firewall and cloud security group.
For example, with UFW:

```sh
sudo ufw allow 443/udp
```

No inbound TCP/443 listener is created by `masquecat-relay` itself.

### 2. Obtain a certificate

Use a normal ACME client / internal PKI and provide PEM files containing the
certificate chain and private key. For example, after obtaining a certificate
for `relay.example.com`:

```text
/etc/letsencrypt/live/relay.example.com/fullchain.pem
/etc/letsencrypt/live/relay.example.com/privkey.pem
```

### 3. Start the relay

```sh
sudo ./masquecat-relay \
  -listen :443 \
  -cert /etc/letsencrypt/live/relay.example.com/fullchain.pem \
  -key /etc/letsencrypt/live/relay.example.com/privkey.pem
```

For a non-privileged development port:

```sh
./masquecat-relay \
  -listen :8443 \
  -cert ./cert.pem \
  -key ./key.pem
```

and use `https://relay.example.com:8443` as `RelayURL`.

### systemd example

A minimal service using UDP/443 can be run under a dedicated account while
allowing only the capability required to bind a privileged port:

```ini
[Unit]
Description=MasqueCat CONNECT-UDP relay
After=network-online.target
Wants=network-online.target

[Service]
User=masquecat
Group=masquecat
ExecStart=/usr/local/bin/masquecat-relay \
  -listen :443 \
  -cert /etc/masquecat/tls/fullchain.pem \
  -key /etc/masquecat/tls/privkey.pem
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths=/etc/masquecat/tls

[Install]
WantedBy=multi-user.target
```

Store readable certificate copies under `/etc/masquecat/tls` or otherwise make
sure the service account can follow/read your ACME client's certificate files.
Reload the service after certificate renewal unless a later relay version adds
live certificate reload support.

## Run a MasqueCat server with the Go API

The following example exposes a local TCP service on port 8080 through a
relay-only MasqueCat tunnel. The server itself needs no inbound public port.

```go
package main

import (
	"fmt"
	"log"
	"net"

	"github.com/tailscale/tailcat"
)

func main() {
	s := &tailcat.MasqueServer{
		Server: tailcat.Server{
			ServedTCPPorts: nil,
			OnTCP: func(port uint16) func(net.Conn) {
				if port != 8080 {
					return nil
				}
				return func(tunnel net.Conn) {
					local, err := net.Dial("tcp", "127.0.0.1:8080")
					if err != nil {
						tunnel.Close()
						return
					}
					tailcat.ProxyConns(tunnel, local)
				}
			},
		},
		RelayURL: "https://relay.example.com",
	}
	if err := s.Start(); err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	fmt.Println(s.ConnBlob()) // mc...
	select {}
}
```

For a direct endpoint, load a TLS certificate and add the direct configuration:

```go
cert, err := tls.LoadX509KeyPair("fullchain.pem", "privkey.pem")
if err != nil {
	log.Fatal(err)
}

s.DirectListen = ":443"
s.DirectURL = "https://mc.example.com"
s.DirectTLSConfig = &tls.Config{
	Certificates: []tls.Certificate{cert},
}
```

You may configure both the direct endpoint and `RelayURL` on the same server.

### Restrict client node keys

`MasqueServer` embeds the normal Tailcat `Server`, so the existing
`AllowedClients` admission control still applies:

```go
s.Server.AllowedClients = []key.NodePublic{allowedClientKey}
```

The allowlist is checked when the inner Tailcat/WireGuard peer is admitted. It
is separate from the relay's current transport-level registration behavior.

## Connect with the Go API

Given an `mc...` token printed by `MasqueServer.ConnBlob()`:

```go
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/tailscale/tailcat"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: client mcTOKEN")
	}
	c := tailcat.NewMasqueClient(tailcat.MasqueConnBlob(os.Args[1]))
	defer c.Close()

	ctx := context.Background()
	conn, err := c.DialTCPPort(ctx, 8080)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(os.Stderr, "path: %s\n", c.Path())
	_, _ = io.Copy(os.Stdout, conn)
}
```

The same client also exposes `Dial`, `DialTCP`, `Ping`, `DrainTCP`, `Status`,
`PublicKey`, and `Close` analogously to Tailcat's client API.

## What a relay does and does not do

`MasqueRelay` is not a generic RFC 9298 open UDP proxy. The CONNECT-UDP target
is a synthetic MasqueCat node-key address such as:

```text
<node-public-key>.peer.masquecat.invalid:1
```

A relay registers the HTTP/3 stream under that node key and forwards only
MasqueCat-framed datagrams whose destination is another currently registered
node key. It never resolves that synthetic hostname and never opens an arbitrary
UDP socket to the requested target.

This distinction is important operationally: exposing `masquecat-relay` does
not intentionally create a general-purpose UDP forwarding service.

## What remains local-only

The compatibility DERP server is created with an ephemeral TLS certificate and
bound to loopback. `wgengine` talks to that adapter because Tailcat currently
constructs the WireGuard bind through magicsock. MASQUE packets entering from a
peer are injected back through the adapter with the original Tailcat node key so
the existing engine receives the same peer identity it expects.

The compatibility adapter is **not** the public relay, is **not** encoded into
the `mc...` token, and is not intended to be reachable from another machine.

## Operational visibility

Useful current log events include:

- `direct MASQUE peer connected`;
- `MASQUE relay peer registered`;
- direct / relay receive-loop failures;
- malformed or identity-mismatched datagram drops;
- the selected path through `MasqueClient.Path()`.

Prometheus-style relay metrics, structured connection counters, health probes,
and explicit path-failover telemetry are not implemented in this first slice.

## Current limitations

The first implementation intentionally keeps scope narrow. Before calling it a
production transport, at least the following should be addressed:

- cryptographic proof of possession for relay registration;
- automatic reconnect and direct/relay failover after startup;
- end-to-end direct and relay tests with real WireGuard/TCP traffic;
- complete `mc...` integration into the `tailcat` CLI, including SSH, serve,
  ping, parse, and saved-key workflows;
- certificate reload / custom trust-root ergonomics;
- relay resource limits, per-peer quotas, abuse protection, and metrics;
- explicit MTU sizing and fragmentation tests for the extra H3/MasqueCat
  encapsulation;
- validation on Linux, macOS, and Windows once CI is running on the fork.

## Comparison with original Tailcat

| Property | Tailcat (`tc...`) | MasqueCat (`mc...`) |
| --- | --- | --- |
| Inner encryption | WireGuard | WireGuard |
| Userspace TCP/IP | gVisor netstack | gVisor netstack |
| External relay | DERP | MasqueCat CONNECT-UDP relay |
| Direct path | raw peer UDP selected by magicsock | explicit direct HTTP/3 CONNECT-UDP endpoint |
| STUN | yes | suppressed on MasqueCat external path |
| CallMeMaybe/disco | used for direct-path discovery | retained internally but dropped at MASQUE boundary |
| NAT hole punching | yes | no |
| Server inbound port in relay-only mode | no | no |
| Direct server requirement | reachable peer UDP endpoint | reachable QUIC/UDP endpoint with TLS cert |
| External carrier | DERP and/or peer UDP | QUIC / HTTP/3 / CONNECT-UDP |
| Token path data | DERP region/node data | explicit direct and/or relay HTTPS URLs |

The intent is not to replace normal Tailcat for every environment. Tailcat's
STUN/disco behavior provides better automatic NAT traversal. MasqueCat trades
that automatic path discovery for a smaller, explicit set of externally visible
transport behaviors and a deployment model controlled by the operator.
