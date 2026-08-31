# MasqueCat

MasqueCat is an experimental fork of Tailcat that keeps the useful userspace
WireGuard + gVisor netstack model while replacing the externally visible
DERP/STUN/disco/raw-peer-UDP transport with explicit HTTP/3 MASQUE
CONNECT-UDP paths.

The design goal is a small remote-access tool with a Tailcat-like experience:

```text
application / SSH / forwarded TCP
              |
        gVisor netstack
              |
     WireGuard end-to-end
              |
      wgengine / magicsock
              |
  loopback-only compatibility bridge
              |
      MasqueCat datagram framing
              |
      HTTP/3 CONNECT-UDP
              |
        QUIC / UDP 443
        /           \
 direct MASQUE     MasqueCat relay
 endpoint          endpoint
```

## No built-in infrastructure

MasqueCat deliberately has **no built-in public relay, map service, control
plane, or default external hostname**.

Every Internet-facing endpoint is operator supplied:

- `DirectURL` is an explicitly advertised peer MASQUE endpoint.
- `RelayURL` is an explicitly configured MasqueCat relay.
- relay-only deployments require only outbound UDP/443 from both peers.
- direct deployments require an explicitly reachable QUIC/UDP endpoint.

There is no automatic fallback to an upstream relay or map service.

MasqueCat also does not use external STUN discovery, CallMeMaybe endpoint
exchange, UDP hole punching, candidate probing, or a raw peer WireGuard path.
Direct mode means **WireGuard-over-MASQUE directly to the peer**, not raw
WireGuard over UDP.

## Path selection

MasqueCat currently uses deterministic startup-time selection:

```text
DirectURL configured?
    |
    +-- yes --> try that exact MASQUE endpoint once
    |              |
    |              +-- success --> direct-masque
    |              |
    |              +-- failure --+
    |                            |
    +-- no ----------------------+--> RelayURL configured?
                                      |
                                      +-- yes --> relay-masque
                                      |
                                      +-- no --> fail
```

No alternate peer addresses are discovered or probed.

## Deployment modes

| Mode | Server inbound requirement | Client behavior |
| --- | --- | --- |
| Relay-only | none | both peers make outbound QUIC/UDP 443 connections to the relay |
| Direct-only | reachable QUIC/UDP endpoint with a valid TLS certificate | client connects directly with HTTP/3 CONNECT-UDP |
| Direct + relay | direct endpoint plus outbound relay access | client tries the configured direct endpoint, then uses the relay if startup fails |

For the detailed architecture, TLS requirements, firewall rules, systemd relay
example, Go API examples, trust boundaries, and current limitations, see
[`docs/masquecat.md`](./docs/masquecat.md).

## Build

This branch is still experimental and is not represented by an existing release
artifact.

```sh
git clone https://github.com/knowlet/tailcat.git
cd tailcat
git checkout feat/masquecat-masque-transport

go build ./cmd/masquecat-relay
```

The full client CLI integration is still in progress. The current MasqueCat
server/client data path is exposed through the Go API (`MasqueServer` and
`MasqueClient`), while `cmd/masquecat-relay` is directly runnable.

## Relay deployment

A relay terminates HTTP/3 itself. Give it a public DNS name, a trusted TLS
certificate, and inbound UDP/443.

```sh
sudo ./masquecat-relay \
  -listen :443 \
  -cert /etc/masquecat/tls/fullchain.pem \
  -key /etc/masquecat/tls/privkey.pem
```

A TCP-only HTTP/1.1 or HTTP/2 reverse proxy is not sufficient. A
QUIC/UDP-capable pass-through load balancer is fine.

In relay-only mode the protected machine does not need an inbound Internet
port; both the client and server only initiate outbound QUIC connections to the
relay.

## Direct deployment

A server with a reachable UDP endpoint can advertise a direct MASQUE listener.
For example, conceptually:

```go
cert, err := tls.LoadX509KeyPair("fullchain.pem", "privkey.pem")
if err != nil {
    log.Fatal(err)
}

s := &tailcat.MasqueServer{
    Server: tailcat.Server{
        OnTCP: myTCPHandler,
    },
    DirectListen: ":443",
    DirectURL:    "https://mc.example.com",
    DirectTLSConfig: &tls.Config{
        Certificates: []tls.Certificate{cert},
    },
    RelayURL: "https://relay.example.com", // optional fallback
}
```

MasqueCat will never try to derive a public endpoint with STUN. If the server is
behind NAT, configure a static UDP port-forward or use relay mode.

## Relay-only Go example

```go
package main

import (
    "fmt"
    "log"
    "net"

    tailcat "github.com/tailscale/tailcat"
)

func main() {
    s := &tailcat.MasqueServer{
        Server: tailcat.Server{
            OnTCP: func(port uint16) func(net.Conn) {
                if port != 22 {
                    return nil
                }
                return func(tunnel net.Conn) {
                    local, err := net.Dial("tcp", "127.0.0.1:22")
                    if err != nil {
                        _ = tunnel.Close()
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

Client:

```go
c := tailcat.NewMasqueClient(tailcat.MasqueConnBlob(token))
defer c.Close()

conn, err := c.DialTCPPort(context.Background(), 22)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()
```

## Security model

There are two cryptographic layers:

1. WireGuard protects the inner tunnel end-to-end between MasqueCat peers.
2. QUIC/TLS 1.3 protects each HTTP/3 transport hop.

On a relay path, the relay terminates the outer QUIC/TLS connection but receives
already encrypted WireGuard payloads. A relay can still observe connection
source addresses, registered peer keys used for routing, packet sizes, timing,
and traffic volume.

The first relay implementation is **not yet production hardened**. In
particular, transport-level peer registration still needs cryptographic
proof-of-possession, resource quotas, abuse controls, and production metrics.
WireGuard still authenticates the inner peer session.

## What MasqueCat is not

MasqueCat uses a standardized HTTP/3 transport. It does not claim to be
undetectable, anonymous, or resistant to traffic analysis. It does not implement
browser fingerprint cloning, domain fronting, TLS fingerprint mutation, traffic
morphing, or active-probing countermeasures.

## Current implementation status

Implemented in this branch:

- `mc...` connection tokens with explicit direct and/or relay URLs
- HTTP/3 CONNECT-UDP transport with QUIC DATAGRAM
- direct MASQUE peer path
- paired MasqueCat relay
- direct-first, relay-fallback startup selection
- end-to-end WireGuard carried inside MASQUE
- loopback-only compatibility bridge for the reused userspace networking engine
- suppression of the reused engine's external STUN/UDP discovery in MasqueCat mode
- dropping legacy disco/CallMeMaybe packets at the MASQUE boundary

Still required before merge-ready / production-ready:

- complete `mc...` CLI integration (`serve`, `ssh`, `ping`, `parse`, saved keys)
- relay registration proof-of-possession
- direct and relay WireGuard/TCP/SSH E2E tests
- reconnect and runtime direct-to-relay failover
- MTU / fragmentation validation
- relay limits, health endpoint, structured metrics, and abuse protection
- Linux/macOS/Windows build and test validation

## Upstream code reuse

MasqueCat is intentionally being developed as an in-place Tailcat fork, so the
current branch still reuses upstream open-source networking packages at compile
time. That source-level dependency is distinct from runtime infrastructure:
MasqueCat's transport configuration has no built-in external service endpoint.

Removing the upstream networking module itself would require replacing the
current wgengine/netstack integration with a standalone WireGuard + gVisor
implementation and is tracked as a separate architectural migration rather than
being hidden behind a hostname change.

## License and attribution

This fork retains the upstream BSD-3-Clause licensing and copyright notices.
See [`LICENSE`](./LICENSE).
