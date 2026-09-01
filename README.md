# MasqueCat

MasqueCat is an experimental Tailcat fork that keeps the useful userspace
WireGuard + gVisor model while replacing Tailcat's external
DERP/STUN/disco/raw-peer-UDP transport with explicit HTTP/3 MASQUE
CONNECT-UDP paths.

The MasqueCat runtime data plane is now independent of Tailscale `magicsock`:

```text
application / SSH / forwarded TCP
              |
        gVisor netstack
              |
     wireguard-go Device
              |
          MasqueBind
              |
      MasqueCat framing
              |
      HTTP/3 CONNECT-UDP
              |
        QUIC / UDP 443
        /           \
 direct MASQUE     MasqueCat relay
 endpoint          endpoint
```

`MasqueBind` is a `wireguard-go/conn.Bind` implementation. WireGuard sees each
peer as a logical node-key endpoint; the bind selects an explicit MASQUE path
instead of opening a WireGuard UDP socket or delegating transport to magicsock.

The original Tailcat `tc...` code remains in this repository and still uses the
upstream Tailscale data plane. That legacy implementation is separate from the
MasqueCat `mc...` runtime.

## External network behavior

When `MasqueServer` / `MasqueClient` are used, MasqueCat does **not** initialize:

- `magicsock.Conn`;
- DERP clients or a local DERP compatibility server;
- netcheck;
- STUN discovery;
- Tailscale disco / CallMeMaybe exchange;
- endpoint candidate probing or UDP hole punching;
- a raw peer WireGuard UDP socket.

The intended Internet-facing transport is the independently configured MASQUE
HTTP/3 connection over QUIC/UDP, normally UDP port 443.

This is a transport design, not an anonymity guarantee. A network observer can
still see QUIC traffic, endpoint addresses, packet sizes, timing and connection
lifetimes.

## No built-in infrastructure

MasqueCat deliberately has **no built-in public relay, map service, control
plane, or default external hostname**. Every Internet-facing endpoint is
operator supplied:

- `DirectURL` advertises an explicitly reachable peer MASQUE endpoint.
- `RelayURL` configures an explicit MasqueCat relay.
- relay-only deployments require outbound QUIC/UDP 443 from both peers.
- direct deployments require an explicitly reachable QUIC/UDP endpoint.

There is no fallback to an upstream Tailscale DERP or DERP map.

## Path selection

Startup selection is deterministic:

```text
DirectURL configured?
    |
    +-- yes --> connect that exact MASQUE endpoint
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

No alternate peer addresses are discovered or probed. After a path is selected,
its QUIC connection uses keepalive and reconnects to the same configured
endpoint with capped exponential backoff. Runtime direct-to-relay failover is
not implemented yet.

An important startup property is that `MasqueClient` establishes the outer
CONNECT-UDP carrier before constructing its WireGuard/gVisor core. If QUIC or
TLS establishment fails, the error therefore comes directly from the MASQUE
transport; there is no preceding magicsock/netcheck/DERP startup sequence.

## Deployment modes

| Mode | Server inbound requirement | Client behavior |
| --- | --- | --- |
| Relay-only | none | both peers make outbound QUIC/UDP 443 connections to the relay |
| Direct-only | reachable QUIC/UDP endpoint with a valid TLS certificate | client connects directly with HTTP/3 CONNECT-UDP |
| Direct + relay | direct endpoint plus outbound relay access | client tries the configured direct endpoint, then the relay if startup fails |

## Security model

Application traffic is protected by two layers:

1. WireGuard provides end-to-end encryption between the MasqueCat peers.
2. QUIC/TLS 1.3 protects the outer HTTP/3 connection to the direct endpoint or
   relay.

A relay terminates the outer TLS connection but forwards opaque WireGuard
ciphertext. It can observe peer node keys and traffic metadata but cannot decrypt
the inner WireGuard session.

Direct and relay CONNECT-UDP registration uses a one-time challenge and proof of
possession of the advertised node private key. Duplicate live registrations are
rejected rather than silently replacing the current peer.

`InsecureSkipVerify` exists only for development. Production endpoints should
use normal certificate and hostname verification.

## Go API

### Server

```go
srv := &tailcat.MasqueServer{
    Server: tailcat.Server{
        OnTCP: func(port uint16) func(net.Conn) {
            return func(c net.Conn) {
                defer c.Close()
                // Serve the application protocol.
            }
        },
    },
    RelayURL: "https://relay.example.com",
}

if err := srv.Start(); err != nil {
    log.Fatal(err)
}
defer srv.Close()

fmt.Println(srv.ConnBlob()) // mc...
```

For direct mode, additionally configure `DirectListen`, `DirectURL`, and
`DirectTLSConfig`.

### Client

```go
client := tailcat.NewMasqueClient(token)
defer client.Close()

conn, err := client.DialTCPPort(ctx, 22)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()
```

Useful client operations include `Ping`, `DialTCPPort`, `DialTCP`, `Dial`,
`DrainTCP`, `Path`, and `Close`.

The current generic `Dial` path accepts IP-literal destinations; the primary
peer-service API is `DialTCPPort`.

## Connection tokens

MasqueCat uses a distinct `mc...` token containing:

- protocol version;
- server WireGuard/node public key;
- optional `DirectURL`;
- optional `RelayURL`;
- a legacy disco-public-key field retained in token version 1 for format
  compatibility only.

That legacy token field does not cause the MasqueCat runtime to construct a
disco endpoint or send disco traffic.

At least one MASQUE URL is required. URLs must use `https://` and may not contain
userinfo, query strings, or fragments.

## Relay deployment

`cmd/masquecat-relay` is directly runnable. The relay must terminate HTTP/3
itself and receive UDP/443; a TCP-only HTTP/1.1 or HTTP/2 reverse proxy cannot
carry this protocol.

```sh
go build ./cmd/masquecat-relay

sudo ./masquecat-relay \
  -listen :443 \
  -cert /etc/masquecat/tls/fullchain.pem \
  -key /etc/masquecat/tls/privkey.pem
```

See [`cmd/masquecat-relay/README.md`](./cmd/masquecat-relay/README.md) and
[`docs/masquecat-relay-deployment.md`](./docs/masquecat-relay-deployment.md)
for deployment details.

## Build and test

This branch is experimental and is not represented by an existing release
artifact.

```sh
git clone https://github.com/knowlet/tailcat.git
cd tailcat
git checkout feat/masquecat-masque-transport

go test ./...
go build ./...
```

The stable CLI integration for the MasqueCat client/server path is still in
progress. The transport is currently exposed through the Go API, while the
relay has a dedicated command.

For a deeper design description, see
[`docs/masquecat.md`](./docs/masquecat.md).
