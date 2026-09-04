# masquecat-relay

`masquecat-relay` is the self-hosted MASQUE relay used by MasqueCat
when two peers cannot use an explicitly configured direct MASQUE endpoint.

It accepts HTTP/3 over QUIC and an RFC 9298 HTTP/2-over-TCP fallback, both over TLS, and forwards MasqueCat
framed datagrams between connected peer identities. The inner WireGuard tunnel
remains end-to-end between the MasqueCat peers; the relay does not receive a
WireGuard private key and is not intended to decrypt application traffic.

> [!IMPORTANT]
> Peer registration uses a one-time proof-of-possession challenge. The relay
> issues a 30-second challenge bound to source key, target key, and path mode;
> the client proves possession of the advertised node private key before the
> CONNECT-UDP stream is registered. A live registration is fail-closed: a
> duplicate registration for the same node key is rejected instead of replacing
> the existing peer.
>
> The relay is still experimental. Production resource quotas, abuse controls,
> metrics, a health endpoint, live certificate reload, and horizontal shared
> state are not implemented yet.

## Architecture

Relay-only topology:

```text
MasqueCat client                         MasqueCat server
      |                                       |
      | outbound QUIC / UDP 443               | outbound QUIC / UDP 443
      | HTTP/3 CONNECT-UDP                     | HTTP/3 CONNECT-UDP
      +------------------+   +-----------------+
                         v   v
                  +------------------+
                  | masquecat-relay  |
                  |                  |
                  | authenticates    |
                  | node ownership   |
                  | then routes      |
                  | opaque WG data   |
                  +------------------+
```

Both peers initiate outbound connections. The protected MasqueCat server does
not need an inbound Internet port in relay-only mode.

The relay is **not** a generic UDP proxy. CONNECT-UDP requests use a synthetic
MasqueCat peer target, and the relay forwards only between peer identities that
are currently registered with the relay.

## Registration authentication

The first CONNECT-UDP request is intentionally unauthenticated. The relay
responds with HTTP 401 plus:

- `Masquecat-Challenge` — a random one-time challenge;
- `Masquecat-Verifier` — the relay authentication public key.

The client encrypts/seals the challenge using its node private key and the
verifier public key, then retries with `Masquecat-Proof`.

The relay accepts the retry only when the proof opens successfully and matches
the pending challenge tuple:

```text
source node key + target node key + mode
```

Current challenge controls include:

- 30-second challenge lifetime;
- at most 1024 pending challenges globally;
- at most 4 pending challenges per source node key;
- at most 64 pending challenges per remote address;
- identical unauthenticated retries reuse an existing pending challenge;
- successful/attempted proof verification consumes the challenge;
- an existing live node-key registration cannot be replaced by a duplicate.

These controls authenticate the routing identity, but they are not a substitute
for production bandwidth quotas, admission policy, or abuse prevention.

## Build

From this branch:

```sh
git clone https://github.com/knowlet/tailcat.git
cd tailcat
git checkout feat/masquecat-masque-transport

go build -o masquecat-relay ./cmd/masquecat-relay
```

## Command-line flags

| Flag | Default | Required | Meaning |
| --- | --- | --- | --- |
| `-listen` | `:443` | no | shared port/address: UDP for HTTP/3 and TCP for HTTP/2 fallback |
| `-cert` | empty | together with `-key` for non-interactive/production use | TLS certificate PEM file |
| `-key` | empty | together with `-cert` for non-interactive/production use | TLS private-key PEM file |

Production-style example:

```sh
./masquecat-relay \
  -listen :443 \
  -cert /etc/masquecat/tls/fullchain.pem \
  -key /etc/masquecat/tls/privkey.pem
```

For an unprivileged development port:

```sh
./masquecat-relay \
  -listen :8443 \
  -cert ./cert.pem \
  -key ./key.pem
```

Peers must then use a relay URL containing that port, for example
`https://relay.example.com:8443`.

## Interactive self-signed certificate mode

If **neither** `-cert` nor `-key` is supplied and stdin is an interactive
terminal, the relay asks:

```text
No TLS certificate configured. Generate an ephemeral self-signed certificate for this run? [y/N]
```

Answering `y` or `yes` generates an Ed25519-backed self-signed certificate in
memory. The generated certificate:

- is valid for 24 hours;
- is not written to disk;
- contains SANs for `localhost`, the machine hostname when available,
  `127.0.0.1`, and `::1`;
- is regenerated on every process start.

This mode is intended for local development and trusted test environments.
Because the certificate is self-signed, a normal MasqueCat client will reject
it unless the CA/certificate is explicitly trusted. For deliberate development
use, both `MasqueClient` and `MasqueServer` expose:

```go
InsecureSkipVerify: true
```

which disables TLS certificate and hostname verification for their outbound
MASQUE connections.

> [!WARNING]
> `InsecureSkipVerify` disables server authentication and makes a connection
> vulnerable to man-in-the-middle attacks. It is false by default. Do not use it
> for normal Internet-facing production deployments.

Fail-closed behavior is intentional:

- if only one of `-cert` / `-key` is supplied, startup fails;
- if no certificate is supplied in a non-interactive environment (systemd,
  most containers, CI), startup fails instead of silently creating a self-signed
  certificate;
- declining the prompt fails startup.

## Network requirements

For a normal production-like deployment the relay needs:

- a stable DNS name, for example `relay.example.com`;
- a certificate valid for that DNS name;
- inbound **UDP and TCP** on the configured listen port, normally 443;
- return traffic allowed for established QUIC and TCP/TLS sessions.

HTTP/3 over UDP remains the preferred carrier. When QUIC is blocked or
unavailable, clients retry RFC 9298 CONNECT-UDP over HTTP/2 on the same port.
A layer-4 TCP pass-through proxy can carry the H2 fallback. A layer-7 HTTP/2
proxy must explicitly support RFC 8441 Extended CONNECT and CONNECT-UDP; an
ordinary HTTP/2 reverse proxy is not automatically sufficient.

For local self-signed testing, a public DNS name is not required, but clients
must either trust the generated certificate or explicitly opt into
`InsecureSkipVerify`.

## TLS

When PEM paths are supplied, the binary loads the certificate and private key at
startup using `tls.LoadX509KeyPair`. By default, MasqueCat clients verify the
relay hostname using the operating-system trust store.

Use a publicly trusted certificate for Internet-facing deployments, or an
internal CA that is already trusted by every MasqueCat peer.

The current binary does not implement live certificate reload. After replacing
certificate files, restart the service.

## Quick firewall examples

UFW:

```sh
sudo ufw allow 443/udp
sudo ufw allow 443/tcp
```

firewalld:

```sh
sudo firewall-cmd --permanent --add-port=443/udp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

Cloud firewalls / security groups should allow both protocols on the configured
port. UDP enables the preferred HTTP/3 path; TCP enables the HTTP/2 fallback.

## systemd

A minimal hardened unit is documented in
[`docs/masquecat-relay-deployment.md`](../../docs/masquecat-relay-deployment.md).
System services are non-interactive, so explicitly configure `-cert` and `-key`.

## Container deployment

The repository does not currently ship a dedicated relay container image or a
relay-specific Dockerfile. A container can run the binary, but the deployment
must publish the port as **UDP**, not TCP, and should mount certificate/key
files. Most container launches are non-interactive, so the automatic
self-signed prompt is intentionally unavailable there.

See the deployment guide for a reproducible multi-stage example.

## What the relay can observe

The relay can observe transport and routing metadata such as:

- peer source IP addresses;
- peer node public keys used for routing;
- source/destination node public keys in MasqueCat framing;
- packet sizes and timing;
- connection lifetime and traffic volume.

The application payload is still protected by the inner WireGuard session.

## Current operational limitations

The current relay has no built-in:

- HTTP health endpoint;
- Prometheus metrics;
- per-peer bandwidth quota;
- connection-count quota;
- configurable admission ACL;
- general per-IP request/bandwidth rate limiting beyond authentication challenge caps;
- live TLS certificate reload;
- multi-relay federation or shared registry;
- automatic horizontal state synchronization.

These limitations still matter for production deployment even though peer
routing identities are authenticated.

## Full deployment guide

See [`docs/masquecat-relay-deployment.md`](../../docs/masquecat-relay-deployment.md)
for DNS, firewall, systemd, container, load-balancer, troubleshooting, trust
model, and production-readiness notes.
