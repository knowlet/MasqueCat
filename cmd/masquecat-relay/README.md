# masquecat-relay

`masquecat-relay` is the self-hosted HTTP/3 / MASQUE relay used by MasqueCat
when two peers cannot use an explicitly configured direct MASQUE endpoint.

It terminates the **outer** QUIC/TLS 1.3 connection and forwards MasqueCat
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

The current binary intentionally has only three flags:

| Flag | Default | Required | Meaning |
| --- | --- | --- | --- |
| `-listen` | `:443` | no | UDP listen address for HTTP/3 / QUIC |
| `-cert` | empty | yes | TLS certificate PEM file |
| `-key` | empty | yes | TLS private-key PEM file |

Example:

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

## Network requirements

The relay needs:

- a stable DNS name, for example `relay.example.com`;
- a certificate valid for that DNS name;
- inbound **UDP** on the configured listen port, normally UDP/443;
- return traffic allowed for established QUIC sessions.

There is no TCP listener in the current relay. A conventional HTTP/1.1 or
HTTP/2 reverse proxy in front of the process is therefore not sufficient.

If a load balancer or firewall sits in front of the relay, it must preserve
QUIC/UDP traffic to the relay process. UDP pass-through is the simplest model
for the current implementation.

## TLS

The binary loads the PEM certificate and private key at startup using
`tls.LoadX509KeyPair`. Clients verify the relay hostname using the operating
system trust store.

Use a publicly trusted certificate for Internet-facing deployments, or an
internal CA that is already trusted by every MasqueCat peer.

The current binary does not implement live certificate reload. After replacing
certificate files, restart the service.

## Quick firewall examples

UFW:

```sh
sudo ufw allow 443/udp
```

firewalld:

```sh
sudo firewall-cmd --permanent --add-port=443/udp
sudo firewall-cmd --reload
```

Cloud firewalls / security groups must allow the same UDP port in addition to
the host firewall.

## systemd

A minimal hardened unit is documented in
[`docs/masquecat-relay-deployment.md`](../../docs/masquecat-relay-deployment.md).

## Container deployment

The repository does not currently ship a dedicated relay container image or a
relay-specific Dockerfile. A container can run the binary, but the deployment
must publish the port as **UDP**, not TCP, and mount the certificate/key files.
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
