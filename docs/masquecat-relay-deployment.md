# MasqueCat relay deployment guide

This document describes how to deploy the current experimental
`cmd/masquecat-relay` binary.

For the broader MasqueCat architecture, direct-vs-relay path selection, and Go
API usage, see [`masquecat.md`](./masquecat.md).

> [!IMPORTANT]
> Relay registration is cryptographically authenticated with a one-time
> proof-of-possession challenge bound to the advertised node key, target key,
> and path mode. Duplicate live registrations are rejected rather than silently
> replacing an existing peer. The relay is still **not production hardened**:
> bandwidth/connection quotas, general abuse controls, metrics, health probes,
> live certificate reload, and horizontal shared state are not implemented yet.

## 1. What the relay does

`masquecat-relay` terminates HTTP/3 / QUIC and forwards MasqueCat datagrams
between authenticated peer identities.

```text
peer A
  |
  | QUIC / TLS 1.3
  | HTTP/3 CONNECT-UDP
  | node-key proof
  v
+------------------+
| masquecat-relay  |
+------------------+
  ^
  | QUIC / TLS 1.3
  | HTTP/3 CONNECT-UDP
  | node-key proof
  |
peer B
```

The inner WireGuard packet is already encrypted before it reaches the relay.
The relay does not need either peer's WireGuard private key.

The relay is not intended to be an unrestricted RFC 9298 UDP proxy. It routes
only MasqueCat-framed traffic between connected MasqueCat node identities.

## 2. Current command surface

Build:

```sh
go build -o masquecat-relay ./cmd/masquecat-relay
```

Run:

```sh
./masquecat-relay \
  -listen :443 \
  -cert /etc/masquecat/tls/fullchain.pem \
  -key /etc/masquecat/tls/privkey.pem
```

Current flags:

| Flag | Default | Required | Description |
| --- | --- | --- | --- |
| `-listen` | `:443` | no | UDP listen address used by HTTP/3 / QUIC |
| `-cert` | empty | together with `-key` for non-interactive/production use | certificate PEM file |
| `-key` | empty | together with `-cert` for non-interactive/production use | private-key PEM file |

There are currently no CLI flags for quotas, metrics, authentication policy,
certificate reload, or health endpoints. Node-key proof authentication is part
of the relay protocol rather than a command-line option.

## 3. DNS

Use a stable DNS name, for example:

```text
relay.example.com.  A     203.0.113.10
relay.example.com.  AAAA  2001:db8::10
```

IPv6 is optional. Do not publish an AAAA record unless the relay is actually
reachable over IPv6.

MasqueCat peers should then use:

```text
https://relay.example.com
```

as their `RelayURL`.

If using a non-standard port:

```text
https://relay.example.com:8443
```

## 4. TLS certificate

For non-interactive and production deployments, provide both `-cert` and `-key`.
The binary loads them with `tls.LoadX509KeyPair`. Supplying only one of the two
fails startup.

When neither flag is supplied and stdin is an interactive terminal, the relay
asks whether it should generate an ephemeral self-signed certificate for that
process invocation. Answering `y` or `yes` creates an Ed25519-backed certificate
in memory with a 24-hour lifetime and SANs for `localhost`, the local hostname,
`127.0.0.1`, and `::1`. It is not written to disk and is regenerated on restart.

In non-interactive environments such as systemd, CI, or normal container
launches, missing certificate flags remain a hard error; there is no silent
security downgrade.

Recommended deployment layout:

```text
/etc/masquecat/tls/fullchain.pem
/etc/masquecat/tls/privkey.pem
```

The certificate SAN must match the hostname in `RelayURL`.

Accepted trust models:

- public WebPKI certificate;
- internal CA already installed in the peer operating-system trust store.

An arbitrary self-signed certificate will fail normal hostname verification
unless the corresponding CA is installed on every peer. For explicit local
development, `MasqueClient.InsecureSkipVerify` and
`MasqueServer.InsecureSkipVerify` can disable verification for outbound MASQUE
connections. This is an opt-in development escape hatch and should not be used
for normal Internet-facing deployments because it permits man-in-the-middle
attacks.

The current relay does not reload certificates dynamically. Restart it after
certificate renewal. The interactive ephemeral certificate is regenerated on
every restart.

## 5. Firewall requirements

The external transport is QUIC, so the important rule is **UDP**, not TCP.

Minimum inbound rule for the conventional port:

```text
UDP/443 -> masquecat-relay
```

UFW:

```sh
sudo ufw allow 443/udp
```

firewalld:

```sh
sudo firewall-cmd --permanent --add-port=443/udp
sudo firewall-cmd --reload
```

Cloud security groups / network ACLs need a matching UDP rule.

The binary does not create a TCP/443 listener. Opening only TCP/443 will not
make the relay reachable.

## 6. NAT and port forwarding

A relay should normally have a stable public endpoint.

If it is behind NAT, configure a static UDP port-forward:

```text
public UDP/443 -> relay-host UDP/443
```

Do not rely on STUN or automatic port mapping; `masquecat-relay` does not
perform them.

## 7. Reverse proxies and load balancers

A normal TCP-only reverse proxy cannot proxy this relay.

Examples that are insufficient by themselves:

- HTTP/1.1 reverse proxy listening only on TCP/443;
- HTTP/2 reverse proxy listening only on TCP/443;
- TLS terminator that does not accept HTTP/3 / QUIC on UDP.

The simplest supported topology is UDP pass-through:

```text
Internet UDP/443
      |
      v
UDP-capable load balancer / firewall
      |
      v
masquecat-relay UDP/443
```

Because the relay keeps an in-memory map of connected peer identities, naive
horizontal load balancing across multiple independent relay processes is not a
shared-state cluster. Two peers that land on different relay instances cannot
assume a common peer registry.

Until federation/shared state is implemented, use one relay process per relay
URL, or provide external connection affinity that guarantees the application
semantics you require.

## 8. systemd deployment

Create a dedicated account:

```sh
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin masquecat
sudo install -d -o root -g masquecat -m 0750 /etc/masquecat/tls
sudo install -m 0755 ./masquecat-relay /usr/local/bin/masquecat-relay
```

Install certificate material so the service can read it without allowing the
service user to modify it.

Example `/etc/systemd/system/masquecat-relay.service`:

```ini
[Unit]
Description=MasqueCat HTTP/3 CONNECT-UDP relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
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

Enable it:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now masquecat-relay
sudo systemctl status masquecat-relay
```

Logs:

```sh
journalctl -u masquecat-relay -f
```

After certificate renewal:

```sh
sudo systemctl restart masquecat-relay
```

## 9. Container deployment

The repository does not currently publish a dedicated relay image. If you want
an image for testing, a minimal multi-stage Dockerfile can be built from the
repository source:

```dockerfile
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/masquecat-relay ./cmd/masquecat-relay

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/masquecat-relay /masquecat-relay
ENTRYPOINT ["/masquecat-relay"]
```

Run it with the relay port published as UDP:

```sh
docker run --rm \
  -p 443:443/udp \
  -v /etc/masquecat/tls:/tls:ro \
  IMAGE \
  -listen :443 \
  -cert /tls/fullchain.pem \
  -key /tls/privkey.pem
```

Important:

- `-p 443:443/tcp` is not sufficient;
- the certificate mount should be read-only;
- the container example does not add health checks because the binary has no
  health endpoint yet;
- rootless/non-root container networking may require a high internal port such
  as 8443, with the host publishing external UDP/443 to that container port.

Example:

```sh
docker run --rm \
  -p 443:8443/udp \
  -v /etc/masquecat/tls:/tls:ro \
  IMAGE \
  -listen :8443 \
  -cert /tls/fullchain.pem \
  -key /tls/privkey.pem
```

## 10. Relay-only MasqueCat topology

A typical relay-only installation looks like this:

```text
private server / CGNAT                         client / laptop
        |                                            |
        | outbound UDP/443                           | outbound UDP/443
        +----------------------+  +------------------+
                               v  v
                         relay.example.com
                              UDP/443
```

Server configuration:

```go
s := &tailcat.MasqueServer{
    Server: tailcat.Server{
        OnTCP: myTCPHandler,
    },
    RelayURL: "https://relay.example.com",
}
```

The generated `mc...` token carries that relay URL. The client uses the same
relay to reach the server's node identity.

The private server does not need a public inbound port in this topology.

## 11. Security and trust boundary

The outer layer is:

```text
peer <-> QUIC/TLS 1.3 <-> relay
```

The inner layer is:

```text
MasqueCat peer <-> WireGuard <-> MasqueCat peer
```

The relay can observe:

- peer IP addresses;
- node public keys used for routing;
- packet size and timing;
- connection duration and traffic volume.

It should not be able to read the inner WireGuard application payload merely by
terminating the outer QUIC connection.

### Registration authentication

Relay registration is a two-request challenge flow:

1. The peer sends CONNECT-UDP with its advertised source key and target.
2. The relay returns HTTP 401 with a random `Masquecat-Challenge` and a
   `Masquecat-Verifier` public key.
3. The peer seals the challenge to the verifier using its node private key and
   retries with `Masquecat-Proof`.
4. The relay opens the proof using the advertised source public key and accepts
   it only if the pending challenge matches source, target, and mode and has not
   expired.

The challenge lifetime is 30 seconds. Pending challenge allocation is capped at
1024 globally, 4 per source node key, and 64 per remote address. An identical
unauthenticated retry reuses the outstanding challenge instead of consuming a
new slot.

A successfully validated duplicate node-key registration does not evict the
existing live registration: the relay reserves node keys atomically and returns
HTTP 409 when the key is already active.

This prevents the original unauthenticated node-key slot hijack / routing
impersonation problem. It does not provide general service admission policy or
bandwidth abuse control.

## 12. Current observability

The relay currently logs through the standard Go logger. Useful events include
peer registration, connection closure, malformed datagram drops, and forwarding
errors.

Not currently implemented:

- `/healthz` or `/readyz`;
- Prometheus metrics;
- structured JSON logs;
- connection gauges;
- per-peer bandwidth counters;
- distributed tracing.

For now, process liveness should be supervised by the service manager. A future
health endpoint should verify that the QUIC listener is active without exposing
peer-registry contents.

## 13. Resource and abuse controls

Authentication challenge allocation has bounded pending-state limits, but the
current implementation does not yet expose configurable general service limits
for:

- maximum active peers;
- maximum active connections;
- maximum datagram rate;
- maximum bandwidth;
- general per-IP connection/bandwidth limits;
- explicit idle timeout policy beyond underlying transport behavior;
- operator-defined admission ACLs.

These are important blockers for an Internet-scale public relay.

## 14. Troubleshooting

### Client times out immediately

Check that UDP, not just TCP, is open:

```sh
sudo ss -u -l -n -p | grep ':443'
```

Also verify the cloud firewall/security group allows UDP/443.

### TLS / hostname verification fails

Confirm:

- `RelayURL` hostname matches the certificate SAN;
- the full certificate chain is served from the configured PEM;
- the client OS trusts the issuing CA;
- DNS resolves to the intended relay.

### Works on LAN but not over Internet

Typical causes:

- UDP/443 not forwarded through NAT;
- cloud provider security group only permits TCP/443;
- upstream network blocks QUIC/UDP;
- AAAA record points to an unreachable IPv6 address.

### TCP reverse proxy shows no requests

Expected if the proxy listens only on TCP. MasqueCat relay traffic is HTTP/3 over
QUIC/UDP.

### Peers connected to different relay instances cannot find each other

The current peer registry is process-local. There is no cross-instance shared
state or federation.

### Duplicate peer receives HTTP 409

This is intentional. A live node-key registration is not replaced by a second
connection using the same identity. Close the old peer cleanly or wait until it
is unregistered before reconnecting with that key.

### Authentication retry receives HTTP 401 again

The proof is single-use and challenge-bound. Common causes include an expired
challenge, mismatched source/target/mode, or retrying an already consumed proof.
The client transport normally performs the challenge retry automatically.

## 15. Production-readiness checklist

Before calling a relay deployment production-ready, at minimum require:

- security review of the node-key challenge/proof protocol and replay limits;
- connection and bandwidth quotas;
- rate limiting / abuse controls beyond challenge allocation;
- explicit idle and maximum-session lifetime policies;
- health/readiness endpoints;
- metrics and alerting;
- certificate reload strategy;
- tested graceful shutdown/drain behavior;
- validated MTU and loss behavior;
- real direct/relay WireGuard + TCP/SSH E2E tests;
- documented upgrade and rollback process.

## 16. Related documents

- [`cmd/masquecat-relay/README.md`](../cmd/masquecat-relay/README.md) — command quick start and flags.
- [`masquecat.md`](./masquecat.md) — overall MasqueCat architecture and Go API.
- [`benchmarks.md`](./benchmarks.md) — framing benchmark scope and results.
