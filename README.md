# MasqueCat

MasqueCat is a Tailcat fork that keeps Tailcat's userspace WireGuard + gVisor
application model while replacing the normal runtime transport with explicit
HTTP/3 MASQUE CONNECT-UDP paths.

The goal is an **in-place Tailcat CLI replacement**: keep the `tailcat` binary,
command shape, server/client workflow, SSH/file-transfer integration, and saved
key behavior as close to upstream Tailcat as practical, while using `mc...`
connection tokens and MASQUE direct/relay transport.

The original `tc...` client path is still supported for compatibility. Starting
a legacy DERP/STUN/disco server is explicit with `--legacy-derp`; MasqueCat does
not silently fall back to public Tailscale DERP infrastructure.

## Build

This branch is experimental and currently has no release artifact. Build the two
user-facing executables explicitly:

```sh
git clone https://github.com/knowlet/tailcat.git
cd tailcat
git checkout feat/masquecat-masque-transport

mkdir -p bin
go build -o ./bin/tailcat ./cmd/tailcat
go build -o ./bin/masquecat-relay ./cmd/masquecat-relay

./bin/tailcat version
./bin/tailcat --help
```

`go build ./...` is useful as a compile check, but it matches multiple packages.
Go builds those packages into its build cache and does **not** leave a
`./tailcat` executable in the current directory. Use `go build -o ...
./cmd/tailcat` when you want a binary you can run.

To test the whole repository:

```sh
go test ./...
```

## Quick start: relay-only

MasqueCat deliberately has no built-in public relay. A normal relay-only setup
therefore has three steps: run your relay, point the server at it, then give the
printed `mc...` token to the client.

### 1. Run the relay

The relay terminates HTTP/3 itself and must receive **UDP/443**. A TCP-only
HTTP/1.1 or HTTP/2 reverse proxy cannot carry this protocol.

```sh
sudo ./bin/masquecat-relay \
  -listen :443 \
  -cert /etc/masquecat/tls/fullchain.pem \
  -key /etc/masquecat/tls/privkey.pem
```

Use a certificate whose hostname matches the relay URL used by peers.

### 2. Start a Tailcat-compatible server

Set the relay once in the environment:

```sh
export MASQUECAT_RELAY_URL=https://relay.example.com
./bin/tailcat
```

With no positional arguments, `tailcat` enters server mode just like upstream
Tailcat. It prints both the configured MASQUE endpoint and the connection token,
for example:

```text
# MASQUE relay server: https://relay.example.com
# 🐈 Server listening with new address: mc...
```

Because this fork intentionally has no default public relay, running `tailcat`
with neither a relay nor a direct endpoint configured fails closed with a clear
configuration error instead of silently reverting to DERP.

The flag form is equivalent:

```sh
./bin/tailcat --relay-url https://relay.example.com
```

### 3. Connect with the printed token

The basic Tailcat pipe interface is unchanged:

```sh
# Default pipe mode.
echo 'hello' | ./bin/tailcat 'mc...'

# Connect to a TCP port exposed by the peer.
./bin/tailcat 'mc...' 8000

# Diagnostics.
./bin/tailcat ping 'mc...'
./bin/tailcat parse 'mc...'
./bin/tailcat resolve 'mc...'
```

`resolve` simply validates and reprints an `mc...` token because MASQUE tokens
already contain their exact direct/relay URLs; there is no DERP-map expansion.

## Serve local ports

The upstream `serve` syntax is retained:

```sh
export MASQUECAT_RELAY_URL=https://relay.example.com

# Proxy incoming peer traffic to local TCP ports 80 and 443.
./bin/tailcat serve 80,443

# Ranges work too.
./bin/tailcat serve 8000-8999
```

Then a client can use the same token with the desired port:

```sh
./bin/tailcat 'mc...' 80
```

## SSH

The built-in auth-free SSH server is retained. The WireGuard peer identity is
the authentication boundary, as in Tailcat.

Server:

```sh
export MASQUECAT_RELAY_URL=https://relay.example.com
./bin/tailcat serve no-auth-ssh
```

Client:

```sh
./bin/tailcat ssh 'mc...'
./bin/tailcat ssh 'mc...' uname -a
```

`tailcat ssh` continues to use the current `tailcat` executable as OpenSSH's
`ProxyCommand`. Because the root pipe mode now understands `mc...`, SSH uses the
same MASQUE carrier without a separate MasqueCat SSH command.

The upstream `cp` / `ls` commands follow the same ProxyCommand path when the
server enables the corresponding SSH/files service.

## Saved server and client keys

Without `--key`, server mode uses a saved key named `default` if it exists;
otherwise it uses a new ephemeral key. To keep a stable server identity/token:

```sh
export MASQUECAT_RELAY_URL=https://relay.example.com
./bin/tailcat genkey --key=default
./bin/tailcat
```

For a persistent client identity:

```sh
./bin/tailcat genkey --client --key=client-default
```

Client commands automatically load `client-default` when it exists.

## Direct MASQUE mode

A directly reachable server can advertise its own HTTP/3 endpoint. Direct mode
requires an externally reachable UDP listener and a normal TLS certificate:

```sh
./bin/tailcat \
  --direct-url https://mc.example.com \
  --direct-listen :443 \
  --tls-cert /etc/masquecat/tls/fullchain.pem \
  --tls-key /etc/masquecat/tls/privkey.pem
```

You can configure both direct and relay endpoints:

```sh
./bin/tailcat \
  --direct-url https://mc.example.com \
  --direct-listen :443 \
  --tls-cert /etc/masquecat/tls/fullchain.pem \
  --tls-key /etc/masquecat/tls/privkey.pem \
  --relay-url https://relay.example.com
```

At startup a client tries the explicit direct endpoint first and the explicit
relay if direct setup fails. Runtime direct-to-relay migration after an already
established path fails is not implemented yet.

## MASQUE CLI options and environment

| CLI option | Environment | Purpose |
| --- | --- | --- |
| `--relay-url URL` | `MASQUECAT_RELAY_URL` | Explicit MasqueCat relay URL |
| `--direct-url URL` | `MASQUECAT_DIRECT_URL` | Public URL advertised for direct MASQUE |
| `--direct-listen ADDR` | `MASQUECAT_DIRECT_LISTEN` | UDP listener for direct HTTP/3, e.g. `:443` |
| `--tls-cert FILE` | `MASQUECAT_TLS_CERT` | Direct endpoint TLS certificate |
| `--tls-key FILE` | `MASQUECAT_TLS_KEY` | Direct endpoint TLS private key |
| `--insecure-skip-verify` | `MASQUECAT_INSECURE_SKIP_VERIFY=1` | Development-only outer TLS verification bypass |
| `--legacy-derp` | `TAILCAT_LEGACY_DERP=1` | Use the original Tailcat DERP/STUN/disco server/genkey path |

Production deployments should use normal TLS hostname and certificate
verification. `--insecure-skip-verify` is for development only.

## Legacy Tailcat compatibility

Existing `tc...` tokens continue to dispatch to the upstream Tailcat client
implementation automatically:

```sh
./bin/tailcat 'tc...'
./bin/tailcat ping 'tc...'
./bin/tailcat ssh 'tc...'
```

To deliberately start the original Tailcat server instead of MasqueCat:

```sh
./bin/tailcat --legacy-derp
```

DERP-specific options such as DERP-map/region selection belong to this legacy
mode. MasqueCat itself never needs STUN, netcheck, disco CallMeMaybe, endpoint
probing, UDP hole punching, or a raw peer WireGuard UDP socket.

## Data plane

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
peer as a logical node-key endpoint; the bind selects a configured MASQUE path
instead of opening a WireGuard UDP socket or delegating transport to magicsock.

## No built-in infrastructure

MasqueCat has no built-in public relay, map service, control plane, or default
external hostname. Every Internet-facing endpoint is operator supplied:

- `DirectURL` advertises an explicitly reachable peer MASQUE endpoint.
- `RelayURL` configures an explicit MasqueCat relay.
- relay-only deployments require outbound QUIC/UDP 443 from both peers.
- direct deployments require an explicitly reachable QUIC/UDP endpoint.

There is no MasqueCat fallback to an upstream Tailscale DERP or DERP map.

## Security model

Application traffic is protected by two layers:

1. WireGuard provides end-to-end encryption between MasqueCat peers.
2. QUIC/TLS 1.3 protects the outer HTTP/3 connection to the direct endpoint or
   relay.

A relay terminates the outer TLS connection but forwards opaque WireGuard
ciphertext. It can observe peer node keys and traffic metadata but cannot decrypt
the inner WireGuard session.

Direct and relay CONNECT-UDP registration uses a one-time challenge and proof of
possession of the advertised node private key. Duplicate live registrations are
rejected rather than silently replacing the current peer.

This transport design is not an anonymity guarantee. A network observer can
still see QUIC traffic, endpoint addresses, packet sizes, timing, and connection
lifetimes.

## Go API

The CLI is the normal entry point, but the transport is also available as a Go
API through `tailcat.MasqueServer` and `tailcat.MasqueClient`. Useful client
operations include `Ping`, `DialTCPPort`, `DialTCP`, `Dial`, `DrainTCP`, `Path`,
and `Close`.

For deeper protocol/design notes and relay deployment details, see:

- [`docs/masquecat.md`](./docs/masquecat.md)
- [`cmd/masquecat-relay/README.md`](./cmd/masquecat-relay/README.md)
- [`docs/masquecat-relay-deployment.md`](./docs/masquecat-relay-deployment.md)
