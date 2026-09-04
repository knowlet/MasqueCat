from pathlib import Path
import re


def replace_once(text, old, new, label):
    if old not in text:
        raise SystemExit(f"missing expected text for {label}")
    return text.replace(old, new, 1)


p = Path("masquecat_h2.go")
s = p.read_text()
s = replace_once(s, "\treturn &http.Request{\n", "\treq := &http.Request{\n", "H2 request literal")
s = replace_once(
    s,
    "\t}.WithContext(ctx), nil\n}\n\ntype masqueH2ResponseWriter",
    "\t}\n\treturn req.WithContext(ctx), nil\n}\n\ntype masqueH2ResponseWriter",
    "H2 request WithContext",
)
start_re = re.compile(r"func startMasqueHTTP2\(\n.*?\n\) error \{.*?\n\}\n\n// ServeMasque", re.S)
new_start = '''func startMasqueHTTP2(
\tctx context.Context,
\taddr string,
\ttlsConfig *tls.Config,
\thandler http.Handler,
\tlogf logger.Logf,
) (*masqueHTTP2Server, error) {
\tsrv, err := newMasqueHTTP2Server(tlsConfig, handler)
\tif err != nil {
\t\treturn nil, err
\t}
\tln, err := net.Listen("tcp", addr)
\tif err != nil {
\t\treturn nil, fmt.Errorf("listen for HTTP/2 MASQUE: %w", err)
\t}
\ttlsLn := tls.NewListener(ln, srv.TLSConfig)
\tgo func() {
\t\tif err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil && logf != nil {
\t\t\tlogf("HTTP/2 MASQUE listener stopped: %v", err)
\t\t}
\t}()
\tgo func() {
\t\t<-ctx.Done()
\t\t_ = srv.Close()
\t}()
\treturn srv, nil
}

// ServeMasque'''
s, n = start_re.subn(new_start, s, count=1)
if n != 1:
    raise SystemExit("failed to replace startMasqueHTTP2")
p.write_text(s)

p = Path("masquecat.go")
s = p.read_text()
s = replace_once(
    s,
    "\tdirectHTTP *http3.Server\n\tdirectPC   net.PacketConn\n",
    "\tdirectHTTP *http3.Server\n\tdirectH2   *masqueHTTP2Server\n\tdirectPC   net.PacketConn\n",
    "MasqueServer directH2 field",
)
s = replace_once(
    s,
    "\t\tif s.directHTTP != nil {\n\t\t\t_ = s.directHTTP.Close()\n\t\t}\n\t\tif s.directPC != nil {",
    "\t\tif s.directHTTP != nil {\n\t\t\t_ = s.directHTTP.Close()\n\t\t}\n\t\tif s.directH2 != nil {\n\t\t\t_ = s.directH2.Close()\n\t\t}\n\t\tif s.directPC != nil {",
    "startup cleanup direct H2",
)
s = replace_once(
    s,
    "\t\ts.directHTTP = nil\n\t\ts.directPC = nil\n",
    "\t\ts.directHTTP = nil\n\t\ts.directH2 = nil\n\t\ts.directPC = nil\n",
    "startup cleanup reset direct H2",
)
s = replace_once(
    s,
    "\t\tif err := startMasqueHTTP2(ctx, h2Addr, s.DirectTLSConfig, handler, logf); err != nil {\n\t\t\t_ = pc.Close()\n\t\t\tcleanup()\n\t\t\treturn fmt.Errorf(\"start direct HTTP/2 MASQUE: %w\", err)\n\t\t}\n",
    "\t\th2, err := startMasqueHTTP2(ctx, h2Addr, s.DirectTLSConfig, handler, logf)\n\t\tif err != nil {\n\t\t\t_ = pc.Close()\n\t\t\tcleanup()\n\t\t\treturn fmt.Errorf(\"start direct HTTP/2 MASQUE: %w\", err)\n\t\t}\n\t\ts.directH2 = h2\n",
    "start direct H2 handle",
)
s = replace_once(
    s,
    "\tif s.directHTTP != nil {\n\t\terrs = append(errs, s.directHTTP.Close())\n\t\ts.directHTTP = nil\n\t}\n\tif s.directPC != nil {",
    "\tif s.directHTTP != nil {\n\t\terrs = append(errs, s.directHTTP.Close())\n\t\ts.directHTTP = nil\n\t}\n\tif s.directH2 != nil {\n\t\terrs = append(errs, s.directH2.Close())\n\t\ts.directH2 = nil\n\t}\n\tif s.directPC != nil {",
    "MasqueServer.Close direct H2",
)
p.write_text(s)

p = Path("cmd/masquecat-relay/README.md")
s = p.read_text()
s = s.replace(
    "`masquecat-relay` is the self-hosted HTTP/3 / MASQUE relay used by MasqueCat",
    "`masquecat-relay` is the self-hosted MASQUE relay used by MasqueCat",
)
s = s.replace(
    "It terminates the **outer** QUIC/TLS 1.3 connection and forwards MasqueCat",
    "It accepts HTTP/3 over QUIC and an RFC 9298 HTTP/2-over-TCP fallback, both over TLS, and forwards MasqueCat",
)
s = s.replace(
    "| `-listen` | `:443` | no | UDP listen address for HTTP/3 / QUIC |",
    "| `-listen` | `:443` | no | shared port/address: UDP for HTTP/3 and TCP for HTTP/2 fallback |",
)
s = re.sub(
    r"## Network requirements\n.*?\n## TLS",
    '''## Network requirements

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

## TLS''',
    s,
    count=1,
    flags=re.S,
)
s = re.sub(
    r"## Quick firewall examples\n.*?\n## systemd",
    '''## Quick firewall examples

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

## systemd''',
    s,
    count=1,
    flags=re.S,
)
p.write_text(s)

p = Path("docs/masquecat-relay-deployment.md")
s = p.read_text()
s = s.replace(
    "`masquecat-relay` terminates HTTP/3 / QUIC and forwards MasqueCat datagrams",
    "`masquecat-relay` accepts HTTP/3 / QUIC and RFC 9298 HTTP/2 / TCP CONNECT-UDP and forwards MasqueCat datagrams",
)
s = s.replace(
    "| `-listen` | `:443` | no | UDP listen address used by HTTP/3 / QUIC |",
    "| `-listen` | `:443` | no | shared address/port: UDP for HTTP/3 and TCP for HTTP/2 fallback |",
)
s = re.sub(
    r"## 5\. Firewall requirements\n.*?\n## 6\. NAT and port forwarding",
    '''## 5. Firewall requirements

The relay listens on the same configured port using **both UDP and TCP**:

```text
UDP/443 -> HTTP/3 / QUIC (preferred)
TCP/443 -> HTTP/2 CONNECT-UDP fallback
```

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

Cloud security groups / network ACLs should expose both protocols. UDP keeps the
preferred H3 path available; TCP makes the fallback useful on networks that
block QUIC.

## 6. NAT and port forwarding''',
    s,
    count=1,
    flags=re.S,
)
s = re.sub(
    r"## 6\. NAT and port forwarding\n.*?\n## 7\. Reverse proxies and load balancers",
    '''## 6. NAT and port forwarding

A relay should normally have a stable public endpoint. If it is behind NAT,
forward both transports to the same internal port:

```text
public UDP/443 -> relay-host UDP/443
public TCP/443 -> relay-host TCP/443
```

Do not rely on STUN or automatic port mapping; `masquecat-relay` does not
perform them.

## 7. Reverse proxies and load balancers''',
    s,
    count=1,
    flags=re.S,
)
s = re.sub(
    r"## 7\. Reverse proxies and load balancers\n.*?\n## 8\. systemd deployment",
    '''## 7. Reverse proxies and load balancers

HTTP/3 uses UDP/QUIC and the fallback uses HTTP/2 over TCP/TLS. Layer-4
pass-through for both UDP and TCP is the simplest deployment model. A TCP-only
path can still carry the H2 fallback, but loses H3.

A layer-7 HTTP/2 reverse proxy is suitable only if it preserves RFC 8441
Extended CONNECT and RFC 9298 CONNECT-UDP semantics; generic HTTP/2 proxying is
not enough. Likewise, an HTTP/3 proxy must support CONNECT-UDP rather than only
ordinary requests.

Because the relay keeps an in-memory map of connected peer identities, naive
horizontal load balancing across independent relay processes does not create a
shared-state cluster. Use one relay process per relay URL or connection affinity
until shared state/federation exists.

## 8. systemd deployment''',
    s,
    count=1,
    flags=re.S,
)
s = s.replace("Description=MasqueCat HTTP/3 CONNECT-UDP relay", "Description=MasqueCat CONNECT-UDP relay (HTTP/3 + HTTP/2 fallback)")
s = s.replace("Run it with the relay port published as UDP:", "Run it with the relay port published as both UDP and TCP:")
s = s.replace("  -p 443:443/udp \\\n", "  -p 443:443/udp \\\n  -p 443:443/tcp \\\n", 1)
s = s.replace("- `-p 443:443/tcp` is not sufficient;", "- publish both UDP and TCP if you want both H3 and H2 fallback paths;")
s = s.replace("  -p 443:8443/udp \\\n", "  -p 443:8443/udp \\\n  -p 443:8443/tcp \\\n", 1)
s = s.replace("| outbound UDP/443", "| outbound UDP/443 or TCP/443")
s = s.replace("relay.example.com\n                              UDP/443", "relay.example.com\n                         UDP/443 + TCP/443")
s = s.replace("peer <-> QUIC/TLS 1.3 <-> relay", "peer <-> HTTP/3(QUIC) or HTTP/2(TCP), TLS <-> relay")
s = s.replace("that the QUIC listener is active", "that the UDP/H3 and TCP/H2 listeners are active")
s = s.replace("Check that UDP, not just TCP, is open:", "Check both the preferred UDP/H3 path and the TCP/H2 fallback:")
s = s.replace("sudo ss -u -l -n -p | grep ':443'", "sudo ss -u -l -n -p | grep ':443'\nsudo ss -t -l -n -p | grep ':443'")
s = s.replace("Also verify the cloud firewall/security group allows UDP/443.", "Also verify the cloud firewall/security group allows both UDP/443 and TCP/443.")
s = s.replace("- UDP/443 not forwarded through NAT;", "- UDP/443 and TCP/443 are not both forwarded through NAT;")
s = s.replace("- cloud provider security group only permits TCP/443;", "- cloud provider security group permits neither UDP/443 nor the TCP fallback;")
s = re.sub(
    r"### TCP reverse proxy shows no requests\n\nExpected if the proxy listens only on TCP\. MasqueCat relay traffic is HTTP/3 over\nQUIC/UDP\.",
    '''### TCP reverse proxy shows no requests

A TCP path can carry the HTTP/2 fallback, but a layer-7 proxy must support RFC
8441 Extended CONNECT and RFC 9298 CONNECT-UDP. Use TCP pass-through if the
proxy does not implement those semantics.''',
    s,
    count=1,
)
p.write_text(s)
