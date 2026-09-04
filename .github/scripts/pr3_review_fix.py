from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"{path}: expected exactly one {label}, found {text.count(old)}")
    p.write_text(text.replace(old, new, 1))


# Preserve RFC 8441 ALPN/TLS requirements when applications dynamically
# select a TLS config through GetConfigForClient.
replace_once(
    "masquecat_h2.go",
    '''\tconf := tlsConfig.Clone()\n\tconf.MinVersion = tls.VersionTLS13\n\tconf.NextProtos = []string{http2.NextProtoTLS}\n\treturn &masqueHTTP2Server{\n''',
    '''\tconf := tlsConfig.Clone()\n\tconf.MinVersion = tls.VersionTLS13\n\tconf.NextProtos = []string{http2.NextProtoTLS}\n\tif getConfigForClient := conf.GetConfigForClient; getConfigForClient != nil {\n\t\tconf.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {\n\t\t\tselected, err := getConfigForClient(hello)\n\t\t\tif err != nil || selected == nil {\n\t\t\t\treturn selected, err\n\t\t\t}\n\t\t\tselected = selected.Clone()\n\t\t\tif selected.MinVersion < tls.VersionTLS13 {\n\t\t\t\tselected.MinVersion = tls.VersionTLS13\n\t\t\t}\n\t\t\tselected.NextProtos = []string{http2.NextProtoTLS}\n\t\t\treturn selected, nil\n\t\t}\n\t}\n\treturn &masqueHTTP2Server{\n''',
    "HTTP/2 TLS configuration block",
)

# Stream 1 is fixed for the lifetime of this dedicated one-stream H2 client.
# Publish it before the reader goroutine starts so HEADERS/DATA can never race
# with the later request-header write path.
replace_once(
    "masquecat_h2_client.go",
    '''\t\tpeerMaxFrameSize:  16384,\n\t\tbodyR:             bodyR,\n''',
    '''\t\tpeerMaxFrameSize:  16384,\n\t\tstreamID:          1,\n\t\tbodyR:             bodyR,\n''',
    "client connection initialization",
)
replace_once(
    "masquecat_h2_client.go",
    '''\tc.flowMu.Lock()\n\tc.streamID = 1\n\tc.peerStreamWindow = c.peerInitialWindow\n\tc.flowMu.Unlock()\n''',
    '''\tc.flowMu.Lock()\n\tc.peerStreamWindow = c.peerInitialWindow\n\tc.flowMu.Unlock()\n''',
    "late stream ID publication",
)

# Correct the remaining UDP-only container guidance.
replace_once(
    "cmd/masquecat-relay/README.md",
    '''must publish the port as **UDP**, not TCP, and should mount certificate/key\nfiles. Most container launches are non-interactive, so the automatic\nself-signed prompt is intentionally unavailable there.\n''',
    '''must publish the configured port as **both UDP and TCP**: UDP carries the\npreferred HTTP/3 path and TCP carries the HTTP/2 fallback. It should also mount\ncertificate/key files. Most container launches are non-interactive, so the\nautomatic self-signed prompt is intentionally unavailable there.\n''',
    "container protocol guidance",
)

# Add a focused regression test for dynamic TLS selection. It verifies both the
# top-level and callback-selected configurations preserve the H2-only ALPN and
# TLS 1.3 floor without mutating the caller-owned selected config.
test = Path("masquecat_h2_test.go")
text = test.read_text()
marker = "func TestMasqueHTTP2CompanionAddrUsesUDPPortForEphemeralListen"
if "func TestMasqueHTTP2DynamicTLSConfigPreservesH2" in text:
    raise SystemExit("dynamic TLS regression test already exists")
idx = text.find(marker)
if idx < 0:
    raise SystemExit("masquecat_h2_test.go: companion address test marker not found")
addition = r'''func TestMasqueHTTP2DynamicTLSConfigPreservesH2(t *testing.T) {
	selected := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	base := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return selected, nil
		},
	}

	srv, err := newMasqueHTTP2Server(base, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatal(err)
	}
	if srv.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("top-level MinVersion = %x, want TLS 1.3", srv.TLSConfig.MinVersion)
	}
	if len(srv.TLSConfig.NextProtos) != 1 || srv.TLSConfig.NextProtos[0] != "h2" {
		t.Fatalf("top-level NextProtos = %v, want [h2]", srv.TLSConfig.NextProtos)
	}

	got, err := srv.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("dynamic TLS callback returned nil config")
	}
	if got.MinVersion != tls.VersionTLS13 {
		t.Fatalf("dynamic MinVersion = %x, want TLS 1.3", got.MinVersion)
	}
	if len(got.NextProtos) != 1 || got.NextProtos[0] != "h2" {
		t.Fatalf("dynamic NextProtos = %v, want [h2]", got.NextProtos)
	}
	if selected.MinVersion != tls.VersionTLS12 || len(selected.NextProtos) != 1 || selected.NextProtos[0] != "http/1.1" {
		t.Fatalf("caller-owned TLS config was mutated: MinVersion=%x NextProtos=%v", selected.MinVersion, selected.NextProtos)
	}
}

'''
test.write_text(text[:idx] + addition + text[idx:])
