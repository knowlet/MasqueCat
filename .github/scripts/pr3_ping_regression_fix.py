from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"expected exactly one {label}")
    return text.replace(old, new, 1)


core = Path("masquecat_core.go")
text = core.read_text()
old = """\tif err := st.AddProtocolAddress(masqueCoreNIC, tcpip.ProtocolAddress{\n\t\tProtocol: ipv6.ProtocolNumber,\n\t\tAddressWithPrefix: tcpip.AddressWithPrefix{\n\t\t\tAddress:   tcpip.AddrFromSlice(addr.AsSlice()),\n\t\t\tPrefixLen: addr.BitLen(),\n\t\t},\n\t}, stack.AddressProperties{}); err != nil {\n\t\tst.Close()\n\t\treturn nil, fmt.Errorf(\"masquecat: add local gVisor address: %v\", err)\n\t}\n\n\tmtun := newMasqueTun(link)\n"""
new = """\tif err := st.AddProtocolAddress(masqueCoreNIC, tcpip.ProtocolAddress{\n\t\tProtocol: ipv6.ProtocolNumber,\n\t\tAddressWithPrefix: tcpip.AddressWithPrefix{\n\t\t\tAddress:   tcpip.AddrFromSlice(addr.AsSlice()),\n\t\t\tPrefixLen: addr.BitLen(),\n\t\t},\n\t}, stack.AddressProperties{}); err != nil {\n\t\tst.Close()\n\t\treturn nil, fmt.Errorf(\"masquecat: add local gVisor address: %v\", err)\n\t}\n\tif opts.IsServer {\n\t\tif err := st.AddProtocolAddress(masqueCoreNIC, tcpip.ProtocolAddress{\n\t\t\tProtocol: ipv6.ProtocolNumber,\n\t\t\tAddressWithPrefix: tcpip.AddressWithPrefix{\n\t\t\t\tAddress:   tcpip.AddrFromSlice(masqueCorePingAddr.AsSlice()),\n\t\t\t\tPrefixLen: masqueCorePingAddr.BitLen(),\n\t\t\t},\n\t\t}, stack.AddressProperties{}); err != nil {\n\t\t\tst.Close()\n\t\t\treturn nil, fmt.Errorf(\"masquecat: add ping gVisor address: %v\", err)\n\t\t}\n\t}\n\n\tmtun := newMasqueTun(link)\n"""
core.write_text(replace_once(text, old, new, "local gVisor address block"))


test = Path("masquecat_core_test.go")
text = test.read_text()
old_import = """import (\n\t\"bytes\"\n\t\"testing\"\n"""
new_import = """import (\n\t\"bytes\"\n\t\"context\"\n\t\"testing\"\n\t\"time\"\n"""
text = replace_once(text, old_import, new_import, "masquecat_core_test.go import block")
if "func TestMasqueCorePingControlAddress" in text:
    raise SystemExit("ping regression test already exists")
text = text.rstrip() + r'''


type injectingMasqueForwarder struct {
	dst *masqueCore
}

func (f *injectingMasqueForwarder) ForwardPacket(src, _ key.NodePublic, payload []byte) error {
	return f.dst.Inject(src, payload)
}

func TestMasqueCorePingControlAddress(t *testing.T) {
	client, err := newMasqueCore(key.NewNode(), masqueCoreOptions{}, t.Logf)
	if err != nil {
		t.Fatalf("new client core: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	server, err := newMasqueCore(key.NewNode(), masqueCoreOptions{IsServer: true}, t.Logf)
	if err != nil {
		t.Fatalf("new server core: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	if err := client.SetPath(server.pub, &injectingMasqueForwarder{dst: server}); err != nil {
		t.Fatalf("set client path: %v", err)
	}
	if err := server.SetPath(client.pub, &injectingMasqueForwarder{dst: client}); err != nil {
		t.Fatalf("set server path: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Ping(ctx, server.pub); err != nil {
		t.Fatalf("Ping over internal control address: %v", err)
	}
}
''' + "\n"
test.write_text(text)
