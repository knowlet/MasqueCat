//go:build !js

package tailcat

import (
	"bytes"
	"testing"

	"go4.org/mem"
	"tailscale.com/types/key"
)

func FuzzDecodeMasquePacket(f *testing.F) {
	var srcRaw, dstRaw [key.NodePublicRawLen]byte
	for i := range srcRaw {
		srcRaw[i] = 0x11
		dstRaw[i] = 0x22
	}
	src := key.NodePublicFromRaw32(mem.B(srcRaw[:]))
	dst := key.NodePublicFromRaw32(mem.B(dstRaw[:]))
	groundTruth := append([]byte{masquePacketVersion}, srcRaw[:]...)
	groundTruth = append(groundTruth, dstRaw[:]...)
	groundTruth = append(groundTruth, []byte("wire")...)
	if got := encodeMasquePacket(src, dst, []byte("wire")); !bytes.Equal(got, groundTruth) {
		f.Fatalf("canonical packet encoding changed:\n got %x\nwant %x", got, groundTruth)
	}
	decoded, err := decodeMasquePacket(groundTruth)
	if err != nil {
		f.Fatalf("canonical packet rejected: %v", err)
	}
	if decoded.src != src || decoded.dst != dst || string(decoded.payload) != "wire" {
		f.Fatalf("canonical packet decoded incorrectly: %#v", decoded)
	}

	src = key.NewNode().Public()
	dst = key.NewNode().Public()
	for _, payload := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte{0xa5}, 1200)} {
		f.Add(encodeMasquePacket(src, dst, payload))
	}
	f.Add([]byte{})
	f.Add([]byte{masquePacketVersion})

	f.Fuzz(func(t *testing.T, in []byte) {
		pkt, err := decodeMasquePacket(in)
		if err != nil {
			return
		}
		// Any accepted packet must survive a canonical encode/decode cycle.
		canonical := encodeMasquePacket(pkt.src, pkt.dst, pkt.payload)
		got, err := decodeMasquePacket(canonical)
		if err != nil {
			t.Fatalf("canonical packet rejected: %v", err)
		}
		if got.src != pkt.src || got.dst != pkt.dst || !bytes.Equal(got.payload, pkt.payload) {
			t.Fatal("canonical packet changed decoded content")
		}
	})
}

func FuzzParseMasqueConnBlob(f *testing.F) {
	var nodeRaw, discoRaw [32]byte
	for i := range nodeRaw {
		nodeRaw[i] = 0x11
		discoRaw[i] = 0x22
	}
	canonicalInfo := MasqueConnInfo{
		Version:           1,
		ServerPublic:      key.NodePublicFromRaw32(mem.B(nodeRaw[:])),
		ServerDiscoPublic: key.DiscoPublicFromRaw32(mem.B(discoRaw[:])),
		DirectURL:         "https://peer.example:443",
		RelayURL:          "https://relay.example:443",
	}
	const canonicalToken = "mceyJ2IjoxLCJrIjoibm9kZWtleToxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwiZCI6ImRpc2Nva2V5OjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLCJwIjoiaHR0cHM6Ly9wZWVyLmV4YW1wbGU6NDQzIiwiciI6Imh0dHBzOi8vcmVsYXkuZXhhbXBsZTo0NDMifQ"
	canonical, err := canonicalInfo.ConnBlob()
	if err != nil {
		f.Fatal(err)
	}
	if canonical != canonicalToken {
		f.Fatalf("canonical token encoding changed:\n got %s\nwant %s", canonical, canonicalToken)
	}
	parsedCanonical, err := ParseMasqueConnBlob(canonicalToken)
	if err != nil {
		f.Fatalf("canonical token rejected: %v", err)
	}
	if parsedCanonical != canonicalInfo {
		f.Fatalf("canonical token decoded incorrectly: got %#v, want %#v", parsedCanonical, canonicalInfo)
	}

	priv := key.NewNode()
	valid, err := (MasqueConnInfo{
		Version:           1,
		ServerPublic:      priv.Public(),
		ServerDiscoPublic: DiscoPublicForNode(priv).DiscoPublic,
		DirectURL:         "https://peer.example:443",
		RelayURL:          "https://relay.example:443",
	}).ConnBlob()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(valid))
	f.Add("")
	f.Add("mc")
	f.Add("tcdeadbeef")

	f.Fuzz(func(t *testing.T, raw string) {
		ci, err := ParseMasqueConnBlob(MasqueConnBlob(raw))
		if err != nil {
			return
		}
		blob, err := ci.ConnBlob()
		if err != nil {
			t.Fatalf("accepted token cannot be re-serialized: %v", err)
		}
		if _, err := ParseMasqueConnBlob(blob); err != nil {
			t.Fatalf("canonical token cannot be parsed: %v", err)
		}
	})
}
