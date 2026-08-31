//go:build !js

package tailcat

import (
	"bytes"
	"testing"

	"tailscale.com/types/key"
)

func FuzzDecodeMasquePacket(f *testing.F) {
	src := key.NewNode().Public()
	dst := key.NewNode().Public()
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
