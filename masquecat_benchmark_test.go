//go:build !js

package tailcat

import (
	"fmt"
	"testing"

	"tailscale.com/types/key"
)

func BenchmarkEncodeMasquePacket(b *testing.B) {
	src := key.NewNode().Public()
	dst := key.NewNode().Public()
	for _, size := range []int{64, 256, 1200, 1400, 4096} {
		b.Run(fmt.Sprintf("payload_%d", size), func(b *testing.B) {
			payload := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				_ = encodeMasquePacket(src, dst, payload)
			}
		})
	}
}

func BenchmarkDecodeMasquePacket(b *testing.B) {
	src := key.NewNode().Public()
	dst := key.NewNode().Public()
	for _, size := range []int{64, 256, 1200, 1400, 4096} {
		b.Run(fmt.Sprintf("payload_%d", size), func(b *testing.B) {
			packet := encodeMasquePacket(src, dst, make([]byte, size))
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				if _, err := decodeMasquePacket(packet); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMasqueTargetRoundTrip(b *testing.B) {
	k := key.NewNode().Public()
	target := masqueTarget(k)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseMasqueTarget(target); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMasqueConnBlobRoundTrip(b *testing.B) {
	priv := key.NewNode()
	ci := MasqueConnInfo{
		Version:           1,
		ServerPublic:      priv.Public(),
		ServerDiscoPublic: DiscoPublicForNode(priv).DiscoPublic,
		DirectURL:         "https://peer.example:443",
		RelayURL:          "https://relay.example:443",
	}
	b.ReportAllocs()
	for b.Loop() {
		blob, err := ci.ConnBlob()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := ParseMasqueConnBlob(blob); err != nil {
			b.Fatal(err)
		}
	}
}
