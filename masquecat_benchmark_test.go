//go:build !js

package tailcat

import (
	"fmt"
	"testing"

	"tailscale.com/types/key"
)

var (
	benchmarkPacketBytes []byte
	benchmarkPacket      masquePacket
	benchmarkPeerKey     key.NodePublic
	benchmarkConnBlob    MasqueConnBlob
	benchmarkConnInfo    MasqueConnInfo
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
				benchmarkPacketBytes = encodeMasquePacket(src, dst, payload)
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
				got, err := decodeMasquePacket(packet)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkPacket = got
			}
		})
	}
}

func BenchmarkMasqueTargetRoundTrip(b *testing.B) {
	k := key.NewNode().Public()
	target := masqueTarget(k)
	b.ReportAllocs()
	for b.Loop() {
		got, err := parseMasqueTarget(target)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkPeerKey = got
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
		got, err := ParseMasqueConnBlob(blob)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkConnBlob = blob
		benchmarkConnInfo = got
	}
}
