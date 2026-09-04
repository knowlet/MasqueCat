//go:build !js

package tailcat

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/types/key"
)

const (
	// QUIC requires endpoints to be able to send 1200-byte UDP payloads. Keep
	// each MasqueCat application datagram comfortably below that floor after
	// accounting for the HTTP Datagram context ID, the 65-byte MasqueCat peer
	// header, QUIC short-header / packet-number / AEAD overhead, and the fragment
	// header below. A 1000-byte WireGuard fragment produces a 1086-byte HTTP
	// Datagram payload (1 + 65 + 20 + 1000), leaving more than 100 bytes for the
	// QUIC packet envelope even on the minimum-size path.
	masqueWGFragmentChunkSize          = 1000
	masqueWGFragmentHeaderLen          = 20
	masqueWGFragmentMaxSize            = 64 << 10
	masqueWGFragmentTTL                = 30 * time.Second
	masqueWGMaxAssemblies              = 256
	masqueWGMaxAssembliesPerSource     = 32
)

var (
	// WireGuard messages start with a little-endian uint32 message type in the
	// range 1..4. This marker therefore cannot collide with a valid current
	// WireGuard message at offset zero.
	masqueWGFragmentMagic = [4]byte{'M', 'C', 'F', 1}
	masqueWGFragmentSeq   atomic.Uint64
)

type masqueWGFragmentKey struct {
	src key.NodePublic
	id  uint64
}

type masqueWGFragmentAssembly struct {
	count    uint16
	total    uint32
	parts    [][]byte
	received int
	updated  time.Time
}

type masqueWGReassembler struct {
	mu   sync.Mutex
	sets map[masqueWGFragmentKey]*masqueWGFragmentAssembly
}

func nextMasqueWGFragmentID() uint64 {
	// The timestamp makes reuse across process restarts vanishingly unlikely,
	// while the atomic sequence guarantees uniqueness for concurrent sends in a
	// single process even when multiple fragments are created in one nanosecond.
	return uint64(time.Now().UnixNano()) + masqueWGFragmentSeq.Add(1)
}

func fragmentMasqueWireGuardPacket(payload []byte) ([][]byte, error) {
	if len(payload) <= masqueWGFragmentChunkSize {
		return nil, nil
	}
	if len(payload) > masqueWGFragmentMaxSize {
		return nil, fmt.Errorf("masquecat: WireGuard packet too large to fragment: %d bytes", len(payload))
	}
	count := (len(payload) + masqueWGFragmentChunkSize - 1) / masqueWGFragmentChunkSize
	if count > int(^uint16(0)) {
		return nil, fmt.Errorf("masquecat: WireGuard packet needs too many fragments: %d", count)
	}

	id := nextMasqueWGFragmentID()
	fragments := make([][]byte, 0, count)
	for i, off := 0, 0; off < len(payload); i, off = i+1, off+masqueWGFragmentChunkSize {
		end := off + masqueWGFragmentChunkSize
		if end > len(payload) {
			end = len(payload)
		}
		fragment := make([]byte, masqueWGFragmentHeaderLen+end-off)
		copy(fragment[:4], masqueWGFragmentMagic[:])
		binary.BigEndian.PutUint64(fragment[4:12], id)
		binary.BigEndian.PutUint16(fragment[12:14], uint16(i))
		binary.BigEndian.PutUint16(fragment[14:16], uint16(count))
		binary.BigEndian.PutUint32(fragment[16:20], uint32(len(payload)))
		copy(fragment[masqueWGFragmentHeaderLen:], payload[off:end])
		fragments = append(fragments, fragment)
	}
	return fragments, nil
}

func (r *masqueWGReassembler) Reset() {
	r.mu.Lock()
	r.sets = nil
	r.mu.Unlock()
}

func (r *masqueWGReassembler) cleanupLocked(now time.Time) {
	for k, set := range r.sets {
		if now.Sub(set.updated) >= masqueWGFragmentTTL {
			delete(r.sets, k)
		}
	}
}

func (r *masqueWGReassembler) sourceAssemblyCountLocked(src key.NodePublic) int {
	count := 0
	for k := range r.sets {
		if k.src == src {
			count++
		}
t}
	return count
}

func (r *masqueWGReassembler) Push(src key.NodePublic, payload []byte) ([]byte, bool, error) {
	if !bytes.HasPrefix(payload, masqueWGFragmentMagic[:]) {
		return payload, true, nil
	}
	if len(payload) < masqueWGFragmentHeaderLen {
		return nil, false, fmt.Errorf("masquecat: short WireGuard fragment header: %d bytes", len(payload))
	}

	id := binary.BigEndian.Uint64(payload[4:12])
	index := binary.BigEndian.Uint16(payload[12:14])
	count := binary.BigEndian.Uint16(payload[14:16])
	total := binary.BigEndian.Uint32(payload[16:20])
	chunk := payload[masqueWGFragmentHeaderLen:]

	if count < 2 || index >= count {
		return nil, false, fmt.Errorf("masquecat: invalid WireGuard fragment index %d/%d", index, count)
	}
	if total <= masqueWGFragmentChunkSize || total > masqueWGFragmentMaxSize {
		return nil, false, fmt.Errorf("masquecat: invalid WireGuard fragmented size %d", total)
	}
	expectedCount := (int(total) + masqueWGFragmentChunkSize - 1) / masqueWGFragmentChunkSize
	if int(count) != expectedCount {
		return nil, false, fmt.Errorf("masquecat: WireGuard fragment count %d does not match size %d", count, total)
	}
	expectedChunkLen := masqueWGFragmentChunkSize
	if int(index) == expectedCount-1 {
		expectedChunkLen = int(total) - (expectedCount-1)*masqueWGFragmentChunkSize
	}
	if len(chunk) != expectedChunkLen {
		return nil, false, fmt.Errorf("masquecat: WireGuard fragment %d has %d bytes, want %d", index, len(chunk), expectedChunkLen)
	}

	now := time.Now()
	key := masqueWGFragmentKey{src: src, id: id}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sets == nil {
		r.sets = make(map[masqueWGFragmentKey]*masqueWGFragmentAssembly)
	}
	r.cleanupLocked(now)

	set := r.sets[key]
	if set == nil {
		if r.sourceAssemblyCountLocked(src) >= masqueWGMaxAssembliesPerSource {
			return nil, false, fmt.Errorf("masquecat: too many incomplete WireGuard fragment assemblies for source")
		}
		if len(r.sets) >= masqueWGMaxAssemblies {
			return nil, false, fmt.Errorf("masquecat: too many incomplete WireGuard fragment assemblies")
		}
		set = &masqueWGFragmentAssembly{
			count:   count,
			total:   total,
			parts:   make([][]byte, count),
			updated: now,
		}
		r.sets[key] = set
	} else if set.count != count || set.total != total {
		delete(r.sets, key)
		return nil, false, fmt.Errorf("masquecat: inconsistent WireGuard fragment metadata")
	}

	if old := set.parts[index]; old != nil {
		if bytes.Equal(old, chunk) {
			// Duplicates are not forward progress. Do not refresh the TTL here,
			// otherwise an incomplete assembly can be pinned indefinitely by
			// repeatedly replaying one already-received fragment.
			return nil, false, nil
		}
		delete(r.sets, key)
		return nil, false, fmt.Errorf("masquecat: conflicting duplicate WireGuard fragment %d", index)
	}
	set.parts[index] = append([]byte(nil), chunk...)
	set.received++
	set.updated = now
	if set.received != int(set.count) {
		return nil, false, nil
	}

	out := make([]byte, 0, int(set.total))
	for _, part := range set.parts {
		if part == nil {
			return nil, false, nil
		}
		out = append(out, part...)
	}
	delete(r.sets, key)
	if len(out) != int(set.total) {
		return nil, false, fmt.Errorf("masquecat: reassembled WireGuard packet has %d bytes, want %d", len(out), set.total)
	}
	return out, true, nil
}
