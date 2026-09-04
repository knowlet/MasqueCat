package tailcat

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"tailscale.com/types/key"
)

const (
	masqueWGFragmentVersion            = 1
	masqueWGFragmentHeaderLen          = 20
	masqueWGFragmentChunkSize          = 960
	masqueWGFragmentMaxSize            = 64 << 10
	masqueWGMaxAssemblies              = 256
	masqueWGMaxAssembliesPerSource     = 32
	masqueWGFragmentAssemblyExpiration = 30 * time.Second
)

var masqueWGFragmentMagic = [4]byte{'M', 'C', 'F', masqueWGFragmentVersion}

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

func (r *masqueWGReassembler) Reset() {
	r.mu.Lock()
	r.sets = nil
	r.mu.Unlock()
}

func (r *masqueWGReassembler) cleanupLocked(now time.Time) {
	for k, set := range r.sets {
		if now.Sub(set.updated) >= masqueWGFragmentAssemblyExpiration {
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
	}
	return count
}

func fragmentMasqueWireGuardPacket(payload []byte) ([][]byte, error) {
	if len(payload) <= masqueWGFragmentChunkSize {
		return nil, nil
	}
	if len(payload) > masqueWGFragmentMaxSize {
		return nil, fmt.Errorf("masquecat: WireGuard packet exceeds %d-byte fragmentation limit", masqueWGFragmentMaxSize)
	}
	count := (len(payload) + masqueWGFragmentChunkSize - 1) / masqueWGFragmentChunkSize
	if count > int(^uint16(0)) {
		return nil, fmt.Errorf("masquecat: WireGuard packet needs too many fragments: %d", count)
	}
	var idBytes [8]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, fmt.Errorf("masquecat: generate fragment id: %w", err)
	}
	id := binary.BigEndian.Uint64(idBytes[:])
	fragments := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		start := i * masqueWGFragmentChunkSize
		end := start + masqueWGFragmentChunkSize
		if end > len(payload) {
			end = len(payload)
		}
		fragment := make([]byte, masqueWGFragmentHeaderLen+end-start)
		copy(fragment[:4], masqueWGFragmentMagic[:])
		binary.BigEndian.PutUint64(fragment[4:12], id)
		binary.BigEndian.PutUint16(fragment[12:14], uint16(i))
		binary.BigEndian.PutUint16(fragment[14:16], uint16(count))
		binary.BigEndian.PutUint32(fragment[16:20], uint32(len(payload)))
		copy(fragment[masqueWGFragmentHeaderLen:], payload[start:end])
		fragments = append(fragments, fragment)
	}
	return fragments, nil
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
			// A duplicate is not forward progress. In particular, do not refresh
			// the assembly TTL here: otherwise one tiny duplicate can pin an
			// incomplete assembly forever and exhaust the shared reassembly quota.
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
