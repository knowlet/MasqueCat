//go:build !js

package tailcat

import (
	"testing"

	"tailscale.com/types/key"
)

func TestDirectMasqueReservationsRejectDuplicate(t *testing.T) {
	var r directMasqueReservations
	peer := key.NewNode().Public()

	if !r.reserve(peer) {
		t.Fatal("first direct reservation rejected")
	}
	if r.reserve(peer) {
		t.Fatal("duplicate direct reservation unexpectedly succeeded")
	}

	r.release(peer)
	if !r.reserve(peer) {
		t.Fatal("direct reservation was not released")
	}
}

func TestDirectMasqueReservationsArePerPeer(t *testing.T) {
	var r directMasqueReservations
	first := key.NewNode().Public()
	second := key.NewNode().Public()

	if !r.reserve(first) {
		t.Fatal("first peer reservation rejected")
	}
	if !r.reserve(second) {
		t.Fatal("second peer reservation rejected")
	}
}
