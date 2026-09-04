//go:build !js

package tailcat

import (
	"testing"

	"tailscale.com/types/key"
)

func TestMasqueRelayReservationRejectsDuplicateBeforeActivation(t *testing.T) {
	r := new(MasqueRelay)
	k := key.NewNode().Public()

	first, ok := r.reserve(k)
	if !ok {
		t.Fatal("first reservation rejected")
	}
	if got := r.lookup(k); got != nil {
		t.Fatalf("reserved peer became routable before activation: %p", got)
	}
	if _, ok := r.reserve(k); ok {
		t.Fatal("duplicate reservation unexpectedly succeeded")
	}

	stream := newFakeMasqueDatagramStream()
	if !r.activate(first, &streamForwarder{str: stream}) {
		t.Fatal("activating reserved peer failed")
	}
	if got := r.lookup(k); got != first {
		t.Fatalf("lookup after activation = %p, want %p", got, first)
	}

	r.unregister(first)
	if got := r.lookup(k); got != nil {
		t.Fatalf("lookup after unregister = %p, want nil", got)
	}
	if _, ok := r.reserve(k); !ok {
		t.Fatal("reservation was not released after unregister")
	}
}

func TestMasqueRelayReservationReleaseAfterFailedAcceptance(t *testing.T) {
	r := new(MasqueRelay)
	k := key.NewNode().Public()

	peer, ok := r.reserve(k)
	if !ok {
		t.Fatal("reservation rejected")
	}
	// Handler defers unregister immediately after reserve, so an acceptance
	// failure releases the key without ever publishing a forwarder.
	r.unregister(peer)
	if got := r.lookup(k); got != nil {
		t.Fatalf("failed reservation remained routable: %p", got)
	}
	if _, ok := r.reserve(k); !ok {
		t.Fatal("key remained reserved after failed acceptance cleanup")
	}
}
