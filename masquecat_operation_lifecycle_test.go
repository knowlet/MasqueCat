//go:build !js

package tailcat

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMasqueOperationContextCanceledByLifecycle(t *testing.T) {
	lifecycleCtx, cancelLifecycle := context.WithCancel(context.Background())
	opCtx, stop := masqueOperationContext(context.Background(), lifecycleCtx)
	defer stop()

	cancelLifecycle()
	select {
	case <-opCtx.Done():
		if !errors.Is(opCtx.Err(), context.Canceled) {
			t.Fatalf("operation context error = %v, want canceled", opCtx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("lifecycle cancellation did not cancel operation context")
	}
}

func TestMasqueClientCloseCancelsAndWaitsForActiveLease(t *testing.T) {
	lifecycleCtx, cancelLifecycle := context.WithCancel(context.Background())
	c := &MasqueClient{
		core:         new(masqueCore),
		lifecycleCtx: lifecycleCtx,
		cancel:       cancelLifecycle,
		started:      true,
	}

	_, _, opCtx, release, err := c.acquireCore(context.Background())
	if err != nil {
		t.Fatalf("acquireCore: %v", err)
	}

	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()

	select {
	case <-opCtx.Done():
		// Close must be able to acquire c.mu and cancel the lifecycle even while
		// the lease remains active.
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel an active operation lease")
	}

	select {
	case err := <-closed:
		t.Fatalf("Close returned before active operation released its lease: %v", err)
	default:
	}

	release()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after operation lease release")
	}
}
