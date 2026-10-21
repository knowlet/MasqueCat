// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package browserdial

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/tailscale/tailcat"
)

// PingUntil retries failed probes without starving the browser event loop.
func PingUntil(ctx context.Context, ping func(context.Context) (tailcat.PingResult, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("ping: %w", err)
		}
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := ping(pctx)
		cancel()
		if err == nil {
			return nil
		}
		log.Printf("ping attempt failed: %v", err)
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("ping: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

// ValidateAddress rejects malformed tokens before retryable network work. Permanent
// parse errors cannot improve on a retry and must not monopolize the WASM loop.
func ValidateAddress(addr string) error {
	if !strings.HasPrefix(addr, "mc") {
		return nil
	}
	ci, err := tailcat.ParseMasqueConnBlob(tailcat.MasqueConnBlob(addr))
	if err != nil {
		// Parser errors can contain endpoint URLs; do not echo token payloads.
		return errors.New("invalid MasqueCat token")
	}
	if ci.RelayURL == "" {
		return errors.New("MasqueCat browser connections require a relay URL")
	}
	return nil
}
