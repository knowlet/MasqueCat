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
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("ping: %w", errors.Join(err, lastErr))
		}
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := ping(pctx)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		log.Printf("ping attempt failed: %v", err)
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("ping: %w", errors.Join(ctx.Err(), lastErr))
		case <-timer.C:
		}
	}
}

// ValidateAddress rejects malformed tokens before retryable network work. Permanent
// parse errors cannot improve on a retry and must not monopolize the WASM loop.
func ValidateAddress(addr string) error {
	if !strings.HasPrefix(addr, "mc") {
		ci, err := tailcat.ParseConnBlob(tailcat.ConnBlob(addr))
		// Both keys are required: the node key identifies the peer and the
		// disco key is needed to reach it. Without either, retries cannot help.
		if err != nil || ci.ServerPublic.IsZero() || ci.ServerDiscoPublic.IsZero() {
			return errors.New("invalid Tailcat token")
		}
		// A token must name a DERP region by ID, or embed one that has a
		// node. Expand is a no-op once any inline region is present, so an
		// empty inline region is never filled in and every ping fails
		// until the retry budget runs out.
		if !legacyDERPReachable(ci) {
			return errors.New("invalid Tailcat token")
		}
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
	// net/url accepts ports above 65535 and hosts the browser URL parser
	// rejects (invalid IPv4, IPv6 literals, and IDNA). The WebTransport
	// constructor throws synchronously for those URLs instead of returning
	// a rejected promise, which panics the WASM program.
	if !browserCanParseURL(ci.RelayURL) {
		return errors.New("invalid MasqueCat token")
	}
	return nil
}

// legacyDERPReachable reports whether a parsed legacy token can reach a
// DERP relay without a retry. A region ID is resolved from the DERP map
// later. An inline region replaces that lookup, so it has to carry a node.
func legacyDERPReachable(ci tailcat.ConnInfo) bool {
	if len(ci.Region) == 0 {
		return ci.RegionID != 0
	}
	for _, region := range ci.Region {
		if region != nil && len(region.Nodes) > 0 {
			return true
		}
	}
	return false
}
