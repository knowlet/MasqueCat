// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package tailcat

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// PickBestRegion runs a netcheck over the DERP regions in dm and
// returns the region ID with the lowest latency. It returns 0 (and a
// nil error) if the netcheck report contained no usable region
// latencies.
func PickBestRegion(ctx context.Context, dm *tailcfg.DERPMap) (regionID tailcfg.DERPRegionID, err error) {
	return pickBestRegion(ctx, dm, netmon.NewStatic())
}

func pickBestRegion(ctx context.Context, dm *tailcfg.DERPMap, monitor *netmon.Monitor) (regionID tailcfg.DERPRegionID, err error) {
	// NewStatic intentionally hides interface enumeration errors. Never pass a
	// missing snapshot to netcheck, whose probe planner dereferences it.
	if monitor == nil || monitor.InterfaceState() == nil {
		return 0, errors.New("network interface state unavailable; cannot select a DERP region")
	}
	nc := &netcheck.Client{
		NetMon:  monitor,
		Verbose: Verbose,
		Logf:    logger.Discard,
	}
	if Verbose {
		nc.Logf = log.Printf
	}
	if err := nc.Standalone(ctx, ":0"); err != nil {
		return 0, fmt.Errorf("netcheck.Standalone: %w", err)
	}
	t0 := time.Now()
	nr, err := nc.GetReport(ctx, dm, &netcheck.GetReportOpts{})
	if err != nil {
		return 0, fmt.Errorf("failed to get netcheck report: %w", err)
	}
	if Verbose {
		log.Printf("Got netcheck after %v: %v", time.Since(t0), logger.AsJSON(nr))
	}
	bestLatency := time.Hour
	for rid, d := range nr.RegionLatency {
		if _, ok := dm.Regions[rid]; !ok {
			continue // shouldn't happen
		}
		if d < bestLatency {
			bestLatency = d
			regionID = rid
		}
	}
	return regionID, nil
}
