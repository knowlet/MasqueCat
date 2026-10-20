// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package tailcat

import (
	"context"
	"strings"
	"testing"

	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
)

func TestPickBestRegionRejectsUnavailableInterfaceState(t *testing.T) {
	// A zero monitor models NewStatic's nil snapshot after interface enumeration
	// fails (for example when a sandbox denies netlink). No probe must be started.
	dm := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1, Nodes: []*tailcfg.DERPNode{{Name: "test", RegionID: 1, IPv4: "127.0.0.1"}}}}}
	region, err := pickBestRegion(context.Background(), dm, &netmon.Monitor{})
	if err == nil || !strings.Contains(err.Error(), "network interface state unavailable") {
		t.Fatalf("got region=%d, err=%v; want unavailable interface error", region, err)
	}
	if region != 0 {
		t.Fatalf("unexpected region %d on failure", region)
	}
}
