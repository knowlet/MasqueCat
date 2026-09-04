// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"net"
	"net/netip"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// cliTCPClient is the transport-neutral subset used by client subcommands that
// only need TCP over a Tailcat connection token.
type cliTCPClient interface {
	DialTCPPort(context.Context, uint16) (net.Conn, error)
	DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
}

func newCLITCPClient(logf logger.Logf, blob tailcat.ConnBlob, priv key.NodePrivate) cliTCPClient {
	if isMasqueBlob(string(blob)) {
		return newMasqueCLIClient(logf, string(blob), priv)
	}
	return newClient(logf, blob, priv)
}

func closeCLITCPClient(cl cliTCPClient) error {
	switch cl := cl.(type) {
	case *tailcat.Client:
		return cl.Close()
	case *tailcat.MasqueClient:
		return cl.Close()
	default:
		return nil
	}
}

func pingCLITCPClient(ctx context.Context, cl cliTCPClient) (tailcat.PingResult, error) {
	switch cl := cl.(type) {
	case *tailcat.Client:
		return cl.Ping(ctx)
	case *tailcat.MasqueClient:
		return cl.Ping(ctx)
	default:
		return tailcat.PingResult{}, nil
	}
}

func validCLIConnBlob(blob tailcat.ConnBlob) bool {
	if isMasqueBlob(string(blob)) {
		_, err := tailcat.ParseMasqueConnBlob(tailcat.MasqueConnBlob(blob))
		return err == nil
	}
	_, err := tailcat.ParseConnBlob(blob)
	return err == nil
}
