package browserdial

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
)

func TestPingUntilImmediateFailureIsRateLimited(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	calls := 0
	err := PingUntil(ctx, func(context.Context) (tailcat.PingResult, error) {
		calls++
		return tailcat.PingResult{}, errors.New("synthetic failure")
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	if calls > 2 {
		t.Fatalf("immediate errors caused %d retry attempts in 60ms", calls)
	}
}
func TestPingUntilCancelledDoesNotStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := PingUntil(ctx, func(context.Context) (tailcat.PingResult, error) { calls++; return tailcat.PingResult{}, nil })
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
func TestPingUntilSuccess(t *testing.T) {
	calls := 0
	err := PingUntil(context.Background(), func(context.Context) (tailcat.PingResult, error) { calls++; return tailcat.PingResult{}, nil })
	if err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestInvalidMasqueTokenIsRejected(t *testing.T) {
	if err := ValidateAddress("mc!"); err == nil {
		t.Fatal("invalid token accepted")
	}
}
func TestLegacyAddressIsNotParsedAsMasque(t *testing.T) {
	if err := ValidateAddress("tc-synthetic"); err != nil {
		t.Fatal(err)
	}
}

func TestPingUntilRetriesTransientFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	calls := 0
	err := PingUntil(ctx, func(context.Context) (tailcat.PingResult, error) {
		calls++
		if calls == 1 {
			return tailcat.PingResult{}, errors.New("transient")
		}
		return tailcat.PingResult{}, nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
func TestBrowserAddressRequiresRelay(t *testing.T) {
	priv := key.NewNode()
	ci := tailcat.MasqueConnInfo{ServerPublic: priv.Public(), ServerDiscoPublic: tailcat.DiscoPublicForNode(priv).DiscoPublic, DirectURL: "https://127.0.0.1:4433"}
	blob, err := ci.ConnBlob()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAddress(string(blob)); err == nil {
		t.Fatal("direct-only token accepted")
	}
	ci.RelayURL = "https://127.0.0.1:4434"
	blob, err = ci.ConnBlob()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAddress(string(blob)); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidMasqueTokenDoesNotEchoPayload(t *testing.T) {
	payload := `{"v":1,"k":"not-a-key-sensitive-marker"}`
	blob := "mc" + base64.RawURLEncoding.EncodeToString([]byte(payload))
	if err := ValidateAddress(blob); err == nil || err.Error() != "invalid MasqueCat token" {
		t.Fatalf("unexpected validation result: %v", err)
	}
}
