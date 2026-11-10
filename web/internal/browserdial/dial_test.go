package browserdial

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"testing/synctest"
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
	priv := key.NewNode()
	ci := &tailcat.ConnInfo{
		ServerPublic:      tailcat.NodePublic{NodePublic: priv.Public()},
		ServerDiscoPublic: tailcat.DiscoPublicForNode(priv),
	}
	if err := ValidateAddress(string(ci.ConnBlob())); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyAddressWithoutDiscoKeyIsRejected(t *testing.T) {
	ci := &tailcat.ConnInfo{ServerPublic: tailcat.NodePublic{NodePublic: key.NewNode().Public()}}
	blob := ci.ConnBlob()
	parsed, err := tailcat.ParseConnBlob(blob)
	if err != nil {
		t.Fatalf("legacy token must remain parseable: %v", err)
	}
	if !parsed.ServerDiscoPublic.IsZero() {
		t.Fatal("fixture unexpectedly contains a disco key")
	}
	if err := ValidateAddress(string(blob)); err == nil || err.Error() != "invalid Tailcat token" {
		t.Fatalf("unexpected validation result: %v", err)
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

func TestInvalidLegacyAndUnknownAddressesAreRejected(t *testing.T) {
	for _, addr := range []string{"tc!", "tc-synthetic", "unknown", ""} {
		if err := ValidateAddress(addr); err == nil || err.Error() != "invalid Tailcat token" {
			t.Errorf("ValidateAddress(%q) = %v", addr, err)
		}
	}
}

func TestPingUntilCancellationDuringBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cause := errors.New("synthetic transport failure")
		done := make(chan error, 1)
		go func() {
			done <- PingUntil(ctx, func(context.Context) (tailcat.PingResult, error) { return tailcat.PingResult{}, cause })
		}()
		synctest.Wait() // PingUntil is now durably blocked in its backoff.
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) {
				t.Fatalf("lost cancellation or transport cause: %v", err)
			}
		default:
			t.Fatal("cancellation did not interrupt the backoff")
		}
	})
}
