package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	"layzmd/internal/httpget"
)

// fakeClock is a deterministic clock for tests. Sleep records the duration
// and advances the fake "now" — no real sleeping occurs.
type fakeClock struct {
	t     time.Time
	slept []time.Duration
}

func (f *fakeClock) clock() Clock {
	return Clock{
		Now: func() time.Time { return f.t },
		Sleep: func(_ context.Context, d time.Duration) error {
			f.slept = append(f.slept, d)
			f.t = f.t.Add(d)
			return nil
		},
	}
}

// TestLimiter_BurstThenBlock: limit=2, window=30s.
// First two Waits burst (no sleep). Third Wait blocks until the oldest
// in-window grant ages out (30s sleep).
func TestLimiter_BurstThenBlock(t *testing.T) {
	fc := &fakeClock{t: time.Unix(0, 0)}
	lim := NewLimiterWithClock(2, 30*time.Second, fc.clock())
	ctx := context.Background()

	if err := lim.Wait(ctx); err != nil {
		t.Fatalf("Wait 1: %v", err)
	}
	if err := lim.Wait(ctx); err != nil {
		t.Fatalf("Wait 2: %v", err)
	}
	// After two bursts, no sleep should have occurred.
	if len(fc.slept) != 0 {
		t.Fatalf("expected no sleeps after burst, got %v", fc.slept)
	}

	if err := lim.Wait(ctx); err != nil {
		t.Fatalf("Wait 3: %v", err)
	}
	// Exactly one sleep: wait for oldest grant (at t=0) to age out of the
	// 30s window (now is still t=0 from the fake clock's perspective).
	if len(fc.slept) != 1 {
		t.Fatalf("expected 1 sleep, got %d: %v", len(fc.slept), fc.slept)
	}
	if fc.slept[0] != 30*time.Second {
		t.Fatalf("expected sleep of 30s, got %v", fc.slept[0])
	}
}

// TestLimiter_SlotFreesAfterWindow: limit=1, window=10s.
// Wait (immediate), advance clock past window, Wait again → no sleep.
func TestLimiter_SlotFreesAfterWindow(t *testing.T) {
	fc := &fakeClock{t: time.Unix(0, 0)}
	lim := NewLimiterWithClock(1, 10*time.Second, fc.clock())
	ctx := context.Background()

	if err := lim.Wait(ctx); err != nil {
		t.Fatalf("Wait 1: %v", err)
	}
	// Advance clock past the window so the grant ages out.
	fc.t = fc.t.Add(10 * time.Second)

	if err := lim.Wait(ctx); err != nil {
		t.Fatalf("Wait 2: %v", err)
	}
	if len(fc.slept) != 0 {
		t.Fatalf("expected no sleep when slot freed by window, got %v", fc.slept)
	}
}

// TestLimiter_MinIntervalIsLimit1: limit=1, window=1s.
// Two back-to-back Waits → second sleeps exactly 1s.
func TestLimiter_MinIntervalIsLimit1(t *testing.T) {
	fc := &fakeClock{t: time.Unix(0, 0)}
	lim := NewLimiterWithClock(1, time.Second, fc.clock())
	ctx := context.Background()

	if err := lim.Wait(ctx); err != nil {
		t.Fatalf("Wait 1: %v", err)
	}
	if err := lim.Wait(ctx); err != nil {
		t.Fatalf("Wait 2: %v", err)
	}
	if len(fc.slept) != 1 || fc.slept[0] != time.Second {
		t.Fatalf("expected exactly 1s sleep, got %v", fc.slept)
	}
}

// TestRetry_429ThenOK: fn returns 429 on first call, nil on second.
// Retry returns nil; fn called twice; one backoff sleep of base (1s).
func TestRetry_429ThenOK(t *testing.T) {
	fc := &fakeClock{t: time.Unix(0, 0)}
	calls := 0
	fn := func() error {
		calls++
		if calls == 1 {
			return &httpget.HTTPError{StatusCode: 429}
		}
		return nil
	}

	err := Retry(context.Background(), 2, time.Second, fc.clock(), fn)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected fn called 2 times, got %d", calls)
	}
	if len(fc.slept) != 1 || fc.slept[0] != time.Second {
		t.Fatalf("expected one 1s sleep, got %v", fc.slept)
	}
}

// TestRetry_NonRetryable: fn returns 404 → Retry returns error immediately,
// fn called once, no sleep.
func TestRetry_NonRetryable(t *testing.T) {
	fc := &fakeClock{t: time.Unix(0, 0)}
	want := &httpget.HTTPError{StatusCode: 404}
	calls := 0
	fn := func() error {
		calls++
		return want
	}

	err := Retry(context.Background(), 2, time.Second, fc.clock(), fn)
	if !errors.Is(err, want) {
		t.Fatalf("expected 404 error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected fn called once, got %d", calls)
	}
	if len(fc.slept) != 0 {
		t.Fatalf("expected no sleeps, got %v", fc.slept)
	}
}

// TestRetry_Exhausted: fn always returns 503 → after attempts retries
// returns the last error; sleeps are 1s, 2s (base<<0, base<<1).
func TestRetry_Exhausted(t *testing.T) {
	fc := &fakeClock{t: time.Unix(0, 0)}
	retryable := &httpget.HTTPError{StatusCode: 503}
	calls := 0
	fn := func() error {
		calls++
		return retryable
	}

	err := Retry(context.Background(), 2, time.Second, fc.clock(), fn)
	var he *httpget.HTTPError
	if !errors.As(err, &he) || he.StatusCode != 503 {
		t.Fatalf("expected 503 error, got %v", err)
	}
	// attempts=2 means 2 retries → 3 total calls (initial + 2 retries).
	if calls != 3 {
		t.Fatalf("expected 3 calls (initial + 2 retries), got %d", calls)
	}
	// Sleeps: base<<0 = 1s, base<<1 = 2s.
	if len(fc.slept) != 2 || fc.slept[0] != time.Second || fc.slept[1] != 2*time.Second {
		t.Fatalf("expected sleeps [1s, 2s], got %v", fc.slept)
	}
}

// TestRetry_RetryAfterOverrides: fn returns 429 with RetryAfter=5s on first
// call (base=1s → RetryAfter wins), nil on second → sleep is 5s.
func TestRetry_RetryAfterOverrides(t *testing.T) {
	fc := &fakeClock{t: time.Unix(0, 0)}
	calls := 0
	fn := func() error {
		calls++
		if calls == 1 {
			return &httpget.HTTPError{StatusCode: 429, RetryAfter: 5 * time.Second}
		}
		return nil
	}

	err := Retry(context.Background(), 2, time.Second, fc.clock(), fn)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected fn called 2 times, got %d", calls)
	}
	if len(fc.slept) != 1 || fc.slept[0] != 5*time.Second {
		t.Fatalf("expected one 5s sleep (RetryAfter), got %v", fc.slept)
	}
}
