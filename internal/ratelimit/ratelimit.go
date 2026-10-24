// Package ratelimit provides a sliding-window rate limiter and a
// retry-with-exponential-backoff helper, both driven by an injectable Clock so
// tests never sleep for real.
package ratelimit

import (
	"context"
	"errors"
	"sync"
	"time"

	"layzmd/internal/httpget"
)

// Clock bundles the two time-related side effects that Limiter and Retry need.
// Inject a fake implementation in tests to avoid real sleeping.
type Clock struct {
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// SystemClock returns a Clock backed by the real wall clock. Sleep is
// context-aware: it returns ctx.Err() if the context is cancelled before the
// duration elapses.
func SystemClock() Clock {
	return Clock{
		Now: time.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
}

// Limiter is a sliding-window rate limiter. It allows up to limit grants
// within any rolling window of the given duration. The first limit calls to
// Wait burst with no delay; subsequent calls block until a slot opens.
// Limiter is safe for concurrent use.
type Limiter struct {
	limit  int
	window time.Duration
	clock  Clock
	mu     sync.Mutex
	grants []time.Time // timestamps of recent grants still inside the window
}

// NewLimiter returns a Limiter using the system clock.
func NewLimiter(limit int, window time.Duration) *Limiter {
	return NewLimiterWithClock(limit, window, SystemClock())
}

// NewLimiterWithClock returns a Limiter using the provided Clock. Use this in
// tests to inject a deterministic fake clock.
func NewLimiterWithClock(limit int, window time.Duration, c Clock) *Limiter {
	return &Limiter{
		limit:  limit,
		window: window,
		clock:  c,
	}
}

// Wait blocks until a rate-limit slot is available, then records the grant and
// returns. It returns ctx.Err() if the context is cancelled while waiting.
//
// Algorithm (sliding window):
//  1. Check ctx cancellation.
//  2. Record now; drop grants older than now-window from the front of grants.
//  3. If len(grants) < limit: append now, return nil (burst path).
//  4. Else compute sleep = grants[0]+window-now (time until oldest ages out),
//     sleep (honoring ctx), then loop back to step 1.
func (l *Limiter) Wait(ctx context.Context) error {
	for {
		// Step 1: respect context cancellation.
		if err := ctx.Err(); err != nil {
			return err
		}

		l.mu.Lock()

		// Step 2: evict grants that have slid out of the window.
		now := l.clock.Now()
		cutoff := now.Add(-l.window)
		i := 0
		for i < len(l.grants) && !l.grants[i].After(cutoff) {
			i++
		}
		l.grants = l.grants[i:]

		if len(l.grants) < l.limit {
			// Step 3: burst — a slot is free; record the grant and return.
			l.grants = append(l.grants, now)
			l.mu.Unlock()
			return nil
		}

		// Step 4: at capacity — compute how long until the oldest grant ages out.
		wait := l.grants[0].Add(l.window).Sub(now)
		l.mu.Unlock()

		if err := l.clock.Sleep(ctx, wait); err != nil {
			return err
		}
		// Loop: re-evaluate now that time has advanced.
	}
}

// retryable status codes — only these trigger a retry in Retry.
var retryableCodes = map[int]bool{
	429: true,
	500: true,
	502: true,
	503: true,
	504: true,
}

// isRetryable reports whether err is an *httpget.HTTPError with a retryable
// status code.
func isRetryable(err error) bool {
	var he *httpget.HTTPError
	return errors.As(err, &he) && retryableCodes[he.StatusCode]
}

// Retry calls fn repeatedly, retrying on retryable *httpget.HTTPError values
// with exponential backoff. It makes at most 1+attempts calls to fn (one
// initial attempt plus up to attempts retries).
//
//   - A nil return from fn → Retry returns nil immediately.
//   - A non-retryable error → Retry returns it immediately (no sleep).
//   - A retryable error → sleep base<<i then retry (i starts at 0).
//   - If HTTPError.RetryAfter exceeds the computed backoff, RetryAfter is used.
//   - After attempts retries are exhausted, the last error is returned.
//   - If Clock.Sleep returns an error (ctx cancelled), that error is returned.
func Retry(ctx context.Context, attempts int, base time.Duration, c Clock, fn func() error) error {
	for i := 0; ; i++ {
		err := fn()
		if err == nil {
			return nil
		}
		if !isRetryable(err) {
			return err
		}
		if i >= attempts {
			return err
		}

		// Compute backoff: base<<i, but honor RetryAfter when it's larger.
		d := base << uint(i)
		var he *httpget.HTTPError
		if errors.As(err, &he) && he.RetryAfter > d {
			d = he.RetryAfter
		}

		if serr := c.Sleep(ctx, d); serr != nil {
			return serr
		}
	}
}
