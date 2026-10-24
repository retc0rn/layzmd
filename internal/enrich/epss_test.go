package enrich

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"layzmd/internal/ratelimit"
)

func testClock() ratelimit.Clock {
	return ratelimit.Clock{
		Now:   func() time.Time { return time.Unix(0, 0) },
		Sleep: func(_ context.Context, _ time.Duration) error { return nil },
	}
}

func testLimiter(clk ratelimit.Clock) *ratelimit.Limiter {
	return ratelimit.NewLimiterWithClock(1000, time.Second, clk)
}

const epssJSON = `{"data":[{"cve":"CVE-2021-1","epss":"0.04521","percentile":"0.91234"},{"cve":"CVE-2021-2","epss":95,"percentile":0.5}]}`

func approx(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

// TestEpss_Parse checks string-vs-number parsing and >1 normalization.
func TestEpss_Parse(t *testing.T) {
	clk := testClock()
	fg := new(fakeGetter).add("api.first.org", epssJSON, nil)
	src := NewEpssSource(fg, testLimiter(clk), clk)

	ctx := context.Background()
	result, err := src.Fetch(ctx, []string{"CVE-2021-1", "CVE-2021-2", "CVE-2021-3"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("want 3 keys, got %d", len(result))
	}

	// CVE-2021-1: epss string "0.04521", percentile string "0.91234"
	d1, ok := result["CVE-2021-1"]
	if !ok {
		t.Fatal("missing CVE-2021-1")
	}
	if d1.Score == nil || !approx(*d1.Score, 0.04521) {
		t.Errorf("CVE-2021-1 Score: got %v, want ~0.04521", d1.Score)
	}
	if d1.Percentile == nil || !approx(*d1.Percentile, 0.91234) {
		t.Errorf("CVE-2021-1 Percentile: got %v, want ~0.91234", d1.Percentile)
	}

	// CVE-2021-2: epss number 95 (>1 → /100 = 0.95), percentile number 0.5
	d2, ok := result["CVE-2021-2"]
	if !ok {
		t.Fatal("missing CVE-2021-2")
	}
	if d2.Score == nil || !approx(*d2.Score, 0.95) {
		t.Errorf("CVE-2021-2 Score: got %v, want ~0.95", d2.Score)
	}
	if d2.Percentile == nil || !approx(*d2.Percentile, 0.5) {
		t.Errorf("CVE-2021-2 Percentile: got %v, want ~0.5", d2.Percentile)
	}

	// CVE-2021-3: absent from response → nil, nil
	d3, ok := result["CVE-2021-3"]
	if !ok {
		t.Fatal("missing CVE-2021-3")
	}
	if d3.Score != nil || d3.Percentile != nil {
		t.Errorf("CVE-2021-3: want {nil,nil}, got Score=%v Percentile=%v", d3.Score, d3.Percentile)
	}
}

// TestEpss_Batching checks that 150 CVEs produce exactly 2 HTTP calls.
func TestEpss_Batching(t *testing.T) {
	clk := testClock()
	fg := new(fakeGetter).add("api.first.org", `{"data":[]}`, nil)
	src := NewEpssSource(fg, testLimiter(clk), clk)

	cves := make([]string, 150)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2021-%d", i+1)
	}

	ctx := context.Background()
	_, err := src.Fetch(ctx, cves)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fg.calls) != 2 {
		t.Errorf("want 2 HTTP calls, got %d", len(fg.calls))
	}
}

// TestEpss_BatchFailure checks that a batch error leaves CVEs as {nil,nil}
// and does NOT fail the whole call.
func TestEpss_BatchFailure(t *testing.T) {
	clk := testClock()
	fg := new(fakeGetter).add("api.first.org", "", fmt.Errorf("network error"))
	src := NewEpssSource(fg, testLimiter(clk), clk)

	ctx := context.Background()
	result, err := src.Fetch(ctx, []string{"CVE-2021-1", "CVE-2021-2"})
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("want 2 keys, got %d", len(result))
	}
	for cve, d := range result {
		if d.Score != nil || d.Percentile != nil {
			t.Errorf("%s: want {nil,nil} on batch error, got Score=%v Percentile=%v", cve, d.Score, d.Percentile)
		}
	}
}
