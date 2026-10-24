package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"layzmd/internal/enrichcache"
	"layzmd/internal/ratelimit"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// staleAll clock / cache helpers.
func fixedNow() func() time.Time {
	t0 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	return func() time.Time { return t0 }
}

func newTestCache(t *testing.T, staleAll bool) *enrichcache.Cache {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.json")
	c, err := enrichcache.OpenAt(path, fixedNow(), staleAll)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	return c
}

// buildSources wires a single fakeGetter into all four sources with
// permissive limiters and a no-sleep clock. Returns the Sources and the
// underlying fakeGetter so tests can inspect f.calls.
func buildSources(f *fakeGetter) Sources {
	clk := ratelimit.Clock{
		Now:   func() time.Time { return time.Unix(0, 0) },
		Sleep: func(_ context.Context, _ time.Duration) error { return nil },
	}
	lim := ratelimit.NewLimiterWithClock(1000, time.Second, clk)
	return Sources{
		Kev:  NewKevSource(f, clk),
		Epss: NewEpssSource(f, lim, clk),
		Nvd:  NewNvdSource(f, "", lim, clk),
		Poc:  NewPocSource(f, lim, clk),
	}
}

// Standard fake responses.
const (
	kevBody = `{"vulnerabilities":[{"cveID":"CVE-2017-0144"},{"cveID":"CVE-NOTANUMBER"}]}`
	// EPSS returns both CVEs with valid data.
	epssBody = `{"data":[{"cve":"CVE-2017-0144","epss":"0.97","percentile":"0.99"},{"cve":"CVE-2020-1","epss":"0.10","percentile":"0.50"}]}`
	// NVD for CVE-2017-0144 — includes both weaknesses and an en description.
	nvdBody = `{"vulnerabilities":[{"cve":{"weaknesses":[{"description":[{"value":"CWE-119"}]}],"descriptions":[{"lang":"en","value":"EternalBlue SMB exploit."}]}}]}`
	// PoC VulnCheck for CVE-2017-0144
	pocVCBody = `{"data":[{"url":"https://example.com/poc1"},{"url":"https://example.com/poc2"}]}`
	// empty NVD / PoC for CVE-2020-1
	nvdEmptyBody   = `{"vulnerabilities":[]}`
	pocVCEmptyBody = `{"data":[]}`
)

// ─── tests ────────────────────────────────────────────────────────────────────

// TestEnrich_NoNetworkDoesNotCacheCore guards the EPSS cache-poisoning fix: a
// --no-enrich (noNetwork) run must NOT persist a nil-EPSS "core" entry, or a
// later online run would reuse it as fresh and EPSS would never populate.
func TestEnrich_NoNetworkDoesNotCacheCore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	cve := "CVE-2017-0144"

	// Offline run over an empty cache — must not write a core entry.
	c1, err := enrichcache.OpenAt(path, fixedNow(), false)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	e1 := NewEnricher(buildSources(new(fakeGetter)), c1, true) // noNetwork
	if _, err := e1.Enrich(context.Background(), []string{cve}, nil); err != nil {
		t.Fatalf("offline Enrich: %v", err)
	}
	// Re-open the persisted cache and confirm no core was written.
	c2, err := enrichcache.OpenAt(path, fixedNow(), false)
	if err != nil {
		t.Fatalf("OpenAt#2: %v", err)
	}
	if _, ok := c2.Get(cve, "core"); ok {
		t.Fatal("offline run poisoned the cache: a core entry was written in --no-enrich mode")
	}

	// Online run now fetches EPSS (not a poisoned nil core).
	f := new(fakeGetter).
		add("cisa.gov", `{"vulnerabilities":[]}`, nil).
		add("api.first.org", `{"data":[{"cve":"`+cve+`","epss":"0.97","percentile":"0.99"}]}`, nil).
		add("cveId="+cve, `{"vulnerabilities":[]}`, nil).
		add("xdb/?cve="+cve, `{"data":[]}`, nil).
		add("topics?name="+cve, `{"data":[]}`, nil)
	e2 := NewEnricher(buildSources(f), c2, false)
	res, err := e2.Enrich(context.Background(), []string{cve}, nil)
	if err != nil {
		t.Fatalf("online Enrich: %v", err)
	}
	if res[cve].EpssPercentile == nil {
		t.Fatal("EPSS percentile still nil after online run — cache poisoning not fixed")
	}
}

func TestEnrich_EndToEnd(t *testing.T) {
	f := new(fakeGetter).
		add("cisa.gov", kevBody, nil).
		add("api.first.org", epssBody, nil).
		add("cveId=CVE-2017-0144", nvdBody, nil).
		add("cveId=CVE-2020-1", nvdEmptyBody, nil).
		add("xdb/?cve=CVE-2017-0144", pocVCBody, nil).
		add("xdb/?cve=CVE-2020-1", pocVCEmptyBody, nil)

	cache := newTestCache(t, false)
	s := buildSources(f)
	e := NewEnricher(s, cache, false)

	ctx := context.Background()
	result, err := e.Enrich(ctx, []string{"CVE-2017-0144", "CVE-2020-1"}, nil)
	if err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("want 2 results, got %d", len(result))
	}

	// CVE-2017-0144: InKev true, EPSS populated, CWE set, Poc with URLs.
	vu := result["CVE-2017-0144"]
	if !vu.InKev {
		t.Error("CVE-2017-0144: want InKev=true")
	}
	if vu.EpssScore == nil || *vu.EpssScore < 0.90 {
		t.Errorf("CVE-2017-0144: want EpssScore ~0.97, got %v", vu.EpssScore)
	}
	if vu.EpssPercentile == nil || *vu.EpssPercentile < 0.90 {
		t.Errorf("CVE-2017-0144: want EpssPercentile ~0.99, got %v", vu.EpssPercentile)
	}
	if len(vu.CWEs) == 0 || vu.CWEs[0] != "CWE-119" {
		t.Errorf("CVE-2017-0144: want CWEs=[CWE-119], got %v", vu.CWEs)
	}
	if vu.Poc == nil || !vu.Poc.HasPoc {
		t.Errorf("CVE-2017-0144: want Poc.HasPoc=true, got %+v", vu.Poc)
	}
	if vu.Description != "EternalBlue SMB exploit." {
		t.Errorf("CVE-2017-0144: want Description from NVD, got %q", vu.Description)
	}

	// CVE-2020-1: InKev false.
	vu2 := result["CVE-2020-1"]
	if vu2.InKev {
		t.Error("CVE-2020-1: want InKev=false")
	}
	if vu2.EpssScore == nil {
		t.Error("CVE-2020-1: want EpssScore non-nil")
	}
}

func TestEnrich_CacheHitSkipsNetwork(t *testing.T) {
	// Pre-populate a fresh cache with all data for "CVE-2021-1".
	cache := newTestCache(t, false)

	// Pre-populate core.
	core := coreDTO{
		InKev:          true,
		EpssScore:      ptr(0.5),
		EpssPercentile: ptr(0.8),
	}
	if err := cache.Put("CVE-2021-1", "core", core); err != nil {
		t.Fatalf("Put core: %v", err)
	}
	// Pre-populate poc.
	poc := PocResult{HasPoc: true, PocURLs: []string{"https://cached-poc.example.com"}}
	if err := cache.Put("CVE-2021-1", "poc", poc); err != nil {
		t.Fatalf("Put poc: %v", err)
	}
	// Pre-populate nvd with the new NvdData shape.
	nd := NvdData{CWEs: []string{"CWE-79"}, Description: "Cached NVD description."}
	if err := cache.Put("CVE-2021-1", "nvd", nd); err != nil {
		t.Fatalf("Put nvd: %v", err)
	}
	// Pre-populate KEV catalog.
	kevList := []string{"CVE-2021-1"}
	if err := cache.Put("_kev", "catalog", kevList); err != nil {
		t.Fatalf("Put kev: %v", err)
	}
	// Pre-populate the bulk PoC indexes so a fully-cached run makes no network calls.
	for _, k := range []string{"_exploitdb", "_metasploit", "_nuclei"} {
		if err := cache.Put(k, "index", PocIndex{}); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}
	if err := cache.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reopen the same cache file.
	cache2, err := enrichcache.OpenAt(cache.Path(), fixedNow(), false)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	// Use a fakeGetter with no routes — any network call should fail.
	f := new(fakeGetter)
	s := buildSources(f)
	e := NewEnricher(s, cache2, false)

	ctx := context.Background()
	result, err := e.Enrich(ctx, []string{"CVE-2021-1"}, nil)
	if err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	// Zero network calls for the cached CVE.
	if len(f.calls) != 0 {
		t.Errorf("want 0 HTTP calls (all cached), got %d: %v", len(f.calls), f.calls)
	}

	vu := result["CVE-2021-1"]
	if !vu.InKev {
		t.Error("want InKev=true from cache")
	}
	if vu.Poc == nil || !vu.Poc.HasPoc {
		t.Errorf("want Poc from cache, got %+v", vu.Poc)
	}
	if len(vu.CWEs) == 0 || vu.CWEs[0] != "CWE-79" {
		t.Errorf("want CWEs from cache, got %v", vu.CWEs)
	}
	if vu.Description != "Cached NVD description." {
		t.Errorf("want Description from cache, got %q", vu.Description)
	}
}

func TestEnrich_NoNetwork(t *testing.T) {
	// Empty cache + noNetwork=true → zero-value results, zero HTTP calls.
	f := new(fakeGetter)
	s := buildSources(f)
	cache := newTestCache(t, false)
	e := NewEnricher(s, cache, true)

	ctx := context.Background()
	result, err := e.Enrich(ctx, []string{"CVE-2021-1", "CVE-2021-2"}, nil)
	if err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	if len(f.calls) != 0 {
		t.Errorf("want 0 HTTP calls in noNetwork mode, got %d: %v", len(f.calls), f.calls)
	}
	if len(result) != 2 {
		t.Fatalf("want 2 entries (zero-value), got %d", len(result))
	}
	for cve, vu := range result {
		if vu.InKev || vu.EpssScore != nil || vu.EpssPercentile != nil || len(vu.CWEs) != 0 {
			t.Errorf("%s: want zero-value, got %+v", cve, vu)
		}
		// Poc pointer can be nil or &PocResult{}.
		if vu.Poc != nil && (vu.Poc.HasPoc || len(vu.Poc.PocURLs) > 0) {
			t.Errorf("%s: want empty Poc, got %+v", cve, vu.Poc)
		}
	}
}

func TestEnrich_SourceFailureDegrades(t *testing.T) {
	// PoC route errors; KEV/EPSS/NVD still populate.
	f := new(fakeGetter).
		add("cisa.gov", kevBody, nil).
		add("api.first.org", epssBody, nil).
		add("cveId=CVE-2017-0144", nvdBody, nil).
		add("vulncheck.com", "", fmt.Errorf("connection refused"))

	cache := newTestCache(t, false)
	s := buildSources(f)
	e := NewEnricher(s, cache, false)

	ctx := context.Background()
	result, err := e.Enrich(ctx, []string{"CVE-2017-0144"}, nil)
	// Enrich itself must not error.
	if err != nil {
		t.Fatalf("Enrich returned error: %v", err)
	}

	vu := result["CVE-2017-0144"]
	if !vu.InKev {
		t.Error("want InKev=true despite PoC failure")
	}
	if vu.EpssScore == nil {
		t.Error("want EpssScore populated despite PoC failure")
	}
	if len(vu.CWEs) == 0 {
		t.Error("want CWEs populated despite PoC failure")
	}
	// Poc should reflect the error / empty state (no panic, no abort).
	// HasPoc is false because no URLs.
	if vu.Poc != nil && vu.Poc.HasPoc {
		t.Error("want HasPoc=false when VulnCheck fails")
	}
}

func TestEnrich_Progress(t *testing.T) {
	f := new(fakeGetter).
		add("cisa.gov", kevBody, nil).
		add("api.first.org", epssBody, nil).
		add("nvd.nist.gov", nvdEmptyBody, nil).
		add("vulncheck.com", pocVCEmptyBody, nil)

	cache := newTestCache(t, false)
	s := buildSources(f)
	e := NewEnricher(s, cache, false)

	cves := []string{"CVE-2017-0144", "CVE-2020-1"}
	var progDone []int
	progress := func(done, total int) {
		progDone = append(progDone, done)
		if total != len(cves) {
			t.Errorf("progress total=%d, want %d", total, len(cves))
		}
	}

	ctx := context.Background()
	_, err := e.Enrich(ctx, cves, progress)
	if err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	if len(progDone) == 0 {
		t.Fatal("want at least one progress call")
	}
	// Under the concurrent worker pool, progress calls may arrive out of order —
	// monotonic ordering is NOT guaranteed. Assert only that the maximum observed
	// done value equals total (all CVEs accounted for).
	maxDone := 0
	for _, d := range progDone {
		if d > maxDone {
			maxDone = d
		}
	}
	if maxDone != len(cves) {
		t.Errorf("max progress done=%d, want %d", maxDone, len(cves))
	}
}

func TestEnrich_Deterministic(t *testing.T) {
	// Two fresh runs over the same inputs produce identical maps.
	makeCache := func() *enrichcache.Cache { return newTestCache(t, false) }
	f1 := new(fakeGetter).
		add("cisa.gov", kevBody, nil).
		add("api.first.org", epssBody, nil).
		add("cveId=CVE-2017-0144", nvdBody, nil).
		add("cveId=CVE-2020-1", nvdEmptyBody, nil).
		add("xdb/?cve=CVE-2017-0144", pocVCBody, nil).
		add("xdb/?cve=CVE-2020-1", pocVCEmptyBody, nil)
	f2 := new(fakeGetter).
		add("cisa.gov", kevBody, nil).
		add("api.first.org", epssBody, nil).
		add("cveId=CVE-2017-0144", nvdBody, nil).
		add("cveId=CVE-2020-1", nvdEmptyBody, nil).
		add("xdb/?cve=CVE-2017-0144", pocVCBody, nil).
		add("xdb/?cve=CVE-2020-1", pocVCEmptyBody, nil)

	ctx := context.Background()
	cves := []string{"CVE-2020-1", "CVE-2017-0144"} // intentionally unsorted

	e1 := NewEnricher(buildSources(f1), makeCache(), false)
	r1, err := e1.Enrich(ctx, cves, nil)
	if err != nil {
		t.Fatalf("run1 error: %v", err)
	}

	e2 := NewEnricher(buildSources(f2), makeCache(), false)
	r2, err := e2.Enrich(ctx, cves, nil)
	if err != nil {
		t.Fatalf("run2 error: %v", err)
	}

	for _, cve := range cves {
		b1, _ := json.Marshal(r1[cve])
		b2, _ := json.Marshal(r2[cve])
		if string(b1) != string(b2) {
			t.Errorf("%s: results differ:\n  run1=%s\n  run2=%s", cve, b1, b2)
		}
	}
}

func TestEnrich_CtxCancel(t *testing.T) {
	// A context cancelled before the per-CVE loop → returns ctx.Err().
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	f := new(fakeGetter).
		add("cisa.gov", kevBody, nil).
		add("api.first.org", epssBody, nil)
	// Don't add NVD/PoC routes — if the loop runs, it'll hit no-route errors.

	cache := newTestCache(t, false)
	s := buildSources(f)
	e := NewEnricher(s, cache, false)

	_, err := e.Enrich(ctx, []string{"CVE-2017-0144", "CVE-2020-1"}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
}

func TestEnrich_RefreshStaleAll(t *testing.T) {
	// staleAll=true cache → should still fetch from network (every Get returns false).
	// After enrichment the entries should be written (Put under staleAll persists through Save).
	f := new(fakeGetter).
		add("cisa.gov", kevBody, nil).
		add("api.first.org", epssBody, nil).
		add("nvd.nist.gov", nvdEmptyBody, nil).
		add("vulncheck.com", pocVCEmptyBody, nil)

	// staleAll=true simulates --refresh.
	cache := newTestCache(t, true)
	s := buildSources(f)
	e := NewEnricher(s, cache, false)

	ctx := context.Background()
	result, err := e.Enrich(ctx, []string{"CVE-2017-0144"}, nil)
	if err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	// Should have fetched from network.
	if len(f.calls) == 0 {
		t.Error("want network calls under staleAll (--refresh), got none")
	}
	// InKev should be true (from KEV body).
	if !result["CVE-2017-0144"].InKev {
		t.Error("want InKev=true")
	}
}

// TestEnrich_OldShapeNvdCacheIsMiss verifies that a legacy []string nvd cache
// entry (the SP3b shape) fails to unmarshal into NvdData and is treated as a
// cache miss, causing a network refetch.
func TestEnrich_OldShapeNvdCacheIsMiss(t *testing.T) {
	cache := newTestCache(t, false)

	// Pre-populate with old shape: a bare []string, not NvdData.
	oldShape := []string{"CWE-79"}
	if err := cache.Put("CVE-2021-1", "nvd", oldShape); err != nil {
		t.Fatalf("Put nvd (old shape): %v", err)
	}
	// Also populate core and poc so those paths don't make network calls.
	core := coreDTO{InKev: false, EpssScore: ptr(0.1), EpssPercentile: ptr(0.2)}
	if err := cache.Put("CVE-2021-1", "core", core); err != nil {
		t.Fatalf("Put core: %v", err)
	}
	poc := PocResult{HasPoc: false}
	if err := cache.Put("CVE-2021-1", "poc", poc); err != nil {
		t.Fatalf("Put poc: %v", err)
	}
	kevList := []string{}
	if err := cache.Put("_kev", "catalog", kevList); err != nil {
		t.Fatalf("Put kev: %v", err)
	}
	if err := cache.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reopen the cache.
	cache2, err := enrichcache.OpenAt(cache.Path(), fixedNow(), false)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	// Network returns fresh NvdData with a description.
	f := new(fakeGetter).add("cveId=CVE-2021-1", `{"vulnerabilities":[{"cve":{"weaknesses":[{"description":[{"value":"CWE-79"}]}],"descriptions":[{"lang":"en","value":"Refetched description."}]}}]}`, nil)
	s := buildSources(f)
	e := NewEnricher(s, cache2, false)

	ctx := context.Background()
	result, err := e.Enrich(ctx, []string{"CVE-2021-1"}, nil)
	if err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	// The old-shape entry must have caused a refetch.
	nvdCalls := 0
	for _, c := range f.calls {
		if strings.Contains(c, "cveId=CVE-2021-1") {
			nvdCalls++
		}
	}
	if nvdCalls == 0 {
		t.Error("want NVD network call because old-shape cache entry is a miss, got 0 NVD calls")
	}

	vu := result["CVE-2021-1"]
	if vu.Description != "Refetched description." {
		t.Errorf("want Description from refetch, got %q", vu.Description)
	}
	if len(vu.CWEs) == 0 || vu.CWEs[0] != "CWE-79" {
		t.Errorf("want CWEs from refetch, got %v", vu.CWEs)
	}
}

// TestEnrich_ConcurrentPool verifies that the bounded worker pool produces
// exactly one result per input CVE — no lost or duplicated entries — when run
// over N distinct CVEs each with its own distinct fake routes.
func TestEnrich_ConcurrentPool(t *testing.T) {
	const N = 50

	// Build a fakeGetter with routes for every CVE.
	// KEV and EPSS are shared; each CVE gets its own NVD + PoC routes.
	f := new(fakeGetter).
		add("cisa.gov", kevBody, nil).
		add("api.first.org", `{"data":[]}`, nil) // no EPSS hits, that's fine

	for i := range N {
		cve := fmt.Sprintf("CVE-2000-%d", i+1)
		nvdResp := fmt.Sprintf(`{"vulnerabilities":[{"cve":{"weaknesses":[],"descriptions":[{"lang":"en","value":"desc-%d"}]}}]}`, i+1)
		f.add("cveId="+cve, nvdResp, nil)
		f.add("xdb/?cve="+cve, pocVCEmptyBody, nil)
		f.add("topics?name="+cve, `{"data":[]}`, nil)
	}

	cves := make([]string, N)
	for i := range N {
		cves[i] = fmt.Sprintf("CVE-2000-%d", i+1)
	}

	cache := newTestCache(t, false)
	s := buildSources(f)
	e := NewEnricher(s, cache, false)

	ctx := context.Background()
	result, err := e.Enrich(ctx, cves, nil)
	if err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	// All N CVEs must be present — no lost or duplicated entries.
	if len(result) != N {
		t.Fatalf("want %d results, got %d", N, len(result))
	}
	for i := range N {
		cve := fmt.Sprintf("CVE-2000-%d", i+1)
		if _, ok := result[cve]; !ok {
			t.Errorf("missing result for %s", cve)
		}
	}
}

// ptr returns a pointer to the given float64 value.
func ptr(f float64) *float64 { return &f }
