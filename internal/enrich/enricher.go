package enrich

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"layzmd/internal/enrichcache"
)

// Sources groups the four network data sources used by the Enricher.
type Sources struct {
	Kev  *KevSource
	Epss *EpssSource
	Nvd  *NvdSource
	Poc  *PocSource
}

// coreDTO is the on-disk shape for the "core" cache entry (KEV + EPSS).
// Priority is intentionally absent — it is computed at merge time in SP3c.
type coreDTO struct {
	InKev          bool     `json:"in_kev"`
	EpssScore      *float64 `json:"epss_score,omitempty"`
	EpssPercentile *float64 `json:"epss_percentile,omitempty"`
}

// Enricher orchestrates KEV, EPSS, NVD, and PoC fetches with a disk cache,
// graceful per-source degradation, noNetwork mode, and progress reporting.
type Enricher struct {
	sources   Sources
	cache     *enrichcache.Cache
	noNetwork bool
}

// NewEnricher constructs an Enricher. When noNetwork is true no HTTP calls are
// made; only existing cache entries are used.
func NewEnricher(s Sources, cache *enrichcache.Cache, noNetwork bool) *Enricher {
	return &Enricher{sources: s, cache: cache, noNetwork: noNetwork}
}

// Enrich fetches enrichment data for the given CVEs. CVEs are deduplicated,
// upper-cased, and sorted for deterministic iteration. progress is called after
// each CVE in the per-CVE loop (done counts from 1; total == len(unique CVEs));
// progress may be nil. On context cancellation the partial map is returned
// together with the context error.
func (e *Enricher) Enrich(ctx context.Context, cves []string, progress func(done, total int)) (map[string]VulnEnrichment, error) {
	// Normalise: upper-case, dedupe, sort.
	normalised := normaliseCVEs(cves)
	total := len(normalised)
	result := make(map[string]VulnEnrichment, total)

	// ── Phase 1: KEV set ─────────────────────────────────────────────────────
	kevSet := e.loadKevSet(ctx)

	// ── Phase 2: Core (EPSS + InKev) ─────────────────────────────────────────
	cores := e.loadCores(ctx, normalised, kevSet)

	// ── Phase 2b: Bulk PoC indexes (fetched once, cached, read-only) ─────────
	// Merged into each CVE's PocResult in Phase 3. Read-only after construction,
	// so the worker goroutines may share them without synchronisation.
	pocIdxEDB := e.loadPocIndex(ctx, "_exploitdb", exploitDBURL, parseExploitDB)
	pocIdxMSF := e.loadPocIndex(ctx, "_metasploit", metasploitURL, parseMetasploit)
	pocIdxNuc := e.loadPocIndex(ctx, "_nuclei", nucleiTreeURL, parseNuclei)

	// ── Phase 3: Bounded worker pool over per-CVE PoC + NVD ─────────────────
	//
	// Safety reasoning (in lieu of go test -race which requires CGO):
	//
	//   • The work channel (cveWork) is written by the dispatcher (main goroutine)
	//     and read by workers — safe by channel semantics.
	//   • The results channel (cveResult) is written by workers and read by the
	//     collector (main goroutine after WaitGroup.Wait) — safe by channel
	//     semantics. The channel is buffered to total so workers never block.
	//   • result map[string]VulnEnrichment is written exclusively by the main
	//     goroutine (the collector loop after all workers finish) — single writer,
	//     no concurrent map writes.
	//   • enrichcache.Cache.Get/Put are mutex-guarded (sync.Mutex) — safe for
	//     concurrent access by workers.
	//   • Per-source ratelimit.Limiters are mutex-guarded — safe for concurrent
	//     access by workers.
	//   • done counter is incremented with sync/atomic — safe for concurrent
	//     workers calling progress concurrently.
	//   • No other shared mutable state is touched by workers.

	// Type for passing results from workers to the collector.
	type cveEntry struct {
		cve string
		ve  VulnEnrichment
	}

	numWorkers := total
	if numWorkers > 16 {
		numWorkers = 16
	}

	// cveWork feeds CVEs to workers. Buffered to total so the dispatcher never
	// blocks when cancellation has stopped workers early.
	cveWork := make(chan string, total)
	// cveResult collects results. Buffered to total so workers never block.
	cveResult := make(chan cveEntry, total)

	var wg sync.WaitGroup
	var done atomic.Int64

	// Start workers.
	wg.Add(numWorkers)
	for range numWorkers {
		go func() {
			defer wg.Done()
			for cve := range cveWork {
				// Honour context cancellation.
				if ctx.Err() != nil {
					// Drain remaining work items without processing them so
					// the dispatcher (which has already stopped sending) and
					// the WaitGroup close correctly. We do NOT need to drain
					// here — the dispatcher closes cveWork after sending all
					// items (or after cancellation is detected), so the range
					// will terminate naturally.
					continue
				}

				core := cores[cve]
				poc := e.loadPoc(ctx, cve)
				poc = mergePocRefs(poc, cve, pocIdxEDB, pocIdxMSF, pocIdxNuc)
				nd := e.loadNvd(ctx, cve)

				cveResult <- cveEntry{
					cve: cve,
					ve: VulnEnrichment{
						InKev:          core.InKev,
						EpssScore:      core.EpssScore,
						EpssPercentile: core.EpssPercentile,
						CWEs:           nd.CWEs,
						Description:    nd.Description,
						Poc:            poc,
					},
				}

				n := done.Add(1)
				if progress != nil {
					progress(int(n), total)
				}
			}
		}()
	}

	// Dispatch CVEs to workers. Stop dispatching on cancellation.
	for _, cve := range normalised {
		if ctx.Err() != nil {
			break
		}
		cveWork <- cve
	}
	close(cveWork)

	// Wait for all workers to finish, then close the results channel so the
	// collector loop below terminates.
	wg.Wait()
	close(cveResult)

	// Collect results — single writer for the result map.
	for entry := range cveResult {
		result[entry.cve] = entry.ve
	}

	// Persist all newly written entries to disk. Best-effort — don't lose results.
	_ = e.cache.Save()

	// Return partial map + ctx error if the context was cancelled.
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

// ── private helpers ───────────────────────────────────────────────────────────

// normaliseCVEs upper-cases, deduplicates, and sorts the input slice.
func normaliseCVEs(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	for _, c := range in {
		seen[strings.ToUpper(c)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// loadKevSet returns the KEV set from cache or network.
func (e *Enricher) loadKevSet(ctx context.Context) map[string]struct{} {
	// Try cache first.
	if raw, ok := e.cache.Get("_kev", "catalog"); ok {
		var list []string
		if err := json.Unmarshal(raw, &list); err == nil {
			set := make(map[string]struct{}, len(list))
			for _, c := range list {
				set[c] = struct{}{}
			}
			return set
		}
	}

	if e.noNetwork {
		return map[string]struct{}{}
	}

	// Fetch from network — KevSource already degrades on error.
	set, _ := e.sources.Kev.Fetch(ctx)

	// Write a sorted slice to the cache.
	sorted := make([]string, 0, len(set))
	for c := range set {
		sorted = append(sorted, c)
	}
	sort.Strings(sorted)
	_ = e.cache.Put("_kev", "catalog", sorted)

	return set
}

// loadCores returns a map[cve]coreDTO for all normalised CVEs.
// Cache-hit CVEs are loaded directly; misses are batch-fetched via EPSS.
func (e *Enricher) loadCores(ctx context.Context, cves []string, kevSet map[string]struct{}) map[string]coreDTO {
	cores := make(map[string]coreDTO, len(cves))
	var missing []string

	for _, cve := range cves {
		if raw, ok := e.cache.Get(cve, "core"); ok {
			var dto coreDTO
			if err := json.Unmarshal(raw, &dto); err == nil {
				cores[cve] = dto
				continue
			}
		}
		missing = append(missing, cve)
	}

	if len(missing) == 0 {
		return cores
	}

	// Fetch EPSS for the missing CVEs (unless noNetwork).
	var epssMap map[string]EpssData
	if !e.noNetwork {
		epssMap, _ = e.sources.Epss.Fetch(ctx, missing)
	}

	for _, cve := range missing {
		_, inKev := kevSet[cve]
		var score, percentile *float64
		if epssMap != nil {
			if d, ok := epssMap[cve]; ok {
				score = d.Score
				percentile = d.Percentile
			}
		}
		dto := coreDTO{
			InKev:          inKev,
			EpssScore:      score,
			EpssPercentile: percentile,
		}
		cores[cve] = dto
		// Only persist when we actually fetched online. In --no-enrich mode we
		// must NOT cache a nil-EPSS core: a later online run would treat it as
		// fresh (24h TTL) and EPSS would never populate.
		if !e.noNetwork {
			_ = e.cache.Put(cve, "core", dto)
		}
	}

	return cores
}

// loadPocIndex returns a bulk PoC index (ExploitDB/Metasploit/Nuclei), reading
// the cache first. In noNetwork mode it uses the cache when present, else an
// empty index. All fetches are best-effort.
func (e *Enricher) loadPocIndex(ctx context.Context, key, url string, parse func(string) PocIndex) PocIndex {
	if raw, ok := e.cache.Get(key, "index"); ok {
		var idx PocIndex
		if err := json.Unmarshal(raw, &idx); err == nil {
			return idx
		}
	}
	if e.noNetwork {
		return PocIndex{}
	}
	idx := fetchPocIndex(ctx, e.sources.Poc.g, url, parse)
	_ = e.cache.Put(key, "index", idx)
	return idx
}

// mergePocRefs appends any bulk-index refs for cve into p (creating p when it is
// nil and there are hits), de-dupes by URL, and recomputes HasPoc. Returns p
// unchanged (possibly nil) when no index has a ref for the CVE.
func mergePocRefs(p *PocResult, cve string, idxs ...PocIndex) *PocResult {
	key := strings.ToUpper(cve)
	var refs []PocRef
	for _, idx := range idxs {
		refs = append(refs, idx[key]...)
	}
	if len(refs) == 0 {
		return p
	}
	if p == nil {
		p = &PocResult{}
	}
	seen := make(map[string]bool, len(p.Refs))
	for _, r := range p.Refs {
		seen[r.URL] = true
	}
	for _, r := range refs {
		if !seen[r.URL] {
			seen[r.URL] = true
			p.Refs = append(p.Refs, r)
		}
	}
	p.recomputeHasPoc()
	return p
}

// loadPoc returns the PocResult for a single CVE, reading from cache first.
func (e *Enricher) loadPoc(ctx context.Context, cve string) *PocResult {
	if raw, ok := e.cache.Get(cve, "poc"); ok {
		var poc PocResult
		if err := json.Unmarshal(raw, &poc); err == nil {
			return &poc
		}
	}

	if e.noNetwork {
		return nil
	}

	// Fetch — PocSource never returns an error (failures captured in PocResult.Error).
	poc := e.sources.Poc.Fetch(ctx, cve)
	_ = e.cache.Put(cve, "poc", poc)
	return &poc
}

// loadNvd returns the NvdData for a single CVE, reading from cache first.
// An old-shape cache entry (bare []string from SP3b) will fail to unmarshal
// into NvdData and is treated as a miss, causing a refetch.
func (e *Enricher) loadNvd(ctx context.Context, cve string) NvdData {
	if raw, ok := e.cache.Get(cve, "nvd"); ok {
		var nd NvdData
		if err := json.Unmarshal(raw, &nd); err == nil {
			return nd
		}
		// Old-shape entry ([]string) or corrupt — fall through to refetch.
	}

	if e.noNetwork {
		return NvdData{CWEs: []string{}}
	}

	// Fetch — NvdSource already degrades on error (returns NvdData{}).
	nd, _ := e.sources.Nvd.Fetch(ctx, cve)
	_ = e.cache.Put(cve, "nvd", nd)
	return nd
}
