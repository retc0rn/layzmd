package enrich

import (
	"time"

	"layzmd/internal/httpget"
	"layzmd/internal/ratelimit"
)

// BuildSources constructs the four enrichment sources with the real production
// rate limiters. It is a tested seam so the load-bearing rate-limit values do
// not live in untested main code.
//
// Rate limits:
//   - KEV:  no limiter (single bulk download)
//   - EPSS: 1 request per 500 ms
//   - NVD:  5/30 s anonymous; 50/30 s when nvdKey != ""
//   - PoC:  2/s for VulnCheck
func BuildSources(g httpget.HTTPGetter, nvdKey string, clk ratelimit.Clock) Sources {
	// KEV — no rate limiter.
	kev := NewKevSource(g, clk)

	// EPSS — 1 request per 500 ms.
	epss := NewEpssSource(g, ratelimit.NewLimiterWithClock(1, 500*time.Millisecond, clk), clk)

	// NVD — anonymous: 5/30 s; keyed: 50/30 s.
	var nvdLim *ratelimit.Limiter
	if nvdKey == "" {
		nvdLim = ratelimit.NewLimiterWithClock(5, 30*time.Second, clk)
	} else {
		nvdLim = ratelimit.NewLimiterWithClock(50, 30*time.Second, clk)
	}
	nvd := NewNvdSource(g, nvdKey, nvdLim, clk)

	// PoC — VulnCheck at 2/s.
	poc := NewPocSource(g, ratelimit.NewLimiterWithClock(2, time.Second, clk), clk)

	return Sources{
		Kev:  kev,
		Epss: epss,
		Nvd:  nvd,
		Poc:  poc,
	}
}
