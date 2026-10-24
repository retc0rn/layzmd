package enrich

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"layzmd/internal/httpget"
	"layzmd/internal/ratelimit"
)

const (
	vulnCheckBase = "https://www.vulncheck.com/api/xdb/?cve="
	// Browser UA required by VulnCheck — copy verbatim from the spec §poc.
	vulnCheckUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

	pocUserAgent = "PTCompanion/1.0"

	pocMaxURLs = 5
)

// PocSource fetches proof-of-concept references for individual CVEs from
// VulnCheck. A VulnCheck failure is captured in PocResult.Error.
type PocSource struct {
	g         httpget.HTTPGetter
	vulncheck *ratelimit.Limiter
	clk       ratelimit.Clock
}

// NewPocSource constructs a PocSource with its own VulnCheck rate limiter.
func NewPocSource(g httpget.HTTPGetter, vulncheck *ratelimit.Limiter, clk ratelimit.Clock) *PocSource {
	return &PocSource{g: g, vulncheck: vulncheck, clk: clk}
}

// Fetch retrieves PoC references for the given CVE. It never returns an error;
// failures are represented in the returned PocResult.
func (s *PocSource) Fetch(ctx context.Context, cve string) PocResult {
	upper := strings.ToUpper(cve)
	var res PocResult

	// — VulnCheck ——————————————————————————————————————————————————————————————
	if err := s.vulncheck.Wait(ctx); err == nil {
		url := vulnCheckBase + upper
		var body string
		vcErr := ratelimit.Retry(ctx, 2, time.Second, s.clk, func() error {
			var gerr error
			body, gerr = s.g.Get(ctx, url, vulnCheckUA, nil)
			return gerr
		})
		if vcErr != nil {
			res.Error = vcErr.Error()
		} else {
			res.PocURLs = parseVulnCheckURLs(body)
		}
	}

	res.recomputeHasPoc()
	return res
}

// parseVulnCheckURLs extracts the first pocMaxURLs URL strings from a
// VulnCheck API response.
func parseVulnCheckURLs(body string) []string {
	var resp struct {
		Data []struct {
			URL string `json:"url"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil
	}

	var urls []string
	for _, item := range resp.Data {
		if len(urls) >= pocMaxURLs {
			break
		}
		if item.URL != "" {
			urls = append(urls, item.URL)
		}
	}
	return urls
}
