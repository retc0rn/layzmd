package enrich

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"layzmd/internal/httpget"
	"layzmd/internal/ratelimit"
)

const (
	kevURL       = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevUserAgent = "PTCompanion/1.0"
)

var kevCVERegex = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

// KevSource fetches the CISA Known Exploited Vulnerabilities catalog. It
// requires no rate limiter (single download) but still wraps the call in Retry.
type KevSource struct {
	g   httpget.HTTPGetter
	clk ratelimit.Clock
}

// NewKevSource constructs a KevSource with the given HTTP getter and clock.
func NewKevSource(g httpget.HTTPGetter, clk ratelimit.Clock) *KevSource {
	return &KevSource{g: g, clk: clk}
}

// Fetch downloads the KEV catalog and returns a set of CVE IDs (upper-cased).
// Any error returns an empty set and a nil error — the caller should treat a
// missing KEV catalog as "no known exploited vulnerabilities".
func (s *KevSource) Fetch(ctx context.Context) (map[string]struct{}, error) {
	var body string
	err := ratelimit.Retry(ctx, 2, time.Second, s.clk, func() error {
		var gerr error
		body, gerr = s.g.Get(ctx, kevURL, kevUserAgent, nil)
		return gerr
	})
	if err != nil {
		return map[string]struct{}{}, nil
	}

	var resp struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if jerr := json.Unmarshal([]byte(body), &resp); jerr != nil {
		return map[string]struct{}{}, nil
	}

	result := make(map[string]struct{}, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		upper := strings.ToUpper(v.CveID)
		if kevCVERegex.MatchString(upper) {
			result[upper] = struct{}{}
		}
	}
	return result, nil
}
