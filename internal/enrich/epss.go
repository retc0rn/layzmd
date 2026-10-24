package enrich

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"layzmd/internal/httpget"
	"layzmd/internal/ratelimit"
)

const (
	epssBaseURL   = "https://api.first.org/data/v1/epss"
	epssUserAgent = "PTCompanion/1.0"
	epssBatchSize = 100
)

// EpssSource fetches EPSS scores from api.first.org. CVEs are batched in
// groups of 100. A batch-level error leaves that batch's CVEs with nil values
// without failing the entire call.
type EpssSource struct {
	g   httpget.HTTPGetter
	lim *ratelimit.Limiter
	clk ratelimit.Clock
}

// NewEpssSource constructs an EpssSource with the given HTTP getter, rate
// limiter, and clock.
func NewEpssSource(g httpget.HTTPGetter, lim *ratelimit.Limiter, clk ratelimit.Clock) *EpssSource {
	return &EpssSource{g: g, lim: lim, clk: clk}
}

// Fetch retrieves EPSS data for the given CVEs. Every requested CVE is
// pre-seeded to EpssData{nil,nil}; the response overwrites present entries.
// Fetch returns a nil error even when all batches fail.
func (s *EpssSource) Fetch(ctx context.Context, cves []string) (map[string]EpssData, error) {
	result := make(map[string]EpssData, len(cves))
	for _, cve := range cves {
		result[cve] = EpssData{}
	}

	for i := 0; i < len(cves); i += epssBatchSize {
		end := i + epssBatchSize
		if end > len(cves) {
			end = len(cves)
		}
		batch := cves[i:end]

		if err := s.lim.Wait(ctx); err != nil {
			return result, err
		}

		url := epssBaseURL + "?cve=" + strings.Join(batch, ",")
		var body string
		err := ratelimit.Retry(ctx, 2, time.Second, s.clk, func() error {
			var gerr error
			body, gerr = s.g.Get(ctx, url, epssUserAgent, nil)
			return gerr
		})
		if err != nil {
			// Leave this batch pre-seeded as {nil,nil}; continue with next batch.
			continue
		}

		// Parse the response.
		var resp struct {
			Data []json.RawMessage `json:"data"`
		}
		if jerr := json.Unmarshal([]byte(body), &resp); jerr != nil {
			continue
		}

		for _, raw := range resp.Data {
			var item struct {
				CVE        string          `json:"cve"`
				EPSS       json.RawMessage `json:"epss"`
				Percentile json.RawMessage `json:"percentile"`
			}
			if jerr := json.Unmarshal(raw, &item); jerr != nil {
				continue
			}
			if item.CVE == "" {
				continue
			}
			if _, ok := result[item.CVE]; !ok {
				continue
			}
			result[item.CVE] = EpssData{
				Score:      parseNum(item.EPSS),
				Percentile: parseNum(item.Percentile),
			}
		}
	}

	return result, nil
}

// parseNum parses a JSON value that may be a string or number into a float64
// pointer. Values greater than 1.0 are divided by 100 (normalisation). Returns
// nil if the field is absent, null, or unparsable.
func parseNum(raw json.RawMessage) *float64 {
	if len(raw) == 0 {
		return nil
	}

	var d float64

	// Try as a JSON string first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil
		}
		d = v
	} else {
		// Try as a JSON number.
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil
		}
	}

	if d > 1.0 {
		d = d / 100.0
	}
	return &d
}
