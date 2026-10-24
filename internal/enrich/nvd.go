package enrich

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"time"

	"layzmd/internal/httpget"
	"layzmd/internal/ratelimit"
)

const (
	nvdBaseURL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdUserAgent = "PTCompanion/1.0"
)

var cwePattern = regexp.MustCompile(`(?i)^CWE-\d+$`)

// NvdData holds the data fetched from NVD for a single CVE.
// CWEs is never nil (empty slice when none). Description is the NVD English
// description ("" when unavailable).
type NvdData struct {
	CWEs        []string `json:"cwes"`
	Description string   `json:"description"`
}

// NvdSource fetches CWE identifiers and English descriptions for individual
// CVEs from the NVD REST API v2. When an API key is configured it is sent as
// the "apiKey" request header, enabling the higher-rate tier. Anonymous access
// works at the lower rate.
type NvdSource struct {
	g      httpget.HTTPGetter
	apiKey string
	lim    *ratelimit.Limiter
	clk    ratelimit.Clock
}

// NewNvdSource constructs an NvdSource. Pass an empty string for apiKey to use
// anonymous (lower-rate) access.
func NewNvdSource(g httpget.HTTPGetter, apiKey string, lim *ratelimit.Limiter, clk ratelimit.Clock) *NvdSource {
	return &NvdSource{g: g, apiKey: apiKey, lim: lim, clk: clk}
}

// Fetch retrieves CWE identifiers and the English description for the given CVE
// from NVD. CWEs are deduped in first-seen order. On a limiter error the error
// is returned. On any HTTP/parse error NvdData{} and nil are returned.
func (s *NvdSource) Fetch(ctx context.Context, cve string) (NvdData, error) {
	if err := s.lim.Wait(ctx); err != nil {
		return NvdData{}, err
	}

	reqURL := nvdBaseURL + "?cveId=" + url.QueryEscape(cve)

	var headers map[string]string
	if s.apiKey != "" {
		headers = map[string]string{"apiKey": s.apiKey}
	}

	var body string
	err := ratelimit.Retry(ctx, 2, time.Second, s.clk, func() error {
		var gerr error
		body, gerr = s.g.Get(ctx, reqURL, nvdUserAgent, headers)
		return gerr
	})
	if err != nil {
		return NvdData{}, nil
	}

	return parseNvd(body), nil
}

// parseNvd extracts CWE identifiers (deduped, first-seen order) and the NVD
// English description from an NVD v2 response body.
func parseNvd(body string) NvdData {
	var resp struct {
		Vulnerabilities []struct {
			CVE struct {
				Weaknesses []struct {
					Description []struct {
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if jerr := json.Unmarshal([]byte(body), &resp); jerr != nil {
		return NvdData{CWEs: []string{}}
	}

	seen := make(map[string]struct{})
	var cwes []string
	var description string

	for _, vuln := range resp.Vulnerabilities {
		// Parse CWEs from all vulnerability entries (existing behaviour).
		for _, weakness := range vuln.CVE.Weaknesses {
			for _, desc := range weakness.Description {
				v := desc.Value
				if v == "" {
					continue
				}
				if !cwePattern.MatchString(v) {
					continue
				}
				if _, exists := seen[v]; exists {
					continue
				}
				seen[v] = struct{}{}
				cwes = append(cwes, v)
			}
		}

		// Pick the first en description found across all vulnerability entries.
		if description == "" {
			for _, d := range vuln.CVE.Descriptions {
				if d.Lang == "en" && d.Value != "" {
					description = d.Value
					break
				}
			}
		}
	}

	if cwes == nil {
		cwes = []string{}
	}
	return NvdData{CWEs: cwes, Description: description}
}
