// Package enrich provides enrichment data sources (EPSS, KEV, NVD, PoC) that
// are faithful ports of the C# PTCompanion.Core.Enrichment namespace. Each
// source accepts an httpget.HTTPGetter so tests can inject a fake with no live
// network access.
package enrich

// EpssData holds the EPSS score and percentile for a single CVE. Both fields
// are pointers so that a missing / unavailable value is represented as nil
// rather than a misleading zero.
type EpssData struct {
	Score      *float64
	Percentile *float64
}

// PocRef is a single labeled proof-of-concept / detection reference from a bulk
// source (ExploitDB, Metasploit, or Nuclei).
type PocRef struct {
	Source string
	URL    string
}

// PocResult holds proof-of-concept reference data for a single CVE.
type PocResult struct {
	HasPoc  bool
	PocURLs []string // VulnCheck-aggregated GitHub PoC URLs
	Refs    []PocRef // ExploitDB / Metasploit / Nuclei
	Error   string
}

// recomputeHasPoc sets HasPoc from the presence of a real proof-of-concept.
// Nuclei (detection template) is deliberately EXCLUDED from the PoC signal and
// surfaced in its own section.
func (p *PocResult) recomputeHasPoc() {
	has := len(p.PocURLs) > 0
	for _, r := range p.Refs {
		if r.Source == "ExploitDB" || r.Source == "Metasploit" {
			has = true
			break
		}
	}
	p.HasPoc = has
}

// VulnEnrichment is the combined enrichment snapshot for a single CVE.
// Priority is deliberately absent (computed at merge time in SP3c).
// Description is the NVD English description for the CVE ("" when unavailable).
type VulnEnrichment struct {
	InKev          bool
	EpssScore      *float64
	EpssPercentile *float64
	CWEs           []string
	Description    string
	Poc            *PocResult
}
