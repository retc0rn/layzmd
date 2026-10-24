// Package vulnview is the pure merge layer for layzmd SP3c. It combines the
// grouped vulnerability model (internal/vuln) with the per-CVE enrichment map
// (internal/enrich) into priority-sorted, display-ready structs. No I/O, no
// time, no external state — deterministic given the same inputs.
package vulnview

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"layzmd/internal/category"
	"layzmd/internal/enrich"
	"layzmd/internal/priority"
	"layzmd/internal/vuln"
)

// versionRe matches purely-version-like tokens that should be dropped from the
// leading words of a vulnerability name when deriving the system meta-group.
// Matches: v1, 1.0, 1.0.1, 1.0.1a, .x, 2.x, etc.
var versionRe = regexp.MustCompile(`^(v?\d+(\.\d+)*[a-z]?|\d+\.x|\.\d+\.x|\.x)$`)

// titleWord upper-cases the first letter of an ASCII word and leaves the rest
// unchanged (so "apache"→"Apache" but "vCenter"/"OpenSSL" are untouched by the
// caller, which only passes all-lowercase words here).
func titleWord(w string) string {
	if w == "" {
		return w
	}
	return strings.ToUpper(w[:1]) + w[1:]
}

// systemStopwords is the set of lower-cased words at which systemName stops
// collecting product tokens. These are vulnerability-class descriptors, not
// product names.
var systemStopwords = map[string]bool{
	"multiple":        true,
	"vulnerability":   true,
	"vulnerabilities": true,
	"detection":       true,
	"disclosure":      true,
	"remote":          true,
	"denial":          true,
	"dos":             true,
	"unsupported":     true,
	"cipher":          true,
	"ciphers":         true,
	"information":     true,
	"overflow":        true,
	"injection":       true,
	"execution":       true,
	"bypass":          true,
	"traversal":       true,
	"escalation":      true,
	"security":        true,
	"update":          true,
	"eol":             true,
}

// Meta carries scan-level metadata stamped into the Report by main.
type Meta struct {
	ScanName  string
	Generated string // date string, e.g. "2026-07-10"
}

// Link is a labelled URL reference (PoC source or Nessus See-Also entry).
type Link struct {
	Label string
	URL   string
}

// CveView is the display-ready view of a single CVE within a GroupView.
// Solution is intentionally absent; Description comes from NVD.
type CveView struct {
	CVE, CVSS, Priority string
	Category            string // vuln-class classified from this CVE's CWEs
	HostCount           int
	InKev, HasPoc       bool
	HasNuclei           bool
	EpssPercent         string   // "94.2%" or "" when unknown
	Description         string   // from NVD; "" when unavailable
	CWEs                []string // this CVE's CWEs from NVD enrichment
	HostsByPort         []vuln.PortHosts
	PocLinks            []Link // VulnCheck / ExploitDB / Metasploit
	NucleiLinks         []Link // Nuclei detection templates (not counted as PoC)
	RefLinks            []Link // parsed from Nessus See-Also of this CVE
}

// GroupView is the display-ready view of a grouped vulnerability. It carries
// everything the Vulnerabilities.md emitter needs without exposing enrich types.
type GroupView struct {
	Name, Category, Priority, CVSS string
	System                         string // product/system meta-group from systemName(Name)
	Bucket                         string // semantic bucket (Quick Wins, High Priority, …)
	Rank                           int    // 1-based global position in the priority-sorted report
	HostCount                      int
	InKev, HasPoc                  bool
	HasNuclei                      bool
	EpssPercent                    string
	CWEs                           []string // first-seen deduped union of all CVE CWEs in this group
	IPs                            []string
	HostsByPort                    []vuln.PortHosts
	Description                    string // Nessus group description — used ONLY for no-CVE groups
	RefLinks                       []Link // Nessus See-Also — used for single/no-CVE groups
	PocLinks                       []Link // group-level PoC; populated for single-CVE groups
	NucleiLinks                    []Link // group-level Nuclei; populated for single-CVE groups
	CVEs                           []CveView
}

// BandSummary aggregates counts for one priority band.
type BandSummary struct {
	Priority       string // "Urgent", "High", "Medium", "Low"
	Vulns, Hosts   int
	InKev, WithPoc int
}

// Report is the fully merged, sorted, display-ready vulnerability report.
type Report struct {
	Meta      Meta
	VulnCount int
	HostCount int
	Bands     []BandSummary // always four entries: Urgent, High, Medium, Low
	Groups    []GroupView   // sorted: priority rank desc → CVSS desc → Name asc
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fmtPct formats an EPSS percentile pointer as a percentage string with one
// decimal place (e.g. 0.9418 → "94.2%"). Returns "" when p is nil.
func fmtPct(p *float64) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%.1f%%", *p*100)
}

// parseLinks splits a Nessus See-Also string on whitespace, keeps tokens that
// start with "http://" or "https://", and turns each into a Link whose Label
// is the URL host (falling back to the raw token if parsing fails). Returns
// nil when no valid URLs are found.
func parseLinks(seeAlso string) []Link {
	var out []Link
	for _, tok := range strings.Fields(seeAlso) {
		if !strings.HasPrefix(tok, "http://") && !strings.HasPrefix(tok, "https://") {
			continue
		}
		label := tok
		if u, err := url.Parse(tok); err == nil && u.Host != "" {
			label = u.Host
		}
		out = append(out, Link{Label: label, URL: tok})
	}
	return out
}

// pocLinks converts a PocResult into real proof-of-concept Links (nil → nil).
// Order: VulnCheck (each PocURL), then ExploitDB/Metasploit refs.
// Nuclei is a detection template, not a PoC — see nucleiLinks.
func pocLinks(p *enrich.PocResult) []Link {
	if p == nil {
		return nil
	}
	var out []Link
	for _, u := range p.PocURLs {
		out = append(out, Link{Label: "VulnCheck", URL: u})
	}
	for _, r := range p.Refs {
		if r.Source == "ExploitDB" || r.Source == "Metasploit" {
			out = append(out, Link{Label: r.Source, URL: r.URL})
		}
	}
	return out
}

// nucleiLinks returns the Nuclei detection-template Links (nil → nil). Kept
// separate from pocLinks so Nuclei does not inflate the PoC signal.
func nucleiLinks(p *enrich.PocResult) []Link {
	if p == nil {
		return nil
	}
	var out []Link
	for _, r := range p.Refs {
		if r.Source == "Nuclei" {
			out = append(out, Link{Label: "Nuclei", URL: r.URL})
		}
	}
	return out
}

// msBulletinRe matches a leading Microsoft security-bulletin prefix
// (e.g. "MS08-067:", "MS17-010 ") so it can be stripped before deriving the
// product — otherwise every bulletin becomes its own "product".
var msBulletinRe = regexp.MustCompile(`(?i)^\s*MS\d\d-\d{3}\s*:?\s*`)

// msFillerRe matches common Microsoft-advisory filler that sits between the
// bulletin number and the actual product (e.g. "Security Update for",
// "Vulnerability in"), so the product surfaces to the front for systemName.
var msFillerRe = regexp.MustCompile(`(?i)^\s*(?:(?:cumulative\s+)?security\s+update\s+for|update\s+for|vulnerabilit(?:y|ies)\s+in|security\s+update)\s+`)

// productName is the grouping product key: systemName after stripping a leading
// MS##-### bulletin prefix (and its common filler) so Microsoft advisories
// combine by their real product rather than by bulletin number.
func productName(name string) string {
	n := msBulletinRe.ReplaceAllString(name, "")
	if n != name { // only strip filler when it was actually an MS bulletin
		n = msFillerRe.ReplaceAllString(n, "")
	}
	return systemName(n)
}

// systemName derives a product/system meta-group name from a Nessus finding
// name. Algorithm:
//  1. Split on whitespace.
//  2. Drop any leading tokens that are purely version-like (versionRe).
//  3. Collect words until hitting a vuln-class stopword (systemStopwords),
//     stopping before that word. Cap at 2 words; minimum 1.
//  4. Join with a single space.
//  5. Casing: preserve a word verbatim if it contains any uppercase letter
//     (SSL, IOS, SMB, OpenSSL, vCenter); otherwise Title-case it.
//
// Examples:
//
//	"Apache Tomcat .x Multiple Vulnerabilities" → "Apache Tomcat"
//	"Cisco IOS Software Smart Install Remote…"  → "Cisco IOS"
//	"Microsoft Windows SMB Remote Code…"        → "Microsoft Windows"
//	"OpenSSL 1.0.1 Multiple Vulnerabilities"    → "OpenSSL"
//	"SSL Certificate Cannot Be Trusted"         → "SSL Certificate"
func systemName(name string) string {
	words := strings.Fields(name)

	// Step 1: drop leading version-like tokens.
	for len(words) > 0 && versionRe.MatchString(words[0]) {
		words = words[1:]
	}

	// Step 2: collect up to 2 product words, stopping at a stopword.
	// Version-like tokens are skipped anywhere (not just the lead), so
	// "OpenSSL 1.0.1 Multiple…" → skip 1.0.1, stop at "Multiple" → "OpenSSL".
	const maxWords = 2
	var kept []string
	for _, w := range words {
		if len(kept) >= maxWords {
			break
		}
		if systemStopwords[strings.ToLower(w)] {
			break
		}
		// Skip version-like tokens (anywhere, not just leading).
		if versionRe.MatchString(w) {
			continue
		}
		// Casing: preserve if any uppercase letter exists; otherwise Title-case.
		hasUpper := false
		for _, r := range w {
			if r >= 'A' && r <= 'Z' {
				hasUpper = true
				break
			}
		}
		if hasUpper {
			kept = append(kept, w)
		} else {
			kept = append(kept, titleWord(w))
		}
	}

	// Minimum 1 word: if nothing was kept (all version tokens or name is empty)
	// take the first original word Title-cased.
	if len(kept) == 0 && len(words) > 0 {
		w := words[0]
		hasUpper := false
		for _, r := range w {
			if r >= 'A' && r <= 'Z' {
				hasUpper = true
				break
			}
		}
		if hasUpper {
			kept = append(kept, w)
		} else {
			kept = append(kept, titleWord(w))
		}
	}

	if len(kept) == 0 {
		// Degenerate input (empty/whitespace-only name): never return "" — System
		// is used as a folder-name segment downstream.
		return "Other"
	}
	return strings.Join(kept, " ")
}

// priorityRank maps a priority label to a sort rank (urgent=3 > high=2 >
// medium=1 > anything else=0). Used for ordering groups and CVEs.
func priorityRank(label string) int {
	switch strings.ToLower(label) {
	case "urgent":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	default:
		return 0
	}
}

// priorityDisplay returns the title-cased display form of a priority label.
// Unknown or empty labels → "Low".
func priorityDisplay(label string) string {
	switch strings.ToLower(label) {
	case "urgent":
		return "Urgent"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	default:
		return "Low"
	}
}

// cvssFloat parses a CVSS string to float64 for numeric comparisons.
// Returns -1 on empty string or parse error (sorts last).
func cvssFloat(s string) float64 {
	if s == "" {
		return -1
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return -1
	}
	return v
}

// maxPtr returns the larger of two *float64 values. Both nil → nil.
// One nil → the non-nil. Both non-nil → whichever is larger.
func maxPtr(a, b *float64) *float64 {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if *a >= *b {
		return a
	}
	return b
}

// distinctHosts accumulates distinct IP strings from the IPs slice of each
// GroupView into the provided set. Caller initialises the map.
func distinctHosts(groups []GroupView) int {
	seen := make(map[string]struct{})
	for _, g := range groups {
		for _, ip := range g.IPs {
			seen[ip] = struct{}{}
		}
	}
	return len(seen)
}

// sortCveViews sorts CVEs: priorityRank desc → cvssFloat desc → CVE string asc.
func sortCveViews(cs []CveView) {
	sort.SliceStable(cs, func(i, j int) bool {
		ri, rj := priorityRank(cs[i].Priority), priorityRank(cs[j].Priority)
		if ri != rj {
			return ri > rj
		}
		ci, cj := cvssFloat(cs[i].CVSS), cvssFloat(cs[j].CVSS)
		if ci != cj {
			return ci > cj
		}
		return cs[i].CVE < cs[j].CVE
	})
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

// Build merges the grouped vulnerability model with enrichment data and returns
// a fully populated, priority-sorted Report ready for the Vulnerabilities.md
// emitter.
func Build(groups []vuln.VulnGroup, enr map[string]enrich.VulnEnrichment, meta Meta) Report {
	views := make([]GroupView, 0, len(groups))

	for _, g := range groups {
		// ------------------------------------------------------------------
		// Per-CVE pass
		// ------------------------------------------------------------------
		cveViews := make([]CveView, 0, len(g.CVEs))

		// Track group-level aggregates derived from CVE enrichment.
		var unionCWEs []string            // ordered, deduplicated union of all CVE CWEs
		seenCWEs := make(map[string]bool) // for deduplication
		var maxPct *float64               // max non-nil EPSS percentile
		anyInKev := false
		anyPoc := false
		anyNuclei := false

		for _, cve := range g.CVEs {
			e := enr[cve.CVE] // absent → zero VulnEnrichment

			// Per-CVE priority.
			cPriority := priority.Label(cve.Risk, e.EpssPercentile, e.InKev)

			// Per-CVE flags.
			hasPoc := e.Poc != nil && e.Poc.HasPoc
			cNuclei := nucleiLinks(e.Poc)

			cv := CveView{
				CVE:         cve.CVE,
				CVSS:        cve.CVSS,
				Priority:    cPriority,
				Category:    category.Classify(e.CWEs, g.Name, cve.Description),
				HostCount:   cve.HostCount,
				InKev:       e.InKev,
				HasPoc:      hasPoc,
				HasNuclei:   len(cNuclei) > 0,
				EpssPercent: fmtPct(e.EpssPercentile),
				Description: e.Description,
				CWEs:        e.CWEs,
				HostsByPort: cve.HostsByPort,
				PocLinks:    pocLinks(e.Poc),
				NucleiLinks: cNuclei,
				RefLinks:    parseLinks(cve.SeeAlso),
			}
			cveViews = append(cveViews, cv)

			// Accumulate group-level data.
			for _, cw := range e.CWEs {
				if !seenCWEs[cw] {
					seenCWEs[cw] = true
					unionCWEs = append(unionCWEs, cw)
				}
			}
			maxPct = maxPtr(maxPct, e.EpssPercentile)
			if e.InKev {
				anyInKev = true
			}
			if hasPoc {
				anyPoc = true
			}
			if len(cNuclei) > 0 {
				anyNuclei = true
			}
		}

		// Sort CVEs: priorityRank desc → cvssFloat desc → CVE string asc.
		sortCveViews(cveViews)

		// ------------------------------------------------------------------
		// Group-level merge
		// ------------------------------------------------------------------

		// Category: re-classify using the real CWE union (overrides SP3a keyword).
		// category.Classify uses the group Description as the synopsis/text arg.
		cat := category.Classify(unionCWEs, g.Name, g.Description)

		// Group priority: uses maxPct from CVEs (nil for no-CVE groups).
		// For no-CVE groups anyInKev is already false and maxPct is nil.
		gPriority := priority.Label(g.Risk, maxPct, anyInKev)

		// Group-level PoC/Nuclei links: populated from the single CVE when exactly
		// one CVE exists; otherwise left empty (emitter uses per-CVE links).
		var gPocLinks, gNucleiLinks []Link
		if len(cveViews) == 1 {
			gPocLinks = cveViews[0].PocLinks
			gNucleiLinks = cveViews[0].NucleiLinks
		}

		gv := GroupView{
			Name:        g.Name,
			Category:    cat,
			Priority:    gPriority,
			CVSS:        g.CVSS,
			System:      productName(g.Name),
			HostCount:   g.HostCount,
			InKev:       anyInKev,
			HasPoc:      anyPoc,
			HasNuclei:   anyNuclei,
			EpssPercent: fmtPct(maxPct),
			CWEs:        unionCWEs,
			IPs:         g.IPs,
			HostsByPort: g.HostsByPort,
			Description: g.Description,
			RefLinks:    parseLinks(g.SeeAlso),
			PocLinks:    gPocLinks,
			NucleiLinks: gNucleiLinks,
			CVEs:        cveViews,
		}
		gv.Bucket = bucketOf(gv)
		views = append(views, gv)
	}

	// Sort groups: priorityRank desc → cvssFloat desc → Name asc.
	sort.SliceStable(views, func(i, j int) bool {
		ri, rj := priorityRank(views[i].Priority), priorityRank(views[j].Priority)
		if ri != rj {
			return ri > rj
		}
		ci, cj := cvssFloat(views[i].CVSS), cvssFloat(views[j].CVSS)
		if ci != cj {
			return ci > cj
		}
		return views[i].Name < views[j].Name
	})

	// Assign 1-based global priority rank after sorting.
	for i := range views {
		views[i].Rank = i + 1
	}

	// ------------------------------------------------------------------
	// Bands
	// ------------------------------------------------------------------
	bandLabels := []string{"urgent", "high", "medium", "low"}
	bands := make([]BandSummary, 0, 4)
	for _, bl := range bandLabels {
		var inBand []GroupView
		for _, gv := range views {
			if strings.ToLower(gv.Priority) == bl {
				inBand = append(inBand, gv)
			}
		}

		inKevCount := 0
		withPocCount := 0
		for _, gv := range inBand {
			if gv.InKev {
				inKevCount++
			}
			if gv.HasPoc {
				withPocCount++
			}
		}

		bands = append(bands, BandSummary{
			Priority: priorityDisplay(bl),
			Vulns:    len(inBand),
			Hosts:    distinctHosts(inBand),
			InKev:    inKevCount,
			WithPoc:  withPocCount,
		})
	}

	// ------------------------------------------------------------------
	// Report-level distinct host count
	// ------------------------------------------------------------------
	allDistinct := distinctHosts(views)

	return Report{
		Meta:      meta,
		VulnCount: len(groups),
		HostCount: allDistinct,
		Bands:     bands,
		Groups:    views,
	}
}
