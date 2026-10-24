package vulnview_test

import (
	"testing"

	"layzmd/internal/enrich"
	"layzmd/internal/vuln"
	"layzmd/internal/vulnview"
)

// ptr returns a pointer to f. Helper for constructing *float64 EPSS values.
func ptr(f float64) *float64 { return &f }

// buildTestInputs constructs the canonical three-group fixture used across
// all sub-tests.
//
//   - Group 0: "Apache Tomcat" — multi-CVE, Critical risk
//   - Group 1: "POODLE" — single-CVE, Medium risk, CVSS 3.4
//   - Group 2: "Unsupported" — no CVE, None risk ("Unsupported Software Detected")
func buildTestInputs() ([]vuln.VulnGroup, map[string]enrich.VulnEnrichment) {
	groups := []vuln.VulnGroup{
		{
			Name:     "Apache Tomcat",
			Category: "Other", // will be overridden by CWE-78 → RCE
			Risk:     "Critical",
			CVSS:     "9.8",
			IPs:      []string{"10.0.0.1", "10.0.0.2"},
			HostsByPort: []vuln.PortHosts{
				{Port: "8080/tcp", IPs: []string{"10.0.0.1", "10.0.0.2"}},
			},
			HostCount:   2,
			Description: "Apache Tomcat group description",
			SeeAlso:     "",
			CVEs: []vuln.VulnCve{
				{
					CVE:       "CVE-2020-1938",
					CVSS:      "9.8",
					Risk:      "Critical",
					HostCount: 2,
					IPs:       []string{"10.0.0.1", "10.0.0.2"},
					HostsByPort: []vuln.PortHosts{
						{Port: "8080/tcp", IPs: []string{"10.0.0.1", "10.0.0.2"}},
					},
					Description: "Nessus description AJP",
					SeeAlso:     "",
				},
				{
					CVE:       "CVE-2019-0221",
					CVSS:      "6.1",
					Risk:      "Medium",
					HostCount: 1,
					IPs:       []string{"10.0.0.1"},
					HostsByPort: []vuln.PortHosts{
						{Port: "8080/tcp", IPs: []string{"10.0.0.1"}},
					},
					Description: "Nessus description XSS",
					SeeAlso:     "",
				},
			},
		},
		{
			Name:     "POODLE",
			Category: "Cryptographic Weakness",
			Risk:     "Medium",
			CVSS:     "3.4",
			IPs:      []string{"10.0.0.3"},
			HostsByPort: []vuln.PortHosts{
				{Port: "443/tcp", IPs: []string{"10.0.0.3"}},
			},
			HostCount:   1,
			Description: "POODLE group description",
			SeeAlso:     "",
			CVEs: []vuln.VulnCve{
				{
					CVE:       "CVE-2014-3566",
					CVSS:      "3.4",
					Risk:      "Medium",
					HostCount: 1,
					IPs:       []string{"10.0.0.3"},
					HostsByPort: []vuln.PortHosts{
						{Port: "443/tcp", IPs: []string{"10.0.0.3"}},
					},
					Description: "Nessus POODLE description",
					SeeAlso:     "https://openssl.org/poodle",
				},
			},
		},
		{
			Name:        "Unsupported Software Detected",
			Category:    "Outdated Software",
			Risk:        "None",
			CVSS:        "",
			IPs:         []string{"10.0.0.4"},
			HostsByPort: nil,
			HostCount:   1,
			Description: "The remote host...",
			SeeAlso:     "",
			CVEs:        nil,
		},
	}

	poc1938 := &enrich.PocResult{
		HasPoc:  true,
		PocURLs: []string{"https://github.com/x/ghostcat"},
	}
	enr := map[string]enrich.VulnEnrichment{
		"CVE-2020-1938": {
			InKev:          true,
			EpssPercentile: ptr(0.9418),
			EpssScore:      ptr(0.98),
			CWEs:           []string{"CWE-78"},
			Description:    "AJP...",
			Poc:            poc1938,
		},
		"CVE-2019-0221": {
			EpssPercentile: ptr(0.031),
		},
		"CVE-2014-3566": {
			EpssPercentile: ptr(0.010),
		},
	}
	return groups, enr
}

func TestBuild_GroupOrder(t *testing.T) {
	groups, enr := buildTestInputs()
	r := vulnview.Build(groups, enr, vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"})

	if len(r.Groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(r.Groups))
	}
	// Apache (urgent) must be first. Names are now "<product> — <class>".
	if r.Groups[0].Name != "Apache Tomcat" {
		t.Errorf("groups[0].Name = %q, want Apache Tomcat", r.Groups[0].Name)
	}
	// POODLE (low, cvss 3.4) must be second — same band as Unsupported (low, no cvss)
	// but higher CVSS numeric value.
	if r.Groups[1].Name != "POODLE" {
		t.Errorf("groups[1].Name = %q, want POODLE", r.Groups[1].Name)
	}
	// Unsupported sorts last (same low band, lower CVSS).
	if r.Groups[2].Name != "Unsupported Software Detected" {
		t.Errorf("groups[2].Name = %q, want Unsupported Software Detected", r.Groups[2].Name)
	}
}

func TestBuild_ApacheTomcat_GroupFields(t *testing.T) {
	groups, enr := buildTestInputs()
	r := vulnview.Build(groups, enr, vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"})

	g := r.Groups[0]

	// Priority: SeverityPoints(Critical)=4 + EpssPoints(0.9418→>=0.90→4) + KevPoints(true)=4 = 12 → "urgent"
	if g.Priority != "urgent" {
		t.Errorf("Apache group Priority = %q, want urgent", g.Priority)
	}
	// Category: CWE-78 → RCE (overrides keyword "Other")
	if g.Category != "RCE" {
		t.Errorf("Apache group Category = %q, want RCE", g.Category)
	}
	if !g.InKev {
		t.Error("Apache group InKev should be true")
	}
	if !g.HasPoc {
		t.Error("Apache group HasPoc should be true")
	}
	// maxPct = 0.9418 → fmtPct = "94.2%"
	if g.EpssPercent != "94.2%" {
		t.Errorf("Apache group EpssPercent = %q, want 94.2%%", g.EpssPercent)
	}
}

func TestBuild_ApacheTomcat_CVESort(t *testing.T) {
	groups, enr := buildTestInputs()
	r := vulnview.Build(groups, enr, vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"})

	g := r.Groups[0]
	if len(g.CVEs) != 2 {
		t.Fatalf("Apache group: expected 2 CVEs, got %d", len(g.CVEs))
	}

	// CVE-2020-1938: urgent (rank 3), CVSS 9.8
	// CVE-2019-0221: low (rank 0), CVSS 6.1
	// Sort: priorityRank desc, cvssFloat desc, CVE asc → 1938 first
	if g.CVEs[0].CVE != "CVE-2020-1938" {
		t.Errorf("CVEs[0].CVE = %q, want CVE-2020-1938", g.CVEs[0].CVE)
	}
	if g.CVEs[1].CVE != "CVE-2019-0221" {
		t.Errorf("CVEs[1].CVE = %q, want CVE-2019-0221", g.CVEs[1].CVE)
	}
}

func TestBuild_CVE20201938_Fields(t *testing.T) {
	groups, enr := buildTestInputs()
	r := vulnview.Build(groups, enr, vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"})

	var cv vulnview.CveView
	for _, c := range r.Groups[0].CVEs {
		if c.CVE == "CVE-2020-1938" {
			cv = c
			break
		}
	}

	// Priority: SeverityPoints(Critical)=4 + EpssPoints(0.9418)=4 + KevPoints(true)=4 = 12 → "urgent"
	if cv.Priority != "urgent" {
		t.Errorf("CVE-2020-1938 Priority = %q, want urgent", cv.Priority)
	}
	if !cv.InKev {
		t.Error("CVE-2020-1938 InKev should be true")
	}
	if !cv.HasPoc {
		t.Error("CVE-2020-1938 HasPoc should be true")
	}
	if cv.EpssPercent != "94.2%" {
		t.Errorf("CVE-2020-1938 EpssPercent = %q, want 94.2%%", cv.EpssPercent)
	}
	// Description comes from NVD enrichment, not Nessus.
	if cv.Description != "AJP..." {
		t.Errorf("CVE-2020-1938 Description = %q, want AJP...", cv.Description)
	}
	// PocLinks from VulnCheck URL — label is now "VulnCheck" (source label, not host).
	if len(cv.PocLinks) != 1 {
		t.Fatalf("CVE-2020-1938 PocLinks len = %d, want 1", len(cv.PocLinks))
	}
	if cv.PocLinks[0].URL != "https://github.com/x/ghostcat" {
		t.Errorf("CVE-2020-1938 PocLinks[0].URL = %q", cv.PocLinks[0].URL)
	}
	if cv.PocLinks[0].Label != "VulnCheck" {
		t.Errorf("CVE-2020-1938 PocLinks[0].Label = %q, want VulnCheck", cv.PocLinks[0].Label)
	}
	// CWEs: CVE-2020-1938 has CWE-78.
	if len(cv.CWEs) != 1 || cv.CWEs[0] != "CWE-78" {
		t.Errorf("CVE-2020-1938 CWEs = %v, want [CWE-78]", cv.CWEs)
	}
}

func TestBuild_CVE20190221_Fields(t *testing.T) {
	groups, enr := buildTestInputs()
	r := vulnview.Build(groups, enr, vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"})

	var cv vulnview.CveView
	for _, c := range r.Groups[0].CVEs {
		if c.CVE == "CVE-2019-0221" {
			cv = c
			break
		}
	}

	// Priority: SeverityPoints(Medium)=2 + EpssPoints(0.031→<0.40→1) + KevPoints(false)=0 = 3 → "low"
	if cv.Priority != "low" {
		t.Errorf("CVE-2019-0221 Priority = %q, want low", cv.Priority)
	}
	if cv.InKev {
		t.Error("CVE-2019-0221 InKev should be false")
	}
	if cv.HasPoc {
		t.Error("CVE-2019-0221 HasPoc should be false")
	}
}

func TestBuild_POODLE_SingleCVE(t *testing.T) {
	groups, enr := buildTestInputs()
	r := vulnview.Build(groups, enr, vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"})

	// POODLE is at index 1 in sorted output.
	g := r.Groups[1]
	if g.Name != "POODLE" {
		t.Fatalf("groups[1].Name = %q, want POODLE", g.Name)
	}

	// Group priority: SeverityPoints(Medium)=2 + EpssPoints(0.010→<0.40→1) + KevPoints(false)=0 = 3 → "low"
	if g.Priority != "low" {
		t.Errorf("POODLE group Priority = %q, want low", g.Priority)
	}

	if len(g.CVEs) != 1 {
		t.Fatalf("POODLE group CVEs len = %d, want 1", len(g.CVEs))
	}

	cv := g.CVEs[0]
	if cv.CVE != "CVE-2014-3566" {
		t.Errorf("CVE = %q, want CVE-2014-3566", cv.CVE)
	}

	// RefLinks from Nessus See-Also of the VulnCve.
	if len(cv.RefLinks) != 1 {
		t.Fatalf("CVE-2014-3566 RefLinks len = %d, want 1", len(cv.RefLinks))
	}
	if cv.RefLinks[0].Label != "openssl.org" {
		t.Errorf("RefLinks[0].Label = %q, want openssl.org", cv.RefLinks[0].Label)
	}
	if cv.RefLinks[0].URL != "https://openssl.org/poodle" {
		t.Errorf("RefLinks[0].URL = %q, want https://openssl.org/poodle", cv.RefLinks[0].URL)
	}
}

func TestBuild_Unsupported_NoCVE(t *testing.T) {
	groups, enr := buildTestInputs()
	r := vulnview.Build(groups, enr, vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"})

	g := r.Groups[2]
	if g.Name != "Unsupported Software Detected" {
		t.Fatalf("groups[2].Name = %q", g.Name)
	}

	// no CVE → low priority regardless
	if g.Priority != "low" {
		t.Errorf("Unsupported group Priority = %q, want low", g.Priority)
	}
	if len(g.CVEs) != 0 {
		t.Errorf("Unsupported group CVEs len = %d, want 0", len(g.CVEs))
	}
	// Nessus description preserved.
	if g.Description != "The remote host..." {
		t.Errorf("Unsupported group Description = %q, want 'The remote host...'", g.Description)
	}
}

func TestBuild_Bands(t *testing.T) {
	groups, enr := buildTestInputs()
	r := vulnview.Build(groups, enr, vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"})

	// Bands must be exactly four entries in order.
	if len(r.Bands) != 4 {
		t.Fatalf("Bands len = %d, want 4", len(r.Bands))
	}

	// Expected band priorities in order.
	wantPriorities := []string{"Urgent", "High", "Medium", "Low"}
	for i, want := range wantPriorities {
		if r.Bands[i].Priority != want {
			t.Errorf("Bands[%d].Priority = %q, want %q", i, r.Bands[i].Priority, want)
		}
	}

	// Urgent band: 1 group (Apache Tomcat), InKev=1, WithPoc=1.
	ub := r.Bands[0]
	if ub.Vulns != 1 {
		t.Errorf("Urgent.Vulns = %d, want 1", ub.Vulns)
	}
	if ub.Hosts != 2 {
		// Apache IPs: 10.0.0.1, 10.0.0.2
		t.Errorf("Urgent.Hosts = %d, want 2", ub.Hosts)
	}
	if ub.InKev != 1 {
		t.Errorf("Urgent.InKev = %d, want 1", ub.InKev)
	}
	if ub.WithPoc != 1 {
		t.Errorf("Urgent.WithPoc = %d, want 1", ub.WithPoc)
	}

	// High band: 0 groups.
	hb := r.Bands[1]
	if hb.Vulns != 0 {
		t.Errorf("High.Vulns = %d, want 0", hb.Vulns)
	}

	// Medium band: 0 groups (POODLE is "low" per the real priority.Label).
	mb := r.Bands[2]
	if mb.Vulns != 0 {
		t.Errorf("Medium.Vulns = %d, want 0 (POODLE scores low with real priority.Label)", mb.Vulns)
	}

	// Low band: 2 groups (POODLE + Unsupported), InKev=0, WithPoc=0.
	lb := r.Bands[3]
	if lb.Vulns != 2 {
		t.Errorf("Low.Vulns = %d, want 2", lb.Vulns)
	}
	// Distinct hosts: 10.0.0.3 (POODLE) + 10.0.0.4 (Unsupported) = 2
	if lb.Hosts != 2 {
		t.Errorf("Low.Hosts = %d, want 2 (10.0.0.3 + 10.0.0.4)", lb.Hosts)
	}
	if lb.InKev != 0 {
		t.Errorf("Low.InKev = %d, want 0", lb.InKev)
	}
	if lb.WithPoc != 0 {
		t.Errorf("Low.WithPoc = %d, want 0", lb.WithPoc)
	}
}

func TestBuild_ReportCounts(t *testing.T) {
	groups, enr := buildTestInputs()
	r := vulnview.Build(groups, enr, vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"})

	if r.VulnCount != 3 {
		t.Errorf("VulnCount = %d, want 3", r.VulnCount)
	}
	// Distinct hosts across all groups: 10.0.0.1, 10.0.0.2 (Apache) + 10.0.0.3 (POODLE) + 10.0.0.4 (Unsupported) = 4
	if r.HostCount != 4 {
		t.Errorf("HostCount = %d, want 4", r.HostCount)
	}
}

func TestBuild_Meta(t *testing.T) {
	groups, enr := buildTestInputs()
	r := vulnview.Build(groups, enr, vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"})

	if r.Meta.ScanName != "Test" {
		t.Errorf("Meta.ScanName = %q", r.Meta.ScanName)
	}
	if r.Meta.Generated != "2026-07-10" {
		t.Errorf("Meta.Generated = %q", r.Meta.Generated)
	}
}

func TestBuild_AbsentEnrichment(t *testing.T) {
	// A group with a CVE that has no enrichment entry should get zero enrichment
	// and "low" priority from severity alone (Low risk → score 1 → "low").
	groups := []vuln.VulnGroup{
		{
			Name: "Test Vuln",
			Risk: "Low",
			CVSS: "2.0",
			IPs:  []string{"192.168.1.1"},
			CVEs: []vuln.VulnCve{
				{CVE: "CVE-9999-0001", CVSS: "2.0", Risk: "Low", HostCount: 1, IPs: []string{"192.168.1.1"}},
			},
		},
	}
	r := vulnview.Build(groups, map[string]enrich.VulnEnrichment{}, vulnview.Meta{})

	if len(r.Groups) != 1 {
		t.Fatalf("expected 1 group")
	}
	g := r.Groups[0]
	// Low severity, no EPSS (nil percentile), not in KEV → score=1 → "low"
	if g.Priority != "low" {
		t.Errorf("Priority = %q, want low", g.Priority)
	}
	if g.InKev {
		t.Error("InKev should be false")
	}
	if g.HasPoc {
		t.Error("HasPoc should be false")
	}
	if g.EpssPercent != "" {
		t.Errorf("EpssPercent = %q, want empty", g.EpssPercent)
	}
	cv := g.CVEs[0]
	if cv.Description != "" {
		t.Errorf("CVE Description should be empty when no enrichment, got %q", cv.Description)
	}
}

func TestBuild_PocVulnCheck(t *testing.T) {
	// Verify the VulnCheck PoC link is set correctly.
	groups := []vuln.VulnGroup{
		{
			Name: "Vuln With PoC",
			Risk: "High",
			CVSS: "7.5",
			IPs:  []string{"10.1.1.1"},
			CVEs: []vuln.VulnCve{
				{CVE: "CVE-2021-1234", CVSS: "7.5", Risk: "High", HostCount: 1, IPs: []string{"10.1.1.1"}},
			},
		},
	}
	enr := map[string]enrich.VulnEnrichment{
		"CVE-2021-1234": {
			Poc: &enrich.PocResult{
				HasPoc:  true,
				PocURLs: []string{"https://exploit.example.com/poc"},
			},
		},
	}
	r := vulnview.Build(groups, enr, vulnview.Meta{})
	cv := r.Groups[0].CVEs[0]

	if len(cv.PocLinks) != 1 || cv.PocLinks[0].Label != "VulnCheck" ||
		cv.PocLinks[0].URL != "https://exploit.example.com/poc" {
		t.Fatalf("PocLinks = %+v, want single VulnCheck", cv.PocLinks)
	}
}

func TestBuild_UnionCWEs_CategoryOverride(t *testing.T) {
	// Two CVEs contributing different CWEs; first-seen win for the union.
	groups := []vuln.VulnGroup{
		{
			Name:     "Multi-CWE Group",
			Category: "Other",
			Risk:     "High",
			CVSS:     "8.0",
			IPs:      []string{"10.0.0.1"},
			CVEs: []vuln.VulnCve{
				{CVE: "CVE-2021-0001", CVSS: "8.0", Risk: "High", HostCount: 1, IPs: []string{"10.0.0.1"}},
				{CVE: "CVE-2021-0002", CVSS: "7.0", Risk: "High", HostCount: 1, IPs: []string{"10.0.0.1"}},
			},
		},
	}
	enr := map[string]enrich.VulnEnrichment{
		"CVE-2021-0001": {CWEs: []string{"CWE-89"}}, // SQL Injection
		"CVE-2021-0002": {CWEs: []string{"CWE-79"}}, // Cross-Site Scripting
	}
	// Iteration over CVEs in the VulnGroup is in slice order; CVE-2021-0001 first → CWE-89 first → SQL Injection wins.
	r := vulnview.Build(groups, enr, vulnview.Meta{})

	if len(r.Groups) != 1 {
		t.Fatalf("expected 1 group")
	}
	if r.Groups[0].Category != "SQL Injection" {
		t.Errorf("Category = %q, want SQL Injection (CWE-89 first)", r.Groups[0].Category)
	}
}

func TestBuild_ParseLinks_MultipleURLs(t *testing.T) {
	// SeeAlso with multiple space-separated URLs; non-URL tokens ignored.
	groups := []vuln.VulnGroup{
		{
			Name: "Link Test",
			Risk: "Low",
			CVSS: "1.0",
			IPs:  []string{"10.0.0.1"},
			CVEs: []vuln.VulnCve{
				{
					CVE:     "CVE-2022-0001",
					CVSS:    "1.0",
					Risk:    "Low",
					IPs:     []string{"10.0.0.1"},
					SeeAlso: "https://example.com/advisory http://nvd.nist.gov/vuln not-a-url",
				},
			},
		},
	}
	r := vulnview.Build(groups, map[string]enrich.VulnEnrichment{}, vulnview.Meta{})
	cv := r.Groups[0].CVEs[0]

	if len(cv.RefLinks) != 2 {
		t.Fatalf("RefLinks len = %d, want 2 (non-URL token filtered out)", len(cv.RefLinks))
	}
	if cv.RefLinks[0].Label != "example.com" {
		t.Errorf("RefLinks[0].Label = %q, want example.com", cv.RefLinks[0].Label)
	}
	if cv.RefLinks[1].Label != "nvd.nist.gov" {
		t.Errorf("RefLinks[1].Label = %q, want nvd.nist.gov", cv.RefLinks[1].Label)
	}
}

func TestBuild_GroupPocLinks_SingleCVE(t *testing.T) {
	// For a single-CVE group the group's PocLinks should be populated from
	// the single CVE's enrichment. Label is now "VulnCheck" (source label).
	groups := []vuln.VulnGroup{
		{
			Name: "Single CVE PoC Group",
			Risk: "High",
			CVSS: "7.0",
			IPs:  []string{"10.0.0.1"},
			CVEs: []vuln.VulnCve{
				{CVE: "CVE-2023-0001", CVSS: "7.0", Risk: "High", HostCount: 1, IPs: []string{"10.0.0.1"}},
			},
		},
	}
	enr := map[string]enrich.VulnEnrichment{
		"CVE-2023-0001": {
			Poc: &enrich.PocResult{
				HasPoc:  true,
				PocURLs: []string{"https://github.com/example/poc"},
			},
		},
	}
	r := vulnview.Build(groups, enr, vulnview.Meta{})
	g := r.Groups[0]

	// Group PocLinks should be set for single-CVE groups.
	if len(g.PocLinks) != 1 {
		t.Fatalf("group PocLinks len = %d, want 1 for single-CVE group", len(g.PocLinks))
	}
	if g.PocLinks[0].Label != "VulnCheck" {
		t.Errorf("group PocLinks[0].Label = %q, want VulnCheck", g.PocLinks[0].Label)
	}
}

// ---------------------------------------------------------------------------
// Task 2 — new tests: CWEs, PoC-source labels, System, Rank
// ---------------------------------------------------------------------------

// TestBuild_GroupCWEs verifies that GroupView.CWEs is the first-seen deduped
// union of all CVE CWEs within the group, and that CveView.CWEs carries each
// CVE's own CWEs.
func TestBuild_GroupCWEs(t *testing.T) {
	groups := []vuln.VulnGroup{
		{
			Name: "CWE Union Group",
			Risk: "High",
			CVSS: "8.0",
			IPs:  []string{"10.0.0.1"},
			CVEs: []vuln.VulnCve{
				{CVE: "CVE-2024-0001", CVSS: "8.0", Risk: "High", HostCount: 1, IPs: []string{"10.0.0.1"}},
				{CVE: "CVE-2024-0002", CVSS: "7.0", Risk: "High", HostCount: 1, IPs: []string{"10.0.0.1"}},
				{CVE: "CVE-2024-0003", CVSS: "6.0", Risk: "Medium", HostCount: 1, IPs: []string{"10.0.0.1"}},
			},
		},
	}
	enr := map[string]enrich.VulnEnrichment{
		// CVE-0001: CWE-79 and CWE-89
		"CVE-2024-0001": {CWEs: []string{"CWE-79", "CWE-89"}},
		// CVE-0002: CWE-89 (duplicate) and CWE-119 (new)
		"CVE-2024-0002": {CWEs: []string{"CWE-89", "CWE-119"}},
		// CVE-0003: no CWEs
		"CVE-2024-0003": {},
	}
	r := vulnview.Build(groups, enr, vulnview.Meta{})
	g := r.Groups[0]

	// Union (first-seen, deduped, ordered by first appearance):
	// CVE-0001 → CWE-79, CWE-89; CVE-0002 adds CWE-119 (CWE-89 already seen).
	// Expected: [CWE-79, CWE-89, CWE-119].
	wantGroupCWEs := []string{"CWE-79", "CWE-89", "CWE-119"}
	if len(g.CWEs) != len(wantGroupCWEs) {
		t.Fatalf("GroupView.CWEs = %v, want %v", g.CWEs, wantGroupCWEs)
	}
	for i, want := range wantGroupCWEs {
		if g.CWEs[i] != want {
			t.Errorf("GroupView.CWEs[%d] = %q, want %q", i, g.CWEs[i], want)
		}
	}

	// Per-CVE CWEs: each CveView carries its own CVE's CWEs.
	// After sort: CVE-2024-0001 (High, 8.0) first, CVE-2024-0002 (High, 7.0) second,
	// CVE-2024-0003 (Medium, 6.0) last (lower priority rank).
	if len(g.CVEs) != 3 {
		t.Fatalf("CVEs len = %d, want 3", len(g.CVEs))
	}
	for _, cv := range g.CVEs {
		switch cv.CVE {
		case "CVE-2024-0001":
			want := []string{"CWE-79", "CWE-89"}
			if len(cv.CWEs) != len(want) || cv.CWEs[0] != want[0] || cv.CWEs[1] != want[1] {
				t.Errorf("CVE-2024-0001 CWEs = %v, want %v", cv.CWEs, want)
			}
		case "CVE-2024-0002":
			want := []string{"CWE-89", "CWE-119"}
			if len(cv.CWEs) != len(want) || cv.CWEs[0] != want[0] || cv.CWEs[1] != want[1] {
				t.Errorf("CVE-2024-0002 CWEs = %v, want %v", cv.CWEs, want)
			}
		case "CVE-2024-0003":
			if len(cv.CWEs) != 0 {
				t.Errorf("CVE-2024-0003 CWEs = %v, want empty", cv.CWEs)
			}
		}
	}
}

// TestBuild_PocSourceLabels verifies that VulnCheck PoC URLs are labelled
// "VulnCheck", one Link per URL, in order.
func TestBuild_PocSourceLabels(t *testing.T) {
	groups := []vuln.VulnGroup{
		{
			Name: "PoC Source Label Test",
			Risk: "High",
			CVSS: "8.0",
			IPs:  []string{"10.0.0.1"},
			CVEs: []vuln.VulnCve{
				{CVE: "CVE-2024-9001", CVSS: "8.0", Risk: "High", HostCount: 1, IPs: []string{"10.0.0.1"}},
			},
		},
	}
	enr := map[string]enrich.VulnEnrichment{
		"CVE-2024-9001": {
			Poc: &enrich.PocResult{
				HasPoc:  true,
				PocURLs: []string{"https://x/1", "https://y/2"},
			},
		},
	}
	r := vulnview.Build(groups, enr, vulnview.Meta{})
	cv := r.Groups[0].CVEs[0]

	wantPoc := []vulnview.Link{
		{Label: "VulnCheck", URL: "https://x/1"},
		{Label: "VulnCheck", URL: "https://y/2"},
	}
	if len(cv.PocLinks) != len(wantPoc) {
		t.Fatalf("PocLinks = %v, want %v", cv.PocLinks, wantPoc)
	}
	for i, want := range wantPoc {
		if cv.PocLinks[i] != want {
			t.Errorf("PocLinks[%d] = %+v, want %+v", i, cv.PocLinks[i], want)
		}
	}
}

// TestBuild_SystemName verifies that GroupView.System is derived correctly
// from the group Name via the systemName heuristic.
func TestBuild_SystemName(t *testing.T) {
	cases := []struct {
		name       string
		wantSystem string
	}{
		{"Apache Tomcat .x Multiple Vulnerabilities", "Apache Tomcat"},
		{"Cisco IOS Software Smart Install Remote Code Execution", "Cisco IOS"},
		{"Microsoft Windows SMB Remote Code Execution Vulnerability", "Microsoft Windows"},
		{"OpenSSL 1.0.1 Multiple Vulnerabilities", "OpenSSL"},
		{"SSL Certificate Cannot Be Trusted", "SSL Certificate"},
	}

	for _, tc := range cases {
		groups := []vuln.VulnGroup{
			{
				Name: tc.name,
				Risk: "Medium",
				CVSS: "5.0",
				IPs:  []string{"10.0.0.1"},
				CVEs: nil,
			},
		}
		r := vulnview.Build(groups, map[string]enrich.VulnEnrichment{}, vulnview.Meta{})
		if len(r.Groups) != 1 {
			t.Fatalf("expected 1 group for name %q", tc.name)
		}
		got := r.Groups[0].System
		if got != tc.wantSystem {
			t.Errorf("systemName(%q) = %q, want %q", tc.name, got, tc.wantSystem)
		}
	}
}

// TestBuild_Rank verifies that Groups[i].Rank == i+1 (1-based) after the
// existing priority/CVSS/Name sort.
func TestBuild_Rank(t *testing.T) {
	groups, enr := buildTestInputs()
	r := vulnview.Build(groups, enr, vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"})

	if len(r.Groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(r.Groups))
	}
	for i, g := range r.Groups {
		wantRank := i + 1
		if g.Rank != wantRank {
			t.Errorf("Groups[%d] (%q) Rank = %d, want %d", i, g.Name, g.Rank, wantRank)
		}
	}
}
