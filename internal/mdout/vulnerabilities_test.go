package mdout

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"layzmd/internal/vuln"
	"layzmd/internal/vulnview"
)

// buildTestReport builds a hand-crafted vulnview.Report covering all four
// rendering cases:
//  1. multi-CVE group, group-level hosts (High Priority bucket)
//  2. multi-CVE group with per-port host blocks (High Priority bucket)
//  3. single-CVE group with CWEs (Cryptographic bucket)
//  4. no-CVE portless group (Outdated bucket)
//
// Also exercises: CWEs on groups and CVEs, source-labeled PoC links, per-CVE
// categories, semantic Bucket assignment, System / Rank fields.
func buildTestReport() vulnview.Report {
	return vulnview.Report{
		Meta:      vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"},
		VulnCount: 4,
		HostCount: 6,
		Bands: []vulnview.BandSummary{
			{Priority: "Urgent", Vulns: 2, Hosts: 5, InKev: 2, WithPoc: 2},
			{Priority: "High", Vulns: 0, Hosts: 0, InKev: 0, WithPoc: 0},
			{Priority: "Medium", Vulns: 1, Hosts: 1, InKev: 0, WithPoc: 0},
			{Priority: "Low", Vulns: 1, Hosts: 1, InKev: 0, WithPoc: 0},
		},
		Groups: []vulnview.GroupView{
			// Case 1: multi-CVE where both CVEs share the same hosts on the same
			// port → consolidated map == each CVE's HostsByPort → hosts shown once,
			// no per-CVE host blocks.
			// CVE-2023-2222 lists IPs in reverse order to exercise the order-independent
			// de-dup fix (B2): should still de-dup to one consolidated block.
			{
				Name:        "Multi-Shared CVE Group",
				Category:    "Authentication Bypass",
				Bucket:      vulnview.BucketHighPriority,
				Priority:    "urgent",
				System:      "Multi-Shared",
				Rank:        1,
				CVSS:        "8.1",
				HostCount:   2,
				InKev:       true,
				HasPoc:      true,
				EpssPercent: "72.3%",
				CWEs:        []string{"CWE-287"},
				IPs:         []string{"10.0.0.1", "10.0.0.2"},
				CVEs: []vulnview.CveView{
					{
						CVE:         "CVE-2023-1111",
						CVSS:        "8.1",
						Priority:    "urgent",
						HostCount:   2,
						InKev:       true,
						HasPoc:      true,
						EpssPercent: "72.3%",
						Description: "Authentication bypass via crafted request.",
						CWEs:        []string{"CWE-287"},
						HostsByPort: []vuln.PortHosts{
							{Port: "8443/tcp", IPs: []string{"10.0.0.1", "10.0.0.2"}},
						},
						PocLinks: []vulnview.Link{
							{Label: "VulnCheck", URL: "https://github.com/y/poc1"},
						},
						RefLinks: []vulnview.Link{
							{Label: "vendor.example.com", URL: "https://vendor.example.com/advisory"},
						},
					},
					{
						CVE:         "CVE-2023-2222",
						CVSS:        "7.5",
						Priority:    "high",
						HostCount:   2,
						EpssPercent: "45.0%",
						Description: "Privilege escalation in the same product.",
						// IPs in reverse order — de-dup must still collapse to one block.
						HostsByPort: []vuln.PortHosts{
							{Port: "8443/tcp", IPs: []string{"10.0.0.2", "10.0.0.1"}},
						},
					},
				},
			},
			// Case 2: multi-CVE where each CVE hits a different port/host set →
			// consolidated map has two ports, neither CVE matches → both keep blocks.
			{
				Name:        "Apache Tomcat — Multiple Vulnerabilities",
				Category:    "RCE",
				Bucket:      vulnview.BucketHighPriority,
				Priority:    "urgent",
				System:      "Apache Tomcat",
				Rank:        2,
				CVSS:        "9.8",
				HostCount:   3,
				InKev:       true,
				HasPoc:      true,
				EpssPercent: "94.2%",
				CWEs:        []string{"CWE-22", "CWE-79"},
				IPs:         []string{"10.20.1.11", "10.20.1.12", "10.20.1.15"},
				CVEs: []vulnview.CveView{
					{
						CVE:         "CVE-2020-1938",
						CVSS:        "9.8",
						Priority:    "urgent",
						HostCount:   2,
						InKev:       true,
						HasPoc:      true,
						EpssPercent: "94.2%",
						Description: "AJP Connector request injection allows reading web-app files.",
						CWEs:        []string{"CWE-22"},
						HostsByPort: []vuln.PortHosts{
							{Port: "8009/tcp", IPs: []string{"10.20.1.11", "10.20.1.12"}},
						},
						PocLinks: []vulnview.Link{
							{Label: "VulnCheck", URL: "https://github.com/x/ghostcat"},
						},
						RefLinks: []vulnview.Link{
							{Label: "tomcat.apache.org", URL: "https://tomcat.apache.org/advisory"},
						},
					},
					{
						CVE:         "CVE-2019-0221",
						CVSS:        "6.1",
						Priority:    "low",
						HostCount:   1,
						EpssPercent: "3.1%",
						CWEs:        []string{"CWE-79"},
						HostsByPort: []vuln.PortHosts{
							{Port: "8080/tcp", IPs: []string{"10.20.1.15"}},
						},
					},
				},
			},
			// Case 3: single-CVE group, with CWEs.
			{
				Name:        "SSL/TLS — POODLE",
				Category:    "Cryptographic Weakness",
				Bucket:      vulnview.BucketCrypto,
				Priority:    "medium",
				System:      "SSL-TLS",
				Rank:        3,
				CVSS:        "3.4",
				HostCount:   1,
				InKev:       false,
				HasPoc:      false,
				EpssPercent: "55.0%",
				CWEs:        []string{"CWE-326"},
				IPs:         []string{"10.20.2.5"},
				HostsByPort: []vuln.PortHosts{
					{Port: "443/tcp", IPs: []string{"10.20.2.5"}},
				},
				RefLinks: []vulnview.Link{
					{Label: "openssl.org", URL: "https://openssl.org/poodle"},
				},
				CVEs: []vulnview.CveView{
					{
						CVE:         "CVE-2014-3566",
						CVSS:        "3.4",
						Priority:    "medium",
						HostCount:   1,
						EpssPercent: "55.0%",
						CWEs:        []string{"CWE-326"},
						Description: "SSLv3 CBC padding allows MITM plaintext recovery.",
					},
				},
			},
			// Case 4: no-CVE portless group.
			{
				Name:        "Microsoft Windows Server 2012 — Unsupported",
				Category:    "Outdated Software",
				Bucket:      vulnview.BucketOutdated,
				Priority:    "low",
				System:      "Microsoft Windows",
				Rank:        4,
				CVSS:        "",
				HostCount:   1,
				IPs:         []string{"10.20.4.7"},
				Description: "The remote host runs an unsupported Windows Server.",
				CVEs:        nil,
			},
		},
	}
}

// ── Slug tests ──────────────────────────────────────────────────────────────

func TestSlug(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Apache Tomcat — Multiple Vulnerabilities", "apache-tomcat-multiple-vulnerabilities"},
		{"VMware vCenter (VMSA-2024-0019)", "vmware-vcenter-vmsa-2024-0019"},
		{"", "group"},
		{"  --- ", "group"},
		{"SSL/TLS — POODLE", "ssl-tls-poodle"},
		{"Multi-Shared CVE Group", "multi-shared-cve-group"},
		// Length cap: 80 chars.
		{strings.Repeat("a", 90), strings.Repeat("a", 80)},
		// Non-alphanum at position 80 boundary gets trimmed.
		{"aaaa bbb" + strings.Repeat("c", 73), "aaaa-bbb" + strings.Repeat("c", 72)},
	}

	for _, tc := range cases {
		got := Slug(tc.in)
		if got != tc.want {
			t.Errorf("Slug(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── Index golden test ────────────────────────────────────────────────────────

func TestRenderVulnerabilitiesIndex_GoldenMatch(t *testing.T) {
	r := buildTestReport()
	got := normalizeNewlines(RenderVulnerabilitiesIndex(r))

	goldenBytes, err := os.ReadFile("../../testdata/golden_vuln_index.md")
	if err != nil {
		t.Fatalf("read golden_vuln_index.md: %v", err)
	}
	want := normalizeNewlines(string(goldenBytes))

	if got != want {
		t.Errorf("RenderVulnerabilitiesIndex mismatch:\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

// ── Group note golden test (Multi-Shared: B2 de-dup, hosts shown once) ──────

func TestRenderVulnGroupNote_GoldenMatch(t *testing.T) {
	r := buildTestReport()
	multiShared := r.Groups[0] // "Multi-Shared CVE Group"
	got := normalizeNewlines(RenderVulnGroupNote(multiShared))

	goldenBytes, err := os.ReadFile("../../testdata/golden_vuln_group.md")
	if err != nil {
		t.Fatalf("read golden_vuln_group.md: %v", err)
	}
	want := normalizeNewlines(string(goldenBytes))

	if got != want {
		t.Errorf("RenderVulnGroupNote (Multi-Shared) mismatch:\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

// ── Multi-CVE group: one section per CVE, group-level Affected assets ────────

func TestRenderVulnGroupNote_MultiCVE(t *testing.T) {
	r := buildTestReport()
	tomcat := r.Groups[1] // "Apache Tomcat — Multiple Vulnerabilities"
	got := RenderVulnGroupNote(tomcat)

	// Frontmatter + H1 title.
	if !strings.HasPrefix(got, "---\n") {
		t.Errorf("expected YAML frontmatter, got: %q", got[:40])
	}
	if !strings.Contains(got, "\n# Apache Tomcat") {
		t.Errorf("expected H1 title in note, got: %q", got[:100])
	}

	// Group-level Affected assets section, emitted once, before the CVE sections.
	assetsIdx := strings.Index(got, "## Affected assets")
	if assetsIdx == -1 {
		t.Fatal("missing '## Affected assets' section")
	}
	if strings.Count(got, "## Affected assets") != 1 {
		t.Error("expected exactly one '## Affected assets' section")
	}

	// One section per CVE, each a large header.
	cve1Idx := strings.Index(got, "## CVE-2020-1938")
	cve2Idx := strings.Index(got, "## CVE-2019-0221")
	if cve1Idx == -1 || cve2Idx == -1 {
		t.Fatal("expected a '## <CVE>' section for each CVE")
	}
	if assetsIdx > cve1Idx {
		t.Error("Affected assets should appear before the per-CVE sections")
	}

	// Bold detail lines and per-CVE CWE.
	if !strings.Contains(got, "**CVSS:** 9.8") {
		t.Error("expected bold CVSS line for CVE-2020-1938")
	}
	if !strings.Contains(got, "**CWE:** CWE-22") {
		t.Error("expected per-CVE CWE line for CVE-2020-1938")
	}

	// Back-link callout.
	if !strings.Contains(got, "[[Vulnerabilities|← all vulnerabilities]]") {
		t.Error("missing back-link callout")
	}
}

// ── Single-CVE group ─────────────────────────────────────────────────────────

func TestRenderVulnGroupNote_SingleCVE(t *testing.T) {
	r := buildTestReport()
	poodle := r.Groups[2] // "SSL/TLS — POODLE"
	got := RenderVulnGroupNote(poodle)

	// Must start with frontmatter.
	if !strings.HasPrefix(got, "---\n") {
		t.Errorf("expected YAML frontmatter, got: %q", got[:40])
	}

	// Must have H1 title after frontmatter.
	if !strings.Contains(got, "\n# SSL/TLS — POODLE\n") {
		t.Errorf("expected H1 title 'SSL/TLS — POODLE'")
	}
	if !strings.Contains(got, "[[Vulnerabilities|← all vulnerabilities]]") {
		t.Error("missing back-link callout")
	}
	// Group-level Affected assets with the port block.
	if !strings.Contains(got, "## Affected assets") {
		t.Error("missing '## Affected assets' section")
	}
	if !strings.Contains(got, "`443/tcp`") {
		t.Error("missing port label `443/tcp`")
	}
	// The single CVE gets its own section.
	if !strings.Contains(got, "## CVE-2014-3566") {
		t.Error("missing '## CVE-2014-3566' section")
	}
	if !strings.Contains(got, "SSLv3 CBC padding allows MITM plaintext recovery.") {
		t.Error("missing CVE description")
	}
	if !strings.Contains(got, "**See also:**\n- [openssl.org]") {
		t.Error("missing See also link")
	}
	// Per-CVE CWE bold line.
	if !strings.Contains(got, "**CWE:** CWE-326") {
		t.Error("expected CWE line for single-CVE group")
	}
	// Frontmatter must have cwe key.
	if !strings.Contains(got, "cwe: [CWE-326]") {
		t.Error("expected cwe frontmatter with CWE-326")
	}
}

// ── No-CVE portless group ────────────────────────────────────────────────────

func TestRenderVulnGroupNote_NoCVE(t *testing.T) {
	r := buildTestReport()
	winSrv := r.Groups[3] // "Microsoft Windows Server 2012 — Unsupported"
	got := RenderVulnGroupNote(winSrv)

	// Must start with frontmatter.
	if !strings.HasPrefix(got, "---\n") {
		t.Errorf("expected YAML frontmatter, got: %q", got[:60])
	}
	// Must have H1 title after frontmatter.
	if !strings.Contains(got, "\n# Microsoft Windows Server 2012 — Unsupported\n") {
		t.Errorf("expected H1 title")
	}
	if !strings.Contains(got, "[[Vulnerabilities|← all vulnerabilities]]") {
		t.Error("missing back-link callout")
	}
	// No CVEs → frontmatter records cves: 0 and there is no per-CVE section.
	if !strings.Contains(got, "cves: 0") {
		t.Error("expected 'cves: 0' in frontmatter")
	}
	if strings.Contains(got, "## CVE-") {
		t.Error("no-CVE group should not have a per-CVE section")
	}
	// Group-level Affected assets with the portless IP block.
	if !strings.Contains(got, "## Affected assets") {
		t.Error("missing '## Affected assets' section")
	}
	if !strings.Contains(got, "10.20.4.7") {
		t.Error("missing host IP in block")
	}
	// Finding description present.
	if !strings.Contains(got, "The remote host runs an unsupported Windows Server.") {
		t.Error("missing finding description")
	}
}

// ── WriteVulnerabilities round-trip ─────────────────────────────────────────

func TestWriteVulnerabilities_RoundTrip(t *testing.T) {
	r := buildTestReport()
	dir := t.TempDir()

	// Place a stray file in Vulnerabilities/ BEFORE the call — it must be gone after.
	strayDir := filepath.Join(dir, "Vulnerabilities")
	if err := os.MkdirAll(strayDir, 0o755); err != nil {
		t.Fatalf("mkdir stray dir: %v", err)
	}
	strayPath := filepath.Join(strayDir, "stray.md")
	if err := os.WriteFile(strayPath, []byte("old note"), 0o644); err != nil {
		t.Fatalf("write stray: %v", err)
	}

	if err := WriteVulnerabilities(dir, r); err != nil {
		t.Fatalf("WriteVulnerabilities: %v", err)
	}

	// Index note exists and matches RenderVulnerabilitiesIndex.
	indexData, err := os.ReadFile(filepath.Join(dir, "Vulnerabilities.md"))
	if err != nil {
		t.Fatalf("read Vulnerabilities.md: %v", err)
	}
	if got, want := normalizeNewlines(string(indexData)), normalizeNewlines(RenderVulnerabilitiesIndex(r)); got != want {
		t.Errorf("Vulnerabilities.md round-trip mismatch:\ngot:\n%s\n\nwant:\n%s", got, want)
	}

	// Per-group notes exist at <System>/<NN>-<slug>.md paths.
	paths := groupNotePaths(r)
	for i, relPath := range paths {
		p := filepath.Join(dir, "Vulnerabilities", filepath.FromSlash(relPath+".md"))
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected group note [%d] at %s to exist: %v", i, relPath, err)
		}
	}

	// Multi-Shared note matches RenderVulnGroupNote.
	noteRelPath := paths[0] // "Multi-Shared/1-multi-shared-cve-group"
	noteData, err := os.ReadFile(filepath.Join(dir, "Vulnerabilities", filepath.FromSlash(noteRelPath+".md")))
	if err != nil {
		t.Fatalf("read %s.md: %v", noteRelPath, err)
	}
	if got, want := normalizeNewlines(string(noteData)), normalizeNewlines(RenderVulnGroupNote(r.Groups[0])); got != want {
		t.Errorf("group note round-trip mismatch:\ngot:\n%s\n\nwant:\n%s", got, want)
	}

	// Stray file is GONE.
	if _, err := os.Stat(strayPath); err == nil {
		t.Error("stray.md should have been removed by WriteVulnerabilities")
	}

	// Index contains matching [[Vulnerabilities/<band>/<NN>-<slug>\|…]] links
	// (pipe escaped for the markdown table).
	idx := string(indexData)
	for i, g := range r.Groups {
		wantLink := fmt.Sprintf("[[Vulnerabilities/%s\\|%s]]", paths[i], g.Name)
		if !strings.Contains(idx, wantLink) {
			t.Errorf("index missing link for group %q: want %q", g.Name, wantLink)
		}
	}
}

// ── Slug disambiguation within same System dir ───────────────────────────────

func TestWriteVulnerabilities_SlugDisambiguation(t *testing.T) {
	// Two groups with the same name (same slug) in the same System → second gets -2 suffix.
	r := vulnview.Report{
		Meta:      vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"},
		VulnCount: 2,
		HostCount: 2,
		Bands:     []vulnview.BandSummary{{Priority: "Low", Vulns: 2, Hosts: 2}},
		Groups: []vulnview.GroupView{
			{Name: "Duplicate Group", Category: "Other", Bucket: vulnview.BucketResidual, Priority: "low", System: "Other", Rank: 1, CVSS: "", HostCount: 1, IPs: []string{"1.2.3.4"}, CVEs: nil},
			{Name: "Duplicate Group", Category: "Other", Bucket: vulnview.BucketResidual, Priority: "low", System: "Other", Rank: 2, CVSS: "", HostCount: 1, IPs: []string{"1.2.3.5"}, CVEs: nil},
		},
	}

	dir := t.TempDir()
	if err := WriteVulnerabilities(dir, r); err != nil {
		t.Fatalf("WriteVulnerabilities: %v", err)
	}

	// Same bucket folder → second collides → gets -2 suffix.
	paths := groupNotePaths(r)
	for _, relPath := range paths {
		p := filepath.Join(dir, "Vulnerabilities", filepath.FromSlash(relPath+".md"))
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file at %s: %v", relPath, err)
		}
	}

	// The index links must use the SAME disambiguated paths (pipe escaped).
	idx := RenderVulnerabilitiesIndex(r)
	for i, g := range r.Groups {
		wantLink := fmt.Sprintf("[[Vulnerabilities/%s\\|%s]]", paths[i], g.Name)
		if !strings.Contains(idx, wantLink) {
			t.Errorf("index missing link %q; got:\n%s", wantLink, idx)
		}
	}
}

// ── Slug disambiguation: same name in DIFFERENT buckets → no -2 needed ────────

func TestWriteVulnerabilities_SlugDisambiguationCrossBucket(t *testing.T) {
	// Same name, different bucket → different folders → no collision, no -2.
	r := vulnview.Report{
		Meta:      vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"},
		VulnCount: 2,
		HostCount: 2,
		Groups: []vulnview.GroupView{
			{Name: "Duplicate Group", Category: "Other", Bucket: vulnview.BucketHighPriority, Priority: "urgent", System: "X", Rank: 1, HostCount: 1, IPs: []string{"1.2.3.4"}, CVEs: nil},
			{Name: "Duplicate Group", Category: "Other", Bucket: vulnview.BucketOutdated, Priority: "low", System: "Y", Rank: 2, HostCount: 1, IPs: []string{"1.2.3.5"}, CVEs: nil},
		},
	}
	dir := t.TempDir()
	if err := WriteVulnerabilities(dir, r); err != nil {
		t.Fatalf("WriteVulnerabilities: %v", err)
	}
	paths := groupNotePaths(r)
	// Paths: "2 High Priority/1-…" and "8 Outdated Software/Unsupported Versions/2-…" — no "-2".
	for _, relPath := range paths {
		if strings.Contains(relPath, "duplicate-group-2") {
			t.Errorf("cross-bucket should not disambiguate with -2: %s", relPath)
		}
		if _, err := os.Stat(filepath.Join(dir, "Vulnerabilities", filepath.FromSlash(relPath+".md"))); err != nil {
			t.Errorf("expected file at %s: %v", relPath, err)
		}
	}
	if !strings.HasPrefix(paths[0], "2 High Priority/") || !strings.HasPrefix(paths[1], "8 Outdated Software/Unsupported Versions/") {
		t.Errorf("bucket folders wrong: %v", paths)
	}
}

// ── Dashboard structure ──────────────────────────────────────────────────────

func TestRenderVulnerabilitiesIndex_Dashboard(t *testing.T) {
	r := buildTestReport()
	got := normalizeNewlines(RenderVulnerabilitiesIndex(r))

	// Bucket-first: bucket headings present; NO product/system headings.
	for _, want := range []string{
		"## 🔴 High Priority (2)",
		"## 🔐 Cryptographic and Certificate Issues (1)",
		"## ⌛ Outdated Software (1)",
		"> [!abstract] Overview",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	if strings.Contains(got, "## Multi-Shared") || strings.Contains(got, "## Apache Tomcat") {
		t.Error("dashboard must not have product/system headings")
	}
	// Priority bands are gone — no band or KEV "start here" headings.
	if strings.Contains(got, "Start here") {
		t.Error("KEV start-here section should be removed")
	}
	// Overview must include the KEV/PoC totals line.
	if !strings.Contains(got, "**Known-exploited (KEV):** 2") {
		t.Error("missing KEV total in Overview")
	}
	// Links use bucket-folder paths with escaped pipe.
	paths := groupNotePaths(r)
	for i, g := range r.Groups {
		wantLink := fmt.Sprintf("[[Vulnerabilities/%s\\|%s]]", paths[i], g.Name)
		if !strings.Contains(got, wantLink) {
			t.Errorf("index missing link for %q: want %q", g.Name, wantLink)
		}
	}
}

// ── Multiple groups in one bucket → single bucket section ────────────────────

func TestRenderVulnerabilitiesIndex_MultiGroupBucket(t *testing.T) {
	// Two groups in the same bucket.
	outdatedGroup := func(name, ip string, rank int) vulnview.GroupView {
		return vulnview.GroupView{
			Name: name, Category: "Outdated Software", Bucket: vulnview.BucketOutdated,
			Priority: "low", System: "Other", Rank: rank,
			CVSS: "", HostCount: 1, IPs: []string{ip},
			Description: "Unsupported.", CVEs: nil,
		}
	}
	r := vulnview.Report{
		Meta:      vulnview.Meta{ScanName: "Test", Generated: "2026-07-10"},
		VulnCount: 2, HostCount: 2,
		Groups: []vulnview.GroupView{
			outdatedGroup("Group A", "10.0.0.1", 1),
			outdatedGroup("Group B", "10.0.0.2", 2),
		},
	}
	got := normalizeNewlines(RenderVulnerabilitiesIndex(r))

	// Both groups appear as rows in the single Outdated Software section.
	paths := groupNotePaths(r)
	for i, g := range r.Groups {
		wantLink := fmt.Sprintf("[[Vulnerabilities/%s\\|%s]]", paths[i], g.Name)
		if !strings.Contains(got, wantLink) {
			t.Errorf("missing link %q", wantLink)
		}
	}
	if count := strings.Count(got, "## ⌛ Outdated Software"); count != 1 {
		t.Errorf("expected exactly one Outdated Software section, got %d", count)
	}
}
