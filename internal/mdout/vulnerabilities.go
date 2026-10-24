package mdout

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"layzmd/internal/vulnview"
)

// vulnPriorityDisplay returns the title-cased display form of a priority label.
func vulnPriorityDisplay(p string) string {
	switch strings.ToLower(p) {
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

// slugRe matches runs of non-alphanumeric characters for slug generation.
var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// systemSanitizeRe matches path-illegal characters in system names.
// Keeps spaces and casing for readability (Obsidian handles spaces).
var systemSanitizeRe = regexp.MustCompile(`[<>:"/\\|?*]`)

// Slug converts a vulnerability group name into a deterministic, filesystem-safe
// slug: lowercase; each run of non-[a-z0-9] replaced by a single "-"; leading
// and trailing "-" trimmed; capped at 80 characters; empty result → "group".
func Slug(name string) string {
	s := strings.ToLower(name)
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 80 {
		// Cap at 80 chars, trim any trailing "-" that results.
		s = strings.TrimRight(s[:80], "-")
	}
	if s == "" {
		return "group"
	}
	return s
}

// sanitizePathSeg replaces path-illegal characters in a name with "-", keeping
// spaces and case for Obsidian readability. Empty input returns "Other".
// Shared by the Vulnerabilities, Hosts, Services, and AD emitters.
func sanitizePathSeg(system string) string {
	s := systemSanitizeRe.ReplaceAllString(system, "-")
	if s == "" {
		return "Other"
	}
	return s
}

// yamlQuoteString wraps s in double quotes if it contains any character that
// might be interpreted as YAML special syntax (colon, quote, leading dash,
// leading bracket, etc.). Safe to call on any string value.
func yamlQuoteString(s string) string {
	if s == "" {
		return `""`
	}
	// Quote if the value contains a colon, double-quote, or starts with
	// characters that have YAML meaning.
	needsQuote := strings.ContainsAny(s, `:"'[]{}|>&*!%@`) ||
		strings.HasPrefix(s, "-") ||
		strings.HasPrefix(s, " ") ||
		strings.HasSuffix(s, " ")
	if needsQuote {
		escaped := strings.ReplaceAll(s, `"`, `\"`)
		return `"` + escaped + `"`
	}
	return s
}

// groupNotePaths computes the relative path "<System>/<NN>-<slug>" for each
// group in the report (indexed by group position). The path string is shared by
// the index renderer (for [[…]] link targets, WITHOUT ".md") and
// WriteVulnerabilities (for filenames, WITH ".md"), ensuring links == files.
//
// Rules:
//   - <System> is sanitized (path-illegal chars → "-"), spaces/case kept.
//   - <NN> is the group's Rank zero-padded to the digit-width of the max rank.
//   - <slug> is Slug(Name), disambiguated with -2,-3,… on collision WITHIN the
//     same <System> dir (in group order).
func groupNotePaths(r vulnview.Report) []string {
	if len(r.Groups) == 0 {
		return nil
	}

	// Compute padding width from max Rank.
	maxRank := 0
	for _, g := range r.Groups {
		if g.Rank > maxRank {
			maxRank = g.Rank
		}
	}
	width := len(fmt.Sprintf("%d", maxRank))

	// Disambiguate slugs per (band, base-slug) pair.
	slugCount := make(map[string]int)
	paths := make([]string, len(r.Groups))

	for i, g := range r.Groups {
		band := bucketFolder(g.Bucket)
		rank := g.Rank
		if rank == 0 {
			rank = i + 1 // fallback when Rank not set
		}
		nn := fmt.Sprintf("%0*d", width, rank)
		base := Slug(g.Name)
		key := band + "/" + base
		slugCount[key]++
		slug := base
		if n := slugCount[key]; n > 1 {
			slug = fmt.Sprintf("%s-%d", base, n)
		}
		paths[i] = band + "/" + nn + "-" + slug
	}
	return paths
}

// bucketDisplay is the semantic-bucket display order (folders numbered by this)
// with a dashboard emoji. Buckets sharing a Group render under one dashboard
// section and one parent folder, split into Sub subsections/subfolders (Outdated
// Software groups Unsupported Versions + Missing Patches).
var bucketDisplay = []struct{ Bucket, Group, Sub, Folder, Emoji string }{
	{vulnview.BucketQuickWins, "Quick Wins", "", "1 Quick Wins", "🟢"},
	{vulnview.BucketHighPriority, "High Priority", "", "2 High Priority", "🔴"},
	{vulnview.BucketResidual, "Residual Findings", "", "3 Residual Findings", "▫"},
	{vulnview.BucketWebApp, "Web Application Weaknesses", "", "4 Web Application Weaknesses", "🕸"},
	{vulnview.BucketCrypto, "Cryptographic and Certificate Issues", "", "5 Cryptographic and Certificate Issues", "🔐"},
	{vulnview.BucketBoring, "Boring Bin", "", "6 Boring Bin", "🗑"},
	{vulnview.BucketDoS, "Denial of Service", "", "7 Denial of Service", "💥"},
	{vulnview.BucketOutdated, "Outdated Software", "Unsupported Versions", "8 Outdated Software/Unsupported Versions", "⌛"},
	{vulnview.BucketMissingPatches, "Outdated Software", "Missing Patches", "8 Outdated Software/Missing Patches", "🩹"},
}

// bucketFolder maps a semantic bucket to its numbered folder (display order).
func bucketFolder(bucket string) string {
	for _, b := range bucketDisplay {
		if b.Bucket == bucket {
			return b.Folder
		}
	}
	return "3 Residual Findings"
}

// displayGroup is a dashboard section: one or more buckets rendered together
// (a single flat table, or subsections when the buckets carry Sub labels).
type displayGroup struct {
	Name, Emoji string
	Buckets     []int // indices into bucketDisplay, in display order
}

// displayGroups collapses bucketDisplay into ordered sections by Group
// (first-seen order), so grouped buckets share one section/parent folder.
func displayGroups() []displayGroup {
	var groups []displayGroup
	pos := map[string]int{}
	for i, b := range bucketDisplay {
		if p, ok := pos[b.Group]; ok {
			groups[p].Buckets = append(groups[p].Buckets, i)
			continue
		}
		pos[b.Group] = len(groups)
		groups = append(groups, displayGroup{Name: b.Group, Emoji: b.Emoji, Buckets: []int{i}})
	}
	return groups
}

// groupCategories returns the distinct per-CVE vuln-classes (first-seen order).
func groupCategories(g vulnview.GroupView) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range g.CVEs {
		if c.Category != "" && !seen[c.Category] {
			seen[c.Category] = true
			out = append(out, c.Category)
		}
	}
	return out
}

// renderFrontmatter writes the YAML frontmatter block for a group note.
func renderFrontmatter(sb *strings.Builder, g vulnview.GroupView) {
	sb.WriteString("---\n")
	// category: the distinct union of per-CVE vuln-classes (a flow list when >1),
	// falling back to the group category for no-CVE findings.
	cats := groupCategories(g)
	if len(cats) <= 1 {
		one := g.Category
		if len(cats) == 1 {
			one = cats[0]
		}
		sb.WriteString(fmt.Sprintf("category: %s\n", yamlQuoteString(one)))
	} else {
		sb.WriteString(fmt.Sprintf("category: [%s]\n", strings.Join(cats, ", ")))
	}
	sb.WriteString(fmt.Sprintf("priority: %s\n", strings.ToLower(g.Priority)))
	sb.WriteString(fmt.Sprintf("bucket: %s\n", yamlQuoteString(g.Bucket)))
	sb.WriteString(fmt.Sprintf("system: %s\n", yamlQuoteString(g.System)))
	sb.WriteString(fmt.Sprintf("hosts: %d\n", g.HostCount))

	cvssVal := g.CVSS
	if cvssVal == "" {
		sb.WriteString("cvss: \"\"\n")
	} else {
		sb.WriteString(fmt.Sprintf("cvss: %s\n", yamlQuoteString(cvssVal)))
	}

	epssVal := g.EpssPercent
	if epssVal == "" {
		sb.WriteString("epss: \"\"\n")
	} else {
		sb.WriteString(fmt.Sprintf("epss: %s\n", yamlQuoteString(epssVal)))
	}

	if g.InKev {
		sb.WriteString("kev: true\n")
	} else {
		sb.WriteString("kev: false\n")
	}
	if g.HasPoc {
		sb.WriteString("poc: true\n")
	} else {
		sb.WriteString("poc: false\n")
	}
	if g.HasNuclei {
		sb.WriteString("nuclei: true\n")
	} else {
		sb.WriteString("nuclei: false\n")
	}

	// CWE: emit as YAML flow list only when non-empty.
	if len(g.CWEs) > 0 {
		quoted := make([]string, len(g.CWEs))
		for i, cw := range g.CWEs {
			quoted[i] = cw
		}
		sb.WriteString(fmt.Sprintf("cwe: [%s]\n", strings.Join(quoted, ", ")))
	}

	sb.WriteString(fmt.Sprintf("cves: %d\n", len(g.CVEs)))
	sb.WriteString("---\n")
}

// RenderVulnGroupNote returns the full Markdown content for one finding note.
// Pure: no I/O, no time. Layout: frontmatter → title → back-link → Affected
// assets (always) → per-CVE sections (or the finding description for no-CVE).
func RenderVulnGroupNote(g vulnview.GroupView) string {
	var sb strings.Builder

	renderFrontmatter(&sb, g)
	sb.WriteString("# " + g.Name + "\n\n")
	sb.WriteString("> [!info] [[Vulnerabilities|← all vulnerabilities]]\n")

	renderAffectedAssets(&sb, g)

	if len(g.CVEs) == 0 {
		renderNoCveBody(&sb, g)
	} else {
		for _, cve := range g.CVEs {
			renderCveSection(&sb, cve)
		}
	}

	// Group-level Nessus See-Also links (a different source than per-CVE NVD
	// references) — shown once at the foot of the note.
	if len(g.RefLinks) > 0 {
		sb.WriteString("\n**See also:**\n")
		for _, l := range g.RefLinks {
			sb.WriteString(fmt.Sprintf("- [%s](%s)\n", l.Label, l.URL))
		}
	}

	result := sb.String()
	return strings.TrimRight(result, "\n") + "\n"
}

// renderAffectedAssets always emits an "## Affected assets" section from the
// group's authoritative hosts (per-port blocks when ports are known, else a
// single IP block). Fixes the bug where per-CVE-only host derivation left
// multi-CVE notes with no assets.
func renderAffectedAssets(sb *strings.Builder, g vulnview.GroupView) {
	sb.WriteString("\n## Affected assets\n")
	switch {
	case len(g.HostsByPort) > 0:
		for _, ph := range g.HostsByPort {
			sb.WriteString("`" + ph.Port + "`\n")
			writeCodeBlock(sb, ph.IPs)
		}
	case len(g.IPs) > 0:
		writeCodeBlock(sb, g.IPs)
	default:
		sb.WriteString("_None recorded._\n")
	}
}

func writeCodeBlock(sb *strings.Builder, items []string) {
	sb.WriteString("```\n")
	for _, s := range items {
		sb.WriteString(s + "\n")
	}
	sb.WriteString("```\n")
}

// renderCveSection writes one per-CVE section: a large header and bold detail
// lines (one per line), then the description and references.
func renderCveSection(sb *strings.Builder, cve vulnview.CveView) {
	sb.WriteString("\n## " + cve.CVE + "\n")
	cvss := cve.CVSS
	if cvss == "" {
		cvss = "–"
	}
	boldLine(sb, "CVSS", cvss)
	boldLine(sb, "Priority", vulnPriorityDisplay(cve.Priority))
	if cve.Category != "" {
		boldLine(sb, "Category", cve.Category)
	}
	if cve.EpssPercent != "" {
		boldLine(sb, "EPSS", cve.EpssPercent)
	}
	boldLine(sb, "KEV", yesNo(cve.InKev))
	boldLine(sb, "Hosts", fmt.Sprintf("%d", cve.HostCount))
	if len(cve.PocLinks) > 0 {
		boldLine(sb, "PoC", joinLinks(cve.PocLinks))
	}
	if len(cve.NucleiLinks) > 0 {
		boldLine(sb, "Nuclei", joinLinks(cve.NucleiLinks))
	}
	if len(cve.CWEs) > 0 {
		boldLine(sb, "CWE", strings.Join(cve.CWEs, " · "))
	}
	if cve.Description != "" {
		sb.WriteString("\n" + cve.Description + "\n")
	}
	writeReferences(sb, cve.RefLinks)
}

// renderNoCveBody writes the body for a finding with no CVEs (metadata lives in
// the frontmatter / Properties panel). Group-level references are emitted by the
// caller as a "See also" section.
func renderNoCveBody(sb *strings.Builder, g vulnview.GroupView) {
	if g.Description != "" {
		sb.WriteString("\n" + g.Description + "\n")
	}
}

func writeReferences(sb *strings.Builder, links []vulnview.Link) {
	if len(links) == 0 {
		return
	}
	sb.WriteString("\n**References:**\n")
	for _, l := range links {
		sb.WriteString(fmt.Sprintf("- [%s](%s)\n", l.Label, l.URL))
	}
}

// boldLine writes "**Label:** value" with a trailing hard line break.
func boldLine(sb *strings.Builder, label, value string) {
	sb.WriteString("**" + label + ":** " + value + "  \n")
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// joinLinks renders links inline as "[label](url) · [label](url)".
func joinLinks(links []vulnview.Link) string {
	parts := make([]string, len(links))
	for i, l := range links {
		parts[i] = fmt.Sprintf("[%s](%s)", l.Label, l.URL)
	}
	return strings.Join(parts, " · ")
}

// RenderVulnerabilitiesIndex returns the Vulnerabilities.md index content for
// the given Report. Pure: no I/O, no time.
//
// Structure: frontmatter → H1 title → [!abstract] summary table → intro line →
// per system (ordered by best rank then name): ## System → one bullet per group.
func RenderVulnerabilitiesIndex(r vulnview.Report) string {
	var sb strings.Builder

	// --- YAML frontmatter ---
	sb.WriteString("---\n")
	sb.WriteString(fmt.Sprintf("scan: %s\n", r.Meta.ScanName))
	sb.WriteString(fmt.Sprintf("generated: %s\n", r.Meta.Generated))
	sb.WriteString(fmt.Sprintf("vulnerabilities: %d\n", r.VulnCount))
	sb.WriteString(fmt.Sprintf("hosts: %d\n", r.HostCount))
	sb.WriteString("---\n")

	// --- Title ---
	sb.WriteString(fmt.Sprintf("\n# Vulnerabilities — %s\n", r.Meta.ScanName))

	// Group indices by semantic bucket (r.Groups is already priority-sorted, so
	// within-bucket order is priority order).
	paths := groupNotePaths(r)
	bucketIdx := map[string][]int{}
	for i, g := range r.Groups {
		bucketIdx[g.Bucket] = append(bucketIdx[g.Bucket], i)
	}
	distinctHostsOf := func(idxs []int) int {
		seen := map[string]bool{}
		for _, i := range idxs {
			for _, ip := range r.Groups[i].IPs {
				seen[ip] = true
			}
		}
		return len(seen)
	}
	kevTotal, pocTotal := 0, 0
	for _, g := range r.Groups {
		if g.InKev {
			kevTotal++
		}
		if g.HasPoc {
			pocTotal++
		}
	}

	groups := displayGroups()
	// idxsFor returns the combined report indices for a display group's buckets.
	idxsFor := func(gr displayGroup) []int {
		var idxs []int
		for _, bi := range gr.Buckets {
			idxs = append(idxs, bucketIdx[bucketDisplay[bi].Bucket]...)
		}
		return idxs
	}

	// --- Overview: findings + distinct hosts per group, exploitability totals. ---
	sb.WriteString("\n> [!abstract] Overview\n")
	sb.WriteString("> | Bucket | Findings | Hosts |\n> |---|--:|--:|\n")
	for _, gr := range groups {
		idxs := idxsFor(gr)
		if len(idxs) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("> | %s %s | %d | %d |\n", gr.Emoji, gr.Name, len(idxs), distinctHostsOf(idxs)))
	}
	sb.WriteString(fmt.Sprintf("> \n> **Known-exploited (KEV):** %d  ·  **Public PoC:** %d\n", kevTotal, pocTotal))

	// --- One scannable section per non-empty group, in display order. Grouped
	// buckets (Outdated Software) render as subsections under one heading. ---
	for _, gr := range groups {
		if len(idxsFor(gr)) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("\n## %s %s (%d)\n", gr.Emoji, gr.Name, len(idxsFor(gr))))
		if len(gr.Buckets) == 1 && bucketDisplay[gr.Buckets[0]].Sub == "" {
			writeFindingTable(&sb, r, paths, bucketIdx[bucketDisplay[gr.Buckets[0]].Bucket])
			continue
		}
		for _, bi := range gr.Buckets {
			b := bucketDisplay[bi]
			idxs := bucketIdx[b.Bucket]
			if len(idxs) == 0 {
				continue
			}
			sb.WriteString(fmt.Sprintf("\n### %s %s (%d)\n", b.Emoji, b.Sub, len(idxs)))
			writeFindingTable(&sb, r, paths, idxs)
		}
	}

	result := sb.String()
	result = strings.TrimRight(result, "\n") + "\n"
	return result
}

// writeFindingTable writes the dashboard finding table (header + one row per
// index, in report/priority order) for a set of report indices.
func writeFindingTable(sb *strings.Builder, r vulnview.Report, paths []string, idxs []int) {
	sb.WriteString("\n| Finding | Category | Hosts | CVSS | EPSS | KEV | PoC | CVEs |\n")
	sb.WriteString("|---|---|--:|--:|--:|:-:|:-:|--:|\n")
	for _, i := range idxs {
		sb.WriteString(findingRow(r.Groups[i], paths[i], true) + "\n")
	}
}

// findingRow renders one dashboard table row for a finding. The wikilink's pipe
// is escaped (\|) so it survives inside the markdown table. withKev includes a
// KEV column (the KEV "start here" table omits it — every row is KEV).
func findingRow(g vulnview.GroupView, path string, withKev bool) string {
	cvss := g.CVSS
	if cvss == "" {
		cvss = "–"
	}
	epss := g.EpssPercent
	if epss == "" {
		epss = "–"
	}
	cves := "–"
	if len(g.CVEs) > 0 {
		cves = fmt.Sprintf("%d", len(g.CVEs))
	}
	check := func(b bool) string {
		if b {
			return "✓"
		}
		return ""
	}
	name := strings.ReplaceAll(g.Name, "|", "\\|")
	link := fmt.Sprintf("[[Vulnerabilities/%s\\|%s]]", path, name)
	if withKev {
		return fmt.Sprintf("| %s | %s | %d | %s | %s | %s | %s | %s |",
			link, g.Category, g.HostCount, cvss, epss, check(g.InKev), check(g.HasPoc), cves)
	}
	return fmt.Sprintf("| %s | %s | %d | %s | %s | %s | %s |",
		link, g.Category, g.HostCount, cvss, epss, check(g.HasPoc), cves)
}

// WriteVulnerabilities writes:
//   - dir/Vulnerabilities.md — the index note (RenderVulnerabilitiesIndex)
//   - dir/Vulnerabilities/<System>/<NN>-<slug>.md — one note per group
//
// The Vulnerabilities/ subfolder is removed and recreated on each write, so
// stale notes from a smaller prior scan do not linger.
func WriteVulnerabilities(dir string, r vulnview.Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Write the index note.
	indexPath := filepath.Join(dir, "Vulnerabilities.md")
	if err := os.WriteFile(indexPath, []byte(RenderVulnerabilitiesIndex(r)), 0o644); err != nil {
		return err
	}

	// Clear and recreate the Vulnerabilities/ subfolder.
	vulnDir := filepath.Join(dir, "Vulnerabilities")
	if err := os.RemoveAll(vulnDir); err != nil {
		return err
	}
	if err := os.MkdirAll(vulnDir, 0o755); err != nil {
		return err
	}

	// Compute shared paths (SAME as index renderer — links match filenames).
	paths := groupNotePaths(r)

	// Write one note per group, using the shared path computation.
	for i, g := range r.Groups {
		notePath := filepath.Join(vulnDir, filepath.FromSlash(paths[i]+".md"))
		// Ensure the system subfolder exists.
		if err := os.MkdirAll(filepath.Dir(notePath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(notePath, []byte(RenderVulnGroupNote(g)), 0o644); err != nil {
			return err
		}
	}

	return nil
}
