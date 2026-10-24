package mdout

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"layzmd/internal/ad"
	"layzmd/internal/ipsort"
)

// ipCodeBlock renders a fenced code block of the given IPs, de-duplicated and
// numerically sorted (ipsort.Key). Returns "" for an empty set.
func ipCodeBlock(ips []string) string {
	seen := make(map[string]bool, len(ips))
	uniq := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		uniq = append(uniq, ip)
	}
	sort.Slice(uniq, func(i, j int) bool {
		ki, kj := ipsort.Key(uniq[i]), ipsort.Key(uniq[j])
		if ki != kj {
			return ki < kj
		}
		return uniq[i] < uniq[j]
	})
	var sb strings.Builder
	sb.WriteString("```\n")
	for _, ip := range uniq {
		sb.WriteString(ip + "\n")
	}
	sb.WriteString("```\n")
	return sb.String()
}

// ---------------------------------------------------------------------------
// Markdown table helpers
// ---------------------------------------------------------------------------

// mdCell renders a single table cell value:
// - empty string or nil slice → "–"
// - []string → joined with " · " (each element pipe-escaped)
// - string → pipe-escaped
func mdCell(v interface{}) string {
	switch val := v.(type) {
	case string:
		if val == "" {
			return "–"
		}
		return strings.ReplaceAll(val, "|", `\|`)
	case []string:
		if len(val) == 0 {
			return "–"
		}
		parts := make([]string, len(val))
		for i, s := range val {
			parts[i] = strings.ReplaceAll(s, "|", `\|`)
		}
		return strings.Join(parts, " · ")
	default:
		return "–"
	}
}

// mdIntCell renders an integer cell (numeric, right-aligned column).
func mdIntCell(n int) string {
	return fmt.Sprintf("%d", n)
}

// mdTable builds a complete Markdown table string (no trailing newline).
// headers: column names. alignRight: set of column indices (0-based) to right-align.
// rows: each row is a slice of cell strings (pre-rendered).
func mdTable(headers []string, alignRight map[int]bool, rows [][]string) string {
	var sb strings.Builder
	// Header row
	sb.WriteString("| ")
	sb.WriteString(strings.Join(headers, " | "))
	sb.WriteString(" |")
	// Separator row
	sb.WriteString("\n|")
	for i := range headers {
		if alignRight[i] {
			sb.WriteString("--:|")
		} else {
			sb.WriteString("---|")
		}
	}
	// Data rows
	for _, row := range rows {
		sb.WriteString("\n| ")
		sb.WriteString(strings.Join(row, " | "))
		sb.WriteString(" |")
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Domain-grouping helper
// ---------------------------------------------------------------------------

// groupByDomain groups rows by their domain string, returning sorted domain
// keys (alphabetical, with "(unknown domain)" always last) and a map of
// domain → indices into the original slice.
func groupByDomain(domains []string) ([]string, map[string][]int) {
	order := make(map[string][]int)
	for i, d := range domains {
		key := d
		if key == "" {
			key = "(unknown domain)"
		}
		order[key] = append(order[key], i)
	}

	keys := make([]string, 0, len(order))
	for k := range order {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		// "(unknown domain)" always last
		if keys[i] == "(unknown domain)" {
			return false
		}
		if keys[j] == "(unknown domain)" {
			return true
		}
		return keys[i] < keys[j]
	})
	return keys, order
}

// ---------------------------------------------------------------------------
// Section renderers
// ---------------------------------------------------------------------------

// renderDomains renders the flat Domains table.
func renderDomains(rows []ad.Domain) string {
	headers := []string{"Domain", "Confidence", "Hosts", "Sources"}
	alignRight := map[int]bool{2: true}
	tableRows := make([][]string, len(rows))
	for i, r := range rows {
		tableRows[i] = []string{
			mdCell(r.Name),
			mdCell(r.Confidence),
			mdIntCell(r.Hosts),
			mdCell(r.Sources),
		}
	}
	return mdTable(headers, alignRight, tableRows)
}

// renderNetbios renders the flat NetBIOS / Workgroup table.
func renderNetbios(rows []ad.NetbiosName) string {
	headers := []string{"Name", "Hosts"}
	alignRight := map[int]bool{1: true}
	tableRows := make([][]string, len(rows))
	for i, r := range rows {
		tableRows[i] = []string{
			mdCell(r.Name),
			mdIntCell(r.Hosts),
		}
	}
	return mdTable(headers, alignRight, tableRows)
}

// renderDCsGrouped renders Domain Controllers grouped by domain.
func renderDCsGrouped(rows []ad.DCRow) string {
	// Extract domain per row
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.Domain
	}
	keys, groups := groupByDomain(domains)

	var sb strings.Builder
	for ki, key := range keys {
		if ki > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("### ")
		sb.WriteString(key)
		sb.WriteString("\n")

		headers := []string{"IP", "FQDN", "Domains", "Confidence"}
		var tableRows [][]string
		for _, idx := range groups[key] {
			r := rows[idx]
			tableRows = append(tableRows, []string{
				mdCell(r.IP),
				mdCell(r.FQDN),
				mdCell(r.Domains),
				mdCell(r.Confidence),
			})
		}
		sb.WriteString(mdTable(headers, nil, tableRows))
	}
	return sb.String()
}

// renderDNSGrouped renders DNS Servers grouped by domain.
func renderDNSGrouped(rows []ad.DNSRow) string {
	// DNS rows have no Domain field; group all under "(unknown domain)" unless
	// we can derive a domain — they don't have a Domain field, so flat render
	// Actually DNSRow has no Domain field per model.go. Flat table.
	headers := []string{"IP", "FQDN", "Port"}
	tableRows := make([][]string, len(rows))
	for i, r := range rows {
		tableRows[i] = []string{
			mdCell(r.IP),
			mdCell(r.FQDN),
			mdCell(r.Port),
		}
	}
	return mdTable(headers, nil, tableRows)
}

// renderSMBSigningSummary renders the SMB Signing summary table.
func renderSMBSigningSummary(rows []ad.SMBSigningSummary) string {
	headers := []string{"Domain", "Hosts"}
	alignRight := map[int]bool{1: true}
	tableRows := make([][]string, len(rows))
	for i, r := range rows {
		tableRows[i] = []string{
			mdCell(r.Domain),
			mdIntCell(r.Hosts),
		}
	}
	return mdTable(headers, alignRight, tableRows)
}

// renderSMBSigningGrouped renders SMB Signing affected hosts grouped by domain,
// as an IP-only code block per domain (FQDN/Port omitted).
func renderSMBSigningGrouped(rows []ad.SMBSigningRow) string {
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.Domain
	}
	keys, groups := groupByDomain(domains)

	var sb strings.Builder
	for ki, key := range keys {
		if ki > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString("### ")
		sb.WriteString(key)
		sb.WriteString("\n")

		ips := make([]string, 0, len(groups[key]))
		for _, idx := range groups[key] {
			ips = append(ips, rows[idx].IP)
		}
		sb.WriteString(ipCodeBlock(ips))
	}
	return sb.String()
}

// renderShareSummary renders the SMB Shares summary table.
func renderShareSummary(rows []ad.ShareSummary) string {
	headers := []string{"Domain", "Hosts", "Shares", "Non-Default", "Writable", "Low-Priv"}
	alignRight := map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true}
	tableRows := make([][]string, len(rows))
	for i, r := range rows {
		tableRows[i] = []string{
			mdCell(r.Domain),
			mdIntCell(r.Hosts),
			mdIntCell(r.Shares),
			mdIntCell(r.NonDefault),
			mdIntCell(r.Writable),
			mdIntCell(r.LowPriv),
		}
	}
	return mdTable(headers, alignRight, tableRows)
}

// renderSharesGrouped renders notable SMB share rows grouped by domain.
func renderSharesGrouped(rows []ad.ShareRow) string {
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.Domain
	}
	keys, groups := groupByDomain(domains)

	var sb strings.Builder
	for ki, key := range keys {
		if ki > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("### ")
		sb.WriteString(key)
		sb.WriteString("\n")

		headers := []string{"IP", "FQDN", "Share", "UNC", "Access", "Principals"}
		var tableRows [][]string
		for _, idx := range groups[key] {
			r := rows[idx]
			tableRows = append(tableRows, []string{
				mdCell(r.IP),
				mdCell(r.FQDN),
				mdCell(r.Share),
				mdCell(r.UNC),
				mdCell(r.Access),
				mdCell(r.Principals),
			})
		}
		sb.WriteString(mdTable(headers, nil, tableRows))
	}
	return sb.String()
}

// renderGuestGrouped renders Guest Account Access rows grouped by domain.
func renderGuestGrouped(rows []ad.GuestRow) string {
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.Domain
	}
	keys, groups := groupByDomain(domains)

	var sb strings.Builder
	for ki, key := range keys {
		if ki > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("### ")
		sb.WriteString(key)
		sb.WriteString("\n")

		headers := []string{"IP", "FQDN", "Port", "Access"}
		var tableRows [][]string
		for _, idx := range groups[key] {
			r := rows[idx]
			tableRows = append(tableRows, []string{
				mdCell(r.IP),
				mdCell(r.FQDN),
				mdCell(r.Port),
				mdCell(r.Access),
			})
		}
		sb.WriteString(mdTable(headers, nil, tableRows))
	}
	return sb.String()
}

// renderSmbV1Grouped renders SMBv1 / Null Session rows grouped by domain.
func renderSmbV1Grouped(rows []ad.SmbV1Row) string {
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.Domain
	}
	keys, groups := groupByDomain(domains)

	var sb strings.Builder
	for ki, key := range keys {
		if ki > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("### ")
		sb.WriteString(key)
		sb.WriteString("\n")

		headers := []string{"IP", "FQDN", "Detail", "Port"}
		var tableRows [][]string
		for _, idx := range groups[key] {
			r := rows[idx]
			tableRows = append(tableRows, []string{
				mdCell(r.IP),
				mdCell(r.FQDN),
				mdCell(r.Detail),
				mdCell(r.Port),
			})
		}
		sb.WriteString(mdTable(headers, nil, tableRows))
	}
	return sb.String()
}

// renderEmailSummary renders the Email Addresses summary table.
func renderEmailSummary(rows []ad.EmailSummary) string {
	headers := []string{"Source", "Emails", "Source Hosts", "Confidence"}
	alignRight := map[int]bool{1: true, 2: true}
	tableRows := make([][]string, len(rows))
	for i, r := range rows {
		tableRows[i] = []string{
			mdCell(r.Source),
			mdIntCell(r.Emails),
			mdIntCell(r.SourceHosts),
			mdCell(r.Confidence),
		}
	}
	return mdTable(headers, alignRight, tableRows)
}

// renderEmailsFull renders the full Email Addresses list (flat).
func renderEmailsFull(rows []ad.EmailRow) string {
	headers := []string{"Email", "Source", "Source Hosts", "Confidence"}
	tableRows := make([][]string, len(rows))
	for i, r := range rows {
		tableRows[i] = []string{
			mdCell(r.Email),
			mdCell(r.Source),
			mdCell(r.SourceHosts),
			mdCell(r.Confidence),
		}
	}
	return mdTable(headers, nil, tableRows)
}

// renderDefensive renders the flat Defensive Technology table.
func renderDefensive(rows []ad.DefensiveRow) string {
	headers := []string{"Category", "Product", "Hosts", "Confidence", "Evidence Types"}
	alignRight := map[int]bool{2: true}
	tableRows := make([][]string, len(rows))
	for i, r := range rows {
		tableRows[i] = []string{
			mdCell(r.Category),
			mdCell(r.Product),
			mdIntCell(r.Hosts),
			mdCell(r.Confidence),
			mdCell(r.EvidenceTypes),
		}
	}
	return mdTable(headers, alignRight, tableRows)
}

// renderMssqlGrouped renders MS-SQL Servers grouped by domain.
func renderMssqlGrouped(rows []ad.MssqlRow) string {
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.Domain
	}
	keys, groups := groupByDomain(domains)

	var sb strings.Builder
	for ki, key := range keys {
		if ki > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("### ")
		sb.WriteString(key)
		sb.WriteString("\n")

		headers := []string{"IP", "Port", "FQDN", "Instance", "Version", "Domains"}
		var tableRows [][]string
		for _, idx := range groups[key] {
			r := rows[idx]
			tableRows = append(tableRows, []string{
				mdCell(r.IP),
				mdCell(r.Port),
				mdCell(r.FQDN),
				mdCell(r.Instance),
				mdCell(r.Version),
				mdCell(r.Domains),
			})
		}
		sb.WriteString(mdTable(headers, nil, tableRows))
	}
	return sb.String()
}

// renderAdcs combines the ADCS Certificate Authority and Enrollment Endpoint
// tables into one section with two sub-headings (only non-empty parts appear).
func renderAdcs(ca []ad.AdcsCARow, ep []ad.AdcsEndpointRow) string {
	var parts []string
	if len(ca) > 0 {
		parts = append(parts, "## Certificate Authorities\n"+renderAdcsCAGrouped(ca))
	}
	if len(ep) > 0 {
		parts = append(parts, "## Enrollment Endpoints\n"+renderAdcsEndpointsGrouped(ep))
	}
	return strings.Join(parts, "\n\n")
}

// renderAdcsCAGrouped renders ADCS Certificate Authority rows grouped by domain.
func renderAdcsCAGrouped(rows []ad.AdcsCARow) string {
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.Domain
	}
	keys, groups := groupByDomain(domains)

	var sb strings.Builder
	for ki, key := range keys {
		if ki > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("### ")
		sb.WriteString(key)
		sb.WriteString("\n")

		headers := []string{"IP", "Ports", "FQDN", "Issuer", "Subject", "Domain"}
		var tableRows [][]string
		for _, idx := range groups[key] {
			r := rows[idx]
			tableRows = append(tableRows, []string{
				mdCell(r.IP),
				mdCell(r.Ports),
				mdCell(r.FQDN),
				mdCell(r.Issuer),
				mdCell(r.Subject),
				mdCell(r.Domain),
			})
		}
		sb.WriteString(mdTable(headers, nil, tableRows))
	}
	return sb.String()
}

// renderAdcsEndpointsGrouped renders ADCS Enrollment Endpoint rows grouped by domain.
func renderAdcsEndpointsGrouped(rows []ad.AdcsEndpointRow) string {
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.Domain
	}
	keys, groups := groupByDomain(domains)

	var sb strings.Builder
	for ki, key := range keys {
		if ki > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("### ")
		sb.WriteString(key)
		sb.WriteString("\n")

		headers := []string{"IP", "Ports", "FQDN", "Indicator"}
		var tableRows [][]string
		for _, idx := range groups[key] {
			r := rows[idx]
			tableRows = append(tableRows, []string{
				mdCell(r.IP),
				mdCell(r.Ports),
				mdCell(r.FQDN),
				mdCell(r.Indicator),
			})
		}
		sb.WriteString(mdTable(headers, nil, tableRows))
	}
	return sb.String()
}

// renderSccmGrouped renders SCCM Services. The primary roles
// (configuration_manager_cpe, management_point) are shown as a per-domain
// table; remote_control_agent hosts (typically every managed endpoint) are
// listed separately afterwards as an IP-only code block.
func renderSccmGrouped(rows []ad.SccmRow) string {
	var primary []ad.SccmRow
	var rcaIPs []string
	for _, r := range rows {
		if r.Role == "remote_control_agent" {
			rcaIPs = append(rcaIPs, r.IP)
			continue
		}
		primary = append(primary, r)
	}

	var sb strings.Builder

	if len(primary) > 0 {
		domains := make([]string, len(primary))
		for i, r := range primary {
			domains[i] = r.Domain
		}
		keys, groups := groupByDomain(domains)
		for ki, key := range keys {
			if ki > 0 {
				sb.WriteString("\n\n")
			}
			sb.WriteString("### ")
			sb.WriteString(key)
			sb.WriteString("\n")

			headers := []string{"Role", "IP", "Port", "FQDN", "Site", "Version"}
			var tableRows [][]string
			for _, idx := range groups[key] {
				r := primary[idx]
				tableRows = append(tableRows, []string{
					mdCell(r.Role),
					mdCell(r.IP),
					mdCell(r.Port),
					mdCell(r.FQDN),
					mdCell(r.Site),
					mdCell(r.Version),
				})
			}
			sb.WriteString(mdTable(headers, nil, tableRows))
		}
	}

	if len(rcaIPs) > 0 {
		if sb.Len() > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("### Remote Control Agent Hosts\n")
		sb.WriteString(ipCodeBlock(rcaIPs))
	}
	return sb.String()
}

// renderAdfsGrouped renders ADFS Servers rows grouped by domain.
func renderAdfsGrouped(rows []ad.AdfsRow) string {
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.Domain
	}
	keys, groups := groupByDomain(domains)

	var sb strings.Builder
	for ki, key := range keys {
		if ki > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("### ")
		sb.WriteString(key)
		sb.WriteString("\n")

		headers := []string{"IP", "FQDN", "Services", "Ports"}
		var tableRows [][]string
		for _, idx := range groups[key] {
			r := rows[idx]
			tableRows = append(tableRows, []string{
				mdCell(r.IP),
				mdCell(r.FQDN),
				mdCell(r.Services),
				mdCell(r.Ports),
			})
		}
		sb.WriteString(mdTable(headers, nil, tableRows))
	}
	return sb.String()
}

// renderExchangeGrouped renders Exchange Servers rows grouped by domain.
func renderExchangeGrouped(rows []ad.ExchangeRow) string {
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.Domain
	}
	keys, groups := groupByDomain(domains)

	var sb strings.Builder
	for ki, key := range keys {
		if ki > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("### ")
		sb.WriteString(key)
		sb.WriteString("\n")

		headers := []string{"IP", "FQDN", "Services", "Ports"}
		var tableRows [][]string
		for _, idx := range groups[key] {
			r := rows[idx]
			tableRows = append(tableRows, []string{
				mdCell(r.IP),
				mdCell(r.FQDN),
				mdCell(r.Services),
				mdCell(r.Ports),
			})
		}
		sb.WriteString(mdTable(headers, nil, tableRows))
	}
	return sb.String()
}

// renderServices renders Infrastructure / Identity-Adjacent Services, one
// sub-heading per service with its hosts as an IP-only code block.
func renderServices(rows []ad.ServiceRow) string {
	var sb strings.Builder
	for i, r := range rows {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString("### ")
		sb.WriteString(r.Service)
		sb.WriteString("\n")
		if strings.TrimSpace(r.Detail) != "" {
			sb.WriteString(r.Detail + "\n")
		}
		sb.WriteString(ipCodeBlock(r.Hosts))
	}
	return sb.String()
}

// renderOutdatedGrouped renders Outdated Windows Hosts rows grouped by domain.
func renderOutdatedGrouped(rows []ad.OutdatedWinRow) string {
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.Domain
	}
	keys, groups := groupByDomain(domains)

	var sb strings.Builder
	for ki, key := range keys {
		if ki > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString("### ")
		sb.WriteString(key)
		sb.WriteString("\n")

		headers := []string{"IP", "FQDN", "Detected OS", "Reason"}
		var tableRows [][]string
		for _, idx := range groups[key] {
			r := rows[idx]
			tableRows = append(tableRows, []string{
				mdCell(r.IP),
				mdCell(r.FQDN),
				mdCell(r.OS),
				mdCell(r.Reason),
			})
		}
		sb.WriteString(mdTable(headers, nil, tableRows))
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Section notes
// ---------------------------------------------------------------------------

// adSection is one populated AD report section: its title, count, rendered
// body, and vault-relative note path.
type adSection struct {
	title string
	count int
	body  string
	path  string
}

// adSectionNotes returns one entry per POPULATED section, in emit order.
// Titles, order, and bodies match the pre-split single-file layout; counts
// match the former buildSummary. SINGLE source of sections + paths for both
// the index and the writer.
func adSectionNotes(r ad.Report) []adSection {
	type def struct {
		title string
		count int
		body  func() string
	}
	defs := []def{
		{"Domains", len(r.Domains), func() string { return renderDomains(r.Domains) }},
		{"NetBIOS / Workgroup", len(r.Netbios), func() string { return renderNetbios(r.Netbios) }},
		{"Domain Controllers", len(r.DomainControllers), func() string { return renderDCsGrouped(r.DomainControllers) }},
		{"DNS Servers", len(r.DNSServers), func() string { return renderDNSGrouped(r.DNSServers) }},
		{"SMB Signing Not Required", len(r.SMBSigning), func() string {
			return renderSMBSigningSummary(r.SMBSigningSummary) + "\n\n" + renderSMBSigningGrouped(r.SMBSigning)
		}},
		{"SMB Shares", len(r.Shares), func() string {
			return renderShareSummary(r.ShareSummary) + "\n\n" + renderSharesGrouped(r.Shares)
		}},
		{"Guest Account Access", len(r.Guest), func() string { return renderGuestGrouped(r.Guest) }},
		{"SMBv1 / Null Session", len(r.SmbV1), func() string { return renderSmbV1Grouped(r.SmbV1) }},
		// Email Addresses → top-level "Usernames - Creds" (WriteCreds);
		// Defensive Technology → top-level Defensive.md (WriteDefensive).
		{"MS-SQL Servers", len(r.Mssql), func() string { return renderMssqlGrouped(r.Mssql) }},
		{"ADCS", len(r.AdcsCA) + len(r.AdcsEndpoints), func() string { return renderAdcs(r.AdcsCA, r.AdcsEndpoints) }},
		{"SCCM Services", len(r.Sccm), func() string { return renderSccmGrouped(r.Sccm) }},
		{"ADFS Servers", len(r.Adfs), func() string { return renderAdfsGrouped(r.Adfs) }},
		{"Exchange Servers", len(r.Exchange), func() string { return renderExchangeGrouped(r.Exchange) }},
		{"Infrastructure / Identity-Adjacent Services", len(r.Services), func() string { return renderServices(r.Services) }},
		{"Outdated Windows Hosts", len(r.OutdatedWindows), func() string { return renderOutdatedGrouped(r.OutdatedWindows) }},
	}
	var out []adSection
	for _, d := range defs {
		if d.count == 0 {
			continue
		}
		out = append(out, adSection{
			title: d.title,
			count: d.count,
			body:  d.body(),
			path:  "AD/" + sanitizePathSeg(d.title) + ".md",
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// AD.md index + section notes
// ---------------------------------------------------------------------------

// renderADSectionNote renders one AD section note (frontmatter + body).
// Pure: no I/O.
func renderADSectionNote(s adSection, scanName string) string {
	var sb strings.Builder
	writeFrontmatter(&sb, [][2]string{
		{"section", s.title},
		{"scan", scanName},
	})
	sb.WriteString("# " + s.title + "\n")
	sb.WriteString(s.body)
	return sb.String()
}

// RenderADIndex returns the AD.md content: header + a summary table whose rows
// link to each populated section note. Pure: no I/O.
func RenderADIndex(r ad.Report) string {
	notes := adSectionNotes(r)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Active Directory — %s\n\n", r.ScanName))
	sb.WriteString("> [!abstract] Summary\n")
	sb.WriteString("> | Section | Count |\n")
	sb.WriteString("> |---|--:|\n")
	for _, n := range notes {
		link := strings.TrimSuffix(n.path, ".md")
		sb.WriteString(fmt.Sprintf("> | [[%s\\|%s]] | %d |\n", link, n.title, n.count))
	}
	return sb.String()
}

// WriteAD writes AD.md and the AD/ subfolder section notes into dir.
func WriteAD(dir string, r ad.Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sub := filepath.Join(dir, "AD")
	if err := os.RemoveAll(sub); err != nil {
		return err
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		return err
	}
	for _, n := range adSectionNotes(r) {
		p := filepath.Join(dir, filepath.FromSlash(n.path))
		if err := os.WriteFile(p, []byte(renderADSectionNote(n, r.ScanName)), 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, "AD.md"), []byte(RenderADIndex(r)), 0o644)
}

// WriteDefensive writes a top-level Defensive.md when any defensive technology
// is detected; otherwise removes a stale one.
func WriteDefensive(dir string, r ad.Report) error {
	path := filepath.Join(dir, "Defensive.md")
	if len(r.Defensive) == 0 {
		_ = os.Remove(path)
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var sb strings.Builder
	writeFrontmatter(&sb, [][2]string{
		{"section", "Defensive Technology"},
		{"scan", r.ScanName},
	})
	sb.WriteString("# Defensive Technology\n")
	sb.WriteString(renderDefensive(r.Defensive))
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

// credsDir is the top-level folder for credential-related findings.
const credsDir = "Usernames - Creds"

// WriteCreds writes the top-level "Usernames - Creds" folder (index + Email
// Addresses note) when emails are detected; otherwise removes a stale one.
// The folder is named for future username work; today it holds only emails.
func WriteCreds(dir string, r ad.Report) error {
	sub := filepath.Join(dir, credsDir)
	indexPath := filepath.Join(dir, credsDir+".md")
	if len(r.Emails) == 0 {
		_ = os.RemoveAll(sub)
		_ = os.Remove(indexPath)
		return nil
	}
	if err := os.RemoveAll(sub); err != nil {
		return err
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		return err
	}

	var body strings.Builder
	writeFrontmatter(&body, [][2]string{
		{"section", "Email Addresses"},
		{"scan", r.ScanName},
	})
	body.WriteString("# Email Addresses\n")
	body.WriteString(renderEmailSummary(r.EmailSummary))
	body.WriteString("\n\n")
	body.WriteString(renderEmailsFull(r.Emails))
	if err := os.WriteFile(filepath.Join(sub, "Email Addresses.md"), []byte(body.String()), 0o644); err != nil {
		return err
	}

	var idx strings.Builder
	idx.WriteString("# Usernames / Credentials\n\n")
	idx.WriteString("> [!abstract] Summary\n")
	idx.WriteString("> | Section | Count |\n> |---|--:|\n")
	idx.WriteString(fmt.Sprintf("> | [[%s/Email Addresses\\|Email Addresses]] | %d |\n", credsDir, len(r.Emails)))
	return os.WriteFile(indexPath, []byte(idx.String()), 0o644)
}
