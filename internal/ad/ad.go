package ad

import (
	"regexp"
	"sort"
	"strings"

	"layzmd/internal/adparse"
	"layzmd/internal/ipsort"
	"layzmd/internal/nessus"
	"layzmd/internal/osclass"
	"layzmd/internal/osdetect"
)

// ---------------------------------------------------------------------------
// Package-level compiled regexes
// ---------------------------------------------------------------------------

// smbDomainRe matches "remote SMB Domain Name is : VALUE" lines.
var smbDomainRe = regexp.MustCompile(`(?i)remote SMB Domain Name is\s*:\s*(\S+)`)

// ipv4Re matches a bare IPv4 address (all-numeric octets).
var ipv4Re = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)

// SMB share permissions parsing regexes (nadda.py ~2011–2041).
var (
	sharePathRe      = regexp.MustCompile(`(?i)^\s*Share path\s*:\s*(\\{2}\S.+?)\s*$`)
	shareLocalPathRe = regexp.MustCompile(`(?i)^\s*Local path\s*:\s*(.+?)\s*$`)
	shareCommentRe   = regexp.MustCompile(`(?i)^\s*Comment\s*:\s*(.+?)\s*$`)
	// principal_match — capture principal name, stripping optional "(SID)" suffix
	// and requiring the trailing colon that real Nessus output always includes.
	// Matches nadda.py ~2027: required colon, no $ anchor, SID group optional.
	sharePrincipalRe  = regexp.MustCompile(`(?i)^\s*\[\*\]\s+Allow ACE for\s+(.+?)(?:\s+\([^)]+\))?\s*:\s*`)
	sharePermissionRe = regexp.MustCompile(`(?i)^\s*FILE_GENERIC_(READ|WRITE|EXECUTE)\s*:\s*(YES|NO)\s*$`)
)

// guestOutputRe matches guest-login evidence in plugin output (nadda.py ~2062).
var guestOutputRe = regexp.MustCompile(`(?i)authenticated as ['"]?guest['"]?|guest account|log(?:ged)? in as ['"]?guest['"]?`)

// ---------------------------------------------------------------------------
// Identity detector regexes (nadda.py ~571–596)
// ---------------------------------------------------------------------------

// emailRe matches email addresses (nadda.py EMAIL_PATTERN ~596).
var emailRe = regexp.MustCompile(`(?:^|[^\w.+-])([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:[^\w.-]|$)`)

// defaultSMBShares is the set of well-known default administrative shares.
// Ported from nadda.py DEFAULT_SMB_SHARES ~3982.
var defaultSMBShares = map[string]bool{
	"ADMIN$": true,
	"C$":     true,
	"D$":     true,
	"E$":     true,
	"F$":     true,
	"G$":     true,
	"IPC$":   true,
	"PRINT$": true,
}

// lowPrivSMBPrincipals is the set of well-known low-privilege SMB principals.
// Ported from nadda.py LOW_PRIVILEGE_SMB_PRINCIPALS ~3984.
var lowPrivSMBPrincipals = map[string]bool{
	"everyone":            true,
	"guest":               true,
	"guests":              true,
	"authenticated users": true,
	"domain users":        true,
}

// ---------------------------------------------------------------------------
// Domain source ranks (nadda.py DOMAIN_SOURCE_RANKS ~1470)
// ---------------------------------------------------------------------------

var domainSourceRanks = map[string]int{
	"Kerberos realm":          0,
	"LDAP DN":                 1,
	"DNS domain name":         2,
	"DNS tree name":           2,
	"ADCS certificate issuer": 3,
	"MSSQL NTLMSSP":           4,
	"DNS computer name":       5,
	"FQDN resolution":         6,
}

// ---------------------------------------------------------------------------
// Denylist helpers (ported from nadda.py normalize_domain ~1015 and
// normalize_netbios_domain ~1033)
// ---------------------------------------------------------------------------

// domainWordDenylist mirrors nadda.py DOMAIN_WORD_DENYLIST (compared uppercase).
var domainWordDenylist = map[string]bool{
	"WORKGROUP": true,
	"LOCALHOST": true,
	"NULL":      true,
	"NONE":      true,
	"UNKNOWN":   true,
}

// validDomain returns true when s is an acceptable DNS domain candidate.
// s must already be lowercased and slash-stripped by the caller (mirroring
// how nadda.py normalize_domain processes the value before denylist checks).
func validDomain(s string) bool {
	if s == "" {
		return false
	}
	// Word denylist (case-insensitive; compare uppercased)
	if domainWordDenylist[strings.ToUpper(s)] {
		return false
	}
	// Exact denylist
	if s == "ec2.internal" {
		return false
	}
	// Angle brackets
	if strings.Contains(s, "<") || strings.Contains(s, ">") {
		return false
	}
	// Must contain a dot (bare labels rejected)
	if !strings.Contains(s, ".") {
		return false
	}
	// Prefix denylist
	if strings.HasPrefix(s, "domaindnszones.") || strings.HasPrefix(s, "forestdnszones.") {
		return false
	}
	// Bare IPv4 address
	if ipv4Re.MatchString(s) {
		return false
	}
	return true
}

// validNetbios returns true when s is an acceptable NetBIOS name candidate.
// s must already be uppercased and trimmed by the caller (mirroring
// nadda.py normalize_netbios_domain).
func validNetbios(s string) bool {
	if s == "" {
		return false
	}
	// Word denylist (s is already uppercased)
	if domainWordDenylist[s] {
		return false
	}
	// NetBIOS names must NOT contain a dot (nadda.py ~1037: if "." in domain: return "")
	if strings.Contains(s, ".") {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Internal aggregation types
// ---------------------------------------------------------------------------

// hostInfo tracks per-host identity information accumulated during pass 1.
type hostInfo struct {
	ip         string
	fqdns      []string // ordered, deduped
	domains    []string // DNS/LDAP-derived, insertion order
	netbios    []string // NetBIOS names, insertion order
	caps       map[string]bool
	fqdnSet    map[string]bool
	domainSet  map[string]bool
	netbiosSet map[string]bool
}

// domainAgg aggregates sources and hosts for a single domain name.
type domainAgg struct {
	sources map[string]bool
	hosts   map[string]bool
}

// dcEntry holds confidence/evidence for an identified Domain Controller.
type dcEntry struct {
	confidence string
	evidence   string
}

// ---------------------------------------------------------------------------
// Aggregation helpers
// ---------------------------------------------------------------------------

func containsAnyStr(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// addFQDN records an FQDN on h (deduped) and derives a domain candidate from it.
func addFQDN(h *hostInfo, fqdn, ip, source string, domainAggs map[string]*domainAgg) {
	fqdn = strings.ToLower(strings.TrimSpace(fqdn))
	fqdn = strings.TrimSuffix(fqdn, ".")
	if fqdn == "" || !strings.Contains(fqdn, ".") {
		return
	}
	if !h.fqdnSet[fqdn] {
		h.fqdnSet[fqdn] = true
		h.fqdns = append(h.fqdns, fqdn)
	}
	// Derive domain from FQDN and add as a domain candidate.
	domain := adparse.DomainFromFqdn(fqdn)
	if domain != "" {
		addDomainCandidate(h, ip, domain, source, domainAggs)
	}
}

// addDomainCandidate normalises raw, validates it, and records it in both
// the host and the global domain aggregation map.
func addDomainCandidate(h *hostInfo, ip, raw, source string, domainAggs map[string]*domainAgg) {
	norm := adparse.NormalizeDomain(raw)
	norm = strings.Trim(norm, "/\\")
	if !validDomain(norm) {
		return
	}
	if !h.domainSet[norm] {
		h.domainSet[norm] = true
		h.domains = append(h.domains, norm)
	}
	// Detectors (e.g. detectMssql) call this after pass-1 aggregation with a nil
	// domainAggs to record a domain on the host without re-aggregating. Guard the
	// aggregation-map writes so that path does not panic on a nil map.
	if domainAggs == nil {
		return
	}
	agg := domainAggs[norm]
	if agg == nil {
		agg = &domainAgg{
			sources: make(map[string]bool),
			hosts:   make(map[string]bool),
		}
		domainAggs[norm] = agg
	}
	agg.sources[source] = true
	agg.hosts[ip] = true
}

// addNetbiosCandidate normalises raw and records it on h (deduped).
func addNetbiosCandidate(h *hostInfo, raw string) {
	norm := adparse.NormalizeNetbiosDomain(raw)
	if !validNetbios(norm) {
		return
	}
	if !h.netbiosSet[norm] {
		h.netbiosSet[norm] = true
		h.netbios = append(h.netbios, norm)
	}
}

// ---------------------------------------------------------------------------
// Output helpers (ported from nadda.py ~1522–1535)
// ---------------------------------------------------------------------------

// bestFQDN returns the shortest FQDN (tie-broken lexicographically).
// Mirrors nadda.py best_fqdn ~1522.
func bestFQDN(h *hostInfo) string {
	if h == nil || len(h.fqdns) == 0 {
		return ""
	}
	best := h.fqdns[0]
	for _, f := range h.fqdns[1:] {
		if len(f) < len(best) || (len(f) == len(best) && f < best) {
			best = f
		}
	}
	return best
}

// bestDomain returns a comma-joined sorted list of the host's DNS domains
// (or NetBIOS names when no DNS domains are known).
// Mirrors nadda.py best_domain ~1528.
func bestDomain(h *hostInfo) string {
	if h == nil {
		return ""
	}
	if len(h.domains) > 0 {
		ds := make([]string, len(h.domains))
		copy(ds, h.domains)
		sort.Strings(ds)
		return strings.Join(ds, ", ")
	}
	if len(h.netbios) > 0 {
		ns := make([]string, len(h.netbios))
		copy(ns, h.netbios)
		sort.Strings(ns)
		return strings.Join(ns, ", ")
	}
	return ""
}

// ---------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------

// domainConfidenceLabel returns "High"/"Medium"/"Low" based on best source rank.
// Ported from nadda.py domain_confidence_label ~1486. Confidence labels are
// capitalized consistently across all AD sections (matches nadda.py).
func domainConfidenceLabel(sources map[string]bool) string {
	rank := 99
	for s := range sources {
		if r, ok := domainSourceRanks[s]; ok && r < rank {
			rank = r
		}
	}
	if rank <= 2 {
		return "High"
	}
	if rank <= 4 {
		return "Medium"
	}
	return "Low"
}

// domainSortRank returns the minimum source rank for a domain aggregate.
func domainSortRank(agg *domainAgg) int {
	rank := 99
	for s := range agg.sources {
		if r, ok := domainSourceRanks[s]; ok && r < rank {
			rank = r
		}
	}
	return rank
}

// ---------------------------------------------------------------------------
// Section builders
// ---------------------------------------------------------------------------

func buildDomains(domainAggs map[string]*domainAgg, hosts map[string]*hostInfo) []Domain {
	result := make([]Domain, 0, len(domainAggs))
	for name, agg := range domainAggs {
		// Count hosts that have recorded this domain.
		hostCount := 0
		for _, h := range hosts {
			if h.domainSet[name] {
				hostCount++
			}
		}
		// Build sources slice sorted by rank then name (deterministic).
		sources := make([]string, 0, len(agg.sources))
		for s := range agg.sources {
			sources = append(sources, s)
		}
		sort.Slice(sources, func(i, j int) bool {
			ri := 99
			if r, ok := domainSourceRanks[sources[i]]; ok {
				ri = r
			}
			rj := 99
			if r, ok := domainSourceRanks[sources[j]]; ok {
				rj = r
			}
			if ri != rj {
				return ri < rj
			}
			return sources[i] < sources[j]
		})
		result = append(result, Domain{
			Name:       name,
			Confidence: domainConfidenceLabel(agg.sources),
			Sources:    sources,
			Hosts:      hostCount,
		})
	}
	// Sort by confidence rank ascending (best first) then name.
	sort.Slice(result, func(i, j int) bool {
		ri := domainSortRank(domainAggs[result[i].Name])
		rj := domainSortRank(domainAggs[result[j].Name])
		if ri != rj {
			return ri < rj
		}
		return result[i].Name < result[j].Name
	})
	return result
}

func buildNetbios(hosts map[string]*hostInfo) []NetbiosName {
	counts := make(map[string]int)
	for _, h := range hosts {
		for _, n := range h.netbios {
			counts[n]++
		}
	}
	result := make([]NetbiosName, 0, len(counts))
	for name, cnt := range counts {
		result = append(result, NetbiosName{Name: name, Hosts: cnt})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}

func buildDCs(dcs map[string]*dcEntry, hosts map[string]*hostInfo) []DCRow {
	// Collect IPs sorted numerically.
	ips := make([]string, 0, len(dcs))
	for ip := range dcs {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return ipsort.Key(ips[i]) < ipsort.Key(ips[j])
	})

	result := make([]DCRow, 0, len(ips))
	for _, ip := range ips {
		dc := dcs[ip]
		h := hosts[ip]
		fqdn := bestFQDN(h)
		domain := bestDomain(h)
		var domains []string
		if h != nil {
			ds := make([]string, len(h.domains))
			copy(ds, h.domains)
			sort.Strings(ds)
			domains = ds
		}
		result = append(result, DCRow{
			IP:         ip,
			FQDN:       fqdn,
			Domain:     domain,
			Confidence: dc.confidence,
			Domains:    domains,
		})
	}
	return result
}

func buildDNSServers(dnsServers map[string]string, hosts map[string]*hostInfo) []DNSRow {
	ips := make([]string, 0, len(dnsServers))
	for ip := range dnsServers {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return ipsort.Key(ips[i]) < ipsort.Key(ips[j])
	})

	result := make([]DNSRow, 0, len(ips))
	for _, ip := range ips {
		h := hosts[ip]
		port := dnsServers[ip]
		if port == "" {
			port = "53"
		}
		result = append(result, DNSRow{
			IP:   ip,
			FQDN: bestFQDN(h),
			Port: port,
		})
	}
	return result
}

// ---------------------------------------------------------------------------
// isDefaultSMBShare reports whether share is a well-known default admin share.
// Ported from nadda.py is_default_smb_share ~3987.
// ---------------------------------------------------------------------------
func isDefaultSMBShare(share string) bool {
	upper := strings.ToUpper(strings.TrimSpace(share))
	if defaultSMBShares[upper] {
		return true
	}
	// Single drive-letter dollar shares e.g. "H$" match [A-Z]$.
	if len(upper) == 2 && upper[0] >= 'A' && upper[0] <= 'Z' && upper[1] == '$' {
		return true
	}
	return false
}

// isLowPrivPrincipal reports whether a principal's last component (after \)
// is in the low-privilege set. Ported from nadda.py low_privilege_smb_principals ~3992.
func isLowPrivPrincipal(principal string) bool {
	parts := strings.SplitN(principal, "\\", 2)
	last := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
	return lowPrivSMBPrincipals[last]
}

// shareFromUNC returns the last path component of a UNC path.
// Ported from nadda.py share_from_unc ~1989.
func shareFromUNC(unc string) string {
	trimmed := strings.TrimLeft(strings.TrimSpace(unc), "\\")
	parts := strings.Split(trimmed, "\\")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

// smbShareAccess builds a human-readable access label from boolean permission flags.
// Ported from nadda.py smb_share_access_summary ~4001.
func smbShareAccess(readable, writable, executable bool, hasPerms bool) string {
	var parts []string
	if readable {
		parts = append(parts, "Read")
	}
	if writable {
		parts = append(parts, "Write")
	}
	if executable {
		parts = append(parts, "Execute")
	}
	if len(parts) > 0 {
		return strings.Join(parts, ", ")
	}
	if hasPerms {
		return "Permissions reported"
	}
	return "Listed"
}

// ---------------------------------------------------------------------------
// SMB Signing detector (nadda.py detect_smb_signing ~1949)
// ---------------------------------------------------------------------------

// detectSMBSigning fills Report.SMBSigning and Report.SMBSigningSummary.
func detectSMBSigning(fs []nessus.Finding, hosts map[string]*hostInfo) ([]SMBSigningRow, []SMBSigningSummary) {
	// domain → set of IPs
	type domainEntry struct {
		ips map[string]bool
	}
	domainMap := make(map[string]*domainEntry)
	var rows []SMBSigningRow

	for _, f := range fs {
		if strings.ToLower(strings.TrimSpace(f.Name)) != "smb signing not required" {
			continue
		}
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" {
			continue
		}
		h := hosts[ip]
		domain := bestDomain(h)
		fqdn := bestFQDN(h)
		port := strings.TrimSpace(f.Port)
		if port == "" {
			port = "445"
		}
		rows = append(rows, SMBSigningRow{
			Domain: domain,
			IP:     ip,
			FQDN:   fqdn,
			Port:   port,
		})
		if domainMap[domain] == nil {
			domainMap[domain] = &domainEntry{ips: make(map[string]bool)}
		}
		domainMap[domain].ips[ip] = true
	}

	// Sort rows: domain-grouped, then by IP (ipsort).
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Domain != rows[j].Domain {
			return rows[i].Domain < rows[j].Domain
		}
		return ipsort.Key(rows[i].IP) < ipsort.Key(rows[j].IP)
	})

	// Build summaries sorted by count desc then domain name.
	summaries := make([]SMBSigningSummary, 0, len(domainMap))
	for domain, entry := range domainMap {
		summaries = append(summaries, SMBSigningSummary{
			Domain: domain,
			Hosts:  len(entry.ips),
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Hosts != summaries[j].Hosts {
			return summaries[i].Hosts > summaries[j].Hosts
		}
		return summaries[i].Domain < summaries[j].Domain
	})

	return rows, summaries
}

// ---------------------------------------------------------------------------
// SMB Shares detector (nadda.py detect_smb_shares ~2044, parse_smb_share_permissions ~2007)
// ---------------------------------------------------------------------------

// smbShareKey is the dedup key for a share finding.
type smbShareKey struct{ ip, share string }

// smbShareFinding holds the mutable state built during share parsing.
type smbShareFinding struct {
	ip           string
	share        string
	unc          string
	port         string
	readable     bool
	writable     bool
	executable   bool
	hasPerms     bool // any FILE_GENERIC_* line seen
	principals   []string
	principalSet map[string]bool
}

func newSmbShareFinding(ip, share, unc, port string) *smbShareFinding {
	return &smbShareFinding{
		ip:           ip,
		share:        share,
		unc:          unc,
		port:         port,
		principalSet: make(map[string]bool),
	}
}

func (sf *smbShareFinding) addPrincipal(p string) {
	if !sf.principalSet[p] {
		sf.principalSet[p] = true
		sf.principals = append(sf.principals, p)
	}
}

// detectShares fills Report.Shares and Report.ShareSummary.
func detectShares(fs []nessus.Finding, hosts map[string]*hostInfo) ([]ShareRow, []ShareSummary) {
	// keyed by (ip, share-lower)
	shareMap := make(map[smbShareKey]*smbShareFinding)

	ensureShare := func(f nessus.Finding, share, unc string) *smbShareFinding {
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" || share == "" {
			return nil
		}
		key := smbShareKey{ip: ip, share: strings.ToLower(share)}
		sf := shareMap[key]
		if sf == nil {
			port := strings.TrimSpace(f.Port)
			if port == "" {
				port = "445"
			}
			sf = newSmbShareFinding(ip, share, unc, port)
			shareMap[key] = sf
		} else if unc != "" && sf.unc == "" {
			sf.unc = unc
		}
		return sf
	}

	for _, f := range fs {
		pluginID := strings.TrimSpace(f.PluginID)
		nameLower := strings.ToLower(strings.TrimSpace(f.Name))

		if pluginID == "10395" || nameLower == "microsoft windows smb shares enumeration" {
			// Parse "  - ShareName" lines.
			for _, line := range strings.Split(f.PluginOutput, "\n") {
				// nadda.py parse_smb_share_names: match "^\s*-\s+(.+?)\s*$"
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "- ") {
					share := strings.TrimSpace(trimmed[2:])
					if share != "" {
						ensureShare(f, share, "")
					}
				}
			}
			continue
		}

		if pluginID == "60119" || nameLower == "microsoft windows smb share permissions enumeration" {
			// Parse share-permission blocks.
			var current *smbShareFinding
			var currentPrincipal string
			for _, line := range strings.Split(f.PluginOutput, "\n") {
				if m := sharePathRe.FindStringSubmatch(line); m != nil {
					unc := strings.TrimSpace(m[1])
					share := shareFromUNC(unc)
					current = ensureShare(f, share, unc)
					currentPrincipal = ""
					continue
				}
				if current == nil {
					continue
				}
				if shareLocalPathRe.MatchString(line) {
					// local path recorded but not stored on the row (nadda.py stores it on finding)
					continue
				}
				if shareCommentRe.MatchString(line) {
					continue
				}
				if m := sharePrincipalRe.FindStringSubmatch(line); m != nil {
					currentPrincipal = strings.TrimSpace(m[1])
					current.addPrincipal(currentPrincipal)
					continue
				}
				if m := sharePermissionRe.FindStringSubmatch(line); m != nil && currentPrincipal != "" {
					perm := strings.ToUpper(m[1])
					yn := strings.ToUpper(m[2])
					current.hasPerms = true
					if yn == "YES" {
						switch perm {
						case "READ":
							current.readable = true
						case "WRITE":
							current.writable = true
						case "EXECUTE":
							current.executable = true
						}
					}
					continue
				}
			}
			continue
		}
	}

	// Build rows from shareMap.
	// domain → per-domain stats for summary.
	type domainStats struct {
		ips        map[string]bool
		shares     int
		nonDefault int
		writable   int
		lowPriv    int
	}
	domainMap := make(map[string]*domainStats)

	var rows []ShareRow
	for _, sf := range shareMap {
		h := hosts[sf.ip]
		domain := bestDomain(h)
		fqdn := bestFQDN(h)

		// Build UNC if missing (nadda.py ~2825–2827).
		unc := sf.unc
		if unc == "" {
			// Use FQDN or IP as server name.
			serverName := fqdn
			if serverName == "" {
				serverName = sf.ip
			}
			unc = `\\` + serverName + `\` + sf.share
		}

		// Build principals list (low-priv first, then all others).
		var lowPriv []string
		var otherPrincipals []string
		for _, p := range sf.principals {
			if isLowPrivPrincipal(p) {
				lowPriv = append(lowPriv, p)
			} else {
				otherPrincipals = append(otherPrincipals, p)
			}
		}
		principals := append(lowPriv, otherPrincipals...)

		access := smbShareAccess(sf.readable, sf.writable, sf.executable, sf.hasPerms)

		rows = append(rows, ShareRow{
			Domain:     domain,
			IP:         sf.ip,
			FQDN:       fqdn,
			Share:      sf.share,
			UNC:        unc,
			Access:     access,
			Principals: principals,
		})

		// Update domain stats.
		ds := domainMap[domain]
		if ds == nil {
			ds = &domainStats{ips: make(map[string]bool)}
			domainMap[domain] = ds
		}
		ds.ips[sf.ip] = true
		ds.shares++
		if !isDefaultSMBShare(sf.share) {
			ds.nonDefault++
		}
		if sf.writable {
			ds.writable++
		}
		hasLP := false
		for _, p := range sf.principals {
			if isLowPrivPrincipal(p) {
				hasLP = true
				break
			}
		}
		if hasLP {
			ds.lowPriv++
		}
	}

	// Sort rows: domain-grouped, then by IP.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Domain != rows[j].Domain {
			return rows[i].Domain < rows[j].Domain
		}
		if rows[i].IP != rows[j].IP {
			return ipsort.Key(rows[i].IP) < ipsort.Key(rows[j].IP)
		}
		return strings.ToLower(rows[i].Share) < strings.ToLower(rows[j].Share)
	})

	// Build summaries sorted by count desc then domain.
	summaries := make([]ShareSummary, 0, len(domainMap))
	for domain, ds := range domainMap {
		summaries = append(summaries, ShareSummary{
			Domain:     domain,
			Hosts:      len(ds.ips),
			Shares:     ds.shares,
			NonDefault: ds.nonDefault,
			Writable:   ds.writable,
			LowPriv:    ds.lowPriv,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Hosts != summaries[j].Hosts {
			return summaries[i].Hosts > summaries[j].Hosts
		}
		return summaries[i].Domain < summaries[j].Domain
	})

	return rows, summaries
}

// ---------------------------------------------------------------------------
// Guest Account Access detector (nadda.py detect_guest_access ~2055)
// ---------------------------------------------------------------------------

// detectGuest fills Report.Guest.
func detectGuest(fs []nessus.Finding, hosts map[string]*hostInfo) []GuestRow {
	// Dedup by IP — one row per host.
	seen := make(map[string]bool)
	var rows []GuestRow

	for _, f := range fs {
		pluginID := strings.TrimSpace(f.PluginID)
		nameLower := strings.ToLower(strings.TrimSpace(f.Name))

		if pluginID != "10394" && !strings.Contains(nameLower, "smb log in possible") {
			continue
		}

		combined := nameLower + "\n" + f.PluginOutput
		if !guestOutputRe.MatchString(combined) {
			continue
		}

		ip := strings.TrimSpace(f.HostIP)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true

		h := hosts[ip]
		port := strings.TrimSpace(f.Port)
		if port == "" {
			port = "445"
		}
		rows = append(rows, GuestRow{
			Domain: bestDomain(h),
			IP:     ip,
			FQDN:   bestFQDN(h),
			Port:   port,
			Access: "Guest",
		})
	}

	// Sort: domain-grouped then by IP.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Domain != rows[j].Domain {
			return rows[i].Domain < rows[j].Domain
		}
		return ipsort.Key(rows[i].IP) < ipsort.Key(rows[j].IP)
	})

	return rows
}

// ---------------------------------------------------------------------------
// SMBv1 / Null Session detector (nadda.py ~2795)
// ---------------------------------------------------------------------------

// smbv1Signals is the ordered list of bounded search terms for SMBv1/null session.
// Ported from nadda.py ~2795: six terms plus a compound check.
var smbv1Signals = []string{"smbv1", "smb v1", "version 1 enabled", "null session", "anonymous smb", "smb null"}

// detectSmbV1 fills Report.SmbV1.
func detectSmbV1(fs []nessus.Finding, hosts map[string]*hostInfo) []SmbV1Row {
	// Dedup by (ip, detail).
	type smbV1Key struct{ ip, detail string }
	seen := make(map[smbV1Key]bool)
	var rows []SmbV1Row

	for _, f := range fs {
		nameLower := strings.ToLower(strings.TrimSpace(f.Name))
		combined := nameLower + " " + strings.ToLower(f.PluginOutput)

		for _, signal := range smbv1Signals {
			if !adparse.ContainsAnyBounded(combined, signal) {
				continue
			}
			ip := strings.TrimSpace(f.HostIP)
			if ip == "" {
				continue
			}
			key := smbV1Key{ip: ip, detail: signal}
			if seen[key] {
				continue
			}
			seen[key] = true

			h := hosts[ip]
			port := strings.TrimSpace(f.Port)
			rows = append(rows, SmbV1Row{
				Domain: bestDomain(h),
				IP:     ip,
				FQDN:   bestFQDN(h),
				Detail: signal,
				Port:   port,
			})
		}

		// Compound check: "server message block" AND "version 1" (nadda.py ~2795).
		if adparse.ContainsAnyBounded(combined, "server message block") &&
			adparse.ContainsAnyBounded(combined, "version 1") {
			const compoundDetail = "server message block + version 1"
			ip := strings.TrimSpace(f.HostIP)
			if ip != "" {
				key := smbV1Key{ip: ip, detail: compoundDetail}
				if !seen[key] {
					seen[key] = true
					h := hosts[ip]
					port := strings.TrimSpace(f.Port)
					rows = append(rows, SmbV1Row{
						Domain: bestDomain(h),
						IP:     ip,
						FQDN:   bestFQDN(h),
						Detail: compoundDetail,
						Port:   port,
					})
				}
			}
		}
	}

	// Sort: domain-grouped, then by IP, then by detail.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Domain != rows[j].Domain {
			return rows[i].Domain < rows[j].Domain
		}
		if rows[i].IP != rows[j].IP {
			return ipsort.Key(rows[i].IP) < ipsort.Key(rows[j].IP)
		}
		return rows[i].Detail < rows[j].Detail
	})

	return rows
}

// ---------------------------------------------------------------------------
// confidenceRank returns 0=High, 1=Medium, 2=Low, 3=unknown for comparison
// (lower = better). An empty/unknown label ranks worse than "Low" so that
// betterConfidence("", "Low") returns "Low" rather than keeping the empty seed.
// ---------------------------------------------------------------------------
func confidenceRank(c string) int {
	switch c {
	case "High":
		return 0
	case "Medium":
		return 1
	case "Low":
		return 2
	default:
		return 3 // empty or unknown ranks worse than Low
	}
}

// betterConfidence returns the higher-priority confidence label.
func betterConfidence(a, b string) string {
	if confidenceRank(a) <= confidenceRank(b) {
		return a
	}
	return b
}

// httpNameRe matches http/web plugin names (nadda.py ~2210).
var httpNameRe = regexp.MustCompile(`\b(http|web server|web mirroring|hypertext)\b`)

// certOutputRe matches certificate field headers in plugin output (nadda.py ~2212).
var certOutputRe = regexp.MustCompile(`(?i)\b(subject|issuer|common name|email address)\s*:`)

// emailSourceType returns the source type label for an email finding.
// Ported from nadda.py email_source_type ~2198.
func emailSourceType(pluginID, nameLower, outputLower string) string {
	if pluginID == "49705" || strings.Contains(nameLower, "harvested email") {
		return "web_harvest"
	}
	if pluginID == "50504" || strings.Contains(nameLower, "common credentials") || strings.Contains(outputLower, "default credential") {
		return "credential"
	}
	if strings.Contains(nameLower, "ldap") {
		return "ldap"
	}
	if strings.Contains(nameLower, "smtp") || strings.Contains(nameLower, "starttls") {
		return "smtp"
	}
	if httpNameRe.MatchString(nameLower) {
		return "http"
	}
	if strings.Contains(nameLower, "ssl certificate") || certOutputRe.MatchString(outputLower) {
		return "certificate"
	}
	return "plugin_output"
}

// emailConfidence returns the confidence label for a source type.
// Ported from nadda.py email_confidence_for_source ~2238.
// domain_matches_client is false here (we don't have client domain context in this detector).
func emailConfidence(sourceType string) string {
	switch sourceType {
	case "web_harvest", "credential", "ldap", "smtp", "http":
		return "Medium"
	default:
		return "Low"
	}
}

// emailKey is the dedup key for an email finding.
type emailKey struct{ email, source string }

// emailFinding accumulates data for a single discovered email address.
type emailFinding struct {
	email      string
	source     string
	confidence string
	hostSet    map[string]bool
}

// junkEmailDomains: infrastructure / library / scanner / reference domains that
// surface in plugin output (SSH algorithm names like aes128-gcm@openssh.com and
// curve25519-sha256@libssh.org, mod_ssl, Nessus references, Apache mailing
// lists) but are never real target email addresses.
var junkEmailDomains = []string{
	"openssh.com", "libssh.org", "lysator.liu.se", "modssl.org",
	"nessus.org", "tenable.com", "apache.org",
}

// cryptoAlgoTokens: local-part substrings that mark an SSH cipher/MAC/KEX
// algorithm name (RFC 4251 "name@domain" form) mis-parsed as an email.
var cryptoAlgoTokens = []string{
	"-cbc", "-ctr", "-gcm", "-etm", "chacha20", "poly1305", "umac-",
	"hmac-", "curve25519", "ecdh-", "diffie-hellman", "rijndael",
	"aes128", "aes192", "aes256", "3des-", "blowfish-", "cast128-", "arcfour",
	"ssh-rsa", "ssh-ed25519", "ssh-dss",
}

// isJunkEmail reports whether an extracted "email" is actually an SSH algorithm
// identifier, a library/reference domain, or a mailing-list address rather than
// a real target address.
func isJunkEmail(email string) bool {
	lower := strings.ToLower(email)
	at := strings.LastIndex(lower, "@")
	if at < 0 {
		return false
	}
	local, domain := lower[:at], lower[at+1:]
	for _, d := range junkEmailDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	for _, tok := range cryptoAlgoTokens {
		if strings.Contains(local, tok) {
			return true
		}
	}
	return false
}

// detectEmails fills Report.Emails and Report.EmailSummary.
// Ported from nadda.py detect_emails ~2277–2286.
func detectEmails(fs []nessus.Finding) ([]EmailRow, []EmailSummary) {
	findings := make(map[string]*emailFinding) // key = email (lowercased)

	for _, f := range fs {
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" {
			continue
		}

		// Build search blob (name + synopsis + description + plugin output).
		blob := f.Name + " " + f.Synopsis + " " + f.Description + " " + f.PluginOutput

		// Gate: must contain "@".
		if !strings.Contains(blob, "@") {
			continue
		}

		pluginID := strings.TrimSpace(f.PluginID)
		nameLower := strings.ToLower(strings.TrimSpace(f.Name))
		outputLower := strings.ToLower(f.PluginOutput)
		sourceType := emailSourceType(pluginID, nameLower, outputLower)
		conf := emailConfidence(sourceType)

		for _, m := range emailRe.FindAllStringSubmatch(blob, -1) {
			email := m[1]
			if isJunkEmail(email) {
				continue
			}
			emailLower := strings.ToLower(email)

			ef := findings[emailLower]
			if ef == nil {
				ef = &emailFinding{
					email:      email,
					source:     sourceType,
					confidence: conf,
					hostSet:    make(map[string]bool),
				}
				findings[emailLower] = ef
			}
			// Best confidence wins.
			ef.confidence = betterConfidence(ef.confidence, conf)
			if ip != "" {
				ef.hostSet[ip] = true
			}
		}
	}

	// Build sorted EmailRow slice.
	rows := make([]EmailRow, 0, len(findings))
	for _, f := range findings {
		hosts := make([]string, 0, len(f.hostSet))
		for h := range f.hostSet {
			hosts = append(hosts, h)
		}
		sort.Slice(hosts, func(i, j int) bool {
			return ipsort.Key(hosts[i]) < ipsort.Key(hosts[j])
		})
		rows = append(rows, EmailRow{
			Email:       f.email,
			Source:      f.source,
			SourceHosts: hosts,
			Confidence:  f.confidence,
		})
	}
	// Sort by Email ascending (deterministic).
	sort.Slice(rows, func(i, j int) bool {
		return strings.ToLower(rows[i].Email) < strings.ToLower(rows[j].Email)
	})

	// Build EmailSummary grouped by Source.
	type sourceStats struct {
		emails     map[string]bool
		hostSet    map[string]bool
		confidence string
	}
	sourceMap := make(map[string]*sourceStats)
	for _, r := range rows {
		ss := sourceMap[r.Source]
		if ss == nil {
			ss = &sourceStats{
				emails:  make(map[string]bool),
				hostSet: make(map[string]bool),
			}
			sourceMap[r.Source] = ss
		}
		ss.emails[strings.ToLower(r.Email)] = true
		for _, h := range r.SourceHosts {
			ss.hostSet[h] = true
		}
		ss.confidence = betterConfidence(ss.confidence, r.Confidence)
	}
	summaries := make([]EmailSummary, 0, len(sourceMap))
	for source, ss := range sourceMap {
		summaries = append(summaries, EmailSummary{
			Source:      source,
			Emails:      len(ss.emails),
			SourceHosts: len(ss.hostSet),
			Confidence:  ss.confidence,
		})
	}
	// Sort by Emails desc then Source asc.
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Emails != summaries[j].Emails {
			return summaries[i].Emails > summaries[j].Emails
		}
		return summaries[i].Source < summaries[j].Source
	})

	return rows, summaries
}

// ---------------------------------------------------------------------------
// Defensive Technology detector (nadda.py detect_defensive_tech ~2464–2487)
// ---------------------------------------------------------------------------

// defensiveSig is a single entry in the DEFENSIVE_TECH_SIGNATURES table.
type defensiveSig struct {
	category string
	product  string
	pattern  *regexp.Regexp
}

// defensiveTechSignatures is the verbatim port of nadda.py DEFENSIVE_TECH_SIGNATURES ~306–340.
// Each entry: (category, product, compiled regex).
var defensiveTechSignatures = []defensiveSig{
	{"AV/EDR", "Microsoft Defender", regexp.MustCompile(`(?i)\b(microsoft defender|windows defender|defender for endpoint|mdatp|sense service|windefend)\b`)},
	{"EDR", "CrowdStrike Falcon", regexp.MustCompile(`(?i)\b(crowdstrike|falcon sensor|csagent)\b`)},
	{"EDR", "SentinelOne", regexp.MustCompile(`(?i)\b(sentinelone|sentinel agent)\b`)},
	{"EDR", "Carbon Black", regexp.MustCompile(`(?i)\b(carbon black|carbonblack|cb defense|cber|vmware carbon black)\b`)},
	{"AV/EDR", "Sophos", regexp.MustCompile(`(?i)\b(sophos|intercept x)\b`)},
	{"AV/EDR", "Trellix/McAfee", regexp.MustCompile(`(?i)\b(trellix|mcafee|mcshield|endpoint security platform|ens platform)\b`)},
	{"AV/EDR", "Symantec/Broadcom", regexp.MustCompile(`(?i)\b(symantec endpoint|symantec antivirus|broadcom endpoint|sep client)\b`)},
	{"AV/EDR", "Trend Micro", regexp.MustCompile(`(?i)\b(trend micro|officescan|apex one)\b`)},
	{"EDR", "Cortex XDR", regexp.MustCompile(`(?i)\b(cortex xdr|palo alto traps|\btraps\b)\b`)},
	{"EDR", "Elastic Agent", regexp.MustCompile(`(?i)\b(elastic agent|elastic endpoint)\b`)},
	{"Endpoint Management", "Tanium", regexp.MustCompile(`(?i)\btanium\b`)},
	{"Vulnerability Management", "Qualys Cloud Agent", regexp.MustCompile(`(?i)\b(qualys cloud agent|qualysagent)\b`)},
	{"SIEM/Logging", "Splunk", regexp.MustCompile(`(?i)\b(splunk|splunkd|splunk forwarder)\b`)},
	{"SIEM/Logging", "IBM QRadar", regexp.MustCompile(`(?i)\b(qradar|ibm security qradar)\b`)},
	{"SIEM/Logging", "ArcSight", regexp.MustCompile(`(?i)\b(arcsight|esm manager|smartconnector)\b`)},
	{"SIEM/Logging", "Elastic Stack", regexp.MustCompile(`(?i)\b(kibana|logstash|elasticsearch)\b`)},
	{"SIEM/Logging", "Graylog", regexp.MustCompile(`(?i)\bgraylog\b`)},
	{"SIEM/Logging", "Wazuh", regexp.MustCompile(`(?i)\bwazuh\b`)},
	{"Vulnerability Management", "Tenable", regexp.MustCompile(`(?i)\b(tenable\.sc|tenable io|tenable\.io|tenable securitycenter|nessus agent|nessus manager|nessus web server|nessuswww)\b`)},
	{"Vulnerability Management", "Rapid7", regexp.MustCompile(`(?i)\b(rapid7|nexpose|insightvm)\b`)},
	{"MDR", "Huntress", regexp.MustCompile(`(?i)\bhuntress\b`)},
	{"MDR", "Arctic Wolf", regexp.MustCompile(`(?i)\barctic wolf\b`)},
	{"MDR", "Secureworks", regexp.MustCompile(`(?i)\bsecureworks\b`)},
	{"RMM/MDR", "ConnectWise", regexp.MustCompile(`(?i)\b(connectwise|screenconnect)\b`)},
	{"RMM/MDR", "NinjaOne", regexp.MustCompile(`(?i)\b(ninjaone|ninja rmm)\b`)},
	{"RMM/MDR", "Kaseya", regexp.MustCompile(`(?i)\bkaseya\b`)},
	{"RMM/MDR", "Datto", regexp.MustCompile(`(?i)\bdatto\b`)},
	{"Network Security", "Fortinet", regexp.MustCompile(`(?i)\b(fortinet|fortigate|fortianalyzer|fortimanager)\b`)},
	{"Network Security", "Palo Alto", regexp.MustCompile(`(?i)\b(palo alto|pan-os|panorama)\b`)},
	{"Network Security", "Cisco Security", regexp.MustCompile(`(?i)\b(cisco asa|firepower|secure firewall)\b`)},
	{"Network Security", "Check Point", regexp.MustCompile(`(?i)\b(check point|checkpoint firewall)\b`)},
	{"SASE/SWG", "Zscaler", regexp.MustCompile(`(?i)\bzscaler\b`)},
	{"SASE/SWG", "Netskope", regexp.MustCompile(`(?i)\bnetskope\b`)},
}

// defensiveTechKeywords is the gate for defensive tech detection.
// Ported verbatim from nadda.py DEFENSIVE_TECH_KEYWORDS ~344–427.
var defensiveTechKeywords = []string{
	"microsoft defender",
	"windows defender",
	"defender for endpoint",
	"mdatp",
	"sense service",
	"windefend",
	"crowdstrike",
	"falcon sensor",
	"csagent",
	"sentinelone",
	"sentinel agent",
	"carbon black",
	"carbonblack",
	"cb defense",
	"cber",
	"sophos",
	"intercept x",
	"trellix",
	"mcafee",
	"mcshield",
	"endpoint security platform",
	"ens platform",
	"symantec endpoint",
	"symantec antivirus",
	"broadcom endpoint",
	"sep client",
	"trend micro",
	"officescan",
	"apex one",
	"cortex xdr",
	"palo alto traps",
	"traps",
	"elastic agent",
	"elastic endpoint",
	"tanium",
	"qualys cloud agent",
	"qualysagent",
	"splunk",
	"splunkd",
	"splunk forwarder",
	"qradar",
	"arcsight",
	"smartconnector",
	"kibana",
	"logstash",
	"elasticsearch",
	"graylog",
	"wazuh",
	"tenable.sc",
	"tenable io",
	"tenable.io",
	"tenable securitycenter",
	"nessus agent",
	"nessus manager",
	"nessus web server",
	"nessuswww",
	"rapid7",
	"nexpose",
	"insightvm",
	"huntress",
	"arctic wolf",
	"secureworks",
	"connectwise",
	"screenconnect",
	"ninjaone",
	"ninja rmm",
	"kaseya",
	"datto",
	"fortinet",
	"fortigate",
	"fortianalyzer",
	"fortimanager",
	"palo alto",
	"pan-os",
	"panorama",
	"cisco asa",
	"firepower",
	"secure firewall",
	"check point",
	"checkpoint firewall",
	"zscaler",
	"netskope",
}

// defensiveServiceFieldRe matches service/daemon/process field lines in plugin output.
var defensiveServiceFieldRe = regexp.MustCompile(`(?i)\b(service name|display name|process name|daemon)\s*:`)

// defensiveCertFieldRe matches cert subject/issuer lines in plugin output.
var defensiveCertFieldRe = regexp.MustCompile(`(?i)\b(subject|issuer|common name)\s*:`)

// defensiveEvidenceType returns the evidence type label and confidence for a finding.
// Ported from nadda.py defensive_evidence_type ~2418–2431.
func defensiveEvidenceType(nameLower, text string) (string, string) {
	if regexp.MustCompile(`(?i)\b(installed software|software enumeration|software installed|package listing)\b`).MatchString(nameLower) {
		return "Installed software", "High"
	}
	if regexp.MustCompile(`(?i)\b(service|daemon|process)\b`).MatchString(nameLower) || defensiveServiceFieldRe.MatchString(text) {
		return "Service/process", "High"
	}
	if strings.Contains(nameLower, "cpe") || strings.Contains(strings.ToLower(text), "cpe:/") {
		return "CPE", "Medium"
	}
	if strings.Contains(nameLower, "ssl certificate") || defensiveCertFieldRe.MatchString(text) {
		return "Certificate", "Medium"
	}
	if regexp.MustCompile(`(?i)\b(http|web server|title|server header)\b`).MatchString(nameLower) {
		return "HTTP", "Medium"
	}
	return "Plugin output", "Medium"
}

// defensiveKey is the dedup key for an aggregated defensive tech detection.
type defensiveKey struct{ category, product string }

// defensiveFinding accumulates data for a single (category, product) pair.
type defensiveFinding struct {
	category      string
	product       string
	confidence    string
	hostSet       map[string]bool
	evidenceTypes map[string]bool
}

// detectDefensive fills Report.Defensive.
// Ported from nadda.py detect_defensive_tech ~2464–2487.
func detectDefensive(fs []nessus.Finding, hosts map[string]*hostInfo) []DefensiveRow {
	findings := make(map[defensiveKey]*defensiveFinding)

	addFinding := func(category, product, evType, confidence, ip string) {
		key := defensiveKey{category: strings.ToLower(category), product: strings.ToLower(product)}
		df := findings[key]
		if df == nil {
			df = &defensiveFinding{
				category:      category,
				product:       product,
				confidence:    confidence,
				hostSet:       make(map[string]bool),
				evidenceTypes: make(map[string]bool),
			}
			findings[key] = df
		}
		df.confidence = betterConfidence(df.confidence, confidence)
		df.evidenceTypes[evType] = true
		if ip != "" {
			df.hostSet[ip] = true
		}
	}

	for _, f := range fs {
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" {
			continue
		}

		// Build search blob (name + synopsis + description + plugin output, lowercased).
		text := f.Name + " " + f.Synopsis + " " + f.Description + " " + f.PluginOutput
		textLower := strings.ToLower(text)

		// Gate: must contain at least one DEFENSIVE_TECH_KEYWORDS term.
		gateOK := false
		for _, kw := range defensiveTechKeywords {
			if strings.Contains(textLower, kw) {
				gateOK = true
				break
			}
		}
		if !gateOK {
			continue
		}

		nameLower := strings.ToLower(strings.TrimSpace(f.Name))
		evType, confidence := defensiveEvidenceType(nameLower, text)

		for _, sig := range defensiveTechSignatures {
			if sig.pattern.MatchString(text) {
				addFinding(sig.category, sig.product, evType, confidence, ip)
			}
		}
	}

	// Build sorted DefensiveRow slice — flat table sorted by Hosts desc then Category/Product.
	rows := make([]DefensiveRow, 0, len(findings))
	for _, df := range findings {
		evTypes := make([]string, 0, len(df.evidenceTypes))
		for et := range df.evidenceTypes {
			evTypes = append(evTypes, et)
		}
		sort.Strings(evTypes)
		rows = append(rows, DefensiveRow{
			Category:      df.category,
			Product:       df.product,
			Hosts:         len(df.hostSet),
			Confidence:    df.confidence,
			EvidenceTypes: evTypes,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Hosts != rows[j].Hosts {
			return rows[i].Hosts > rows[j].Hosts
		}
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].Product < rows[j].Product
	})
	return rows
}

// ---------------------------------------------------------------------------
// MS-SQL Server detector (nadda.py detect_mssql ~2490–2523)
// ---------------------------------------------------------------------------

// detectMssql fills Report.Mssql.
// Ported from nadda.py detect_mssql ~2490–2523.
func detectMssql(fs []nessus.Finding, hosts map[string]*hostInfo) []MssqlRow {
	// key: (ip, port)
	type mssqlKey struct{ ip, port string }
	type mssqlFinding struct {
		ip       string
		port     string
		fqdn     string
		instance string
		service  string
		version  string
		domains  map[string]bool
	}

	findingMap := make(map[mssqlKey]*mssqlFinding)

	for _, f := range fs {
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" {
			continue
		}
		nameLower := strings.ToLower(strings.TrimSpace(f.Name))
		if !strings.Contains(nameLower, "microsoft sql server") && !strings.Contains(nameLower, "mssql") {
			continue
		}

		port := strings.TrimSpace(f.Port)
		if port == "" {
			port = "0"
		}
		key := mssqlKey{ip: ip, port: port}
		mf := findingMap[key]
		if mf == nil {
			h := hosts[ip]
			mf = &mssqlFinding{
				ip:      ip,
				port:    port,
				fqdn:    bestFQDN(h),
				domains: make(map[string]bool),
			}
			findingMap[key] = mf
		}

		// Seed domains from the host's known domains.
		h := hosts[ip]
		if h != nil {
			for _, d := range h.domains {
				mf.domains[d] = true
			}
		}

		output := f.PluginOutput
		values := adparse.ParseKeyValues(output)

		if vals := values["instancename"]; len(vals) > 0 && mf.instance == "" {
			mf.instance = vals[0]
		}
		if vals := values["service"]; len(vals) > 0 {
			mf.service = vals[0]
			// If no instance yet and service is hyphenated, derive instance from suffix.
			// Ported from nadda.py ~2512–2515.
			if mf.instance == "" && strings.Contains(mf.service, "-") {
				parts := strings.SplitN(mf.service, "-", 2)
				mf.instance = parts[1]
			}
		}
		if vals := values["version"]; len(vals) > 0 {
			// Update version if this is a listener/udp-query plugin OR we have no version yet.
			// Ported from nadda.py ~2516–2517.
			if strings.Contains(nameLower, "listener detection") || strings.Contains(nameLower, "udp query") || mf.version == "" {
				mf.version = vals[0]
			}
		}
		// DNS computer name → update FQDN on host and finding.
		for _, fqdnVal := range values["dns computer name"] {
			addFQDN(h, fqdnVal, ip, "MSSQL NTLMSSP", nil)
			if h != nil {
				mf.fqdn = bestFQDN(h)
			}
		}
		// DNS domain name → add domain.
		for _, domain := range values["dns domain name"] {
			norm := adparse.NormalizeDomain(domain)
			if norm != "" {
				mf.domains[norm] = true
			}
		}
	}

	// Build sorted MssqlRow slice — domain-grouped then by ipsort.
	rows := make([]MssqlRow, 0, len(findingMap))
	for _, mf := range findingMap {
		h := hosts[mf.ip]
		domain := bestDomain(h)
		// Build sorted domains slice.
		domainSlice := make([]string, 0, len(mf.domains))
		for d := range mf.domains {
			domainSlice = append(domainSlice, d)
		}
		sort.Strings(domainSlice)
		rows = append(rows, MssqlRow{
			Domain:   domain,
			IP:       mf.ip,
			Port:     mf.port,
			FQDN:     mf.fqdn,
			Instance: mf.instance,
			Version:  mf.version,
			Domains:  domainSlice,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Domain != rows[j].Domain {
			return rows[i].Domain < rows[j].Domain
		}
		return ipsort.Key(rows[i].IP) < ipsort.Key(rows[j].IP)
	})
	return rows
}

// ---------------------------------------------------------------------------
// ADCS, SCCM, ADFS, Exchange, Services detectors (nadda.py ~2526–2793)
// ---------------------------------------------------------------------------

// adcsIssuerDenylist rejects well-known vendor/public CA issuers from being
// classified as internal ADCS Certificate Authorities. Ported verbatim from
// nadda.py ADCS_ISSUER_DENYLIST ~63-66.
var adcsIssuerDenylist = regexp.MustCompile(
	`(?i)(vmware|vsphere|fortinet|cisco|tp-link|hewlett|hpe|symantec|digicert|let'?s encrypt|default issuer)`,
)

// adcsCaNameRe checks if an issuer CN contains "CA" as a standalone token.
var adcsCaNameRe = regexp.MustCompile(`(?i)(^|[-_\s])(ca|certificate authority)([-_\s]|$)`)

// adcsEndpointRe matches ADCS enrollment endpoint URL patterns (nadda.py ~2551-2555).
var adcsEndpointRe = regexp.MustCompile(
	`(?i)(/certsrv\b|/certenroll\b|certfnsh\.asp|certnew\.cer|certcarc\.asp|` +
		`active directory certificate services|certificate services web enrollment|certificate enrollment web service)`,
)

// sccmMgmtPointRe matches SCCM management point key-value lines.
var sccmMgmtPointRe = regexp.MustCompile(`(?i)^\s*(Site code|Management point name|Management point version)\s*:\s*(.*?)\s*$`)

// isAdcsIssuer checks if an issuer CN + domain-component data represent an internal ADCS CA.
// Ported from nadda.py is_adcs_issuer ~2526-2534.
func isAdcsIssuer(issuer string, cn adparse.CertNames) bool {
	if issuer == "" {
		return false
	}
	// Build combined issuer text for denylist check (mirrors nadda.py all_issuer_text).
	allIssuerText := strings.Join(append(append(cn.IssuerCommonName, cn.IssuerDomainComponent...), cn.IssuerOrg...), " ")
	if adcsIssuerDenylist.MatchString(allIssuerText) {
		return false
	}
	// Issuer CN must contain "ca" or "certificate authority" with word boundaries.
	if !adcsCaNameRe.MatchString(issuer) {
		return false
	}
	// Must have ≥2 domain components.
	// First try explicit DC= label fields, then fall back to ParseDNDomains on org fields.
	if len(cn.IssuerDomainComponent) >= 2 {
		return true
	}
	// Fall back: check if org fields contain dc= chains with ≥2 components.
	for _, org := range cn.IssuerOrg {
		labels := adparse.ParseDNDomains(org)
		for _, d := range labels {
			parts := strings.Split(d, ".")
			if len(parts) >= 2 {
				return true
			}
		}
	}
	return false
}

// detectAdcs fills Report.AdcsCA and Report.AdcsEndpoints.
// Ported from nadda.py detect_adcs ~2537-2592.
func detectAdcs(fs []nessus.Finding, hosts map[string]*hostInfo) ([]AdcsCARow, []AdcsEndpointRow) {
	type caKey struct{ ip, port, issuerLower string }
	type endpointKey struct{ ip, port, indicatorLower string }
	caMap := make(map[caKey]*AdcsCARow)
	endpointMap := make(map[endpointKey]*AdcsEndpointRow)

	for _, f := range fs {
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" {
			continue
		}
		nameLower := strings.ToLower(strings.TrimSpace(f.Name))
		port := strings.TrimSpace(f.Port)
		if port == "" {
			port = "0"
		}
		h := hosts[ip]

		// Endpoint detection (nadda.py ~2548-2563): any finding where name != "ssl certificate information"
		// but combined blob contains an ADCS enrollment URL/keyword.
		if nameLower != "ssl certificate information" {
			m := adcsEndpointRe.FindStringSubmatch(f.Name + " " + f.PluginOutput)
			if m != nil {
				indicator := m[1]
				key := endpointKey{ip: ip, port: port, indicatorLower: strings.ToLower(indicator)}
				if endpointMap[key] == nil {
					endpointMap[key] = &AdcsEndpointRow{
						Domain:    bestDomain(h),
						IP:        ip,
						Ports:     port,
						FQDN:      bestFQDN(h),
						Indicator: indicator,
					}
				}
			}
		}

		// CA detection (nadda.py ~2565-2592): only "ssl certificate information" plugin.
		if nameLower != "ssl certificate information" {
			continue
		}
		cn := adparse.ParseCertNamesExt(f.PluginOutput)
		var subject, issuer string
		if len(cn.SubjectCommonName) > 0 {
			subject = cn.SubjectCommonName[0]
		}
		if len(cn.IssuerCommonName) > 0 {
			issuer = cn.IssuerCommonName[0]
		}
		// Reject localhost/local subjects (nadda.py ~2570-2571).
		subjectLower := strings.ToLower(subject)
		if subjectLower == "localhost" || subjectLower == "local" {
			continue
		}
		if !isAdcsIssuer(issuer, cn) {
			continue
		}
		// Infer domain from issuer DC= components (nadda.py ~2574-2579).
		var inferredDomain string
		if len(cn.IssuerDomainComponent) > 0 {
			inferredDomain = adparse.DomainFromComponents(cn.IssuerDomainComponent)
		}
		if inferredDomain == "" {
			// Fall back: try org fields via ParseDNDomains.
			for _, org := range cn.IssuerOrg {
				ds := adparse.ParseDNDomains(org)
				if len(ds) > 0 {
					inferredDomain = ds[0]
					break
				}
			}
		}
		// Domain mismatch guard (nadda.py ~2576-2577): skip if host has known domains
		// but inferred domain doesn't match and subject domain doesn't match.
		if inferredDomain != "" && h != nil && len(h.domains) > 0 {
			subjectDomain := adparse.DomainFromFqdn(subject)
			inferredInHost := false
			for _, d := range h.domains {
				if d == inferredDomain {
					inferredInHost = true
					break
				}
			}
			if !inferredInHost && subjectDomain != inferredDomain {
				continue
			}
		}
		// Determine domain for row.
		domain := inferredDomain
		if domain == "" {
			domain = bestDomain(h)
		}
		key := caKey{ip: ip, port: port, issuerLower: strings.ToLower(issuer)}
		if caMap[key] == nil {
			caMap[key] = &AdcsCARow{
				Domain:  domain,
				IP:      ip,
				Ports:   port,
				FQDN:    bestFQDN(h),
				Issuer:  issuer,
				Subject: subject,
			}
		}
	}

	// Build sorted slices.
	caRows := make([]AdcsCARow, 0, len(caMap))
	for _, row := range caMap {
		caRows = append(caRows, *row)
	}
	sort.Slice(caRows, func(i, j int) bool {
		if caRows[i].Domain != caRows[j].Domain {
			return caRows[i].Domain < caRows[j].Domain
		}
		return ipsort.Key(caRows[i].IP) < ipsort.Key(caRows[j].IP)
	})

	endpointRows := make([]AdcsEndpointRow, 0, len(endpointMap))
	for _, row := range endpointMap {
		endpointRows = append(endpointRows, *row)
	}
	sort.Slice(endpointRows, func(i, j int) bool {
		if endpointRows[i].Domain != endpointRows[j].Domain {
			return endpointRows[i].Domain < endpointRows[j].Domain
		}
		return ipsort.Key(endpointRows[i].IP) < ipsort.Key(endpointRows[j].IP)
	})

	return caRows, endpointRows
}

// detectSccm fills Report.Sccm.
// Ported from nadda.py detect_sccm ~2612-2663.
func detectSccm(fs []nessus.Finding, hosts map[string]*hostInfo) []SccmRow {
	type sccmKey struct{ ip, port, role, fqdnLower string }
	sccmMap := make(map[sccmKey]*SccmRow)

	for _, f := range fs {
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" {
			continue
		}
		port := strings.TrimSpace(f.Port)
		if port == "" {
			port = "0"
		}
		h := hosts[ip]
		combined := f.Name + " " + f.PluginOutput

		if !adparse.ContainsAnyBounded(combined, "sccm", "system center configuration manager") {
			continue
		}

		// Management point role (nadda.py ~2626-2649).
		if adparse.ContainsAnyBounded(combined, "management point") {
			// Parse management point fields from plugin output.
			var points []struct{ site, fqdn, version string }
			var cur struct{ site, fqdn, version string }
			for _, line := range strings.Split(f.PluginOutput, "\n") {
				m := sccmMgmtPointRe.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				key := strings.ToLower(m[1])
				val := strings.TrimSpace(m[2])
				switch {
				case strings.Contains(key, "site code"):
					cur.site = val
				case strings.Contains(key, "management point name"):
					cur.fqdn = val
				case strings.Contains(key, "management point version"):
					cur.version = val
					points = append(points, cur)
					cur = struct{ site, fqdn, version string }{}
				}
			}
			if cur.site != "" || cur.fqdn != "" {
				points = append(points, cur)
			}

			if len(points) > 0 {
				for _, pt := range points {
					fqdn := pt.fqdn
					if fqdn == "" {
						fqdn = bestFQDN(h)
					}
					key := sccmKey{ip: ip, port: port, role: "management_point", fqdnLower: strings.ToLower(fqdn)}
					if sccmMap[key] == nil {
						sccmMap[key] = &SccmRow{
							Domain:  bestDomain(h),
							Role:    "management_point",
							IP:      ip,
							Port:    port,
							FQDN:    fqdn,
							Site:    pt.site,
							Version: pt.version,
						}
					}
				}
			} else {
				fqdn := bestFQDN(h)
				key := sccmKey{ip: ip, port: port, role: "management_point", fqdnLower: strings.ToLower(fqdn)}
				if sccmMap[key] == nil {
					sccmMap[key] = &SccmRow{
						Domain: bestDomain(h),
						Role:   "management_point",
						IP:     ip,
						Port:   port,
						FQDN:   fqdn,
					}
				}
			}
		}

		// Remote control agent role (nadda.py ~2651-2656).
		if adparse.ContainsAnyBounded(combined, "remote control agent") {
			fqdn := bestFQDN(h)
			key := sccmKey{ip: ip, port: port, role: "remote_control_agent", fqdnLower: strings.ToLower(fqdn)}
			if sccmMap[key] == nil {
				sccmMap[key] = &SccmRow{
					Domain: bestDomain(h),
					Role:   "remote_control_agent",
					IP:     ip,
					Port:   port,
					FQDN:   fqdn,
				}
			}
		}

		// Configuration manager CPE role (nadda.py ~2658-2663).
		if adparse.ContainsAnyBounded(combined, "system_center_configuration_manager") {
			fqdn := bestFQDN(h)
			key := sccmKey{ip: ip, port: port, role: "configuration_manager_cpe", fqdnLower: strings.ToLower(fqdn)}
			if sccmMap[key] == nil {
				sccmMap[key] = &SccmRow{
					Domain: bestDomain(h),
					Role:   "configuration_manager_cpe",
					IP:     ip,
					Port:   port,
					FQDN:   fqdn,
				}
			}
		}
	}

	rows := make([]SccmRow, 0, len(sccmMap))
	for _, row := range sccmMap {
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Domain != rows[j].Domain {
			return rows[i].Domain < rows[j].Domain
		}
		if rows[i].IP != rows[j].IP {
			return ipsort.Key(rows[i].IP) < ipsort.Key(rows[j].IP)
		}
		return rows[i].Role < rows[j].Role
	})
	return rows
}

// detectAdfs fills Report.Adfs.
// Ported from nadda.py ~2725-2726.
func detectAdfs(fs []nessus.Finding, hosts map[string]*hostInfo) []AdfsRow {
	type adfsAgg struct {
		services map[string]bool
		ports    map[string]bool
	}
	adfsByIP := make(map[string]*adfsAgg)

	for _, f := range fs {
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" {
			continue
		}
		combined := f.Name + " " + f.PluginOutput
		if !adparse.ContainsAnyBounded(combined, "adfs", "active directory federation services", "federation service") {
			continue
		}
		agg := adfsByIP[ip]
		if agg == nil {
			agg = &adfsAgg{services: make(map[string]bool), ports: make(map[string]bool)}
			adfsByIP[ip] = agg
		}
		svc := strings.TrimSpace(f.Name)
		if svc != "" {
			agg.services[svc] = true
		}
		port := strings.TrimSpace(f.Port)
		if port != "" && port != "0" {
			agg.ports[port] = true
		}
	}

	ips := make([]string, 0, len(adfsByIP))
	for ip := range adfsByIP {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return ipsort.Key(ips[i]) < ipsort.Key(ips[j])
	})

	rows := make([]AdfsRow, 0, len(ips))
	for _, ip := range ips {
		agg := adfsByIP[ip]
		h := hosts[ip]
		svcs := make([]string, 0, len(agg.services))
		for s := range agg.services {
			svcs = append(svcs, s)
		}
		sort.Strings(svcs)
		ports := make([]string, 0, len(agg.ports))
		for p := range agg.ports {
			ports = append(ports, p)
		}
		sort.Strings(ports)
		rows = append(rows, AdfsRow{
			Domain:   bestDomain(h),
			IP:       ip,
			FQDN:     bestFQDN(h),
			Services: strings.Join(svcs, ", "),
			Ports:    strings.Join(ports, ", "),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Domain != rows[j].Domain {
			return rows[i].Domain < rows[j].Domain
		}
		return ipsort.Key(rows[i].IP) < ipsort.Key(rows[j].IP)
	})
	return rows
}

// detectExchange fills Report.Exchange.
// Ported from nadda.py ~2731-2734.
func detectExchange(fs []nessus.Finding, hosts map[string]*hostInfo) []ExchangeRow {
	type exchAgg struct {
		services map[string]bool
		ports    map[string]bool
	}
	exchByIP := make(map[string]*exchAgg)

	for _, f := range fs {
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" {
			continue
		}
		combined := f.Name + " " + f.PluginOutput

		nameSignal := adparse.ContainsAnyBounded(f.Name, "microsoft exchange", "exchange server", "outlook web app", "autodiscover")
		outputSignal := adparse.ContainsAnyBounded(combined, "microsoft exchange", "cpe:/a:microsoft:exchange")
		if !nameSignal && !outputSignal {
			continue
		}

		agg := exchByIP[ip]
		if agg == nil {
			agg = &exchAgg{services: make(map[string]bool), ports: make(map[string]bool)}
			exchByIP[ip] = agg
		}
		svc := strings.TrimSpace(f.Name)
		if svc != "" {
			agg.services[svc] = true
		}
		port := strings.TrimSpace(f.Port)
		if port != "" && port != "0" {
			agg.ports[port] = true
		}
	}

	ips := make([]string, 0, len(exchByIP))
	for ip := range exchByIP {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return ipsort.Key(ips[i]) < ipsort.Key(ips[j])
	})

	rows := make([]ExchangeRow, 0, len(ips))
	for _, ip := range ips {
		agg := exchByIP[ip]
		h := hosts[ip]
		svcs := make([]string, 0, len(agg.services))
		for s := range agg.services {
			svcs = append(svcs, s)
		}
		sort.Strings(svcs)
		ports := make([]string, 0, len(agg.ports))
		for p := range agg.ports {
			ports = append(ports, p)
		}
		sort.Strings(ports)
		rows = append(rows, ExchangeRow{
			Domain:   bestDomain(h),
			IP:       ip,
			FQDN:     bestFQDN(h),
			Services: strings.Join(svcs, ", "),
			Ports:    strings.Join(ports, ", "),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Domain != rows[j].Domain {
			return rows[i].Domain < rows[j].Domain
		}
		return ipsort.Key(rows[i].IP) < ipsort.Key(rows[j].IP)
	})
	return rows
}

// filterEmpty returns non-empty strings from the input slice.
func filterEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// detectServices fills Report.Services with infrastructure service categories.
// Ported from nadda.py detect_ad_services ~2699-2793.
func detectServices(fs []nessus.Finding, hosts map[string]*hostInfo) []ServiceRow {
	// serviceAgg accumulates hosts and detail for a single service category.
	type serviceAgg struct {
		hostSet map[string]bool
		details map[string]bool
	}
	svcMap := make(map[string]*serviceAgg)

	addSvc := func(category, ip, detail string) {
		agg := svcMap[category]
		if agg == nil {
			agg = &serviceAgg{hostSet: make(map[string]bool), details: make(map[string]bool)}
			svcMap[category] = agg
		}
		if ip != "" {
			agg.hostSet[ip] = true
		}
		if detail != "" {
			agg.details[detail] = true
		}
	}

	for _, f := range fs {
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" {
			continue
		}
		nameLower := strings.ToLower(strings.TrimSpace(f.Name))
		port := strings.TrimSpace(f.Port)
		combined := f.Name + " " + f.Synopsis + " " + f.Description + " " + f.PluginOutput
		combinedLower := strings.ToLower(combined)

		// Global Catalog (nadda.py ~2711-2713).
		if (port == "3268" || port == "3269") &&
			(adparse.ContainsAnyBounded(combined, "ldap") || nameLower == "ssl certificate information") {
			detail := "Global Catalog"
			if port == "3269" {
				detail = "Global Catalog over SSL"
			}
			addSvc("Global Catalog", ip, detail)
		}

		// LDAPS Certificate (nadda.py ~2715-2723).
		if port == "636" || port == "3269" {
			if nameLower == "ssl certificate information" {
				cn := adparse.ParseCertNamesExt(f.PluginOutput)
				subject := ""
				if len(cn.SubjectCommonName) > 0 {
					subject = cn.SubjectCommonName[0]
				}
				issuer := ""
				if len(cn.IssuerCommonName) > 0 {
					issuer = cn.IssuerCommonName[0]
				}
				detail := strings.Join(filterEmpty(subject, issuer), " / ")
				if detail == "" {
					detail = "LDAPS certificate observed"
				}
				addSvc("LDAPS Certificate", ip, detail)
			} else if strings.Contains(nameLower, "ssl certificate") {
				addSvc("LDAPS Certificate", ip, f.Name)
			}
		}

		// ADFS (nadda.py ~2725-2726) — also has dedicated detector.
		if adparse.ContainsAnyBounded(combined, "adfs", "active directory federation services", "federation service") {
			addSvc("ADFS", ip, f.Name)
		}

		// ADWS (nadda.py ~2728-2729).
		if port == "9389" || adparse.ContainsAnyBounded(combined, "active directory web services", "adws") {
			addSvc("ADWS", ip, f.Name)
		}

		// Exchange (nadda.py ~2731-2734) — also has dedicated detector.
		nameSignal := adparse.ContainsAnyBounded(f.Name, "microsoft exchange", "exchange server", "outlook web app", "autodiscover")
		outputSignal := adparse.ContainsAnyBounded(combined, "microsoft exchange", "cpe:/a:microsoft:exchange")
		if nameSignal || outputSignal {
			addSvc("Exchange", ip, f.Name)
		}

		// Mail (nadda.py ~2736-2737).
		mailPorts := map[string]bool{"25": true, "110": true, "143": true, "465": true, "587": true, "993": true, "995": true}
		if mailPorts[port] || adparse.ContainsAnyBounded(combined, "smtp server", "imap service", "pop server", "pop3", "starttls command support") {
			addSvc("Mail", ip, f.Name)
		}

		// WSUS (nadda.py ~2739-2740).
		if port == "8530" || port == "8531" || adparse.ContainsAnyBounded(combined, "wsus", "windows server update services") {
			addSvc("WSUS", ip, f.Name)
		}

		// RADIUS/NPS (nadda.py ~2742-2743).
		if port == "1812" || port == "1813" || adparse.ContainsAnyBounded(combined, "radius server", "network policy server", "nps") {
			addSvc("RADIUS/NPS", ip, f.Name)
		}

		// MSMQ (nadda.py ~2745-2747).
		msmqPorts := map[string]bool{"1801": true, "2103": true, "2105": true, "2107": true}
		if msmqPorts[port] || adparse.ContainsAnyBounded(combined, "microsoft message queuing", "message queuing", "msmq", "queuejumper") {
			posture := "Detected"
			if strings.Contains(combinedLower, "queuejumper") {
				posture = "RCE exposure"
			}
			addSvc("MSMQ", ip, posture)
		}

		// Deployment (nadda.py ~2749-2750).
		deployPorts := map[string]bool{"67": true, "69": true, "4011": true}
		if deployPorts[port] || adparse.ContainsAnyBounded(combined, "dhcp server", "tftp daemon", "windows deployment", "pxe", "bootp", "wds") {
			addSvc("Deployment", ip, f.Name)
		}

		// Virtualization (nadda.py ~2752-2753).
		virtPorts := map[string]bool{"902": true, "903": true, "912": true, "9084": true, "9087": true}
		if virtPorts[port] || adparse.ContainsAnyBounded(combined, "vmware esx", "vmware esxi", "vmware vsphere", "vcenter", "hyper-v", "proxmox", "xenserver") {
			addSvc("Virtualization", ip, f.Name)
		}

		// SNMP (nadda.py ~2755-2756).
		if port == "161" || adparse.ContainsAnyBounded(combined, "snmp server", "snmp agent", "snmp protocol", "snmp community") {
			addSvc("SNMP", ip, f.Name)
		}

		// OOB Management (nadda.py ~2758-2759).
		oobPorts := map[string]bool{"623": true, "1311": true}
		if oobPorts[port] || adparse.ContainsAnyBounded(combined, "idrac", "ipmi", "openmanage", "open manage", "integrated remote access controller", "baseboard management", "rmcp") {
			addSvc("OOB Management", ip, f.Name)
		}

		// DFS/FRS (nadda.py ~2761-2764).
		if adparse.ContainsAnyBounded(combined, "dfsr", "distributed file system", "file replication service", "dfs", "frs") {
			addSvc("DFS/FRS", ip, f.Name)
		}

		// WinRM (nadda.py ~2766-2768).
		if adparse.ContainsAnyBounded(combined, "winrm", "windows remote management", "ws-management") {
			posture := "Detected"
			if port == "5985" {
				posture = "HTTP"
			} else if port == "5986" {
				posture = "HTTPS"
			}
			addSvc("WinRM", ip, posture)
		}

		// RDP/NLA (nadda.py ~2770-2779).
		rdpSignal := strings.Contains(nameLower, "remote desktop protocol") || strings.Contains(nameLower, "terminal services")
		nlaSignal := strings.Contains(nameLower, "doesn't use network level authentication") ||
			adparse.ContainsAnyBounded(combined, "non-nla")
		if rdpSignal || nlaSignal {
			posture := "Detected"
			if strings.Contains(nameLower, "doesn't use network level authentication") || adparse.ContainsAnyBounded(combined, "non-nla") {
				posture = "NLA not required"
			} else if adparse.ContainsAnyBounded(combined, "network level authentication") && !strings.Contains(combinedLower, "not") {
				posture = "NLA indicated"
			}
			addSvc("RDP/NLA", ip, posture)
		}

		// NTP (nadda.py ~2781-2782).
		if strings.Contains(nameLower, "ntp") || strings.Contains(nameLower, "network time protocol") {
			addSvc("NTP", ip, f.Name)
		}

		// RPC/DCOM (nadda.py ~2784-2786).
		rpcSignal := adparse.ContainsAnyBounded(f.Name, "dce/rpc", "dcerpc", "dcom", "endpoint mapper", "epmapper", "rpc endpoint", "rpc service")
		if rpcSignal || ((port == "135" || port == "593") &&
			(strings.Contains(nameLower, "service detection") || strings.Contains(nameLower, "dce services enumeration"))) {
			addSvc("RPC/DCOM", ip, f.Name)
		}

		// LDAP Signing / Channel Binding (nadda.py ~2788-2793).
		if adparse.ContainsAnyBounded(combined, "ldap signing", "ldap server signing", "channel binding", "ldap channel binding") {
			posture := "Reported"
			if adparse.ContainsAnyBounded(combined, "not required", "not enforced", "disabled", "vulnerable") {
				posture = "Weak or not enforced"
			}
			addSvc("LDAP Signing/Channel Binding", ip, posture)
		}
	}

	// Build sorted ServiceRow slice.
	categories := make([]string, 0, len(svcMap))
	for cat := range svcMap {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	rows := make([]ServiceRow, 0, len(categories))
	for _, cat := range categories {
		agg := svcMap[cat]
		hostList := make([]string, 0, len(agg.hostSet))
		for h := range agg.hostSet {
			hostList = append(hostList, h)
		}
		sort.Slice(hostList, func(i, j int) bool {
			return ipsort.Key(hostList[i]) < ipsort.Key(hostList[j])
		})
		details := make([]string, 0, len(agg.details))
		for d := range agg.details {
			details = append(details, d)
		}
		sort.Strings(details)
		rows = append(rows, ServiceRow{
			Service: cat,
			Hosts:   hostList,
			Detail:  strings.Join(details, "; "),
		})
	}
	return rows
}

// ---------------------------------------------------------------------------
// Outdated Windows detector (nadda.py outdated_windows_hosts ~1703–1728)
// ---------------------------------------------------------------------------

// windowsVersionHints is the port of nadda.py WINDOWS_VERSION_HINTS ~1677–1689.
// Each entry: (compiled regex, reason string).
// First match wins per os_name (ported from outdated_windows_reason ~1703).
var windowsVersionHints = []struct {
	pattern *regexp.Regexp
	reason  string
}{
	{regexp.MustCompile(`(?i)windows product version 5\.1\b`), "Windows XP"},
	{regexp.MustCompile(`(?i)windows product version 5\.2\b`), "Windows Server 2003 / XP x64"},
	{regexp.MustCompile(`(?i)windows product version 6\.0\b`), "Windows Vista / Server 2008"},
	{regexp.MustCompile(`(?i)windows product version 6\.1\b`), "Windows 7 / Server 2008 R2"},
	{regexp.MustCompile(`(?i)windows product version 6\.2\b`), "Windows 8 / Server 2012"},
	{regexp.MustCompile(`(?i)windows product version 6\.3\b`), "Windows 8.1 / Server 2012 R2"},
	{regexp.MustCompile(`(?i)windows\s+(?:xp|vista|7|8|8\.1)\b`), "Legacy Windows workstation"},
	{regexp.MustCompile(`(?i)windows\s+server\s+2003\b`), "Windows Server 2003"},
	{regexp.MustCompile(`(?i)windows\s+server\s+2008(?:\s+r2)?\b`), "Windows Server 2008/R2"},
	{regexp.MustCompile(`(?i)windows\s+server\s+2012(?:\s+r2)?\b`), "Windows Server 2012/R2"},
	// nadda.py's WINDOWS_VERSION_HINTS lists "windows 10", but Windows 10 is a
	// supported OS — flagging it outdated is a false positive, so it is omitted
	// here per the SP4 spec's unsupported-OS set (Server 2012/2008/2003, XP–8.1).
}

// outdatedWindowsReason returns the reason string for an outdated/EOL Windows OS name,
// or "" if not matched. Ported from nadda.py outdated_windows_reason ~1703.
func outdatedWindowsReason(osName string) string {
	for _, hint := range windowsVersionHints {
		if hint.pattern.MatchString(osName) {
			return hint.reason
		}
	}
	return ""
}

// detectOutdatedWindows fills Report.OutdatedWindows.
// Per-host: OS from first non-empty DetectedOS across findings, else osdetect.FromPluginOutput.
// If OS is Windows family AND outdatedWindowsReason returns non-empty → emit row.
// Ported from nadda.py outdated_windows_hosts ~1721–1728.
func detectOutdatedWindows(fs []nessus.Finding, hosts map[string]*hostInfo) []OutdatedWinRow {
	// Collect per-host: first DetectedOS + all plugin outputs for fallback.
	type hostOSData struct {
		detectedOS    string
		pluginOutputs []string
	}
	// Use a map keyed by IP; preserve insertion order for determinism via ips slice.
	hostOSMap := make(map[string]*hostOSData)
	var ipOrder []string

	for _, f := range fs {
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" {
			continue
		}
		d := hostOSMap[ip]
		if d == nil {
			d = &hostOSData{}
			hostOSMap[ip] = d
			ipOrder = append(ipOrder, ip)
		}
		// First non-empty DetectedOS wins.
		if d.detectedOS == "" && strings.TrimSpace(f.DetectedOS) != "" {
			d.detectedOS = strings.TrimSpace(f.DetectedOS)
		}
		if f.PluginOutput != "" {
			d.pluginOutputs = append(d.pluginOutputs, f.PluginOutput)
		}
	}

	var rows []OutdatedWinRow
	seen := make(map[string]bool) // dedup by IP

	for _, ip := range ipOrder {
		if seen[ip] {
			continue
		}
		d := hostOSMap[ip]

		// Determine OS string: DetectedOS first, then osdetect from plugin outputs.
		osName := d.detectedOS
		if osName == "" {
			for _, out := range d.pluginOutputs {
				detected := osdetect.FromPluginOutput(out)
				if detected != "" {
					osName = detected
					break
				}
			}
		}
		if osName == "" {
			continue
		}

		// Must be a Windows family.
		class := osclass.Classify(osName)
		if !strings.HasPrefix(class, "Windows") {
			continue
		}

		reason := outdatedWindowsReason(osName)
		if reason == "" {
			continue
		}

		seen[ip] = true
		h := hosts[ip]
		rows = append(rows, OutdatedWinRow{
			Domain: bestDomain(h),
			IP:     ip,
			FQDN:   bestFQDN(h),
			OS:     osName,
			Reason: reason,
		})
	}

	// Sort: domain-grouped then by ipsort.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Domain != rows[j].Domain {
			return rows[i].Domain < rows[j].Domain
		}
		return ipsort.Key(rows[i].IP) < ipsort.Key(rows[j].IP)
	})
	return rows
}

// ---------------------------------------------------------------------------
// Analyze — main entry point
// ---------------------------------------------------------------------------

// Analyze runs one aggregation pass over findings, identifies per-host identity
// (FQDNs, domains, NetBIOS, service capabilities), aggregates domains with
// confidence labels, identifies Domain Controllers, and returns a Report with
// the four discovery sections populated (Domains, Netbios, DomainControllers,
// DNSServers). All other Report slices are nil (populated by later SP4 tasks).
func Analyze(fs []nessus.Finding) Report {
	hosts := make(map[string]*hostInfo)
	domainAggs := make(map[string]*domainAgg)
	dnsServers := make(map[string]string) // ip → port
	dcs := make(map[string]*dcEntry)

	// -----------------------------------------------------------------------
	// Pass 1: process each finding — build hostInfo + domain aggregation.
	// Ported from nadda.py detect_host_identity ~1800–1875.
	// -----------------------------------------------------------------------
	for _, f := range fs {
		ip := strings.TrimSpace(f.HostIP)
		if ip == "" {
			continue
		}

		h := hosts[ip]
		if h == nil {
			h = &hostInfo{
				ip:         ip,
				caps:       make(map[string]bool),
				fqdnSet:    make(map[string]bool),
				domainSet:  make(map[string]bool),
				netbiosSet: make(map[string]bool),
			}
			hosts[ip] = h
		}

		output := f.PluginOutput
		outputLower := strings.ToLower(output)
		nameLower := strings.ToLower(strings.TrimSpace(f.Name))

		// FQDN from "resolves as" (nadda.py ~1822).
		if strings.Contains(outputLower, "resolves as") {
			fqdn := adparse.ParseFqdnResolution(output)
			if fqdn != "" {
				addFQDN(h, fqdn, ip, "FQDN resolution", domainAggs)
			}
		}

		// Key-values: DNS Domain Name, DNS Tree Name, Realm, NetBIOS Domain Name,
		// DNS Computer Name (nadda.py ~1827–1838).
		if containsAnyStr(outputLower,
			"dns computer name", "dns domain name", "dns tree name",
			"realm", "netbios domain name") {
			kv := adparse.ParseKeyValues(output)
			for _, fqdn := range kv["dns computer name"] {
				addFQDN(h, fqdn, ip, "DNS computer name", domainAggs)
			}
			for _, d := range kv["dns domain name"] {
				addDomainCandidate(h, ip, d, "DNS domain name", domainAggs)
			}
			for _, d := range kv["dns tree name"] {
				addDomainCandidate(h, ip, d, "DNS tree name", domainAggs)
			}
			for _, r := range kv["realm"] {
				addDomainCandidate(h, ip, r, "Kerberos realm", domainAggs)
			}
			for _, n := range kv["netbios domain name"] {
				addNetbiosCandidate(h, n)
			}
		}

		// LDAP DN (nadda.py ~1840–1842).
		if strings.Contains(outputLower, "dc=") {
			for _, d := range adparse.ParseDNDomains(output) {
				addDomainCandidate(h, ip, d, "LDAP DN", domainAggs)
			}
		}

		// Remote SMB domain name → NetBIOS (nadda.py ~1844–1847).
		if strings.Contains(outputLower, "remote smb domain name") {
			m := smbDomainRe.FindStringSubmatch(output)
			if m != nil {
				addNetbiosCandidate(h, m[1])
			}
		}

		// NetBIOS assignments (nadda.py ~1849–1860):
		// "Domain Controllers" role → explicit DC.
		if strings.Contains(output, " = ") &&
			containsAnyStr(outputLower, "computer name", "workgroup / domain name", "domain controllers") {
			for _, pair := range adparse.ParseNetbiosAssignments(output) {
				label := strings.ToLower(pair[1])
				if strings.Contains(label, "workgroup / domain name") {
					addNetbiosCandidate(h, pair[0])
				}
				if strings.Contains(label, "domain controllers") {
					addNetbiosCandidate(h, pair[0])
					// Explicit DC identification.
					if _, ok := dcs[ip]; !ok {
						dcs[ip] = &dcEntry{
							confidence: "High",
							evidence:   "NetBIOS role is Domain Controllers",
						}
					}
				}
			}
		}

		// Capabilities (nadda.py ~1862–1874).
		switch nameLower {
		case "dns server detection":
			h.caps["dns"] = true
			port := strings.TrimSpace(f.Port)
			if port == "" {
				port = "53"
			}
			dnsServers[ip] = port
		case "ldap server detection":
			h.caps["ldap"] = true
		case "kerberos information disclosure":
			h.caps["kerberos"] = true
		}
		if f.Port == "445" || strings.Contains(nameLower, "microsoft windows smb service detection") {
			h.caps["smb"] = true
		}
	}

	// -----------------------------------------------------------------------
	// Pass 2: finalize Domain Controllers — inferred (nadda.py ~2803–2812).
	// -----------------------------------------------------------------------
	for ip, h := range hosts {
		if h.caps["kerberos"] && h.caps["ldap"] && (h.caps["dns"] || h.caps["smb"]) {
			if _, ok := dcs[ip]; !ok {
				dcs[ip] = &dcEntry{
					confidence: "Inferred",
					evidence:   "AD core services detected",
				}
			}
		}
	}

	// -----------------------------------------------------------------------
	// Build Report discovery sections.
	// -----------------------------------------------------------------------
	smbSigningRows, smbSigningSummary := detectSMBSigning(fs, hosts)
	shareRows, shareSummary := detectShares(fs, hosts)
	guestRows := detectGuest(fs, hosts)
	smbV1Rows := detectSmbV1(fs, hosts)
	emailRows, emailSummary := detectEmails(fs)
	defensiveRows := detectDefensive(fs, hosts)
	mssqlRows := detectMssql(fs, hosts)
	outdatedWinRows := detectOutdatedWindows(fs, hosts)
	adcsCARows, adcsEndpointRows := detectAdcs(fs, hosts)
	sccmRows := detectSccm(fs, hosts)
	adfsRows := detectAdfs(fs, hosts)
	exchangeRows := detectExchange(fs, hosts)
	serviceRows := detectServices(fs, hosts)

	r := Report{
		Domains:           buildDomains(domainAggs, hosts),
		Netbios:           buildNetbios(hosts),
		DomainControllers: buildDCs(dcs, hosts),
		DNSServers:        buildDNSServers(dnsServers, hosts),

		SMBSigningSummary: smbSigningSummary,
		SMBSigning:        smbSigningRows,

		ShareSummary: shareSummary,
		Shares:       shareRows,
		Guest:        guestRows,
		SmbV1:        smbV1Rows,

		EmailSummary: emailSummary,
		Emails:       emailRows,

		Defensive:       defensiveRows,
		Mssql:           mssqlRows,
		OutdatedWindows: outdatedWinRows,

		AdcsCA:        adcsCARows,
		AdcsEndpoints: adcsEndpointRows,
		Sccm:          sccmRows,
		Adfs:          adfsRows,
		Exchange:      exchangeRows,
		Services:      serviceRows,
	}
	return r
}
