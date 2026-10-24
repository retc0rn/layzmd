// Package adparse provides pure parsing helpers for Active Directory Nessus
// plugin output. All functions are ported from nadda.py (approx lines 1015–1211).
// Stdlib only; no I/O; all regexes compiled as package-level vars.
package adparse

import (
	"regexp"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Package-level compiled regexes
// ---------------------------------------------------------------------------

// keyValueRe matches "  Key Name : value" lines.
// Group 1 = key, Group 2 = value (nadda.py parse_key_values ~1052).
var keyValueRe = regexp.MustCompile(`(?i)^\s*([A-Za-z][A-Za-z0-9 /_-]+?)\s*:\s*(.*?)\s*$`)

// multiSpaceRe collapses internal whitespace in keys.
var multiSpaceRe = regexp.MustCompile(`\s+`)

// netbiosAssignRe matches "NAME = ROLE" lines (nadda.py parse_netbios_assignments ~1064).
// The Python original requires \s{2,}= but the brief test uses single space; we accept \s+= \s+.
var netbiosAssignRe = regexp.MustCompile(`(?i)^\s*([A-Za-z0-9_. -]{1,64}?)\s+=\s+(.+?)\s*$`)

// fqdnResolutionRe matches "<ip> resolves as <fqdn>" (nadda.py ~1071).
var fqdnResolutionRe = regexp.MustCompile(`(?i)\bresolves as\s+([A-Za-z0-9_.-]+)\.?`)

// dnDomainRe matches dc=label chains (nadda.py parse_dn_domains ~1098).
var dnDomainRe = regexp.MustCompile(`(?i)(?:^|[,\s])dc=([A-Za-z0-9_-]+(?:,dc=[A-Za-z0-9_-]+)+)`)

// dcLabelRe extracts individual dc= labels from a matched chain.
var dcLabelRe = regexp.MustCompile(`(?i)dc=([A-Za-z0-9_-]+)`)

// certSubjectRe matches "Subject:" or "Subject Name:" section headers.
var certSubjectRe = regexp.MustCompile(`(?i)^Subject(?:\s+Name)?\s*:`)

// certIssuerRe matches "Issuer:" or "Issuer Name:" section headers.
var certIssuerRe = regexp.MustCompile(`(?i)^Issuer(?:\s+Name)?\s*:`)

// certFieldRe matches "Common Name: value" lines within a cert section.
var certFieldRe = regexp.MustCompile(`(?i)^Common Name\s*:\s*(.*?)\s*$`)

// certDomainComponentRe matches "Domain Component: value" lines within a cert section.
var certDomainComponentRe = regexp.MustCompile(`(?i)^Domain Component\s*:\s*(.*?)\s*$`)

// certOrgRe matches "Organization" or "Organization Unit" lines within a cert section.
var certOrgRe = regexp.MustCompile(`(?i)^Organization(?:\s+Unit)?\s*:\s*(.*?)\s*$`)

// tldLikeLabels mirrors nadda.py's TLD_LIKE_LABELS set (minus "corp" — see
// note below). When the first component equals one of these labels the
// components are reversed before joining, which handles MSSQL/LDAP component
// lists delivered in TLD-first order.
//
// nadda.py includes "corp" in this set, but the brief test
// DomainFromComponents(["corp","acme","com"]) → "corp.acme.com" requires that
// "corp" does NOT trigger reversal. The Go port therefore omits "corp" from
// the trigger set — "corp" as a leftmost label is treated as a subdomain
// prefix, not a TLD.
var tldLikeLabels = map[string]bool{
	"com": true, "net": true, "org": true, "edu": true,
	"gov": true, "mil": true, "int": true, "local": true,
	"lan": true,
}

// ---------------------------------------------------------------------------
// ContainsAnyBounded cache
// ---------------------------------------------------------------------------

// boundedCache holds compiled regexes keyed by needle string.
// nadda.py uses functools.lru_cache(maxsize=512) on bounded_term_re (~1194).
var (
	boundedCacheMu sync.Mutex
	boundedCache   = make(map[string]*regexp.Regexp, 64)
)

// boundedTermRe returns a cached *regexp.Regexp for the given needle, using
// word-boundary logic ported from nadda.py bounded_term_pattern (~1185–1191).
func boundedTermRe(needle string) *regexp.Regexp {
	boundedCacheMu.Lock()
	if re, ok := boundedCache[needle]; ok {
		boundedCacheMu.Unlock()
		return re
	}
	boundedCacheMu.Unlock()

	// Port of bounded_term_pattern:
	// 1. Escape the needle and replace escaped-space with \s+
	escaped := regexp.QuoteMeta(needle)
	escaped = strings.ReplaceAll(escaped, `\ `, `\s+`)

	// 2. If needle starts with alnum, prepend a negative lookbehind equivalent.
	//    Go's RE2 has no lookbehind, so we use a non-capturing word-boundary
	//    construct: (?:^|[^A-Za-z0-9]) then capture the needle, then strip the
	//    prefix char in the match. Simpler: we check \b only when alnum boundary
	//    applies using (?:^|[^A-Za-z0-9]) and (?:[^A-Za-z0-9]|$).
	//    We implement this as RE2-compatible alternatives.
	var pattern string
	startsAlnum := len(needle) > 0 && isAlnum(rune(needle[0]))
	endsAlnum := len(needle) > 0 && isAlnum(rune(needle[len(needle)-1]))

	prefix := ""
	suffix := ""
	if startsAlnum {
		prefix = `(?:^|[^A-Za-z0-9])`
	}
	if endsAlnum {
		suffix = `(?:[^A-Za-z0-9]|$)`
	}
	pattern = "(?i)" + prefix + escaped + suffix

	re := regexp.MustCompile(pattern)

	boundedCacheMu.Lock()
	boundedCache[needle] = re
	boundedCacheMu.Unlock()
	return re
}

func isAlnum(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

// NormalizeDomain trims whitespace, lowercases, and strips a trailing dot.
// This is the minimal normalization used by the brief's signature.
// (nadda.py normalize_domain does additional denylist filtering; that logic
// lives in the ad analyzer which calls this helper.)
func NormalizeDomain(v string) string {
	v = strings.TrimSpace(v)
	v = strings.ToLower(v)
	v = strings.TrimSuffix(v, ".")
	return v
}

// NormalizeNetbiosDomain trims whitespace and uppercases.
// (nadda.py normalize_netbios_domain ~1033.)
func NormalizeNetbiosDomain(v string) string {
	return strings.ToUpper(strings.TrimSpace(v))
}

// DomainFromFqdn returns the domain portion of an FQDN (all labels after the
// first). Returns "" if fqdn has fewer than 2 labels.
// (nadda.py domain_from_fqdn ~1042.)
func DomainFromFqdn(fqdn string) string {
	fqdn = strings.TrimSpace(fqdn)
	fqdn = strings.TrimSuffix(fqdn, ".")
	fqdn = strings.ToLower(fqdn)
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return ""
	}
	domain := strings.Join(parts[1:], ".")
	return NormalizeDomain(domain)
}

// ParseKeyValues parses "Key : Value" lines from plugin output text.
// Keys are lowercased and collapsed whitespace; values are trimmed.
// Multiple lines with the same key accumulate into the slice.
// (nadda.py parse_key_values ~1049.)
func ParseKeyValues(text string) map[string][]string {
	result := make(map[string][]string)
	for _, line := range strings.Split(text, "\n") {
		m := keyValueRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		rawKey := m[1]
		rawVal := m[2]
		key := strings.ToLower(multiSpaceRe.ReplaceAllString(strings.TrimSpace(rawKey), " "))
		val := strings.TrimSpace(rawVal)
		// clean_value: strip leading/trailing dots as well
		val = strings.Trim(val, ".")
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		result[key] = append(result[key], val)
	}
	return result
}

// ParseNetbiosAssignments parses "NAME = ROLE" lines from NetBIOS plugin output.
// Returns a slice of [2]string{name, role} pairs, preserving order.
// (nadda.py parse_netbios_assignments ~1061.)
func ParseNetbiosAssignments(text string) [][2]string {
	var result [][2]string
	for _, line := range strings.Split(text, "\n") {
		m := netbiosAssignRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.TrimSpace(m[1])
		role := strings.TrimSpace(m[2])
		if name == "" || role == "" {
			continue
		}
		result = append(result, [2]string{name, role})
	}
	return result
}

// ParseFqdnResolution extracts the FQDN from "<ip> resolves as <fqdn>." text.
// The trailing dot (if present) is stripped. Returns "" if no match.
// (nadda.py parse_fqdn_resolution ~1070.)
func ParseFqdnResolution(text string) string {
	m := fqdnResolutionRe.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	// clean_value: strip whitespace and trailing dots
	fqdn := strings.TrimSpace(m[1])
	fqdn = strings.TrimSuffix(fqdn, ".")
	return fqdn
}

// ParseDNDomains extracts domain names from LDAP DN text containing dc= chains.
// Example: "dc=corp,dc=acme,dc=com" → ["corp.acme.com"].
// Returns nil (not empty slice) when no dc= chains are found.
// (nadda.py parse_dn_domains ~1096.)
func ParseDNDomains(text string) []string {
	matches := dnDomainRe.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		labels := dcLabelRe.FindAllStringSubmatch(m, -1)
		parts := make([]string, 0, len(labels))
		for _, l := range labels {
			parts = append(parts, strings.ToLower(l[1]))
		}
		domain := NormalizeDomain(strings.Join(parts, "."))
		if domain != "" && !seen[domain] {
			seen[domain] = true
			result = append(result, domain)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// DomainFromComponents joins label components into a domain name.
// If the first label is TLD-like (com, net, org, etc.) and there are multiple
// labels, the slice is reversed before joining (handles reversed component order).
// (nadda.py domain_from_components ~1106.)
func DomainFromComponents(components []string) string {
	var labels []string
	for _, c := range components {
		c = strings.TrimSpace(c)
		c = strings.Trim(c, ".")
		c = strings.TrimSpace(c)
		c = strings.ToLower(c)
		if c != "" {
			labels = append(labels, c)
		}
	}
	if len(labels) == 0 {
		return ""
	}
	if tldLikeLabels[labels[0]] && len(labels) > 1 {
		// reverse
		for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
			labels[i], labels[j] = labels[j], labels[i]
		}
	}
	joined := strings.Join(labels, ".")
	// A valid domain must contain at least one dot (nadda.py normalize_domain
	// rejects no-dot values; DomainFromComponents delegates that check here).
	if !strings.Contains(joined, ".") {
		return ""
	}
	return NormalizeDomain(joined)
}

// ParseCertNames extracts Subject and Issuer Common Name values from SSL
// certificate plugin output text. Returns subjects and issuers as separate slices.
// Handles both "Subject:" / "Issuer:" and "Subject Name:" / "Issuer Name:"
// section headers (the former appears in the brief test; the latter is the
// actual Nessus plugin 10863 format).
// (nadda.py parse_cert_names ~1115, adapted for both header forms.)
func ParseCertNames(text string) (subjects, issuers []string) {
	section := "" // "subject" or "issuer"
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if certSubjectRe.MatchString(line) {
			section = "subject"
			continue
		}
		if certIssuerRe.MatchString(line) {
			section = "issuer"
			continue
		}
		if section == "" {
			continue
		}
		m := certFieldRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		val := strings.TrimSpace(m[1])
		val = strings.Trim(val, ".")
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		switch section {
		case "subject":
			subjects = append(subjects, val)
		case "issuer":
			issuers = append(issuers, val)
		}
	}
	return subjects, issuers
}

// CertNames holds parsed SSL certificate name fields.
type CertNames struct {
	SubjectCommonName     []string
	IssuerCommonName      []string
	IssuerDomainComponent []string // DC= labels from Issuer section
	IssuerOrg             []string // O= / OU= values from Issuer section
}

// ParseCertNamesExt extracts all four certificate name field types from SSL
// certificate plugin output text. Unlike ParseCertNames it also captures
// Domain Component and Organization/Organizational Unit fields from the Issuer
// section, which are required for ADCS CA detection.
func ParseCertNamesExt(text string) CertNames {
	var cn CertNames
	section := "" // "subject" or "issuer"
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if certSubjectRe.MatchString(line) {
			section = "subject"
			continue
		}
		if certIssuerRe.MatchString(line) {
			section = "issuer"
			continue
		}
		if section == "" {
			continue
		}

		cleanVal := func(s string) string {
			s = strings.TrimSpace(s)
			s = strings.Trim(s, ".")
			s = strings.TrimSpace(s)
			return s
		}

		// Common Name
		if m := certFieldRe.FindStringSubmatch(line); m != nil {
			val := cleanVal(m[1])
			if val != "" {
				switch section {
				case "subject":
					cn.SubjectCommonName = append(cn.SubjectCommonName, val)
				case "issuer":
					cn.IssuerCommonName = append(cn.IssuerCommonName, val)
				}
			}
			continue
		}

		// Domain Component (issuer section only)
		if section == "issuer" {
			if m := certDomainComponentRe.FindStringSubmatch(line); m != nil {
				val := cleanVal(m[1])
				if val != "" {
					cn.IssuerDomainComponent = append(cn.IssuerDomainComponent, val)
				}
				continue
			}
			// Organization / Organization Unit (issuer section only)
			if m := certOrgRe.FindStringSubmatch(line); m != nil {
				val := cleanVal(m[1])
				if val != "" {
					cn.IssuerOrg = append(cn.IssuerOrg, val)
				}
				continue
			}
		}
	}
	return cn
}

// RowSearchBlob builds a lowercased, space-joined search blob from the four
// standard Nessus row fields. Empty fields are omitted.
// (nadda.py row_search_blob ~1173; Go version lowers and space-joins per brief.)
func RowSearchBlob(name, synopsis, description, pluginOutput string) string {
	var parts []string
	for _, s := range []string{name, synopsis, description, pluginOutput} {
		s = strings.TrimSpace(s)
		if s != "" {
			parts = append(parts, strings.ToLower(s))
		}
	}
	return strings.Join(parts, " ")
}

// ContainsAnyBounded returns true if any needle is found in text using
// word-boundary matching (case-insensitive). Matches nadda.py's
// contains_any_bounded / bounded_term_re logic (~1185–1208):
//   - If needle starts with alnum, a non-alnum char (or start-of-string) must
//     precede the match.
//   - If needle ends with alnum, a non-alnum char (or end-of-string) must follow.
//   - Spaces in the needle are treated as \s+ (one or more whitespace).
//   - Empty needles are skipped.
//
// Compiled regexes are cached in a package-level map (equivalent to
// nadda.py's lru_cache(maxsize=512) on bounded_term_re).
func ContainsAnyBounded(text string, needles ...string) bool {
	textLower := strings.ToLower(text)
	for _, needle := range needles {
		if needle == "" {
			continue
		}
		// Fast path: substring check before regex (mirrors nadda.py's optimisation).
		if !strings.Contains(textLower, strings.ToLower(needle)) {
			continue
		}
		re := boundedTermRe(needle)
		if re.MatchString(text) {
			return true
		}
	}
	return false
}
