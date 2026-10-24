package vulnview

import (
	"regexp"
	"strconv"
	"strings"
)

// Bucket names (semantic categories). Display/folder order is defined in the
// emitter; assignment precedence is defined by bucketOf (themes before High
// Priority).
const (
	BucketQuickWins      = "Quick Wins"
	BucketHighPriority   = "High Priority"
	BucketWebApp         = "Web Application Weaknesses"
	BucketCrypto         = "Cryptographic and Certificate Issues"
	BucketBoring         = "Boring Bin"
	BucketDoS            = "Denial of Service"
	BucketMissingPatches = "Missing Patches"
	BucketOutdated       = "Outdated Software"
	BucketResidual       = "Residual Findings"
)

// quickWinCreds: default-credential / low-attack-complexity name keywords
// (includes unauthenticated SMB SID/user enumeration, a classic recon quick win).
var quickWinCreds = []string{
	"default password", "default credential", "default account", "common credentials",
	"hard-coded", "hardcoded", "blank password", "no password", "weak password",
	"weak credential", "anonymous ftp", "anonymous logon", "null session",
	"guest account", "guest access", "default community", "factory default", "well-known",
	"sid to enumerate", "sid enumeration",
}

// webAppKw: web-application-attack name keywords (clickjacking/auto-complete are
// deliberately excluded — they belong to Boring Bin). Also folds in a few
// web-server detections (phpinfo, reverse proxy, dangerous methods) that are
// web-surface findings worth grouping with the web weaknesses.
var webAppKw = []string{
	"xss", "cross-site scripting", "cross site scripting", "ssrf",
	"server-side request forgery", "sql injection", "sqli", "csrf",
	"cross-site request forgery", "command injection", "code injection",
	"local file inclusion", "remote file inclusion", "browsable web director",
	"basic authentication without https", "web.config", "directory traversal", "path traversal",
	"phpinfo", "reverse proxy", "dangerous method",
	"internal ip disclosure", "web application information disclosure",
}

// cryptoKw: cryptography / certificate / transport-security name keywords
// (includes cleartext/unencrypted transport, MitM weaknesses, and SSH Terrapin).
var cryptoKw = []string{
	"ssl", "tls", "certificate", "cipher", "openssl", "fips", "poodle", "sweet32",
	"beast", "drown", "logjam", "freak", "heartbleed", "rc4", "3des", "weak hashing",
	"self-signed", "diffie-hellman", "terminal services encryption",
	"terrapin", "cleartext", "unencrypted", "man-in-the-middle",
}

// boringKw: common-but-low-value detection name keywords.
var boringKw = []string{
	"password auto-complet", "autocomplete", "clickjacking", "dhcp server detection",
	"mdns detection", "non-standard port detection", "quote of the day", "qotd",
	"echo service", "chargen", "daytime", "finger service", "service detection",
	"traceroute information", "rpc services", "dns server detection", "ntp server detection",
	"ip forwarding",
}

func matchAny(s string, kws []string) bool {
	for _, kw := range kws {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// hasWordToken reports whether w appears in s bounded by non-alphanumerics.
func hasWordToken(s, w string) bool {
	for start := 0; ; {
		i := strings.Index(s[start:], w)
		if i < 0 {
			return false
		}
		i += start
		before := i == 0 || !isAlnum(s[i-1])
		end := i + len(w)
		after := end >= len(s) || !isAlnum(s[end])
		if before && after {
			return true
		}
		start = i + 1
	}
}

func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z')
}

// hasMetasploit reports whether any of the group's PoC links is a Metasploit module.
func hasMetasploit(g GroupView) bool {
	for _, l := range g.PocLinks {
		if l.Label == "Metasploit" {
			return true
		}
	}
	for _, c := range g.CVEs {
		for _, l := range c.PocLinks {
			if l.Label == "Metasploit" {
				return true
			}
		}
	}
	return false
}

// versionRollupRe matches a version comparator ("< 2.4.60", "<= 8u332",
// "< 7.0.100") — the signature of a Nessus product-version "patch me" finding.
var versionRollupRe = regexp.MustCompile(`<=?\s*[0-9]`)

// isVersionRollup reports whether the finding name looks like a product
// version-rollup (an "update to a fixed version" finding).
func isVersionRollup(nameLower string) bool {
	return versionRollupRe.MatchString(nameLower)
}

// isOutdated reports whether the finding is an unsupported / end-of-life product
// (must be replaced, not merely patched). Folds in Nessus "SEoL" findings.
func isOutdated(nameLower string) bool {
	return strings.Contains(nameLower, "unsupported") ||
		strings.Contains(nameLower, "seol") ||
		strings.Contains(nameLower, "end of life") ||
		strings.Contains(nameLower, "end-of-life")
}

// cvssAtLeast reports whether the CVSS string parses to a float >= min.
// Empty or unparseable strings return false.
func cvssAtLeast(cvss string, min float64) bool {
	v, err := strconv.ParseFloat(strings.TrimSpace(cvss), 64)
	if err != nil {
		return false
	}
	return v >= min
}

func isCryptoBucket(nameLower, category string) bool {
	if category == "Cryptographic Weakness" {
		return true
	}
	if matchAny(nameLower, cryptoKw) {
		return true
	}
	if strings.Contains(nameLower, "ssh") {
		for _, k := range []string{"cipher", "algorithm", "mac ", "kex", "key exchange", "host key", "encryption"} {
			if strings.Contains(nameLower, k) {
				return true
			}
		}
	}
	return false
}

// bucketOf assigns a finding to a semantic bucket by first-match precedence.
// "Themes win" over the severity escalation: a PoC'd/critical XSS lands in Web
// App, not High Priority. Quick Wins requires a Metasploit module that is also
// KEV (or a credential/default-password finding). Non-critical product
// version-rollups fall to Missing Patches; the KEV || PoC || CVSS>=9 escalation
// is the late fallthrough, so only unthemed criticals reach High Priority.
func bucketOf(g GroupView) string {
	n := strings.ToLower(g.Name)
	highSev := g.InKev || g.HasPoc || cvssAtLeast(g.CVSS, 9.0)
	switch {
	case (hasMetasploit(g) && g.InKev) || matchAny(n, quickWinCreds):
		return BucketQuickWins
	case strings.HasPrefix(n, "cgi") || matchAny(n, webAppKw):
		return BucketWebApp
	case isCryptoBucket(n, g.Category):
		return BucketCrypto
	case matchAny(n, boringKw):
		return BucketBoring
	case isOutdated(n):
		return BucketOutdated
	case isVersionRollup(n) && !highSev:
		return BucketMissingPatches
	case (g.Category == "Denial of Service" || strings.Contains(n, "denial of service") || hasWordToken(n, "dos")) && !isVersionRollup(n):
		// DoS holds genuine DoS advisories only; version-rollups never land here
		// (non-critical → Missing Patches above; critical/PoC → High Priority below).
		return BucketDoS
	case highSev:
		return BucketHighPriority
	default:
		return BucketResidual
	}
}
