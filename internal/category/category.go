// Package category classifies a vulnerability into a named category via a
// CWE numeric lookup first, then an ordered keyword fallback, else "Other".
//
// Port of PTCompanion.Core.Analysis.CategoryClassifier (C#).
package category

import (
	"regexp"
	"strconv"
	"strings"
)

// cweMap maps a CWE integer ID to a category name.
// Faithfully ported from CategoryClassifier.cs.
var cweMap = map[int]string{
	// Buffer Overflow
	787: "Buffer Overflow",
	120: "Buffer Overflow",
	121: "Buffer Overflow",
	122: "Buffer Overflow",
	119: "Buffer Overflow",
	125: "Buffer Overflow",

	// RCE
	78: "RCE",
	94: "RCE",
	77: "RCE",

	// SQL Injection
	89: "SQL Injection",

	// Cross-Site Scripting
	79: "Cross-Site Scripting",

	// SSRF
	918: "SSRF",

	// Path Traversal
	22: "Path Traversal",
	23: "Path Traversal",
	36: "Path Traversal",

	// Authentication Bypass
	287: "Authentication Bypass",
	306: "Authentication Bypass",
	862: "Authentication Bypass",
	863: "Authentication Bypass",

	// Privilege Escalation
	269: "Privilege Escalation",
	268: "Privilege Escalation",
	250: "Privilege Escalation",

	// Information Disclosure
	200: "Information Disclosure",
	209: "Information Disclosure",
	532: "Information Disclosure",

	// Denial of Service
	400: "Denial of Service",
	404: "Denial of Service",
	770: "Denial of Service",

	// Cryptographic Weakness
	327: "Cryptographic Weakness",
	326: "Cryptographic Weakness",
	295: "Cryptographic Weakness",
	310: "Cryptographic Weakness",
	311: "Cryptographic Weakness",

	// Default/Weak Credentials
	798: "Default/Weak Credentials",
	259: "Default/Weak Credentials",
	521: "Default/Weak Credentials",

	// Misconfiguration
	16:   "Misconfiguration",
	1188: "Misconfiguration",
}

// cwePattern extracts the numeric portion of a "CWE-<n>" token (case-insensitive).
var cwePattern = regexp.MustCompile(`(?i)cwe-(\d+)`)

// Word-boundary regexes for short abbreviations that would otherwise match
// as substrings inside longer words (e.g. "rce" in "resource", "dos" in
// "methodology"). Compiled once at package init.
var (
	reRce  = regexp.MustCompile(`(?i)\brce\b`)
	reDos  = regexp.MustCompile(`(?i)\bdos\b`)
	reXss  = regexp.MustCompile(`(?i)\bxss\b`)
	reSsrf = regexp.MustCompile(`(?i)\bssrf\b`)
	reEol  = regexp.MustCompile(`(?i)\beol\b`)
	reKb   = regexp.MustCompile(`(?i)\bkb\b`)
)

// Classify returns the category for a vulnerability.
//
//   - cwes: list of CWE strings (e.g. "CWE-89", "cwe-79"). First hit in the
//     CWE map wins.
//   - name, synopsis: vulnerability name and synopsis text. The keyword
//     fallback operates over strings.ToLower(name+" "+synopsis).
//
// Returns "Other" when nothing matches.
func Classify(cwes []string, name, synopsis string) string {
	// 1. CWE map — first matching CWE wins.
	for _, cwe := range cwes {
		m := cwePattern.FindStringSubmatch(cwe)
		if m == nil {
			continue
		}
		id, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		if cat, ok := cweMap[id]; ok {
			return cat
		}
	}

	// 2. Keyword fallback over combined name + synopsis (ordered, first match
	//    wins). Multi-word phrases match as substrings; short abbreviations
	//    (rce, dos, xss, ssrf, eol, kb) require word boundaries.
	text := strings.ToLower(name + " " + synopsis)

	if strings.Contains(text, "remote code execution") ||
		strings.Contains(text, "arbitrary code") ||
		reRce.MatchString(text) {
		return "RCE"
	}

	if strings.Contains(text, "buffer overflow") ||
		strings.Contains(text, "heap overflow") ||
		strings.Contains(text, "stack overflow") {
		return "Buffer Overflow"
	}

	if strings.Contains(text, "sql injection") {
		return "SQL Injection"
	}

	if strings.Contains(text, "cross-site scripting") || reXss.MatchString(text) {
		return "Cross-Site Scripting"
	}

	if strings.Contains(text, "server-side request forgery") || reSsrf.MatchString(text) {
		return "SSRF"
	}

	if strings.Contains(text, "directory traversal") ||
		strings.Contains(text, "path traversal") {
		return "Path Traversal"
	}

	if strings.Contains(text, "denial of service") || reDos.MatchString(text) {
		return "Denial of Service"
	}

	if strings.Contains(text, "privilege escalation") ||
		strings.Contains(text, "elevation of privilege") {
		return "Privilege Escalation"
	}

	if strings.Contains(text, "authentication bypass") ||
		strings.Contains(text, "auth bypass") {
		return "Authentication Bypass"
	}

	if strings.Contains(text, "unsupported") ||
		strings.Contains(text, "end of life") ||
		strings.Contains(text, "end-of-life") ||
		reEol.MatchString(text) ||
		strings.Contains(text, "obsolete") ||
		strings.Contains(text, "no longer supported") ||
		strings.Contains(text, "outdated") {
		return "Outdated Software"
	}

	if strings.Contains(text, "ssl") ||
		strings.Contains(text, "tls") ||
		strings.Contains(text, "certificate") ||
		strings.Contains(text, "cipher") ||
		strings.Contains(text, "weak encryption") ||
		strings.Contains(text, "deprecated protocol") {
		return "Cryptographic Weakness"
	}

	if strings.Contains(text, "default credentials") ||
		strings.Contains(text, "default password") ||
		strings.Contains(text, "weak password") {
		return "Default/Weak Credentials"
	}

	if strings.Contains(text, "information disclosure") ||
		strings.Contains(text, "sensitive information") ||
		strings.Contains(text, "information leak") {
		return "Information Disclosure"
	}

	if strings.Contains(text, "security update") ||
		strings.Contains(text, "missing") ||
		strings.Contains(text, "patch") ||
		reKb.MatchString(text) {
		return "Missing Patch"
	}

	// 3. No match.
	return "Other"
}
