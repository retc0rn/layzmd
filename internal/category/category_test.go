package category_test

import (
	"testing"

	"layzmd/internal/category"
)

// cwes is a helper to parse a comma-separated CWE string into a slice.
// Empty string returns nil.
func cwes(s string) []string {
	if s == "" {
		return nil
	}
	// simple split — no fancy trimming needed for test inputs
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			tok := s[start:i]
			// trim spaces
			j, k := 0, len(tok)-1
			for j < len(tok) && tok[j] == ' ' {
				j++
			}
			for k >= j && tok[k] == ' ' {
				k--
			}
			if j <= k {
				out = append(out, tok[j:k+1])
			}
			start = i + 1
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// CWE map cases (from the brief + C# test file)
// ---------------------------------------------------------------------------

func TestClassify_CweMap(t *testing.T) {
	cases := []struct {
		cweStr   string
		name     string
		synopsis string
		want     string
	}{
		{"CWE-787", "", "", "Buffer Overflow"},
		{"CWE-89", "", "", "SQL Injection"},
		{"CWE-918", "", "", "SSRF"},
		{"CWE-79", "", "", "Cross-Site Scripting"},
		{"CWE-22", "", "", "Path Traversal"},
		{"CWE-287", "", "", "Authentication Bypass"},
		{"CWE-78", "", "", "RCE"},
		// Additional CWE map entries from C# tests
		{"CWE-269", "", "", "Privilege Escalation"},
		{"CWE-200", "", "", "Information Disclosure"},
		{"CWE-400", "", "", "Denial of Service"},
		{"CWE-327", "", "", "Cryptographic Weakness"},
		{"CWE-798", "", "", "Default/Weak Credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.cweStr, func(t *testing.T) {
			got := category.Classify(cwes(tc.cweStr), tc.name, tc.synopsis)
			if got != tc.want {
				t.Errorf("Classify(%q, %q, %q) = %q, want %q", tc.cweStr, tc.name, tc.synopsis, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Keyword fallback (empty CWEs) — brief cases + extended C# test cases
// ---------------------------------------------------------------------------

func TestClassify_KeywordFallback(t *testing.T) {
	cases := []struct {
		name     string
		synopsis string
		want     string
	}{
		// Brief cases
		{"Foo Remote Code Execution", "", "RCE"},
		{"X", "Host runs an unsupported version of Windows", "Outdated Software"},
		{"SSL Certificate Cannot Be Trusted", "", "Cryptographic Weakness"},
		{"SQL Injection in Y", "", "SQL Injection"},
		// Extended from C# test file
		{"arbitrary code execution vulnerability", "", "RCE"},
		{"buffer overflow in library", "", "Buffer Overflow"},
		{"cross-site scripting via param", "", "Cross-Site Scripting"},
		{"server-side request forgery", "", "SSRF"},
		{"directory traversal exploit", "", "Path Traversal"},
		{"denial of service via malformed packet", "", "Denial of Service"},
		{"privilege escalation flaw", "", "Privilege Escalation"},
		{"authentication bypass in login", "", "Authentication Bypass"},
		{"end of life software detected", "", "Outdated Software"},
		{"weak encryption algorithm in use", "", "Cryptographic Weakness"},
		{"default credentials found", "", "Default/Weak Credentials"},
		{"information disclosure via error page", "", "Information Disclosure"},
		{"missing security patch for kb123", "", "Missing Patch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := category.Classify(nil, tc.name, tc.synopsis)
			if got != tc.want {
				t.Errorf("Classify(nil, %q, %q) = %q, want %q", tc.name, tc.synopsis, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Word-boundary: short abbreviations must NOT match inside longer words
// ---------------------------------------------------------------------------

func TestClassify_WordBoundary_NoFalsePositive(t *testing.T) {
	cases := []struct {
		name     string
		synopsis string
		want     string
	}{
		// "rce" inside "resource" must not match
		{"Adobe Reader font resource handling", "", "Other"},
		// "dos" inside "methodology" must not match
		{"Some methodology flaw", "", "Other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := category.Classify(nil, tc.name, tc.synopsis)
			if got != tc.want {
				t.Errorf("Classify(nil, %q, %q) = %q, want %q", tc.name, tc.synopsis, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Word-boundary: short abbreviations as whole words must still classify
// ---------------------------------------------------------------------------

func TestClassify_WordBoundary_PositiveCases(t *testing.T) {
	cases := []struct {
		name     string
		synopsis string
		want     string
	}{
		{"Apache Struts RCE", "", "RCE"},
		{"DoS condition", "", "Denial of Service"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := category.Classify(nil, tc.name, tc.synopsis)
			if got != tc.want {
				t.Errorf("Classify(nil, %q, %q) = %q, want %q", tc.name, tc.synopsis, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CWE beats keyword
// ---------------------------------------------------------------------------

func TestClassify_CweBeatsKeyword(t *testing.T) {
	got := category.Classify([]string{"CWE-89"}, "denial of service issue", "")
	if got != "SQL Injection" {
		t.Errorf("got %q, want %q", got, "SQL Injection")
	}
}

// ---------------------------------------------------------------------------
// No match anywhere → "Other"
// ---------------------------------------------------------------------------

func TestClassify_NoMatch_ReturnsOther(t *testing.T) {
	got := category.Classify(nil, "Totally generic thing", "")
	if got != "Other" {
		t.Errorf("got %q, want %q", got, "Other")
	}
}

func TestClassify_Empty_ReturnsOther(t *testing.T) {
	got := category.Classify(nil, "", "")
	if got != "Other" {
		t.Errorf("got %q, want %q", got, "Other")
	}
}

// ---------------------------------------------------------------------------
// Case-insensitive CWE parsing
// ---------------------------------------------------------------------------

func TestClassify_CweCaseInsensitive(t *testing.T) {
	got := category.Classify([]string{"cwe-79"}, "", "")
	if got != "Cross-Site Scripting" {
		t.Errorf("got %q, want %q", got, "Cross-Site Scripting")
	}
}
