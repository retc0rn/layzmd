package namenorm_test

import (
	"testing"

	"layzmd/internal/namenorm"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		raw        string
		wantKey    string
		wantDisplay string // empty string means "don't check display"
	}{
		// Combine: all three Tomcat version ranges → same grouping key
		{
			raw:     "Apache Tomcat 7.0.0 < 7.0.81 Multiple Vulnerabilities",
			wantKey: "apache tomcat multiple vulnerabilities",
		},
		{
			raw:     "Apache Tomcat 7.0.0 < 7.0.82 Multiple Vulnerabilities",
			wantKey: "apache tomcat multiple vulnerabilities",
		},
		{
			raw:     "Apache Tomcat 9.0.0 < 9.0.31 Multiple Vulnerabilities",
			wantKey: "apache tomcat multiple vulnerabilities",
		},
		// Suffix-distinct: "Denial of Service" produces a different key
		{
			raw:     "Apache Tomcat 8.5.0 < 8.5.50 Denial of Service",
			wantKey: "apache tomcat denial of service",
		},
		// Display: version stripped, original casing preserved
		{
			raw:         "Apache Tomcat 7.0.0 < 7.0.81 Multiple Vulnerabilities",
			wantKey:     "apache tomcat multiple vulnerabilities",
			wantDisplay: "Apache Tomcat Multiple Vulnerabilities",
		},
		// Range phrases removed
		{
			raw:     "OpenSSL 1.0.2 through 1.0.2t Multiple Vulnerabilities",
			wantKey: "openssl multiple vulnerabilities",
		},
		{
			raw:     "PHP prior to 7.4.3 Multiple Vulnerabilities",
			wantKey: "php multiple vulnerabilities",
		},
		{
			raw:     "OpenSSL before 1.1.1d Remote Code Execution",
			wantKey: "openssl remote code execution",
		},
		{
			raw:     "curl up to 7.85.0 Information Disclosure",
			wantKey: "curl information disclosure",
		},
		{
			raw:     "libssl and earlier 1.0.2 Buffer Overflow",
			wantKey: "libssl buffer overflow",
		},
		// KB / build numbers dropped (parenthetical 4+ digits)
		{
			raw:         "MS17-010: Security Update for Microsoft Windows SMB Server (4013389)",
			wantKey:     "ms17-010: security update for microsoft windows smb server",
			wantDisplay: "MS17-010: Security Update for Microsoft Windows SMB Server",
		},
		// No-version inputs pass through unchanged (key is just lowercased)
		{
			raw:         "SSL Certificate Cannot Be Trusted",
			wantKey:     "ssl certificate cannot be trusted",
			wantDisplay: "SSL Certificate Cannot Be Trusted",
		},
		// Conservative guard: SMBv1 (no dot) must survive
		{
			raw:     "Microsoft Windows SMBv1 Detection",
			wantKey: "microsoft windows smbv1 detection",
		},
		// SHA-1 (hyphenated, not dotted version) must survive
		{
			raw:     "SHA-1 Deprecation",
			wantKey: "sha-1 deprecation",
		},
		// TLS 1.0 — "1.0" is a dotted version and IS removed; surrounding words kept
		{
			raw:     "TLS Version 1.0 Protocol Detection",
			wantKey: "tls version protocol detection",
		},
		// Empty string
		{
			raw:     "",
			wantKey: "",
		},
	}

	// Deduplicate entries that share the same raw (the wantDisplay entries have
	// duplicates for the Tomcat and KB cases); we run each explicitly.
	type tc struct {
		raw        string
		wantKey    string
		wantDisplay string
	}
	var cases []tc
	for _, tt := range tests {
		cases = append(cases, tc{tt.raw, tt.wantKey, tt.wantDisplay})
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.raw, func(t *testing.T) {
			key, display := namenorm.Normalize(tt.raw)
			if key != tt.wantKey {
				t.Errorf("Normalize(%q).key = %q; want %q", tt.raw, key, tt.wantKey)
			}
			if tt.wantDisplay != "" && display != tt.wantDisplay {
				t.Errorf("Normalize(%q).display = %q; want %q", tt.raw, display, tt.wantDisplay)
			}
		})
	}
}

// Additional targeted tests mined from C# NameNormalizerTests.cs

func TestNormalize_KBDrop_ContainsAdvisoryAndSmbNotKb(t *testing.T) {
	key, _ := namenorm.Normalize("MS17-010: Security Update for Microsoft Windows SMB Server (4013389)")
	if key == "" {
		t.Fatal("key must not be empty")
	}
	for _, want := range []string{"ms17-010", "smb server"} {
		if !contains(key, want) {
			t.Errorf("key %q does not contain %q", key, want)
		}
	}
	if contains(key, "4013389") {
		t.Errorf("key %q must NOT contain the KB number 4013389", key)
	}
}

func TestNormalize_TLS_KeyNonEmptyContainsTlsAndProtocolDetection(t *testing.T) {
	key, _ := namenorm.Normalize("TLS Version 1.0 Protocol Detection")
	if key == "" {
		t.Fatal("key must not be empty")
	}
	if !contains(key, "tls") {
		t.Errorf("key %q must contain \"tls\"", key)
	}
	if !contains(key, "protocol detection") {
		t.Errorf("key %q must contain \"protocol detection\"", key)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
