package mdout

import (
	"strings"
	"testing"
)

func TestSanitizePathSeg(t *testing.T) {
	cases := map[string]string{
		"Apache Tomcat":    "Apache Tomcat",  // spaces/case preserved
		"SSL/TLS":          "SSL-TLS",         // path-illegal / replaced
		`a<b>c:"d\e|f?g*h`: "a-b-c--d-e-f-g-h", // each illegal char → one -; consecutive :" → --
		"":                 "Other",           // empty → "Other" (behavior preserved from sanitizeSystem)
	}
	for in, want := range cases {
		if got := sanitizePathSeg(in); got != want {
			t.Errorf("sanitizePathSeg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteFrontmatter(t *testing.T) {
	var sb strings.Builder
	writeFrontmatter(&sb, [][2]string{
		{"category", "Web"},
		{"hosts", "3"},
		{"ports", "[80/tcp, 443/tcp]"}, // flow list written raw
		{"service", "a: b"},            // special char → quoted by yamlQuoteString
	})
	got := sb.String()
	want := "---\ncategory: Web\nhosts: 3\nports: [80/tcp, 443/tcp]\nservice: \"a: b\"\n---\n"
	if got != want {
		t.Errorf("writeFrontmatter =\n%q\nwant\n%q", got, want)
	}
}
