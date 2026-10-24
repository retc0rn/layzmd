package mdout

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Summary holds the data needed to render an index.md stub.
type Summary struct {
	ScanName          string
	Generated         string
	Findings          int
	Hosts             int
	WithCVE           int
	VulnGroups        int
	Domains           int
	DomainControllers int
	// HasDefensive/HasCreds/HasWeb gate the optional top-level section links.
	HasDefensive bool
	HasCreds     bool
	HasWeb       bool
}

// RenderIndex returns the index.md content for s. Pure: no I/O, no time.Now.
func RenderIndex(s Summary) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, `---
scan: %s
generated: %s
---
# %s — Scan Report

> [!abstract] Summary
> - **Hosts:** %d
> - **Findings:** %d  ·  **With CVE:** %d
> - **Vulnerabilities:** %d grouped  ·  **Domains:** %d  ·  **Domain Controllers:** %d

## Sections
- [[Hosts]] — hosts grouped by OS
- [[Services]] — services grouped by category
- [[Vulnerabilities]] — findings by priority
- [[AD]] — Active Directory analysis
`, s.ScanName, s.Generated, s.ScanName, s.Hosts, s.Findings, s.WithCVE, s.VulnGroups, s.Domains, s.DomainControllers)
	if s.HasWeb {
		sb.WriteString("- [[Web Attack Surface]] — web servers, pages, and categorized web surface\n")
	}
	if s.HasDefensive {
		sb.WriteString("- [[Defensive]] — detected defensive technologies\n")
	}
	if s.HasCreds {
		sb.WriteString("- [[Usernames - Creds]] — discovered credentials / email addresses\n")
	}
	return sb.String()
}

// WriteIndex writes index.md into dir (creating dir if needed).
func WriteIndex(dir string, s Summary) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "index.md"), []byte(RenderIndex(s)), 0o644)
}
