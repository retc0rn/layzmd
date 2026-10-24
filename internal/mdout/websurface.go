package mdout

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"layzmd/internal/websurface"
)

// webCat describes one category output file.
type webCat struct {
	Name    string
	Entries []websurface.CatEntry
	Detail  bool // append "# <Detail>" (e.g. dangerous methods) after the URL
}

// webCategories returns the category files in display order: the attack
// categories, then the interesting-file subpages, then the Other Pages catch-all.
func webCategories(r websurface.Report) []webCat {
	cats := []webCat{
		{"Login Pages", r.Logins, false},
		{"API Endpoints", r.APIs, false},
		{"Basic Auth", r.BasicAuth, false},
		{"Admin Consoles", r.Admin, false},
		{"Dangerous Methods", r.Dangerous, true},
		{"Default Pages", r.DefaultPage, false},
	}
	for _, name := range websurface.FileCategoryNames() {
		cats = append(cats, webCat{name, r.Files[name], false})
	}
	return append(cats, webCat{"Other Pages", r.Other, false})
}

// webURL builds a ready-to-copy absolute URL for an entry: scheme from TLS,
// port always included, e.g. "http://10.0.0.1:80/admin".
func webURL(e websurface.CatEntry) string {
	scheme := "http"
	if e.TLS {
		scheme = "https"
	}
	path := e.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("%s://%s:%s%s", scheme, e.Host, e.Port, path)
}

// webCatLines returns the deduped code-block lines for a category (URL, plus a
// trailing "# detail" comment when detail is requested and present).
func webCatLines(entries []websurface.CatEntry, detail bool) []string {
	seen := map[string]bool{}
	var lines []string
	for _, e := range entries {
		u := webURL(e)
		if seen[u] {
			continue
		}
		seen[u] = true
		if detail && e.Detail != "" {
			lines = append(lines, u+"  # "+e.Detail)
		} else {
			lines = append(lines, u)
		}
	}
	return lines
}

// RenderWebCategory renders one category file: frontmatter + heading + back-link
// + a code block of ready-to-copy URLs. Pure.
func RenderWebCategory(name string, entries []websurface.CatEntry, detail bool) string {
	lines := webCatLines(entries, detail)
	var sb strings.Builder
	writeFrontmatter(&sb, [][2]string{
		{"category", name},
		{"count", strconv.Itoa(len(lines))},
	})
	sb.WriteString("# " + name + "\n")
	sb.WriteString("\n> [!info] [[Web Attack Surface|← all web attack surface]]\n")
	sb.WriteString("\n```\n")
	for _, l := range lines {
		sb.WriteString(l + "\n")
	}
	sb.WriteString("```\n")
	return sb.String()
}

// RenderWebSurfaceIndex renders the Web Attack Surface.md index. Pure.
func RenderWebSurfaceIndex(r websurface.Report) string {
	var sb strings.Builder
	sb.WriteString("---\n")
	sb.WriteString(fmt.Sprintf("scan: %s\n", r.Meta.ScanName))
	sb.WriteString(fmt.Sprintf("generated: %s\n", r.Meta.Generated))
	sb.WriteString(fmt.Sprintf("web_services: %d\n", r.Counts.Browsable))
	sb.WriteString(fmt.Sprintf("hosts: %d\n", r.Counts.Hosts))
	sb.WriteString("---\n")
	sb.WriteString(fmt.Sprintf("\n# Web Attack Surface — %s\n", r.Meta.ScanName))

	sb.WriteString("\n> [!abstract] Overview\n")
	sb.WriteString(fmt.Sprintf("> - **Hosts:** %d  ·  **Browsable web services:** %d\n", r.Counts.Hosts, r.Counts.Browsable))
	sb.WriteString(fmt.Sprintf("> - **TLS:** %d  ·  **Plaintext:** %d\n", r.Counts.TLS, r.Counts.Plaintext))
	if r.Counts.Management > 0 {
		sb.WriteString(fmt.Sprintf("> - _Excluded %d management/protocol endpoints (WinRM, appliance mgmt)._\n", r.Counts.Management))
	}

	sb.WriteString("\n## Categories\n")
	for _, c := range webCategories(r) {
		n := len(webCatLines(c.Entries, c.Detail))
		if n == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("- [[Web Attack Surface/%s|%s]] — %d\n", c.Name, c.Name, n))
	}
	return strings.TrimRight(sb.String(), "\n") + "\n"
}

// WriteWebSurface writes Web Attack Surface.md plus one file per non-empty
// category under Web Attack Surface/. The subfolder is cleared and recreated.
func WriteWebSurface(dir string, r websurface.Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "Web Attack Surface.md"),
		[]byte(RenderWebSurfaceIndex(r)), 0o644); err != nil {
		return err
	}
	sub := filepath.Join(dir, "Web Attack Surface")
	if err := os.RemoveAll(sub); err != nil {
		return err
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		return err
	}
	for _, c := range webCategories(r) {
		if len(webCatLines(c.Entries, c.Detail)) == 0 {
			continue
		}
		p := filepath.Join(sub, c.Name+".md")
		if err := os.WriteFile(p, []byte(RenderWebCategory(c.Name, c.Entries, c.Detail)), 0o644); err != nil {
			return err
		}
	}
	return nil
}
