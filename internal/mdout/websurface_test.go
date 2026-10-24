package mdout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"layzmd/internal/websurface"
)

func webTestReport() websurface.Report {
	return websurface.Report{
		Meta:   websurface.Meta{ScanName: "Test", Generated: "2026-07-14"},
		Counts: websurface.Counts{Hosts: 2, Services: 3, Browsable: 2, Management: 1, TLS: 1, Plaintext: 1},
		Logins: []websurface.CatEntry{
			{Host: "10.0.0.1", Port: "443", Path: "/admin/login", TLS: true},
			{Host: "10.0.0.2", Port: "80", Path: "/main_login.html"},
		},
		APIs:      []websurface.CatEntry{{Host: "10.0.0.1", Port: "443", Path: "/api/v1/users", TLS: true}},
		BasicAuth: []websurface.CatEntry{{Host: "10.0.0.1", Port: "443", Path: "/admin/login", Detail: "Basic", TLS: true}},
		Admin:     []websurface.CatEntry{{Host: "10.0.0.1", Port: "443", Path: "/admin/login", TLS: true}},
		Dangerous: []websurface.CatEntry{{Host: "10.0.0.2", Port: "80", Path: "/dav", Detail: "PUT DELETE"}},
		Files: map[string][]websurface.CatEntry{
			"Config Files":   {{Host: "10.0.0.1", Port: "443", Path: "/app/web.config", TLS: true}},
			"Database Dumps": {{Host: "10.0.0.2", Port: "80", Path: "/db/backup.sql"}},
		},
		Other: []websurface.CatEntry{{Host: "10.0.0.2", Port: "80", Path: "/images/logo.png"}},
	}
}

func TestRenderWebSurfaceIndex_Golden(t *testing.T) {
	got := normalizeNewlines(RenderWebSurfaceIndex(webTestReport()))
	want, err := os.ReadFile("../../testdata/golden_web_index.md")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != normalizeNewlines(string(want)) {
		t.Errorf("index mismatch:\ngot:\n%s", got)
	}
}

func TestRenderWebCategory_Golden(t *testing.T) {
	// Dangerous Methods exercises the "# detail" annotation.
	got := normalizeNewlines(RenderWebCategory("Dangerous Methods", webTestReport().Dangerous, true))
	want, err := os.ReadFile("../../testdata/golden_web_category.md")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != normalizeNewlines(string(want)) {
		t.Errorf("category mismatch:\ngot:\n%s", got)
	}
}

func TestWebURL(t *testing.T) {
	cases := []struct {
		e    websurface.CatEntry
		want string
	}{
		{websurface.CatEntry{Host: "10.0.0.1", Port: "80", Path: "/admin"}, "http://10.0.0.1:80/admin"},
		{websurface.CatEntry{Host: "10.0.0.1", Port: "443", Path: "/x", TLS: true}, "https://10.0.0.1:443/x"},
	}
	for _, c := range cases {
		if got := webURL(c.e); got != c.want {
			t.Errorf("webURL=%q want %q", got, c.want)
		}
	}
}

func TestWriteWebSurface_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := WriteWebSurface(dir, webTestReport()); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "Web Attack Surface.md")); err != nil {
		t.Errorf("index missing: %v", err)
	}
	// Non-empty categories become files; empty (Default Pages) do not.
	for _, name := range []string{"Login Pages", "API Endpoints", "Basic Auth", "Admin Consoles", "Dangerous Methods", "Other Pages"} {
		if _, err := os.Stat(filepath.Join(dir, "Web Attack Surface", name+".md")); err != nil {
			t.Errorf("missing category %q: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "Web Attack Surface", "Default Pages.md")); err == nil {
		t.Error("empty Default Pages should not be written")
	}
	// Login file contains ready-to-copy full URLs in a code block.
	b, _ := os.ReadFile(filepath.Join(dir, "Web Attack Surface", "Login Pages.md"))
	if !strings.Contains(string(b), "https://10.0.0.1:443/admin/login") || !strings.Contains(string(b), "```") {
		t.Errorf("login file missing URL/code block:\n%s", b)
	}
}
