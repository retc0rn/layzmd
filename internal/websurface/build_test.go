package websurface

import (
	"strings"
	"testing"

	"layzmd/internal/nessus"
)

func TestBuild_EndToEnd(t *testing.T) {
	fs := []nessus.Finding{
		{HostIP: "10.0.0.1", Port: "443", Name: "HyperText Transfer Protocol (HTTP) Information"},
		{HostIP: "10.0.0.1", Port: "443", Name: "HTTP Server Type and Version", PluginOutput: "The remote web server type is :\n\nApache/2.4.6"},
		{HostIP: "10.0.0.1", Port: "443", Name: "Web Application Sitemap", PluginOutput: "sitemap:\n\n  - https://10.0.0.1/\n  - https://10.0.0.1/api/v1/users"},
		{HostIP: "10.0.0.1", Port: "443", Name: "Protected Web Page Detection", PluginOutput: "protected by the Basic authentication scheme :\n\n/admin/login"},
		{HostIP: "10.0.0.1", Port: "443", Name: "SSL Certificate Information", PluginOutput: "x"},
		{HostIP: "10.0.0.2", Port: "5985", Name: "HyperText Transfer Protocol (HTTP) Information", PluginOutput: ""},
	}
	r := Build(fs, Meta{ScanName: "T", Generated: "2026-07-14"})

	if r.Counts.Hosts != 2 || r.Counts.Services != 2 {
		t.Fatalf("counts=%+v", r.Counts)
	}
	if r.Counts.Management != 1 || r.Counts.Browsable != 1 {
		t.Errorf("browsable/mgmt split wrong: %+v", r.Counts)
	}
	svc := r.Hosts[0].Services[0]
	if !svc.TLS || svc.Software != "Apache/2.4.6" {
		t.Errorf("svc meta wrong: %+v", svc)
	}
	if !hasCat(svc.Cats, "api") || !hasCat(svc.Cats, "basic-auth") || !hasCat(svc.Cats, "admin") {
		t.Errorf("cats=%v", svc.Cats)
	}
	if len(r.APIs) == 0 || len(r.BasicAuth) == 0 || r.Counts.Management != 1 {
		t.Errorf("rollups: apis=%d basic=%d mgmt=%d", len(r.APIs), len(r.BasicAuth), r.Counts.Management)
	}
	// "/" matches no category -> Other; management service contributes nothing.
	foundRoot := false
	for _, e := range r.Other {
		if e.Path == "/" && e.Host == "10.0.0.1" {
			foundRoot = true
		}
		if e.Host == "10.0.0.2" {
			t.Errorf("management host leaked into Other: %+v", e)
		}
	}
	if !foundRoot {
		t.Errorf("expected '/' in Other, got %+v", r.Other)
	}
}

func TestBuild_InterestingFiles(t *testing.T) {
	fs := []nessus.Finding{
		{HostIP: "10.0.0.5", Port: "80", Name: "HyperText Transfer Protocol (HTTP) Information"},
		{HostIP: "10.0.0.5", Port: "80", Name: "Web Application Sitemap", PluginOutput: "map:\n\n  - http://10.0.0.5/db/backup.sql\n  - http://10.0.0.5/logs/app.log\n  - http://10.0.0.5/index.html"},
	}
	r := Build(fs, Meta{})
	if len(r.Files["Database Dumps"]) != 1 || r.Files["Database Dumps"][0].Path != "/db/backup.sql" {
		t.Errorf("Database Dumps=%+v", r.Files["Database Dumps"])
	}
	if len(r.Files["Log Files"]) != 1 {
		t.Errorf("Log Files=%+v", r.Files["Log Files"])
	}
	// The .sql/.log must NOT appear in Other; /index.html should.
	for _, e := range r.Other {
		if strings.HasSuffix(e.Path, ".sql") || strings.HasSuffix(e.Path, ".log") {
			t.Errorf("interesting file leaked into Other: %s", e.Path)
		}
	}
	foundHTML := false
	for _, e := range r.Other {
		if e.Path == "/index.html" {
			foundHTML = true
		}
	}
	if !foundHTML {
		t.Errorf("plain page should be in Other, got %+v", r.Other)
	}
}

// The "Based on tests of each method" block enumerates every probed method and
// must be ignored: only the OPTIONS-response block counts toward methods/dirs.
func TestBuild_MethodsOptionsBlockOnly(t *testing.T) {
	out := `Based on the response to an OPTIONS request :

  - HTTP methods  GET  OPTIONS HEAD are allowed on :

    /

Based on tests of each method :

  - HTTP methods PUT DELETE PROPFIND MKCOL COPY MOVE are allowed on :

    /
`
	fs := []nessus.Finding{
		{HostIP: "10.0.0.9", Port: "80", Name: "HyperText Transfer Protocol (HTTP) Information"},
		{HostIP: "10.0.0.9", Port: "80", Name: "HTTP Methods Allowed (per directory)", PluginOutput: out},
	}
	r := Build(fs, Meta{})
	svc := r.Hosts[0].Services[0]
	if len(svc.Dirs) != 1 || svc.Dirs[0].Path != "/" {
		t.Fatalf("dirs=%+v", svc.Dirs)
	}
	// Only GET/OPTIONS/HEAD — no WebDAV — so NOT dangerous.
	if hasCat(svc.Cats, "dangerous") {
		t.Errorf("must not be dangerous from the tests block; methods=%v", svc.Dirs[0].Methods)
	}
	if len(r.Dangerous) != 0 {
		t.Errorf("Dangerous rollup should be empty, got %d", len(r.Dangerous))
	}
}
