package vuln_test

import (
	"os"
	"testing"

	"layzmd/internal/nessus"
	"layzmd/internal/vuln"
)

func loadFindings(t *testing.T, path string) []nessus.Finding {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	findings, err := nessus.Parse(f)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return findings
}

func TestGroup_SampleVuln(t *testing.T) {
	findings := loadFindings(t, "../../testdata/sample_vuln.csv")
	groups := vuln.Group(findings)

	// ── 3 groups total ──────────────────────────────────────────────────────
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}

	// ── Sort order: Critical desc, then Name asc ────────────────────────────
	// [0] Apache Tomcat Multiple Vulnerabilities (Critical)
	// [1] MS17-010 SMB Remote Code Execution     (Critical, comes after "Apache" alphabetically)
	// [2] Microsoft Windows Server 2012 Unsupported (None)
	tomcat := groups[0]
	ms17 := groups[1]
	unsupported := groups[2]

	// ── Tomcat group ─────────────────────────────────────────────────────────
	if tomcat.Name != "Apache Tomcat 7.0.0 < 7.0.100 Multiple Vulnerabilities" {
		t.Errorf("tomcat Name = %q, want %q", tomcat.Name, "Apache Tomcat 7.0.0 < 7.0.100 Multiple Vulnerabilities")
	}
	if tomcat.Category != "Other" {
		t.Errorf("tomcat Category = %q, want %q", tomcat.Category, "Other")
	}
	if tomcat.Risk != "Critical" {
		t.Errorf("tomcat Risk = %q, want %q", tomcat.Risk, "Critical")
	}
	if tomcat.CVSS != "9.8" {
		t.Errorf("tomcat CVSS = %q, want %q", tomcat.CVSS, "9.8")
	}
	if tomcat.HostCount != 2 {
		t.Errorf("tomcat HostCount = %d, want 2", tomcat.HostCount)
	}
	wantIPs := []string{"10.1.0.1", "10.1.0.2"}
	if len(tomcat.IPs) != len(wantIPs) {
		t.Errorf("tomcat IPs len = %d, want %d", len(tomcat.IPs), len(wantIPs))
	} else {
		for i, ip := range wantIPs {
			if tomcat.IPs[i] != ip {
				t.Errorf("tomcat IPs[%d] = %q, want %q", i, tomcat.IPs[i], ip)
			}
		}
	}

	// Tomcat CVEs: sorted [CVE-2019-0221, CVE-2020-1938]
	if len(tomcat.CVEs) != 2 {
		t.Fatalf("tomcat CVEs len = %d, want 2", len(tomcat.CVEs))
	}
	if tomcat.CVEs[0].CVE != "CVE-2019-0221" {
		t.Errorf("tomcat CVEs[0].CVE = %q, want %q", tomcat.CVEs[0].CVE, "CVE-2019-0221")
	}
	if tomcat.CVEs[1].CVE != "CVE-2020-1938" {
		t.Errorf("tomcat CVEs[1].CVE = %q, want %q", tomcat.CVEs[1].CVE, "CVE-2020-1938")
	}

	// Per-CVE host isolation
	cve0221 := tomcat.CVEs[0] // CVE-2019-0221 → 10.1.0.2, port 8080
	cve1938 := tomcat.CVEs[1] // CVE-2020-1938 → 10.1.0.1, port 8009

	if cve1938.HostCount != 1 {
		t.Errorf("CVE-2020-1938 HostCount = %d, want 1", cve1938.HostCount)
	}
	if len(cve1938.IPs) != 1 || cve1938.IPs[0] != "10.1.0.1" {
		t.Errorf("CVE-2020-1938 IPs = %v, want [10.1.0.1]", cve1938.IPs)
	}
	if cve0221.HostCount != 1 {
		t.Errorf("CVE-2019-0221 HostCount = %d, want 1", cve0221.HostCount)
	}
	if len(cve0221.IPs) != 1 || cve0221.IPs[0] != "10.1.0.2" {
		t.Errorf("CVE-2019-0221 IPs = %v, want [10.1.0.2]", cve0221.IPs)
	}

	// Tomcat HostsByPort: [8009/tcp→[10.1.0.1], 8080/tcp→[10.1.0.2]]
	if len(tomcat.HostsByPort) != 2 {
		t.Fatalf("tomcat HostsByPort len = %d, want 2", len(tomcat.HostsByPort))
	}
	if tomcat.HostsByPort[0].Port != "8009/tcp" {
		t.Errorf("tomcat HostsByPort[0].Port = %q, want %q", tomcat.HostsByPort[0].Port, "8009/tcp")
	}
	if len(tomcat.HostsByPort[0].IPs) != 1 || tomcat.HostsByPort[0].IPs[0] != "10.1.0.1" {
		t.Errorf("tomcat HostsByPort[0].IPs = %v, want [10.1.0.1]", tomcat.HostsByPort[0].IPs)
	}
	if tomcat.HostsByPort[1].Port != "8080/tcp" {
		t.Errorf("tomcat HostsByPort[1].Port = %q, want %q", tomcat.HostsByPort[1].Port, "8080/tcp")
	}
	if len(tomcat.HostsByPort[1].IPs) != 1 || tomcat.HostsByPort[1].IPs[0] != "10.1.0.2" {
		t.Errorf("tomcat HostsByPort[1].IPs = %v, want [10.1.0.2]", tomcat.HostsByPort[1].IPs)
	}

	// ── MS17 group ───────────────────────────────────────────────────────────
	if ms17.Name != "MS17-010 SMB Remote Code Execution" {
		t.Errorf("ms17 Name = %q, want %q", ms17.Name, "MS17-010 SMB Remote Code Execution")
	}
	if ms17.Category != "RCE" {
		t.Errorf("ms17 Category = %q, want %q", ms17.Category, "RCE")
	}
	if ms17.HostCount != 1 {
		t.Errorf("ms17 HostCount = %d, want 1", ms17.HostCount)
	}
	if len(ms17.CVEs) != 1 {
		t.Fatalf("ms17 CVEs len = %d, want 1", len(ms17.CVEs))
	}
	if ms17.CVEs[0].CVE != "CVE-2017-0144" {
		t.Errorf("ms17 CVEs[0].CVE = %q, want %q", ms17.CVEs[0].CVE, "CVE-2017-0144")
	}

	// ── Unsupported group ─────────────────────────────────────────────────────
	if unsupported.Name != "Microsoft Windows Server 2012 Unsupported" {
		t.Errorf("unsupported Name = %q, want %q", unsupported.Name, "Microsoft Windows Server 2012 Unsupported")
	}
	if unsupported.Category != "Outdated Software" {
		t.Errorf("unsupported Category = %q, want %q", unsupported.Category, "Outdated Software")
	}
	if unsupported.HostCount != 1 {
		t.Errorf("unsupported HostCount = %d, want 1", unsupported.HostCount)
	}
	if len(unsupported.CVEs) != 0 {
		t.Errorf("unsupported CVEs len = %d, want 0", len(unsupported.CVEs))
	}
	if len(unsupported.HostsByPort) != 0 {
		t.Errorf("unsupported HostsByPort len = %d, want 0", len(unsupported.HostsByPort))
	}
}
