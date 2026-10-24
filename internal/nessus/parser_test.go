package nessus

import (
	"os"
	"strings"
	"testing"
)

func TestParse_SampleCSV(t *testing.T) {
	f, err := os.Open("../../testdata/sample_scan.csv")
	if err != nil {
		t.Fatalf("open testdata: %v", err)
	}
	defer f.Close()

	findings, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Empty-host row must be skipped → 4 findings.
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	// Finding 0: Apache Tomcat AJP
	f0 := findings[0]
	checks := []struct {
		field, got, want string
	}{
		{"HostIP", f0.HostIP, "10.20.1.11"},
		{"Port", f0.Port, "8009"},
		{"Protocol", f0.Protocol, "tcp"},
		{"CVE", f0.CVE, "CVE-2020-1938"},
		{"CVSS", f0.CVSS, "9.8"},
		{"Risk", f0.Risk, "Critical"},
		{"Name", f0.Name, "Apache Tomcat AJP"},
		{"Service", f0.Service, "ajp13"},
		{"SeeAlso", f0.SeeAlso, "https://example.invalid/a"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("findings[0].%s = %q, want %q", c.field, c.got, c.want)
		}
	}

	// Finding 1: OpenSSL — v2 CVSS fallback, raw multi-CVE cell.
	f1 := findings[1]
	if f1.CVSS != "7.5" {
		t.Errorf("findings[1].CVSS = %q, want %q (v2 fallback)", f1.CVSS, "7.5")
	}
	if f1.CVE != "CVE-2016-2107,CVE-2016-2108" {
		t.Errorf("findings[1].CVE = %q, want raw multi-CVE cell", f1.CVE)
	}

	// Finding 2: Windows Server 2012 Unsupported — port 0, blank risk → "None", no CVSS.
	f2 := findings[2]
	if f2.Port != "0" {
		t.Errorf("findings[2].Port = %q, want %q", f2.Port, "0")
	}
	if f2.Risk != "None" {
		t.Errorf("findings[2].Risk = %q, want %q (blank → None)", f2.Risk, "None")
	}
	if f2.CVSS != "" {
		t.Errorf("findings[2].CVSS = %q, want empty", f2.CVSS)
	}
}

func TestParse_DetectedOS(t *testing.T) {
	const csv = `Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Detected OS,Plugin Output,Service
10001,,,None,10.20.4.7,tcp,3389,RDP Detection,Microsoft Windows Server 2019,,ms-wbt-server
10004,,,None,10.20.3.14,tcp,22,SSH,,Operating System : Ubuntu 20.04,ssh
`
	findings, err := Parse(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].DetectedOS != "Microsoft Windows Server 2019" {
		t.Errorf("findings[0].DetectedOS = %q, want %q", findings[0].DetectedOS, "Microsoft Windows Server 2019")
	}
	if findings[1].DetectedOS != "" {
		t.Errorf("findings[1].DetectedOS = %q, want empty", findings[1].DetectedOS)
	}
	// SP1 sample has no Detected OS column — DetectedOS must be empty.
	f, err2 := os.Open("../../testdata/sample_scan.csv")
	if err2 != nil {
		t.Fatalf("open sample_scan.csv: %v", err2)
	}
	defer f.Close()
	sp1, err2 := Parse(f)
	if err2 != nil {
		t.Fatalf("Parse SP1: %v", err2)
	}
	for i, fi := range sp1 {
		if fi.DetectedOS != "" {
			t.Errorf("SP1 findings[%d].DetectedOS = %q, want empty", i, fi.DetectedOS)
		}
	}
}

func TestParse_HeaderOrderIndependence(t *testing.T) {
	// Reordered columns with renamed headers: IP Address, Risk Factor, CVSS Base Score.
	const variant = `IP Address,Risk Factor,CVSS Base Score,Plugin ID,Protocol,Port,Name,CVE,Synopsis,Description,Solution,See Also,Plugin Output,Service
10.20.1.11,Critical,9.8,100001,tcp,8009,Apache Tomcat AJP,CVE-2020-1938,Ghostcat,AJP request injection,Upgrade Tomcat,https://example.invalid/a,out1,ajp13
`
	findings, err := Parse(strings.NewReader(variant))
	if err != nil {
		t.Fatalf("Parse variant: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from variant, got %d", len(findings))
	}

	f := findings[0]
	if f.HostIP != "10.20.1.11" {
		t.Errorf("HostIP = %q, want 10.20.1.11", f.HostIP)
	}
	if f.Risk != "Critical" {
		t.Errorf("Risk = %q, want Critical", f.Risk)
	}
	if f.CVSS != "9.8" {
		t.Errorf("CVSS = %q, want 9.8 (via 'cvss base score')", f.CVSS)
	}
	if f.CVE != "CVE-2020-1938" {
		t.Errorf("CVE = %q, want CVE-2020-1938", f.CVE)
	}
	if f.Name != "Apache Tomcat AJP" {
		t.Errorf("Name = %q, want Apache Tomcat AJP", f.Name)
	}
}
