package mdout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"layzmd/internal/ad"
	"layzmd/internal/nessus"
)

func adTestReport() ad.Report {
	return ad.Report{
		ScanName:  "T",
		Generated: "2026-07-11",
		Domains: []ad.Domain{
			{Name: "corp.local", Confidence: "High", Hosts: 3, Sources: []string{"DNS domain name"}},
		},
	}
}

func TestADSectionNotes_OnlyPopulated(t *testing.T) {
	notes := adSectionNotes(adTestReport())
	if len(notes) != 1 {
		t.Fatalf("len(notes) = %d, want 1 (only Domains populated)", len(notes))
	}
	if notes[0].title != "Domains" {
		t.Errorf("title = %q, want Domains", notes[0].title)
	}
	if notes[0].path != "AD/Domains.md" {
		t.Errorf("path = %q, want AD/Domains.md", notes[0].path)
	}
	if notes[0].count != 1 {
		t.Errorf("count = %d, want 1", notes[0].count)
	}
}

func TestRenderADIndex_Golden(t *testing.T) {
	got := normalizeNewlines(RenderADIndex(adTestReport()))
	want := readGolden(t, "golden_ad_index.md")
	if got != want {
		t.Errorf("AD index mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderADSectionNote_Golden(t *testing.T) {
	r := adTestReport()
	s := adSectionNotes(r)[0]
	got := normalizeNewlines(renderADSectionNote(s, r.ScanName))
	want := readGolden(t, "golden_ad_section.md")
	if got != want {
		t.Errorf("AD section note mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestWriteAD_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	r := adTestReport()
	if err := os.MkdirAll(filepath.Join(dir, "AD"), 0o755); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(dir, "AD", "stale.md")
	if err := os.WriteFile(stray, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteAD(dir, r); err != nil {
		t.Fatalf("WriteAD: %v", err)
	}
	if _, err := os.Stat(stray); err == nil {
		t.Error("stray file not cleared")
	}
	if _, err := os.Stat(filepath.Join(dir, "AD", "Domains.md")); err != nil {
		t.Error("no Domains section note")
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "AD.md"))
	if !strings.Contains(string(idx), "[[AD/Domains\\|Domains]]") {
		t.Errorf("index link missing in:\n%s", idx)
	}
}

// TestWriteAD_SampleAD_Smoke runs the real sample_ad fixture end-to-end and
// verifies every index link resolves to an emitted section note.
func TestWriteAD_SampleAD_Smoke(t *testing.T) {
	f, err := os.Open("../../testdata/sample_ad.csv")
	if err != nil {
		t.Fatalf("open sample_ad.csv: %v", err)
	}
	defer f.Close()
	findings, err := nessus.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := ad.Analyze(findings)
	r.ScanName = "sample_ad"
	r.Generated = "2026-07-10"

	dir := t.TempDir()
	if err := WriteAD(dir, r); err != nil {
		t.Fatalf("WriteAD: %v", err)
	}
	idx, err := os.ReadFile(filepath.Join(dir, "AD.md"))
	if err != nil {
		t.Fatalf("read AD.md: %v", err)
	}
	notes := adSectionNotes(r)
	if len(notes) == 0 {
		t.Fatal("sample_ad produced no AD sections")
	}
	// Every section note exists on disk and is linked from the index.
	for _, n := range notes {
		p := filepath.Join(dir, filepath.FromSlash(n.path))
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing section note %s", n.path)
		}
		linkTarget := strings.TrimSuffix(n.path, ".md")
		if !strings.Contains(string(idx), "[["+linkTarget+"\\|"+n.title+"]]") {
			t.Errorf("index missing link to %q", n.title)
		}
	}
}

func TestSP11_Renderers(t *testing.T) {
	// SMB Signing: IP-only code block, no FQDN/Port columns.
	smb := renderSMBSigningGrouped([]ad.SMBSigningRow{
		{Domain: "corp", IP: "10.0.0.2", FQDN: "a.corp", Port: "445"},
		{Domain: "corp", IP: "10.0.0.10", FQDN: "b.corp", Port: "445"},
	})
	if strings.Contains(smb, "a.corp") || strings.Contains(smb, "| IP |") {
		t.Errorf("SMB signing should be IP-only, got:\n%s", smb)
	}
	if !strings.Contains(smb, "```\n10.0.0.2\n10.0.0.10\n```") {
		t.Errorf("SMB signing IP block wrong:\n%s", smb)
	}

	// SCCM: RCA hosts separated into their own IP block.
	sccm := renderSccmGrouped([]ad.SccmRow{
		{Domain: "corp", Role: "management_point", IP: "10.0.0.5", FQDN: "mp.corp"},
		{Domain: "corp", Role: "remote_control_agent", IP: "10.0.0.20"},
		{Domain: "corp", Role: "remote_control_agent", IP: "10.0.0.21"},
	})
	if !strings.Contains(sccm, "management_point") {
		t.Error("SCCM primary table missing management_point")
	}
	if !strings.Contains(sccm, "### Remote Control Agent Hosts") {
		t.Error("SCCM missing RCA sub-section")
	}
	// RCA IPs must NOT appear in the primary table rows.
	primary := sccm[:strings.Index(sccm, "### Remote Control Agent Hosts")]
	if strings.Contains(primary, "10.0.0.20") {
		t.Error("RCA IP leaked into primary SCCM table")
	}

	// Infra services: sub-heading + IP code block, not a joined table cell.
	svc := renderServices([]ad.ServiceRow{
		{Service: "Global Catalog", Hosts: []string{"10.0.0.2", "10.0.0.1"}, Detail: "GC"},
	})
	if !strings.Contains(svc, "### Global Catalog") || !strings.Contains(svc, "```\n10.0.0.1\n10.0.0.2\n```") {
		t.Errorf("infra services rendering wrong:\n%s", svc)
	}

	// ADCS: one combined section with two sub-headings.
	adcs := renderAdcs(
		[]ad.AdcsCARow{{Domain: "corp", IP: "10.0.0.3"}},
		[]ad.AdcsEndpointRow{{Domain: "corp", IP: "10.0.0.4"}},
	)
	if !strings.Contains(adcs, "## Certificate Authorities") || !strings.Contains(adcs, "## Enrollment Endpoints") {
		t.Errorf("ADCS combined section wrong:\n%s", adcs)
	}
}

func TestWriteDefensiveAndCreds(t *testing.T) {
	dir := t.TempDir()
	r := ad.Report{
		ScanName:     "T",
		Defensive:    []ad.DefensiveRow{{Category: "EDR", Product: "CrowdStrike", Hosts: 3}},
		EmailSummary: []ad.EmailSummary{{Source: "web_harvest", Emails: 2, SourceHosts: 1}},
		Emails:       []ad.EmailRow{{Email: "a@corp.com", Source: "web_harvest"}},
	}
	if err := WriteDefensive(dir, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteCreds(dir, r); err != nil {
		t.Fatal(err)
	}
	// Defensive.md at top level.
	if b, err := os.ReadFile(filepath.Join(dir, "Defensive.md")); err != nil {
		t.Error("no Defensive.md")
	} else if !strings.Contains(string(b), "# Defensive Technology") || !strings.Contains(string(b), "CrowdStrike") {
		t.Errorf("Defensive.md content wrong:\n%s", b)
	}
	// Creds folder + index + email note.
	if _, err := os.Stat(filepath.Join(dir, "Usernames - Creds", "Email Addresses.md")); err != nil {
		t.Error("no Email Addresses note in Creds folder")
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "Usernames - Creds.md"))
	if !strings.Contains(string(idx), "[[Usernames - Creds/Email Addresses\\|Email Addresses]]") {
		t.Errorf("Creds index link missing:\n%s", idx)
	}

	// Empty report removes stale files.
	empty := ad.Report{ScanName: "T"}
	if err := WriteDefensive(dir, empty); err != nil {
		t.Fatal(err)
	}
	if err := WriteCreds(dir, empty); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "Defensive.md")); err == nil {
		t.Error("stale Defensive.md not removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "Usernames - Creds.md")); err == nil {
		t.Error("stale Creds index not removed")
	}
}

func TestRenderIndex_ConditionalLinks(t *testing.T) {
	withBoth := RenderIndex(Summary{ScanName: "T", HasDefensive: true, HasCreds: true})
	if !strings.Contains(withBoth, "[[Defensive]]") || !strings.Contains(withBoth, "[[Usernames - Creds]]") {
		t.Error("expected Defensive + Creds links")
	}
	without := RenderIndex(Summary{ScanName: "T"})
	if strings.Contains(without, "[[Defensive]]") || strings.Contains(without, "[[Usernames - Creds]]") {
		t.Error("links should be absent when flags false")
	}
}
