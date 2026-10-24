package mdout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"layzmd/internal/ad"
	"layzmd/internal/nessus"
	"layzmd/internal/vuln"
)

var fixedSummary = Summary{
	ScanName:          "sample_scan",
	Generated:         "2026-07-09",
	Findings:          4,
	Hosts:             3,
	WithCVE:           3,
	VulnGroups:        4,
	Domains:           0,
	DomainControllers: 0,
}

func normCRLF(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

func TestRenderIndex_MatchesGolden(t *testing.T) {
	// Parse sample_scan.csv to compute the dynamic counts.
	f, err := os.Open("../../testdata/sample_scan.csv")
	if err != nil {
		t.Fatalf("open sample_scan.csv: %v", err)
	}
	defer f.Close()
	findings, err := nessus.Parse(f)
	if err != nil {
		t.Fatalf("parse sample_scan.csv: %v", err)
	}

	vg := vuln.Group(findings)
	adReport := ad.Analyze(findings)

	s := Summary{
		ScanName:          fixedSummary.ScanName,
		Generated:         fixedSummary.Generated,
		Findings:          fixedSummary.Findings,
		Hosts:             fixedSummary.Hosts,
		WithCVE:           fixedSummary.WithCVE,
		VulnGroups:        len(vg),
		Domains:           len(adReport.Domains),
		DomainControllers: len(adReport.DomainControllers),
	}

	raw, err := os.ReadFile("../../testdata/golden_index.md")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	golden := normCRLF(string(raw))
	got := normCRLF(RenderIndex(s))
	if got != golden {
		t.Errorf("RenderIndex mismatch\ngot:    %q\nwanted: %q", got, golden)
	}

	// Assert all four section wikilinks appear.
	for _, link := range []string{"[[Hosts]]", "[[Services]]", "[[Vulnerabilities]]", "[[AD]]"} {
		if !strings.Contains(got, link) {
			t.Errorf("RenderIndex missing wikilink %s", link)
		}
	}
}

func TestWriteIndex_WritesFile(t *testing.T) {
	dir := t.TempDir()
	if err := WriteIndex(dir, fixedSummary); err != nil {
		t.Fatalf("WriteIndex: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "index.md"))
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	got := normCRLF(string(raw))
	want := normCRLF(RenderIndex(fixedSummary))
	if got != want {
		t.Errorf("written file mismatch\ngot:    %q\nwanted: %q", got, want)
	}
}
