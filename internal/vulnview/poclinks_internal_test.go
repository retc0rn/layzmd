package vulnview

import (
	"testing"

	"layzmd/internal/enrich"
)

func TestPocNucleiSplit(t *testing.T) {
	p := &enrich.PocResult{
		PocURLs: []string{"v"},
		Refs: []enrich.PocRef{
			{Source: "ExploitDB", URL: "e"},
			{Source: "Metasploit", URL: "m"},
			{Source: "Nuclei", URL: "n"},
		},
	}
	poc := pocLinks(p)
	nuc := nucleiLinks(p)
	if len(poc) != 3 || len(nuc) != 1 {
		t.Fatalf("poc=%d nuc=%d", len(poc), len(nuc))
	}
	want := []string{"VulnCheck", "ExploitDB", "Metasploit"}
	for i, w := range want {
		if poc[i].Label != w {
			t.Errorf("poc[%d].Label = %q, want %q", i, poc[i].Label, w)
		}
	}
	if nuc[0].Label != "Nuclei" || nuc[0].URL != "n" {
		t.Errorf("nuclei = %+v", nuc[0])
	}
}
