package enrich

import (
	"context"
	"fmt"
	"testing"
)

func TestRecomputeHasPoc(t *testing.T) {
	nuc := PocResult{Refs: []PocRef{{Source: "Nuclei", URL: "u"}}}
	nuc.recomputeHasPoc()
	if nuc.HasPoc {
		t.Error("Nuclei-only must NOT be HasPoc")
	}
	edb := PocResult{Refs: []PocRef{{Source: "ExploitDB", URL: "u"}}}
	edb.recomputeHasPoc()
	if !edb.HasPoc {
		t.Error("ExploitDB must be HasPoc")
	}
	empty := PocResult{}
	empty.recomputeHasPoc()
	if empty.HasPoc {
		t.Error("empty PocResult must NOT be HasPoc")
	}
}

const vulncheckJSON = `{"data":[{"url":"https://a/1"},{"url":"https://a/2"}]}`

// TestPoc_Basic checks the normal happy path: VulnCheck succeeds.
func TestPoc_Basic(t *testing.T) {
	clk := testClock()
	fg := new(fakeGetter).add("vulncheck.com", vulncheckJSON, nil)
	src := NewPocSource(fg, testLimiter(clk), clk)

	res := src.Fetch(context.Background(), "CVE-2021-1")

	if !res.HasPoc {
		t.Error("want HasPoc=true")
	}
	if len(res.PocURLs) != 2 {
		t.Fatalf("want 2 URLs, got %d: %v", len(res.PocURLs), res.PocURLs)
	}
	if res.PocURLs[0] != "https://a/1" || res.PocURLs[1] != "https://a/2" {
		t.Errorf("unexpected URLs: %v", res.PocURLs)
	}
	if res.Error != "" {
		t.Errorf("want empty Error, got %q", res.Error)
	}
}

// TestPoc_First5 checks that only the first 5 VulnCheck URLs are kept.
func TestPoc_First5(t *testing.T) {
	clk := testClock()
	const sevenURLs = `{"data":[{"url":"https://a/1"},{"url":"https://a/2"},{"url":"https://a/3"},{"url":"https://a/4"},{"url":"https://a/5"},{"url":"https://a/6"},{"url":"https://a/7"}]}`
	fg := new(fakeGetter).add("vulncheck.com", sevenURLs, nil)
	src := NewPocSource(fg, testLimiter(clk), clk)

	res := src.Fetch(context.Background(), "CVE-2021-1")

	if len(res.PocURLs) != 5 {
		t.Errorf("want 5 URLs, got %d", len(res.PocURLs))
	}
	if !res.HasPoc {
		t.Error("want HasPoc=true")
	}
}

// TestPoc_VulncheckErrorCaptured checks that a VulnCheck error is stored in
// Error and leaves HasPoc false when there is no exploit source.
func TestPoc_VulncheckErrorCaptured(t *testing.T) {
	clk := testClock()
	fg := new(fakeGetter).add("vulncheck.com", "", fmt.Errorf("connection refused"))
	src := NewPocSource(fg, testLimiter(clk), clk)

	res := src.Fetch(context.Background(), "CVE-2021-1")

	if res.Error == "" {
		t.Error("want non-empty Error when VulnCheck fails")
	}
	if res.HasPoc {
		t.Error("want HasPoc=false")
	}
}
