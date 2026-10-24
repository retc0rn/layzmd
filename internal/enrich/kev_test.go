package enrich

import (
	"context"
	"fmt"
	"testing"
)

const kevJSON = `{"vulnerabilities":[{"cveID":"CVE-2017-0144"},{"cveID":"not-a-cve"},{"cveID":"cve-2019-0708"}]}`

// TestKev_Parse checks regex filtering and upper-casing of CVE IDs.
func TestKev_Parse(t *testing.T) {
	clk := testClock()
	fg := new(fakeGetter).add("cisa.gov", kevJSON, nil)
	src := NewKevSource(fg, clk)

	ctx := context.Background()
	set, err := src.Fetch(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(set) != 2 {
		t.Errorf("want 2 entries, got %d", len(set))
	}
	if _, ok := set["CVE-2017-0144"]; !ok {
		t.Error("missing CVE-2017-0144")
	}
	// cve-2019-0708 should be upper-cased to CVE-2019-0708
	if _, ok := set["CVE-2019-0708"]; !ok {
		t.Error("missing CVE-2019-0708 (should be upper-cased)")
	}
	if _, ok := set["not-a-cve"]; ok {
		t.Error("not-a-cve should have been filtered out")
	}
}

// TestKev_ErrorEmpty checks that a network error returns an empty set and no error.
func TestKev_ErrorEmpty(t *testing.T) {
	clk := testClock()
	fg := new(fakeGetter).add("cisa.gov", "", fmt.Errorf("connection refused"))
	src := NewKevSource(fg, clk)

	ctx := context.Background()
	set, err := src.Fetch(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(set) != 0 {
		t.Errorf("want empty set, got %d entries", len(set))
	}
}
