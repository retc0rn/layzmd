package enrich

import (
	"context"
	"fmt"
	"testing"
)

// nvdJSON includes weaknesses (for CWE parsing) and descriptions (for description parsing).
// es entry comes first to verify lang=="en" selection picks the right one.
const nvdJSON = `{"vulnerabilities":[{"cve":{"weaknesses":[{"description":[{"value":"CWE-79"},{"value":"CWE-79"},{"value":"NVD-CWE-Other"}]}],"descriptions":[{"lang":"es","value":"Inyeccion"},{"lang":"en","value":"AJP request injection."}]}}]}`

// nvdJSONNoDesc has weaknesses but no descriptions array.
const nvdJSONNoDesc = `{"vulnerabilities":[{"cve":{"weaknesses":[{"description":[{"value":"CWE-79"}]}]}}]}`

// TestNvd_Parse checks CWE dedup and filtering of non-CWE-\d+ values.
func TestNvd_Parse(t *testing.T) {
	clk := testClock()
	fg := new(fakeGetter).add("nvd.nist.gov", nvdJSON, nil)
	src := NewNvdSource(fg, "", testLimiter(clk), clk)

	ctx := context.Background()
	got, err := src.Fetch(ctx, "CVE-2021-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// CWE-79 appears twice → deduped to one; NVD-CWE-Other → filtered out
	if len(got.CWEs) != 1 {
		t.Fatalf("want 1 CWE, got %d: %v", len(got.CWEs), got.CWEs)
	}
	if got.CWEs[0] != "CWE-79" {
		t.Errorf("want CWE-79, got %s", got.CWEs[0])
	}
}

// TestNvd_Description checks that the en description is picked, not es.
func TestNvd_Description(t *testing.T) {
	clk := testClock()
	fg := new(fakeGetter).add("nvd.nist.gov", nvdJSON, nil)
	src := NewNvdSource(fg, "", testLimiter(clk), clk)

	ctx := context.Background()
	got, err := src.Fetch(ctx, "CVE-2021-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Description != "AJP request injection." {
		t.Errorf("want Description=%q, got %q", "AJP request injection.", got.Description)
	}
}

// TestNvd_NoDescriptions checks that Description is "" when no descriptions array is present.
func TestNvd_NoDescriptions(t *testing.T) {
	clk := testClock()
	fg := new(fakeGetter).add("nvd.nist.gov", nvdJSONNoDesc, nil)
	src := NewNvdSource(fg, "", testLimiter(clk), clk)

	ctx := context.Background()
	got, err := src.Fetch(ctx, "CVE-2021-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Description != "" {
		t.Errorf("want empty Description, got %q", got.Description)
	}
}

// TestNvd_ApiKeyHeader checks that the apiKey header is sent when a key is set
// and absent when no key is set.
func TestNvd_ApiKeyHeader(t *testing.T) {
	clk := testClock()

	t.Run("with_key", func(t *testing.T) {
		fg := new(fakeGetter).add("nvd.nist.gov", nvdJSON, nil)
		src := NewNvdSource(fg, "my-secret-key", testLimiter(clk), clk)

		_, err := src.Fetch(context.Background(), "CVE-2021-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if fg.lastHeaders == nil {
			t.Fatal("expected headers to be recorded")
		}
		if fg.lastHeaders["apiKey"] != "my-secret-key" {
			t.Errorf("want apiKey header 'my-secret-key', got %q", fg.lastHeaders["apiKey"])
		}
	})

	t.Run("without_key", func(t *testing.T) {
		fg := new(fakeGetter).add("nvd.nist.gov", nvdJSON, nil)
		src := NewNvdSource(fg, "", testLimiter(clk), clk)

		_, err := src.Fetch(context.Background(), "CVE-2021-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// No key configured -> the source passes a nil headers map. Assert that
		// directly so a regression sending a (non-nil) headers map is caught,
		// rather than silently skipped.
		if fg.lastHeaders != nil {
			t.Errorf("expected nil headers for anonymous NVD request, got %v", fg.lastHeaders)
		}
	})
}

// TestNvd_ErrorEmpty checks that a network error returns empty NvdData and no error.
func TestNvd_ErrorEmpty(t *testing.T) {
	clk := testClock()
	fg := new(fakeGetter).add("nvd.nist.gov", "", fmt.Errorf("timeout"))
	src := NewNvdSource(fg, "", testLimiter(clk), clk)

	ctx := context.Background()
	got, err := src.Fetch(ctx, "CVE-2021-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.CWEs) != 0 {
		t.Errorf("want empty CWEs, got %v", got.CWEs)
	}
	if got.Description != "" {
		t.Errorf("want empty Description, got %q", got.Description)
	}
}
