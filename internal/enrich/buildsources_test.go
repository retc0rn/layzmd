package enrich

import (
	"context"
	"time"

	"layzmd/internal/ratelimit"
	"testing"
)

// noSleepClock returns a Clock whose Sleep returns immediately (no real delay).
func noSleepClock() ratelimit.Clock {
	return ratelimit.Clock{
		Now: time.Now,
		Sleep: func(_ context.Context, _ time.Duration) error {
			return nil
		},
	}
}

// TestBuildSources_AllSourcesConstructed checks that BuildSources returns
// four non-nil sources for both the no-key and keyed NVD branches.
func TestBuildSources_AllSourcesConstructed(t *testing.T) {
	clk := noSleepClock()
	g := &fakeGetter{}

	tests := []struct {
		name   string
		nvdKey string
	}{
		{"no key", ""},
		{"with key", "myapikey"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := BuildSources(g, tc.nvdKey, clk)
			if s.Kev == nil {
				t.Error("Sources.Kev is nil")
			}
			if s.Epss == nil {
				t.Error("Sources.Epss is nil")
			}
			if s.Nvd == nil {
				t.Error("Sources.Nvd is nil")
			}
			if s.Poc == nil {
				t.Error("Sources.Poc is nil")
			}
		})
	}
}
