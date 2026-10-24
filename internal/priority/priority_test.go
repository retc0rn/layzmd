package priority

import "testing"

func ptr(f float64) *float64 { return &f }

func TestSeverityPoints(t *testing.T) {
	tests := []struct {
		risk string
		want int
	}{
		{"critical", 4},
		{"HIGH", 3},
		{"Medium", 2},
		{"low", 1},
		{"info", 0},
		{"", 0},
		{"None", 0},
	}
	for _, tc := range tests {
		if got := SeverityPoints(tc.risk); got != tc.want {
			t.Errorf("SeverityPoints(%q) = %d, want %d", tc.risk, got, tc.want)
		}
	}
}

func TestEpssPoints(t *testing.T) {
	tests := []struct {
		percentile *float64
		want       int
	}{
		{nil, 0},          // no EPSS data
		{ptr(0.95), 4},   // >=0.90
		{ptr(0.90), 4},   // exactly 0.90
		{ptr(0.70), 3},   // exactly 0.70
		{ptr(0.40), 2},   // exactly 0.40
		{ptr(0.10), 1},   // below 0.40 → 1 (C# else branch returns 1, not 0)
		{ptr(0.30), 1},   // below 0.40 → 1
	}
	for _, tc := range tests {
		if got := EpssPoints(tc.percentile); got != tc.want {
			t.Errorf("EpssPoints(%v) = %d, want %d", tc.percentile, got, tc.want)
		}
	}
}

func TestKevPoints(t *testing.T) {
	if got := KevPoints(true); got != 4 {
		t.Errorf("KevPoints(true) = %d, want 4", got)
	}
	if got := KevPoints(false); got != 0 {
		t.Errorf("KevPoints(false) = %d, want 0", got)
	}
}

func TestLabel(t *testing.T) {
	tests := []struct {
		risk  string
		epss  *float64
		inKev bool
		want  string
	}{
		// Four full combos from task brief
		{"Critical", ptr(0.95), true, "urgent"},  // 4+4+4=12
		{"High", nil, true, "high"},              // 3+0+4=7
		{"Medium", ptr(0.75), false, "medium"},   // 2+3+0=5
		{"Low", nil, false, "low"},               // 1+0+0=1
		{"None", nil, false, "low"},              // 0+0+0=0
		// Additional cases from C# test suite
		{"Critical", nil, false, "medium"},       // 4+0+0=4
		{"High", ptr(0.75), false, "medium"},     // 3+3+0=6
		{"Medium", ptr(0.50), false, "medium"},   // 2+2+0=4
		{"", ptr(0.30), false, "low"},            // 0+1+0=1
		// EPSS tier boundary checks (with Low=1 as base to isolate EPSS contribution)
		{"Low", ptr(0.90), false, "medium"},      // 1+4+0=5
		{"Low", ptr(0.70), false, "medium"},      // 1+3+0=4
		{"Low", ptr(0.40), false, "low"},         // 1+2+0=3
		{"Low", ptr(0.10), false, "low"},         // 1+1+0=2
		// nil EPSS with various severities
		{"High", nil, false, "low"},              // 3+0+0=3
		{"Medium", nil, false, "low"},            // 2+0+0=2
		// Label band boundary: score=10 → urgent
		{"Critical", ptr(0.95), true, "urgent"},  // 4+4+4=12 (duplicate, confirms >=10)
		// Label band boundary: score=7 → high
		{"High", nil, true, "high"},              // 3+0+4=7 (duplicate, confirms >=7)
		// Label band boundary: score=4 → medium
		{"Critical", nil, false, "medium"},       // 4+0+0=4 (duplicate, confirms >=4)
	}

	for _, tc := range tests {
		if got := Label(tc.risk, tc.epss, tc.inKev); got != tc.want {
			t.Errorf("Label(%q, epss=%v, kev=%v) = %q, want %q",
				tc.risk, tc.epss, tc.inKev, got, tc.want)
		}
	}
}
