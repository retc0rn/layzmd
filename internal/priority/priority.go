// Package priority computes a priority label for a vulnerability from
// severity, EPSS percentile, and KEV membership. It is a faithful port of
// PTCompanion.Core.Enrichment.PriorityCalc (C#).
package priority

import "strings"

// SeverityPoints maps a Nessus risk string to severity score points.
// Comparison is case-insensitive. Unknown values return 0.
func SeverityPoints(risk string) int {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// EpssPoints maps an EPSS percentile to score points.
// nil means no EPSS data available and returns 0.
// NOTE: the C# source returns 1 for percentile < 0.40 (not 0).
// This matches the C# exactly: >=0.90→4, >=0.70→3, >=0.40→2, else→1.
func EpssPoints(percentile *float64) int {
	if percentile == nil {
		return 0
	}
	p := *percentile
	if p >= 0.90 {
		return 4
	}
	if p >= 0.70 {
		return 3
	}
	if p >= 0.40 {
		return 2
	}
	return 1
}

// KevPoints returns 4 if the vulnerability is in CISA KEV, else 0.
func KevPoints(inKev bool) int {
	if inKev {
		return 4
	}
	return 0
}

// Label computes a priority label from severity, EPSS percentile, and KEV
// membership. Score = SeverityPoints + EpssPoints + KevPoints.
// >=10 → "urgent"; >=7 → "high"; >=4 → "medium"; else → "low".
func Label(risk string, epssPercentile *float64, inKev bool) string {
	score := SeverityPoints(risk) + EpssPoints(epssPercentile) + KevPoints(inKev)
	if score >= 10 {
		return "urgent"
	}
	if score >= 7 {
		return "high"
	}
	if score >= 4 {
		return "medium"
	}
	return "low"
}
