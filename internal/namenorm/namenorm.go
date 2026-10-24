// Package namenorm strips version numbers, ranges, and KB build numbers from a
// Nessus finding name to produce a stable (key, display) pair suitable for
// grouping findings by product + vulnerability class.
//
// Port of PTCompanion.Core.Analysis.NameNormalizer (C#).
package namenorm

import (
	"regexp"
	"strings"
)

// Pass 1 — parenthetical build/KB numbers: (4013389), (12345678), etc.
var rxKbParen = regexp.MustCompile(`\(\s*\d{4,}\s*\)`)

// Pass 2a — range phrases with their trailing version bound (case-insensitive):
//
//	"prior to 7.4.3"  "before 1.1.1d"  "through 1.0.2t"
//	"up to 7.85.0"   "and earlier 1.0.2"  "and prior 8.5.0"
var rxRangePhrase = regexp.MustCompile(`(?i)\b(?:prior\s+to|before|up\s+to|through|and\s+(?:earlier|prior))\b\s*v?\d+(?:\.\d+)*[a-z]?`)

// Pass 2b — comparison operators with dotted version bounds: "< 7.0.81"  ">= 1.0.2"
// Requires at least one dot (so bare integers like "SMBv1" are not touched).
var rxComparisonVersion = regexp.MustCompile(`[<>]=?\s*v?\d+(?:\.\d+)+[a-z]?`)

// Pass 3a — standalone dotted version tokens: "7.0.0"  "v1.1.1"  "1.0.2t"
// Requires at least one dot → lone integers (SMBv1, Windows 10) survive.
var rxDottedVersion = regexp.MustCompile(`\bv?\d+(?:\.\d+)+[a-z]?\b`)

// Pass 3b — wildcard version tokens: "4.x"  "1.x"
var rxWildcardVersion = regexp.MustCompile(`(?i)\b\d+\.x\b`)

// Pass 4 — dangling punctuation at token edges left by removals.
var rxDanglingPunct = regexp.MustCompile(`\s+([<>\-/,])\s+|\s+([<>\-/,])$|^([<>\-/,])\s+`)

// Pass 4 — collapse runs of whitespace.
var rxMultiSpace = regexp.MustCompile(`\s{2,}`)

// Normalize strips version/range/KB tokens from rawName and returns:
//   - display: cleaned string with original casing
//   - key:     strings.ToLower(display)
func Normalize(raw string) (key, display string) {
	if raw == "" {
		return "", ""
	}

	s := raw

	// Pass 1: remove parenthetical KB/build numbers.
	s = rxKbParen.ReplaceAllString(s, "")

	// Pass 2: remove range phrases (with their version bound) and comparison+version pairs.
	s = rxRangePhrase.ReplaceAllString(s, "")
	s = rxComparisonVersion.ReplaceAllString(s, "")

	// Pass 3: remove remaining standalone dotted versions and wildcard tokens.
	s = rxDottedVersion.ReplaceAllString(s, "")
	s = rxWildcardVersion.ReplaceAllString(s, "")

	// Pass 4: clean up dangling punctuation and collapse whitespace.
	s = rxDanglingPunct.ReplaceAllString(s, " ")
	s = rxMultiSpace.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)

	display = s
	key = strings.ToLower(display)
	return key, display
}
