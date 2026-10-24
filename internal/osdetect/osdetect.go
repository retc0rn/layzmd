// Package osdetect extracts an OS string from Nessus plugin output text.
package osdetect

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	reRemote = regexp.MustCompile(`(?i)Remote operating system\s*:\s*(.+)`)
	reIs     = regexp.MustCompile(`(?i)The remote Operating System is\s*:\s*(.+)`)
	reOS     = regexp.MustCompile(`(?i)Operating System\s*:\s*(.+)`)
)

// FromPluginOutput tries to extract an OS string from Nessus plugin output.
// It tries three patterns in order and returns the first match, trimmed and
// cut at the first newline. Returns "" if no pattern matches.
func FromPluginOutput(out string) string {
	for _, re := range []*regexp.Regexp{reRemote, reIs, reOS} {
		m := re.FindStringSubmatch(out)
		if m == nil {
			continue
		}
		capture := m[1]
		// Cut at first newline.
		if idx := strings.IndexAny(capture, "\r\n"); idx >= 0 {
			capture = capture[:idx]
		}
		capture = strings.TrimSpace(capture)
		// Guard against degenerate captures (e.g. plugin 10785 emits
		// "The remote Operating System is : (" → a bare "("). A real OS
		// string always contains a letter; treat letterless captures as no
		// match and try the next pattern.
		if !hasLetter(capture) {
			continue
		}
		return capture
	}
	return ""
}

// hasLetter reports whether s contains at least one Unicode letter.
func hasLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}
