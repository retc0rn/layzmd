package websurface

import (
	"regexp"
	"strings"
)

var schemeHostRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+`)

// urlPath reduces a URL (or already-relative path) to its host-relative path.
// "http://h:8443/a/b" -> "/a/b"; "host/x" -> "/x"; bare host -> "/".
func urlPath(raw string) string {
	s := strings.TrimSpace(raw)
	if loc := schemeHostRe.FindStringIndex(s); loc != nil {
		s = s[loc[1]:]
	} else if !strings.HasPrefix(s, "/") {
		if i := strings.Index(s, "/"); i >= 0 {
			s = s[i:]
		} else {
			s = "/"
		}
	}
	if s == "" {
		s = "/"
	}
	return s
}

// splitPaths splits a possibly comma-separated path line ("/a, /b, /c") into
// individual "/"-prefixed paths.
func splitPaths(line string) []string {
	var out []string
	for _, tok := range strings.Split(line, ",") {
		t := strings.TrimSpace(tok)
		if strings.HasPrefix(t, "/") {
			out = append(out, t)
		}
	}
	return out
}

// parseListPaths returns paths appearing after the first line containing header,
// stopping at the blank line after the paths. Comma-separated lines are split.
func parseListPaths(out, header string) []string {
	var res []string
	started := false
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		if !started {
			if strings.Contains(ln, header) {
				started = true
			}
			continue
		}
		if strings.HasPrefix(t, "/") {
			res = append(res, splitPaths(t)...)
		} else if len(res) > 0 && t == "" {
			break
		}
	}
	return res
}

var methodsLineRe = regexp.MustCompile(`(?i)HTTP methods\s+(.+?)\s+are allowed on`)

// parseMethodsBlocks parses "HTTP methods X Y Z are allowed on :\n\n /a\n /b"
// blocks into DirEntry rows. Multi-line method lists are joined until
// "allowed on".
func parseMethodsBlocks(out string) []DirEntry {
	lines := strings.Split(out, "\n")
	var res []DirEntry
	for i := 0; i < len(lines); i++ {
		if !strings.Contains(strings.ToLower(lines[i]), "http methods") {
			continue
		}
		hdr := strings.TrimSpace(lines[i])
		j := i
		for !strings.Contains(strings.ToLower(hdr), "allowed on") && j+1 < len(lines) {
			j++
			hdr += " " + strings.TrimSpace(lines[j])
		}
		m := methodsLineRe.FindStringSubmatch(hdr)
		if m == nil {
			i = j
			continue
		}
		methods := strings.Fields(m[1])
		for k := j + 1; k < len(lines); k++ {
			t := strings.TrimSpace(lines[k])
			if strings.HasPrefix(t, "/") {
				for _, p := range splitPaths(t) {
					res = append(res, DirEntry{Path: p, Methods: methods})
				}
			} else if t == "" {
				if hasPathAfterBlank(lines, k) {
					continue
				}
				i = k
				break
			} else {
				i = k
				break
			}
		}
	}
	return res
}

func hasPathAfterBlank(lines []string, k int) bool {
	for k++; k < len(lines); k++ {
		t := strings.TrimSpace(lines[k])
		if t == "" {
			continue
		}
		return strings.HasPrefix(t, "/")
	}
	return false
}

var schemeRe = regexp.MustCompile(`(?i)protected by the (\w+) authentication scheme`)

// parseProtectedPages parses Protected Web Page Detection output into AuthPages.
func parseProtectedPages(out string) []AuthPage {
	scheme := "Unknown"
	if m := schemeRe.FindStringSubmatch(out); m != nil {
		w := m[1]
		scheme = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
	}
	var res []AuthPage
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "/") {
			res = append(res, AuthPage{Path: t, Scheme: scheme})
		}
	}
	return res
}
