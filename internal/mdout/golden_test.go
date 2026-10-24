package mdout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// normalizeNewlines converts CRLF to LF so golden comparisons are stable across
// platforms (git may check out golden files with CRLF on Windows).
func normalizeNewlines(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

// readGolden reads a golden file from the repo-root testdata dir and returns it
// with newlines normalized.
func readGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return normalizeNewlines(string(b))
}
