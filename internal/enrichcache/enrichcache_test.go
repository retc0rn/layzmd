package enrichcache_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"layzmd/internal/enrichcache"
)

// makeNow returns a controllable now function backed by a *time.Time pointer.
func makeNow(t0 time.Time) (*time.Time, func() time.Time) {
	cur := t0
	return &cur, func() time.Time { return cur }
}

func TestPutGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, nowFn := makeNow(t0)

	c, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}

	if err := c.Put("CVE-2021-1", "poc", map[string]any{"has_poc": true}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	raw, ok := c.Get("CVE-2021-1", "poc")
	if !ok {
		t.Fatal("Get: expected ok=true")
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if result["has_poc"] != true {
		t.Errorf("has_poc: got %v, want true", result["has_poc"])
	}
}

func TestGet_Miss(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, nowFn := makeNow(t0)

	c, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}

	_, ok := c.Get("CVE-X", "core")
	if ok {
		t.Fatal("Get on empty cache: expected ok=false")
	}
}

func TestTTL_CoreExpires(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	curTime, nowFn := makeNow(t0)

	c, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}

	if err := c.Put("CVE-C", "core", map[string]any{"val": 1}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// At T0+23h → still fresh
	*curTime = t0.Add(23 * time.Hour)
	_, ok := c.Get("CVE-C", "core")
	if !ok {
		t.Error("expected fresh at T0+23h")
	}

	// At T0+24h+1s → stale
	*curTime = t0.Add(24*time.Hour + time.Second)
	_, ok = c.Get("CVE-C", "core")
	if ok {
		t.Error("expected stale at T0+24h+1s")
	}
}

func TestTTL_NvdLong(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	curTime, nowFn := makeNow(t0)

	c, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}

	if err := c.Put("CVE-NVD", "nvd", map[string]any{"cwes": []string{"CWE-79"}}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// At T0+29d → fresh
	*curTime = t0.Add(29 * 24 * time.Hour)
	_, ok := c.Get("CVE-NVD", "nvd")
	if !ok {
		t.Error("expected fresh at T0+29d")
	}

	// At T0+31d → stale (past 30d TTL)
	*curTime = t0.Add(31 * 24 * time.Hour)
	_, ok = c.Get("CVE-NVD", "nvd")
	if ok {
		t.Error("expected stale at T0+31d")
	}
}

func TestStaleAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, nowFn := makeNow(t0)

	// Put+Save with staleAll=false
	c, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	if err := c.Put("CVE-S", "poc", map[string]any{"val": 1}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reopen with staleAll=true → Get must return false even though entry is recent
	c2, err := enrichcache.OpenAt(path, nowFn, true)
	if err != nil {
		t.Fatalf("OpenAt staleAll=true: %v", err)
	}
	_, ok := c2.Get("CVE-S", "poc")
	if ok {
		t.Error("staleAll=true: expected ok=false")
	}
}

func TestSaveReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, nowFn := makeNow(t0)

	c, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	if err := c.Put("CVE-1", "poc", map[string]any{"x": 1}); err != nil {
		t.Fatalf("Put CVE-1: %v", err)
	}
	if err := c.Put("CVE-2", "nvd", map[string]any{"cwes": []string{"CWE-89"}}); err != nil {
		t.Fatalf("Put CVE-2: %v", err)
	}
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Assert file exists and is valid JSON
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var check any
	if err := json.Unmarshal(data, &check); err != nil {
		t.Fatalf("file is not valid JSON: %v", err)
	}

	// Reload and check both entries
	c2, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt reload: %v", err)
	}
	if _, ok := c2.Get("CVE-1", "poc"); !ok {
		t.Error("reload: CVE-1/poc not found")
	}
	if _, ok := c2.Get("CVE-2", "nvd"); !ok {
		t.Error("reload: CVE-2/nvd not found")
	}
}

func TestCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	// Write corrupt JSON
	if err := os.WriteFile(path, []byte("{ not json"), 0o644); err != nil {
		t.Fatalf("WriteFile corrupt: %v", err)
	}

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, nowFn := makeNow(t0)

	// OpenAt must not error on corrupt file
	c, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt corrupt: expected no error, got %v", err)
	}

	// Cache must be empty (all-miss)
	_, ok := c.Get("CVE-ANY", "core")
	if ok {
		t.Error("corrupt file: expected empty cache (miss)")
	}

	// Put+Save must cleanly overwrite the corrupt file
	if err := c.Put("CVE-NEW", "poc", map[string]any{"has_poc": false}); err != nil {
		t.Fatalf("Put after corrupt: %v", err)
	}
	if err := c.Save(); err != nil {
		t.Fatalf("Save after corrupt: %v", err)
	}

	// Reload — should succeed cleanly
	c2, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt after overwrite: %v", err)
	}
	if _, ok := c2.Get("CVE-NEW", "poc"); !ok {
		t.Error("after overwrite: CVE-NEW/poc not found")
	}
}

func TestAtomicNoPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, nowFn := makeNow(t0)

	c, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	if err := c.Put("CVE-A", "core", map[string]any{"v": 1}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// No .tmp files must remain in dir
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover .tmp file after Save: %s", e.Name())
		}
	}
}

func TestPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, nowFn := makeNow(t0)

	c, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	if c.Path() != path {
		t.Errorf("Path(): got %q, want %q", c.Path(), path)
	}
}

func TestUnknownSourceAlwaysStale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, nowFn := makeNow(t0)

	c, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}

	// "unknown" source has TTL=0 → always stale, even at T0 exactly
	if err := c.Put("CVE-Z", "unknown", map[string]any{"val": 1}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, ok := c.Get("CVE-Z", "unknown")
	if ok {
		t.Error("unknown source: expected always stale (ok=false)")
	}
}

func TestSaveMissingDir(t *testing.T) {
	// Path in a directory that doesn't yet exist
	parent := t.TempDir()
	path := filepath.Join(parent, "subdir", "nested", "cache.json")

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, nowFn := makeNow(t0)

	c, err := enrichcache.OpenAt(path, nowFn, false)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	if err := c.Put("CVE-D", "core", map[string]any{"v": 1}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Save must create missing dirs
	if err := c.Save(); err != nil {
		t.Fatalf("Save with missing dir: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}
