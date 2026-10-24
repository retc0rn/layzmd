// Package enrichcache provides a JSON file-backed cache for vulnerability
// enrichment data, keyed by (CVE, source) with per-source TTL and atomic writes.
package enrichcache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry holds a single cached value together with its fetch timestamp.
type Entry struct {
	FetchedAt time.Time       `json:"fetched_at"`
	Data      json.RawMessage `json:"data"`
}

// diskShape is the on-disk JSON wrapper: {"entries": {cve: {source: Entry}}}.
type diskShape struct {
	Entries map[string]map[string]Entry `json:"entries"`
}

// Cache is an in-memory cache backed by a JSON file on disk.
type Cache struct {
	mu       sync.Mutex
	path     string
	now      func() time.Time
	staleAll bool
	entries  map[string]map[string]Entry // cve → source → Entry
}

// ttlFor returns the freshness duration for the given source.
// A return value of 0 means "always stale" (never returned fresh).
func ttlFor(source string) time.Duration {
	switch source {
	case "core", "catalog":
		return 24 * time.Hour
	case "poc", "nvd":
		return 30 * 24 * time.Hour
	case "index":
		// Bulk PoC datasets (ExploitDB/Metasploit/Nuclei) change slowly.
		return 7 * 24 * time.Hour
	default:
		return 0
	}
}

// Open loads the cache from os.UserCacheDir()/layzmd/enrichment.json.
// If now is nil, time.Now is used. If staleAll is true every Get returns false
// (writes still work and persist through Save).
func Open(now func() time.Time, staleAll bool) (*Cache, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "layzmd", "enrichment.json")
	return OpenAt(path, now, staleAll)
}

// OpenAt loads the cache from the given path. Missing, unreadable, or corrupt
// files are treated as an empty cache — no error is returned. If now is nil,
// time.Now is used.
func OpenAt(path string, now func() time.Time, staleAll bool) (*Cache, error) {
	if now == nil {
		now = time.Now
	}

	c := &Cache{
		path:     path,
		now:      now,
		staleAll: staleAll,
		entries:  make(map[string]map[string]Entry),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// Missing or unreadable → empty cache, no error.
		return c, nil
	}

	var ds diskShape
	if err := json.Unmarshal(data, &ds); err != nil {
		// Corrupt → empty cache, no error.
		return c, nil
	}

	if ds.Entries != nil {
		c.entries = ds.Entries
	}
	return c, nil
}

// Path returns the file path this cache is backed by.
func (c *Cache) Path() string {
	return c.path
}

// Get returns the cached data for (cve, source) when the entry is present and
// fresh. It returns (nil, false) when staleAll is set, the entry is absent,
// the source TTL is ≤ 0, or the entry has expired.
func (c *Cache) Get(cve, source string) (json.RawMessage, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.staleAll {
		return nil, false
	}

	sourceMap, ok := c.entries[cve]
	if !ok {
		return nil, false
	}

	entry, ok := sourceMap[source]
	if !ok {
		return nil, false
	}

	ttl := ttlFor(source)
	if ttl <= 0 {
		return nil, false
	}

	if c.now().Sub(entry.FetchedAt) > ttl {
		return nil, false
	}

	return entry.Data, true
}

// Put marshals v and stores it as a fresh Entry for (cve, source), stamping
// FetchedAt with now().
func (c *Cache) Put(cve, source string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries[cve] == nil {
		c.entries[cve] = make(map[string]Entry)
	}
	c.entries[cve][source] = Entry{
		FetchedAt: c.now(),
		Data:      raw,
	}
	return nil
}

// Save atomically persists all entries to disk. It creates the directory if it
// doesn't exist, writes to a temp file in the same directory, then renames it
// over the target path. No partial files or leftover .tmp files remain on error.
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	ds := diskShape{Entries: c.entries}
	data, err := json.Marshal(ds)
	if err != nil {
		return err
	}

	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		_ = os.Remove(tmp) // best-effort cleanup
		return err
	}

	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp) // best-effort cleanup
		return err
	}

	return nil
}
