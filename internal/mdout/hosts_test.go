package mdout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"layzmd/internal/hosts"
)

func TestRenderHostGroupNote_Golden(t *testing.T) {
	g := hosts.OSGroup{Category: "Windows Server", Versions: []hosts.OSVersion{
		{OS: "Microsoft Windows Server 2019 Standard", IPs: []string{"10.0.0.2", "10.0.0.10"}},
		{OS: "", IPs: []string{"10.0.0.4"}},
	}}
	got := normalizeNewlines(RenderHostGroupNote(g))
	want := readGolden(t, "golden_hosts_group.md")
	if got != want {
		t.Errorf("note mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderHostsIndex_Golden(t *testing.T) {
	groups := []hosts.OSGroup{
		{Category: "Windows Server", Versions: []hosts.OSVersion{
			{OS: "x", IPs: []string{"10.0.0.2", "10.0.0.10"}},
			{OS: "", IPs: []string{"10.0.0.4"}},
		}},
		{Category: "Ubuntu", Versions: []hosts.OSVersion{
			{OS: "Ubuntu 20.04", IPs: []string{"10.0.0.5"}},
		}},
	}
	got := normalizeNewlines(RenderHostsIndex(groups))
	want := readGolden(t, "golden_hosts_index.md")
	if got != want {
		t.Errorf("index mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestWriteHosts_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	groups := []hosts.OSGroup{
		{Category: "Windows Server", Versions: []hosts.OSVersion{{OS: "x", IPs: []string{"10.0.0.2"}}}},
	}
	// A stray file in Hosts/ must be cleared by WriteHosts.
	if err := os.MkdirAll(filepath.Join(dir, "Hosts"), 0o755); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(dir, "Hosts", "stale.md")
	if err := os.WriteFile(stray, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteHosts(dir, groups); err != nil {
		t.Fatalf("WriteHosts: %v", err)
	}
	if _, err := os.Stat(stray); err == nil {
		t.Error("stray file not cleared")
	}
	if _, err := os.Stat(filepath.Join(dir, "Hosts.md")); err != nil {
		t.Error("no Hosts.md index")
	}
	if _, err := os.Stat(filepath.Join(dir, "Hosts", "Windows Server.md")); err != nil {
		t.Error("no category note")
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "Hosts.md"))
	if !strings.Contains(string(idx), "[[Hosts/Windows Server|Windows Server]]") {
		t.Error("index link missing")
	}
}
