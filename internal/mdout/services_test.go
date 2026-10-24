package mdout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"layzmd/internal/services"
)

func TestServiceNotes_GroupByName(t *testing.T) {
	groups := []services.ProtoGroup{
		{Name: "DNS", Port: "53", Transport: "udp", IPs: []string{"10.0.0.1"}},
		{Name: "DNS", Port: "53", Transport: "tcp", IPs: []string{"10.0.0.1", "10.0.0.2"}},
		{Name: "HTTP", Port: "80", Transport: "tcp", IPs: []string{"10.0.0.3"}},
	}
	notes := serviceNotes(groups)

	var dns *serviceNote
	for i := range notes {
		if notes[i].name == "DNS" {
			dns = &notes[i]
		}
	}
	if dns == nil {
		t.Fatal("no DNS note")
	}
	if dns.category != "Infrastructure" {
		t.Errorf("DNS category = %q, want Infrastructure", dns.category)
	}
	if len(dns.variants) != 2 {
		t.Errorf("DNS variants = %d, want 2", len(dns.variants))
	}
	if dns.hostCount != 2 { // distinct hosts: 10.0.0.1, 10.0.0.2
		t.Errorf("DNS hostCount = %d, want 2", dns.hostCount)
	}
	if dns.path != "Services/Infrastructure/dns.md" {
		t.Errorf("DNS path = %q", dns.path)
	}
}

func TestRenderServiceNote_Golden(t *testing.T) {
	n := serviceNotes([]services.ProtoGroup{
		{Name: "DNS", Port: "53", Transport: "udp", IPs: []string{"10.0.0.1"}},
		{Name: "DNS", Port: "53", Transport: "tcp", IPs: []string{"10.0.0.1", "10.0.0.2"}},
	})[0]
	got := normalizeNewlines(RenderServiceNote(n))
	want := readGolden(t, "golden_services_note.md")
	if got != want {
		t.Errorf("note mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderServicesIndex_Golden(t *testing.T) {
	groups := []services.ProtoGroup{
		{Name: "DNS", Port: "53", Transport: "udp", IPs: []string{"10.0.0.1"}},
		{Name: "HTTP", Port: "80", Transport: "tcp", IPs: []string{"10.0.0.3"}},
	}
	got := normalizeNewlines(RenderServicesIndex(groups))
	want := readGolden(t, "golden_services_index.md")
	if got != want {
		t.Errorf("index mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestWriteServices_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	groups := []services.ProtoGroup{{Name: "DNS", Port: "53", Transport: "udp", IPs: []string{"10.0.0.1"}}}
	if err := os.MkdirAll(filepath.Join(dir, "Services"), 0o755); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(dir, "Services", "stale.md")
	if err := os.WriteFile(stray, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteServices(dir, groups); err != nil {
		t.Fatalf("WriteServices: %v", err)
	}
	if _, err := os.Stat(stray); err == nil {
		t.Error("stray file not cleared")
	}
	if _, err := os.Stat(filepath.Join(dir, "Services", "Infrastructure", "dns.md")); err != nil {
		t.Error("no service note")
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "Services.md"))
	if !strings.Contains(string(idx), "[[Services/Infrastructure/dns|DNS]]") {
		t.Error("index link missing")
	}
}
