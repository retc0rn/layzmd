package hosts

import (
	"os"
	"testing"

	"layzmd/internal/nessus"
)

// allIPs flattens a group's per-version IPs in version order.
func allIPs(g OSGroup) []string {
	var out []string
	for _, v := range g.Versions {
		out = append(out, v.IPs...)
	}
	return out
}

func TestGroup_SampleHS(t *testing.T) {
	f, err := os.Open("../../testdata/sample_hs.csv")
	if err != nil {
		t.Fatalf("open testdata: %v", err)
	}
	defer f.Close()

	findings, err := nessus.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	groups := Group(findings)

	// Expect 3 groups in order: Windows Server, Ubuntu, Unknown.
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d: %v", len(groups), groups)
	}

	wantGroups := []struct {
		cat string
		ips []string
	}{
		{"Windows Server", []string{"10.20.4.7", "10.20.4.8"}},
		{"Ubuntu", []string{"10.20.3.14"}},
		{"Unknown", []string{"10.20.9.9"}},
	}

	for i, wg := range wantGroups {
		g := groups[i]
		if g.Category != wg.cat {
			t.Errorf("groups[%d].Category = %q, want %q", i, g.Category, wg.cat)
		}
		if g.HostCount() != len(wg.ips) {
			t.Errorf("groups[%d].HostCount() = %d, want %d", i, g.HostCount(), len(wg.ips))
		}
		got := allIPs(g)
		if len(got) != len(wg.ips) {
			t.Errorf("groups[%d] IPs = %v, want %v", i, got, wg.ips)
			continue
		}
		// The two Windows Server hosts may sit in different OS-version buckets;
		// compare as a set-independent-of-bucket ordering by checking membership.
		want := map[string]bool{}
		for _, ip := range wg.ips {
			want[ip] = true
		}
		for _, ip := range got {
			if !want[ip] {
				t.Errorf("groups[%d] unexpected IP %q (want subset of %v)", i, ip, wg.ips)
			}
		}
	}
}

func TestGroup_VersionSubgrouping(t *testing.T) {
	fs := []nessus.Finding{
		{HostIP: "10.0.0.2", DetectedOS: "Microsoft Windows Server 2019 Standard"},
		{HostIP: "10.0.0.10", DetectedOS: "Microsoft Windows Server 2019 Standard"},
		{HostIP: "10.0.0.3", DetectedOS: "Microsoft Windows Server 2016 Standard"},
		{HostIP: "10.0.0.4"}, // no OS → Unknown category, empty-OS ("Unspecified") bucket
	}
	groups := Group(fs)

	var ws, unk *OSGroup
	for i := range groups {
		switch groups[i].Category {
		case "Windows Server":
			ws = &groups[i]
		case "Unknown":
			unk = &groups[i]
		}
	}
	if ws == nil {
		t.Fatalf("no Windows Server group in %v", groups)
	}
	// Windows Server: 3 hosts across 2 OS-version buckets, 2019 (2 hosts) first.
	if ws.HostCount() != 3 {
		t.Errorf("Windows Server HostCount = %d, want 3", ws.HostCount())
	}
	if len(ws.Versions) != 2 {
		t.Fatalf("Windows Server len(Versions) = %d, want 2: %+v", len(ws.Versions), ws.Versions)
	}
	if ws.Versions[0].OS != "Microsoft Windows Server 2019 Standard" || len(ws.Versions[0].IPs) != 2 {
		t.Errorf("Versions[0] = %+v, want 2019 with 2 hosts", ws.Versions[0])
	}
	if ws.Versions[0].IPs[0] != "10.0.0.2" || ws.Versions[0].IPs[1] != "10.0.0.10" {
		t.Errorf("Versions[0].IPs not numeric-sorted: %v", ws.Versions[0].IPs)
	}

	// The no-OS host lands in Unknown with an empty-OS bucket (rendered "Unspecified").
	if unk == nil {
		t.Fatalf("no Unknown group in %v", groups)
	}
	if len(unk.Versions) != 1 || unk.Versions[0].OS != "" || unk.Versions[0].IPs[0] != "10.0.0.4" {
		t.Errorf("Unknown group = %+v, want single empty-OS bucket [10.0.0.4]", unk.Versions)
	}
}
