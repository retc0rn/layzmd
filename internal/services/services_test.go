package services_test

import (
	"os"
	"testing"

	"layzmd/internal/nessus"
	"layzmd/internal/services"
)

func TestGroup_SampleCSV(t *testing.T) {
	f, err := os.Open("../../testdata/sample_hs.csv")
	if err != nil {
		t.Fatalf("open sample_hs.csv: %v", err)
	}
	defer f.Close()

	findings, err := nessus.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	groups := services.Group(findings)

	// Expect 6 groups in order (Name then numeric Port):
	//   HTTP(80), HTTP(8080), HTTPS(8443), RDP(3389), SMB(445), SSH(22).
	// The 8443 row uses plugin 22964 with "A web server is running on this port
	// through TLSv1.2." → HTTPS (rank 3).  The 8080 row uses plugin name
	// "HTTP Server Type and Version" → HTTP (rank 2).  The 445 bucket receives
	// "Microsoft Windows SMB Service Detection" → SMB (rank 2).
	want := []services.ProtoGroup{
		{Name: "HTTP", Port: "80", Transport: "tcp", IPs: []string{"10.20.9.9"}},
		{Name: "HTTP", Port: "8080", Transport: "tcp", IPs: []string{"10.20.9.9"}},
		{Name: "HTTPS", Port: "8443", Transport: "tcp", IPs: []string{"10.20.9.9"}},
		{Name: "RDP", Port: "3389", Transport: "tcp", IPs: []string{"10.20.4.7", "10.20.4.8"}},
		{Name: "SMB", Port: "445", Transport: "tcp", IPs: []string{"10.20.4.7"}},
		{Name: "SSH", Port: "22", Transport: "tcp", IPs: []string{"10.20.3.14"}},
	}

	if len(groups) != len(want) {
		t.Fatalf("Group returned %d groups, want %d", len(groups), len(want))
	}

	for i, g := range groups {
		w := want[i]
		if g.Name != w.Name || g.Port != w.Port || g.Transport != w.Transport {
			t.Errorf("group[%d]: got {%s %s %s}, want {%s %s %s}",
				i, g.Name, g.Port, g.Transport, w.Name, w.Port, w.Transport)
		}
		if len(g.IPs) != len(w.IPs) {
			t.Errorf("group[%d] %s/%s: got %d IPs %v, want %d %v",
				i, g.Name, g.Port, len(g.IPs), g.IPs, len(w.IPs), w.IPs)
			continue
		}
		for j, ip := range g.IPs {
			if ip != w.IPs[j] {
				t.Errorf("group[%d] %s IPs[%d]: got %q, want %q", i, g.Name, j, ip, w.IPs[j])
			}
		}
	}
}

func TestGroup_Resolution(t *testing.T) {
	fs := []nessus.Finding{
		// RDP masked by a TLS-only SD result → must resolve RDP via the port map.
		{HostIP: "10.0.0.1", Port: "3389", Protocol: "tcp", PluginID: "22964", Name: "Service Detection", PluginOutput: "A TLSv1 server answered on this port."},
		// SSH keyword on a non-ephemeral odd port → dropped (implausible) → Unknown.
		{HostIP: "10.0.0.2", Port: "40175", Protocol: "udp", PluginID: "10881", Name: "SSH Protocol Versions Supported"},
		// SSH keyword on an ephemeral port → dropped → Ephemeral bucket.
		{HostIP: "10.0.0.9", Port: "50000", Protocol: "udp", PluginID: "10881", Name: "SSH Protocol Versions Supported"},
		// 69/udp → TFTP via port map (not FTP, despite an "FTP" plugin name).
		{HostIP: "10.0.0.3", Port: "69", Protocol: "udp", PluginID: "1", Name: "FTP Something"},
		// 5353/udp → mDNS via port map (not DNS).
		{HostIP: "10.0.0.4", Port: "5353", Protocol: "udp", PluginID: "1", Name: "DNS Something"},
		// SSH on 22 confirmed by Service Detection → SSH.
		{HostIP: "10.0.0.5", Port: "22", Protocol: "tcp", PluginID: "22964", Name: "Service Detection", PluginOutput: "An SSH server is running on this port."},
	}
	got := map[string]string{}
	for _, g := range services.Group(fs) {
		got[g.Port+"/"+g.Transport] = g.Name
	}
	want := map[string]string{
		"3389/tcp": "RDP",
		"69/udp":   "TFTP",
		"5353/udp": "mDNS",
		"22/tcp":   "SSH",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// Unidentified SYN-only / ephemeral ports are excluded from Services.
	for _, k := range []string{"40175/udp", "50000/udp"} {
		if name, ok := got[k]; ok {
			t.Errorf("%s should be excluded, got %q", k, name)
		}
	}
}
