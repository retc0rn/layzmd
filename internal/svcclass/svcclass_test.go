package svcclass

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct{ name, port, transport, want string }{
		{"HTTP", "80", "tcp", "Web"},
		{"www", "8080", "tcp", "Web"},
		{"MSSQL", "1433", "tcp", "Database"},
		{"mysql", "3306", "tcp", "Database"},
		{"SSH", "22", "tcp", "Remote Access"},
		{"ms-wbt-server", "3389", "tcp", "Remote Access"},
		{"WinRM", "5985", "tcp", "Remote Access"}, // WinRM → Remote Access (per spec)
		{"SMB", "445", "tcp", "File Sharing"},
		{"ftp", "21", "tcp", "File Sharing"},
		{"smtp", "25", "tcp", "Mail"},
		{"imaps", "993", "tcp", "Mail"},
		{"LDAP", "389", "tcp", "Directory Services"},
		{"kerberos", "88", "tcp", "Directory Services"},
		{"ipp", "631", "tcp", "Printing"},
		{"jetdirect", "9100", "tcp", "Printing"},
		{"vmware-auth", "902", "tcp", "Virtualization / Management"},
		{"ipmi", "623", "udp", "Virtualization / Management"},
		{"modbus", "502", "tcp", "Industrial / ICS"},
		{"bacnet", "47808", "udp", "Industrial / ICS"},
		{"sip", "5060", "udp", "VoIP / Telephony"},
		{"h323", "1720", "tcp", "VoIP / Telephony"},
		{"dns", "53", "udp", "Infrastructure"},
		{"ntp", "123", "udp", "Infrastructure"},
		{"snmp", "161", "udp", "Infrastructure"},
		{"totally-unmatched", "64999", "tcp", "Other"},
		// Port-only fallback (name yields no keyword match):
		{"unknown", "445", "tcp", "File Sharing"},
		// NetBIOS name service (137/138) classifies by name, not just port 139.
		{"NetBIOS", "137", "udp", "File Sharing"},
		// Word-boundary: short tokens must not fire inside larger words.
		{"IIS7", "80", "tcp", "Web"},          // "s7" inside IIS7 must NOT → ICS (port 80 → Web)
		{"gossip", "64998", "tcp", "Other"},   // "sip" inside gossip must NOT → VoIP
		{"echoprint", "64997", "tcp", "Other"}, // "echo" inside echoprint must NOT → Infrastructure
		{"s7comm", "102", "tcp", "Industrial / ICS"}, // caught by port 102 (word-boundary rejects "s7" inside s7comm; real S7 is always :102)
		{"sip", "64996", "udp", "VoIP / Telephony"},  // standalone token still matches
		// SP9: canonical names the resolver now emits.
		{"echo", "7", "tcp", "Other"},                  // echo moved out of Infrastructure
		{"Docker", "2375", "tcp", "Container / Kubernetes"},
		{"Kubernetes", "6443", "tcp", "Container / Kubernetes"},
		{"etcd", "2379", "tcp", "Container / Kubernetes"},
		{"RDP", "3389", "tcp", "Remote Access"},
		{"HTTPS", "443", "tcp", "Web"},
		{"mDNS", "5353", "udp", "Infrastructure"},
		{"TFTP", "69", "udp", "File Sharing"},
		{"NFS", "2049", "tcp", "File Sharing"},
		{"Kerberos", "88", "tcp", "Directory Services"},
		{"SunRPC", "111", "tcp", "Infrastructure"},
		{"MSRPC", "135", "tcp", "Infrastructure"},
		{"LDAPS", "636", "tcp", "Directory Services"},
	}
	for _, c := range cases {
		if got := Classify(c.name, c.port, c.transport); got != c.want {
			t.Errorf("Classify(%q,%q,%q) = %q, want %q", c.name, c.port, c.transport, got, c.want)
		}
	}
}

func TestCategoriesOrder(t *testing.T) {
	got := Categories()
	want := []string{"Web", "Database", "Remote Access", "File Sharing", "Mail",
		"Directory Services", "Infrastructure", "Printing",
		"Virtualization / Management", "Industrial / ICS", "VoIP / Telephony",
		"Container / Kubernetes", "Other"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Categories()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
