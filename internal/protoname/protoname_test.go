package protoname_test

import (
	"testing"

	"layzmd/internal/protoname"
)

func TestName(t *testing.T) {
	tests := []struct {
		svc       string
		port      string
		transport string
		want      string
	}{
		// serviceAlias hits
		{"msrdp", "3389", "tcp", "RDP"},
		{"ms-wbt-server", "3389", "tcp", "RDP"},
		{"cifs", "445", "tcp", "SMB"},
		{"ms-sql-s", "1433", "tcp", "MSSQL"},
		{"www", "80", "tcp", "HTTP"},
		{"wsman", "5985", "tcp", "WinRM"},
		// case-insensitive alias
		{"MSRDP", "3389", "tcp", "RDP"},
		// unmapped specific svc → UPPER (step 2)
		{"sip", "5060", "udp", "SIP"},
		// generic set → falls through to port map (step 3)
		{"unknown", "3389", "tcp", "RDP"},
		// empty svc → port map (step 3)
		{"", "445", "tcp", "SMB"},
		// alias beats port (ssh on non-standard port)
		{"ssh", "2222", "tcp", "SSH"},
		// transport fallback (step 4)
		{"", "9999", "tcp", "tcp"},
		// empty transport → "tcp"
		{"", "9999", "", "tcp"},
	}

	for _, tt := range tests {
		got := protoname.Name(tt.svc, tt.port, tt.transport)
		if got != tt.want {
			t.Errorf("Name(%q, %q, %q) = %q; want %q", tt.svc, tt.port, tt.transport, got, tt.want)
		}
	}
}

func TestByPort(t *testing.T) {
	cases := map[string]string{
		"3389": "RDP", "443": "HTTPS", "636": "LDAPS", "69": "TFTP", "5353": "mDNS",
		"143": "IMAP", "993": "IMAPS", "2049": "NFS", "88": "Kerberos", "464": "Kerberos",
		"514": "syslog", "137": "NetBIOS", "135": "MSRPC", "111": "SunRPC",
		"6443": "Kubernetes", "2375": "Docker", "2379": "etcd",
	}
	for p, want := range cases {
		if got, ok := protoname.ByPort(p, "tcp"); !ok || got != want {
			t.Errorf("ByPort(%s) = (%q,%v), want (%q,true)", p, got, ok, want)
		}
	}
	if _, ok := protoname.ByPort("40175", "udp"); ok {
		t.Error("40175 should be unknown")
	}
	if _, ok := protoname.ByPort("notaport", "tcp"); ok {
		t.Error("non-numeric port should be unknown")
	}
}

func TestIsEphemeral(t *testing.T) {
	if !protoname.IsEphemeral("49664") {
		t.Error("49664 is ephemeral")
	}
	if !protoname.IsEphemeral("65535") {
		t.Error("65535 is ephemeral")
	}
	if protoname.IsEphemeral("443") {
		t.Error("443 not ephemeral")
	}
	if protoname.IsEphemeral("40175") {
		t.Error("40175 below dynamic range, not ephemeral")
	}
}
