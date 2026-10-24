package svcname_test

import (
	"testing"

	"layzmd/internal/svcname"
)

func TestServiceDetection(t *testing.T) {
	cases := []struct {
		id, name, out, wantSvc string
		wantTLS, wantFound     bool
	}{
		{"22964", "Service Detection", "An SSH server is running on this port.", "SSH", false, true},
		{"22964", "Service Detection", "A web server is running on this port.", "HTTP", false, true},
		{"22964", "Service Detection", "A web server is running on this port through TLSv1.2.", "HTTPS", false, true},
		{"22964", "Service Detection", "An FTP server is running on this port through TLSv1.2.", "FTPS", false, true},
		{"22964", "Service Detection", "A TLSv1 server answered on this port.", "", true, true},  // TLS-only flag
		{"22964", "Service Detection", "An SSLv3 server answered on this port.", "", true, true}, // TLS-only flag
		{"22964", "Service Detection", "A telnet server is running on this port.", "Telnet", false, true},
		{"22964", "Service Detection", "An HTTP proxy is running on this port.", "HTTP Proxy", false, true},
		{"22964", "Service Detection", "The service closed the connection without sending any data.", "", false, false},
		{"11111", "Some Other Plugin", "An SSH server is running on this port.", "", false, false}, // not SD → ignored
	}
	for _, c := range cases {
		svc, tls, found := svcname.ServiceDetection(c.id, c.name, c.out)
		if svc != c.wantSvc || tls != c.wantTLS || found != c.wantFound {
			t.Errorf("ServiceDetection(%q,%q)=(%q,%v,%v) want (%q,%v,%v)",
				c.id, c.out, svc, tls, found, c.wantSvc, c.wantTLS, c.wantFound)
		}
	}
}

func TestServiceDetectionByName(t *testing.T) {
	svc, tls, found := svcname.ServiceDetection("", "service detection", "An SSH server is running on this port.")
	if svc != "SSH" || tls || !found {
		t.Errorf("by-name SD = (%q,%v,%v), want (SSH,false,true)", svc, tls, found)
	}
}

func TestKeywordName(t *testing.T) {
	if svc, ok := svcname.KeywordName("Portmapper (RPC) Service"); !ok || svc != "RPC" {
		t.Errorf("bounded rpc: got (%q,%v)", svc, ok)
	}
	if svc, ok := svcname.KeywordName("SSH Server CBC Mode Ciphers Enabled"); !ok || svc != "SSH" {
		t.Errorf("ssh: got (%q,%v)", svc, ok)
	}
	if svc, ok := svcname.KeywordName("Microsoft SQL Server Detection"); !ok || svc != "MSSQL" {
		t.Errorf("mssql: got (%q,%v)", svc, ok)
	}
	if svc, ok := svcname.KeywordName("HTTP Server Type and Version"); !ok || svc != "HTTP" {
		t.Errorf("http: got (%q,%v)", svc, ok)
	}
	// ssl/tls catch-all removed → TLS only comes from Service Detection.
	if svc, ok := svcname.KeywordName("SSL / TLS Versions Supported"); ok {
		t.Errorf("ssl/tls keyword should be gone, got (%q,%v)", svc, ok)
	}
	// "dce" removed → not matched (port 135 is named via the port map instead).
	if svc, ok := svcname.KeywordName("DCE Services Enumeration"); ok {
		t.Errorf("dce keyword should be gone, got (%q,%v)", svc, ok)
	}
	if _, ok := svcname.KeywordName("Some unrelated plugin"); ok {
		t.Error("unrelated plugin should not match")
	}
}

func TestPlausibleForPort(t *testing.T) {
	if svcname.PlausibleForPort("SSH", "40175", "udp") {
		t.Error("SSH on 40175/udp must be implausible")
	}
	if !svcname.PlausibleForPort("SSH", "22", "tcp") {
		t.Error("SSH on 22 plausible")
	}
	if svcname.PlausibleForPort("SNMP", "50000", "udp") {
		t.Error("SNMP on 50000 implausible")
	}
	if svcname.PlausibleForPort("Telnet", "9999", "tcp") {
		t.Error("telnet on 9999 implausible")
	}
	if !svcname.PlausibleForPort("HTTP", "12345", "tcp") {
		t.Error("ungated svc plausible anywhere")
	}
}
