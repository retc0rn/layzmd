package vulnview

import "testing"

func TestProductName(t *testing.T) {
	cases := map[string]string{
		"MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling RCE": "Microsoft Windows",
		"MS17-010: Security Update for Microsoft Windows SMB Server":                  "Microsoft Windows",
		"Apache Tomcat .x Multiple Vulnerabilities":                                   "Apache Tomcat",
	}
	for in, want := range cases {
		if got := productName(in); got != want {
			t.Errorf("productName(%q) = %q, want %q", in, got, want)
		}
	}
}
