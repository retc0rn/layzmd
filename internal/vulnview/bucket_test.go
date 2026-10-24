package vulnview

import "testing"

func TestBucketOf(t *testing.T) {
	msf := []Link{{Label: "Metasploit", URL: "m"}}
	vc := []Link{{Label: "VulnCheck", URL: "v"}}

	cases := []struct {
		name string
		g    GroupView
		want string
	}{
		// Quick Wins now requires Metasploit AND KEV (or a credential finding).
		{"metasploit+kev -> quick win", GroupView{Name: "Some RCE", PocLinks: msf, HasPoc: true, InKev: true}, BucketQuickWins},
		{"metasploit+kev wins over theme", GroupView{Name: "Some XSS thing", PocLinks: msf, HasPoc: true, InKev: true}, BucketQuickWins},
		{"metasploit no kev -> not quick win (theme)", GroupView{Name: "Some XSS thing", PocLinks: msf, HasPoc: true}, BucketWebApp},
		{"metasploit no kev, no theme -> high", GroupView{Name: "Some RCE", PocLinks: msf, HasPoc: true}, BucketHighPriority},
		{"default creds", GroupView{Name: "Default Password for FTP 'admin' Account"}, BucketQuickWins},
		{"null session", GroupView{Name: "SMB NULL Session Authentication"}, BucketQuickWins},
		{"anonymous ftp", GroupView{Name: "Anonymous FTP Enabled"}, BucketQuickWins},
		{"cgi prefix", GroupView{Name: "CGI Generic SSI Injection (HTTP headers)"}, BucketWebApp},
		{"xss no msf", GroupView{Name: "Reflected XSS in Login", PocLinks: vc, HasPoc: true}, BucketWebApp}, // themes win
		{"ssl cert", GroupView{Name: "SSL Certificate Cannot Be Trusted"}, BucketCrypto},
		{"crypto category", GroupView{Name: "Whatever", Category: "Cryptographic Weakness"}, BucketCrypto},
		{"ssh cipher", GroupView{Name: "SSH Weak Cipher Suites Enabled"}, BucketCrypto},
		{"terrapin -> crypto", GroupView{Name: "SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)"}, BucketCrypto},
		{"cleartext ftp -> crypto", GroupView{Name: "FTP Supports Cleartext Authentication"}, BucketCrypto},
		{"unencrypted telnet -> crypto", GroupView{Name: "Unencrypted Telnet Server"}, BucketCrypto},
		{"crypto-named rollup wins over missing patches", GroupView{Name: "Apache Tomcat 7.0.x < 7.0.60 Multiple Vulnerabilities (FREAK)", CVSS: "7.5"}, BucketCrypto},
		{"phpinfo detection -> web", GroupView{Name: "Web Server info.php / phpinfo.php Detection"}, BucketWebApp},
		{"reverse proxy detection -> web", GroupView{Name: "Web Server Reverse Proxy Detection"}, BucketWebApp},
		{"dangerous method detection -> web", GroupView{Name: "Web Server HTTP Dangerous Method Detection"}, BucketWebApp},
		{"clickjacking is boring", GroupView{Name: "Web Application Potentially Vulnerable to Clickjacking"}, BucketBoring},
		{"dhcp detection boring", GroupView{Name: "DHCP Server Detection"}, BucketBoring},
		{"ip forwarding -> boring", GroupView{Name: "IP Forwarding Enabled"}, BucketBoring},
		{"rdp mitm -> crypto", GroupView{Name: "Remote Desktop Protocol Server Man-in-the-Middle Weakness"}, BucketCrypto},
		{"internal ip disclosure -> web", GroupView{Name: "Web Server HTTP Header Internal IP Disclosure"}, BucketWebApp},
		{"web app info disclosure -> web", GroupView{Name: "Web Application Information Disclosure"}, BucketWebApp},
		{"smb sid enum -> quick wins", GroupView{Name: "SMB Use Host SID to Enumerate Local Users Without Credentials"}, BucketQuickWins},
		{"smb lsaquery sid enum -> quick wins", GroupView{Name: "Microsoft Windows SMB LsaQueryInformationPolicy Function SID Enumeration Without Credentials"}, BucketQuickWins},
		{"unsupported", GroupView{Name: "Microsoft IIS Unsupported Version Detection"}, BucketOutdated},
		{"seol -> outdated", GroupView{Name: "Apache Tomcat SEoL (7.0.x)"}, BucketOutdated},
		{"non-critical rollup -> missing patches", GroupView{Name: "Apache 2.4.x < 2.4.53 Multiple Vulnerabilities", CVSS: "7.5"}, BucketMissingPatches},
		{"critical rollup -> high (severity beats patches)", GroupView{Name: "Apache 2.4.x < 2.4.60 Multiple Vulnerabilities", CVSS: "9.8"}, BucketHighPriority},
		{"poc rollup -> high (severity beats patches)", GroupView{Name: "Apache Tomcat 7.0.0 < 7.0.104", PocLinks: vc, HasPoc: true}, BucketHighPriority},
		{"dos by category", GroupView{Name: "Foo", Category: "Denial of Service"}, BucketDoS},
		{"dos by name", GroupView{Name: "NTP monlist Command Enabled DoS"}, BucketDoS},
		{"real dos advisory stays dos", GroupView{Name: "Cisco IOS Software Smart Install DoS (cisco-sa-20180328-smi)", Category: "Denial of Service"}, BucketDoS},
		{"dos rollup -> missing patches (non-critical)", GroupView{Name: "Apache 2.4.x < 2.4.35 DoS", CVSS: "7.5"}, BucketMissingPatches},
		{"dos rollup with poc -> high, not dos", GroupView{Name: "Apache 2.4.x < 2.4.39 Multiple Vulnerabilities", Category: "Denial of Service", PocLinks: vc, HasPoc: true}, BucketHighPriority},
		{"kev only -> high", GroupView{Name: "Some RCE", InKev: true}, BucketHighPriority},
		{"poc only -> high", GroupView{Name: "Some RCE", PocLinks: vc, HasPoc: true}, BucketHighPriority},
		{"unthemed critical -> high", GroupView{Name: "Telnetd - Remote Code Execution", CVSS: "9.8"}, BucketHighPriority},
		{"leftover", GroupView{Name: "Some Info Disclosure"}, BucketResidual},
	}
	for _, c := range cases {
		if got := bucketOf(c.g); got != c.want {
			t.Errorf("%s: bucketOf(%q) = %q, want %q", c.name, c.g.Name, got, c.want)
		}
	}
}
