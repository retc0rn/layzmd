// Package protoname resolves a canonical application-protocol display name
// from the Nessus service field, port number, and transport.  Pure helper — no I/O.
// Port of PTCompanion.Core.Analysis.ProtocolNamer (C#).
package protoname

import (
	"strconv"
	"strings"
)

// serviceAlias maps lowercased Nessus service tokens to canonical display names.
var serviceAlias = map[string]string{
	// RDP
	"msrdp":         "RDP",
	"ms-wbt-server": "RDP",
	// SMB
	"cifs":         "SMB",
	"microsoft-ds": "SMB",
	"smb":          "SMB",
	// LDAP
	"ldap":  "LDAP",
	"ldaps": "LDAP",
	// Kerberos
	"kerberos": "Kerberos",
	"kpasswd":  "Kerberos",
	// MSSQL
	"ms-sql-s": "MSSQL",
	"mssql":    "MSSQL",
	// MySQL
	"mysql": "MySQL",
	// PostgreSQL
	"postgresql": "PostgreSQL",
	"postgres":   "PostgreSQL",
	// HTTP / HTTPS
	"www":   "HTTP",
	"http":  "HTTP",
	"https": "HTTPS",
	// SSH
	"ssh": "SSH",
	// WinRM
	"wsman": "WinRM",
	"winrm": "WinRM",
	// DNS
	"domain": "DNS",
	// SMTP
	"smtp": "SMTP",
	// FTP
	"ftp": "FTP",
	// Telnet
	"telnet": "Telnet",
	// VNC
	"vnc": "VNC",
	// RPC
	"rpcbind":    "RPC",
	"portmapper": "RPC",
	// NetBIOS
	"netbios-ssn": "NetBIOS",
	"netbios-ns":  "NetBIOS",
	// Global Catalog
	"global-catalog": "Global Catalog",
	"gc":             "Global Catalog",
	// SNMP
	"snmp": "SNMP",
}

// portMap maps well-known port numbers to canonical display names (curated
// IANA/nmap-services subset). Tier 2 of the service resolver.
var portMap = map[int]string{
	// Web
	80: "HTTP", 8000: "HTTP", 8008: "HTTP", 8080: "HTTP", 8081: "HTTP", 8888: "HTTP",
	443: "HTTPS", 4443: "HTTPS", 8443: "HTTPS",
	// Remote access
	22: "SSH", 23: "Telnet", 3389: "RDP",
	5900: "VNC", 5901: "VNC", 5902: "VNC", 5903: "VNC", 5904: "VNC", 5905: "VNC",
	5985: "WinRM", 5986: "WinRM",
	// File sharing
	21: "FTP", 990: "FTPS", 69: "TFTP", 139: "NetBIOS", 445: "SMB",
	2049: "NFS", 873: "rsync",
	// Mail
	25: "SMTP", 587: "SMTP", 465: "SMTPS", 110: "POP3", 995: "POP3S", 143: "IMAP", 993: "IMAPS",
	// Directory services
	88: "Kerberos", 464: "Kerberos", 389: "LDAP", 636: "LDAPS",
	3268: "Global Catalog", 3269: "Global Catalog SSL",
	// Infrastructure
	53: "DNS", 5353: "mDNS", 123: "NTP", 161: "SNMP", 162: "SNMP",
	67: "DHCP", 68: "DHCP", 514: "syslog", 520: "RIP", 427: "SLP",
	137: "NetBIOS", 138: "NetBIOS", 1701: "L2TP", 500: "ISAKMP",
	623: "IPMI", 902: "VMware", 19: "chargen",
	// Databases
	1433: "MSSQL", 1434: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 1521: "Oracle",
	27017: "MongoDB", 6379: "Redis", 5984: "CouchDB",
	// RPC
	111: "SunRPC", 135: "MSRPC", 593: "MSRPC",
	// Printing
	515: "LPD", 631: "IPP", 9100: "JetDirect",
	// VoIP
	5060: "SIP", 5061: "SIP", 1720: "H.323",
	// ICS
	102: "S7", 502: "Modbus", 20000: "DNP3", 47808: "BACnet", 44818: "EtherNet/IP",
	// Container / Kubernetes
	2375: "Docker", 2376: "Docker", 6443: "Kubernetes", 10250: "Kubelet", 10255: "Kubelet",
	2379: "etcd", 2380: "etcd", 5000: "Registry",
}

// ByPort returns the canonical service name for a well-known port. transport is
// accepted for future refinement but currently unused. Tier 2 of the resolver.
func ByPort(port, transport string) (string, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil {
		return "", false
	}
	name, ok := portMap[n]
	return name, ok
}

// IsEphemeral reports whether port is in the IANA dynamic/private range
// (49152–65535) — used to bucket unassignable ports (e.g. Windows DCOM).
func IsEphemeral(port string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil {
		return false
	}
	return n >= 49152 && n <= 65535
}

// generic is the set of vague Nessus service tokens that should not be
// passed through as-is (they fall through to port-map or transport).
var generic = map[string]bool{
	"unknown": true,
	"general": true,
	"service": true,
	"?":       true,
	"none":    true,
}

// Name returns the canonical protocol display name using ordered resolution:
//  1. serviceAlias lookup (lowercased, trimmed svc token).
//  2. Non-generic, non-numeric svc → strings.ToUpper passthrough.
//  3. portMap lookup on the port number.
//  4. transport fallback (empty transport → "tcp").
func Name(nessusService, port, transport string) string {
	s := strings.ToLower(strings.TrimSpace(nessusService))

	// Step 1: alias map
	if canonical, ok := serviceAlias[s]; ok {
		return canonical
	}

	// Step 2: specific non-generic, non-numeric svc → upper
	if s != "" && !generic[s] && !allDigits(s) {
		return strings.ToUpper(s)
	}

	// Step 3: port map
	if n, err := strconv.Atoi(strings.TrimSpace(port)); err == nil {
		if name, ok := portMap[n]; ok {
			return name
		}
	}

	// Step 4: transport fallback
	if transport == "" {
		return "tcp"
	}
	return transport
}

// allDigits reports whether s is non-empty and consists entirely of ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
