// Package svcclass classifies a service (by name and port) into a category.
package svcclass

import "strings"

// Categories returns the 12 service categories in fixed display order.
func Categories() []string {
	return []string{"Web", "Database", "Remote Access", "File Sharing", "Mail",
		"Directory Services", "Infrastructure", "Printing",
		"Virtualization / Management", "Industrial / ICS", "VoIP / Telephony",
		"Container / Kubernetes", "Other"}
}

// nameKeywords maps a lowercase substring of the service name to a category.
// Checked in order before ports, so an identified name wins over a port guess.
// Order matters: more-specific entries (e.g. winrm, ms-wbt) precede generic
// ones (http) so the specific match wins.
//
// word=true requires a word-boundary match (the token is not part of a larger
// alphanumeric run). Used for short/ambiguous tokens like "s7"/"sip"/"echo"
// that would otherwise fire inside unrelated names (e.g. "s7" in "IIS7").
var nameKeywords = []struct {
	sub  string
	cat  string
	word bool
}{
	{"winrm", "Remote Access", false}, // before any generic http/ms- match
	{"ms-wbt", "Remote Access", false}, {"rdp", "Remote Access", false}, {"ssh", "Remote Access", false},
	{"telnet", "Remote Access", false}, {"vnc", "Remote Access", false}, {"rlogin", "Remote Access", false}, {"rexec", "Remote Access", false},
	{"jetdirect", "Printing", false}, {"pdl-datastream", "Printing", false}, {"ipp", "Printing", true}, {"lpd", "Printing", false}, {"printer", "Printing", false},
	{"vmware", "Virtualization / Management", false}, {"ilo", "Virtualization / Management", false}, {"idrac", "Virtualization / Management", false},
	{"ipmi", "Virtualization / Management", false}, {"redfish", "Virtualization / Management", false}, {"wbem", "Virtualization / Management", false},
	{"modbus", "Industrial / ICS", false}, {"dnp3", "Industrial / ICS", false}, {"bacnet", "Industrial / ICS", false},
	{"ethernet/ip", "Industrial / ICS", false}, {"iec-104", "Industrial / ICS", false}, {"s7", "Industrial / ICS", true},
	{"sip", "VoIP / Telephony", true}, {"h323", "VoIP / Telephony", false}, {"h.323", "VoIP / Telephony", false},
	{"sccp", "VoIP / Telephony", false}, {"skinny", "VoIP / Telephony", false}, {"mgcp", "VoIP / Telephony", false}, {"rtp", "VoIP / Telephony", true},
	{"ldap", "Directory Services", false}, {"kerberos", "Directory Services", false}, {"global catalog", "Directory Services", false}, {"msft-gc", "Directory Services", false},
	{"smtp", "Mail", false}, {"submission", "Mail", false}, {"imap", "Mail", false}, {"pop3", "Mail", false},
	{"smb", "File Sharing", false}, {"cifs", "File Sharing", false}, {"microsoft-ds", "File Sharing", false}, {"netbios", "File Sharing", false},
	{"ftp", "File Sharing", false}, {"tftp", "File Sharing", false}, {"nfs", "File Sharing", false}, {"rsync", "File Sharing", false}, {"afp", "File Sharing", false},
	{"mssql", "Database", false}, {"mysql", "Database", false}, {"postgres", "Database", false}, {"oracle", "Database", false}, {"tns", "Database", false},
	{"mongodb", "Database", false}, {"redis", "Database", false}, {"db2", "Database", false}, {"cassandra", "Database", false},
	{"couchdb", "Database", false},
	{"docker", "Container / Kubernetes", false}, {"kubernetes", "Container / Kubernetes", false},
	{"kubelet", "Container / Kubernetes", false}, {"k8s", "Container / Kubernetes", true},
	{"etcd", "Container / Kubernetes", false}, {"containerd", "Container / Kubernetes", false},
	{"registry", "Container / Kubernetes", false},
	{"http", "Web", false}, {"www", "Web", false}, // after winrm/ms-wbt so those win
	{"dns", "Infrastructure", false}, {"ntp", "Infrastructure", false}, {"snmp", "Infrastructure", false}, {"dhcp", "Infrastructure", false},
	{"syslog", "Infrastructure", false}, {"chargen", "Infrastructure", false}, {"upnp", "Infrastructure", false},
	{"msrpc", "Infrastructure", false}, {"sunrpc", "Infrastructure", false}, {"rpc", "Infrastructure", true},
	{"slp", "Infrastructure", true}, {"rip", "Infrastructure", true}, {"l2tp", "Infrastructure", false}, {"isakmp", "Infrastructure", false},
}

// portMap maps a port number (any transport) to a category. Consulted only when
// the name yields no keyword match.
var portMap = map[string]string{
	"80": "Web", "443": "Web", "8000": "Web", "8008": "Web", "8080": "Web", "8443": "Web", "8888": "Web",
	"1433": "Database", "1521": "Database", "3306": "Database", "5432": "Database", "27017": "Database", "6379": "Database", "50000": "Database",
	"22": "Remote Access", "23": "Remote Access", "3389": "Remote Access", "5900": "Remote Access", "5901": "Remote Access", "5985": "Remote Access", "5986": "Remote Access",
	"21": "File Sharing", "69": "File Sharing", "139": "File Sharing", "445": "File Sharing", "2049": "File Sharing", "873": "File Sharing",
	"25": "Mail", "110": "Mail", "143": "Mail", "465": "Mail", "587": "Mail", "993": "Mail", "995": "Mail",
	"88": "Directory Services", "389": "Directory Services", "636": "Directory Services", "3268": "Directory Services", "3269": "Directory Services",
	"515": "Printing", "631": "Printing", "9100": "Printing",
	"623": "Virtualization / Management", "902": "Virtualization / Management", "5989": "Virtualization / Management",
	"102": "Industrial / ICS", "502": "Industrial / ICS", "20000": "Industrial / ICS", "44818": "Industrial / ICS", "47808": "Industrial / ICS",
	"1720": "VoIP / Telephony", "2000": "VoIP / Telephony", "5060": "VoIP / Telephony", "5061": "VoIP / Telephony",
	"53": "Infrastructure", "123": "Infrastructure", "161": "Infrastructure", "162": "Infrastructure", "514": "Infrastructure", "19": "Infrastructure",
}

// Classify returns the category for a service. Name keywords take precedence
// over ports; unmatched services are "Other".
func Classify(name, port, transport string) string {
	n := strings.ToLower(name)
	for _, kw := range nameKeywords {
		if kw.word {
			if hasWord(n, kw.sub) {
				return kw.cat
			}
		} else if strings.Contains(n, kw.sub) {
			return kw.cat
		}
	}
	if cat, ok := portMap[port]; ok {
		return cat
	}
	return "Other"
}

// hasWord reports whether k occurs in n bounded by non-alphanumeric characters
// (or string ends) on both sides — i.e. k is a whole token, not a fragment of a
// larger alphanumeric run.
func hasWord(n, k string) bool {
	for start := 0; ; {
		i := strings.Index(n[start:], k)
		if i < 0 {
			return false
		}
		i += start
		beforeOK := i == 0 || !isAlnumByte(n[i-1])
		end := i + len(k)
		afterOK := end >= len(n) || !isAlnumByte(n[end])
		if beforeOK && afterOK {
			return true
		}
		start = i + 1
	}
}

func isAlnumByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}
