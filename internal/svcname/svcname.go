// Package svcname infers canonical service names from Nessus plugin data.
// Pure helper — no I/O; stdlib only.
package svcname

import (
	"regexp"
	"strconv"
	"strings"
)

// sdRegex matches the first line of a "Service Detection" (22964) plugin output.
// Group 1 = service phrase (e.g. "web", "SSH", "HTTP").
// Group 2 = terminator word: "server", "service", or "proxy".
// Group 3 = optional TLS/SSL qualifier (e.g. "TLSv1.2", "SSLv3").
var sdRegex = regexp.MustCompile(
	`(?i)^(?:an?|the)\s+(.+?)\s+(server|service|proxy)\s+(?:is running|answered)\s+on this port(?:\s+through\s+(sslv\d|tlsv[\d.]+))?`,
)

// phraseMap maps a lowercased service phrase (group 1 of sdRegex) to a canonical name.
var phraseMap = map[string]string{
	"web":        "HTTP",
	"ssh":        "SSH",
	"smtp":       "SMTP",
	"ftp":        "FTP",
	"tftp":       "TFTP",
	"vnc":        "VNC",
	"telnet":     "Telnet",
	"imap":       "IMAP",
	"pop3":       "POP3",
	"pop":        "POP3",
	"ldap":       "LDAP",
	"snmp":       "SNMP",
	"dns":        "DNS",
	"rdp":        "RDP",
	"http proxy": "HTTP Proxy",
}

// tlsUpgrade maps a base service name to its TLS variant.
var tlsUpgrade = map[string]string{
	"HTTP": "HTTPS",
	"SMTP": "SMTPS",
	"FTP":  "FTPS",
	"IMAP": "IMAPS",
	"POP3": "POP3S",
	"LDAP": "LDAPS",
}

// keywordTable is an ordered list of (substring/word, canonical-name) pairs for
// plugin-Name keyword matching (most-specific first). word=true requires a
// word-boundary match (the token is bounded by non-alphanumerics) so short
// tokens like "rpc"/"ssh"/"dns" don't fire inside unrelated words (e.g. "rpc"
// in "DCE/RPC" is fine, but a substring "dce" must not tag arbitrary ports).
var keywordTable = []struct {
	sub  string
	svc  string
	word bool
}{
	{"microsoft sql", "MSSQL", false},
	{"mssql", "MSSQL", false},
	{"mysql", "MySQL", false},
	{"postgres", "PostgreSQL", false},
	{"oracle", "Oracle", false},
	{"smb", "SMB", true},
	{"cifs", "SMB", true},
	{"ssh", "SSH", true},
	{"rdp", "RDP", true},
	{"terminal services", "RDP", false},
	{"remote desktop", "RDP", false},
	{"winrm", "WinRM", false},
	{"ldap", "LDAP", true},
	{"kerberos", "Kerberos", false},
	{"dns", "DNS", true},
	{"ntp", "NTP", true},
	{"snmp", "SNMP", true},
	{"telnet", "Telnet", true},
	{"vnc", "VNC", true},
	{"tftp", "TFTP", true},
	{"ftp", "FTP", true},
	{"smtp", "SMTP", true},
	{"imap", "IMAP", true},
	{"pop3", "POP3", true},
	{"vmware", "VMware", false},
	{"vcenter", "VMware", false},
	{"rpc", "RPC", true},
	// Web (most general — last of the substantive entries)
	{"web server", "HTTP", false},
	{"hypertext", "HTTP", false},
	{"http", "HTTP", true},
}

// ServiceDetection parses Service Detection (plugin 22964) output.
//   - found == false: not an SD finding, or nothing recognizable.
//   - svc != "": a specific service was named (TLS-upgraded if the phrase
//     carried a TLS qualifier).
//   - svc == "" && tlsOnly: SD saw only a TLS handshake ("A TLSv1 server
//     answered on this port.") with no underlying service — a TLS flag, not a
//     name; the caller resolves the wrapped service via the port map.
func ServiceDetection(pluginID, name, pluginOutput string) (svc string, tlsOnly bool, found bool) {
	nameLow := strings.ToLower(strings.TrimSpace(name))
	if pluginID != "22964" && nameLow != "service detection" {
		return "", false, false
	}

	firstLine := pluginOutput
	if idx := strings.IndexByte(pluginOutput, '\n'); idx >= 0 {
		firstLine = pluginOutput[:idx]
	}
	m := sdRegex.FindStringSubmatch(strings.TrimSpace(firstLine))
	if m == nil {
		return "", false, false
	}

	phrase := strings.ToLower(strings.TrimSpace(m[1]))
	terminator := strings.ToLower(strings.TrimSpace(m[2]))
	tlsGroup := strings.TrimSpace(m[3])

	// TLS-only handshake ("An SSLv3 server answered …") — flag, not a service.
	if isTLSPhrase(phrase) {
		return "", true, true
	}

	upgrade := func(canonical string) string {
		if tlsGroup != "" {
			if up, ok := tlsUpgrade[canonical]; ok {
				return up
			}
		}
		return canonical
	}

	if terminator == "proxy" {
		if canonical, ok := phraseMap[phrase+" proxy"]; ok {
			return upgrade(canonical), false, true
		}
	}
	if canonical, ok := phraseMap[phrase]; ok {
		return upgrade(canonical), false, true
	}
	if phrase != "" {
		if terminator == "proxy" {
			return titleCase(phrase + " proxy"), false, true
		}
		return titleCase(phrase), false, true
	}
	return "", false, false
}

// KeywordName returns a canonical service inferred from a plugin Name via
// word-boundary/substring keyword matching. ok == false when nothing matches.
func KeywordName(pluginName string) (svc string, ok bool) {
	nameLow := strings.ToLower(strings.TrimSpace(pluginName))
	for _, e := range keywordTable {
		if e.word {
			if hasWord(nameLow, e.sub) {
				return e.svc, true
			}
		} else if strings.Contains(nameLow, e.sub) {
			return e.svc, true
		}
	}
	return "", false
}

// plausiblePorts gates a small set of false-positive-prone services to their
// plausible ports. Services absent from this map are plausible on any port.
var plausiblePorts = map[string]map[int]bool{
	"SSH":    {22: true, 222: true, 830: true, 2022: true, 2222: true},
	"Telnet": {23: true, 107: true, 992: true, 2323: true},
	"SNMP":   {161: true, 162: true, 199: true, 391: true, 1993: true},
	"RPC":    {111: true, 135: true, 530: true, 593: true},
	"FTP":    {21: true, 990: true, 2121: true},
	"DNS":    {53: true, 853: true},
	"NTP":    {123: true},
}

// PlausibleForPort reports whether svc is plausible on the given port. Returns
// true for services that are not gated.
func PlausibleForPort(svc, port, transport string) bool {
	set, gated := plausiblePorts[svc]
	if !gated {
		return true
	}
	p, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil {
		return false
	}
	return set[p]
}

// isTLSPhrase reports whether the phrase looks like a bare TLS/SSL version token.
func isTLSPhrase(phrase string) bool {
	return strings.HasPrefix(phrase, "sslv") || strings.HasPrefix(phrase, "tlsv")
}

// hasWord reports whether k occurs in n bounded by non-alphanumeric characters.
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

// titleCase capitalises the first letter of each word.
func titleCase(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
