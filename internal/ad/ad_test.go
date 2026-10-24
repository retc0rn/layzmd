package ad

import (
	"os"
	"strings"
	"testing"

	"layzmd/internal/nessus"
)

func loadSampleAD(t *testing.T) []nessus.Finding {
	t.Helper()
	f, err := os.Open("../../testdata/sample_ad.csv")
	if err != nil {
		t.Fatalf("open sample_ad.csv: %v", err)
	}
	defer f.Close()
	findings, err := nessus.Parse(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return findings
}

func TestAnalyze_Domains(t *testing.T) {
	r := Analyze(loadSampleAD(t))
	var found bool
	for _, d := range r.Domains {
		if d.Name == "corp.acme.com" {
			found = true
			if d.Confidence != "High" {
				t.Errorf("corp.acme.com confidence = %q, want \"High\"", d.Confidence)
			}
			if d.Hosts < 1 {
				t.Errorf("corp.acme.com hosts = %d, want >=1", d.Hosts)
			}
			hasExpectedSource := false
			for _, s := range d.Sources {
				if s == "DNS domain name" || s == "Kerberos realm" {
					hasExpectedSource = true
				}
			}
			if !hasExpectedSource {
				t.Errorf("corp.acme.com sources = %v, want DNS domain name or Kerberos realm", d.Sources)
			}
		}
	}
	if !found {
		t.Errorf("Domains: corp.acme.com not found; got %+v", r.Domains)
	}
}

func TestAnalyze_Netbios(t *testing.T) {
	r := Analyze(loadSampleAD(t))
	var found bool
	for _, n := range r.Netbios {
		if n.Name == "CORP" {
			found = true
			if n.Hosts != 1 {
				t.Errorf("CORP hosts = %d, want 1", n.Hosts)
			}
		}
	}
	if !found {
		t.Errorf("Netbios: CORP not found; got %+v", r.Netbios)
	}
}

func TestAnalyze_DomainControllers(t *testing.T) {
	r := Analyze(loadSampleAD(t))
	var found bool
	for _, dc := range r.DomainControllers {
		if dc.IP == "10.0.0.5" {
			found = true
			if dc.FQDN != "dc01.corp.acme.com" {
				t.Errorf("DC FQDN = %q, want \"dc01.corp.acme.com\"", dc.FQDN)
			}
			if dc.Confidence == "" {
				t.Error("DC Confidence is empty")
			}
		}
	}
	if !found {
		t.Errorf("DomainControllers: 10.0.0.5 not found; got %+v", r.DomainControllers)
	}
}

func TestAnalyze_DNSServers(t *testing.T) {
	r := Analyze(loadSampleAD(t))
	var found bool
	for _, d := range r.DNSServers {
		if d.IP == "10.0.0.5" {
			found = true
			if d.Port != "53" {
				t.Errorf("DNS port = %q, want \"53\"", d.Port)
			}
		}
	}
	if !found {
		t.Errorf("DNSServers: 10.0.0.5 not found; got %+v", r.DNSServers)
	}
}

func TestValidDomain(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"corp.acme.com", true},
		{"WORKGROUP", false},
		{"workgroup", false},
		{"localhost", false},
		{"NULL", false},
		{"NONE", false},
		{"UNKNOWN", false},
		{"ec2.internal", false},
		{"domaindnszones.corp.acme.com", false},
		{"forestdnszones.corp.acme.com", false},
		{"192.168.1.1", false},
		{"nodot", false},
		{"has<bracket>.com", false},
		{"has>bracket.com", false},
	}
	for _, tc := range cases {
		// Mirror how addDomainCandidate prepares the value before calling validDomain:
		// NormalizeDomain (lowercase, trim, strip trailing dot) then strip slashes.
		norm := strings.ToLower(strings.TrimSpace(tc.input))
		norm = strings.TrimSuffix(norm, ".")
		norm = strings.Trim(norm, "/\\")
		got := validDomain(norm)
		if got != tc.want {
			t.Errorf("validDomain(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestAnalyze_SMBSigning(t *testing.T) {
	r := Analyze(loadSampleAD(t))

	// Must have at least one SMBSigningRow for 10.0.0.5 on port 445.
	var found bool
	for _, row := range r.SMBSigning {
		if row.IP == "10.0.0.5" && row.Port == "445" {
			found = true
		}
	}
	if !found {
		t.Errorf("SMBSigning: no row for 10.0.0.5:445; got %+v", r.SMBSigning)
	}

	// SMBSigningSummary must have the host's domain with Hosts >= 1.
	var sumFound bool
	for _, s := range r.SMBSigningSummary {
		if s.Hosts >= 1 {
			sumFound = true
		}
	}
	if !sumFound {
		t.Errorf("SMBSigningSummary: no entry with Hosts>=1; got %+v", r.SMBSigningSummary)
	}
}

func TestAnalyze_Shares(t *testing.T) {
	r := Analyze(loadSampleAD(t))

	// Must have a row for 10.0.0.6 with share "Data" and UNC "\\10.0.0.6\Data".
	var found bool
	for _, row := range r.Shares {
		if row.IP == "10.0.0.6" && row.Share == "Data" && row.UNC == `\\10.0.0.6\Data` {
			found = true
			// Access must reflect writable.
			if !strings.Contains(row.Access, "Write") {
				t.Errorf("Share access = %q, want to contain Write", row.Access)
			}
			// Principals must contain "Everyone".
			var hasEveryone bool
			for _, p := range row.Principals {
				if strings.EqualFold(p, "Everyone") {
					hasEveryone = true
				}
			}
			if !hasEveryone {
				t.Errorf("Share principals = %v, want to contain Everyone", row.Principals)
			}
		}
	}
	if !found {
		t.Errorf("Shares: no row for 10.0.0.6 Data \\\\10.0.0.6\\Data; got %+v", r.Shares)
	}

	// ShareSummary must have Writable >= 1.
	var writableFound bool
	for _, s := range r.ShareSummary {
		if s.Writable >= 1 {
			writableFound = true
		}
	}
	if !writableFound {
		t.Errorf("ShareSummary: no entry with Writable>=1; got %+v", r.ShareSummary)
	}
}

func TestAnalyze_Guest(t *testing.T) {
	r := Analyze(loadSampleAD(t))

	var found bool
	for _, row := range r.Guest {
		if row.IP == "10.0.0.7" && row.Access == "Guest" {
			found = true
		}
	}
	if !found {
		t.Errorf("Guest: no row for 10.0.0.7 with Access=Guest; got %+v", r.Guest)
	}
}

func TestAnalyze_SmbV1(t *testing.T) {
	r := Analyze(loadSampleAD(t))

	var found8 bool
	for _, row := range r.SmbV1 {
		if row.IP == "10.0.0.8" {
			found8 = true
			if row.Detail == "" {
				t.Errorf("SmbV1 row detail is empty for 10.0.0.8")
			}
		}
	}
	if !found8 {
		t.Errorf("SmbV1: no row for 10.0.0.8; got %+v", r.SmbV1)
	}

	// 10.0.0.18 has "SMB v1 is enabled" — the spaced "smb v1" term must match.
	var found18 bool
	for _, row := range r.SmbV1 {
		if row.IP == "10.0.0.18" {
			found18 = true
			if row.Detail == "" {
				t.Errorf("SmbV1 row detail is empty for 10.0.0.18")
			}
		}
	}
	if !found18 {
		t.Errorf("SmbV1: no row for 10.0.0.18 (smb v1 spaced term); got %+v", r.SmbV1)
	}
}

func TestIsJunkEmail(t *testing.T) {
	junk := []string{
		"aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"umac-64-etm@openssh.com",
		"curve25519-sha256@libssh.org",
		"rijndael-cbc@lysator.liu.se",
		"x@modssl.org",
		"info@nessus.org",
		"users@httpd.apache.org",
		"ssh-rsa@example.net", // algorithm token in local part
	}
	for _, e := range junk {
		if !isJunkEmail(e) {
			t.Errorf("isJunkEmail(%q) = false, want true", e)
		}
	}
	real := []string{
		"bob@corp.acme.com",
		"alice.smith@target.example",
		"admin@client-domain.io",
		"j.doe@sub.corp.local",
	}
	for _, e := range real {
		if isJunkEmail(e) {
			t.Errorf("isJunkEmail(%q) = true, want false", e)
		}
	}
}

func TestAnalyze_Emails(t *testing.T) {
	r := Analyze(loadSampleAD(t))

	// Must contain bob@corp.acme.com with source web_harvest.
	var found bool
	for _, e := range r.Emails {
		if e.Email == "bob@corp.acme.com" && e.Source == "web_harvest" {
			found = true
		}
	}
	if !found {
		t.Errorf("Emails: bob@corp.acme.com web_harvest not found; got %+v", r.Emails)
	}

	// EmailSummary must have an entry grouped by Source.
	if len(r.EmailSummary) == 0 {
		t.Errorf("EmailSummary: empty; got %+v", r.EmailSummary)
	}
	var hasWebHarvest bool
	for _, s := range r.EmailSummary {
		if s.Source == "web_harvest" {
			hasWebHarvest = true
			if s.Emails < 1 {
				t.Errorf("EmailSummary web_harvest Emails = %d, want >=1", s.Emails)
			}
		}
	}
	if !hasWebHarvest {
		t.Errorf("EmailSummary: no web_harvest entry; got %+v", r.EmailSummary)
	}
}

func TestAnalyze_Defensive(t *testing.T) {
	r := Analyze(loadSampleAD(t))

	// Must have a row for CrowdStrike Falcon with Category AV/EDR or EDR.
	// CrowdStrike Falcon is in category "EDR" per the ported signature table.
	var found bool
	for _, row := range r.Defensive {
		if row.Product == "CrowdStrike Falcon" && row.Hosts >= 1 {
			found = true
			if row.Category != "EDR" {
				t.Errorf("Defensive CrowdStrike Falcon: Category = %q, want \"EDR\"", row.Category)
			}
			if row.Confidence != "High" {
				t.Errorf("Defensive CrowdStrike Falcon: Confidence = %q, want \"High\"", row.Confidence)
			}
			var hasInstalled bool
			for _, e := range row.EvidenceTypes {
				if e == "Installed software" {
					hasInstalled = true
				}
			}
			if !hasInstalled {
				t.Errorf("Defensive CrowdStrike Falcon: EvidenceTypes = %v, want to contain \"Installed software\"", row.EvidenceTypes)
			}
		}
	}
	if !found {
		t.Errorf("Defensive: CrowdStrike Falcon not found with Hosts>=1; got %+v", r.Defensive)
	}
}

func TestAnalyze_Mssql(t *testing.T) {
	r := Analyze(loadSampleAD(t))

	var found bool
	for _, row := range r.Mssql {
		if row.IP == "10.0.0.10" && row.Port == "1433" {
			found = true
			if row.Instance != "MSSQLSERVER" {
				t.Errorf("Mssql Instance = %q, want \"MSSQLSERVER\"", row.Instance)
			}
			if row.Version != "15.0.2000.5" {
				t.Errorf("Mssql Version = %q, want \"15.0.2000.5\"", row.Version)
			}
			// A "DNS Computer Name" in the plugin output must resolve the FQDN
			// via detectMssql->addFQDN. This previously panicked (nil domainAggs
			// map write); regression guard for that crash.
			if row.FQDN != "sql01.corp.acme.com" {
				t.Errorf("Mssql FQDN = %q, want \"sql01.corp.acme.com\"", row.FQDN)
			}
		}
	}
	if !found {
		t.Errorf("Mssql: no row for 10.0.0.10:1433; got %+v", r.Mssql)
	}
}

func TestAnalyze_AdcsCA(t *testing.T) {
	r := Analyze(loadSampleAD(t))
	var found bool
	for _, row := range r.AdcsCA {
		if row.IP == "10.0.0.5" && row.Issuer == "corp-CA" && row.Subject == "dc01.corp.acme.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("AdcsCA: no row for 10.0.0.5 issuer=corp-CA subject=dc01.corp.acme.com; got %+v", r.AdcsCA)
	}
}

func TestAnalyze_AdcsEndpoints(t *testing.T) {
	r := Analyze(loadSampleAD(t))
	var found bool
	for _, row := range r.AdcsEndpoints {
		if row.IP == "10.0.0.12" && row.Indicator == "/certsrv" {
			found = true
		}
	}
	if !found {
		t.Errorf("AdcsEndpoints: no row for 10.0.0.12 indicator=/certsrv; got %+v", r.AdcsEndpoints)
	}
}

func TestAnalyze_Sccm(t *testing.T) {
	r := Analyze(loadSampleAD(t))
	var found bool
	for _, row := range r.Sccm {
		if row.IP == "10.0.0.13" && row.Role == "management_point" && row.Site == "ABC" && row.FQDN == "mp.corp.acme.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("Sccm: no row for 10.0.0.13 management_point Site=ABC FQDN=mp.corp.acme.com; got %+v", r.Sccm)
	}
}

func TestAnalyze_Adfs(t *testing.T) {
	r := Analyze(loadSampleAD(t))
	var found bool
	for _, row := range r.Adfs {
		if row.IP == "10.0.0.14" {
			found = true
		}
	}
	if !found {
		t.Errorf("Adfs: no row for 10.0.0.14; got %+v", r.Adfs)
	}
}

func TestAnalyze_Exchange(t *testing.T) {
	r := Analyze(loadSampleAD(t))
	var found bool
	for _, row := range r.Exchange {
		if row.IP == "10.0.0.15" {
			found = true
		}
	}
	if !found {
		t.Errorf("Exchange: no row for 10.0.0.15; got %+v", r.Exchange)
	}
}

func TestAnalyze_Services(t *testing.T) {
	r := Analyze(loadSampleAD(t))

	var foundGC bool
	for _, row := range r.Services {
		if row.Service == "Global Catalog" {
			for _, h := range row.Hosts {
				if h == "10.0.0.16" {
					foundGC = true
				}
			}
		}
	}
	if !foundGC {
		t.Errorf("Services: no Global Catalog entry for 10.0.0.16; got %+v", r.Services)
	}

	var foundWinRM bool
	for _, row := range r.Services {
		if row.Service == "WinRM" {
			for _, h := range row.Hosts {
				if h == "10.0.0.17" {
					foundWinRM = true
				}
			}
		}
	}
	if !foundWinRM {
		t.Errorf("Services: no WinRM entry for 10.0.0.17; got %+v", r.Services)
	}
}

func TestAnalyze_OutdatedWindows(t *testing.T) {
	r := Analyze(loadSampleAD(t))

	var found bool
	for _, row := range r.OutdatedWindows {
		if row.IP == "10.0.0.11" {
			found = true
			if row.OS == "" {
				t.Errorf("OutdatedWindows 10.0.0.11: OS is empty")
			}
			if row.Reason == "" {
				t.Errorf("OutdatedWindows 10.0.0.11: Reason is empty")
			}
			// OS must reflect Windows Server 2012 R2 (from Detected OS column).
			if !strings.Contains(row.OS, "2012") {
				t.Errorf("OutdatedWindows 10.0.0.11: OS = %q, want to contain \"2012\"", row.OS)
			}
			if row.Reason != "Windows Server 2012/R2" {
				t.Errorf("OutdatedWindows 10.0.0.11: Reason = %q, want \"Windows Server 2012/R2\"", row.Reason)
			}
		}
	}
	if !found {
		t.Errorf("OutdatedWindows: no row for 10.0.0.11; got %+v", r.OutdatedWindows)
	}
}

// TestOutdatedWindowsReason_Windows10NotFlagged locks the decision that a
// supported Windows 10 host is NOT reported as outdated (unlike nadda.py's
// WINDOWS_VERSION_HINTS, which the SP4 port intentionally trims).
func TestOutdatedWindowsReason_Windows10NotFlagged(t *testing.T) {
	if got := outdatedWindowsReason("Windows 10 Enterprise"); got != "" {
		t.Errorf("outdatedWindowsReason(\"Windows 10 Enterprise\") = %q, want \"\"", got)
	}
	// A genuinely unsupported OS still returns a reason.
	if got := outdatedWindowsReason("Windows Server 2012 R2"); got == "" {
		t.Error("outdatedWindowsReason(\"Windows Server 2012 R2\") = \"\", want a non-empty reason")
	}
}

func TestValidNetbios(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"CORP", true},
		{"WORKGROUP", false},
		{"LOCALHOST", false},
		{"NULL", false},
		{"NONE", false},
		{"UNKNOWN", false},
		{"corp.acme.com", false}, // has dot → rejected
		{"", false},
	}
	for _, tc := range cases {
		// Mirror how addNetbiosCandidate prepares the value:
		// NormalizeNetbiosDomain (trim, uppercase).
		norm := strings.ToUpper(strings.TrimSpace(tc.input))
		got := validNetbios(norm)
		if got != tc.want {
			t.Errorf("validNetbios(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
