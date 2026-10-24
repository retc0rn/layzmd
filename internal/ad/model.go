// Package ad provides Active Directory analysis of Nessus findings.
// Analyze returns a Report; later SP4 tasks populate the non-discovery sections.
package ad

// Domain represents an observed AD/DNS domain with aggregated metadata.
type Domain struct {
	Name       string
	Confidence string
	Sources    []string
	Hosts      int
}

// NetbiosName represents an observed NetBIOS domain/workgroup name.
type NetbiosName struct {
	Name  string
	Hosts int
}

// DCRow is a discovered Domain Controller row.
type DCRow struct {
	IP, FQDN, Domain, Confidence string
	Domains                      []string
}

// DNSRow is a discovered DNS server row.
type DNSRow struct {
	IP, FQDN, Port string
}

// SMBSigningSummary is a per-domain summary of SMB signing posture.
type SMBSigningSummary struct {
	Domain string
	Hosts  int
}

// SMBSigningRow is a per-host SMB signing finding.
type SMBSigningRow struct {
	Domain, IP, FQDN, Port string
}

// ShareSummary is a per-domain summary of SMB share exposure.
type ShareSummary struct {
	Domain                                       string
	Hosts, Shares, NonDefault, Writable, LowPriv int
}

// ShareRow is a notable SMB share finding.
type ShareRow struct {
	Domain, IP, FQDN, Share, UNC, Access string
	Principals                           []string
}

// GuestRow is a guest-account access finding.
type GuestRow struct {
	Domain, IP, FQDN, Port, Access string
}

// SmbV1Row is an SMBv1 / null-session finding.
type SmbV1Row struct {
	Domain, IP, FQDN, Detail, Port string
}

// EmailSummary is a per-source summary of discovered email addresses.
type EmailSummary struct {
	Source              string
	Emails, SourceHosts int
	Confidence          string
}

// EmailRow is a single email address finding.
type EmailRow struct {
	Email, Source string
	SourceHosts   []string
	Confidence    string
}

// DefensiveRow is a detected defensive technology (AV, EDR, firewall, etc.).
type DefensiveRow struct {
	Category, Product string
	Hosts             int
	Confidence        string
	EvidenceTypes     []string
}

// MssqlRow is a discovered MS-SQL server.
type MssqlRow struct {
	Domain, IP, Port, FQDN, Instance, Version string
	Domains                                   []string
}

// AdcsCARow is a discovered ADCS Certificate Authority.
type AdcsCARow struct {
	Domain, IP, Ports, FQDN, Issuer, Subject string
}

// AdcsEndpointRow is a discovered ADCS enrollment endpoint.
type AdcsEndpointRow struct {
	Domain, IP, Ports, FQDN, Indicator string
}

// SccmRow is a discovered SCCM service.
type SccmRow struct {
	Domain, Role, IP, Port, FQDN, Site, Version string
}

// AdfsRow is a discovered ADFS server.
type AdfsRow struct {
	Domain, IP, FQDN, Services, Ports string
}

// ExchangeRow is a discovered Exchange server.
type ExchangeRow struct {
	Domain, IP, FQDN, Services, Ports string
}

// ServiceRow is an infrastructure service (Global Catalog, WinRM, etc.).
type ServiceRow struct {
	Service string
	Hosts   []string
	Detail  string
}

// OutdatedWinRow is a host running an unsupported/EOL Windows version.
type OutdatedWinRow struct {
	Domain, IP, FQDN, OS, Reason string
}

// Report is the full output of Analyze. Discovery sections (Domains, Netbios,
// DomainControllers, DNSServers) are populated by Task 2. All other slices are
// populated by later SP4 tasks.
type Report struct {
	// ScanName is the name of the scan (used as the note title and frontmatter scan field).
	ScanName string
	// Generated is the date string for the generated frontmatter field (e.g. "2026-07-10").
	Generated string

	Domains           []Domain
	Netbios           []NetbiosName
	DomainControllers []DCRow
	DNSServers        []DNSRow

	SMBSigningSummary []SMBSigningSummary
	SMBSigning        []SMBSigningRow

	ShareSummary []ShareSummary
	Shares       []ShareRow
	Guest        []GuestRow
	SmbV1        []SmbV1Row

	EmailSummary []EmailSummary
	Emails       []EmailRow

	Defensive []DefensiveRow
	Mssql     []MssqlRow

	AdcsCA        []AdcsCARow
	AdcsEndpoints []AdcsEndpointRow
	Sccm          []SccmRow

	Adfs            []AdfsRow
	Exchange        []ExchangeRow
	Services        []ServiceRow
	OutdatedWindows []OutdatedWinRow
}
