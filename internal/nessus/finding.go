package nessus

// Finding represents a single vulnerability finding from a Nessus CSV export.
type Finding struct {
	HostIP       string
	FQDN         string
	Port         string
	Protocol     string
	PluginID     string
	Name         string
	Risk         string
	CVE          string
	CVSS         string
	Synopsis     string
	Description  string
	Solution     string
	SeeAlso      string
	PluginOutput string
	Service      string
	DetectedOS   string
}
