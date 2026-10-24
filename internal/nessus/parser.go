package nessus

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// Parse reads a Nessus CSV export from r and returns a slice of Findings.
// Rows with an empty host field are silently skipped.
// Returns an error only if the CSV cannot be read or contains no header row.
func Parse(r io.Reader) ([]Finding, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true

	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("nessus: reading CSV: %w", err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("nessus: CSV has no header row")
	}

	// Build header index keyed by lowercase trimmed header name.
	idx := make(map[string]int, len(records[0]))
	for i, h := range records[0] {
		key := strings.ToLower(strings.TrimSpace(h))
		idx[key] = i
	}

	// col returns the first non-empty value from the given header name candidates.
	col := func(rec []string, names ...string) string {
		for _, name := range names {
			if i, ok := idx[name]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
		}
		return ""
	}

	// firstNonEmpty returns the first non-empty string from the candidates.
	firstNonEmpty := func(vals ...string) string {
		for _, v := range vals {
			if v != "" {
				return v
			}
		}
		return ""
	}

	// riskOrNone returns "None" if the risk value is blank.
	riskOrNone := func(s string) string {
		if strings.TrimSpace(s) == "" {
			return "None"
		}
		return s
	}

	var findings []Finding
	for _, rec := range records[1:] {
		host := col(rec, "host", "ip address", "ip")
		if host == "" {
			continue
		}

		cvss := firstNonEmpty(
			col(rec, "cvss v3.0 base score"),
			col(rec, "cvss v3.1 base score"),
			col(rec, "cvss base score"),
			col(rec, "cvss v2.0 base score"),
		)

		f := Finding{
			HostIP:       host,
			FQDN:         col(rec, "dns name", "fqdn"),
			Port:         col(rec, "port"),
			Protocol:     strings.ToLower(col(rec, "protocol")),
			PluginID:     col(rec, "plugin id", "pluginid"),
			Name:         col(rec, "name", "plugin name"),
			Risk:         riskOrNone(col(rec, "risk", "risk factor")),
			CVE:          col(rec, "cve"),
			CVSS:         cvss,
			Synopsis:     col(rec, "synopsis"),
			Description:  col(rec, "description"),
			Solution:     col(rec, "solution"),
			SeeAlso:      col(rec, "see also"),
			PluginOutput: col(rec, "plugin output"),
			Service:      col(rec, "service", "svc_name"),
			DetectedOS:   col(rec, "detected os"),
		}
		findings = append(findings, f)
	}

	return findings, nil
}
