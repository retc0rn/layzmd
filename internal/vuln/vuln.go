// Package vuln groups Nessus findings by normalised name into a three-level
// tree: VulnGroup → VulnCve → PortHosts.
//
// Port of PTCompanion.Core.Data.SqliteProject.CollectVulnGroups (C#).
package vuln

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"layzmd/internal/category"
	"layzmd/internal/ipsort"
	"layzmd/internal/nessus"
	"layzmd/internal/priority"
)

// PortHosts holds a port string (e.g. "8080/tcp") and the sorted IPs on it.
type PortHosts struct {
	Port string
	IPs  []string
}

// VulnCve holds per-CVE aggregated data within a VulnGroup.
type VulnCve struct {
	CVE, CVSS, Risk string
	HostCount       int
	IPs             []string
	HostsByPort     []PortHosts
	Description     string
	Solution        string
	SeeAlso         string
}

// VulnGroup holds aggregated data for a group of findings sharing the same
// normalised vulnerability name.
type VulnGroup struct {
	Name, Category, Risk string
	CVEs                 []VulnCve
	HostCount            int
	IPs                  []string
	HostsByPort          []PortHosts
	CVSS                 string
	Description          string
	Solution             string
	SeeAlso              string
}

// cvePattern matches a valid CVE token (case-insensitive; after uppercasing).
var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// riskRank returns an integer rank for a Nessus risk string.
// Delegates to priority.SeverityPoints for consistency.
func riskRank(risk string) int {
	return priority.SeverityPoints(risk)
}

// rankToRisk converts a numeric rank back to a Nessus risk string.
func rankToRisk(rank int) string {
	switch rank {
	case 4:
		return "Critical"
	case 3:
		return "High"
	case 2:
		return "Medium"
	case 1:
		return "Low"
	default:
		return "None"
	}
}

// groupAccumulator holds per-group working state during accumulation.
type groupAccumulator struct {
	display     string
	synopsis    string // representative (from best-rank finding)
	description string
	solution    string
	seeAlso     string
	bestRank    int
	hasRank     bool // true after the first finding is processed
	maxCvssVal  float64
	maxCvssStr  string
	allIPs      map[string]struct{}
	portIPs     map[string]map[string]struct{} // port-string → set of IPs
	cves        map[string]*cveAccumulator
}

func newGroupAccumulator() *groupAccumulator {
	return &groupAccumulator{
		maxCvssVal: -1,
		allIPs:     make(map[string]struct{}),
		portIPs:    make(map[string]map[string]struct{}),
		cves:       make(map[string]*cveAccumulator),
	}
}

// cveAccumulator holds per-CVE working state during accumulation.
type cveAccumulator struct {
	bestRank    int
	hasRank     bool // true after the first finding is processed
	maxCvssVal  float64
	maxCvssStr  string
	description string
	solution    string
	seeAlso     string
	allIPs      map[string]struct{}
	portIPs     map[string]map[string]struct{}
}

func newCveAccumulator() *cveAccumulator {
	return &cveAccumulator{
		maxCvssVal: -1,
		allIPs:     make(map[string]struct{}),
		portIPs:    make(map[string]map[string]struct{}),
	}
}

// addIPToPort adds ip to the per-port map under the given portStr.
func addIPToPort(portIPs map[string]map[string]struct{}, portStr, ip string) {
	if _, ok := portIPs[portStr]; !ok {
		portIPs[portStr] = make(map[string]struct{})
	}
	portIPs[portStr][ip] = struct{}{}
}

// buildPortHosts converts a portStr→ipSet map into a sorted []PortHosts.
// Ports are ordered numerically by the integer before '/', then lexically.
// IPs within each port are sorted by ipsort.Key then lexically.
func buildPortHosts(portIPs map[string]map[string]struct{}) []PortHosts {
	out := make([]PortHosts, 0, len(portIPs))
	for portStr, ipSet := range portIPs {
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool {
			ki, kj := ipsort.Key(ips[i]), ipsort.Key(ips[j])
			if ki != kj {
				return ki < kj
			}
			return ips[i] < ips[j]
		})
		out = append(out, PortHosts{Port: portStr, IPs: ips})
	}
	// Sort ports numerically (by the integer before '/'), then lexically.
	sort.Slice(out, func(i, j int) bool {
		numI := portNum(out[i].Port)
		numJ := portNum(out[j].Port)
		if numI != numJ {
			return numI < numJ
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// portNum parses the numeric port from a "port/proto" string.
// Returns math.MaxInt32 on parse failure.
func portNum(portStr string) int {
	slash := strings.IndexByte(portStr, '/')
	if slash > 0 {
		if n, err := strconv.Atoi(portStr[:slash]); err == nil {
			return n
		}
	}
	return 1<<31 - 1
}

// sortedIPs converts an IP set to a sorted slice (by ipsort.Key, then string).
func sortedIPs(ipSet map[string]struct{}) []string {
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		ki, kj := ipsort.Key(ips[i]), ipsort.Key(ips[j])
		if ki != kj {
			return ki < kj
		}
		return ips[i] < ips[j]
	})
	return ips
}

// Group groups findings by normalised name, returning a sorted []VulnGroup.
// Groups are sorted by max-risk-rank descending, then by Name ascending.
// Within each group, CVEs are sorted by CVE string ascending.
// All IP and port orderings are deterministic (ipsort.Key + explicit sorts).
func Group(fs []nessus.Finding) []VulnGroup {
	// Pass 1: accumulate by normalised-name key.
	// Use a slice to record insertion order (for deterministic processing later).
	accMap := make(map[string]*groupAccumulator)
	var keyOrder []string // first-seen order (for reproducibility)

	for _, f := range fs {
		// Group by the raw finding name (case-insensitive key), preserving the
		// exact Nessus name for display — no version stripping.
		display := strings.TrimSpace(f.Name)
		key := strings.ToLower(display)
		if key == "" {
			continue
		}

		proto := f.Protocol
		if proto == "" {
			proto = "tcp"
		}
		// Port string: "<port>/<proto>"; skip portless (port "" or "0").
		portStr := ""
		if f.Port != "" && f.Port != "0" {
			portStr = f.Port + "/" + proto
		}

		rank := riskRank(f.Risk)

		// Get or create group accumulator.
		a, exists := accMap[key]
		if !exists {
			a = newGroupAccumulator()
			accMap[key] = a
			keyOrder = append(keyOrder, key)
		}

		// Update group representative details from highest-rank finding.
		// Use >= on first finding (hasRank==false) so rank-0 findings still set fields.
		if !a.hasRank || rank > a.bestRank {
			a.hasRank = true
			a.bestRank = rank
			a.display = display
			a.synopsis = f.Synopsis
			a.description = f.Description
			a.solution = f.Solution
			a.seeAlso = f.SeeAlso
		}

		// Track all IPs at group level (including portless).
		if f.HostIP != "" {
			a.allIPs[f.HostIP] = struct{}{}
		}

		// Track group-level port→IPs (only for ported findings).
		if f.HostIP != "" && portStr != "" {
			addIPToPort(a.portIPs, portStr, f.HostIP)
		}

		// Group-level CVSS: numeric max, keep string form.
		if f.CVSS != "" {
			if v, err := strconv.ParseFloat(f.CVSS, 64); err == nil {
				if v > a.maxCvssVal {
					a.maxCvssVal = v
					a.maxCvssStr = f.CVSS
				}
			}
		}

		// Per-CVE accumulation: split f.CVE on ',', keep valid CVE tokens.
		for _, raw := range strings.Split(f.CVE, ",") {
			cve := strings.ToUpper(strings.TrimSpace(raw))
			if !cvePattern.MatchString(cve) {
				continue
			}

			ca, ok := a.cves[cve]
			if !ok {
				ca = newCveAccumulator()
				a.cves[cve] = ca
			}

			if f.HostIP != "" {
				ca.allIPs[f.HostIP] = struct{}{}
			}
			if f.HostIP != "" && portStr != "" {
				addIPToPort(ca.portIPs, portStr, f.HostIP)
			}

			if f.CVSS != "" {
				if v, err := strconv.ParseFloat(f.CVSS, 64); err == nil {
					if v > ca.maxCvssVal {
						ca.maxCvssVal = v
						ca.maxCvssStr = f.CVSS
					}
				}
			}

			if !ca.hasRank || rank > ca.bestRank {
				ca.hasRank = true
				ca.bestRank = rank
				ca.description = f.Description
				ca.solution = f.Solution
				ca.seeAlso = f.SeeAlso
			}
		}
	}

	// Pass 2: build output VulnGroups.
	result := make([]VulnGroup, 0, len(accMap))
	for _, key := range keyOrder {
		a := accMap[key]

		// Build CVE list sorted by CVE string.
		cveList := make([]VulnCve, 0, len(a.cves))
		for cve, ca := range a.cves {
			cveIPs := sortedIPs(ca.allIPs)
			cvePortHosts := buildPortHosts(ca.portIPs)
			cveList = append(cveList, VulnCve{
				CVE:         cve,
				CVSS:        ca.maxCvssStr,
				Risk:        rankToRisk(ca.bestRank),
				HostCount:   len(cveIPs),
				IPs:         cveIPs,
				HostsByPort: cvePortHosts,
				Description: ca.description,
				Solution:    ca.solution,
				SeeAlso:     ca.seeAlso,
			})
		}
		sort.Slice(cveList, func(i, j int) bool {
			return cveList[i].CVE < cveList[j].CVE
		})

		groupIPs := sortedIPs(a.allIPs)
		groupPortHosts := buildPortHosts(a.portIPs)

		// Category: keyword-only in SP3a (nil CWEs).
		// Use Synopsis if non-empty, else Description, as the classifier text.
		classifierText := a.synopsis
		if classifierText == "" {
			classifierText = a.description
		}
		cat := category.Classify(nil, a.display, classifierText)

		result = append(result, VulnGroup{
			Name:        a.display,
			Category:    cat,
			Risk:        rankToRisk(a.bestRank),
			CVEs:        cveList,
			HostCount:   len(groupIPs),
			IPs:         groupIPs,
			HostsByPort: groupPortHosts,
			CVSS:        a.maxCvssStr,
			Description: a.description,
			Solution:    a.solution,
			SeeAlso:     a.seeAlso,
		})
	}

	// Sort: max-risk-rank DESC, then Name ASC.
	sort.Slice(result, func(i, j int) bool {
		ri := riskRank(result[i].Risk)
		rj := riskRank(result[j].Risk)
		if ri != rj {
			return ri > rj
		}
		return result[i].Name < result[j].Name
	})

	return result
}
