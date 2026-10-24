// Package hosts groups Nessus findings by OS category.
package hosts

import (
	"sort"

	"layzmd/internal/ipsort"
	"layzmd/internal/nessus"
	"layzmd/internal/osclass"
	"layzmd/internal/osdetect"
)

// OSVersion holds a specific OS string and the sorted host IPs running it.
// An empty OS string denotes hosts with no detected OS (rendered "Unspecified").
type OSVersion struct {
	OS  string
	IPs []string
}

// OSGroup holds an OS category and its per-version host buckets.
type OSGroup struct {
	Category string
	Versions []OSVersion
}

// HostCount returns the total number of hosts across all versions in the group.
func (g OSGroup) HostCount() int {
	n := 0
	for _, v := range g.Versions {
		n += len(v.IPs)
	}
	return n
}

// categoryRank returns the sort priority for a category name.
// Lower values sort first. Unknown categories get 100.
func categoryRank(cat string) int {
	ranks := map[string]int{
		"Windows Server":  0,
		"Windows Embedded": 1,
		"Windows Desktop": 2,
		"Ubuntu":          3,
		"Debian":          4,
		"Red Hat":         5,
		"CentOS":          6,
		"SUSE":            7,
		"Fedora":          8,
		"Oracle Linux":    9,
		"Linux (other)":   10,
		"macOS":           11,
		"Network device":  12,
		"Unknown":         13,
	}
	if r, ok := ranks[cat]; ok {
		return r
	}
	return 100
}

// Group buckets findings by host OS category, returning sorted OSGroups.
// For each distinct host IP, the OS is determined by:
//  1. First non-empty DetectedOS among the host's findings.
//  2. If still empty, first non-empty result from osdetect.FromPluginOutput
//     over the host's findings' PluginOutput.
//
// IPs within a category are sorted numerically by ipsort.Key, then by string.
// Groups are sorted by categoryRank then category name.
func Group(fs []nessus.Finding) []OSGroup {
	// Collect per-host findings and OS string.
	type hostData struct {
		detectedOS  string
		pluginOuts  []string
	}
	hostMap := make(map[string]*hostData)
	// Preserve insertion order for stable processing.
	var orderedIPs []string

	for _, f := range fs {
		ip := f.HostIP
		if ip == "" {
			continue
		}
		hd, exists := hostMap[ip]
		if !exists {
			hd = &hostData{}
			hostMap[ip] = hd
			orderedIPs = append(orderedIPs, ip)
		}
		if hd.detectedOS == "" && f.DetectedOS != "" {
			hd.detectedOS = f.DetectedOS
		}
		if f.PluginOutput != "" {
			hd.pluginOuts = append(hd.pluginOuts, f.PluginOutput)
		}
	}

	// Determine OS string per host, then bucket by (category, specific OS).
	type catData struct {
		order []string            // OS strings in first-seen order
		byOS  map[string][]string // osString -> IPs
	}
	cats := make(map[string]*catData)
	var catOrder []string

	for _, ip := range orderedIPs {
		hd := hostMap[ip]
		os := hd.detectedOS
		if os == "" {
			for _, po := range hd.pluginOuts {
				if s := osdetect.FromPluginOutput(po); s != "" {
					os = s
					break
				}
			}
		}
		cat := osclass.Classify(os)
		cd, ok := cats[cat]
		if !ok {
			cd = &catData{byOS: map[string][]string{}}
			cats[cat] = cd
			catOrder = append(catOrder, cat)
		}
		if _, seen := cd.byOS[os]; !seen {
			cd.order = append(cd.order, os)
		}
		cd.byOS[os] = append(cd.byOS[os], ip)
	}

	// Build group slice.
	groups := make([]OSGroup, 0, len(cats))
	for _, cat := range catOrder {
		cd := cats[cat]
		versions := make([]OSVersion, 0, len(cd.order))
		for _, os := range cd.order {
			ips := cd.byOS[os]
			sort.Slice(ips, func(i, j int) bool {
				ki, kj := ipsort.Key(ips[i]), ipsort.Key(ips[j])
				if ki != kj {
					return ki < kj
				}
				return ips[i] < ips[j]
			})
			versions = append(versions, OSVersion{OS: os, IPs: ips})
		}
		// Sort versions: host-count desc, then empty-OS last, then OS name asc.
		sort.SliceStable(versions, func(i, j int) bool {
			if len(versions[i].IPs) != len(versions[j].IPs) {
				return len(versions[i].IPs) > len(versions[j].IPs)
			}
			if (versions[i].OS == "") != (versions[j].OS == "") {
				return versions[i].OS != "" // non-empty before empty
			}
			return versions[i].OS < versions[j].OS
		})
		groups = append(groups, OSGroup{Category: cat, Versions: versions})
	}

	// Sort groups by rank then name.
	sort.Slice(groups, func(i, j int) bool {
		ri, rj := categoryRank(groups[i].Category), categoryRank(groups[j].Category)
		if ri != rj {
			return ri < rj
		}
		return groups[i].Category < groups[j].Category
	})

	return groups
}
