// Package services groups Nessus findings by application protocol.
package services

import (
	"sort"
	"strconv"

	"layzmd/internal/ipsort"
	"layzmd/internal/nessus"
	"layzmd/internal/protoname"
	"layzmd/internal/svcname"
)

// ProtoGroup holds a resolved protocol name, the port, transport, and the
// sorted list of host IPs that expose that service.
type ProtoGroup struct {
	Name      string
	Port      string
	Transport string
	IPs       []string
}

// resolveName applies the confidence-tiered resolver for a (port,transport)
// bucket. Order (Service Detection is authoritative — user directive):
//  1. specific Service-Detection service (plugin 22964 named a service)
//  2. curated port map (also resolves the TLS-only case for standard TLS ports)
//  3. TLS-only SD flag on an unmapped port → "SSL/TLS"
//  4. plugin-Name keyword hint, word-boundary + port-plausibility gated
//
// Returns "" when the service cannot be identified (a SYN-only open port with
// no Service Detection, no port-map entry, and no plausible keyword — including
// the dynamic/ephemeral range). Such buckets are excluded from Services.
func resolveName(sdSvc string, sdTLS bool, pluginNames []string, port, transport string) string {
	if sdSvc != "" {
		return sdSvc
	}
	if name, ok := protoname.ByPort(port, transport); ok {
		return name
	}
	if sdTLS {
		return "SSL/TLS"
	}
	for _, pn := range pluginNames {
		if svc, ok := svcname.KeywordName(pn); ok && svcname.PlausibleForPort(svc, port, transport) {
			return svc
		}
	}
	return ""
}

// Group buckets findings by (port, transport), resolves a canonical service
// name per bucket via the tiered resolver, and collects distinct host IPs.
// Findings with Port == "" or Port == "0" are excluded. IPs within a group are
// numeric-sorted (ipsort.Key) then string; groups are sorted by Name then port.
func Group(fs []nessus.Finding) []ProtoGroup {
	type portKey struct{ port, transport string }
	type bucket struct {
		sdSvc       string
		sdTLS       bool
		pluginNames []string
		ips         map[string]struct{}
	}

	keyOrder := []portKey{}
	buckets := make(map[portKey]*bucket)

	for _, f := range fs {
		if f.Port == "" || f.Port == "0" {
			continue
		}
		tr := f.Protocol
		if tr == "" {
			tr = "tcp"
		}
		key := portKey{f.Port, tr}

		b, exists := buckets[key]
		if !exists {
			b = &bucket{ips: make(map[string]struct{})}
			buckets[key] = b
			keyOrder = append(keyOrder, key)
		}

		// Tier 1: Service Detection (authoritative when it names a service).
		if svc, tls, found := svcname.ServiceDetection(f.PluginID, f.Name, f.PluginOutput); found {
			if svc != "" && b.sdSvc == "" {
				b.sdSvc = svc
			}
			if tls {
				b.sdTLS = true
			}
		}
		// Tier 3 candidates (plugin names).
		if f.Name != "" {
			b.pluginNames = append(b.pluginNames, f.Name)
		}

		if f.HostIP != "" {
			b.ips[f.HostIP] = struct{}{}
		}
	}

	groups := make([]ProtoGroup, 0, len(keyOrder))
	for _, k := range keyOrder {
		b := buckets[k]
		name := resolveName(b.sdSvc, b.sdTLS, b.pluginNames, k.port, k.transport)
		if name == "" {
			continue // unidentified SYN-only/ephemeral port — excluded from Services
		}

		ips := make([]string, 0, len(b.ips))
		for ip := range b.ips {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool {
			ki, kj := ipsort.Key(ips[i]), ipsort.Key(ips[j])
			if ki != kj {
				return ki < kj
			}
			return ips[i] < ips[j]
		})
		groups = append(groups, ProtoGroup{Name: name, Port: k.port, Transport: k.transport, IPs: ips})
	}

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Name != groups[j].Name {
			return groups[i].Name < groups[j].Name
		}
		pi, _ := strconv.Atoi(groups[i].Port)
		pj, _ := strconv.Atoi(groups[j].Port)
		if pi != pj {
			return pi < pj
		}
		return groups[i].Port < groups[j].Port
	})

	return groups
}
