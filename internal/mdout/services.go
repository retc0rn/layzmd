package mdout

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"layzmd/internal/services"
	"layzmd/internal/svcclass"
)

type serviceVariant struct {
	port, transport string
	ips             []string
	portNum         int
}

type serviceNote struct {
	name      string
	category  string
	variants  []serviceVariant
	hostCount int    // distinct hosts across variants
	path      string // Services/<Category>/<slug>.md
}

// serviceNotes groups ProtoGroups by service name into per-name notes,
// classifies each into a category folder, and assigns collision-free paths.
// SINGLE source of note paths for both the index and the writer.
func serviceNotes(groups []services.ProtoGroup) []serviceNote {
	type agg struct {
		name     string
		variants []serviceVariant
		hosts    map[string]struct{}
	}
	byName := map[string]*agg{}
	var order []string
	for _, g := range groups {
		key := strings.ToLower(g.Name)
		a, ok := byName[key]
		if !ok {
			a = &agg{name: g.Name, hosts: map[string]struct{}{}}
			byName[key] = a
			order = append(order, key)
		}
		pn, _ := strconv.Atoi(g.Port)
		a.variants = append(a.variants, serviceVariant{port: g.Port, transport: g.Transport, ips: g.IPs, portNum: pn})
		for _, ip := range g.IPs {
			a.hosts[ip] = struct{}{}
		}
	}

	notes := make([]serviceNote, 0, len(order))
	for _, key := range order {
		a := byName[key]
		// Order variants by numeric port then transport.
		sort.SliceStable(a.variants, func(i, j int) bool {
			if a.variants[i].portNum != a.variants[j].portNum {
				return a.variants[i].portNum < a.variants[j].portNum
			}
			return a.variants[i].transport < a.variants[j].transport
		})
		// Category: classify by name using the lowest-port variant as tiebreak.
		cat := svcclass.Classify(a.name, a.variants[0].port, a.variants[0].transport)
		notes = append(notes, serviceNote{
			name:      a.name,
			category:  cat,
			variants:  a.variants,
			hostCount: len(a.hosts),
		})
	}

	// Deterministic order: by category (fixed order), then service name.
	catRank := map[string]int{}
	for i, c := range svcclass.Categories() {
		catRank[c] = i
	}
	sort.SliceStable(notes, func(i, j int) bool {
		if catRank[notes[i].category] != catRank[notes[j].category] {
			return catRank[notes[i].category] < catRank[notes[j].category]
		}
		return strings.ToLower(notes[i].name) < strings.ToLower(notes[j].name)
	})

	// Assign collision-free paths within each category folder.
	slugCount := map[string]int{} // key: category/slug
	for i := range notes {
		slug := Slug(notes[i].name)
		key := notes[i].category + "/" + slug
		slugCount[key]++
		if n := slugCount[key]; n > 1 {
			slug = fmt.Sprintf("%s-%d", slug, n)
		}
		notes[i].path = "Services/" + sanitizePathSeg(notes[i].category) + "/" + slug + ".md"
	}
	return notes
}

// RenderServiceNote renders one service note with per-variant sections.
// Pure: no I/O.
func RenderServiceNote(n serviceNote) string {
	var sb strings.Builder
	ports := make([]string, 0, len(n.variants))
	for _, v := range n.variants {
		ports = append(ports, v.port+"/"+v.transport)
	}
	writeFrontmatter(&sb, [][2]string{
		{"category", n.category},
		{"service", n.name},
		{"ports", "[" + strings.Join(ports, ", ") + "]"},
		{"hosts", strconv.Itoa(n.hostCount)},
	})
	sb.WriteString("# " + n.name + "\n")
	for _, v := range n.variants {
		hostWord := "hosts"
		if len(v.ips) == 1 {
			hostWord = "host"
		}
		sb.WriteString(fmt.Sprintf("\n## %s/%s — %d %s\n", v.port, v.transport, len(v.ips), hostWord))
		sb.WriteString("```\n")
		for _, ip := range v.ips {
			sb.WriteString(ip + "\n")
		}
		sb.WriteString("```\n")
	}
	return sb.String()
}

// RenderServicesIndex renders Services.md — a per-category summary + links.
// Pure: no I/O.
func RenderServicesIndex(groups []services.ProtoGroup) string {
	notes := serviceNotes(groups)
	var sb strings.Builder
	sb.WriteString("# Services\n\n")

	// Summary: per-category service + distinct-host counts.
	type catStat struct {
		svcs  int
		hosts map[string]struct{}
	}
	stats := map[string]*catStat{}
	for _, n := range notes {
		cs := stats[n.category]
		if cs == nil {
			cs = &catStat{hosts: map[string]struct{}{}}
			stats[n.category] = cs
		}
		cs.svcs++
		for _, v := range n.variants {
			for _, ip := range v.ips {
				cs.hosts[ip] = struct{}{}
			}
		}
	}
	sb.WriteString("> [!abstract] Summary\n")
	sb.WriteString("> | Category | Services | Hosts |\n> |---|---:|---:|\n")
	for _, c := range svcclass.Categories() {
		if cs := stats[c]; cs != nil {
			sb.WriteString(fmt.Sprintf("> | %s | %d | %d |\n", c, cs.svcs, len(cs.hosts)))
		}
	}

	// Per-category sections with links (notes already sorted by category then name).
	lastCat := ""
	for _, n := range notes {
		if n.category != lastCat {
			sb.WriteString("\n## " + n.category + "\n")
			lastCat = n.category
		}
		ports := make([]string, 0, len(n.variants))
		for _, v := range n.variants {
			ports = append(ports, v.port+"/"+v.transport)
		}
		hostWord := "hosts"
		if n.hostCount == 1 {
			hostWord = "host"
		}
		link := strings.TrimSuffix(n.path, ".md")
		sb.WriteString(fmt.Sprintf("- [[%s|%s]] — %s · %d %s\n", link, n.name, strings.Join(ports, ", "), n.hostCount, hostWord))
	}
	return sb.String()
}

// WriteServices writes Services.md and the Services/ subfolder notes into dir.
func WriteServices(dir string, groups []services.ProtoGroup) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sub := filepath.Join(dir, "Services")
	if err := os.RemoveAll(sub); err != nil {
		return err
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		return err
	}
	for _, n := range serviceNotes(groups) {
		p := filepath.Join(dir, filepath.FromSlash(n.path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(RenderServiceNote(n)), 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, "Services.md"), []byte(RenderServicesIndex(groups)), 0o644)
}
