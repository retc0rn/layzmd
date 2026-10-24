package websurface

import (
	"regexp"
	"sort"
	"strings"

	"layzmd/internal/ipsort"
	"layzmd/internal/nessus"
)

var serverTypeRe = regexp.MustCompile(`(?i)server type is\s*:?\s*(.+)`)

// extractSoftware pulls the web-server software string from plugin output.
func extractSoftware(out string) string {
	if m := serverTypeRe.FindStringSubmatch(out); m != nil {
		return strings.TrimSpace(strings.SplitN(strings.TrimSpace(m[1]), "\n", 2)[0])
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}

// Build assembles the Report from all findings.
func Build(fs []nessus.Finding, meta Meta) Report {
	type key struct{ host, port string }
	svcMap := map[key]*WebService{}
	hostOrder := []string{}
	hostSeen := map[string]bool{}
	tls := map[key]bool{}

	get := func(k key) *WebService {
		s := svcMap[k]
		if s == nil {
			s = &WebService{Port: k.port}
			svcMap[k] = s
			if !hostSeen[k.host] {
				hostSeen[k.host] = true
				hostOrder = append(hostOrder, k.host)
			}
		}
		return s
	}

	// First pass: any SSL/TLS finding marks its host:port as TLS.
	for _, f := range fs {
		if strings.HasPrefix(f.Name, "SSL") || strings.HasPrefix(f.Name, "TLS") {
			tls[key{f.HostIP, f.Port}] = true
		}
	}

	for _, f := range fs {
		if f.HostIP == "" || f.Port == "" {
			continue
		}
		k := key{f.HostIP, f.Port}
		out := f.PluginOutput
		switch f.Name {
		case "HyperText Transfer Protocol (HTTP) Information", "Embedded Web Server Detection":
			get(k)
		case "HTTP Server Type and Version", "Apache HTTP Server Version", "lighttpd HTTP Server Detection":
			s := get(k)
			if s.Software == "" {
				s.Software = extractSoftware(out)
			}
		case "Web Application Sitemap", "Web mirroring":
			s := get(k)
			for _, ln := range strings.Split(out, "\n") {
				t := strings.TrimSpace(ln)
				t = strings.TrimPrefix(t, "- ")
				if strings.HasPrefix(t, "http") || strings.HasPrefix(t, "/") {
					s.Pages = appendUniq(s.Pages, urlPath(t))
				}
			}
		case "Web Server Directory Enumeration":
			s := get(k)
			for _, p := range parseListPaths(out, "discovered") {
				s.Dirs = appendDir(s.Dirs, DirEntry{Path: p})
			}
		case "HTTP Methods Allowed (per directory)":
			s := get(k)
			// Only the "response to an OPTIONS request" block is reliable; the
			// "Based on tests of each method" block enumerates every method
			// Nessus probed (WebDAV included) and would make nearly every
			// directory look writable — drop everything from that marker on.
			reliable := out
			if i := strings.Index(out, "Based on tests of each method"); i >= 0 {
				reliable = out[:i]
			}
			for _, d := range parseMethodsBlocks(reliable) {
				s.Dirs = appendDir(s.Dirs, d)
			}
		case "Protected Web Page Detection":
			s := get(k)
			s.Auth = append(s.Auth, parseProtectedPages(out)...)
		case "Web Server Allows Password Auto-Completion":
			get(k).AutoComplete = true
		case "Web Server Uses Basic Authentication Without HTTPS":
			get(k).BasicNoHTTPS = true
		case "Web Server Unconfigured - Default Install Page Present":
			get(k).DefaultPage = true
		}
	}

	// Finalize each service: TLS, Kind, classify, sort pages.
	for k, s := range svcMap {
		s.TLS = tls[k] || k.port == "443" || k.port == "8443"
		if isManagement(*s) {
			s.Kind = "management"
		} else {
			s.Kind = "web"
			classify(s)
		}
		sort.Strings(s.Pages)
	}

	byHost := map[string][]WebService{}
	for k, s := range svcMap {
		byHost[k.host] = append(byHost[k.host], *s)
	}
	sort.Slice(hostOrder, func(i, j int) bool {
		return ipsort.Key(hostOrder[i]) < ipsort.Key(hostOrder[j])
	})

	r := Report{Meta: meta, Files: map[string][]CatEntry{}}
	for _, h := range hostOrder {
		svcs := byHost[h]
		sort.Slice(svcs, func(i, j int) bool { return portNum(svcs[i].Port) < portNum(svcs[j].Port) })
		r.Hosts = append(r.Hosts, HostWeb{Host: h, Services: svcs})
		r.Counts.Hosts++
		for _, s := range svcs {
			r.Counts.Services++
			if s.TLS {
				r.Counts.TLS++
			} else {
				r.Counts.Plaintext++
			}
			if s.Kind == "management" {
				// Excluded from all category outputs; counted only.
				r.Counts.Management++
				continue
			}
			r.Counts.Browsable++
			collectRollups(&r, h, s)
		}
	}
	sortEntries(r.Logins)
	sortEntries(r.APIs)
	sortEntries(r.BasicAuth)
	sortEntries(r.Admin)
	sortEntries(r.Dangerous)
	sortEntries(r.DefaultPage)
	sortEntries(r.Other)
	for name := range r.Files {
		sortEntries(r.Files[name])
	}
	return r
}

// sortEntries orders category entries by host (numeric), then port, then path,
// so the rendered URL lists group naturally by host.
func sortEntries(es []CatEntry) {
	sort.Slice(es, func(i, j int) bool {
		ki, kj := ipsort.Key(es[i].Host), ipsort.Key(es[j].Host)
		if ki != kj {
			return ki < kj
		}
		if es[i].Port != es[j].Port {
			return portNum(es[i].Port) < portNum(es[j].Port)
		}
		return es[i].Path < es[j].Path
	})
}

// collectRollups appends a browsable service's URLs to the category rollups.
// Every page/dir URL is classified; a URL matching no category falls to Other.
// Service-level flags (auto-complete, basic-without-HTTPS, default page) point
// at the service root "/".
func collectRollups(r *Report, host string, s WebService) {
	add := func(dst *[]CatEntry, path, detail string) {
		*dst = append(*dst, CatEntry{Host: host, Port: s.Port, Path: path, Detail: detail, TLS: s.TLS})
	}
	authScheme := map[string]string{}
	for _, a := range s.Auth {
		authScheme[a.Path] = a.Scheme
	}
	dangerByPath := map[string][]string{}
	for _, d := range s.Dirs {
		if dm := dangerousMethods(d.Methods); len(dm) > 0 {
			dangerByPath[d.Path] = dm
		}
	}
	for _, p := range dedup(append(pagesAndDirs(s), authPaths(s)...)) {
		matched := false
		for _, c := range pathCats(p) {
			matched = true
			switch c {
			case "login":
				add(&r.Logins, p, "")
			case "api":
				add(&r.APIs, p, "")
			case "admin":
				add(&r.Admin, p, "")
			}
		}
		for _, name := range fileCatNames(p) {
			r.Files[name] = append(r.Files[name], CatEntry{Host: host, Port: s.Port, Path: p, TLS: s.TLS})
			matched = true
		}
		switch authScheme[p] {
		case "Basic":
			add(&r.BasicAuth, p, "Basic")
			matched = true
		case "Form":
			add(&r.Logins, p, "Form")
			matched = true
		}
		if dm, ok := dangerByPath[p]; ok {
			add(&r.Dangerous, p, strings.Join(dm, " "))
			matched = true
		}
		if !matched {
			add(&r.Other, p, "")
		}
	}
	if s.AutoComplete {
		add(&r.Logins, "/", "auto-complete form")
	}
	if s.BasicNoHTTPS {
		add(&r.BasicAuth, "/", "no TLS")
	}
	if s.DefaultPage {
		add(&r.DefaultPage, "/", s.Software)
	}
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func appendDir(ds []DirEntry, d DirEntry) []DirEntry {
	for i, x := range ds {
		if x.Path == d.Path {
			if len(d.Methods) > len(x.Methods) {
				ds[i].Methods = d.Methods
			}
			return ds
		}
	}
	return append(ds, d)
}

func portNum(p string) int {
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func pagesAndDirs(s WebService) []string {
	out := append([]string{}, s.Pages...)
	for _, d := range s.Dirs {
		out = append(out, d.Path)
	}
	return out
}

func authPaths(s WebService) []string {
	var out []string
	for _, a := range s.Auth {
		out = append(out, a.Path)
	}
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

