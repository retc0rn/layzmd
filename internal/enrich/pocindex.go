package enrich

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"regexp"
	"strings"

	"layzmd/internal/httpget"
)

// PocIndex maps an upper-cased CVE ID to the PoC/detection references found for
// it in a bulk dataset (ExploitDB, Metasploit, or Nuclei).
type PocIndex map[string][]PocRef

// Bulk source URLs. All fetched once and cached; all best-effort.
const (
	exploitDBURL  = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
	metasploitURL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
	nucleiTreeURL = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
)

// cveTokenRe matches a CVE identifier anywhere in a string.
var cveTokenRe = regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)

// addRef appends a de-duplicated (by URL) ref under the upper-cased CVE key.
func (idx PocIndex) addRef(cve, source, url string) {
	key := strings.ToUpper(cve)
	for _, r := range idx[key] {
		if r.URL == url {
			return
		}
	}
	idx[key] = append(idx[key], PocRef{Source: source, URL: url})
}

// parseExploitDB builds an index from the exploit-db files_exploits.csv body.
// The "codes" column holds ";"-separated identifiers; CVE tokens map to the
// exploit's web page via its "id" column.
func parseExploitDB(csvBody string) PocIndex {
	idx := PocIndex{}
	r := csv.NewReader(strings.NewReader(csvBody))
	r.FieldsPerRecord = -1 // tolerate ragged rows
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return idx
	}
	idCol, codesCol := -1, -1
	for i, h := range rows[0] {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "id":
			idCol = i
		case "codes":
			codesCol = i
		}
	}
	if idCol < 0 || codesCol < 0 {
		return idx
	}
	for _, row := range rows[1:] {
		if idCol >= len(row) || codesCol >= len(row) {
			continue
		}
		id := strings.TrimSpace(row[idCol])
		if id == "" {
			continue
		}
		for _, cve := range cveTokenRe.FindAllString(row[codesCol], -1) {
			idx.addRef(cve, "ExploitDB", "https://www.exploit-db.com/exploits/"+id)
		}
	}
	return idx
}

// parseMetasploit builds an index from modules_metadata_base.json. Each module
// entry's References may contain CVE tokens; the module maps to its source on
// GitHub.
func parseMetasploit(jsonBody string) PocIndex {
	idx := PocIndex{}
	var mods map[string]struct {
		Fullname   string   `json:"fullname"`
		References []string `json:"references"`
	}
	if err := json.Unmarshal([]byte(jsonBody), &mods); err != nil {
		return idx
	}
	for key, m := range mods {
		full := m.Fullname
		if full == "" {
			full = key
		}
		url := "https://github.com/rapid7/metasploit-framework/blob/master/modules/" + full + ".rb"
		for _, ref := range m.References {
			for _, cve := range cveTokenRe.FindAllString(ref, -1) {
				idx.addRef(cve, "Metasploit", url)
			}
		}
	}
	return idx
}

// parseNuclei builds an index from the nuclei-templates git tree JSON. Template
// paths under cves/ are named by CVE.
func parseNuclei(treeJSON string) PocIndex {
	idx := PocIndex{}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
		} `json:"tree"`
	}
	if err := json.Unmarshal([]byte(treeJSON), &tree); err != nil {
		return idx
	}
	for _, e := range tree.Tree {
		if !strings.HasSuffix(strings.ToLower(e.Path), ".yaml") {
			continue
		}
		for _, cve := range cveTokenRe.FindAllString(e.Path, -1) {
			idx.addRef(cve, "Nuclei", "https://github.com/projectdiscovery/nuclei-templates/blob/main/"+e.Path)
		}
	}
	return idx
}

// fetchPocIndex GETs url (best-effort) and runs parse on the body. On any error
// it returns an empty index.
func fetchPocIndex(ctx context.Context, g httpget.HTTPGetter, url string, parse func(string) PocIndex) PocIndex {
	body, err := g.Get(ctx, url, pocUserAgent, nil)
	if err != nil {
		return PocIndex{}
	}
	return parse(body)
}
