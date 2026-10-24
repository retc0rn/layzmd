package enrich

import "testing"

func TestParseExploitDB(t *testing.T) {
	csv := "id,file,description,date,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n" +
		"50000,x,desc,,,,,,,,1,\"CVE-2021-1;CVE-2021-2\",,,,,\n" +
		"50001,y,desc,,,,,,,,1,\"OSVDB-9\",,,,,\n"
	idx := parseExploitDB(csv)
	if len(idx["CVE-2021-1"]) != 1 || idx["CVE-2021-1"][0].URL != "https://www.exploit-db.com/exploits/50000" {
		t.Errorf("CVE-2021-1 wrong: %+v", idx["CVE-2021-1"])
	}
	if idx["CVE-2021-1"][0].Source != "ExploitDB" {
		t.Error("source label")
	}
	if len(idx["CVE-2021-2"]) != 1 {
		t.Error("CVE-2021-2 missing")
	}
	if _, ok := idx["OSVDB-9"]; ok {
		t.Error("non-CVE code indexed")
	}
}

func TestParseMetasploit(t *testing.T) {
	j := `{"exploit/windows/smb/ms17_010_eternalblue":{"fullname":"exploit/windows/smb/ms17_010_eternalblue","references":["CVE-2017-0144","URL-https://x"]}}`
	idx := parseMetasploit(j)
	got := idx["CVE-2017-0144"]
	want := "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploit/windows/smb/ms17_010_eternalblue.rb"
	if len(got) != 1 || got[0].URL != want || got[0].Source != "Metasploit" {
		t.Errorf("metasploit wrong: %+v", got)
	}
}

func TestParseNuclei(t *testing.T) {
	j := `{"tree":[{"path":"http/cves/2021/CVE-2021-1.yaml"},{"path":"http/misc/other.yaml"},{"path":"README.md"}]}`
	idx := parseNuclei(j)
	got := idx["CVE-2021-1"]
	if len(got) != 1 || got[0].Source != "Nuclei" ||
		got[0].URL != "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-1.yaml" {
		t.Errorf("nuclei wrong: %+v", got)
	}
	if len(idx) != 1 {
		t.Errorf("non-CVE path indexed: %v", idx)
	}
}

func TestParse_BadInput(t *testing.T) {
	if len(parseExploitDB("")) != 0 || len(parseMetasploit("not json")) != 0 || len(parseNuclei("{")) != 0 {
		t.Error("bad input should yield empty index, not panic")
	}
}

func TestMergePocRefs(t *testing.T) {
	edb := PocIndex{"CVE-2021-1": {{Source: "ExploitDB", URL: "e"}}}
	nuc := PocIndex{"CVE-2021-2": {{Source: "Nuclei", URL: "n"}}}

	// CVE in ExploitDB → HasPoc true (case-insensitive key).
	p := mergePocRefs(nil, "cve-2021-1", edb, nuc)
	if p == nil || !p.HasPoc || len(p.Refs) != 1 {
		t.Errorf("edb merge: %+v", p)
	}
	// Nuclei-only → ref present but HasPoc stays false.
	p2 := mergePocRefs(nil, "CVE-2021-2", edb, nuc)
	if p2 == nil || p2.HasPoc || len(p2.Refs) != 1 || p2.Refs[0].Source != "Nuclei" {
		t.Errorf("nuclei merge: %+v", p2)
	}
	// No hit → returns the (nil) input unchanged.
	if mergePocRefs(nil, "CVE-9999-9", edb, nuc) != nil {
		t.Error("no-hit should stay nil")
	}
	// Dedup by URL against existing refs.
	base := &PocResult{Refs: []PocRef{{Source: "ExploitDB", URL: "e"}}}
	if merged := mergePocRefs(base, "CVE-2021-1", edb); len(merged.Refs) != 1 {
		t.Errorf("dedup failed: %+v", merged.Refs)
	}
}
