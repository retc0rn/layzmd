package mdout

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"layzmd/internal/ad"
	"layzmd/internal/canvas"
)

func adCanvasReport() ad.Report {
	return ad.Report{
		ScanName:          "T",
		Domains:           []ad.Domain{{Name: "corp.local", Confidence: "High", Hosts: 3}},
		DomainControllers: []ad.DCRow{{IP: "10.0.0.1", FQDN: "dc1.corp.local"}},
		SMBSigning:        []ad.SMBSigningRow{{Domain: "corp.local", IP: "10.0.0.5"}},
		AdcsCA:            []ad.AdcsCARow{{Domain: "corp.local", IP: "10.0.0.9"}},
	}
}

func TestRenderADCanvas(t *testing.T) {
	c := RenderADCanvas(adCanvasReport())

	// hub + 2 group boxes + 4 section file nodes (Domains, DCs = discovery;
	// SMB Signing, ADCS = attack).
	var hub, groups, files int
	byID := map[string]canvas.Node{}
	for _, n := range c.Nodes {
		byID[n.ID] = n
		switch {
		case n.ID == "hub":
			hub++
		case n.Type == "group":
			groups++
		case n.Type == "file":
			files++
			if !strings.HasPrefix(n.File, "AD/") || !strings.HasSuffix(n.File, ".md") {
				t.Errorf("file node points outside AD/: %q", n.File)
			}
		}
	}
	if hub != 1 || groups != 2 || files != 4 {
		t.Fatalf("nodes: hub=%d groups=%d files=%d, want 1/2/4", hub, groups, files)
	}
	// Attack-surface section is red ("1"), discovery is cyan ("5").
	if smb := byID["n-"+Slug("SMB Signing Not Required")]; smb.Color != "1" {
		t.Errorf("SMB Signing color = %q, want 1", smb.Color)
	}
	if dom := byID["n-"+Slug("Domains")]; dom.Color != "5" {
		t.Errorf("Domains color = %q, want 5", dom.Color)
	}
	// Every file node has an edge from the hub.
	if len(c.Edges) != files {
		t.Errorf("edges = %d, want %d (one per file node from hub)", len(c.Edges), files)
	}
	for _, e := range c.Edges {
		if e.FromNode != "hub" {
			t.Errorf("edge not from hub: %+v", e)
		}
	}
	// Valid JSON Canvas.
	b, err := c.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var round canvas.Canvas
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("canvas JSON invalid: %v", err)
	}
}

func TestWriteADCanvas(t *testing.T) {
	dir := t.TempDir()
	if err := WriteADCanvas(dir, adCanvasReport()); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "Active Directory.canvas")
	if _, err := os.Stat(p); err != nil {
		t.Fatal("no canvas file written")
	}
	// Empty report removes a stale canvas.
	if err := WriteADCanvas(dir, ad.Report{ScanName: "T"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("stale canvas not removed for empty report")
	}
}
