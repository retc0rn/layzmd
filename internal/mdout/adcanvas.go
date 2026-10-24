package mdout

import (
	"fmt"
	"os"
	"path/filepath"

	"layzmd/internal/ad"
	"layzmd/internal/canvas"
)

// adAttackSurface / adHighValue tier the AD sections for the canvas. Everything
// else is treated as discovery/inventory.
var adAttackSurface = map[string]bool{
	"SMB Signing Not Required": true,
	"SMBv1 / Null Session":     true,
	"Guest Account Access":     true,
	"SMB Shares":               true,
	"ADCS":                     true,
}
var adHighValue = map[string]bool{
	"SCCM Services":          true,
	"MS-SQL Servers":         true,
	"Exchange Servers":       true,
	"ADFS Servers":           true,
	"Outdated Windows Hosts": true,
}

// RenderADCanvas builds an Obsidian canvas of the AD attack surface: a hub node
// plus one file node per populated AD section note, split into a red
// "Attack Surface" column and a blue "Discovery" column, with edges from the
// hub. Pure: no I/O.
func RenderADCanvas(r ad.Report) canvas.Canvas {
	sections := adSectionNotes(r)
	if len(sections) == 0 {
		return canvas.Canvas{}
	}

	// Left column = attack-surface then high-value (each in emit order);
	// right column = discovery. Preserve emit order within each tier.
	var left, right []adSection
	for _, s := range sections {
		if adAttackSurface[s.title] {
			left = append(left, s)
		}
	}
	for _, s := range sections {
		if !adAttackSurface[s.title] && adHighValue[s.title] {
			left = append(left, s)
		}
	}
	for _, s := range sections {
		if !adAttackSurface[s.title] && !adHighValue[s.title] {
			right = append(right, s)
		}
	}

	const nodeW, nodeH, pitch = 560, 120, 150
	const leftX, rightX = -740, 160
	const groupTopY = -140

	var c canvas.Canvas

	// Group boxes first (background z-order).
	if len(left) > 0 {
		c.Nodes = append(c.Nodes, canvas.Node{
			ID: "grp-attack", Type: "group", Label: "🔴 Attack Surface",
			X: leftX - 20, Y: groupTopY, Width: nodeW + 40, Height: 40 + len(left)*pitch, Color: "1",
		})
	}
	if len(right) > 0 {
		c.Nodes = append(c.Nodes, canvas.Node{
			ID: "grp-disc", Type: "group", Label: "🔵 Discovery / Inventory",
			X: rightX - 20, Y: groupTopY, Width: nodeW + 40, Height: 40 + len(right)*pitch, Color: "5",
		})
	}

	// Central hub.
	c.Nodes = append(c.Nodes, canvas.Node{
		ID: "hub", Type: "text", X: -160, Y: -330, Width: 300, Height: 150, Color: "6",
		Text: fmt.Sprintf("# Active Directory\n**%s**\n\n%d domains · %d DCs · %d sections",
			r.ScanName, len(r.Domains), len(r.DomainControllers), len(sections)),
	})

	sectionColor := func(title string) string {
		switch {
		case adAttackSurface[title]:
			return "1"
		case adHighValue[title]:
			return "2"
		default:
			return "5"
		}
	}

	addColumn := func(secs []adSection, x int, fromSide, toSide string) {
		for i, s := range secs {
			id := "n-" + Slug(s.title)
			color := sectionColor(s.title)
			c.Nodes = append(c.Nodes, canvas.Node{
				ID: id, Type: "file", File: s.path,
				X: x, Y: groupTopY + 40 + i*pitch, Width: nodeW, Height: nodeH, Color: color,
			})
			c.Edges = append(c.Edges, canvas.Edge{
				ID: "e-" + id, FromNode: "hub", FromSide: fromSide,
				ToNode: id, ToSide: toSide, ToEnd: "arrow", Color: color,
			})
		}
	}
	addColumn(left, leftX, "left", "right")
	addColumn(right, rightX, "right", "left")

	return c
}

// WriteADCanvas writes "Active Directory.canvas" at the vault root when AD data
// exists; otherwise removes a stale one.
func WriteADCanvas(dir string, r ad.Report) error {
	path := filepath.Join(dir, "Active Directory.canvas")
	if len(adSectionNotes(r)) == 0 {
		_ = os.Remove(path)
		return nil
	}
	b, err := RenderADCanvas(r).JSON()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
