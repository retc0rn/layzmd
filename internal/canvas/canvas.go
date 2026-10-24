// Package canvas builds Obsidian JSON Canvas (.canvas) files. The format is the
// open JSON Canvas 1.0 spec (jsoncanvas.org): a document with "nodes" and
// "edges" arrays. Pure data + JSON marshaling — no I/O.
package canvas

import "encoding/json"

// Node is a canvas node. Type is one of "text", "file", "link", "group".
// Only the fields relevant to a node's type are set; the rest are omitted.
type Node struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	X       int    `json:"x"`
	Y       int    `json:"y"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	Color   string `json:"color,omitempty"` // preset "1".."6" or hex "#rrggbb"
	Text    string `json:"text,omitempty"`  // type=text (markdown)
	File    string `json:"file,omitempty"`  // type=file (vault-relative path)
	Subpath string `json:"subpath,omitempty"`
	URL     string `json:"url,omitempty"`   // type=link
	Label   string `json:"label,omitempty"` // type=group
}

// Edge connects two nodes by side, optionally with an arrowhead and label.
type Edge struct {
	ID       string `json:"id"`
	FromNode string `json:"fromNode"`
	FromSide string `json:"fromSide,omitempty"` // top|right|bottom|left
	ToNode   string `json:"toNode"`
	ToSide   string `json:"toSide,omitempty"`
	ToEnd    string `json:"toEnd,omitempty"` // none|arrow
	Color    string `json:"color,omitempty"`
	Label    string `json:"label,omitempty"`
}

// Canvas is a full JSON Canvas document.
type Canvas struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// JSON renders the canvas as indented JSON Canvas bytes.
func (c Canvas) JSON() ([]byte, error) {
	// nodes/edges must be non-nil arrays so an empty canvas is valid JSON Canvas.
	if c.Nodes == nil {
		c.Nodes = []Node{}
	}
	if c.Edges == nil {
		c.Edges = []Edge{}
	}
	return json.MarshalIndent(c, "", "\t")
}
