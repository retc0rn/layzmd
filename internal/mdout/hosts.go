package mdout

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"layzmd/internal/hosts"
)

// hostNotePath returns the vault-relative path for a category note.
func hostNotePath(g hosts.OSGroup) string {
	return "Hosts/" + sanitizePathSeg(g.Category) + ".md"
}

// RenderHostGroupNote renders one OS-category note with per-version subsections.
// Pure: no I/O.
func RenderHostGroupNote(g hosts.OSGroup) string {
	var sb strings.Builder
	writeFrontmatter(&sb, [][2]string{
		{"category", g.Category},
		{"hosts", strconv.Itoa(g.HostCount())},
	})
	sb.WriteString("# " + g.Category + "\n")
	for _, v := range g.Versions {
		label := v.OS
		if label == "" {
			label = "Unspecified"
		}
		sb.WriteString("\n## " + label + "\n")
		sb.WriteString("```\n")
		for _, ip := range v.IPs {
			sb.WriteString(ip + "\n")
		}
		sb.WriteString("```\n")
	}
	return sb.String()
}

// RenderHostsIndex renders Hosts.md — a summary table + links to category notes.
// Pure: no I/O.
func RenderHostsIndex(groups []hosts.OSGroup) string {
	var sb strings.Builder
	sb.WriteString("# Hosts\n\n")
	sb.WriteString("> [!abstract] Summary\n")
	sb.WriteString("> | Category | Hosts |\n> |---|---:|\n")
	for _, g := range groups {
		sb.WriteString(fmt.Sprintf("> | %s | %d |\n", g.Category, g.HostCount()))
	}
	sb.WriteString("\n## Hosts by OS\n")
	for _, g := range groups {
		hostWord := "hosts"
		if g.HostCount() == 1 {
			hostWord = "host"
		}
		link := strings.TrimSuffix(hostNotePath(g), ".md") // Hosts/<Category>
		sb.WriteString(fmt.Sprintf("- [[%s|%s]] — %d %s\n", link, g.Category, g.HostCount(), hostWord))
	}
	return sb.String()
}

// WriteHosts writes Hosts.md and the Hosts/ subfolder notes into dir.
func WriteHosts(dir string, groups []hosts.OSGroup) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sub := filepath.Join(dir, "Hosts")
	if err := os.RemoveAll(sub); err != nil {
		return err
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		return err
	}
	for _, g := range groups {
		p := filepath.Join(dir, filepath.FromSlash(hostNotePath(g)))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(RenderHostGroupNote(g)), 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, "Hosts.md"), []byte(RenderHostsIndex(groups)), 0o644)
}
