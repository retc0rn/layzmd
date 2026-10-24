package mdout

import "strings"

// writeFrontmatter emits a YAML frontmatter block for the given key/value
// pairs in order. A value that begins with "[" is treated as a pre-formatted
// YAML flow list and written raw; all others are quoted via yamlQuoteString.
func writeFrontmatter(sb *strings.Builder, kvs [][2]string) {
	sb.WriteString("---\n")
	for _, kv := range kvs {
		v := kv[1]
		if !strings.HasPrefix(v, "[") {
			v = yamlQuoteString(v)
		}
		sb.WriteString(kv[0])
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\n")
	}
	sb.WriteString("---\n")
}
