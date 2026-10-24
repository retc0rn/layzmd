// Package osclass classifies an OS string into a canonical category.
// Rules are ordered; the first match wins.
package osclass

import "strings"

// Classify returns a canonical OS category for the given OS string.
// Empty or whitespace-only input returns "Unknown".
// If no rule matches, the original string is returned verbatim.
func Classify(os string) string {
	if strings.TrimSpace(os) == "" {
		return "Unknown"
	}

	l := strings.ToLower(os)

	// Windows — ordered: Server and Embedded before Desktop
	if strings.Contains(l, "windows") && strings.Contains(l, "server") {
		return "Windows Server"
	}
	if strings.Contains(l, "windows") && (strings.Contains(l, "embedded") ||
		strings.Contains(l, "iot") ||
		strings.Contains(l, "windows ce") ||
		strings.Contains(l, "posready")) {
		return "Windows Embedded"
	}
	if strings.Contains(l, "windows") {
		return "Windows Desktop"
	}

	// Specific Linux distros — before generic Linux
	if strings.Contains(l, "ubuntu") {
		return "Ubuntu"
	}
	if strings.Contains(l, "debian") {
		return "Debian"
	}
	if strings.Contains(l, "red hat") || strings.Contains(l, "rhel") {
		return "Red Hat"
	}
	if strings.Contains(l, "centos") {
		return "CentOS"
	}
	if strings.Contains(l, "suse") || strings.Contains(l, "sles") {
		return "SUSE"
	}
	if strings.Contains(l, "fedora") {
		return "Fedora"
	}
	if strings.Contains(l, "oracle linux") {
		return "Oracle Linux"
	}

	// Generic Linux
	if strings.Contains(l, "linux") || strings.Contains(l, "kernel") {
		return "Linux (other)"
	}

	// macOS / Darwin
	if strings.Contains(l, "mac os") || strings.Contains(l, "macos") || strings.Contains(l, "darwin") {
		return "macOS"
	}

	// Network devices — note: " eos" has a leading space; NO bare "ios " token
	if strings.Contains(l, "cisco") ||
		strings.Contains(l, "cisco ios") ||
		strings.Contains(l, "ios-xe") ||
		strings.Contains(l, "nx-os") ||
		strings.Contains(l, "junos") ||
		strings.Contains(l, "juniper") ||
		strings.Contains(l, "pan-os") ||
		strings.Contains(l, "fortios") ||
		strings.Contains(l, "fortigate") ||
		strings.Contains(l, "mikrotik") ||
		strings.Contains(l, "arista") ||
		strings.Contains(l, " eos") {
		return "Network device"
	}

	// Product families that ship many builds/versions — coarsen to the product
	// so distinct builds collapse into one category and become OS-version
	// subsections within that host note (rather than one note per build).
	if strings.Contains(l, "esxi") {
		return "VMware ESXi"
	}
	if strings.Contains(l, "vcenter") {
		return "VMware vCenter"
	}
	if strings.Contains(l, "freebsd") {
		return "FreeBSD"
	}
	if strings.Contains(l, "ibmi") || strings.Contains(l, "ibm i") ||
		strings.Contains(l, "os/400") || strings.Contains(l, "i5/os") {
		return "IBM i"
	}

	// Verbatim fallback — return original casing
	return os
}
