package osclass_test

import (
	"testing"

	"layzmd/internal/osclass"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Windows
		{"Microsoft Windows Server 2019", "Windows Server"},
		{"Windows 10 Pro", "Windows Desktop"},
		{"Windows 10 IoT", "Windows Embedded"},
		// Case-insensitive
		{"WINDOWS SERVER 2016", "Windows Server"},
		// Linux distros (specific before generic)
		{"Ubuntu 20.04", "Ubuntu"},
		{"Red Hat Enterprise Linux 8", "Red Hat"},
		{"RHEL 7", "Red Hat"},
		{"CentOS Linux 7", "CentOS"},
		{"Linux Kernel 3.10", "Linux (other)"},
		// macOS
		{"Mac OS X 10.15", "macOS"},
		// Network device
		{"Cisco IOS 15.2", "Network device"},
		// iOS must be verbatim — NOT network device (no bare "ios " token)
		{"iOS 15.2", "iOS 15.2"},
		// Product-family coarsening (distinct builds collapse to the product)
		{"VMware ESXi 7.0.3 build-20036589", "VMware ESXi"},
		{"VMware ESXi 8.0.2 build-23305546", "VMware ESXi"},
		{"VMware vCenter Server 7.0.3 build-20150588", "VMware vCenter"},
		{"FreeBSD 3.4", "FreeBSD"},
		{"FreeBSD 6.0", "FreeBSD"},
		{"IBMi OS V7R3M0", "IBM i"},
		{"IBMi OS V7R4M0", "IBM i"},
		// Verbatim fallback (single-build appliance stays as-is)
		{"ADTRAN Operating System", "ADTRAN Operating System"},
		// Empty / whitespace
		{"", "Unknown"},
		{"   ", "Unknown"},
	}

	for _, c := range cases {
		got := osclass.Classify(c.in)
		if got != c.want {
			t.Errorf("Classify(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}
