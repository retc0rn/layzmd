package osdetect

import "testing"

func TestFromPluginOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Remote operating system pattern",
			input: "Remote operating system : Microsoft Windows Server 2019\nSome other line",
			want:  "Microsoft Windows Server 2019",
		},
		{
			name:  "The remote Operating System is pattern",
			input: "The remote Operating System is : Ubuntu 18.04\n",
			want:  "Ubuntu 18.04",
		},
		{
			name:  "Operating System pattern",
			input: "Operating System : Ubuntu 20.04\nssh",
			want:  "Ubuntu 20.04",
		},
		{
			name:  "No match returns empty",
			input: "Nothing useful here",
			want:  "",
		},
		{
			name:  "Empty string returns empty",
			input: "",
			want:  "",
		},
		{
			name:  "Case insensitive remote pattern",
			input: "REMOTE OPERATING SYSTEM : CentOS 7",
			want:  "CentOS 7",
		},
		{
			name:  "Trims whitespace",
			input: "Operating System :   Fedora 35   \n",
			want:  "Fedora 35",
		},
		{
			// Plugin 10785 degenerate output — a bare "(" must not become an OS.
			name:  "Letterless capture rejected",
			input: "The remote Operating System is : (\n",
			want:  "",
		},
		{
			name:  "Numeric-only capture rejected",
			input: "Operating System : 12345\n",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromPluginOutput(tt.input)
			if got != tt.want {
				t.Errorf("FromPluginOutput(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
