package vulnview

import "testing"

// systemName is used as a folder-name segment downstream, so it must never
// return "". Also confirms the narrowed version regex keeps real dotted words.
func TestSystemName_Edge(t *testing.T) {
	cases := map[string]string{
		"":                              "Other",
		"   ":                           "Other",
		"1.0.1 2.0":                     "Other", // all version tokens
		"PHP":                           "PHP",
		"Apache .htaccess Detection":    "Apache .htaccess", // .htaccess kept, not a version token
		"OpenSSL 1.0.1 Multiple Issues": "OpenSSL",
	}
	for in, want := range cases {
		if got := systemName(in); got != want {
			t.Errorf("systemName(%q) = %q, want %q", in, got, want)
		}
	}
}
