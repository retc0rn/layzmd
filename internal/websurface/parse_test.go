package websurface

import (
	"reflect"
	"testing"
)

func TestURLPath(t *testing.T) {
	cases := map[string]string{
		"http://host/images/index.html": "/images/index.html",
		"https://h:8443/api/v1/users":   "/api/v1/users",
		"/already/relative":             "/already/relative",
		"http://host":                   "/",
		"host/no/scheme":                "/no/scheme",
	}
	for in, want := range cases {
		if got := urlPath(in); got != want {
			t.Errorf("urlPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseListPaths(t *testing.T) {
	out := "The following directories were discovered:\n/images\n/screens\n\nWhile this is not a bug..."
	got := parseListPaths(out, "discovered")
	want := []string{"/images", "/screens"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestParseListPaths_CommaSeparated(t *testing.T) {
	out := "The following directories were discovered:\n/cgi-bin, /intranet, /phpMyAdmin\n"
	got := parseListPaths(out, "discovered")
	want := []string{"/cgi-bin", "/intranet", "/phpMyAdmin"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestParseMethodsBlocks(t *testing.T) {
	out := `Based on the response to an OPTIONS request :

  - HTTP methods  GET  OPTIONS HEAD are allowed on :

    /
    /images
`
	got := parseMethodsBlocks(out)
	if len(got) != 2 {
		t.Fatalf("want 2 dirs, got %d: %+v", len(got), got)
	}
	if got[0].Path != "/" || !reflect.DeepEqual(got[1].Methods, []string{"GET", "OPTIONS", "HEAD"}) {
		t.Errorf("bad parse: %+v", got)
	}
}

func TestParseProtectedPages(t *testing.T) {
	out := "The following pages are protected by the Basic authentication scheme :\n\n/main_login.html\n/screens/index.html"
	got := parseProtectedPages(out)
	if len(got) != 2 || got[0].Scheme != "Basic" || got[0].Path != "/main_login.html" {
		t.Errorf("bad parse: %+v", got)
	}
}
