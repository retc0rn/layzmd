package websurface

import "testing"

func hasCat(cs []string, c string) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
}

func TestPathCats(t *testing.T) {
	cases := []struct {
		path string
		cat  string
	}{
		{"/main_login.html", "login"},
		{"/api/v1/users", "api"},
		{"/rest/things", "api"},
		{"/graphql", "api"},
		{"/admin/index.php", "admin"},
		{"/manager/html", "admin"},
		{"/images/logo.png", ""},
		{"/admin/table_design.css", ""}, // static asset — no category despite /admin
		{"/js/login.js", ""},            // static asset — no login category
	}
	for _, c := range cases {
		got := pathCats(c.path)
		if c.cat == "" {
			if len(got) != 0 {
				t.Errorf("pathCats(%q)=%v want none", c.path, got)
			}
		} else if !hasCat(got, c.cat) {
			t.Errorf("pathCats(%q)=%v want %q", c.path, got, c.cat)
		}
	}
}

func TestClassify_BasicAndDangerous(t *testing.T) {
	svc := WebService{
		Port: "443", TLS: true,
		Auth: []AuthPage{{Path: "/x", Scheme: "Basic"}},
		Dirs: []DirEntry{{Path: "/dav", Methods: []string{"GET", "PUT", "DELETE"}}},
	}
	classify(&svc)
	if !hasCat(svc.Cats, "basic-auth") || !hasCat(svc.Cats, "dangerous") {
		t.Errorf("cats=%v want basic-auth+dangerous", svc.Cats)
	}
}

func TestFileCatNames(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/logs/access.log", "Log Files"},
		{"/app/web.config", "Config Files"},
		{"/.env", "Config Files"},
		{"/backup/index.php.bak", "Backup & Temp Files"},
		{"/index.php~", "Backup & Temp Files"},
		{"/dist/app.war", "Archives"},
		{"/db/dump.sql", "Database Dumps"},
		{"/keys/server.pem", "Credentials & Keys"},
		{"/normal/page.html", ""},
		{"/style.css?v=2", ""},
		{"/content/desktop.ini", ""},  // benign Windows metadata
		{"/images/bmp/Thumbs.db", ""}, // benign thumbnail cache
	}
	for _, c := range cases {
		got := fileCatNames(c.path)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("fileCatNames(%q)=%v want none", c.path, got)
			}
		} else if len(got) == 0 || got[0] != c.want {
			t.Errorf("fileCatNames(%q)=%v want %q", c.path, got, c.want)
		}
	}
}

func TestIsManagement(t *testing.T) {
	winrm := WebService{Port: "5985", Software: "Microsoft-HTTPAPI/2.0"}
	if !isManagement(winrm) {
		t.Error("5985 HTTPAPI should be management")
	}
	web := WebService{Port: "443", Software: "Apache/2.4", Pages: []string{"/"}}
	if isManagement(web) {
		t.Error("apache with pages should be web")
	}
	oddEmpty := WebService{Port: "7056", Software: ""}
	if !isManagement(oddEmpty) {
		t.Error("empty software on odd port should be management")
	}
}
