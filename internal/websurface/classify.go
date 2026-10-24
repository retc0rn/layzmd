package websurface

import (
	"regexp"
	"strings"
)

var (
	loginRe = regexp.MustCompile(`(?i)(login|logon|signin|sign-in|/sso|/saml|/oauth|j_security_check|wp-login|owa/auth)`)
	apiRe   = regexp.MustCompile(`(?i)(/api(/|$)|/rest(/|$)|/restapi|/v[0-9]+/|/graphql|/gql|/soap|\.wsdl|\.asmx|/odata|/jsonrpc|/rpc/|/swagger|/openapi|/ws/|/services/)`)
	adminRe = regexp.MustCompile(`(?i)(/admin|/administrator|/manager/html|/console|/wp-admin|/phpmyadmin|/pma/|/adminer|/cpanel|/webadmin|/system/console|/redfish|/idrac|/ilo|/vsphere|/ui(/|$))`)
)

var dangerSet = map[string]bool{
	"PUT": true, "DELETE": true, "MOVE": true, "COPY": true, "MKCOL": true,
	"PROPFIND": true, "PROPPATCH": true, "LOCK": true, "UNLOCK": true,
	"PATCH": true, "TRACE": true, "TRACK": true, "SEARCH": true, "CONNECT": true,
}

var stdWebPorts = map[string]bool{
	"80": true, "443": true, "8000": true, "8008": true,
	"8080": true, "8443": true, "8888": true,
}

var httpapiRe = regexp.MustCompile(`(?i)microsoft-httpapi`)

// staticAssetRe matches static-asset paths (stylesheets, scripts, images,
// fonts) that are noise in the attack-category lists.
var staticAssetRe = regexp.MustCompile(`(?i)\.(css|js|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|map|bmp|webp)(\?|$)`)

// isStaticAsset reports whether path points at a static asset.
func isStaticAsset(path string) bool { return staticAssetRe.MatchString(path) }

// extCategory maps a set of path extensions to an interesting-file subpage.
type extCategory struct {
	Name string
	Exts []string
}

// fileCategories: interesting files keyed by the path's trailing extension.
// The slice order is the subpage display order.
var fileCategories = []extCategory{
	{"Log Files", []string{".log"}},
	{"Config Files", []string{".conf", ".config", ".cfg", ".ini", ".env", ".yaml", ".yml", ".toml", ".properties", ".htaccess", ".htpasswd"}},
	{"Backup & Temp Files", []string{".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo", ".tmp", ".copy", "~"}},
	{"Archives", []string{".zip", ".tar", ".gz", ".tgz", ".bz2", ".rar", ".7z", ".war", ".jar", ".ear"}},
	{"Database Dumps", []string{".sql", ".db", ".sqlite", ".mdb", ".dump"}},
	{"Credentials & Keys", []string{".pem", ".key", ".crt", ".cer", ".pfx", ".p12", ".keystore", ".jks", ".ppk"}},
}

// FileCategoryNames returns the interesting-file subpage names in display order.
func FileCategoryNames() []string {
	names := make([]string, len(fileCategories))
	for i, fc := range fileCategories {
		names[i] = fc.Name
	}
	return names
}

// benignFiles are common OS-generated files that match an interesting
// extension but carry no value (Windows folder metadata / thumbnail cache,
// macOS directory state). They fall through to Other Pages instead.
var benignFiles = map[string]bool{"desktop.ini": true, "thumbs.db": true, ".ds_store": true}

// fileCatNames returns the interesting-file subpages a path belongs to, matched
// by extension at the end of the path (query/fragment stripped). Benign OS
// files are excluded.
func fileCatNames(path string) []string {
	p := strings.ToLower(path)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	base := p
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if benignFiles[base] {
		return nil
	}
	var names []string
	for _, fc := range fileCategories {
		for _, ext := range fc.Exts {
			if strings.HasSuffix(p, ext) {
				names = append(names, fc.Name)
				break
			}
		}
	}
	return names
}

// pathCats returns the browsable categories a single path matches. Static
// assets never match a category (they fall through to Other).
func pathCats(path string) []string {
	if isStaticAsset(path) {
		return nil
	}
	var cats []string
	if loginRe.MatchString(path) {
		cats = append(cats, "login")
	}
	if apiRe.MatchString(path) {
		cats = append(cats, "api")
	}
	if adminRe.MatchString(path) {
		cats = append(cats, "admin")
	}
	return cats
}

// dangerousMethods returns the subset of methods considered write/WebDAV/debug.
func dangerousMethods(methods []string) []string {
	var out []string
	for _, m := range methods {
		if dangerSet[m] {
			out = append(out, m)
		}
	}
	return out
}

// classify sets svc.Cats from its paths, auth, methods, and flags.
func classify(svc *WebService) {
	seen := map[string]bool{}
	add := func(c string) {
		if !seen[c] {
			seen[c] = true
			svc.Cats = append(svc.Cats, c)
		}
	}
	all := append([]string{}, svc.Pages...)
	for _, d := range svc.Dirs {
		all = append(all, d.Path)
	}
	for _, a := range svc.Auth {
		all = append(all, a.Path)
		if a.Scheme == "Basic" {
			add("basic-auth")
		}
		if a.Scheme == "Form" {
			add("login")
		}
	}
	for _, p := range all {
		for _, c := range pathCats(p) {
			add(c)
		}
	}
	if svc.AutoComplete {
		add("login")
	}
	if svc.BasicNoHTTPS {
		add("basic-auth")
	}
	for _, d := range svc.Dirs {
		if len(dangerousMethods(d.Methods)) > 0 {
			add("dangerous")
			break
		}
	}
}

// isManagement reports a non-browser HTTP endpoint (WinRM / protocol) with no
// browsable evidence.
func isManagement(svc WebService) bool {
	browsable := len(svc.Pages) > 0 || len(svc.Dirs) > 0 || svc.DefaultPage
	if browsable {
		return false
	}
	switch {
	case svc.Port == "5985" || svc.Port == "5986" || svc.Port == "47001":
		return true
	case httpapiRe.MatchString(svc.Software):
		return true
	case svc.Software == "" && !stdWebPorts[svc.Port]:
		return true
	}
	return false
}
