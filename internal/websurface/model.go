package websurface

// Meta carries scan identity for the rendered notes.
type Meta struct{ ScanName, Generated string }

// Report is the full web-attack-surface model. Pure data, no I/O.
// Each category slice holds URL-forming entries for browsable services only;
// management/protocol endpoints are excluded from every category (kept only as
// a Counts.Management tally).
type Report struct {
	Meta        Meta
	Hosts       []HostWeb // used for counts; not rendered
	Logins      []CatEntry
	APIs        []CatEntry
	BasicAuth   []CatEntry
	Admin       []CatEntry
	Dangerous   []CatEntry
	DefaultPage []CatEntry
	// Files holds interesting-file subpages keyed by category name (see
	// FileCategoryNames for the display order).
	Files map[string][]CatEntry
	Other []CatEntry // pages/dirs matching no category
	Counts Counts
}

// Counts holds the Overview tallies.
type Counts struct{ Hosts, Services, Browsable, Management, TLS, Plaintext int }

// HostWeb is one host's web services.
type HostWeb struct {
	Host     string
	Services []WebService
}

// WebService is a single host:port web endpoint.
type WebService struct {
	Port         string
	TLS          bool
	Software     string
	Kind         string   // "web" | "management"
	Pages        []string // distinct host-relative paths
	Dirs         []DirEntry
	Auth         []AuthPage
	DefaultPage  bool
	BasicNoHTTPS bool     // "Basic Authentication Without HTTPS" finding present
	AutoComplete bool     // "Allows Password Auto-Completion"
	Cats         []string // {"login","api","admin","basic-auth","dangerous"}
}

// DirEntry is a discovered directory and its allowed HTTP methods.
type DirEntry struct {
	Path    string
	Methods []string
}

// AuthPage is a protected page and its auth scheme.
type AuthPage struct{ Path, Scheme string } // Scheme: Basic|NTLM|Digest|Form

// CatEntry is one categorized URL: Host:Port + host-relative Path (+ TLS to
// pick the scheme). Detail is optional context (e.g. dangerous methods).
type CatEntry struct {
	Host, Port, Path, Detail string
	TLS                      bool
}
