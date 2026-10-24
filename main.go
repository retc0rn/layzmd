package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ncruces/zenity"
	"layzmd/internal/ad"
	"layzmd/internal/enrich"
	"layzmd/internal/enrichcache"
	"layzmd/internal/hosts"
	"layzmd/internal/httpget"
	"layzmd/internal/mdout"
	"layzmd/internal/nessus"
	"layzmd/internal/ratelimit"
	"layzmd/internal/services"
	"layzmd/internal/vuln"
	"layzmd/internal/vulnview"
	"layzmd/internal/websurface"
)

var version = "dev"

func main() {
	// interactive is set by run() when it shows native dialogs (i.e. launched by
	// double-click rather than with flags). In that mode we surface any failure
	// in a dialog, because the console window closes the instant we exit and the
	// user would otherwise never see the error.
	interactive := false
	if err := run(&interactive); err != nil {
		fmt.Fprintf(os.Stderr, "\nlayzmd: %v\n", err)
		if interactive {
			_ = zenity.Error("layzmd could not finish:\n\n"+err.Error(),
				zenity.Title("layzmd — error"))
		}
		os.Exit(1)
	}
}

// run executes the whole pipeline, returning an error instead of calling
// os.Exit so that main() can report it (including via a dialog). A panic
// anywhere in the pipeline is recovered and returned as an error, so a bad row
// in a real scan surfaces a message instead of a vanishing window.
func run(interactive *bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			// Full stack to stderr for debugging; concise message for the dialog.
			fmt.Fprintf(os.Stderr, "panic: %v\n%s\n", r, debug.Stack())
			err = fmt.Errorf("internal error: %v", r)
		}
	}()

	var csv, out, nvdKey string
	var noEnrich, refresh, showVersion bool
	flag.StringVar(&csv, "csv", "", "path to Nessus CSV export")
	flag.StringVar(&out, "out", "", "output directory for markdown report")
	flag.StringVar(&nvdKey, "nvd-key", "", "NVD API key (raises the NVD rate limit; falls back to $PTC_NVD_API_KEY)")
	flag.BoolVar(&noEnrich, "no-enrich", false, "skip network enrichment; use cached data only")
	flag.BoolVar(&refresh, "refresh", false, "ignore cached enrichment and refetch")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("layzmd %s\n", version)
		return nil
	}

	// Resolve NVD key: flag value, else environment variable.
	key := nvdKey
	if key == "" {
		key = os.Getenv("PTC_NVD_API_KEY")
	}

	// Dialogs are shown (and thus we run interactively) whenever a required
	// path was not supplied on the command line.
	*interactive = csv == "" || out == ""
	csv = pickCsv(csv)
	out = pickOutDir(out)
	if csv == "" || out == "" {
		return fmt.Errorf("no CSV file or output directory selected")
	}

	// When launched interactively (double-click) without a key from --nvd-key or
	// $PTC_NVD_API_KEY, offer a dialog to enter one. A key raises the NVD rate
	// limit (5 -> 50 req/30s), which dramatically speeds up enrichment on large
	// scans. The entry is remembered between runs.
	if *interactive && key == "" {
		key = promptNVDKey()
	}

	f, err := os.Open(csv)
	if err != nil {
		return fmt.Errorf("opening CSV %q: %w", csv, err)
	}
	defer f.Close()

	findings, err := nessus.Parse(f)
	if err != nil {
		return fmt.Errorf("parsing CSV %q: %w", csv, err)
	}
	if len(findings) == 0 {
		return fmt.Errorf("no findings parsed from %q — is it a Nessus CSV export?", csv)
	}

	// Compute groupings up front so counts are available for the index.
	// The Vulnerabilities view excludes informational (Risk "None") findings —
	// SYN scanner, service detection, DNS-hostname plugins, etc. are not
	// vulnerabilities and are already covered by Hosts/Services/AD. Those notes
	// still use the full finding set.
	vg := vuln.Group(vulnFindings(findings))
	adReport := ad.Analyze(findings)

	scanName := strings.TrimSuffix(filepath.Base(csv), filepath.Ext(csv))
	generated := time.Now().Format("2006-01-02")
	web := websurface.Build(findings, websurface.Meta{ScanName: scanName, Generated: generated})

	summary := mdout.Summary{
		ScanName:          scanName,
		Generated:         generated,
		Findings:          len(findings),
		Hosts:             distinctHosts(findings),
		WithCVE:           countWithCVE(findings),
		VulnGroups:        len(vg),
		Domains:           len(adReport.Domains),
		DomainControllers: len(adReport.DomainControllers),
		HasDefensive:      len(adReport.Defensive) > 0,
		HasCreds:          len(adReport.Emails) > 0,
		HasWeb:            len(web.Hosts) > 0,
	}

	if err := mdout.WriteIndex(out, summary); err != nil {
		return fmt.Errorf("writing index.md to %q: %w", out, err)
	}
	fmt.Printf("wrote %s\n", filepath.Join(out, "index.md"))

	hg := hosts.Group(findings)
	if err := mdout.WriteHosts(out, hg); err != nil {
		return fmt.Errorf("writing Hosts.md: %w", err)
	}
	fmt.Printf("wrote %s\n", filepath.Join(out, "Hosts.md"))

	sg := services.Group(findings)
	if err := mdout.WriteServices(out, sg); err != nil {
		return fmt.Errorf("writing Services.md: %w", err)
	}
	fmt.Printf("wrote %s\n", filepath.Join(out, "Services.md"))

	if err := mdout.WriteWebSurface(out, web); err != nil {
		return fmt.Errorf("writing Web Attack Surface.md: %w", err)
	}
	fmt.Printf("wrote %s\n", filepath.Join(out, "Web Attack Surface.md"))

	// ── Vulnerabilities.md ───────────────────────────────────────────────────
	cves := collectCVEs(vg)

	clk := ratelimit.SystemClock()
	client := httpget.NewClient(30 * time.Second)
	srcs := enrich.BuildSources(client, key, clk)

	m := map[string]enrich.VulnEnrichment{}
	cache, cerr := enrichcache.Open(time.Now, refresh)
	if cerr != nil || cache == nil {
		// os.UserCacheDir failed (rare): proceed without enrichment rather
		// than crash — the report still renders from scan data alone.
		fmt.Fprintf(os.Stderr, "cache unavailable (%v); continuing without enrichment\n", cerr)
	} else {
		enricher := enrich.NewEnricher(srcs, cache, noEnrich)
		total := len(cves)
		m, _ = enricher.Enrich(context.Background(), cves, func(done, t int) {
			if total > 0 {
				fmt.Fprintf(os.Stderr, "\rEnriching CVEs: %d/%d", done, t)
			}
		})
		if total > 0 {
			fmt.Fprintln(os.Stderr)
		}
	}

	report := vulnview.Build(vg, m, vulnview.Meta{
		ScanName:  summary.ScanName,
		Generated: time.Now().Format("2006-01-02"),
	})

	if err := mdout.WriteVulnerabilities(out, report); err != nil {
		return fmt.Errorf("writing Vulnerabilities.md: %w", err)
	}
	fmt.Printf("wrote %s\n", filepath.Join(out, "Vulnerabilities.md"))

	adReport.ScanName = summary.ScanName
	adReport.Generated = summary.Generated
	if err := mdout.WriteAD(out, adReport); err != nil {
		return fmt.Errorf("writing AD.md: %w", err)
	}
	fmt.Printf("wrote %s\n", filepath.Join(out, "AD.md"))

	if err := mdout.WriteDefensive(out, adReport); err != nil {
		return fmt.Errorf("writing Defensive.md: %w", err)
	}
	if err := mdout.WriteCreds(out, adReport); err != nil {
		return fmt.Errorf("writing Usernames - Creds: %w", err)
	}
	if err := mdout.WriteADCanvas(out, adReport); err != nil {
		return fmt.Errorf("writing Active Directory.canvas: %w", err)
	}

	// Open output folder (best-effort, ignore errors).
	openFolder(out)

	// Confirm success for double-click users, who otherwise see the window
	// close with no indication that anything happened.
	if *interactive {
		_ = zenity.Info(fmt.Sprintf("Done — wrote the vault (index, Hosts, Services, Vulnerabilities, AD) to:\n\n%s", out),
			zenity.Title("layzmd"))
	}
	return nil
}

// pickCsv shows a native file-picker when --csv is empty.
// Returns empty string if cancelled.
func pickCsv(csv string) string {
	if csv != "" {
		return csv
	}
	path, err := zenity.SelectFile(
		zenity.Title("Select Nessus CSV export"),
		zenity.FileFilter{
			Name:     "Nessus CSV",
			Patterns: []string{"*.csv"},
		},
	)
	if err != nil {
		// ErrCanceled or any dialog error → friendly exit.
		fmt.Println("No file selected. Exiting.")
		os.Exit(0)
	}
	return path
}

// pickOutDir shows a native directory-picker when --out is empty.
// Returns empty string if cancelled.
func pickOutDir(out string) string {
	if out != "" {
		return out
	}
	dir, err := zenity.SelectFile(
		zenity.Title("Select output directory"),
		zenity.Directory(),
	)
	if err != nil {
		fmt.Println("No directory selected. Exiting.")
		os.Exit(0)
	}
	return dir
}

// nvdKeyConfigPath returns the path where an interactively-entered NVD API key
// is remembered between runs (empty if the user config dir is unavailable).
func nvdKeyConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "layzmd", "nvd-key")
}

func readSavedNVDKey() string {
	p := nvdKeyConfigPath()
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func saveNVDKey(key string) {
	p := nvdKeyConfigPath()
	if p == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, []byte(key), 0o600)
}

// promptNVDKey asks the double-click user for an optional NVD API key via a
// native entry dialog, pre-filled with any previously-saved key so it need only
// be entered once. Returns the chosen key ("" runs anonymously). A non-empty
// entry is persisted for next time.
func promptNVDKey() string {
	saved := readSavedNVDKey()
	entered, err := zenity.Entry(
		"Optional — NVD API key.\n\n"+
			"A free key (from nvd.nist.gov) raises the NVD rate limit from 5 to 50 "+
			"requests / 30s — much faster enrichment on large scans. Leave blank to "+
			"run anonymously (slower).",
		zenity.Title("layzmd — NVD API key"),
		zenity.EntryText(saved),
	)
	if err != nil {
		// Cancelled/closed: keep whatever was saved, change nothing.
		return saved
	}
	entered = strings.TrimSpace(entered)
	if entered != "" && entered != saved {
		saveNVDKey(entered)
	}
	return entered
}

// openFolder launches the OS file manager for dir (best-effort).
func openFolder(dir string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", dir)
	case "darwin":
		cmd = exec.Command("open", dir)
	default:
		cmd = exec.Command("xdg-open", dir)
	}
	_ = cmd.Start()
}

// vulnFindings returns the subset of findings that are actual vulnerabilities —
// i.e. it drops informational findings whose Risk is "None" (or blank). Those
// (SYN scanner, service/OS detection, DNS-hostname enumeration, etc.) are not
// vulnerabilities and belong to the Hosts/Services/AD views.
func vulnFindings(findings []nessus.Finding) []nessus.Finding {
	out := make([]nessus.Finding, 0, len(findings))
	for _, f := range findings {
		r := strings.TrimSpace(f.Risk)
		if r == "" || strings.EqualFold(r, "None") {
			continue
		}
		out = append(out, f)
	}
	return out
}

// distinctHosts returns the count of unique HostIP values across findings.
func distinctHosts(findings []nessus.Finding) int {
	seen := make(map[string]struct{})
	for _, f := range findings {
		seen[f.HostIP] = struct{}{}
	}
	return len(seen)
}

// countWithCVE returns the count of findings that have any CVE assigned
// (non-empty CVE field, including multi-CVE cells separated by commas).
func countWithCVE(findings []nessus.Finding) int {
	n := 0
	for _, f := range findings {
		if strings.TrimSpace(f.CVE) != "" {
			n++
		}
	}
	return n
}

// collectCVEs returns a deduplicated slice of all CVE IDs across the given
// VulnGroups. The CVE IDs are taken from each group's CVEs[].CVE field, which
// are already upper-cased and validated by vuln.Group.
func collectCVEs(groups []vuln.VulnGroup) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, g := range groups {
		for _, c := range g.CVEs {
			if _, ok := seen[c.CVE]; !ok {
				seen[c.CVE] = struct{}{}
				out = append(out, c.CVE)
			}
		}
	}
	return out
}
