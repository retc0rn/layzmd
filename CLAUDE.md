# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`layzmd` is a single static Go binary that converts a Nessus CSV export into an Obsidian vault
(Markdown notes with native callouts, wikilinks, YAML frontmatter, plus one `.canvas`). It is a
faithful port of analysis logic that lives outside this repo (C# `ptcompanion-desktop` Core and
`nadda.py` for AD). Guiding rule from the design docs: **port, don't invent** — when a classifier or
heuristic exists in the reference implementation, match it rather than redesign it.

## Commands

Go is **not on PATH** by default on the dev machine. Historically it lived at `C:\Program Files\Go`;
in Git Bash prefix commands with `export PATH="$PATH:/c/Program Files/Go/bin"`. If `go` is still not
found, locate/install it before doing anything else.

```sh
go build ./... && go vet ./... && go test ./...   # the standard green check
go test ./internal/vulnview/                      # one package
go test ./internal/mdout/ -run TestRenderHostsIndex_Golden   # one test
go build .                                        # local binary (layzmd / layzmd.exe)
bash scripts/build-release.sh [version]           # cross-compile into dist/ (sets main.version via ldflags)
./layzmd --csv testdata/sample_scan.csv --out ./out-vault --no-enrich   # offline smoke run
```

- `go test -race` is unavailable (no CGO/GCC on the Windows box). Concurrency in `enrich.Enricher`
  is justified analytically in comments; keep that reasoning updated if you touch it.
- Omitting `--csv`/`--out` opens native zenity dialogs — always pass both when running from a script.
- There is no `-update` flag for golden files. To re-pin a golden, write the renderer's output to the
  matching `testdata/golden_*.md` and re-run tests. Tests normalize CRLF→LF on both sides
  (`internal/mdout/golden_test.go`), so line endings from git checkout are not a concern.

## Architecture

Pipeline (all wiring is in `main.go`):

```
nessus.Parse → []Finding → hosts.Group / services.Group / vuln.Group / ad.Analyze / websurface.Build
                                          │
                   collectCVEs → enrich.Enricher (HTTP + disk cache) → map[CVE]VulnEnrichment
                                          │
                   vulnview.Build (merge + priority + buckets) → mdout.Write* → vault/
```

### Layering rules (enforced by convention, relied on by tests)

- **Pure analysis, impure edges.** Every `internal/*` analysis/render package is deterministic with
  no I/O, no `time.Now`, no network. `time.Now` is called only in `main.go`; file I/O only in
  `mdout.Write*` and `enrichcache`; HTTP only behind `httpget.HTTPGetter`. `mdout.Render*` returns
  strings (tested against goldens); `mdout.Write*` just writes them.
- **Determinism.** Never let map iteration order leak into output — always collect then `sort`.
  IPs sort numerically via `ipsort.Key`.
- **Links == files.** Each section computes note paths through ONE shared helper used by both the
  index renderer and the writer (e.g. `groupNotePaths` in `mdout/vulnerabilities.go`,
  `hostNotePath` in `mdout/hosts.go`). Never build a wikilink path and a file path separately.
- **Subfolders are rebuilt.** `Write*` does `os.RemoveAll` on its subfolder (`Hosts/`, `Services/`,
  `Vulnerabilities/`, `AD/`, `Web Attack Surface/`) every run; top-level `*.md` index notes are
  overwritten in place.
- **No live network in tests.** Enrichment sources take an `httpget.HTTPGetter`; tests use
  `fakeGetter` (`internal/enrich/fake_test.go`) and an injected `ratelimit.Clock` so nothing sleeps.

### Output vault layout (what the user sees in Obsidian)

```
index.md                         summary + nav (Web/Defensive/Creds links are conditional)
Hosts.md        + Hosts/<OS Category>.md
Services.md     + Services/<svcclass Category>/<slug>.md
Vulnerabilities.md + Vulnerabilities/<N Bucket>/<NNN>-<slug>.md   (NNN = global priority rank)
AD.md           + AD/<section>.md, Defensive.md, Usernames - Creds.md + folder, Active Directory.canvas
Web Attack Surface.md + Web Attack Surface/<Category>.md   (code blocks of copy-ready absolute URLs)
```

The Vulnerabilities view excludes informational findings (Risk `None`/blank — see `vulnFindings` in
`main.go`); Hosts/Services/AD/Web use the full finding set.

### Package map by stage

- **Parse:** `nessus` — tolerant CSV reader (header-name lookup, `LazyQuotes`, CVSS v3→v2
  preference, blank risk→`None`, empty-host rows skipped). `Finding` is all strings.
- **Hosts:** `hosts` groups by OS category (`osclass.Classify`) then by specific OS string; OS comes
  from the `Detected OS` column, else `osdetect` regexes over plugin output.
- **Services:** `services.Group` buckets by `(port, transport)` and names each bucket via a
  **confidence-tiered resolver**: Tier 1 Service Detection plugin 22964 output (`svcname`),
  Tier 2 curated port map (`protoname`, incl. ephemeral-range rule), Tier 3 word-bounded plugin-name
  keyword gated by `svcname.PlausibleForPort`. `svcclass.Classify` assigns the folder category.
  Read the SP9 service-resolver spec (local `docs/`, see below) before changing naming.
- **Vulns:** `vuln.Group` (group by raw finding name, per-CVE + per-port hosts) → `vulnview.Build`
  merges enrichment, computes `priority.Label` (severity + EPSS percentile + KEV points), re-classifies
  `category` with NVD CWEs, and assigns a semantic **bucket**. Bucket *assignment precedence*
  (`vulnview/bucket.go`, themes before High Priority) differs from *display/folder order*
  (`bucketDisplay` in `mdout/vulnerabilities.go`) — keep the two concerns separate.
- **Enrichment:** `enrich` orchestrates KEV → EPSS(+KEV "core") → bulk PoC indexes
  (ExploitDB/Metasploit/Nuclei, 7d cache) → per-CVE NVD + VulnCheck PoC in a 16-worker pool.
  `enrich.BuildSources` is the single place rate limits live (NVD 5/30s anon, 50/30s keyed; EPSS
  1/500ms; VulnCheck 2/s). `enrichcache` is a JSON file at `UserCacheDir/layzmd/enrichment.json`
  keyed `(cve, source)` with per-source TTL (`ttlFor`); `--refresh` = treat all stale,
  `--no-enrich` = zero network, cache-only. Nuclei templates are tracked but are *not* counted as
  PoC for `HasPoc`/Quick Wins.
- **AD:** `ad.Analyze` + `adparse` port `nadda.py` detections (DCs, domains, ADCS, SCCM, SMB signing,
  shares, defensive tech, emails). `canvas` + `mdout/adcanvas.go` emit the Obsidian JSON Canvas.
- **Web:** `websurface` parses web-plugin output into per-host:port services, categorizes paths
  (login/API/basic-auth/admin/dangerous-methods/default pages/interesting files by extension/other).
  Management endpoints (WinRM etc.) are counted, not listed. Static assets are filtered.

## Project workflow conventions

- Work is organised as numbered sub-projects ("SPn"). Each has a design spec in
  `docs/superpowers/specs/` and usually an implementation plan in `docs/superpowers/plans/`. That
  `docs/` folder is **git-ignored and local-only** (not in the public GitHub repo); if it is present,
  read the relevant spec before changing a section's behaviour — several record user decisions that reverse
  earlier designs (e.g. SP20 rewrote the Web Attack Surface output; SP15/16/17 reshaped vuln buckets).
- Feature branches `spN-<topic>` are merged into `master` with a `Merge SPn: <summary>` commit; the
  only long-lived branch is `master`. Releases are tagged `vX.Y.Z`; binaries in `dist/` are
  git-ignored.
- Commit prefixes in use: `feat(pkg):`, `fix(pkg):`, `refactor(pkg):`, `docs:`.
- When a change alters rendered Markdown, re-pin the affected golden in the same commit and say so
  in the commit message.
