# layzmd

**layzmd** converts a Nessus CSV export into an Obsidian-friendly Markdown vault: five interconnected notes (`index.md`, `Hosts.md`, `Services.md`, `Vulnerabilities.md`, `AD.md`) with native Obsidian callouts, enriched with CISA KEV, FIRST EPSS, NVD, and proof-of-concept data.

## Build / Install

**From source (requires Go 1.21+):**

```sh
go build .
```

**Cross-compile release binaries (Windows, Linux, macOS amd64 + arm64):**

```sh
bash scripts/build-release.sh [version]
# Produces dist/layzmd_<version>_<os>_<arch>[.exe]
```

**Prebuilt binary:** download from the GitHub Releases page and place it on your PATH.

## Usage

```sh
layzmd --csv scan.csv --out ./vault
```

When `--csv` or `--out` are omitted, layzmd opens a native file or directory picker dialog (requires a desktop environment).

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--csv` | *(dialog)* | Path to the Nessus CSV export |
| `--out` | *(dialog)* | Output directory for the Markdown vault |
| `--nvd-key` | `""` | NVD API key (falls back to `$PTC_NVD_API_KEY`) |
| `--no-enrich` | `false` | Skip all network enrichment; use cached data only |
| `--refresh` | `false` | Ignore cached enrichment and force a refetch |
| `--version` | — | Print version and exit |

## NVD API Key

Pass `--nvd-key <key>` or set the `PTC_NVD_API_KEY` environment variable. Without a key, NVD requests are rate-limited to 5 requests/30s; with a free key the limit rises to 50 requests/30s — a large difference on big scans. Get a free key at <https://nvd.nist.gov/developers/request-an-api-key>.

When launched by double-click (no `--nvd-key`/env key), layzmd shows a dialog to enter the key; what you enter is remembered between runs (stored under your OS user-config directory), so you only enter it once. Leave it blank to run anonymously.

## Enrichment

layzmd enriches each CVE from:

- **CISA KEV** — known exploited vulnerabilities catalog
- **FIRST EPSS** — exploit prediction scoring
- **NVD** — CVSS scores and descriptions
- **PoC sources** — VulnCheck, ExploitDB, Metasploit (and Nuclei detection templates) proof-of-concept references

Enrichment is rate-limited and results are cached under the OS cache directory (`os.UserCacheDir()`). On subsequent runs, cached data is used automatically.

- `--no-enrich` — fully offline mode; only previously cached data is used; no network calls are made
- `--refresh` — ignore the cache and refetch all enrichment data

## Output Vault

After running, open the `--out` folder as an Obsidian vault. The vault contains:

| File | Contents |
|------|----------|
| `index.md` | Navigation hub: summary counts + wikilinks to all section notes |
| `Hosts.md` | Hosts grouped by OS with finding counts |
| `Services.md` | Hosts grouped by protocol/port |
| `Vulnerabilities.md` | Findings grouped by vulnerability, sorted by priority and PoC availability |
| `AD.md` | Active Directory analysis: domains, domain controllers, users |

All notes use native Obsidian callout syntax (`> [!type]`) for clean rendering inside Obsidian.
