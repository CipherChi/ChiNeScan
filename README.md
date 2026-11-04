# ChineScan

ChineScan is a local security assessment and investigation tool. It scans local code, analyzes exported logs and local malware samples, performs domain posture checks only with explicit authorization, and supports investigations and reports. Findings need analyst review; this tool does not establish that a system is safe.

## What Chinescan does

ChineScan helps operators collect and review leads from local assessment workflows. Code scanning reads source files without executing project code. The indicator scanner compares project files with indicator data supplied from local files and operates offline. Other capabilities include exported-log analysis, static malware triage, explicitly authorized domain posture checks, cases, reporting, and database backup and recovery.

## Workable features

- Code scanning with built-in heuristic rules and optional scanner integrations. The `indicators` scanner matches local project files against local indicator files.
- Optional finding evidence grades: `confirmed_artifact`, `pattern_match`, `reference_only`, and `context_only`. Evidence grade is separate from confidence; existing findings may omit a grade.
- Code-scan coverage accounting records examined files and coverage gaps. Verdicts are `leads_found`, `no_matches_with_gaps`, `no_matches_in_scope`, and `scan_failed`.
- Code scans and on-chain traces automatically save JSON and Markdown reports. Log, malware, and domain scans do not currently auto-save JSON or Markdown reports.
- A local authenticated web dashboard supports first-operator sign-up and sign-in.

## CLI quick start

Install Python 3.12 or newer and [uv](https://docs.astral.sh/uv/), then install the project:

```powershell
uv sync --extra dev
uv run chinescan --help
```

On Windows, `py -3.12 -m chinescan` is also supported after installing the project and its
dependencies. For example, from the repository root:

```powershell
py -3.12 -m pip install -e ".[dev]"
py -3.12 -m chinescan --help
```

This module form does not depend on the Python `Scripts` directory being on `PATH`. If using
`chinescan` directly, activate the environment where the project was installed or add that
environment's `Scripts` directory to `PATH`.

Initialize local configuration and inspect it:

```powershell
uv run chinescan config init
uv run chinescan config validate --path "$HOME/.config/chinescan/config.toml"
```

Commands and their options are also available through `chinescan <command> --help`. Configuration initialization does not write secret values.

### Local diagnostics

Run `uv run chinescan doctor` for read-only checks of Python/uv and Node/npm, the Python environment,
frontend lockfile/dependencies and build, local listeners on ports 5173/8765, credentials schema,
configuration, database access, required directories, filesystem policy, and offline readiness.
`uv run chinescan status` prints a short summary. Both support `--json`; exit codes are `0` for all
PASS, `1` when any check is WARN, and `2` when a check is FAIL. The output uses ASCII status markers
and honors `NO_COLOR`. Fix hints explain how to address each non-passing check. Core diagnostics do
not use the network; `pip-audit`, `npm audit`, and authorized domain posture checks are opt-in.

The authenticated dashboard adds **System status**. `GET /api/health` is unauthenticated and returns
only service status, app name, version, uptime, loopback bind address, and timestamp. Authenticated
`GET /api/ready` returns a state (`ok`, `degraded`, or `failed`), readiness checks, and allowed-root
counts; it responds 200 for healthy/degraded and 503 on failure. Authenticated `GET /api/diagnostics`
adds platform/runtime, config/storage, operator, policy counts, scan bounds, record counts, and up to
50 recent redacted error summaries. Checks expose an ID, label, PASS/WARN/FAIL state, safe detail,
and action hint. Payloads omit internal absolute paths, credentials, tokens, request bodies, and stack
traces; error summaries stay bounded in memory.

The System status page has a keyboard-accessible **Check now** button that refreshes all three
endpoints immediately. Healthy polling runs every 30 seconds. Failed connections retry with
exponential delays from 1 second up to a 60-second cap; successful checks reset the retry delay.
An unauthenticated dashboard session is redirected to operator login before detailed status data is
shown.

If the System status page cannot connect, verify the loopback service and operator session, then run
`uv run chinescan doctor --json` with the service's local configuration and database selections.
Missing managed malware storage is a warning only; project scans do not require it. See
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md#local-diagnostics) for endpoint details and troubleshooting.

## Code scan examples

Run built-in rules against a local project. JSON and Markdown reports are saved automatically:

```powershell
uv run chinescan code .
```

Add local indicator matching (see the next section), disable automatic report saving, or return a failure status when coverage gaps are recorded:

```powershell
uv run chinescan code . --scanner builtin --scanner indicators --indicator-file .\indicators.json
uv run chinescan code . --no-save-report
uv run chinescan code . --fail-on-gaps
```

The built-in assessment scans source files only, honors `.gitignore`, and excludes generated/vendor
trees and lockfiles by default. Add project-specific exclusions with `code_excluded_paths` in the
local TOML configuration. Reports include exclusion coverage, grouped findings, remediation guidance,
and a heuristic “vibe-coding risk indicators” score; that score is not evidence of authorship.

From a scan detail in the authenticated dashboard, use **Import external report** to import a
external JSON or SARIF report. If Scanity provides an export in one of these formats, it can be
imported locally; the public Scanity documentation does not currently document an API, CLI, or export
format. Imports are limited to 2 MB, validated locally, and stored as separate
external scanner results. Imported text is untrusted: it is escaped for display, never executed, and
no links or instructions in the report are followed. This import does not send project files or
reports to Scanity. No Scanity upload integration is enabled.

`--fail-on-gaps` exits with status 1 when the scan records coverage gaps. Scanner failures also produce a nonzero exit. A verdict summarizes findings and coverage; it is not a safety determination.

## Indicator scanning examples

The `indicators` scanner requires one or more local files passed with `--indicator-file`. It reads supported JSON, CSV, or text IOC formats, plus supported STIX 2.1 bundle indicator entries and MISP event attributes. Support is limited to the formats and entry types implemented by the parser; unsupported entries may be reported as coverage gaps. Input files are not fetched from URLs, and the scanner does not resolve or contact indicator values. Indicator matching is strictly offline and accepts only local indicator files.

```powershell
uv run chinescan code . --scanner indicators --indicator-file .\indicators.json
uv run chinescan code . --scanner indicators --indicator-file .\domains.txt --indicator-file .\hashes.csv
```

## Reports and share summaries

Code scans and on-chain traces automatically save JSON and Markdown reports. The default directory is `~/.local/share/chinescan/reports`; set it with the global `--reports-dir` option or `CHINESCAN_REPORTS_DIR`. You can also set `reports_dir` in the local TOML configuration. Use `--no-save-report` to opt out for a code scan or on-chain trace.

Reports for persisted scans can be rendered as JSON, Markdown, HTML, CSV, SARIF, or `share-summary`:

```powershell
uv run chinescan report <scan-id> --format share-summary --output .\share-summary.md
```

A share summary contains the verdict and caveat, evidence and severity counts, coverage gaps, indicator-file names and hashes when recorded, and up to ten lead titles with evidence grades and locations. It omits finding descriptions and absolute paths, redacts sensitive values, and masks indicator IDs in lead titles. Review a generated summary before sharing; redaction is not a substitute for checking its contents.

Log, malware, and domain scans do not currently auto-save JSON or Markdown reports. This does not prevent supported explicit report commands from rendering stored scan records.

## Web dashboard sign-in

Start the dashboard and create the first operator from the **Create operator account** link. The operator identity is an email address, normalized to lowercase. Passwords must be at least 12 characters and are stored as Argon2id hashes. Only one operator account is supported, so signup is disabled after the first account exists.

On Windows, after installing frontend dependencies once with `npm ci` in `frontend`, start both
local services from the repository root with:

```powershell
.\scripts\start-dashboard.ps1
```

The script opens separate consoles for the backend and frontend. The dashboard is available at
`http://127.0.0.1:5173`; close each service console to stop that service.

```powershell
uv run chinescan web serve
```

The server binds to `127.0.0.1` by default. `uv run chinescan web bootstrap` remains available for terminal provisioning and refuses to overwrite existing credentials. To reset a forgotten password, select **Forgot password?**, then run `uv run chinescan web reset-password --email operator@example.com` in the local terminal. Enter the printed one-time token on `/reset-password` within 15 minutes. Passwords are resettable, never recoverable; reset revokes existing sessions.

For a legacy account cleanup, run `uv run chinescan web recover-operator`. It makes a timestamped credential backup before prompting you to reset/migrate the account or retire it. Retiring removes only the operator credential file, leaving scans and application settings intact. A legacy username that is not already a valid email must go through this recovery flow; ChineScan does not invent an email address.

To explicitly retire the active account without creating a replacement, run `uv run chinescan web retire-operator` and type `RETIRE OPERATOR` when prompted. It backs up the credential file beside the original, then renames it as retired. To restore one, run `uv run chinescan web restore-operator`, select the archive, and type `RESTORE OPERATOR`; an existing active credential is backed up before replacement. Both commands accept `--credential-file PATH` for custom locations and leave scan/application data untouched. Passwords and Argon2id hashes cannot be recovered; the backup only preserves the hash for restoring that account. After retirement, start the backend and create a new operator manually through signup or `uv run chinescan web bootstrap`.

To inspect the saved email in PowerShell:

```powershell
(Get-Content "$env:USERPROFILE\.config\chinescan\operator.json" | ConvertFrom-Json).email
```

The API routes are `POST /api/auth/signup`, `POST /api/auth/forgot-password`, and `POST /api/auth/reset-password`; see [the API guide](docs/API.md). The forgot-password response is generic and never reveals whether an email is registered. Reset tokens are only displayed by the local CLI and stored as hashes.

The dashboard shows recent scans, verdicts and coverage gaps, scan details, failures and warnings, and JSON/Markdown report downloads for code scans. Access to scans, cases, evidence, reports, and job controls requires authentication.

## Configuration

Configuration can come from the local TOML file and `CHINESCAN_` environment variables. CLI settings take precedence where supported. The reports directory can be set with:

```powershell
$env:CHINESCAN_REPORTS_DIR = "$HOME/chinescan-reports"
uv run chinescan --reports-dir "$HOME/chinescan-reports" code .
```

The default SQLite database and report locations are local user-data paths. Config initialization never writes secret values; logs redact secret-like values.

## Public GitHub imports

Public GitHub imports are opt-in and disabled by default. To enable them, add the following to
your local `config.toml` and restart ChineScan:

```toml
github_import_enabled = true
github_import_timeout_seconds = 120
github_import_max_bytes = 524288000
github_import_max_files = 50000
github_import_max_projects = 20
```

Imports are shallow, do not fetch submodules or Git LFS content, do not run hooks or repository
content, reject links and unsafe filenames, and refuse redirects. Git metadata has a separate
bounded allowance. Import and scan public repositories inside a VM. Files quarantined or removed
by Defender can produce an incomplete import; review system security history without disabling
Defender. Git must be installed. “Not found or private” means only public repositories are
supported; private-repository credentials are not used. Imports can fail at the configured size,
file-count, time, or project cap. If the UI reports `path_too_long`, shorten the configured data
directory; the managed clone uses a short `gh` subfolder, and doctor reports an at-risk Windows
path budget without printing the path.

## Security and responsible use

Use ChineScan only on assets and data you own or are explicitly authorized to assess. Code and indicator scans operate on local files; code scanning does not execute project code. The indicator scanner is offline. Domain posture checks perform network activity and require explicit target authorization. Optional package audit integrations can send dependency metadata to advisory services only when explicitly enabled with `--allow-network-audits`.

Malware analysis is static triage: samples are not executed or uploaded. It is not an OS sandbox. The dashboard is local and authenticated; do not expose it publicly. Matches are leads, not proof; no matches do not prove safety. Coverage gaps and scanner failures limit what a scan can say. ChineScan does not provide protection, threat removal, or complete detection coverage.

## On-chain tracing

List the built-in chains, then trace from a local explorer CSV/JSON export passed with `--import`. Use `--label-file` for local labels. Trace depth is limited to 1–6 and defaults to 3.

```powershell
uv run chinescan chain chains
uv run chinescan chain trace 0x0123456789abcdef0123456789abcdef01234567 --chain ethereum --import .\transfers.csv
uv run chinescan chain export <scan-id> --format transfers-csv --output .\transfers.csv
```

The built-in chain list includes Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, Avalanche, Bitcoin, Tron, and Solana. The built-in online provider is for EVM chains; other families can be traced from local imports. Network lookups require the CLI `--allow-network-chain` flag or, in the dashboard, request opt-in together with server-side `chain_network_enabled = true`. EVM online lookups use the `CHINESCAN_ETHERSCAN_KEY` environment variable when configured. Saved graph exports support `graph-json`, `indicators`, and `transfers-csv`; the other export format is GraphML.

Wallet tracing is offline-first. Behavioral patterns and address labels are leads for investigation, not proof of ownership or identity. No private keys or signing operations are used.

## Development and tests

Install development dependencies and run the local checks:

```powershell
uv sync --extra dev
uv run --locked --extra dev ruff check .
uv run --locked --extra dev mypy --strict chinescan
uv run --locked --extra dev pytest -q
```

The frontend checks are run from `frontend/`:

```powershell
npm ci
npm run typecheck
npm test -- --run
```
