# Development

Project log locations are local, read-only associations. In the authenticated project detail
page, add folders from the project tree or another approved filesystem root, review metadata-only
suggestions, and run analysis against selected locations. CLI support is available through
`uv run chinescan projects logs list --project PROJECT_ID --json`, `add --project PROJECT_ID
--name NAME --path ABSOLUTE_PATH`, `suggest --project PROJECT_ID --json`, `analyze --project
PROJECT_ID [--location LOCATION_ID] --json`, and `remove LOCATION_ID --project PROJECT_ID
--yes`. The CLI accepts paths only for additions because browser selection IDs are short-lived
and session-bound. Removing a location removes its association only; files, scans, and findings
remain. EVTX is surfaced as unsupported until a bounded read-only parser is implemented.

Use Python 3.12+ and `uv`:

```powershell
uv sync --extra dev
uv run ruff check .
uv run ruff format --check .
uv run mypy chinescan
uv run pytest --cov=chinescan --cov-report=term-missing --cov-fail-under=80
uv run pip-audit --skip-editable
uv run chinescan code ./fixtures/sample-python-project
uv run chinescan code ./fixtures/sample-python-project --fail-on high
uv run chinescan code ./fixtures/sample-node-project --format json
uv run chinescan logs ./fixtures/sample-logs --rules ./fixtures/sample-logs --ioc-file ./fixtures/sample-iocs.txt --format json
uv run chinescan malware analyze ./fixtures/sample-malware/synthetic-indicators.txt --format json
uv run chinescan domain your-owned-domain.example --i-own-this-target --operator "Analyst" --profile light
uv run chinescan report SCAN_ID --format sarif --output report.sarif
uv run chinescan case create --from-scan SCAN_ID
uv run chinescan case show CASE_ID
uv run chinescan case link CASE_ID --type finding --id FINDING_ID
uv run chinescan case note add CASE_ID --text "Analyst observation"
uv run chinescan case timeline CASE_ID --format json
uv run chinescan case export CASE_ID --format html --output case-report.html
uv run chinescan db backup --output D:/restricted-backups/chinescan-2026-10-26
uv run chinescan db verify-backup D:/restricted-backups/chinescan-2026-10-26
uv run chinescan db restore D:/restricted-backups/chinescan-2026-10-26 --output D:/recovery/chinescan-restored.sqlite3
uv run chinescan db retention-plan --directory D:/restricted-backups --format json
uv run chinescan compare BASELINE_SCAN_ID CURRENT_SCAN_ID
uv run chinescan trends --days 30 --format json
```

### Local diagnostics

Run `uv run chinescan doctor` for the full read-only local environment report, or
`uv run chinescan doctor --json` for machine-readable output. `uv run chinescan status` prints a
short summary; both commands accept `--json`. Exit status is `0` when all checks pass, `1` when
one or more checks warn, and `2` when a check fails. Output uses ASCII `[PASS]`, `[WARN]`, and
`[FAIL]` markers and honors `NO_COLOR`. Doctor does not access the network, modify configuration,
write to the database, or change listeners. Its network-backed optional features (`pip-audit`,
`npm audit`, and authorized domain posture checks) are listed as opt-in.

The loopback dashboard exposes unauthenticated `GET /api/health` with only `status`, `app_name`,
`version`, `uptime_seconds`, `bind_address`, and `timestamp`. Authenticated `GET /api/ready`
returns `{state, checks, allowed_roots}`; checks have `id`, `label`, `state`, `detail`, and
`action_hint`. It returns HTTP 200 for healthy or degraded status and 503 when a check fails.
Authenticated `GET /api/diagnostics` returns platform/runtime and application versions, config and
storage states, operator state, root and deny-list counts, feature flags, scan bounds, record counts,
the shared checks, and up to 50 recent redacted error summaries. Readiness and diagnostics are
rate-limited. All routes retain loopback Host and same-origin protections.

The System status page offers **Check now** to refresh health, readiness, and diagnostics immediately.
Automatic healthy polling runs every 30 seconds. After a connection failure, retry intervals grow
exponentially from 1 second and cap at 60 seconds; a successful response resets the retry interval.
An unauthenticated browser session returns to operator login before detailed status panels appear.

Doctor checks Python/uv and Node/npm availability, Python environment integrity, frontend dependency
lock consistency and build presence, local ports 5173 and 8765, credentials schema, config and
database access, required directories, filesystem policy, offline readiness, and managed malware
storage. Fix hints accompany non-passing checks: install or repair the named tool/dependencies,
restore a valid credential/config, repair local database access, create required directories,
correct allowed roots or deny entries, or inspect an existing port listener without stopping it.
Missing managed malware storage is a warning; project scans do not require it.

Diagnostics payloads use logical labels and counts rather than absolute internal paths. Credential
contents, tokens, request bodies, and stack traces are never included. Error summaries contain a
stable code, route, request ID, timestamp, and redacted message; the in-memory ring retains at most
50 entries. If diagnostics cannot load, verify the loopback service and local configuration first,
then run `uv run chinescan doctor --json` with the same selected config and database options used by
the service. For browser access, confirm that the local operator session is active; the health route
is public, while readiness and diagnostics require authentication.

Dashboard frontend development additionally requires Node.js 22.12+ and npm. The frontend uses
React, TypeScript, Vite, Vitest, Testing Library, and Playwright; install its locked dependencies
with `npm ci --no-audit` from `frontend/`. Run the backend explicitly with
`uv run chinescan web serve` and the development UI with `npm run dev`. Both bind to loopback;
Vite proxies `/api` to port 8765.

The operator identity is an email address. ChiNeScan trims and lowercases it for case-insensitive
lookup. With no credential file, open the Vite loopback URL and choose **Create operator account**.
Signup creates the sole local operator and signs it in immediately. Passwords require at least 12
characters and are stored as Argon2id hashes. Signup returns a generic conflict after an account
exists.

Passwords cannot be recovered; they can only be reset. **Forgot password?** gives generic local
instructions. Run `uv run chinescan web reset-password --email operator@example.com`; the CLI
prints a one-time token locally. Enter it with the email and new password at `/reset-password`
within 15 minutes. The raw token is never returned by the API or written to logs; only its SHA-256
digest is stored. Tokens are single-use, a later reset request replaces an earlier token, and
repeat CLI requests are limited to one per minute. Reset invalidates existing sessions.

`uv run chinescan web recover-operator` first creates and names a timestamped credential backup,
then asks whether to reset/migrate or retire the local operator. The `retire` choice removes only
the credential file after explicit confirmation; database scans, settings, and other data remain.
The reset/migrate choice asks for an email, preserves the old password hash until the operator
completes the new-token reset flow, and prints a reset token locally. A legacy `username`
credential already containing a valid email is backed up and migrated on app startup. A non-email
legacy value is backed up, marked as requiring recovery, and cannot sign in until the guided
recovery flow replaces it.

`uv run chinescan web bootstrap` remains the terminal setup path and refuses to overwrite an
existing account. The public `POST /api/auth/signup` accepts `email` and `password`; `POST
/api/auth/forgot-password` and `POST /api/auth/reset-password` follow the same loopback and
same-origin guards. See [API](API.md) for request details. Backend coverage is in
`tests/unit/test_web_api.py` (`uv run pytest tests/unit/test_web_api.py`). The Playwright flow in
`frontend/e2e/operator-recovery.spec.ts` covers signup, logout, local reset-token use, login, and
dashboard access with synthetic credentials. Its Playwright trace and screenshots are disabled so
the synthetic one-time token is not retained in test artifacts.

To disable an existing operator without creating another one, run
`uv run chinescan web retire-operator`. The command makes a timestamped copy beside the active
credential file (`operator.json.bak-YYYYMMDD-HHMMSS`), shows only the username/email-field
presence and file paths, then requires the exact phrase `RETIRE OPERATOR`. On confirmation, it
renames the active file to `operator.json.retired-YYYYMMDD-HHMMSS`. It touches no scan records,
application settings, or other files. Pass `--credential-file PATH` if bootstrap/serve uses a
custom credential path. A missing active file is a successful no-op.

To restore an archived credential, run `uv run chinescan web restore-operator`, select a listed
backup or retired file, and type `RESTORE OPERATOR`. If an active credential exists, it is first
copied to a timestamped `.bak-*` file before the selected archive is restored. These commands
never print password hashes or create a replacement account. Passwords and Argon2id hashes cannot
be recovered from the credential file; the backup preserves the hash for restoring the old login.
After retirement, manually start the backend and use browser signup or `uv run chinescan web
bootstrap` when you are ready to create an operator.

For production browser acceptance, first build the frontend and install Playwright's Chromium
browser locally (no global package or system browser installation):

```powershell
cd frontend
npm ci --no-audit
npx playwright install chromium
npm run build
npm run test:e2e
```

The Playwright harness launches the production build served by the authenticated Python app on
an ephemeral loopback port. It creates synthetic SQLite records, a randomly generated temporary
operator account, and temporary credential/data directories. It does not use the configured
operator account, personal database, or assessment commands. Temporary server processes and
fixture data are removed after the run. Traces and screenshots are retained only for failures
under `frontend/test-results/`; do not commit these generated artifacts. The suite requires
Python 3.12+ and the project Python environment available to `py -3.12`.

Create the single operator account in the browser or with `uv run chinescan web bootstrap`. The
default credential file is `%USERPROFILE%\.config\chinescan\operator.json`; it contains the
operator email and Argon2id password hash. To inspect only the email in PowerShell, run:

```powershell
(Get-Content "$env:USERPROFILE\.config\chinescan\operator.json" | ConvertFrom-Json).email
```

On Windows, protect this file through the user's profile ACL; POSIX mode bits do not prove Windows
ACL protection. A custom path can be supplied with `--credential-file`.

The dashboard uses one Uvicorn worker, volatile sessions, 30-minute expiry, HttpOnly and
SameSite=Strict cookies, CSRF validation, loopback host/origin checks, and a five-attempt
per-process login throttle. Logout revokes the current session; process restart invalidates all
sessions. The included service is plain HTTP with `Secure` cookies disabled. A Secure cookie is
not sent over ordinary HTTP; local HTTPS termination is not configured in this stage.

Run the CLI with `uv run chinescan --help`. The test suite uses temporary configuration and SQLite files. Do not point tests at personal data. Keep dependency changes in `pyproject.toml` and regenerate `uv.lock` with `uv lock`.

Configuration precedence is explicit root CLI options (`--database`, `--config`), then
`CHINESCAN_DATABASE_PATH` / other `CHINESCAN_` settings, then the selected TOML file,
then defaults. The TOML path defaults to `~/.config/chinescan/config.toml` and can be
selected with `--config` or `CHINESCAN_CONFIG_PATH`. Settings are validated before a
command opens SQLite or launches scanner tools. `api_token` is accepted as a secret
environment/config value but is not written by `config init` or printed by validation.

Code scanning reads local files and does not execute them. Built-in scanning is the default. Semgrep requires a local rules file; Trivy requires locally cached databases. pip-audit and npm audit require `--allow-network-audits` because they submit dependency metadata to advisory services.

Use `chinescan code <project> --fail-on high` to make a CI job exit with status 1 when candidate findings meet or exceed HIGH severity. Supported thresholds are `critical`, `high`, `medium`, `low`, `info`, and `never`; `never` is the default. These findings remain candidates for analyst validation.

`chinescan trends` reads stored scans, findings, and alerts from local SQLite and reports daily counts for the requested 1–366 day window. It does not include target names or raw evidence.

Log analysis reads local exports and bounded archives without extraction or network access. Raw log lines are not persisted; normalized records are retained in the configured SQLite database. The Sigma evaluator supports a safe, documented subset, not the entire Sigma language.

Malware static triage reads one regular file up to 64 MiB and never executes it. The standalone sample intake and job workflow is deprecated: new sample registrations and jobs return `410 sample_workflow_deprecated`; existing sample records, analyses, and case links remain read-only history. Use `chinescan projects malware scan --project <id> --i-understand-vm-risk` or the project page. Project scans require an explicit acknowledgement at the backend and apply bounded static checks without executing, importing, installing, extracting, or passing project content to a child process. They are heuristic leads, not verdicts. Run Chinescan and the scan inside an isolated VM or sandbox. Process containment is not an OS sandbox and does not isolate filesystem or network access. The B1 sample worker remains a separate historical path with managed storage and Windows Job Object controls; those controls are not an OS sandbox. See [Malware backend operations](MALWARE-BACKEND.md) for its historical storage configuration and recovery boundaries.

Project scanning visits at most 50,000 files, 1 GiB total, 16 MiB per file, depth 32, 2 seconds of checked time per file, and a 300 second job deadline by default. Per-file time is checked between reads; a slow disk read cannot be interrupted. Custom local rules use ChiNeScan's own small bounded TOML rule format and are not native YARA rules. If no rules directory is configured, custom-rule coverage is visibly marked as skipped. The host virtualization hint is unreliable and never controls whether scanning is allowed.

Local project malware rules are read only from `.toml` files in the configured rules directory. Unknown keys or invalid entries reject that file and add a path-free coverage note. The format supports up to 100 rules per file, 20 strings per rule, 500 characters per pattern, and a `min_matches` count from 1 to 50. Regexes use a restricted safe subset; backreferences and nested quantified groups are rejected.

```toml
[[rules]]
id = "download_hint"
title = "Download command hint"
severity = "medium"
description = "A local operator rule for a command indicator."
strings = [
  { kind = "literal", value = "Invoke-WebRequest", nocase = true },
  { kind = "regex", value = "curl[ ]+https?://", nocase = true },
]
condition = { min_matches = 1 }
```

Domain assessment is the sole built-in network posture command. Use it only with explicit ownership or a matching local authorization file. Unit tests mock all domain network operations; do not add live targets to acceptance checks.

Case workflow stores status, severity, typed links, append-only notes, and activity in the
existing local JSON record. Links must resolve to persisted records; Artifact records are
not persisted and cannot be attached. Case exports support JSON, Markdown, and self-contained
HTML, redact secrets and selected direct identifiers, and do not change scan reports or SARIF.
Timeline output distinguishes source event occurrence time from case activity time. Record
ingestion timestamps are not available. Notes and activities are embedded in the Case record,
so a single SQLite transaction saves each workflow update. Case author labels are unverified.

Database backups use SQLite's online backup API and publish a verified database plus manifest
bundle at a new path. Verification never migrates or repairs a backup. Restore only creates a new
database file, upgrading that restored copy when its schema is an older supported revision.
`db retention-plan` is a dry-run preview and never deletes files. Case report output paths must not
exist already; export does not overwrite prior reports.

The dashboard exposes this same `CaseWorkflow` through authenticated, same-origin API routes. For
local code-assessment jobs it reads an operator-controlled TOML project registry and runs the
existing `CodeScanService` with only `BuiltinRuleScanner`; details and path limits are in
[Project operations](PROJECTS.md).
Case creation starts from an existing scan; status updates, link validation/idempotency, and
append-only notes remain enforced by the workflow layer. The UI displays case activity and source
timelines and downloads redacted JSON, Markdown, or HTML case reports, plus supported scan reports.
HTML reports are attachments. Evidence and analyst notes are rendered as text, and legacy author
labels remain unverified. Job requests accept only a stable project ID, and responses contain no
full local project path. There is no cancellation or safe hard wall-clock timeout for the built-in
synchronous scan; graceful shutdown waits for active work.

Dashboard log jobs use the same authenticated single-worker loopback service. The operator maintains
an ID-based local source registry with optional local Sigma rules and IOC list paths; browser requests
cannot submit file paths or detection logic. Alerts, events, and source timelines are paginated and
scoped to a persisted log scan. Partial ingestion is represented as a partial job with path-free
diagnostic categories. See the [log-source operator guide](LOG-SOURCES.md) and [API contract](API.md).
# Authentication throttling

Login, signup, password reset, and forgot-password throttles are held in process memory and keyed by client IP and normalized email. Five failures begin a one minute lockout; repeated groups of five increase the delay to five and fifteen minutes, capped at fifteen minutes. Restarting the local service clears these counters. Locked requests return a generic response and `Retry-After` header.

## Local environment troubleshooting

Use the repository's uv-managed environment for development commands. If `uv run` reports a missing `pyvenv.cfg`, confirm `UV_PROJECT_ENVIRONMENT` and `VIRTUAL_ENV` are unset or point to this repository's `.venv`, then run `uv sync --all-groups --all-extras`. Run pytest with `--basetemp` under the operating system temporary directory so SQLite handles are not removed while the repository is in use. The test configuration rejects a basetemp that resolves inside the repository. On Windows, pass `--basetemp=C:\t`; on other platforms use a short directory below the system temporary directory.

## On-chain provider safety

Wallet tracing is offline by default. CLI lookups require `--allow-network-chain`; web lookups require both request opt-in and `chain_network_enabled = true` in server settings. EVM requests use the built-in Etherscan host allowlist. Custom registry endpoints must specify an explicit `host_allowlist`, use HTTPS and public DNS addresses, cannot include credentials, and use port 443 unless their registry entry explicitly permits another port. Redirects are limited to two HTTPS hops on the original host. The transport resolves and validates DNS again before each connection, pins that public address for the socket, and does not use environment proxies.

The default trace limits are 120 seconds, 100 provider requests, 500 addresses, depth 6, and 2 MB per response. DNS resolution has a separate 2 second timeout and a bounded four-thread daemon pool. Reaching a limit records a coverage gap and makes the scan partial. API keys come only from the environment variable named by the chain registry and are passed only inside the provider request adapter. Diagnostics expose only a configured/not-configured boolean.

## Redaction processing bounds

The shared redactor caps each string or byte value at 1,000,000 characters/bytes, the combined string/key input at 8,000,000 characters/bytes per top-level redaction operation, nested values at 32 levels, and one operation at 100,000 visited values and mapping keys. These fixed safety bounds apply to CLI, API, logging, imports, and report generation; they are not configurable. Inputs exceeding a bound fail closed with `[REDACTED: safe processing limit exceeded]` or, when a report cannot preserve its required structure, an explicit report error. External-report text fields are clipped to their individual retained-field limits (at most 2,000 characters) before redaction, so discarded tails are not persisted. Keep redaction positive controls when changing these limits or patterns.

The built-in Etherscan-family EVM registry uses API V2 (`https://api.etherscan.io/v2/api`) and a numeric `chain_id`. An operator TOML entry for another EVM chain can use the same endpoint and `api_key_env = "CHINESCAN_ETHERSCAN_KEY"`, with `host_allowlist = ["api.etherscan.io"]` and its network's `chain_id`; API keys are sent in the POST body, never the URL. Other registry fields are `family`, `native_asset`, `explorer_api`, `allow_nonstandard_port`, and (for custom hosts) `host_allowlist`. Provider error gaps include `rate_limited`, `invalid_api_key`, and `provider_error` with a short redacted reason. The provider treats “No transactions found” as an empty result.
# EVTX log support

EVTX files are detected by project log suggestions and shown as unsupported until a parser is available. A future parser should use a bounded, read-only implementation: accept only regular files approved by filesystem policy, cap file bytes, records, nesting, and elapsed time, parse from a bounded stream without executing embedded content, and return a partial result with skipped counts when a cap is reached. It must not upload samples or write beside the source file.

# GitHub imports

Public GitHub imports are opt-in. The default is `github_import_enabled = false`; enable it only
with an explicit operator change in the local `config.toml` and restart ChiNeScan:

```toml
github_import_enabled = true
github_import_timeout_seconds = 120
github_import_max_bytes = 524288000
github_import_max_files = 50000
github_import_max_projects = 20
```

The URL preview is local validation only. Import is a second explicit action. Fetches are shallow,
skip submodules and LFS, disable hooks, reject links/reparse points and unsafe names, and refuse
redirects. Repository content is never executed, installed, imported, or opened by another
program. Git metadata has a separate bounded allowance. DNS and TLS use the operating system.
Import and scan inside a VM; the local scanner is not an OS sandbox.

Troubleshooting: install Git if the UI reports `git_missing`; inspect system security history if
files are quarantined and the job is incomplete (never disable Defender); `repo_not_found_or_private`
means the public repository may not exist or may be private; reduce content when the size or file
caps are reached. The default limits are 120 seconds, 500 MiB of project content, 50,000 files,
and 20 GitHub projects. If `path_too_long` is reported, shorten the configured data directory. The
managed clone uses the short `gh` subfolder; doctor and API diagnostics report only `ok` or
`at-risk` for the Windows path budget and never print the path. Private-repository tokens are
unsupported.
