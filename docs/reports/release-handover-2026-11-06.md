# ChiNeScan local release handover — 2026-11-06

This handover describes the validated local, single-operator, built-in-scanner profile. It is not a
deployment approval or a claim that optional external scanners have been verified.

The later release-manager follow-up is recorded in [release notes](release-notes-handover-2026-11-06.md)
and [the release snapshot manifest](release-snapshot-manifest-2026-11-06.json). Those artifacts
include the follow-up documentation/helper corrections and supersede this report's snapshot count
for the final release candidate.

## Snapshot and reproducibility identity

The implementation was validated from an uncommitted working tree based on
`2ad86b05ca82181da78b3eb6bfee5598d63dc8af`. The base commit alone does not identify the release
candidate. The [closure inventory](implementation-inventory-closure-2026-11-06.json) matches all
49 recorded files exactly as of handover preparation: no missing files, hash mismatches, newly dirty
paths, or paths no longer dirty were found. It covers modified ChiNeScan source, relevant tests,
the shared report fixture, schemas, and changed documentation.

The closure inventory is a worktree-delta manifest. Its own file and the companion
`release-closure-2026-11-06.md` are excluded from its hash list by design. At the start of this
handover all 49 listed file hashes matched. Handover documentation then intentionally changed
`README.md` and `docs/API.md` and added this report plus the full snapshot inventory; no product
source or test implementation changed, and the closure inventory was left untouched. The companion
[handover snapshot inventory](implementation-inventory-handover-2026-11-06.json) hashes the full
tracked and unignored checkout snapshot needed alongside the base commit, including source,
fixtures, tests, schemas, documentation, package/lock files, and scripts. It excludes this
inventory and this handover report, plus ignored local state such as `.env`, databases, virtual
environments, dependency directories, and generated test/build output. `.env.example` is included;
it contains placeholders, not operator secrets. No production database or credentials are part of
this handover.

## Supported profile and interpretation

- **Validated profile:** one operator, local machine, loopback dashboard, built-in static code
  scanner, local SQLite. Dashboard startup is explicit and binds to `127.0.0.1`.
- **Unsupported:** remote or multi-user deployment. This work does not add public binding, tenant
  isolation, distributed sessions, or a remote operating model.
- Findings are static-analysis leads for analyst review, not automatic proof of a vulnerability,
  exploitability, or safety. A no-match result does not prove a project safe.
- Code-pattern risk is a deterministic heuristic over configured source patterns. It is not an
  AI-authorship determination, calibrated probability, severity verdict, or completeness measure.
- New explanations separate observed source text, established facts, inferences, possible impact,
  prerequisites, verification steps, and limitations. Confidence labels are heuristic categories.
  The `static-impact-v1` policy keeps severity as potential impact; the built-in matcher does not
  establish runtime reachability or exposure.
- Legacy findings or scans may not contain versioned explanations, confidence rationales, or score
  contribution ledgers. The UI and CLI label those fields unavailable rather than reconstructing
  history.
- `full-json` remains bounded at 10,000 findings and 20 MiB. JSONL is the separate complete
  retrieval path for larger existing scans. An interrupted JSONL file without a valid final
  completion record, matching count, and SHA-256 digest is incomplete.

Protections include local-only defaults, explicit operator authorization before domain posture
checks, authenticated access to scans/cases/evidence/reports/job controls, static-only malware
triage, no scanned-project code execution, bounded file/record/report operations, mandatory
redaction on report/API paths, secret-free configuration initialization, and secret redaction in
logs. These controls do not make this a multi-user service or an OS sandbox. Windows POSIX mode
bits do not establish restrictive ACLs.

## Local quickstart (Windows PowerShell)

Prerequisites: Python 3.12+, `uv`, Node.js 22.12+ and npm. From the repository root, prepare the
locked Python development environment and install the locked frontend dependencies:

```powershell
uv sync --locked --extra dev
Push-Location .\frontend
npm ci --no-audit
Pop-Location
```

Configuration is optional for the defaults. On a first setup only, `uv run chinescan config init`
creates a local TOML file with paths and log level; it does not write secrets. It refuses to
overwrite an existing config. Validate an existing config with
`uv run chinescan config validate --path "$HOME/.config/chinescan/config.toml"`.

Start the backend in one PowerShell window from the repository root:

```powershell
uv run chinescan web serve
```

It starts one backend worker on `127.0.0.1:8765`. In a second window, start the Vite dashboard:

```powershell
Set-Location .\frontend
npm run dev
```

Open `http://127.0.0.1:5173`. Create the one local operator account in the browser using an email
and password chosen for the local installation; do not put real credentials in command history or
source-controlled files. The backend and CLI use the same default SQLite database path. If you
choose a custom database with the CLI's global `--database` option, the backend must be started
with the same option for both surfaces to show the same scans. The Vite proxy and backend both bind
to loopback.

Run the built-in assessment on the repository's controlled sample project:

```powershell
uv run chinescan code .\fixtures\sample-python-project --scanner builtin --format json
```

The JSON output includes `scan_id`; copy that value for the following commands. The scan persists
even when `--no-save-report` is supplied; that flag only disables automatic JSON/Markdown report
files. Inspect explanations and the score contribution ledger in the CLI:

```powershell
uv run chinescan report SCAN_ID --format detail
```

In the dashboard, open the same scan from the recent scans list, select a finding to read its
evidence, severity/confidence rationales, prerequisites, false-positive notes, and limitations, and
review the code-pattern score contribution ledger. A legacy record can truthfully show the
explanation or contribution ledger as unavailable.

Export complete JSON when the scan is within both full-JSON limits:

```powershell
uv run chinescan report SCAN_ID --format full-json --output .\scan-report.json
```

For complete retrieval from a scan above either full-JSON limit, use the line-oriented stream:

```powershell
uv run chinescan report SCAN_ID --format jsonl --output .\findings.jsonl
```

Each line is UTF-8 JSON. The first row is a manifest, finding rows follow stored scan order, and
the last row must be a `complete` record. Verify completion and the SHA-256 digest over the exact
finding-row bytes (including each newline) with Python:

```powershell
@'
import hashlib, json, sys
from pathlib import Path

rows = Path(sys.argv[1]).read_bytes().splitlines(keepends=True)
manifest = json.loads(rows[0])
complete = json.loads(rows[-1])
finding_rows = rows[1:-1]
assert manifest["type"] == "manifest"
assert all(json.loads(row)["type"] == "finding" for row in finding_rows)
assert complete["type"] == "complete"
assert complete["returned_findings"] == manifest["total_findings"] == len(finding_rows)
assert complete["sha256"] == hashlib.sha256(b"".join(finding_rows)).hexdigest()
print(f"Complete: {len(finding_rows)} findings; SHA-256 verified")
'@ | uv run python - .\findings.jsonl
```

The check fails for an absent completion row, error row, count disagreement, or digest mismatch.
The stream snapshots the scan's ordered finding-ID list at start; each bounded batch is read as it
is reached. It is not a whole-database transaction snapshot. An unsafe, oversized individual
record fails closed; no completion marker means the consumer must discard the artifact as
incomplete.

The dashboard's **Pause ambient motion** control disables decorative motion and persists the
preference in that browser. The operating system's reduced-motion preference also disables it.
Click **Resume ambient motion** to turn the decoration back on. Stop each local service with
`Ctrl+C` in its terminal window.

## Optional-scanner verification checklist

Current status for every optional scanner is **unverified on this handover host**. The earlier
closure run found all five executables unavailable and the opt-in tests skipped. Fixture/adapter
tests are not real scanner integration tests. Do not install tools, refresh databases, or fetch
signatures as part of this checklist. `--require-real-scanners` intentionally fails if a required
executable or local asset is missing; it prevents an unavailable integration from being counted as
a pass.

Run the exact opt-in integration suite only in an environment where all required tools/assets are
already installed and local. To verify one scanner, select its named test below; for a release
claim covering all five, run the complete command and require all five tests to pass:

```powershell
py -3.12 -m pytest --require-real-scanners -q -rs --basetemp $env:TEMP\chinescan-real-scanners tests\integration\test_real_scanners.py
```

| Integration | Required local executable/configuration/assets | Test and acceptance evidence | Current status |
|---|---|---|---|
| Semgrep | `semgrep` on `PATH`; repository supplies `fixtures/real-scanners/semgrep-local.yml` and positive/clean source fixtures. No remote ruleset is needed by this test. | `test_semgrep_real_local_positive_negative_persistence_and_report`; record `semgrep --version`, successful positive rule ID/location, clean negative result, persisted finding and report. | Unverified; executable absent in closure environment. |
| Gitleaks | `gitleaks` on `PATH`; local positive and clean directories are under `fixtures/real-scanners/`. Test asserts version 8.30.1 and redaction of the synthetic token. | `test_gitleaks_real_local_positive_negative_persistence_and_redaction`; record exact version, positive/clean outcomes, persisted result, and evidence that fixture token is absent from serialized output. | Unverified; executable absent in closure environment. |
| Trivy | `trivy` on `PATH` and an already-local Trivy vulnerability DB (`%LOCALAPPDATA%\aquasecurity\trivy\db` on Windows, `~/.cache/trivy/db` on Unix); test uses offline flags and local config fixtures. Version is pinned to 0.76.1. | `test_trivy_real_offline_local_database_positive_negative_and_persistence`; record exact version, local DB availability, expected positive misconfiguration, clean negative, and persisted finding. | Unverified; executable and local DB not available/verified in closure environment. |
| YARA | `yara` on `PATH`; local rules `fixtures/real-scanners/yara-local.yar` and positive/clean text samples. | `test_yara_real_local_positive_and_negative`; record version, expected benign marker from positive fixture, and distinct no-match exit for clean fixture. | Unverified; executable absent in closure environment. |
| ClamAV | `clamscan` on `PATH` and existing `.cvd` or `.cld` signature file in a standard local directory (`%ProgramData%\clamav` or `%ProgramFiles%\ClamAV` on Windows; `/var/lib/clamav` or `/usr/local/share/clamav` on Unix). | `test_clamav_real_local_clean_fixture`; record version, signature availability, clean fixture `OK`, and adapter result with no matches/warning. | Unverified; executable and local signatures not available/verified in closure environment. |

The suite uses only controlled local fixtures, bounds direct scanner output to 1 MiB and execution
to 60 seconds, and disables Semgrep metrics. Trivy is invoked with DB/check updates skipped and
offline mode. Any test skip is not a pass. Keep the integration marked unverified until successful
test output from the target environment, tool versions, local asset availability, and the five
fixture outcomes are retained with that release candidate.

## Release-manager follow-up and release notes

The consolidated, unpublished release-note artifact is [release-notes-handover-2026-11-06.md](release-notes-handover-2026-11-06.md).

### Documentation and helper corrections

- `docs/ChiNeScan-improvements.md` and `docs/ChiNeScan-security-review.md` contained dated baseline
  statements that still described large-result retrieval and the R1 redaction issue as unresolved.
  They now label those observations as historical and link to the later closure/remediation status.
- `docs/API.md` now scopes the 10,000 finding/20 MiB rejection to `full-json` and documents JSONL
  streaming separately.
- `scripts/start-dashboard.ps1` now starts the backend using the project `uv` environment and
  rejects non-8765 backend ports because Vite's proxy target is fixed. Its missing-dependency hint
  now matches the documented `npm ci --no-audit` setup. Its supported path was smoke-tested in the
  isolated checkout as recorded below.

### Product release notes

- **Detection quality:** narrowed candidate rules for dynamic SQL, rate-limit handlers, response
  header configuration, cookies, public client configuration names, and JWT `alg=none`; ordinary
  text/comments and safer parameterized query patterns receive additional context handling. These
  remain source-pattern heuristics without full AST or cross-file data-flow analysis.
- **Evidence and classification:** versioned explanations separate observed matches from inferred
  behavior and list prerequisites, conditional impact, false-positive considerations, verification
  steps, and analysis limits. Static severity describes potential impact. A match is not proof of
  runtime behavior or exploitability.
- **Auditable scoring:** the legacy score arithmetic is retained as `legacy-pattern-v1` with a
  visible contribution ledger and redacted evidence. It is labeled Code pattern risk; it is not an
  AI-authorship determination. Historical scores without stored contributions remain unavailable.
- **Surface consistency:** representative persisted scan fields are contract-tested across CLI,
  authenticated API, complete reports, and the dashboard using a shared synthetic fixture.
  Report counts distinguish stored/available findings from grouped/returned issues and omissions.
- **Dashboard:** refreshed visual presentation preserves the existing workspaces, adds explicit
  ambient-motion controls, honors reduced-motion settings, displays legacy explanation state, and
  avoids rendering all scan finding links at once. The historical browser readiness timeout cause
  remains unresolved: the original trace and server timings are unavailable. Current readiness
  requests are independently bounded and report per-endpoint outcomes; this does not establish the
  cause of the earlier event.
- **R1 redaction:** repeated expensive regex work was replaced with a forward delimiter scan;
  imported text is clipped before redaction; documented operation bounds fail closed; CLI/API tests
  check synthetic canary non-disclosure on failure.
- **Large retrieval:** the grouped JSON preview reports omission reasons and counts. Existing
  `full-json` remains bounded at 10,000 findings and 20 MiB. The new JSONL stream retrieves large
  existing scans in bounded batches, redacts every record, and uses a final count/hash completion
  row. Existing package, command, database, and JSON full-export identifiers remain compatible.
- **Known limits:** optional external scanners remain unverified on this host; imported/external
  scanner coverage depends on those integrations and their local assets. Local single-operator use
  is the supported release profile; remote/multi-user operation, exhaustive browser/accessibility
  coverage, formal regex complexity proofs, and penetration testing are outside this handover.

## Fresh-environment validation status

An isolated copy was assembled from the current tracked and unignored implementation files without
copying `.env`, local databases, `.venv`, `node_modules`, or generated artifacts. In that copy:

- `uv sync --locked --extra dev` completed using CPython 3.12.10 and installed 74 packages.
- `npm ci --no-audit` completed and added 106 frontend packages.
- `npm run build` passed (29 Vite modules; generated JavaScript 353.23 kB, 99.09 kB gzip).
- `config init --path .\handover-config.toml` created a local config containing paths/log level
  only; `config validate --path .\handover-config.toml` passed.
- `uv run chinescan --database <temp-db> --reports-dir <temp-reports> code
  .\fixtures\sample-python-project --scanner builtin --format json --no-save-report` completed,
  persisted to a temporary SQLite file, and returned three controlled findings.
- `report --format detail`, bounded `full-json`, and JSONL commands all wrote output. The JSONL
  consumer check verified the manifest, three finding rows, final completion count, and digest.
- `web serve` started with an isolated temporary DB and credential/config paths on
  `127.0.0.1:18765`; `GET /api/health` returned `status: ok`, and the service was stopped.
- The corrected `scripts/start-dashboard.ps1` helper was copied into the isolated checkout.
  `-BackendPort 8766` exited before launching with its documented Vite-proxy constraint. With the
  supported backend port 8765 and a temporary frontend port 5178, the helper launched via `uv run`;
  both `http://127.0.0.1:8765/api/health` and the proxied
  `http://127.0.0.1:5178/api/health` returned `ok`. Only the helper-created process trees were
  stopped after the check.
- `npm run test:e2e` passed all 17 Playwright tests in 2.4 minutes from the isolated copy. The
  harness used generated local credentials, temporary databases, and controlled local fixtures.

This confirms fresh-copy dependency setup, build, CLI assessment/report retrieval, backend startup,
and browser workflows in the current host environment. It was not a clean machine or empty package
cache: `uv`, npm, and Playwright could use host caches. It does not prove offline setup,
cross-platform setup, or a production installation. The isolated copy and temporary data live
outside the repository.

### Remaining handover caveats

- The manual `uv run` plus `npm run dev` startup and the corrected optional helper were both
  validated in the isolated copy. The helper uses `uv run` and rejects a non-8765 backend port
  because the Vite proxy target is fixed at 8765. It uses separate local consoles; stop both
  processes when finished. A custom Vite frontend port was exercised successfully.
- The original cause of the historical readiness timeout remains unresolved because its trace and
  server-side timing evidence are unavailable. Current bounded readiness behavior passed the
  repeatability tests; that does not establish the old cause.
- The five optional integrations remain unverified. That is not a blocker for the built-in-only
  profile; it blocks any release claim that a particular external integration is verified.
- The implementation is still an uncommitted working-tree snapshot. No tag, package, or published
  release is represented by the base commit alone; the full snapshot manifest is required.
- Remote and multi-user operation remains unsupported.
