# ChiNeScan development status audit

Audit date: 2026-10-26
Repository: `C:\src\Chinescan`
Scope: initial read-only audit of the combined working tree, followed by local workflow
hardening and the authenticated dashboard Slice 1 implementation and verification on 2026-10-26.

Sections A–I preserve the initial baseline audit findings and recommendations. Sections J and O
record later changes that supersede the local-workflow and dashboard findings in that baseline.

## A. Executive summary

ChiNeScan is a **partially integrated local CLI application**, not yet the intended
self-hosted platform or a release candidate. It has exercised local vertical slices for
heuristic code assessment, SQLite persistence, reports and simple cases, exported-log
analysis, static file triage, trends, and an explicitly authorized low-impact domain
posture probe. The current test suite passes. External scanner execution and live domain
assessment were not exercised in this audit.

It can be used as a local analyst tool with important limits: built-in code rules are a
small heuristic set; log detection is a subset; domain checking is a few HTTP/TLS posture
checks rather than vulnerability scanning; and malware analysis is ephemeral metadata
triage rather than intake or quarantine. `scan`, malware memory, and detonation are
explicit exit-code-2 stubs. There is no API or dashboard. The repository instructions
prohibit a network listener, so that product area remains deferred until the instruction
changes.

The largest core gaps are the absent API/dashboard and access-control layer, limited
investigation workflows, external integrations verified only with mocked adapter tests,
no runtime migration/upgrade lifecycle, and resource bounds that need tightening in
untrusted archive and subprocess-output handling. CI configuration exists but was not
run by a remote CI service in this audit. Docker image rebuild was not attempted because
it may fetch from a registry; existing-image help was run offline.

The checkout was already substantially modified before this audit: `main` was one commit
behind `origin/main`, with tracked edits and numerous untracked Phase 2–8 modules, tests,
reports, and fixtures. Those changes were treated as user-owned and were not reset or
reverted. Findings below describe that combined worktree, not just committed code.

## B. Capability audit

| Area | Capability | Status | Evidence | Verification | Remaining work |
|---|---|---|---|---|---|
| Foundation | Installable package and CLI | VERIFIED WORKING | `pyproject.toml`; `chinescan/cli/app.py`; `chinescan/cli/commands.py` | Current `--help`, `version`, and full pytest suite passed | Keep CLI contracts and packaging checks in CI. |
| Foundation | Configuration and structured logging | PARTIAL | `chinescan/core/config/{settings,io}.py`; `chinescan/core/logging/{structured,redaction}.py` | Unit tests pass; config commands exercised by tests | Commands generally construct `Settings` from environment/defaults; no shared CLI config-file loading path. Log-level validation is a plain string. |
| Foundation | Canonical records and scanner/analyzer interfaces | PARTIAL | `chinescan/core/models/{common,finding,investigation}.py`; `chinescan/core/orchestration/protocols.py` | Model/schema tests pass | Records exist, but several are not used in workflows; `Analyzer` is an interface only. |
| Foundation | Orchestration, limits, timeout, cancellation | PARTIAL | `chinescan/core/orchestration/code_scan.py`; scanner adapters; `domain_assessment/probe.py` | Offline tests pass | Code scans isolate errors and cap workers; adapters have timeouts. No general cancellation API. External process output is not capped. |
| Foundation | SQLite persistence and migrations | PARTIAL | `chinescan/core/storage/sqlite.py`; `migrations/versions/0001_initial.py`; `tests/unit/test_migration.py` | SQLite and migration unit tests pass | Runtime repository calls `metadata.create_all`; no application migration/upgrade command or versioned upgrade lifecycle. |
| Foundation | Docker/Compose | IMPLEMENTED, NOT VERIFIED (build) | `docker/Dockerfile`; `docker-compose.yml` | Compose validation and existing local image `--help` passed | Rebuild was not run in this audit; CI's remote image build was not observed. Compose is a one-shot CLI runner, not a service. |
| Foundation | Docs, tests, lint, types, CI | PARTIAL | `docs/`; `tests/`; `.github/workflows/ci.yml`; `.gitlab-ci.yml` | 70 tests, Ruff, format, strict mypy, pip-audit, lock check passed locally | Remote CI not run. Documentation describes manual operations; automated health/readiness is absent. |
| Code | Project/language detection and local default | VERIFIED WORKING (limited) | `core/orchestration/code_scan.py:detect_project`, `BuiltinRuleScanner` | Fixture tests and full suite passed | Only selected extensions/manifests and four simple patterns; this is not full language/security coverage. |
| Code | Semgrep, Gitleaks, Trivy | IMPLEMENTED, NOT VERIFIED | `chinescan/scanners/external.py:SemgrepScanner`, `GitleaksScanner`, `TrivyScanner` | Adapter output/error tests are mocked; no real adapter binary run in this audit | Validate tool versions, actual JSON compatibility, and network behavior in isolated integration jobs. Semgrep requires local rules; Trivy uses local cache. |
| Code | Python/Node dependency audits | IMPLEMENTED, NOT VERIFIED (target workflow) | `external.py:PipAuditScanner`, `NpmAuditScanner`; `commands.py:code_scan` | Consent/adapter tests pass; pip-audit here audited the installed project dependency environment, not a target fixture | Verify real target-manifest flows. Explicit consent sends dependency metadata to advisory services. |
| Code | Normalization, severity, dedup, persistence | VERIFIED WORKING | `core/orchestration/code_scan.py:make_finding`, `deduplicate_findings`, `CodeScanService` | Fixture and repository tests pass | Improve heuristic coverage and add tested external-tool integration. |
| Domain | Explicit authorization and scope record | VERIFIED WORKING (offline) | `domain_assessment/authorization.py`; `domain_assessment/service.py`; `AuthorizationRecord` | Tests validate exact host, profile, grant window, no-probe rejection, and persist-before-probe | Ownership assertion is operator-supplied; process remains a local CLI trust boundary. |
| Domain | Built-in HTTP/TLS posture probe | IMPLEMENTED, NOT VERIFIED live | `domain_assessment/probe.py:NetworkDomainProbe` | Mocked probe tests cover address filtering, request counts and bounded headers; no live host contacted | No live verification in this audit. Narrowly checks headers/certificate; no ports, subdomains, testssl, or vulnerability templates. |
| Domain | subfinder/dnsx/httpx/nmap/testssl/Nuclei | MISSING | No such adapters found; `docs/reports/phase-6-report.md` records broader adapters deferred | Not applicable | Add only after scope and traffic policy review. |
| Logs | File/directory and archive ingestion | PARTIAL | `log_analysis/ingest.py:ingest_path`, `_ingest_zip`, `_ingest_tar` | Fixtures and traversal-safe no-extraction tests pass | Global decompression budget is checked after each member has already been decompressed; tighten it before hostile inputs. |
| Logs | JSON/JSONL/CSV, common OS/web logs, CEF/LEEF | VERIFIED WORKING (supported subset) | `log_analysis/parsers.py:parse_log_data` and format parsers | Fixture tests pass; sample fixture CLI result documented in Phase 4 report | Windows/cloud inputs are exported records, not native collectors; unsupported formats need explicit diagnostics. |
| Logs | Normalized events, timeline, Sigma, IOC, alerts | PARTIAL | `log_analysis/{normalization,detections,ioc_matching,service}.py` | Unit tests cover sample parsing, correlations, limits, persistence | Sigma evaluator supports a constrained subset; mappings/rules are small heuristic candidates, not comprehensive detections. |
| Malware | Safe intake/quarantine/access/audit | MISSING | No intake/storage module; `docs/reports/phase-5-report.md` | Not applicable | Do not claim samples are quarantined or access-controlled. |
| Malware | Hashing, type, strings count, metadata, IOC extraction | VERIFIED WORKING (ephemeral) | `malware_analysis/analyzer.py:analyze_file` | Synthetic file tests pass; no sample execution | Limited signature/metadata heuristics; results are not persisted. |
| Malware | YARA/ClamAV | IMPLEMENTED, NOT VERIFIED with real binaries | `malware_analysis/engines.py:run_yara`, `run_clamav` | Mocked binary/output/timeout tests pass | Install/configure engines separately and verify controlled fixtures in an isolated environment. |
| Malware | PE/ELF/Office/PDF/archive parser-grade triage | PARTIAL | `analyzer.py:_identify`, ZIP listing | Synthetic PE/ELF and ZIP tests pass | Signatures and markers are shallow; no rich parsers, recursive archive scanning, or memory analysis. |
| Malware | Volatility/sandbox/external enrichment | DEFERRED / OPTIONAL | `cli/app.py` memory/detonate stubs; Phase 5 report | Stub exit codes verified in existing tests | Still explicit stubs; no sample execution, upload, or enrichment. |
| Reports | JSON/Markdown/HTML/CSV/SARIF and redaction | VERIFIED WORKING for scan findings | `core/reporting.py:render_report` | Rendering, HTML escape, CSV formula handling, and redaction tests pass | Report covers scans/findings, not complete cross-source cases/timelines/evidence. |
| Investigations | Scan history and comparison | VERIFIED WORKING (basic) | `commands.py:compare_scans`, `core/trends.py` | CLI/service tests and `trends` smoke passed | Comparison is fingerprint-set comparison; trends count stored records only. |
| Investigations | Cases, notes, evidence, cross-source correlation | PARTIAL | `commands.py:case_create/show/update`; `Case` model | Case create/show/status and scan comparison tests pass | No analyst notes, evidence links, case event/alert/artifact relationships, or cross-source case correlation. |
| API/UI | Backend API, contracts, dashboard, auth/session/CSRF | MISSING / DEFERRED by repository policy | No API/frontend files; `docs/plans/phase-7.md` | Not run | A network listener is prohibited by `AGENTS.md`; policy change is a prerequisite. |
| Operations | CI thresholds and dependency management | PARTIAL | `.github/workflows/ci.yml`; `pyproject.toml`; `uv.lock` | Lock and dependency audit passed locally | CI only executes after a remote event; not verified here. |
| Operations | Health/readiness, automated backup/retention/upgrade | MISSING (manual guidance exists) | `docs/DEPLOYMENT.md`; `SQLiteRepository`; migration files | Docs inspected; no runtime checks exist | Add migration lifecycle, health checks, retention controls and tested backup/restore automation. |

## C. Completed work

### Verified in this audit

- Python 3.12.10 CLI help/version and the documented Phase 3 `scan` exit-code-2 stub.
- Full fixture/unit suite: 70 passed, 82.27% package coverage.
- Ruff lint and formatting, strict mypy, locked dependency resolution, pip-audit,
  schema JSON parsing, and Docker Compose configuration.
- Existing local image's `--help` command with `--network none`.
- The tests exercise SQLite repository behavior and initial Alembic migration, code
  normalization/deduplication, reports and cases, log ingestion/correlation, static
  malware triage, and mocked domain probe safety.

### Substantial implementation present, but live/external execution not verified

- External code scanner adapters and optional YARA/ClamAV process wrappers.
- Built-in domain DNS/HTTP/TLS probe. Tests mock network calls; this audit intentionally
  contacted no production or external target.
- Python/Node advisory integrations. Explicit consent is required because metadata leaves
  the local machine.

## D. Partial, mocked, and disconnected work

- **API and dashboard:** the workflow stops at the CLI. No backend routes, OpenAPI
  contract, frontend, authentication, session, pagination, or evidence access controls
  exist. The Phase 7 plan explicitly pauses this work because the repository prohibits a
  listener.
- **Code scanning:** the built-in scanner is a few line-based heuristics. External adapters
  launch and parse tools, but tests replace executable discovery/process results; successful
  real Semgrep/Gitleaks/Trivy runs are not established by this audit. Advisory scanners
  require explicit consent and contact upstream services.
- **Domain scanning:** authorization and persistence lead to one small built-in posture
  probe. The original named scanners and broad domain assessment workflow are absent.
  Live DNS/TLS/HTTP behavior was not verified.
- **Log analysis:** fixture inputs pass through parsing, normalization, detections, IOC
  matching, event/alert/timeline persistence. The detection set and Sigma semantics are
  intentionally constrained; this is not broad enterprise log coverage. Decompression
  limits need a global budget applied before each read.
- **Malware:** the static analyzer reads a user-selected file in memory and returns
  metadata. It does not create a quarantine, retain sample bytes, or persist results.
  YARA/ClamAV result tests are mocked; actual engine binaries were not verified.
- **Cases/reports:** report formats operate on stored scan findings. Cases attach scan and
  finding IDs and allow status changes; they do not implement notes, evidence handling, or
  cross-source investigation.
- **Persistence:** repository startup creates tables directly. Although an initial Alembic
  migration exists and is tested, there is no normal application migration or upgrade
  command.
- **Docs versus implementation:** current README and roadmap are comparatively clear about
  the lack of a web service, broad scanners and malware intake. Earlier phase reports record
  historical results; this audit's fresh results are appended to the Phase 1 report.

## E. Missing work by area

- **Foundation:** config-file consumption across commands; constrained configuration
  values; general cancellation; runtime Alembic upgrade lifecycle; stronger storage
  lifecycle and error behavior.
- **Code scanning:** broad language-aware analysis; validated live integrations; output
  bounds around third-party process capture; richer finding evidence/remediation and
  target-manifest integration checks.
- **Domain scanning:** the named recon/TLS/vulnerability scanner integrations, beyond the
  current narrow posture probe.
- **Log analysis:** broad vendor coverage and complete Sigma semantics; a pre-decompression
  global expansion budget; broader correlation quality.
- **Malware analysis:** intake/quarantine, controlled retention and access/audit; parser-grade
  document/binary analysis; memory and optional isolated sandbox integrations.
- **Reporting/cases:** notes, evidence references, richer export of events/alerts/timelines,
  and traceable cross-source correlation.
- **API/dashboard:** all backend/frontend features, authentication and access control;
  blocked by the no-listener repository rule until it changes.
- **Testing/deployment:** real external adapter integration validation; remote CI evidence;
  health/readiness, runtime migrations, automated backup/restore/retention and deployment
  lifecycle.

## F. Security and reliability gaps

Confirmed from code:

- `log_analysis/ingest.py` limits each archive and checks `MAX_TOTAL_BYTES` in
  `_parse_member`, but archive members are fully read/decompressed before that aggregate
  check. Multiple compressed inputs can therefore consume substantially more decompression
  work than the nominal global expanded-byte limit suggests. Treat this as a resource-limit
  defect for untrusted log bundles.
- `scanners/external.py:_JsonTool._run` uses `subprocess.run(capture_output=True)` with a
  timeout but no stdout/stderr size cap. A noisy or malfunctioning scanner can use
  unbounded memory before timeout. In contrast, `malware_analysis/engines.py` has an
  explicit merged output cap.
- There is no authentication or evidence access control because there is no API; the local
  CLI and database rely on operating-system account boundaries. The database is not
  encrypted, as `docs/DEPLOYMENT.md` states.
- Existing Trivy report records in `docs/reports/security-review.md` include high OS
  findings without available fixes and a review date. They are recorded as accepted in
  that worktree report, not independently rescanned in this audit.

Not established as defects by this audit:

- No live target was contacted, so real DNS/TLS/network behavior remains unverified.
- No sample was executed. Malware static tests use synthetic fixtures only.
- No confirmed credential leak or authorization bypass was found in the inspected paths;
  offline tests cover redaction and exact-host authorization. These tests do not substitute
  for a broader security review.
- Docker image rebuild and remote CI/container scans were not run now; historical phase
  reports should not be read as fresh results for this audit.

## G. Prioritized remaining backlog

| Priority | Required change | Relevant files | Dependencies | Acceptance criteria | Size |
|---|---|---|---|---|---|
| P0 blocker | Enforce a global decompressed-byte budget before reading each archive member; abort/skip further expansion deterministically. | `chinescan/log_analysis/ingest.py`; `tests/unit/test_log_analysis.py` | None | Adversarial multi-member/multi-archive fixtures never read beyond configured aggregate expanded bytes; ordinary fixture behavior remains intact. | Medium |
| P1 core | Bound stdout/stderr for external scanner processes while preserving timeout, exit-code and JSON diagnostics. | `chinescan/scanners/external.py`; `tests/unit/test_external_scanners.py` | Windows/POSIX process behavior | Oversized output is terminated or drained safely, returns a bounded diagnostic, and cannot grow captured memory without limit. | Medium |
| P1 core | Define and implement a runtime migration/upgrade path instead of relying on `create_all`. | `chinescan/core/storage/sqlite.py`; `migrations/`; `chinescan/cli/commands.py`; docs | Migration compatibility policy | Fresh and prior-version databases upgrade explicitly; normal CLI startup does not silently bypass migration state. | Medium |
| P1 core | Wire configuration file loading into supported commands and constrain/validate settings. | `chinescan/core/config/{settings,io}.py`; `chinescan/cli/commands.py`; tests | Decide config path precedence | CLI behavior follows documented file/env precedence; invalid settings fail before opening storage; secrets are never serialized. | Medium |
| P1 core | Complete the local investigation vertical slice with event/alert/timeline/artifact links and analyst notes. | `core/models/investigation.py`; `core/reporting.py`; `cli/commands.py`; tests | Schema evolution/migrations | Create/update/show a case with notes and linked evidence; report export includes selected linked records with redaction and traceable IDs. | Large |
| P1 core, policy-blocked | Build API/dashboard only after repository policy explicitly allows a listener and scope is approved. | Future API/frontend packages; `docs/plans/phase-7.md` | Change `AGENTS.md` policy; auth/session/CSRF design | Authenticated loopback service, permission checks, API contract tests, secure evidence access, and default no-service startup. | Large |
| P2 improvement | Run pinned external scanner binaries against local synthetic fixtures in isolated CI and document versions/results. | `tests/unit/test_external_scanners.py`; CI workflow; docs | Approved tools and CI network/cache policy | Each supported adapter has a real-binary fixture job and normalized expected results; no public target scanned. | Large |
| P2 improvement | Expand parser and detection conformance for supported Windows/cloud/Sigma sources. | `log_analysis/parsers.py`; `detections.py`; fixtures/tests | Representative sanitized fixtures | Documented formats/rule subset pass fixture conformance and malformed inputs remain bounded. | Large |
| P2 improvement | Add health/readiness, backup/restore validation, retention and upgrade procedures. | `core/storage`; `docs/DEPLOYMENT.md`; CI | Local service decision and data policy | Repeatable backup integrity/restore test, migration test, documented retention behavior; no listener by default. | Large |
| P3 optional | Add Volatility, isolated sandbox, richer document/binary parsers and optional enrichment. | `malware_analysis/`; docs | Explicit opt-in, isolation and data-transfer policy | Optional tools disabled by default, isolated and bounded, with no sample upload absent consent. | Large |
| P3 optional | Add broad recon and vulnerability scanner integrations. | `domain_assessment/`; `scanners/`; docs | Explicit authorization model and traffic review | Scope, rate, timeout, cancellation and failure-isolation tests; integration fixtures remain offline. | Large |

## H. Recommended next development stage

**Local workflow hardening** is the recommended next stage. It can improve the working
CLI without violating the current no-listener rule: first make archive expansion and
external subprocess output genuinely bounded, then make CLI configuration and migration
behavior explicit, and extend the case/report workflow only after persistence evolution is
defined. This fixes concrete reliability risks and closes existing local workflows before
adding additional disconnected adapters.

Exclude API/dashboard work until `AGENTS.md` changes. Exclude malware intake, sandboxing,
and wider network scanners from this stage. Verify with Python 3.12 tests that include
adversarial resource fixtures, Ruff, strict mypy, dependency audit, migration tests, local
fixture CLI smoke tests, and a documentation update. Any Docker rebuild should be a
separately authorized check when registry access is required.

## I. Ready-to-paste implementation prompt

> In `C:\src\Chinescan`, implement the next **local workflow hardening** slice. Keep all
> work scoped to this repository and preserve existing uncommitted changes. Do not commit
> or push. Do not add a network listener, API, dashboard, public-target scan, malware
> execution, sample upload, or external enrichment. Require Python 3.12+ and use
> `py -3.12` for checks. Do not install dependencies or pull/build containers unless
> separately authorized.
>
> 1. Fix archive expansion accounting in `chinescan/log_analysis/ingest.py`: enforce one
>    aggregate decompressed-byte budget before reading/decompressing each member across
>    the full ingestion job, not after the member has already been materialized. Keep
>    archives read-only and never extract paths. Add adversarial tests in
>    `tests/unit/test_log_analysis.py` for multiple compressed members/files and assert
>    no work beyond the cap while valid fixtures continue to pass.
> 2. Bound external scanner process output in `chinescan/scanners/external.py` while
>    retaining `shell=False`, the environment allowlist, and the configured timeout.
>    Add tests in `tests/unit/test_external_scanners.py` for oversized output, timeout,
>    invalid JSON, and successful normalized output. Ensure child processes are terminated
>    and pipes drained/closed on all paths.
> 3. Inspect `chinescan/core/config/{settings,io}.py` and `chinescan/cli/commands.py`.
>    Either wire config-file settings into supported commands with documented precedence
>    or clearly constrain the CLI to environment/default configuration; validate values
>    such as log level before storage is opened. Never serialize secret values.
> 4. Inspect the `metadata.create_all` startup in `chinescan/core/storage/sqlite.py` and
>    `migrations/`. Propose and implement a minimal explicit migration/upgrade path only
>    if it preserves existing SQLite data; otherwise document the exact safe boundary and
>    add an acceptance test that detects schema drift.
>
> Run the safe Python 3.12 checks available in the repository: unit suite/coverage, Ruff
> lint/format, strict mypy, pip-audit, lock check, schema validation, and Compose
> validation. Do not rebuild an image if it would fetch from a registry. Update the
> relevant report with exact command, exit code, and result. Report any unavailable tool
> or environment constraint rather than claiming verification.

## J. Local workflow hardening stage — 2026-10-26

The original findings were rechecked against the combined worktree before edits. The log
ingestor still checked aggregate expanded bytes only after decompression; scanner wrappers
still used unbounded `capture_output=True`; commands still constructed settings without
reading TOML; and SQLite initialization still used `metadata.create_all` despite one
Alembic revision (`0001_initial`).

The hardening update streams every supported input through a bounded read, shares the
expanded-byte budget across the ingestion job, and stops processing once that budget is
reached without reading a sentinel byte past the cap. A member that exhausts the remaining
budget is discarded; earlier events remain and later inputs are skipped. ZIP and tar paths
remain virtual names and are never extracted. External scanner
stdout and stderr now drain concurrently into fixed-size buffers; exceeding either cap
kills the direct child, timeout and cancellation kill it and close both pipes, and existing
nonzero/invalid-JSON semantics remain errors. Configuration precedence is explicit CLI
options, environment, TOML, then defaults; log levels are constrained and settings errors
avoid echoing invalid values. Fresh SQLite files run Alembic to head; an unversioned
database is stamped at `0001_initial` only when its records schema exactly matches that
revision; incompatible schemas fail without table recreation. Existing record payloads are
retained in the legacy upgrade test.

Fresh focused and repository-wide results, exact commands, and limitations are recorded in
the appended hardening section of `docs/reports/phase-1-report.md`. The next recommended
stage is case/report workflow completion after further schema evolution is expressed as
explicit Alembic revisions. This stage adds no API, dashboard, listener, malware intake,
scanner integration, or public-target activity.



## K. Local investigation workflow — 2026-10-26

The case workflow was checked against the current working tree before implementing this stage. The
existing `Case` model had no typed record links, notes, severity, or activity history; persisted
records already included scans, findings, alerts, events, and timeline entries. Artifacts were only
model types and were not stored. The generic record repository stores payloads in SQLite JSON, and the
initial schema migration had no case-specific tables. The audit therefore uses JSON payload evolution
rather than inventing a relational migration or claiming foreign-key enforcement.

Cases now support severity, open/in-progress/resolved/closed transitions, typed persisted-record links,
append-only local notes, and activity entries. CLI commands provide create-from-scan, show, update,
link, note add/list, timeline, and report export. Reports have JSON, Markdown, and self-contained HTML
formats; dynamic HTML is escaped, secrets are redacted, and selected direct identifiers are masked.
Report buckets retain their structure during redaction. Existing scan/SARIF renderers were not changed.
Timeline entries keep source occurrence and case-activity times distinct; ingestion is explicitly null
because the store has no ingestion timestamp. Missing legacy references are retained and reported.
Artifact links are rejected. Finding reports state that structured remediation guidance is unavailable.
Case notes and activities are saved atomically within one case payload; note ownership is validated.

Migration `0002_case_workflow` records backward-compatible payload evolution without table changes or
payload rewrites. Review found the legacy-schema initialization path stamped a compatible old database
at revision 0001 but did not proceed to head; this was fixed and regression-tested. Fresh DBs migrate to
head, the exact known legacy records schema is stamped then upgraded with its payload retained, and
incompatible schemas are rejected unchanged. This is safe for the current generic JSON storage shape but
provides no SQL-level link constraints.

The acceptance commands and exact results for this stage are recorded in the **Local investigation
workflow verification** section of `docs/reports/phase-1-report.md`: 93 tests pass at 82.78% coverage;
Ruff, strict mypy, dependency audit, Bandit medium threshold, lock check, Compose validation, schema JSON
parsing, and local CLI/config smoke commands pass. Docker image build was not run because it can fetch
images and was not authorized. The worktree remains uncommitted. No production readiness is claimed.

Remaining known limits are no persisted artifact bytes/records, no ingestion timestamps, no structured
finding remediation field, unauthenticated author labels, and no SQL foreign keys for JSON links. The
recommended next stage is local data retention and recovery: backup/restore validation on database
copies and a documented handling policy for sensitive case exports.


## L. Local data protection and recovery — 2026-10-26

Current-code inspection confirmed that SQLite repository startup migrates to Alembic head, cases
embed their notes and activities in JSON payloads, and case links have no SQL foreign keys. The
existing deployment report provided only an operator-written SQLite online-backup example. There
was no backup bundle format, verifier, new-path restore operation, or backup retention planner.
Case export staged content but used `os.replace`, which could silently overwrite an existing report.

Added `core/storage/recovery.py`: read-only source opening; SQLite online backup; bounded time, retry,
and cancellation handling; staged database-plus-manifest bundle; restricted mode requests; SHA-256,
integrity, foreign-key, supported-schema, and application-record verification; new-path staged restore;
and a manifest-validated preview-only age/count retention planner. The manifest contains no paths or
record contents and has a format version, UTC timestamp, application version, revision, size, checksum,
and verification summary. Hashes are documented as mismatch detection, not authentication. Unknown
schemas, corruption, inconsistent case and scanner relationships, and malformed payloads are reported
without repair or deletion. Supported old schemas are read-only verified; only a restored staging copy
is migrated. No database migration or record schema change was required.

Added `db backup`, `db verify-backup`, `db restore`, and `db retention-plan` CLI commands. Restore
rejects existing destinations, active database aliases, and stale WAL/SHM sidecars. Retention only
labels entries as retained/remove/skipped; it never deletes. Case exports now reject existing output
files and publish staged content without overwrite, requesting restrictive mode bits. Operator docs
cover Windows ACL limits, lack of encryption, backup/report sensitivity, non-anonymizing redaction,
manual cutover, and preview-only retention.

Verification details and exact commands are recorded under **Local data protection and recovery
verification** in `docs/reports/phase-1-report.md`: 104 tests passed with 81.85% total coverage; Ruff,
strict mypy, Bandit medium threshold, lock consistency, Compose, schema JSON parsing, CLI smoke, and
`git diff --check` passed. The recovery drill retained case IDs, links, notes, statuses, and activity
through backup/restore and generated all three report formats. Dependency audit was not run because
it would make an external advisory request without approval; the image build was not run because it
may fetch a base image. No commit or push was made.

Remaining risks: database and reports are unencrypted; checksums do not authenticate; Windows mode
bits do not enforce ACLs; relational links are not constrained by SQLite; export publication requires
same-directory hard-link support; retention is preview only; no automatic active-database cutover
exists. The recommended next stage is an operator-controlled cutover and rollback drill against a
restored copy. This implementation and local test results do not establish production readiness.


## M. Recovery acceptance and operator cutover drill — 2026-10-26

Rechecked the recovery bundle service, explicit `--database` option, CLI repository lifecycle,
migrations, case workflow, report publication, and existing tests. The supported restore path writes
to a new destination and applies supported migrations only to that staged copy. Case CLI commands
dispose their repository after each invocation. A missing database supplied to ordinary case
commands can be initialized by repository startup, so the new drill refuses to invoke a case command
unless its selected database is already a regular file.

Added `scripts/recovery_acceptance.py`, an offline synthetic drill using only the checked-in sample
logs. It prepares an original database, linked case, note, and status activity; uses CLI backup,
verification, restore, case show/note/timeline/export commands with explicit database paths; checks
all three report formats; writes a unique note only to the restored database; and selects the original
again. It compares the original database hash before and after and checks that the divergent note
stays only in the restored copy. Temporary drill data is removed at process exit. No configuration
file is rewritten and no existing database is replaced.

Added regressions for the full cutover and rollback, missing-selection refusal without accidental
database creation, failed verification blocking restore while preserving the original, and failed
report publication cleaning temporary output. Existing recovery tests also cover unsupported schema,
new-path refusal, old supported migration, original/restored distinction, and preservation of backup
bundles. Windows permission-denied destination behavior was not asserted because ACL-denial behavior
is environment and privilege dependent; current mode-bit requests do not prove ACL protection.

Exact commands and results are captured in the **Recovery acceptance and operator cutover drill**
section of `docs/reports/phase-1-report.md`. The acceptance verdict is **PASS for the bounded local
synthetic drill**: fixture records and case data survived backup/restore, explicit CLI selection
worked, exports were generated, and rollback by selection left divergent writes unmerged. This is
not a claim about unrelated OS processes, real operational cutover, backup authenticity, or production
readiness. The next recommended stage is controlled real scanner integration verification using
authorized local fixtures and isolated helper processes.


## N. Controlled real scanner integration verification — 2026-10-26

Inspected the existing Semgrep, Gitleaks, Trivy, YARA, and ClamAV adapters, settings/CLI selection,
normalization, persistence, reports, unit tests, dependencies, and CI. All five scanner executables
are absent from this Windows host's `PATH`. The standard local Trivy cache and ClamAV signature
locations checked were absent. CI declares Gitleaks `v8.30.1` and Trivy `v0.76.1`, but these do not
prove local installation or runtime compatibility. Existing adapter parser coverage uses mocked
subprocess output; no real scanner integration evidence existed.

Added local-only positive/negative fixtures where feasible and a `real_scanner` pytest group. These
tests are deselected from the default suite and run only with `--run-real-scanners` or
`--require-real-scanners`. Ordinary explicit selection skips a missing binary/database with a
specific reason. Strict mode fails on missing expected tools/assets, preventing an all-skipped
integration run from passing. Direct execution is bounded by a timeout/output cap and uses
`shell=False`, an allowlisted environment, local rule paths, and tool-level offline/telemetry flags.
The host did not enforce network isolation, and no claim that network access was blocked is made.

No real-tool execution occurred, so no adapter compatibility fix is justified. The detailed inventory,
readiness matrix, fixture inventory, actual selected/strict test results, and proposed pinned CI
provisioning/offline job design are in `docs/reports/real-scanner-integration-verification.md`.
ClamAV positive testing remains omitted because no approved signature/test fixture was present;
Trivy vulnerability scanning remains unavailable without a local DB. Proposed CI provisioning is not
activated and versions for Semgrep/YARA/ClamAV still require explicit approval and pin selection.

The milestone verdict is **BLOCKED for real-binary verification; test harness and fixtures prepared**.
The next action requires approval to provision specified scanner binaries and (for Trivy/ClamAV)
their local databases/signatures, and to select versions for the tools not pinned in current CI. Once
approved assets are available, run the strict integration group on an egress-isolated worker.


## O. Authenticated local dashboard Slice 1 — 2026-10-26

The owner approved FastAPI, Uvicorn, Argon2, React, TypeScript, Vite, and the minimal component/API
test dependencies for Slice 1. They were installed in the existing `.venv` and `frontend/node_modules`
using `uv` and npm. `uv.lock` and `frontend/package-lock.json` capture exact dependency resolutions;
a baseline comparison found no changes to versions of packages already in `uv.lock`.

Implemented `chinescan web bootstrap` and `chinescan web serve`. Bootstrap creates one operator
account with a no-echo password prompt and Argon2id hash, rejects overwrite, and refuses credential
paths inside Git repositories. Serving is explicit, fixed to `127.0.0.1`, single-worker, with proxy
headers and access logging disabled. Sessions are opaque, HttpOnly, SameSite=Strict, expire in 30
minutes, and are process-local; logout revokes and process restart invalidates them. State-changing
requests require same-origin validation and CSRF. Login attempts are throttled. Responses include
security headers and API no-store caching.

The React dashboard serves real overview, paginated scan, and paginated finding data. FastAPI uses
declared Pydantic request/response schemas. The SQLite read APIs enforce bounds and sort/filter
allowlists; severity sorting uses the analyst-facing critical-to-info order. Finding responses use
an explicit allowlist with shared text redaction; raw payloads and target filesystem paths are not
returned. No CORS middleware, arbitrary path endpoint, file access, background job, assessment
action, case/report route, malware intake, public binding, or remote deployment setting was added.
Production static serving and the Vite loopback development proxy use `/api`. Setup, API, and
security boundaries are described in `README.md`, `docs/DEVELOPMENT.md`, `docs/API.md`,
`docs/ARCHITECTURE.md`, and `docs/plans/phase-7.md`.

Verification: `115 passed, 5 deselected`, coverage `83.05%`; Ruff and formatting checks passed;
strict mypy passed for 46 files; `uv lock --check` resolved 76 packages; frontend typecheck passed,
2 component tests passed, and the Vite production build succeeded. A live loopback HTTP harness
confirmed static serving, auth denial, sign-in, empty stored overview, and logout revocation.
Browser-level testing was not performed and no browser binaries were downloaded. `pip-audit` was not
run because it requires an external advisory query outside the owner's package-download approval.

## P. Authenticated case and report dashboard — 2026-10-26

Slice 2 exposes the existing `CaseWorkflow` through the authenticated same-origin API and React
interface. It adds bounded case listing and filters, creation from persisted scans, case detail,
workflow-governed status changes, idempotent supported-record linking, append-only notes, and a
chronological combined activity/source timeline. The API does not accept author identity labels;
legacy author labels remain marked unverified. Case detail returns reviewed linked-record summaries
with redaction rather than raw persistence payloads.

Case JSON/Markdown/HTML reports call the existing redacted report renderer. Existing scan JSON,
Markdown, HTML, CSV, and SARIF formats are downloadable. Downloads use server-generated names,
validated IDs and format allowlists, resource limits, and `Content-Disposition: attachment` (including
HTML). No output filesystem paths are accepted. These additions add no jobs, uploads, external
services, or public listener configuration. Exact checks and the browser result are recorded in the
Slice 2 section of `docs/reports/phase-1-report.md`.

## Q. Browser acceptance for dashboard Slices 1 and 2 — 2026-10-26

Added repeatable Playwright Chromium coverage against the production Vite build served by the
authenticated Python app. The harness seeds synthetic SQLite records and randomly generated
operator credentials in unique temporary directories, binds services to ephemeral loopback ports,
and cleans processes and files after each run. It performs no external assessments or uploads.

The browser suite covers protected-data denial, successful and failed sign-in, fixture-backed
overview/scan/finding list and detail views, case creation from a scan, browser form validation,
case not-found errors, persisted notes and status, idempotent event linking, timeline activities,
redacted JSON/Markdown/HTML downloads, HTML attachment disposition, text-only HTML-like evidence,
keyboard navigation, a 390-pixel viewport, logout, stale-session API denial, and session expiry
during a protected action. The suite checks the exact expected 401/404 responses and records no
unexpected application API failures or JavaScript console errors.

Verification passed: Playwright `3 passed`; Python `116 passed, 5 deselected`, coverage `83.28%`;
Ruff lint and format, strict mypy, Python lock check, frontend typecheck, 5 component tests, production
build, and `git diff --check` passed. The five deselected Python tests are marked `real_scanner` and
require external scanner binaries; no external scanner was run. Details and exact command results
are in `docs/reports/phase-1-report.md`.

The browser run demonstrated one frontend defect: login 401 responses were converted to a
message-less `UnauthorizedError`, leaving invalid credentials without visible feedback. The API
client now preserves the login endpoint's safe error detail for the form while retaining the existing
unauthorized-session handling for protected requests. Browser regression coverage verifies the
visible invalid-credential error. No other product defects were demonstrated.

## R. Dashboard Slice 3A — local code-assessment jobs — 2026-10-26

The dashboard now starts jobs for operator-configured local projects. A TOML registry supplies a
stable project ID, display name, and explicit root; the browser receives only the ID/name pair. The
server validates configured roots against protected database, credential, and registry paths and
revalidates before execution. A one-thread worker processes one job at a time with four queued slots.
Jobs persist `queued`, `running`, `succeeded`, `failed`, or restart-reconciled `interrupted` states
and link a scan only after `CodeScanService` returns persisted result records. The dashboard polls
active jobs every two seconds, links persisted findings, and routes case creation through the
existing `CaseWorkflow`.

The API uses the existing session, loopback, origin, and CSRF controls. Requests accept only an
allowlisted project ID; optional scanners, arguments, commands, environment variables, config paths,
and network-backed dependency checks are unavailable. The worker uses built-in checks only. The
scanner reads source without execution and enforces its existing count and byte bounds. Error text is
fixed/sanitized for non-configuration failures; source and raw logs are not exposed to the browser.

Validation rejects symbolic links and Windows junctions found in configured roots or the project
tree, and the scanner does not recurse into linked directories or open symlink files. Protected
application database storage and the operator credential/registry files are excluded. Path checks
cannot prevent an entry from changing between validation and open, so this is not an OS sandbox.
Built-in synchronous scanning cannot be safely killed at a deadline; no cancellation or fake timeout
is presented. Graceful shutdown waits for active work; process loss marks persisted unfinished jobs
interrupted at the next startup without claiming an external process was killed. Existing scan
records are saved by separate repository operations, so a persistence error can leave partial records
without a job scan link.

Verification: Python `123 passed, 5 deselected`, coverage `83.59%`; Ruff lint and format, strict
mypy, frontend typecheck, 7 component tests, production build, final Playwright `4 passed` in `2.3m`, Python lock
consistency, and `git diff --check` passed. The five deselected tests require optional external
scanner executables. No dependencies were installed, scanner assets downloaded, external services
contacted, or live targets used. Exact commands and outputs are in the Slice 3A section of
`docs/reports/phase-1-report.md`. A later browser retry had one pre-existing expiry-fixture failure
because its 15-second session elapsed before Overview loaded on this slow host; an isolated retry
could not start its local fixture within 60 seconds. The successful complete run still covered the
new job workflow.

Recommended next stage: define a cancellable/resource-limited worker process boundary and atomic
publication of scan results before extending dashboard job types.

## S. Dashboard Slice 3A stabilization — 2026-10-26

The earlier expiry failure was a test-isolation/timing problem: the only 15-second session existed
for the dedicated expiry spec, but that short-lived fixture was started with normal acceptance and
the expiry flow had to finish the Overview transition before beginning its protected action. The
server itself continues to expire the session and return 401. The fixture keeps the standard suite
on an 1,800-second session and the expiry test on a separate server with a genuine 15-second TTL;
the expiry test now synchronizes on the protected request and server-observed 401 rather than a
fixed delay. Retries remain disabled. Three consecutive full browser runs passed.

The previous server startup timeout had no stderr because startup diagnostics were unbounded only
in memory and the harness timed out before emitting them. The cause of that historical instance
cannot be determined from the captured evidence; it is not classified as a host defect. The fixture
now bounds stdout/stderr to the last 4,000 characters, reports early process exit and timeout
context, verifies the `py -3.12` process running from the repository root against an actual HTTP
401 readiness response, uses an OS-assigned loopback port handed to Uvicorn, and terminates only
its own process tree (including the Windows Python launcher tree). Partial startup failures clean up
the owned process and temporary data. No production bypass route was added.

During final stabilization, one startup reproduction printed its loopback URL just after the former
60-second announcement bound, with empty stderr. The bounded announcement window is now 120 seconds;
HTTP readiness remains a separate 10-second observable check. A separate production browser test
snapshot showed the login form still in its `Signing in…` state when the test asserted dashboard
content. That test now waits for the successful login response and visible Overview heading before
asserting stored records. Neither change alters session expiry or authentication behavior.

Project protection now excludes the entire active SQLite parent directory (therefore the main DB
and SQLite sidecars), credential file, and registry automatically. Existing operator
`protected_paths` remains supported. Project roots and entries are resolved and checked for links or
junctions where supported, overlap is rejected in either direction, and validation runs at listing,
submission, and immediately before worker execution. No managed backup/export directory exists in
this dashboard configuration; reports are generated in memory. The filesystem TOCTOU race remains,
and validation is not sandbox isolation.

The existing 1 MB per source, 20,000 source-file, and 250 MB aggregate source bounds remain. A
candidate source above 1 MB previously disappeared from the input silently; it now fails assessment
explicitly. Queue bound (four waiting jobs), concurrency (one thread), input limits, execution
duration, and cancellation are distinct: no cancellation or hard execution deadline exists. Graceful
shutdown waits for active scans; startup reconciliation marks abandoned queued/running jobs
`interrupted`; a failed scan-result persistence produces a redacted failed job outcome. Thread
timeouts would not stop scanning, so process isolation and a hard deadline remain a separate design
change.

The five `tests/integration/test_real_scanners.py` cases are deselected by the default marker
configuration because they require installed Semgrep, Gitleaks, Trivy, YARA, and ClamAV binaries,
with Trivy/ClamAV local databases also required. No dependencies, binaries, signature data, or
external services were installed or contacted.

## T. Stage A dashboard log-analysis workflow — 2026-10-27

Rechecked the authenticated dashboard, persisted case workflow, job manager, log service, parsers,
detections, migrations, and browser harness. Existing log analysis already wrote events, alerts,
timeline entries, and a scan summary into the generic SQLite record table; existing cases already
supported typed alert/event links. Stage A therefore needed no schema migration or new dependency.

Added an operator-controlled `log-sources.toml` registry and explicit
`web serve --log-sources-file` selection. Browser job creation accepts only a source ID. Source,
rule, IOC, credential, registry, database, and operator-protected roots are checked; tree symlinks
and junctions are rejected when observed. The manager runs one job at a time with four waiting
slots and persists queued/running/succeeded/partial/failed/interrupted records. Restart reconciliation
marks abandoned jobs interrupted. Stored results link the actual log scan. Partial outcomes expose
bounded, path-free diagnostic categories. Existing ingestion remains read-only and archive paths are
never extracted; its existing file, byte, archive, and event limits remain the actual enforcement.

Authenticated APIs expose source choices, jobs, paginated alerts/events/timeline, source/severity
filters, and reviewed alert/event detail. Each detail request verifies membership in the owning log
scan. Raw event references (which can contain local paths) are omitted. The React workspace selects
sources, starts and polls jobs, reviews partial diagnostics and results, pages/filter lists, creates
cases, links alerts/events, and uses existing case reports. Browser text rendering preserves HTML-like
evidence as text. The operator guide documents the detection behavior; built-ins remain narrow
heuristics, and Sigma remains the implemented safe subset. No network collection, enrichment, or
upload was added.

The first backend acceptance exposed a possible `raw_ref` leak in a generic serialized event list;
explicit response allowlists corrected it. The first browser rerun exposed incorrect test expectations
and report-link ambiguity (case reports coexist with linked scan reports); the test now selects the
case report explicitly. One component-suite rerun had a slow-host session initialization timeout in
an existing App test; it had passed earlier in the same turn, and is rerun below. Final exact results
are captured in the latest Stage A verification section of `docs/reports/phase-1-report.md`.

Remaining limits: the filesystem can change after validation; no OS sandbox, cancellation, or hard
execution deadline exists; startup reconciliation covers queued/running jobs but cannot prove worker
termination after abrupt process loss; existing log result writes are separate repository saves and
may be partial if persistence itself fails; normalized evidence remains sensitive local data. Stage B1
adds operator-local managed-copy intake and a fixed Windows worker, but does not add authenticated
malware result routes, browser sample intake, retention/deletion, or record-level access controls.
Those B2 decisions remain gated on review and approval. Stage C still needs explicit web network-scope
and authorization approval; Stage D requires controlled profile and binary-readiness assessment.

Roadmap sequence remains: Stage A log-analysis jobs and Stage B1 backend malware work are implemented;
Stage B2 remains unimplemented and requires approval before authenticated result exposure, browser
transfers, case links, retention/deletion, or queue shutdown/cancellation controls. Stage C remains
deferred until web authorization scope and outbound network policy are approved; Stage D requires
operator profiles and real local binary evidence before any engine is called verified; Stage E follows
only from operational workflow needs. No Nuclei, nmap, or broad recon adapter is present. Backup
cutover, destructive retention, multi-user administration, and public deployment remain out of scope.

## U. Stage B1 — backend malware intake and worker foundation — 2026-10-27

Implemented the approved backend-only slice. `malware_managed_directory` must be explicitly
configured; a protected-path helper includes the project/frontend/reports, database and parent,
configuration/secrets, operator credentials, malware and log-source registries, and requires callers
to supply custom config, backup, log-source, report, and other protected roots. The operator TOML registry
maps IDs to explicit local regular files. Intake rejects links/reparse points, checks a 64 MiB limit
while copying, compares source identity before and after the copy, generates opaque 256-bit keys,
uses an exclusive staging file and atomic non-overwriting hard-link publication, and never modifies
originals. Filesystem races remain possible.

Persisted malware sample, job, analysis/result, and audit records use the existing generic SQLite
record convention. A new additive Alembic revision adds a partial status index and preserves prior
records. Sample and analysis identities are separate. Intake writes its three records atomically;
the copy necessarily publishes first, so a database failure leaves a deliberate unexplained orphan
for operator review. Backups include metadata/results only. Recovery reconciliation marks missing or
changed managed objects unavailable and queued/running work interrupted; it does not reconstruct
bytes from registry originals or delete unexplained objects.

The built-in worker is a fixed child entry point with a 4 KiB server-generated request and static profile. Windows Job Object setup,
assignment, and queried limits are required before the parent sends the parsing request. The worker
has a 512 MiB per-process / 768 MiB aggregate memory cap, four-process tree limit, 60-second Job CPU limit, kill-on-close, and
the parent applies a 60-second wall deadline and 3 MiB pipe/result caps. The environment is minimal,
shell execution is disabled, and the parent owns all persistence. ZIP central-directory analysis is
skipped because the standard library parser cannot be bounded by a listing cap; affected results are
explicitly partial. String and indicator caps similarly emit partial warnings. YARA and ClamAV are
not enabled or called by this path; installation, configuration, and real-binary-verification
statuses remain distinct and are recorded as unchecked/not run.

Windows association and synthetic `CreateProcess` child-tree termination are covered separately from
mocked timeout/output-overflow control-path tests. Children launched through alternate system
services are not claimed as contained. See `docs/reports/phase-1-report.md` for exact
acceptance outcomes. These process controls are not filesystem/network sandboxing, managed storage is
not authenticated chain of custody, no retention/deletion policy exists, and no malware dashboard,
upload/download, case-link, or access-control routes were added. B2 still needs approval for
authenticated result disclosure, web queue/shutdown and cancellation policy, retention, case linking,
UI workflows, and any sample transfer through browser channels.

## V. Stage B2 — authenticated malware dashboard and case integration — 2026-10-27

This section supersedes the final B2-unimplemented status in Section U. B2 reuses the managed sample,
job, fixed worker, persistence, and recovery services. `web serve --malware-samples-file` selects the
operator registry. Authenticated APIs expose registry/managed/unavailable states, bounded reviewed
sample metadata, paginated jobs and linked analysis completeness, and allowlisted persisted result
fields. Requests accept registry IDs or managed sample IDs with the fixed `builtin_static` profile;
paths, object keys, executable paths, scanner arguments, and environment variables are not accepted.
Registry-only entries are explicitly un-ingested and have no verified hash.

The existing authenticated session, CSRF, host/origin, loopback, and body limits protect the new
routes. Results redact labels and failures, keep indicators inert, and omit paths, bytes, arbitrary
printable strings, archive names, and raw worker output. Candidate indicators are not confirmed
maliciousness. Case links distinguish stable sample identities from individual analyses, validate
records, and are idempotent. JSON/Markdown/HTML case reports add reviewed malware metadata and
completeness; scan reports and SARIF remain unchanged. No migration was required, and backup
verification validates sample/analysis/job relationships. SQLite backups contain metadata/results,
not managed sample bytes.

An application-owned queue adapter uses the existing one-active/four-queued transactional limit.
HTTP submissions return without waiting for analysis. The only executable path is the fixed child
worker after Windows Job Object setup, assignment, and queried-limit verification. Other hosts retain
historical views while disabling execution. Shutdown stops submissions, waits through the contained
worker's bounded cleanup, marks this manager's unfinished work interrupted where possible, and
restart reconciliation leaves work owned by another live manager alone. No user cancellation was
added. Filesystem race limitations remain; Job Objects do not isolate file/network access and are not
an OS sandbox. Browser upload, download, inline preview, sample deletion, retention, enrichment,
optional scanner enablement, domain jobs, and public deployment remain outside scope.

The real Windows browser acceptance run used a harmless synthetic registry sample and the actual
built-in worker; it observed persisted job/result state and completeness, linked the analysis to a
case, exported redacted JSON, refreshed to confirm persistence, and confirmed protected access after
logout was denied. No YARA/ClamAV binaries or signature data were installed or enabled. The final
verification table, including recovery publication failures, is in `docs/reports/phase-1-report.md`.

Resume verification on 2026-10-27 confirms separate statuses: **B2 browser acceptance passed** (6/6,
including the actual Windows worker, persisted results, case link, and redacted report export);
**full Python acceptance is incomplete** (repeated `KeyboardInterrupt`, with no coverage threshold
result); **backup publication reliability is unresolved**; and **release readiness is blocked**.
The interrupt is a real SIGINT on the test process's main thread. It occurs at different test
locations, including the SQLite backup progress callback, and no signal/control operation exists in
the isolated malware test path. A background PowerShell run ended with `STATUS_CONTROL_C_EXIT`, but
the specific host component sending the event is not identified. The latest standalone recovery
suite passed 15/15, yet a B2 metadata/recovery test failed once at publication and passed alone; an
earlier sequential recovery run raised WinError 5 at `os.rename(staging, output)` twice. A corrected
500-run isolated B2-shaped backup probe did not reproduce the error. No retry, overwrite, or weakened
verification was added. Exact diagnostics and the needed next evidence are recorded in
`docs/reports/phase-1-report.md`.
