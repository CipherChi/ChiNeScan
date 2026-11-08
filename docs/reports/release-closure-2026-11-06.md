# ChiNeScan release closure follow-up — 2026-11-06

This report records a targeted closure pass after R1. It is not a new architecture review,
production deployment, malware execution, penetration test, or claim that external scanners ran.

## Starting state and inventory comparison

Read first: `release-validation-2026-11-06.md`, `redaction-remediation-2026-11-06.md`,
`implementation-inventory-r1-2026-11-06.json`, `AGENTS.md`, `SECURITY.md`, and
`docs/reports/security-review.md`. The initial worktree was already dirty and contained the
reported R1 implementation plus untracked parity/report artifacts. Changes in this closure pass
were kept in the same worktree; no reset, commit, push, deployment, production database, or external
credential was used.

The R1 inventory contained 44 entries. At closure, 49 files are included in the companion
`implementation-inventory-closure-2026-11-06.json`: nine R1-entry hashes changed
(`chinescan/cli/commands.py`, `chinescan/core/reporting.py`, `chinescan/web/app.py`,
`frontend/e2e/dashboard.spec.ts`, `frontend/src/types.ts`, `frontend/src/ui/App.test.tsx`,
`frontend/src/ui/App.tsx`, `tests/unit/test_reporting.py`, and `tests/unit/test_web_api.py`);
five paths were added (`chinescan/core/storage/repository.py`,
`frontend/src/ui/SystemStatus.test.tsx`, `frontend/src/ui/SystemStatus.tsx`, and two carried
R1 report/inventory files); none of the R1 inventory paths disappeared. The original R1 inventory
and its companion report remain unchanged.

## Remaining conditions and classification

| Condition | Observed implementation / impact | Local built-in blocker? | Classification / acceptance |
|---|---|---:|---|
| Complete retrieval above full JSON limits | Prior export rejected over 10,000 findings or 20 MiB; the existing global findings API was paged but not scan-bound. Users could not conveniently retrieve every finding in one operation. | Yes, for retrieving an already oversized scan as a complete artifact. | Fixed with an authenticated scan-specific JSONL stream and CLI JSONL writer. Accept when a >10,000-record synthetic scan returns every scan-linked ID once, in order, redacted, with count/hash completion evidence and bounded processing. |
| Preview omission visibility | Code preview grouped findings and limited groups by category and byte cap; CLI JSON contained some omission fields, but grouped occurrences and exact cap reasons were not distinct; the dashboard did not show the preview metadata before/after download. | Yes, for interpreting a truncated preview; no, for ordinary built-in scanning. | Fixed by explicit stored/available/grouped/returned and omission counts/reasons plus visible dashboard summary. Accept with no-omission, group-cap, byte-cap, occurrence, and unknown/legacy cases. |
| Browser readiness timeout | Prior trace showed “Checking local service” with no completed result. Historical cause is not provable: traces were later cleaned, and request outcomes were not recorded. Existing component used `Promise.all` without request timeouts or per-request outcome state, so one stalled call could hold the view in loading. | No, scan flow unaffected; it blocks confidence in the system-status diagnostic view. | Historical incident remains unresolved. Added bounded request timeout, independent request outcomes, partial data retention, and retry status. Acceptance is deterministic delayed/503/429/offline coverage plus repeatable production-browser runs without retry inflation. |
| Semgrep/Gitleaks/Trivy/YARA/ClamAV unavailable | Executable discovery on this host reported each unavailable. The opt-in real-integration tests are skipped; this does not imply “ran and found none.” | No for the supported built-in-only local profile. Yes only for a release profile claiming any particular external integration. | Capability limitation / not verified here. Accept each integration only after its binary (and Trivy/ClamAV local assets) is available and its real local fixture passes. |
| Remote or multi-user service | Loopback-only, single-operator architecture; sessions and worker queues are process-local. | Outside supported scope. | Unsupported deployment requirement; not enabled by this task. |

Implementation references for the observed behavior: `chinescan/core/reporting.py` contains
preview/group metadata and the redacted JSONL iterator; `chinescan/cli/commands.py` wires the CLI
format; `chinescan/web/app.py` defines the authenticated stream and paged finding counts;
`chinescan/core/storage/repository.py` exposes bounded batch retrieval;
`frontend/src/ui/App.tsx` presents omissions/counts and direct download;
`frontend/src/ui/SystemStatus.tsx` bounds independent readiness requests. Regression coverage is
in `tests/unit/test_reporting.py`, `tests/unit/test_web_api.py`,
`frontend/src/ui/App.test.tsx`, `frontend/src/ui/SystemStatus.test.tsx`, and
`frontend/e2e/dashboard.spec.ts` / `frontend/e2e/system-status.spec.ts`.

## Preview and count contract

The CLI grouped JSON preview now distinguishes `total_stored_findings` (scan-linked IDs),
`available_finding_records` (records found and loaded), `grouped_issue_total`,
`returned_grouped_findings`, and `processing_failure_count`. Each rendered group carries an
`occurrence_count`. `report_omissions` distinguishes category group-cap omissions, 50 KiB JSON
preview byte-cap omissions, omitted groups, omitted occurrences, and a precise retrieval route.
The existing complete JSON has separately labeled raw and grouped totals. Historical values absent
from old responses are displayed as unknown; they are not reconstructed from partial data.

The dashboard findings list distinguishes total stored records, results matching active filters,
and rows on the current page. Empty filtered results say that records remain when filters change.
Scan detail limits rendered finding links to 20 and gives a paged list / JSONL path. Preview
download feedback describes raw, grouped, returned, omitted, and failure counts when the payload
contains them; absent legacy metadata is shown as unknown. Complete JSON remains bounded. The
dashboard's JSONL action uses a browser-managed download instead of buffering the full report in
JavaScript.

## Complete retrieval design

**Format:** new `jsonl` format and `GET /api/scans/{scan_id}/findings.jsonl`; old JSON preview and
`full-json` schemas remain compatible. CLI: `chinescan report <scan-id> --format jsonl`.

**Ordering and continuation:** manifest first; finding rows follow the scan's `finding_ids` order;
one final `complete` row contains returned count and SHA-256 of the exact finding-row lines
(including newline delimiters). Duplicate IDs reject export before streaming. New scan IDs added
after the manifest snapshot are excluded. Each bounded record batch is read when reached. If a row
is missing, invalid, or cannot be safely redacted, the API emits a generic error row and no
completion row; CLI exits with usage/data error and no completion row. Consumers must require a
single final `complete` row, match its count to the manifest, and verify its digest. A truncated or
interrupted file is therefore distinguishable from a completed file.

**Consistency:** the ordered scan-ID list is captured at export start. Each finding payload is read
when its batch is processed; an update before that batch is reflected, while later additions to the
scan ID list are not. This is not a whole-database transaction snapshot. Deletion or malformed
payload during retrieval yields an explicit error/no completion. Ordering and IDs cannot duplicate
because each unique captured ID is emitted exactly once.

**Bounds and redaction:** 100 finding records are fetched per SQLite batch. One finding is
validated, redacted, and serialized at a time. The shared per-operation redaction limits remain in
force; an unsafe/oversized record fails instead of bypassing redaction. No total output-size limit
was removed from full JSON or from the 2 MiB external-report import. JSONL total bytes are not
precomputed, since doing so would require a second complete pass. The API streams and the CLI
iterates directly to stdout or the requested file. The browser does not retain the full output in
application memory.

The 10,000-finding and 20 MiB limits are **single full-JSON export limits**, not the external-report
import limit, redaction-operation limits, or total database size. The JSON preview has a separate
50 KiB limit and per-category cap. External report import has a separate 2 MiB body / 5,000-finding
bound. SQLite has no declared global scan-size ceiling in the inspected implementation; scans are
subject to configured file/byte/runtime bounds and whatever findings they generate.

Compatibility: `full-json` is unchanged; JSONL is a distinct versioned line-oriented format. It is
not interchangeable with a single JSON object. Existing consumers keep using `full-json` within
its published limits.

## Readiness investigation

The original timeout evidence remains insufficient to identify whether backend startup, frontend
loading, polling, browser isolation, resource contention, or a specific HTTP response caused that
run. The code-level verified failure mode was unbounded waiting for all three concurrent
health/readiness/diagnostics requests to resolve. The panel now gives each request a five-second
abort bound, reports health/readiness/diagnostics outcomes independently, retains successful
responses if another endpoint fails, and uses bounded exponential polling after failure. No
arbitrary sleep, longer test timeout, or Playwright retry was added. A targeted delayed-readiness
test reports healthy health/diagnostics results alongside the timed-out readiness result. In a
full browser run concurrent with the full Python suite, 13/14 tests passed and degraded readiness
failed with health received plus readiness and diagnostics timeouts; concurrent resource
contention is plausible but was not established. A later full browser run without the Python suite
running passed 14/14 in 2.3 minutes. The historical cause remains unresolved because the original
trace and server-side timings are unavailable. Current bounded behavior is covered; the repeat
does not retroactively identify the original cause.

## Optional scanner classification

| Integration | Current host | Repo support / safe fixture status | Release profile |
|---|---|---|---|
| Semgrep | Unavailable | Adapter and positive/negative local fixtures exist; no binary run. | Optional; built-in-only profile is independent. |
| Gitleaks | Unavailable | Adapter and synthetic positive/negative fixtures exist; no binary run. | Optional; built-in-only profile is independent. |
| Trivy | Unavailable | Adapter and local misconfiguration fixtures exist; real run also requires local DB; no network update permitted here. | Optional; built-in-only profile is independent. |
| YARA | Unavailable | Static engine adapter and local rules/sample fixtures exist; no binary run. | Optional; built-in-only profile is independent. |
| ClamAV | Unavailable | Local adapter and clean fixture exist; real run also needs a local signature DB; no update permitted here. | Optional; built-in-only profile is independent. |

Adapter fixture tests cover executable lookup, missing executable errors, bounded output,
timeouts/cancellation, malformed JSON, nonzero exit, controlled environments, and normalized
finding content. Missing integrations must be represented through scanner failures/coverage, not as
successful no-finding scans. Real integration tests are reported separately as skips.

## R1 regression and validation record

Synthetic-only validation used no production credentials or external targets. R1 protections are
retained: forward delimiter scanning, clip-before-redact imports, documented operation bounds,
fail-closed behavior, secret canary checks, and no original unredacted value on failure. The
reporting/API tests exercise canaries and failure responses; R1 boundary and malformed-input
regressions ran in the full suite. A single-host informational redaction check recorded medians of
0.000848 s (2,000 chars), 0.001505 s (4,000 chars), and 0.014162 s (20,000 chars), with maxima
0.008353 s, 0.009817 s, and 0.067882 s respectively. This is an observation on this host, not a
formal complexity or service-level guarantee.

### Exact commands and outcomes

| Command | Outcome |
|---|---|
| `py -3.12 -m pytest --basetemp C:\chinescan-closure-full -q` | 632 passed, 5 deselected, 3 warnings, 507.10 s. Deselected tests are opt-in real external scanner integrations. |
| `py -3.12 -m pytest tests/unit/test_reporting.py tests/unit/test_web_api.py tests/unit/test_redaction.py tests/unit/test_code_actionability.py tests/unit/test_external_scanners.py tests/unit/test_malware_analysis.py -q --basetemp C:\chinescan-closure-final-focused2` | 121 passed, 3 warnings, 64.95 s. |
| `py -3.12 -m pytest tests/unit/test_reporting.py::test_jsonl_iterator_streams_beyond_legacy_byte_cap_with_bounded_records -q --basetemp C:\chinescan-closure-byte-cap2` | 1 passed, 2 warnings, 8.21 s; 23 synthetic records produced more than 20 MiB, in order, exactly once, with verified completion digest. |
| `py -3.12 -m pytest tests/unit/test_reporting.py::test_preview_truncation_declares_omissions_and_complete_retrieval tests/unit/test_reporting.py::test_jsonl_iterator_retrieves_more_than_legacy_cap_exactly_once tests/unit/test_web_api.py::test_complete_jsonl_route_is_authenticated_and_has_completion_record -q --basetemp C:\chinescan-closure-large-test` | 3 passed, 3 warnings, 40.53 s; the retrieval test stored 10,005 synthetic findings and verified every ID once. |
| `py -3.12 -m pytest --run-real-scanners -q -rs --basetemp C:\chinescan-closure-scanners tests/integration/test_real_scanners.py` | 5 skipped: Semgrep, Gitleaks, Trivy, YARA, and ClamAV executable unavailable on PATH. No real integration passed or ran. |
| `npm test -- --run` (from `frontend`) | 12 files, 62 tests passed. Non-fatal jsdom navigation/per-file timing notices appeared. |
| `npm run typecheck && npm run build` (from `frontend`) | Passed; Vite built 29 modules; final JS asset 353.23 kB (99.09 kB gzip). |
| `npm run test:e2e` (from `frontend`, final current-build repeat) | 17 passed in 2.1 minutes. An earlier concurrent full run was 13 passed / 1 failed as described above. The first focused run also exposed a missing test-only `readFile` import; after fixing it, the focused browser checks passed. |
| `py -3.12 -m ruff check chinescan tests` | All checks passed. |
| `py -3.12 -m ruff format --check chinescan tests` | Passed; 133 files already formatted. |
| `py -3.12 -m mypy chinescan` | Success; no issues in 84 source files. |
| `py -3.12 -m json.tool schemas\finding.schema.json`, `py -3.12 -m json.tool schemas\investigation.schema.json`, and `py -3.12 -m json.tool frontend\src\test-fixtures\report-parity.json` | All three JSON inputs parsed successfully. |
| `git diff --check` | Passed; Git reported only line-ending normalization notices. |

The byte-cap test was added after the full Python suite, so it was run directly and passed; the
full suite result covers the implementation code before that test-only addition. The suite's five
deselections and the separately observed five scanner skips are not counted as passes. No Docker
build, dependency/network audit, external scanner run, or deployment was performed.

## Readiness decisions

1. **Local single-operator use with the built-in scanner: Ready for the documented supported
   profile.** This decision relies on the local-use security constraints, synthetic validation,
   full backend suite, frontend checks, and completed large-result retrieval evidence. Use JSONL
   and verify the final completion row/count/hash when retrieving large scans. This does not claim
   external scanners ran.
2. **Local use with Semgrep, Gitleaks, Trivy, YARA, or ClamAV: Not verified/available on this
   host.** The exact condition for each is that its executable must be available and its opt-in
   local fixture must pass. Trivy additionally requires an already-local database; ClamAV requires
   local signatures. No signatures/database were downloaded or updated. These integrations are
   optional for the built-in-only profile.
3. **Remote or multi-user deployment: Not ready and unsupported.** This closure did not change
   loopback binding, single-operator assumptions, or process-local state, and did not add tenant
   isolation or a remote deployment model.

No files were deployed, and no commit or push was made. The uncommitted working tree is identified
by the companion inventory, which excludes only itself and this report.
