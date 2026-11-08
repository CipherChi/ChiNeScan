# ChiNeScan release validation — 2026-11-06

This is a verification report for the current dirty working tree. It is not a penetration test, vulnerability-free claim, or scan of the previously assessed application. The only fresh scan below used synthetic source files created under the OS temporary directory and the built-in static scanner. No fixture source code was executed and no production credentials or external targets were used.

## A. Exact implementation identity and inventory

- Repository: standalone Git checkout `C:\src\Chinescan`.
- Base commit: `2ad86b05ca82181da78b3eb6bfee5598d63dc8af`.
- The implementation is not represented by that commit alone. At inventory capture, 36 tracked files were modified and three implementation/documentation paths were untracked. The complete path and SHA-256 manifest is [implementation-inventory-2026-11-06.json](implementation-inventory-2026-11-06.json). It excludes itself and this later-authored report. No commit or push was made.
- The untracked [report-parity.json](../../frontend/src/test-fixtures/report-parity.json) is imported by frontend tests and read by the backend parity test, so it is required for those tests. The untracked ChiNeScan notes and security review are documentation, not runtime modules. No local database, credentials, temporary scan sources, Playwright harness, or report fixture scan was added to the repository.
- `docs/GNET-SCAN-IMPROVEMENTS.md` is absent. User-facing labels are ChiNeScan. The lowercase `chinescan` package, CLI, configuration and route identifiers remain compatible. A legacy animation-preference key is read only for migration.

Runtime/configuration used:

| Component | Observed version/configuration |
|---|---|
| Python | `py -3.12`: 3.12.10; repository requires Python >=3.12 |
| Backend checks | pytest 9.2.0, Ruff 0.17.3, mypy 1.20.2, pip-audit 2.10.1 |
| Frontend runtime | Node v26.13.0, npm 12.1.0; React/React DOM 19.3.1, Vite 8.3.5, Vitest 5.0.5, Playwright 1.64.1 |
| Frontend lock | `frontend/package-lock.json` (80,982 bytes at inspection); production build served from `frontend/dist` |
| Fresh scan | Built-in scanner only, temporary SQLite and report directories, synthetic seven-file project; no optional external scanner, network audit, or scanned-project execution |
| Browser surface | Temporary authenticated ChiNeScan instance bound to `127.0.0.1:18432`, temporary SQLite and operator credential, existing production frontend bundle |

The hash manifest preserves a checkable inventory of the modified files, but it is not a patch file. The present working tree still contains the prior implementation changes and must be reviewed as a whole before release packaging.

## B. Commands and actual outcomes

Commands executed in this validation or in the immediately preceding validation of this unchanged application code:

| Command | Outcome |
|---|---|
| `py -3.12 -m pytest --basetemp C:\shortpytest -q` | 615 passed, 5 deselected, 3 dependency deprecation warnings in 545.03 s. This full run preceded this report-only validation; no application source or test code changed afterward. |
| `py -3.12 -m pytest tests/unit/test_web_api.py tests/unit/test_reporting.py tests/unit/test_code_rules_behavior.py -q --basetemp C:\shortpytest` | 104 passed, 3 warnings. |
| `py -3.12 -m pytest tests/unit/test_web_api.py::test_scan_cli_api_and_complete_export_share_normalized_values tests/unit/test_web_api.py::test_legacy_score_without_ledger_stays_unavailable_in_api_and_export tests/unit/test_reporting.py -q --basetemp C:\shortpytest` | 10 passed, 3 warnings. |
| `npm test -- --run` (from `frontend`) | 12 files, 61 tests passed. |
| `npm run typecheck` and `npm run build` (from `frontend`) | TypeScript check and Vite production build passed. |
| `npm run test:e2e -- --project=chromium-production` (from `frontend`) | Final run: 14 passed in 1.8 minutes. An earlier run in this release check had 13 passed and one degraded-readiness timeout; see section G. |
| `py -3.12 -m pytest --run-real-scanners -q -rs --basetemp C:\shortscanner tests/integration/test_real_scanners.py` | Five skipped because Semgrep, Gitleaks, Trivy, YARA, and ClamAV binaries are not installed/on PATH. No scanner binary was executed. |
| `py -3.12 -m pip_audit --skip-editable` | “No known vulnerabilities found”; the editable `chinescan` distribution was skipped. |
| `npm audit --offline --audit-level=high` (from `frontend`) | `found 0 vulnerabilities` using the frontend lockfile and offline advisory/cache state. This is not a network-refreshed advisory check. |
| `py -3.12 -m ruff check chinescan tests`; `py -3.12 -m ruff format --check chinescan tests`; `py -3.12 -m mypy chinescan` | Passed; 133 files formatted; no mypy issues in 84 source files. |
| `py -3.12 scripts/export_schemas.py`; `py -3.12 -m json.tool` for the two schemas and parity fixture | Passed. |
| `git diff --check` | Passed; Git emitted CRLF-to-LF normalization notices for several edited files. |

The five default-suite deselections are opt-in real-scanner integrations in `tests/integration/test_real_scanners.py`:

1. `test_semgrep_real_local_positive_negative_persistence_and_report`
2. `test_gitleaks_real_local_positive_negative_persistence_and_redaction`
3. `test_trivy_real_offline_local_database_positive_negative_and_persistence`
4. `test_yara_real_local_positive_and_negative`
5. `test_clamav_real_local_clean_fixture`

`tests/conftest.py::pytest_collection_modifyitems` removes tests marked `real_scanner` unless `--run-real-scanners` or `--require-real-scanners` is passed. They use local fixtures, bounded subprocess execution/output, and offline Trivy flags, so they are designed for safe local execution after the tools/assets are installed. They remain unverified on this machine; their absence reduces confidence in optional scanner integration, not the built-in scan observed here.

## C. Fresh controlled scan: expected and observed

Expected behavior was recorded before scanning:

- DOM `querySelector` and hash `.update` calls should not become SQL findings.
- A recognized database call concatenating request-like data into SQL should produce a heuristic candidate; a positional-parameter query should not.
- Public-prefixed synthetic values may trigger a naming review, but the tool must not establish privileged key type or production exposure from a name.
- Partial project header configuration and a login-like route without a same-file limiter should be review leads; deployment headers and imported/shared controls must remain unresolved.
- A fixture with multiple signals should produce a score whose nonzero ledger contributions sum to its total.

Executed the `chinescan code` command with `--format json` against temporary synthetic TypeScript/config files. The actual scan ID was `8836cc7e-f236-4433-83d0-972dc78e2906`. The SQL case excerpt was static fixture text and is not evidence that an application was exploitable.

| Case | Observed result |
|---|---|
| Interpolated DOM `querySelector` | No SQL-INJECTION finding. |
| Interpolated `createHash(...).update(...)` | No SQL-INJECTION finding. |
| `db.query("SELECT ... " + request.query.id)` | One High/POSSIBLE `SQL-INJECTION` candidate at `src/query.ts:2`. Explanation says the SQL sink and dynamic construction matched but taint/runtime execution are unproven. |
| `db.query("SELECT ... ?", [request.query.id])` | No SQL-INJECTION finding. |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` and synthetic `NEXT_PUBLIC_ADMIN_SECRET` | One coalesced Medium/POSSIBLE `NEXT-PUBLIC-SECRET` finding covering both lines. The privileged-looking synthetic value was redacted. The name and `NEXT_PUBLIC_` prefix do not verify key privilege or emitted production exposure; the public-prefixed case is not treated as a demonstrated privileged credential. |
| Next.js config with only a recognizable frame header | One Medium/POSSIBLE header-review finding. It reflects incomplete recognizable values in that inspected config; it does not establish effective application/deployment headers. |
| POST login-shaped handler without a same-file limiter or schema | `LOGIN-NO-RATE-LIMIT`, `REQUEST-NO-SCHEMA`, `API-AUTH-MISSING`, and `ASYNC-ROUTE-ERROR` candidates were emitted. These are file-local pattern results; shared middleware, framework guarantees, and deployment controls were not traced. |
| Multiple score signals | Score 30, `legacy-pattern-v1`, confidence `LIKELY` (heuristic category, not a probability). Nonzero contributions: `leftover_guidance` 1 × 8 = 8; `mock_data` 2 × 8 = 16; `multiple_http_styles` 3 distinct styles triggering one-time 6-point bonus = 6. Sum = 30. Other ledger entries were present with zero contribution. |

The final scan contained 8 normalized findings: 2 high, 4 medium, 2 low, 0 critical, 0 informational; 7 files scanned, 0 excluded, no recorded coverage gap. This does not measure scan completeness beyond the fixture. A prior calibration run of the same temporary fixture before adding score signals was discarded; the final ID above is the one followed across surfaces.

## D. Same-scan product surface comparison

The same stored scan was opened through CLI reports, authenticated API routes, and a real local Chromium dashboard session. The API/CLI contract test also persists the shared deterministic `report-parity.json` and asserts exact normalized full-export equality.

| Surface | Observed values/content |
|---|---|
| CLI summary/preview: `chinescan --database <temp-db> report <scan-id> --format json` | Scan ID and summary for the same scan; preview counts and `report_truncated=false`, 8 returned grouped findings, 0 omitted grouped findings. |
| CLI detail: `... report <scan-id> --format detail` | 8 findings, individual locations/rationales, score 30 and contribution ledger. This uses the human Markdown-style report renderer. |
| CLI machine export: `... report <scan-id> --format full-json` | Valid JSON, all 8 finding IDs, `export_status=complete`, 8 returned, 0 omitted, score 30 with ledger. stdout parsed as JSON without progress/log contamination; saved-report notices from the scan command went to stderr. |
| Authenticated API | `GET /api/scans/{id}` returned the same scan ID. `GET /api/scans/{id}/report/full-json` returned all 8 individual findings, same IDs/severity/confidence/explanation, 30-point ledger, coverage, and exclusions. `GET /api/findings/{id}` returned the authorized detail fields with the synthetic sensitive value redacted. |
| Dashboard | Actual browser page opened the same scan and SQL finding; scan ID, 30/100 score, `legacy-pattern-v1`, score ledger and rationale rendered. Finding ID and rationale matched API data; synthetic secret was absent from dashboard payload. |
| Preview vs complete | The fresh 8-finding preview had no omissions; it cannot demonstrate actual preview truncation. Existing unit tests exercise truncation metadata and retrieval guidance. `fix_first` is a separate ranked subset, not an additional finding total. |
| Legacy record | The shared-fixture API/CLI test verified a finding with no explanation stays unavailable and a score with no ledger remains legacy/unavailable; it does not invent historical rationale. |

The product uses different display formats and grouping: JSON preview has grouped category arrays and omission metadata; `full-json` contains individual records; the dashboard opens selected records and filters its visible rows. Representative values agree, but filtering/count parity was not exercised against the fresh scan. The dashboard does not show preview omitted counts/reasons before download; those appear in the downloaded JSON. “Download JSON preview” labels it as a preview.

## E. Export boundaries and retrieval

Source checks: `MAX_COMPLETE_FINDINGS = 10_000`; `MAX_COMPLETE_JSON_BYTES = 20 * 1024 * 1024` in `chinescan/core/reporting.py`; API equivalents in `chinescan/web/app.py`. Both comparisons reject only when `>` is true, so the configured cap is inclusive. The byte count is the UTF-8 encoded, indented (`indent=2`), sorted JSON text produced with `ensure_ascii=False`; it is measured before returning the body. API separately limits the full JSON download response.

Boundary tests were run with equivalent smaller controlled caps to keep fixtures small:

| Boundary | CLI | API |
|---|---|---|
| Finding cap patched to 2: 1 record | Exit 0, valid JSON | 200, 1 returned |
| Exactly 2 records | Exit 0, valid JSON | 200, 2 returned |
| 3 records | Exit 2, empty stdout, no JSON artifact written by the command | 413, no `Content-Disposition` attachment |
| UTF-8 serialized body 9,697 bytes, cap 9,698 (one byte below limit) | Exit 0 | 200, body 9,697 bytes |
| Same body exactly 9,697 bytes | Exit 0 | 200, body 9,697 bytes |
| Cap lowered to 9,696 bytes | Exit 2, empty stdout | 422 from the renderer’s `ReportingError` mapping, JSON error body and no attachment. When the API route’s own byte guard is reached after rendering, it returns 413. |

The exact production 10,000/10,001-record volume was not materialized; the API and CLI used a patched test cap to prove inclusive threshold behavior. An exact 20 MiB pathological single-string report render was attempted but did not finish in the observation window because redaction performance degraded; it was stopped and is not claimed as a successful boundary run. Existing tests prove the renderer and API guards at small controlled byte caps.

An over-limit `full-json` artifact is not returned as one complete report. Existing records remain available through authenticated API access: `GET /api/scans/{id}` returns all finding IDs, and `GET /api/findings/{finding_id}` returns each finding individually. This is not a bulk/cursor retrieval mechanism; the read rate limit is 1,000 per minute by default, so large scans require many requests. The preview’s suggested `full-json` retrieval works for the tested small scan but will fail at its cap; it does not explain the individual-ID fallback. CLI `detail` also uses the 50 KiB code-report renderer cap for code assessments and is not a complete bulk substitute. These limitations should be explicit to users with an already oversized scan; rerunning a smaller scan does not recover omitted records from the original scan.

For output files, the CLI renders before `write_text`, so a failed render does not write a newly partial file. If a destination file already existed, the failed command does not remove or overwrite that old file; operators should use a fresh path when validating a failed export. The API does not attach its error body. The dashboard reads a failed response before starting a download and shows an alert stating that no file was downloaded.

## F. Deselected integration tests

The five deselections and reason are in section B. The current environment lacks each executable, so the opt-in command reported five skips with those exact missing-tool reasons. These tests are safe by design for local fixtures after tool installation, but cannot be treated as passed. This leaves external scanner command compatibility and their positive/negative controls unverified here.

## G. Initial Chromium readiness timeout

In the first full Chromium run of this validation, 13/14 tests passed. `system status reports degraded readiness for missing optional storage` timed out waiting for “Connected to local service”; the captured error context showed the page still at “Checking local service” and “System checks” without a completed result. That test passed on an isolated rerun and the full 14-test suite passed on the next run. No retry or timeout was added.

The precise cause remains unresolved. Playwright’s later successful run cleaned the earlier trace artifacts; only the failure screenshot/error context was inspected at the time. The failed test does not show whether the three parallel health/readiness/diagnostics requests stalled, were rate limited, or failed before state update. Impact is limited to a system-status view in this observed case, but it is evidence of an intermittent test/runtime readiness path.

## H. Dashboard, mobile, motion, and accessibility

Direct Chromium checks against the temporary live dashboard found:

- At 390 × 844 CSS pixels, document width and scroll width were both 390 px; main navigation was visible (362 × 36 px in the check). This validates one mobile viewport, not every screen size or interaction.
- `prefers-reduced-motion: reduce` with the persistent preference enabled produced an inactive terminal layer and computed `animation-duration: 0s`.
- Pause changed the stored `chinescan-terminal-motion` preference to `off`; after reload it remained off and the control read “Resume ambient motion.”
- The layer had `aria-hidden="true"` and was absent from the rendered meaningful content inspected. No screen-reader product audit was performed.
- A `visibilitychange` event with `document.hidden` simulated in Chromium paused the animation. Headless Chromium did not naturally report the page hidden when a second page was opened, so actual browser tab lifecycle pausing is supported by the component test and event simulation, not verified through a real background-tab lifecycle.
- Keyboard Tab focus in Chromium matched `:focus-visible` and showed a 2 px outline. The production E2E finding test also navigates by keyboard and checks source text is redacted and rendered inertly.
- Vitest covers unauthorized login state, empty state, preference migration/persistence, hidden-document event, reduced-motion mock, shared fixture detail, markup-as-text, and export-limit errors. Browser E2E covers successful downloads, system offline/recovery, and partial project/malware workflows.

Unverified or incomplete dashboard evidence: complete keyboard-path audit, real browser mobile navigation at multiple sizes, screen-reader testing, end-to-end filter/count parity for the same scan, and a visible pre-download truncation summary. The app’s preview file contains omission data, but the UI does not display those counts/reasons itself.

## I. Security review and dependency scope

The current deployment is explicitly local: `chinescan web` starts one Uvicorn worker on `127.0.0.1`; the middleware checks both the request Host and peer address are loopback and rejects non-loopback requests. There is no supported external bind option. Tests include a non-loopback peer rejection. This is a single local operator design, not a tenant boundary; a remote proxy/tunnel or multi-user deployment is unsupported and not ready.

Inspected controls and scope:

- Authenticated scan/finding/report routes depend on the local session. Mutations check same-origin `Origin`; CSRF-protected operations also require the session token. Cookies are HttpOnly and SameSite=Strict, with Secure configurable for a supported HTTPS context (which is not a supported remote deployment here). No permissive CORS middleware was found.
- React renders finding strings as text; report renderers escape HTML/Markdown/CSV-sensitive content. Representative untrusted markup and redaction tests passed. No exhaustive field-by-field fuzzing was run.
- Filesystem browsing uses session-bound selection capabilities, root validation and symlink/reparse-point checks; CLI intentionally reads operator-supplied files. SQLite uses SQLAlchemy bound statements in reviewed repository code. External tools/Git use argument arrays, `shell=False`, timeouts/output limits and constrained environments. No scanner binary was invoked during the fresh scan.
- Log archives have bounded member/total processing and avoid unsafe `extractall`; GitHub, chain and domain outbound paths are optional/configured and require their separate controls. No external destination was contacted.
- There are request/file/archive/output/report limits, but no stress test was run. The release probe found the redaction regex latency issue described in section J; limits alone do not bound its CPU cost.
- `py -3.12 -m pip_audit --skip-editable`: Python 3.12.10 interpreter environment audited; editable ChiNeScan distribution skipped; no known advisories reported.
- `npm audit --offline --audit-level=high`: locked frontend runtime and development dependency graph reported zero known advisories from the offline audit state. No fresh network advisory check was run, so advisory database freshness is unknown.

These checks do not establish that ChiNeScan is secure or vulnerability-free. No independent penetration test, exhaustive dependency/source audit, load test, fuzzing campaign, or full screen-reader audit was performed.

## J. Prioritized issues and readiness

### R1 — Unbounded redaction regex work on untrusted text

- **Status:** Confirmed performance risk; no fix in this verification phase.
- **Evidence:** `chinescan/core/logging/redaction.py::_KEY_ASSIGNMENT` includes an unbounded key-name lookahead; `external_reports.py::_text()` invokes `redact(cleaned)` before truncating imported text. A local Python 3.12.10 probe measured benign `x` strings at 100 chars: 0.0046 s; 500: 0.0614 s; 1,000: 0.1803 s; 2,000: 0.7970 s; 4,000: 2.4316 s. A synthetic 20 MiB render did not complete in the observation window and was interrupted. Timing is environment-specific but repeatable evidence of severe growth.
- **Reproduction:** `py -3.12 <temporary benchmark script>` calling `redact('x' * n)` for those sizes; code path reproduction is authenticated `POST /api/scans/{scan_id}/external-reports` with a permitted local report containing a long benign description. No malicious report or external service was used.
- **User impact:** Import/scan/report requests containing long untrusted text can monopolize the single local server worker and make the UI or CLI appear hung before text truncation. Remote exploitability was not tested; the app is loopback-only and authenticated.
- **Release classification:** **Release blocking for importing untrusted scanner reports or claiming the configured 20 MiB export behaves responsively.** Normal small local scans are not proven affected to the same degree.
- **Targeted correction:** Bound/anchor sensitive-key detection so it does not rescan arbitrary suffixes from every character; clip or stream untrusted strings before expensive redaction while preserving secret detection at the accepted boundary.
- **Acceptance test:** Preserve current secret-redaction positive controls; add long benign and sensitive strings at import, finding serialization, CLI, and API paths; demonstrate bounded scaling at 2 KiB/4 KiB/20 KiB and successful capped-report handling without a long single-worker stall.

### R2 — Over-limit export status and retrieval guidance

- **Status:** Supported implementation gap.
- **Evidence:** Inclusive caps are intentional and tested, but renderer-level byte rejection maps to API HTTP 422, while the API route’s later size guard returns 413. The preview points users to `full-json`, which cannot return one complete artifact above the same cap. API scan IDs plus individual finding routes permit manual retrieval but there is no per-scan cursor/bulk retrieval; the CLI detail renderer is capped at 50 KiB.
- **Reproduction:** With a controlled 9,697-byte report and renderer limit lowered to 9,696, CLI exited 2 and API returned 422 with no attachment. With the API-only response limit lowered, the route returns 413. Count tests at patched cap 2 showed 1/2 succeed and 3 fail (CLI 2, API 413).
- **User impact:** Users see inconsistent HTTP status for the same configured byte cap, and an already oversized scan cannot be saved as one complete export. Individual API calls can recover stored findings but are slow and undocumented as a substitute.
- **Release classification:** **Nonblocking for scans within documented limits; deferred for complete oversized-report workflows.** Existing records can still be fetched by ID through authenticated API calls, but complete one-file export is unavailable.
- **Targeted correction:** Normalize export-limit status/error contracts and add cursor/stream retrieval or a documented per-scan paged endpoint. Make preview omissions point to the actual available retrieval path when `full-json` is over cap.
- **Acceptance test:** At 10,000/10,001 findings and 20 MiB ±1 byte, API/CLI/dashboard agree on inclusive boundaries, status, omitted counts and safe retrieval of every existing finding; no partial artifact or attachment is produced on failure.

### R3 — Dashboard does not show preview omissions before download

- **Status:** Confirmed UI gap.
- **Evidence:** Scan detail has buttons for preview/full JSON/Markdown and handles failed complete exports, but the preview response is downloaded without parsing/rendering its `report_omissions` or truncation fields.
- **Reproduction:** Use a scan with more than the preview category cap and select “Download JSON preview”; omission metadata is in the downloaded JSON, not displayed in dashboard detail beforehand.
- **User impact:** Users must open the downloaded JSON to know how many grouped findings were omitted and why.
- **Release classification:** **Nonblocking**, since the control is labeled preview and the export includes omission metadata.
- **Targeted correction:** Show preview total, returned and omitted counts, truncation reason, and a usable retrieval method in the dashboard.
- **Acceptance test:** A controlled truncated preview displays accurate counts/reason; a non-truncated preview displays zero omissions; detail and full exports retain their current contract.

### R4 — Intermittent degraded-readiness browser test

- **Status:** Unresolved intermittent behavior.
- **Evidence:** One full Chromium run had 13/14 pass and showed the degraded readiness page stuck on “Checking local service”; isolated rerun and subsequent full run passed. No retained trace identifies whether a request stalled, was rate limited, or failed.
- **Reproduction:** `npm run test:e2e -- --project=chromium-production`; initial occurrence was transient and did not reproduce in the next run.
- **User impact:** System-status diagnostics can appear to remain loading in the observed state; scan workflows passed in the final browser run.
- **Release classification:** **Nonblocking, monitor.**
- **Targeted correction:** Instrument/represent each health/readiness/diagnostics request result so a stalled or partial status is diagnosable; do not mask it with blind retries or longer timeouts.
- **Acceptance test:** Deterministically simulate delayed, 503, 429 and offline responses; status leaves loading with truthful partial/error state and a rerun of the configured Chromium suite is stable without retries.

### R5 — Optional real scanner integrations unavailable

- **Status:** Unverified due missing executables/assets.
- **Evidence:** The five named integration tests skipped with missing `semgrep`, `gitleaks`, `trivy`, `yara`, and `clamscan` reasons. No test claimed these passed.
- **Reproduction:** `py -3.12 -m pytest --run-real-scanners -q -rs --basetemp C:\shortscanner tests/integration/test_real_scanners.py`.
- **User impact:** External scanner invocation and results are not release-validated on this host; built-in detection was independently exercised.
- **Release classification:** **Deferred/nonblocking if release scope is built-in scanner only; blocking if advertising these integrations as validated on this platform.**
- **Targeted correction:** Run the opt-in suite in a controlled CI image with the pinned tools and offline assets.
- **Acceptance test:** All five tests execute against repository fixtures with positive and negative controls, persistence/redaction assertions, bounded output/time, and recorded tool versions.

### Readiness by deployment model

- **Local single-operator use:** **Conditional readiness; do not treat as unconditionally release-ready for untrusted report imports until R1 is corrected.** The core built-in scan, same-scan report/API/dashboard paths, settings, motion behavior, and export limits passed their tested cases. Use only within documented scope; large exports remain bounded and incomplete as one artifact.
- **Remote or multi-user use:** **Not ready and unsupported.** Listener and middleware enforce loopback; authorization is one local operator, with no tenant isolation. Do not expose via proxy/tunnel or describe as a multi-user service.
