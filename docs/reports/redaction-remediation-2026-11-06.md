# ChiNeScan redaction remediation follow-up — 2026-11-06

This follow-up preserves the original [release-validation report](release-validation-2026-11-06.md). It records a scoped remediation of that report’s R1 performance issue. The implementation is still the dirty working tree based on `2ad86b05ca82181da78b3eb6bfee5598d63dc8af`; no commit, push, deployment, production data, real credential, or external target was used.

At remediation start, every file hash in the original validation inventory still matched: 38 file hashes plus its one directory entry. The validation report and original inventory were validation artifacts created after that snapshot and therefore were not entries in its hash list. No other intervening source changes were found. The updated [R1 implementation inventory](implementation-inventory-r1-2026-11-06.json) now hashes 44 modified or untracked repository files; it excludes only itself and this companion report. Temporary fixtures, test databases, benchmark input, and browser data remained outside the repository.

## A. Verified R1 root cause

The redaction implementation in `chinescan/core/logging/redaction.py::_KEY_ASSIGNMENT` used a key-name lookahead that could scan the rest of a long string from successive candidate positions. The effect was severe superlinear CPU growth for benign text such as repeated `x` characters. The evidence establishes expensive repeated regular-expression work, but does not establish a formal complexity bound for Python’s regex engine.

The import path amplified the cost. `chinescan/core/external_reports.py::parse_scanity_export` accepts JSON/SARIF bodies up to 2 MiB and at most 5,000 findings. `_map_record` calls `_text` for descriptions and other fields; the old `_text` redacted the complete string, then sliced the result to a retained limit of at most 2,000 characters. Thus discarded attacker-controlled tails still incurred redaction work. The authenticated local API bounds the import body, but a 2 MiB cap did not prevent a long synchronous operation on the single local service worker.

The shared `redact` function is also used by finding/report serialization, API responses consumed by the dashboard, CLI output, exports, and structured logging. Those paths were subject to the same key-assignment behavior. External import findings are redacted before persistence; API finding fields and report renderers redact persisted data again. No source execution or external scanner invocation was needed to reproduce this behavior.

## B. Safe reproduction and baseline measurements

The benchmark ran in one process on Windows with Python 3.12.10. The baseline function was loaded from `HEAD:chinescan/core/logging/redaction.py` (the implementation captured by the release-validation base commit); the current function was imported from the working tree. Both received identical benign strings (`"x" * n`). Each result is the median of three calls, measured with `time.perf_counter`; maximum baseline input was 4,000 characters, a bounded workload.

| Input characters | Baseline redactor | Remediated redactor |
|---:|---:|---:|
| 100 | 0.001732 s | 0.000132 s |
| 500 | 0.029063 s | 0.000230 s |
| 1,000 | 0.140564 s | 0.000359 s |
| 2,000 | 0.438224 s | 0.000680 s |
| 4,000 | 1.674581 s | 0.000821 s |

These are empirical timings from one host, not a guaranteed throughput or proof of asymptotic complexity. They reproduce the original growth pattern and show a large reduction on the same inputs. A 20,000-character current-only probe completed in approximately 0.011 seconds in an earlier sample; timing varied with host load.

The controlled reproducer contains no credentials. Separate tests use clearly synthetic canary strings to verify that ordinary redaction and fail-closed paths do not reveal their contents.

## C. Implemented correction and changed files

- [redaction.py](../../chinescan/core/logging/redaction.py): replaced the backtracking key-assignment regex with a forward scan over `:` and `=` delimiters. For each delimiter it walks the immediately preceding key once and tests that key against the supported sensitive-name patterns. It does not impose a maximum key-name length. It continues to preserve existing value-shape handling for quoted, angle-bracketed, and plain values, plus bearer tokens, Argon hashes, token-like values, and local paths.
- The same module now applies fixed, fail-closed per-operation limits: 1,000,000 characters/bytes per individual value, 8,000,000 combined string/key characters/bytes, 32 nested levels, and 100,000 visited values and mapping keys. An over-limit operation returns `[REDACTED: safe processing limit exceeded]`; it never returns the original value or a partially redacted structure. Limits are intentionally not configurable in this phase.
- [external_reports.py](../../chinescan/core/external_reports.py): `_text` now removes disallowed control characters and redacts only the prefix that can be retained by that field. Per-field retained sizes remain unchanged (maximum 2,000 characters). JSON decoder recursion overflow is translated to the existing generic malformed-report error without echoing the input.
- [reporting.py](../../chinescan/core/reporting.py): report rendering now raises an actionable `ReportingError` when a finding or scan object cannot be safely redacted into the required report structure. The CLI/API render-before-write/attach behavior remains in place, so this does not return a partial report.
- [test_redaction.py](../../tests/unit/test_redaction.py), [test_code_actionability.py](../../tests/unit/test_code_actionability.py), [test_reporting.py](../../tests/unit/test_reporting.py), and [test_web_api.py](../../tests/unit/test_web_api.py): added performance-shape, long-value, aggregate/depth/node boundary, imported-report, malformed nesting, fail-closed report, and same-import surface checks.
- [DEVELOPMENT.md](../DEVELOPMENT.md): documented the shared redaction limits, scope, and failure behavior.

## D. Redaction correctness and performance results

Regression tests cover existing supported secret forms, nested sensitive keys, bearer and Argon values, paths, idempotence, long benign text, long synthetic-secret text, 2,000 repeated nested values, long sensitive key names, and below/at/above configured string, aggregate-character, nesting, and node boundaries. Limit tests assert that no synthetic value appears in the returned marker. A 20,000-level synthetic JSON body produces a generic `ExternalReportError`; the API regression verifies a 422 response without the canary or a traceback.

External report import preserves only bounded fields. The synthetic report test supplies a long description with a canary in the retained prefix, then checks redaction in persisted records, authenticated finding detail, API report responses, CLI detail, CLI JSON preview, and CLI full JSON. The dashboard’s existing Chromium finding-detail regression also verifies a synthetic persisted secret is displayed only as `password=[REDACTED]` and its raw value is absent. The browser suite passed after the redaction correction; this UI fixture is a persisted finding fixture, while the API/CLI import test exercises the imported-report record directly.

For unsupported oversized persisted finding text, API field serialization fails closed to the explicit limit marker. Full report rendering fails with `ReportingError` rather than returning malformed or partially redacted output. An imported oversized text tail is not persisted because `_text` clips before redaction and storage.

## E. CLI/API/dashboard/export consistency

The same authenticated synthetic external-report import was checked through:

| Surface | Result |
|---|---|
| CLI summary (`report --format json`) | Valid JSON; synthetic canary absent. |
| CLI detail (`report --format detail`) | Human-readable report; synthetic canary absent. |
| CLI JSON preview (`report --format json`) | Valid JSON summary/preview; synthetic canary absent. |
| CLI complete JSON (`report --format full-json`) | Valid JSON with no canary and no truncation for this small fixture. |
| Authenticated API finding detail | 200; safe description; canary absent. |
| Authenticated API complete report | 200; canary absent. |
| API Markdown preview | 200; markup escaped and no synthetic secret. |
| Dashboard finding detail | Chromium regression passed against the same API serialization logic; synthetic persisted secret remained redacted and inert. The browser fixture was not the imported-report record used by the CLI/API integration test. |

The shared serializer/redactor means surfaces consume the same sanitized stored data and normalized API values. Formatting differs by surface. A controlled persisted finding above the redaction limit was also tested directly: CLI returned exit code 2 with empty stdout; the authenticated API returned 422 without an attachment; neither response included the synthetic canary. The dashboard’s existing export-error handling consumes API error detail, but a browser test did not force this rare persisted-data condition.

The final backend integration suite verifies CLI/API report parity, JSON parsing, legacy records, redaction, and export behavior. Existing dashboard E2E coverage verifies report download and API error UI. No source file from the previously assessed application was available or rescanned.

## F. Remaining risks and limitations

The original validation report remains authoritative for issues outside this R1 remediation. Their current status is:

| Item | Current classification | Update |
|---|---|---|
| R1 redaction CPU risk | **Resolved for the reproduced mechanism** | Same-input benchmark improved substantially; import, redaction, report and browser regressions pass. This does not establish universal performance or overall product security. |
| R2 full export above caps | **Nonblocking limitation / deferred enhancement** | Exact 20 MiB renderer boundary is now exercised below, at, and above the cap (section G). The separate API HTTP status inconsistency (renderer `422` versus route guard `413`) and lack of cursor/bulk retrieval for already oversized scans remain. |
| R3 preview omission summary in dashboard | **Nonblocking limitation** | Dashboard still does not display omission totals before download; downloaded preview contains metadata. |
| R4 initial Chromium readiness timeout | **Unresolved, nonblocking** | The original timeout’s cause remains unknown. The full Chromium suite passed 14 tests during this work and the focused redaction/finding-detail browser tests passed; neither establishes the old timeout’s root cause. |
| R5 optional real scanner integrations | **Deferred / not validated** | Semgrep, Gitleaks, Trivy, YARA, and ClamAV executables are absent; the five integration tests skipped. |
| Remote or multi-user deployment | **Unsupported deployment requirement** | Loopback-only, single-operator assumptions remain. This task did not add remote exposure or tenant isolation. |
| Screen-reader / full accessibility review | **Deferred** | Automated browser and keyboard checks are not a manual screen-reader audit. |

The redactor is still a static heuristic scrubber, not a secret detector with complete format coverage. Fixed limits can cause explicit placeholder output or report errors for unusually large legacy values. The total-character limit is per top-level `redact` operation; import size and finding-count caps provide additional bounds at their respective entry points. No formal worst-case proof, load test, fuzzing campaign, or third-party security review was performed.

## G. Exact export-boundary and quality-gate results

The production JSON cap is `20 * 1024 * 1024` bytes of the renderer’s final UTF-8 JSON string: sorted keys, two-space indentation, `ensure_ascii=False`. A controlled local fixture contained 1,000 synthetic findings with bounded description strings. Its text was adjusted across four findings so every individual redacted string stayed under the shared 1,000,000-character limit while the complete serialized JSON reached the exact production byte count.

| Serialized renderer output | Configured cap | Outcome |
|---:|---:|---|
| 20,971,519 bytes | 20,971,520 bytes | Accepted |
| 20,971,520 bytes | 20,971,520 bytes | Accepted (inclusive) |
| 20,971,521 bytes | 20,971,520 bytes | `ReportingError`; no report string returned |

This validates the renderer’s real byte boundary after redaction was corrected. It does not test a 20 MiB response through the live API or an actual download. Earlier controlled API tests at lower patched caps verified no attachment on limit failure; the separate status mismatch remains noted under R2. The 10,000-finding production boundary was not rematerialized in this task; prior controlled patched-count boundary tests remain the evidence for inclusive count handling.

Commands and actual outcomes:

| Command | Outcome |
|---|---|
| `py -3.12 -m pytest --basetemp C:\redaction-final-release -q` | 626 passed, 5 deselected, 3 dependency deprecation warnings, 226.27 s. |
| `py -3.12 -m pytest tests/unit/test_redaction.py tests/unit/test_code_actionability.py tests/unit/test_reporting.py tests/unit/test_web_api.py -q --basetemp C:\redaction-final2` | 97 passed, 3 warnings, 23.73 s after the report failure-handling change. A later manual-scanner change was followed by a 38-test redaction/import run, the final full suite above, and focused Chromium checks. |
| `py -3.12 -m pytest tests/unit/test_redaction.py tests/unit/test_code_actionability.py -q --basetemp C:\redaction-manual` | 38 passed, 1.58 s after the final forward-scanner implementation. |
| `py -3.12 -m ruff check chinescan tests` | Passed after final changes. |
| `py -3.12 -m ruff format --check chinescan tests` | Passed; 133 files already formatted. |
| `py -3.12 -m mypy chinescan` | Passed; no issues in 84 source files. |
| `py -3.12 scripts/export_schemas.py` and `py -3.12 -m json.tool` on schemas and parity fixture | Passed; schemas unchanged by this remediation. |
| `npm test -- --run` (from `frontend`) | 12 files, 61 tests passed. |
| `npm run typecheck` and `npm run build` (from `frontend`) | Passed; production bundle built. |
| `npm run test:e2e -- --project=chromium-production` | 14 passed in 1.5 minutes during this remediation, before the final aggregate-limit refinement. |
| `npm run test:e2e -- --project=chromium-production --grep "production dashboard workflows|finding detail shows fixture data"` | 2 passed after the final redaction bounds and scanner changes. |
| `py -3.12 -m pytest --run-real-scanners -q -rs --basetemp C:\redaction-scanners tests/integration/test_real_scanners.py` | Five skipped because `semgrep`, `gitleaks`, `trivy`, `yara`, and `clamscan` are unavailable. No external integration was mocked and reported as passed. |
| `git diff --check` | Passed during final validation; rerun after report/inventory creation before delivery. |

The original validation’s offline dependency audit remains the only dependency evidence: its frontend audit used offline advisory state and its Python audit skipped the editable ChiNeScan distribution. No fresh advisory-network audit was performed here.

## H. Updated local-readiness recommendation

R1 is resolved for its reproduced input and affected shared redaction paths: measured benign-string redaction no longer exhibits the prior severe growth, long imported tails are not scanned when they will be discarded, existing secret formats remain covered by regression tests, and over-limit values fail closed. This supports use for local single-operator scans/imports within documented limits, subject to the remaining export and optional-integration limitations above. It is not a vulnerability-free claim or an unconditional release certification.

Remote or multi-user use remains unsupported and not ready. The loopback-only deployment and single-operator authorization model were not changed.
