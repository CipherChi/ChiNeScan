# Phase 4: Dashboard Scores and Alerts

## Scope and branch

- Branch: `codex/dashboard-scores-alerts`, created from `codex/rust-reporter` at the Phase 3b commit.
- Added the Rust scoring and alert-rule crates and exposed them through the existing short-lived isolated worker.
- No Rust backend listener or remote service was added. No module status changed; Security Dashboard remains `partial`.
- The Security Dashboard capability now reports its Alerts panel and per-module scores as assessed. Its other dashboard limitations remain as documented by the capability data.

## Scoring

Scores range from 0 to 100 and use the following transparent formula:

```text
clamp(round(100 - Σ(severity weight × confidence × 2^(-age_days/60))
               - 50 × (1 - completed_checks/total_checks)), 0, 100)
```

Severity weights are critical 40, high 25, medium 14, low 6, and info 2. Finding age uses a 60-day half-life; confidence is clamped to 0–1. The coverage penalty can remove up to 50 points. Each response contains the score inputs, per-finding penalty breakdown, formula, completed and total checks, not-assessed count, and a plain-language explanation. Modules with no completed checks return `score: null` and “Not scored.” Malware Triage completed assessments and verdict severity are included in its score.

## Alerts and persistence

- Rule IDs: `new_critical_finding`, `malware_triage_hit`, `scan_failure`, `authorization_guard_block`, and `repeated_auth_failures`.
- Duplicate source events retain one alert, increase its occurrence count when a repeated event is observed, and append a `deduplicated` audit event. Routine refreshes of persisted findings do not count as new occurrences.
- Alert states are open, acknowledged, snoozed, and resolved. Snooze duration is limited to one minute through 30 days.
- Migration `0004_dashboard_alerts` adds `dashboard_alerts` and `dashboard_alert_audit`. SQLite triggers reject audit updates and deletes. The recovery verifier accepts this schema revision and still rejects unrelated table layouts.
- Alert and score endpoints use the existing authenticated app middleware, CSRF validation on writes, loopback/origin protections, and request rate limits.
- The SSE endpoint emits audit IDs and rechecks the session. The UI reconnects with the last event cursor and bounded exponential backoff.

## Dashboard hardening and accessibility

- The existing response policy keeps scripts to `'self'`, has no `unsafe-inline` or `unsafe-eval` in `script-src`, and the served HTML contains no inline script. Existing `style-src 'unsafe-inline'` remains for the app’s current dynamic styling.
- Login cookies use `SameSite=Strict`; existing loopback-only startup, idle and absolute session expiry, and `secrets.compare_digest` CSRF comparison are covered by regression tests. New tests verify SameSite, CSP script policy, absence of inline scripts, constant-time comparator use, unauthenticated score/alert/SSE access, and CSRF rejection for alert writes.
- Score links and alert actions use native buttons. The score links and alert action controls have 44px minimum heights, and the app’s existing global `:focus-visible` rule applies. Tests activate navigation with Enter and Space.
- The dashboard component tests cover score explanation rendering. Existing page tests cover the established dashboard and keyboard-accessible controls.

## Verification results

Commands were run from the repository root (or the dashboard-scores-alerts worktree) unless noted.

| Command | Result |
| --- | --- |
| `py -3.12 -m pytest -q --tb=short` | **713 passed, 5 deselected, 2 failed** in 589.92s. The failures are the same Phase 3b baseline failures: `tests/unit/test_github_import.py::test_api_preview_then_import_job_is_session_bound_and_path_free` (`path_too_long` on Windows) and `tests/unit/test_parser_hardening.py::test_log_oversized_input_returns_bounded_error` (message length 206; test expects <200). |
| `py -3.12 -m pytest tests/unit/test_dashboard_alerts.py tests/unit/test_dashboard_scores_alerts_api.py tests/unit/test_migration.py tests/unit/test_storage.py tests/unit/test_recovery.py tests/unit/test_managed_malware.py -q --tb=short` | **63 passed**. |
| `py -3.12 -m ruff check .` | Passed. |
| `py -3.12 -m mypy chinescan` | Passed: no issues in 90 source files. |
| `py -3.12 -m pip_audit` | No known vulnerabilities found. The local `chinescan` and `chinescan-engine` projects are not published on PyPI and were skipped by the index lookup. |
| `cargo fmt --all -- --check` | Passed. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed. |
| `cargo test --workspace --locked` | Passed: 65 tests (2 alerts, 55 engine, 6 reporter, 2 scoring); no failures. |
| `cargo audit` | Passed: scanned 96 locked crate dependencies; no advisories. |
| `cargo deny --offline check` | Passed: advisories, bans, licenses, and sources checks. |
| `py -3.12 -m maturin build --release --locked --manifest-path engine/Cargo.toml` | Passed; built `chinescan_engine-0.1.0-cp312-abi3-win_amd64.whl`. |
| Isolated worker smoke check | Passed: 1 of 2 checks scored 75, reported 1 not assessed, included the severity weights in the formula, and returned `new_critical_finding` for a critical signal. |
| `npm test` (in `frontend`) | Passed: 13 test files, 64 tests. |
| `npm run build` (in `frontend`) | Passed. Vite output: JS 366.65 kB (102.03 kB gzip), CSS 35.88 kB (8.96 kB gzip). |
| `npm ci` (in `frontend`) | Passed; 107 packages audited, 0 vulnerabilities reported. |

The full Python suite emitted existing pytest cleanup warnings for temporary Windows directories (`WinError 145`) and dependency deprecation warnings. These did not alter the two failing test results.

The full-suite run preceded the final explicit score-input echo and unavailable-worker breakdown. Those changes were verified afterward by the focused dashboard, migration, recovery, and security tests (63 passed), plus the final Rust and frontend suites.

## Commits

- `8cadd5e` — Add isolated Rust scoring and alert rules
- `beadae6` — Persist scores and secure dashboard alerts API
- Final commit — Add accessible dashboard score and alert panels (includes this report)

No push was performed.
