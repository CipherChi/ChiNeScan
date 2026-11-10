# Phase 3: Rust Vulnerability Reporter

## Baseline before changes

Command: `uv run --extra dev pytest -q`

Result on branch `codex/rust-zip-metadata` before Phase 3 source changes: **660 passed, 9 skipped, 5 deselected, 10 failed in 394.07s**. The failures were eight existing failures in `tests/unit/test_chain_trace.py`, the known Windows `path_too_long` failure in `tests/unit/test_github_import.py::test_api_preview_then_import_job_is_session_bound_and_path_free`, and one additional failure in `tests/unit/test_parser_hardening.py::test_log_oversized_input_returns_bounded_error`. No Phase 3 change has been made to `tests/unit/test_chain_trace.py`; its pre-existing working-tree diff was preserved.

## Outbound action ledger

No outbound network actions have been taken in Phase 3. The only permitted network exception is `cargo audit`; any invocation will be recorded here.

## Scope and plan

Add reporter/common Rust crates under the existing engine workspace, call them through the isolated worker boundary, and retain the existing Python exporter as an explicit fallback. Export JSON, CSV, Markdown, escaped standalone HTML and SARIF; fingerprint and diff findings; compute CVSS v3.1; accept optional local EPSS/KEV inputs; include integrity metadata and optional detached local signing only if the installed, locked dependency set allows it without unapproved network access. Preserve module status `partial` and keep complete language coverage and comprehensive vulnerability analysis listed as not assessed.

## Implementation and verification

Pending.
