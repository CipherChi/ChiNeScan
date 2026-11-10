# Phase 3: Rust Vulnerability Reporter

## Baseline before changes

Command: `uv run --extra dev pytest -q` on `codex/rust-core-zip-metadata`, before Phase 3 edits.

**660 passed, 9 skipped, 5 deselected, 10 failed in 394.07s.** Failures: eight existing cases in `tests/unit/test_chain_trace.py`, the known Windows `path_too_long` GitHub import test, and `tests/unit/test_parser_hardening.py::test_log_oversized_input_returns_bounded_error`. The chain-trace file was not edited during Phase 3; its pre-existing working-tree change remains untouched.

## Outbound action ledger

| Date | Action | Destination | Data sent | Result |
| --- | --- | --- | --- | --- |
| 2026-11-10 | `cargo audit` in `engine/` | RustSec advisory database and crates.io index | Public package identifiers and versions from `engine/Cargo.lock`; no source, scan, report, or sample data | Passed; loaded 1,430 advisories and scanned 76 dependencies with no vulnerability output. |
| 2026-11-10 | Cargo format, Clippy, tests, and deny; maturin wheel build with `--offline`; uv/npm tests | Local tools/cache only | No outbound data | No package or schema fetch. `cargo deny --offline check` passed. |

## Scope and architecture

Added workspace crates `chinescan-common` and `chinescan-reporter`. The `chinescan_engine.render_report_json` PyO3 entry point is reachable only through the existing short-lived process worker, with a 16 MiB request cap, bounded response handling, timeout/containment inherited from the Phase 2 worker, and panic containment. Python redacts data before dispatch. `CHINESCAN_RUST_REPORTER=on` opts into native rendering; the default is off so existing Python exports remain the compatibility path. Missing extension, API, or worker result falls back to Python.

The common crate defines serde `Finding`, `Severity`, `Evidence`, and `ScanMetadata` types. Native exports support JSON, CSV, Markdown, self-contained HTML, and SARIF 2.1.0. Fingerprints use SHA-256 over lowercased rule ID, normalized location, and normalized evidence. Current-vs-previous findings are classified new, persisting, or fixed. JSON carries a SHA-256 manifest; CSV includes a manifest column; HTML includes a manifest meta element; Markdown includes a comment manifest.

CVSS v3.1 base scores are computed and retained with supplied vectors. Tests include two FIRST-style reference vectors (9.8 and 7.5). CWE labels and optional EPSS/KEV fields can be supplied by a bounded local JSON file selected with `CHINESCAN_REPORTER_LOCAL_DATA`; no network lookup exists. Supported keys are `cwe`, `epss_by_rule`, and `kev_rules`. CSV prefixes values beginning with `=`, `+`, `-`, or `@`. HTML escapes report values, emits no scripts, and uses a restrictive CSP meta policy.

The Vulnerability Reporter card remains `partial`. “Complete language coverage and comprehensive vulnerability analysis” remains listed as not assessed, alongside official SARIF schema validation, local intelligence catalog import, and detached signing limitations.

## Verification

- Full Python suite on final default-off configuration: **670 passed, 5 deselected, 10 failed in 359.03s**. All ten failures match the baseline set: eight chain-trace cases, one known Windows `path_too_long` GitHub import case, and the parser-hardening oversized-input case. No reporter tests failed.
- Reporter focused suite before the final opt-in default adjustment: 18 passed; final full suite covers reporter and did not report new reporter failures. Additional native/fallback tests: 3 passed.
- Rust: `cargo fmt --check`, `cargo clippy --workspace --all-targets --offline -- -D warnings`, and `cargo test --workspace --offline --locked` passed; engine 54 tests and reporter 5 tests passed.
- `cargo audit` passed against 76 locked dependencies. `cargo deny --offline check` passed.
- Python project Ruff and mypy passed. Frontend production build passed; 12 frontend test files and 63 tests passed.
- Built the abi3 wheel with maturin offline and exercised an HTML render through the isolated worker, checking hostile-title escaping and CSP.

## Remaining partial scope and limits

The official OASIS SARIF JSON schema was not available in the local workspace/cache. Phase 3 prohibits outbound fetches except `cargo audit`, so no schema download occurred. Current SARIF tests check 2.1.0 version/core structure only; full official schema validation is not claimed. Detached Ed25519 signing is not implemented. If added later, key storage must use an OS-protected local keystore or restrictive owner-only ACLs, never repository files, worker arguments, logs, or reports. Complete language coverage and comprehensive vulnerability analysis remain unassessed. Optional EPSS/KEV enrichment requires an operator-provided local file.
