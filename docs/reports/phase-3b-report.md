# Phase 3b: Reporter Baseline, SARIF Schema, and Detached Signatures

## Baseline comparison

The Phase 3 final Python run had these 10 failing tests:

1. `tests/unit/test_chain_trace.py::test_evm_provider_sends_v2_chainid_and_maps_error_payloads`
2. `tests/unit/test_chain_trace.py::test_evm_provider_success_pagination_and_malformed_rows`
3. `tests/unit/test_chain_trace.py::test_evm_provider_429_timeout_and_json_errors_become_gaps`
4. `tests/unit/test_chain_trace.py::test_evm_provider_redirect_policy_and_secrets_stay_inside_request_layer`
5. `tests/unit/test_chain_trace.py::test_api_key_url_encoded_form_in_provider_data_becomes_gap`
6. `tests/unit/test_chain_trace.py::test_stdlib_adapter_same_host_redirect_keeps_key_out_of_urls`
7. `tests/unit/test_chain_trace.py::test_service_persists_audit_and_running_scan_before_provider_call`
8. `tests/unit/test_chain_trace.py::test_etherscan_error_reason_is_redacted_before_persistence`
9. `tests/unit/test_github_import.py::test_api_preview_then_import_job_is_session_bound_and_path_free`
10. `tests/unit/test_parser_hardening.py::test_log_oversized_input_returns_bounded_error`

Phase 2's `docs/reports/phase-2-report.md` records 9 failures as eight in the already-modified chain-trace tests and the known Windows GitHub `path_too_long` test. It did not list individual test names. The eight chain-trace names and GitHub import case are the shared failures. The extra Phase 3 failure is `test_log_oversized_input_returns_bounded_error`.

That extra test was run from a clean worktree at Phase 2 commit `d761f81` using `git worktree add --detach .worktrees/phase2-extra d761f81`. It failed there too: the generated error string length was 206 while the test expects less than 200. This is not a Phase 3 regression. The temporary worktree was removed afterward. `tests/unit/test_chain_trace.py` was not changed.

## SARIF schema validation status

The requested operator fixture path `core/reporter/tests/fixtures/sarif-schema-2.1.0.json` was checked and was absent from this checkout (`Test-Path` false; no matching file in repository file enumeration). No schema was fetched. The SARIF tests continue to check 2.1.0 structure and hostile string rendering only; they do not claim full official-schema validation. The user indicated they will provide the schema. Once present, an offline validator test remains to be added and run.

## Outbound action ledger

| Date | Action | Destination | Data sent | Result |
| --- | --- | --- | --- | --- |
| 2026-11-10 | `cargo add ed25519-dalek@=2.2.0` | crates.io index | Public crate name/version and local Rust toolchain metadata only; no source, scan, report, key, or sample data | Exit 0; locked ed25519-dalek 2.2.0 and 18 transitive packages. |
| 2026-11-10 | `cargo test --workspace --locked` and `maturin build` for new crypto dependencies | crates.io crate downloads | Public crate names/versions only; no repository contents or operator data | Fetched locked Ed25519/dalek dependencies and built the abi3 wheel. |
| 2026-11-10 | `cargo audit` | RustSec advisory database and crates.io index | Locked crate identifiers and versions only | Passed; scanned 94 dependencies, no vulnerability output. |
| 2026-11-10 | `cargo deny --offline check`, Rust/Python/frontend checks | Local caches and tools | No outbound data | Deny passed after allowing BSD-3-Clause for the audited Ed25519 dependency tree. |

## Implementation

- Added detached Ed25519 signing, public-key derivation, and verification via `ed25519-dalek` 2.2.0 and the isolated PyO3 worker. The key seed is sent to the short-lived worker over stdin, never as an argument or environment variable; worker errors and logs do not contain key contents.
- `CHINESCAN_REPORT_SIGNING_KEY` can point to a local raw 32-byte seed. `sign_report_detached` returns a detached hex signature; `report_public_key` returns the corresponding hex public key; `verify_report_detached` verifies a report and signature using a supplied public key.
- Missing keys, non-regular files, invalid seed lengths, unavailable ACL inspection, and overly broad permissions fail with explicit errors. POSIX rejects group/world access bits. Windows checks `icacls` ACEs against the current operator and permits only that operator, SYSTEM, and Administrators. Signatures are detached from report content.
- Tests cover correct verification, modified report rejection, wrong-key rejection, missing key, and too-permissive permissions. Rust test suite has a cryptographic tamper/wrong-key test; Python integration covers isolated-worker signing and verification.

## Key storage and rotation

Store the raw 32-byte seed outside the repository in a local private configuration directory. On POSIX, create it with owner-only permissions (`0600`). On Windows, disable inherited ACLs and grant the current operator plus SYSTEM (Administrators may be granted if required by local recovery policy); the runtime rejects other principals. Do not place seeds in command arguments, environment variables, logs, reports, source control, or backups without encryption. The environment variable contains only the local path.

For rotation, generate a new random seed locally, restrict its ACL before use, derive and distribute the new public key through the local trust process, then sign new reports with the new seed. Keep prior public keys to verify historical reports. Retire and securely remove old private keys under the platform's local key-handling policy. Never reuse a seed across installations.

## Verification

- Final full Python suite: **671 passed, 5 deselected, 10 failed in 337.04s**; failures exactly match the ten baseline cases above.
- `tests/unit/test_reporting.py`: **19 passed** including native worker signing, tampered report, wrong key, missing key, and permission rejection.
- Rust: `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo test --workspace --locked` passed (55 engine tests, 6 reporter tests, including hostile SARIF text as JSON data).
- RustSec `cargo audit` passed on 94 dependencies. `cargo deny --offline check` passed.
- Project Ruff and mypy passed. Frontend build passed; 12 files and 63 tests passed.
- Native extension rebuilt from the locked workspace and installed locally without pip network access.

## Remaining work

The operator-supplied SARIF schema is absent from the specified path. Full schema validation cannot be completed until that local fixture is present. No network fetch was made. Vulnerability Reporter remains partial; complete language coverage and comprehensive vulnerability analysis remain not assessed.
