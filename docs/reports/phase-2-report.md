# Phase 2: Rust ZIP/TAR File Analyzer Upgrade

## Outbound action ledger

| UTC date | Action | Destination | Data sent | Result |
| --- | --- | --- | --- | --- |
| 2026-11-10 | `cargo audit` from repository root | RustSec advisory database and crates.io index | Local invocation metadata only; no project data | Exit 1: advisory DB fetched, then command failed because root `Cargo.lock` is absent. |
| 2026-11-10 | `cargo install cargo-deny --locked` | crates.io | Public crate/dependency requests and Rust toolchain metadata; no project or sample data | Exit 0: installed cargo-deny 0.20.2. |
| 2026-11-10 | Rust dependency additions (`flate2` 1.1.5, `tar` 0.4.44 then 0.4.46, `proptest` 1.9.0) | crates.io index and crate downloads | Public crate names/versions only; no project source or samples | Updated locks. Initial `tar` version had two advisories; upgraded to 0.4.46 and rechecked clean. |
| 2026-11-10 | `uv lock`, `uv sync --locked --extra dev` | Python package index | Public package names/versions only; no project or sample data | Exit 0; resolved 77 packages and checked 75 packages in dev environment. |
| 2026-11-10 | `py -3.12 -m maturin build --release --manifest-path engine/Cargo.toml` | crates.io | Target-specific public Rust dependency requests only; no project or sample data | Exit 0; built Python 3.12+ abi3 wheel. |
| 2026-11-10 | `cargo install cargo-deny --locked`, Rust audit and deny checks | crates.io and RustSec advisory DB | Public dependency identifiers/versions and toolchain metadata only | Engine and fuzz `cargo audit` and `cargo deny check` passed; 60 engine dependencies and fuzz lock audited. |
| 2026-11-10 | `cargo check --locked` in `engine/fuzz` | crates.io | Public Rust dependency requests only | Exit 0; fuzz harnesses compile. `cargo fuzz --version` reports no such command; fuzz campaigns unavailable. |
| 2026-11-10 | `uv sync --locked --extra dev` and project-managed checks | Python package index | Public package names/versions only | `ruff`, mypy, and focused tests ran offline after dependency sync; no sample or source data transmitted. |

## Scope and decisions

Phase 1 is closed. This report covers only the Rust file analyzer, process isolation, archive findings, the two File Analyzer capability gaps, and required verification. Reporter, scoring, alerts, dashboard, and 3D UI are out of scope.

Native analysis is static and metadata-only. It does not execute samples, write archive entries, import samples, or make network requests. The Python integration uses an optional PyO3 module dispatched in a short-lived worker process. The worker has a five-second wall timeout and bounded input/output. Windows uses a verified Job Object memory limit and kills the worker on timeout; Windows does not provide Python `rlimit`. POSIX additionally applies CPU, address-space, and core-dump `rlimit`s. The Rust parser catches panics; process isolation is a second crash boundary.

## Implementation/results

- Added an unsafe-free Rust PyO3 engine for bounded ZIP metadata, TAR/TAR.GZ metadata, findings, and magic-signature mismatch inspection. Archive entries are never extracted or written to disk.
- Python dispatch is controlled by `CHINESCAN_RUST_ARCHIVE=auto|on|off`; missing native ZIP support falls back to the existing Python metadata reader, while unsupported native TAR is skipped with an explicit warning.
- Added stable rule IDs and findings for traversal names, duplicate entries, encrypted ZIP entries, high declared compression ratios, symlinks/link entries, nested-archive names, and suspicious double extensions.
- Added tested magic signatures for PE, ELF, PDF, ZIP, gzip, PNG, JPEG, and TAR. File Analyzer remains `partial`; the capability card identifies the formats and signatures still outside tested coverage. Malware triage remains static; no dynamic analysis is performed.

### Verification

- Rust engine: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --locked` passed. 54 tests passed, including proptests.
- Rust dependency policy: `cargo audit` and `cargo deny check` passed for engine and fuzz locks. `cargo check --locked` in `engine/fuzz` passed. Fuzz campaigns could not run because `cargo-fuzz` is not installed.
- Python targeted tests: `uv run --extra dev pytest tests/unit/test_malware_analysis.py tests/unit/test_managed_malware.py -q` passed: 58 passed, 3 skipped. Project-managed Ruff and mypy passed.
- Frontend: `npm run build` passed; `npm test -- --run` passed: 12 files, 63 tests.
- Full Python suite earlier in Phase 2: 669 passed, 5 deselected, 9 failed. Eight failures were in behaviors within the already-modified `tests/unit/test_chain_trace.py`; the only change permitted here was its `cimport json` typo. One GitHub import test failed with `path_too_long` in the Windows temp path. The full suite was not rerun after the final focused edits.
- System-wide `py -3.12 -m mypy chinescan` does not see `types-PyYAML` because that interpreter is outside the project dev environment. `uv run --extra dev mypy chinescan` passed with the locked dependency.

## Remaining partial scope

Archive support is ZIP/TAR/TAR.GZ only; encrypted entry contents are intentionally not inspected. Magic detection is a finite tested table, not a comprehensive file identification engine. Executable static inspection, document/script triage, YARA-compatible rules, broad archive formats (7z, gzip, bz2, xz), nested archive recursion, and dynamic analysis remain unimplemented. Parser fuzz targets are present and compile, but have not received fuzz campaigns in this environment.
