# Optional Rust redaction engine

The Rust engine is an independent Python extension package. The main ChiNeScan
distribution continues to use Hatchling and does not require the engine. The
Python bridge imports `chinescan_engine` only when available and retains the
existing pure-Python redactor for installations without the wheel.

## Redaction behavior and implementation

The implementation follows the current Python string redaction sequence. Fixed
regular expressions are compiled once as `LazyLock<Regex>` values in
`engine/src/redact.rs`; boundary rules that use lookaround in Python are scanned
linearly because the Rust `regex` crate intentionally does not support lookaround.

| Rule | Behavior | Rust location |
|---|---|---|
| Sensitive assignments | Detects password, passwd, pwd, hash, token, secret, API key, authorization, cookie, session, CSRF, and credential key fragments; supports `:` and `=`, quoted keys and values, angle values, and unquoted values. | `is_sensitive_key`, `redact_assignments`, `assignment_value_end` |
| Argon2 strings | Replaces `$argon2id$`, `$argon2i$`, and `$argon2d$` values up to whitespace, quote, or `}`. | `ARGON` |
| Bearer values | Replaces case-insensitive `Bearer` values using Python word-boundary, whitespace, and token rules. | `replace_bearer_values` |
| Environment paths | Replaces the configured user, temp, app-data, and ChiNeScan path roots case-insensitively. | `replace_env_paths`, `env_pattern` |
| Quoted Windows paths | Preserves the original quote while replacing drive and UNC paths with `[PATH]`. | `replace_quoted_windows_paths` |
| Windows paths | Replaces drive and UNC paths when the preceding character is not a Python-style word character. | `replace_windows_paths`, `is_python_word` |
| POSIX paths | Replaces paths under `/Users`, `/home`, `/root`, `/tmp`, `/var/tmp`, `/private/tmp`, `/var/folders`, `/etc`, `/opt`, and `/mnt`, with Python-compatible prefix boundaries. | `replace_posix_paths`, `posix_root_end` |
| Token runs and hashes | Redacts 32+ ASCII token runs with at least two character classes; preserves valid UUIDs and 32+ hexadecimal digests. | `redact_token_runs`, `is_uuid`, `is_hex` |
| Processing limit | Counts Unicode scalar values like Python `len(str)`; over-limit input returns the identical safe-processing marker. | `engine/src/limits.rs`, `redact_text` |

The engine only processes text supplied by the caller. It does not read files,
execute input, access the network, or redact caller-owned location and line
number fields specially.

## Static archive and magic-byte analysis

The optional extension exposes `inspect_zip_metadata(data: bytes) -> dict`,
`inspect_tar_metadata(data: bytes, compressed: bool) -> dict`, and
`identify_file_type(data: bytes, extension: str) -> dict`. The Python analyzer
dispatches recognized ZIP, TAR, TAR.GZ, and known magic signatures through a
short-lived worker when `CHINESCAN_RUST_ARCHIVE` is `auto` (default) or `on`.
Use `off` to force the existing Python ZIP fallback. If the extension is missing,
ZIP falls back to that bounded metadata-only parser; TAR/TAR.GZ report a safe
skip because no existing Python malware-analysis path covered those formats.

The worker accepts at most 64 MiB and emits at most 3 MiB. It runs with a
5-second deadline. On Windows it is created suspended, assigned to the existing
verified Job Object (512 MiB process memory, 768 MiB job memory, process count
limit), then resumed; timeout terminates the Job Object. POSIX uses CPU, address
space, and core-dump `rlimit`s. Archive entries are never written to disk or
executed. ZIP/TAR parsers cap entries at 1,000, names at 4 KiB, and declared or
expanded aggregate size at 64 MiB. TAR.GZ is expanded in memory only to a capped
buffer before header iteration.

Findings include stable IDs, rule IDs, severity, confidence, entry path, and an
explanation for traversal/absolute names, duplicate paths, encrypted ZIP
entries, compression-ratio heuristics, symlink/hardlink entries and escaping
link targets, nested-archive names, and suspicious double extensions. The magic
table covers PE, ELF, PDF, ZIP, gzip, PNG, JPEG, and TAR. It classifies signatures
only; it does not establish authenticity or trust. ZIP64 and multi-disk ZIP are
unsupported, nested archives are named but not opened, encrypted contents are
not inspected, and the signature table is intentionally incomplete. The File
Analyzer remains `partial` with these limits listed on the Modules page.

## Python selection and fallback

`CHINESCAN_ENGINE` accepts `auto`, `python`, or `rust` (the default is `auto`).
In `auto`, the bridge uses Rust when importable and Python otherwise. `python`
forces the pure-Python implementation. `rust` requires the extension and raises a
clear `RuntimeError` when it is missing; a native exception is re-raised in that
mode. In `auto`, a native exception triggers the Python path and one warning
without input text. `redaction.engine_in_use()` reports the selected path.

The Rust Python API is `redact_text(text: str) -> str` and
`engine_info() -> {version, api_version, regex_crate}`. Inputs of 64 KiB or more
are processed with the GIL released. The recursive mapping, sequence, byte, node,
and total-character behavior remains in Python.

The Docker runtime image is unchanged and does not install the optional engine.
With the default `auto` mode, that image selects the existing Python fallback;
the existing Python quality job also runs without the engine wheel.

## Build and verify

Run from `engine/` after setting `PYO3_PYTHON` to a Python 3.12 executable:

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo install cargo-audit --version 0.22.0 --locked
cargo audit
py -3.12 -m maturin build --release
Set-Location ..
py -3.12 -m pip install --force-reinstall (Get-ChildItem engine\target\wheels\chinescan_engine-*.whl | Select-Object -First 1 -ExpandProperty FullName)
py -3.12 -m pytest tests/unit/test_redaction.py tests/unit/test_redaction_parity.py -q -rs
```

Set `$env:CHINESCAN_ENGINE = "rust"` to require and exercise the extension, or
`"python"` to force the fallback path before running the test command.

An `engine/Cargo.lock` from the earlier scaffold already exists and was left
untouched. It currently resolves different `pyo3` and `regex` releases than the
exact pins in `engine/Cargo.toml`. The owner's first successful Cargo resolution
should refresh and review that lock, then commit it. CI generates a fresh lock
before auditing dependencies.

No performance improvement claim is made here. The owner should run
`scripts/bench_redaction.py` and record the measured numbers before making one.
