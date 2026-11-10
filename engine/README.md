# chinescan-engine

Optional PyO3 extension for ChiNeScan redaction and bounded static file metadata.
The main Python distribution remains usable without the wheel. ZIP/TAR/TAR.GZ
parsing is only called in a short-lived containment worker when the feature flag
`CHINESCAN_RUST_ARCHIVE=auto` (default) or `on` is active. Use `off` to force the
existing Python ZIP metadata path. Missing native code falls back for ZIP and
returns a clean unavailable warning for TAR/TAR.GZ.

Set `PYO3_PYTHON` to Python 3.12 before building the wheel. Cargo dependencies
are exact-pinned in `Cargo.toml` and `Cargo.lock`.

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo audit
cargo deny check
py -3.12 -m maturin build --release
```

The parser caps its input at 64 MiB, entries at 1,000, names at 4 KiB, and
aggregate declared/expanded archive size at 64 MiB. ZIP entries are inspected
from central-directory metadata without decompression. TAR.GZ is expanded to a
bounded in-memory buffer only; no archive path is written to disk. The Python
bridge applies a 5-second deadline and the existing Windows Job Object or POSIX
`rlimit` controls. Windows uses the verified memory/process limits already
implemented for local malware workers; POSIX gets CPU, address-space, and
core-dump limits. Neither parser runs samples or contacts the network.

Property tests use inert arbitrary byte strings and synthetic archives:

```powershell
cargo test --locked
cargo check --manifest-path fuzz/Cargo.toml --locked
cargo fuzz run zip_metadata
cargo fuzz run tar_metadata
```

The last two commands require `cargo-fuzz`, which is not bundled with Cargo.
Fuzz seeds should remain synthetic and must not contain malware samples.
