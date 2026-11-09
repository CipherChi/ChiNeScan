# chinescan-engine

Optional PyO3 extension for ChiNeScan text redaction. This package is built
separately from the main `chinescan` distribution; installing the main project
does not require Rust or this wheel.

Set `PYO3_PYTHON` to Python 3.12 before running Cargo. The crate defaults to
linkable test features; maturin enables the extension-module feature for wheel
builds.

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
py -3.12 -m maturin build --release
```

See `../docs/RUST-ENGINE.md` for Python selection, parity behavior, limits, and
installation guidance. The existing lockfile needs a refresh against the exact
manifest pins and should be reviewed and committed after the owner's first
successful dependency resolution.
