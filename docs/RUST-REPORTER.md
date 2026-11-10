# Rust Reporter Core

The `chinescan-common` and `chinescan-reporter` crates share serde schemas and render bounded report requests. The PyO3 entry point is called only by the existing short-lived worker; it enforces the 16 MiB request limit, catches panics, and does not receive file paths or sample bytes. Python redacts findings before serialization and falls back to its existing renderer if the extension/API is unavailable or fails. Set `CHINESCAN_RUST_REPORTER=on` to opt in; default is off for compatibility.

Supported native formats are JSON, CSV, Markdown, standalone HTML, and SARIF 2.1.0. JSON carries a SHA-256 manifest over the report body with an empty manifest field. CSV has a manifest column, HTML a `report-sha256` meta element, and Markdown a trailing comment. HTML escapes values, contains no scripts, and has a restrictive CSP meta policy. CSV cells starting with `=`, `+`, `-`, or `@` receive an apostrophe prefix.

Fingerprints are SHA-256 of lowercased rule ID, slash-normalized and whitespace-normalized location, and whitespace-normalized lowercased evidence, separated by NUL bytes. Diff states use those fingerprints. CVSS v3.1 scores are computed from supplied vectors and retained with the vector. EPSS and KEV fields are accepted only from a local operator file named by `CHINESCAN_REPORTER_LOCAL_DATA`; supported JSON keys are `cwe`, `epss_by_rule`, and `kev_rules`. There is no network fetch. CWE labels come from that same local catalog. The file is capped at 2 MiB and fields are type/length checked.

## Signing key storage

Detached Ed25519 signing is not implemented. If added later, the private key must remain outside the repository and reports, use an OS-protected local keystore or restrictive owner-only ACLs, and never be included in worker arguments, logs, or report output. Windows filesystem ACLs, not POSIX mode bits, must enforce access control.

## Limits

The SARIF exporter emits a 2.1.0 structure and advertises the OASIS schema URL. An official-schema validator and schema fixture are not included because no local schema was available and Phase 3 permits no outbound fetch other than `cargo audit`. Tests check core version/shape only and do not prove full official-schema validity. Complete language coverage and comprehensive vulnerability analysis remain not assessed. Local intelligence is optional and only applies when the operator supplies a valid catalog file. No report signature is produced.
