# Rust Reporter Core

The `chinescan-common` and `chinescan-reporter` crates share serde schemas and render bounded report requests. The PyO3 entry point is called only by the existing short-lived worker; it enforces request size limits, catches panics, and does not receive report file paths or sample bytes. Python redacts findings before serialization and falls back to its existing renderer if the extension/API is unavailable or fails. Set `CHINESCAN_RUST_REPORTER=on` to opt in; default is off for compatibility.

Supported native formats are JSON, CSV, Markdown, standalone HTML, and SARIF 2.1.0. JSON carries a SHA-256 manifest over the report body with an empty manifest field. CSV has a manifest column, HTML a `report-sha256` meta element, and Markdown a trailing comment. HTML escapes values, contains no scripts, and has a restrictive CSP meta policy. CSV cells starting with `=`, `+`, `-`, or `@` receive an apostrophe prefix.

Fingerprints are SHA-256 of lowercased rule ID, slash-normalized and whitespace-normalized location, and whitespace-normalized lowercased evidence, separated by NUL bytes. Diff states use those fingerprints. CVSS v3.1 scores are computed from supplied vectors and retained with the vector. EPSS and KEV fields are accepted only from a local operator file named by `CHINESCAN_REPORTER_LOCAL_DATA`; supported JSON keys are `cwe`, `epss_by_rule`, and `kev_rules`. There is no network fetch. CWE labels come from that same local catalog. The file is capped at 2 MiB and fields are type/length checked.

## Detached signatures

`sign_report_detached(content)` signs report text and returns a detached hex signature. `report_public_key()` derives the matching hex public key. `verify_report_detached(content, signature_hex, public_key_hex)` verifies it. The signing seed is a local raw 32-byte file configured with `CHINESCAN_REPORT_SIGNING_KEY`. Signing and verification use the isolated worker; the key seed is passed on worker stdin, never as an argument or environment value. The API does not automatically publish or persist reports or signatures; the caller stores the returned signature as a separate `.sig` file.

The signer rejects missing files, non-regular files, invalid seed lengths, and permissions it cannot verify. On POSIX it requires no group/world access bits (normally mode `0600`). On Windows it checks `icacls` and allows only the current operator, SYSTEM, and Administrators; other ACEs cause signing to fail. Do not put private seeds in the repository, reports, logs, command arguments, or backups without encryption. Configure the environment variable with the key path, not the key value.

For rotation, create a new random seed in a local private configuration directory, set restrictive permissions before use, derive and distribute its public key through the local trust process, and use the new seed for subsequent reports. Retain old public keys for historical signature verification. Retire old private keys according to the local platform key-handling policy. Do not reuse a seed across installations.

## Limits

The SARIF exporter emits a 2.1.0 structure and advertises the OASIS schema URL. The operator fixture requested at `core/reporter/tests/fixtures/sarif-schema-2.1.0.json` was not present in this checkout. No network fetch was made. Tests check core version/shape only and do not prove full official-schema validity; an offline fixture-backed schema test remains pending the file. Complete language coverage and comprehensive vulnerability analysis remain not assessed. Local intelligence is optional and only applies when the operator supplies a valid catalog file.
