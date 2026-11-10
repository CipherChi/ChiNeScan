# Rust core threat model and current limits

## Scope and trust boundaries

The current service accepts operator-selected local project and sample paths, runs Python orchestration, stores records in local SQLite, and serves an authenticated loopback dashboard. The optional `engine/` PyO3 extension currently performs bounded text redaction only. It is not yet the parser backend described in `docs/rust-core-plan.md`.

### STRIDE summary

| Surface | Threat | Current control / remaining work |
| --- | --- | --- |
| PyO3 bridge | Malformed or oversized arguments; panic crossing FFI | Existing redaction is bounded and covered by parity tests when the extension is installed. The ZIP central-directory metadata function is exposed with a 64 MiB input cap and `catch_unwind`; it returns bounded names/warnings without extraction. It still lacks process isolation and is not wired into the Python analyzer, which retains its existing parser. |
| File parsers | Crafted archive/binary/document inputs exploit parser bugs or exhaust resources | Existing Python analyzer bounds sample size, ZIP entry count, and nested ZIP inspection, and never extracts or executes. The new Rust ZIP metadata function also has a 64 MiB cap, 1,000-entry cap, 4 KiB name cap, bounds checks, and panic containment, but the analyzer does not yet call it and it lacks process isolation. Therefore this does not satisfy the requested Rust-only parser boundary. Multiple archive/document formats remain unsupported. |
| Archive metadata | Path traversal, duplicate entries, links, encrypted payloads, compression bombs, nested bombs | Current ZIP metadata inspection tests traversal, nested ZIPs, encryption markers, and bounds. It does not establish the broader zip/tar/tar.gz/7z/gzip/bz2/xz coverage in the prompt, nor all link and ratio checks. |
| Python/Rust boundary | Sample-controlled strings, paths, hashes, or errors leak in logs or become executable UI content | Existing result models keep paths out of repr and render evidence as text in the UI. Native parser outputs still need schema validation and redaction review before use. |
| Dashboard/API | Unauthenticated access or CSRF to scans, evidence, reports, and job controls | Existing session authentication, CSRF dependencies, login throttling, and authorization checks remain authoritative. This change adds no endpoint, listener, or network behavior. Full requested CSP/SameSite/session-timeout review remains separate work. |
| Local persistence | Unauthorized or cross-operator records; migration corruption | Reuse the existing SQLite and repository layer for future alert/score persistence. No schema migration is introduced here. |
| Rule files | Malicious or pathological local YARA rules consume resources | YARA-X integration is not implemented. Any future compiler must accept operator-local files only and use a timeout and resource limits. |
| Reporting | HTML injection, forged or modified report contents | Existing report outputs are not being changed by this stage. Self-contained CSP HTML, SARIF, stable diff fingerprints, and signatures need independent tests before claims are made. |
| Supply chain | Vulnerable or unreviewed native parser dependencies | Current Cargo lock is retained. `cargo-deny` is unavailable in this environment; no dependency additions are considered audited by this plan. |

## Non-negotiable parser behavior

- Static analysis only. Samples must not be executed, loaded, imported, dynamically linked, extracted, or uploaded.
- Archive members are metadata-inspected in memory; never materialize entries to disk.
- Parser inputs and outputs need hard size, count, depth, and time limits. Untrusted parser calls need a panic boundary; process isolation remains necessary for parser crates with nontrivial attack surface.
- Rule and reputation data must be operator-supplied local files. No network retrieval is allowed by default.
- Keep paths and hashes out of logs unless explicitly necessary and safely redacted.
- Preserve explicit authorization guards for all network-facing assessment modules.

## Honest feature limits

Current module status and `not_assessed` metadata remain unchanged. In particular, comprehensive vulnerability analysis, dynamic malware analysis, broad archive formats, rule scanning, persisted dashboard alerts/scores, and 3D WebGL effects are not claimed as implemented. The existing ambient terminal decoration is not a Three.js terminal tunnel. Windows POSIX mode bits are not an ACL security boundary.

