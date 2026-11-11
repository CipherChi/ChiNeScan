# Release report

## Merged changes

- [PR #25](https://github.com/CipherChi/ChiNeScan/pull/25) merged the Rust core, reporter, dashboard scoring and alerts, and terminal glass UI stack. Merge commit: `896b556e61abbd85470a77a7d265828a99dc4166`.
- [PR #26](https://github.com/CipherChi/ChiNeScan/pull/26) added the supplied README artwork unchanged. Merge commit: `a0b7682`.
- No direct pushes to `main`, force pushes, admin overrides, or test/lint weakening were used.

## CI and fixes

PR #25 CI passed after these fixes:

- `e22f9a0`: applied Ruff formatting to dashboard changes.
- `8b39ebe`: installed the native engine in Python CI so scoring tests exercise the intended implementation.
- `ca1563f`: replaced dynamic SQL in dashboard alert listing with fixed queries after Bandit flagged B608.

PR #25 final CI run [42925160140](https://github.com/CipherChi/ChiNeScan/actions/runs/42925160140) passed all checks. PR #26 passed all checks; the post-merge `main` runs also passed: [ChiNeScan CI 42935309910](https://github.com/CipherChi/ChiNeScan/actions/runs/42935309910), [CodeQL 42935310513](https://github.com/CipherChi/ChiNeScan/actions/runs/42935310513), and [Offline benchmarks 42935309886](https://github.com/CipherChi/ChiNeScan/actions/runs/42935309886). No CI fixes were needed for PR #26.

Local checks on the merged application stack passed: Rust formatting, clippy, tests (65); cargo audit and cargo deny; full Python suite (716 passed, 5 deselected, 82.80% coverage); Ruff and formatting; strict mypy (90 files); frontend typecheck; 73 unit tests; production build/CSP; and Playwright acceptance (18 passed). The initial Playwright attempts were affected by concurrent resource pressure; the isolated full run passed. No tests were skipped or changed to accommodate this.

## Frontend bundle and browser measurement

Before lazy loading Three.js, the main bundle was 898.99 kB. After lazy loading, the main bundle was 368.76 kB (103.26 kB gzip) and the Three.js chunk was 535.41 kB (132.80 kB gzip). Vite's existing chunk-size warning remains visible; the Three.js chunk is intentionally loaded only when effects are enabled and WebGL is available. CSS gradient fallback remains available.

Playwright reported 11–12 FPS in headless software rendering: Windows 11 Pro for Workstations, Intel Core i7-7600U, Intel HD Graphics 620, ANGLE/Vulkan SwiftShader. This number is not representative of hardware performance and is not a 60 FPS claim. The automatic quality-reduction path engaged in this run. The frame cap and quality fallback are verified by unit tests, not inferred from this measurement.

## Artwork

The supplied files were copied unchanged to `docs/assets/`: cover 1600×900, 282,721 bytes; social preview 1280×640, 361,042 bytes. Source and destination SHA-256 values matched. I viewed both images and checked visible text for personal emails, usernames, hostnames, local paths, real hashes, and real scan results; none were present. Artwork terminal text is labeled illustrative in the README.

## History, backup, and safety notes

The two path-search matches (`0d91418`, `6c920a1`) were path removals, as reviewed; no further history rewrite was performed. Added-content and commit-message scans were clean, and gitleaks reported no secrets. The broader final-tree path grep still finds pre-existing examples in phase reports, redaction tests, fixtures, and container configuration; none are added by this release. The terminal glass working copy backup is in the external terminal-glass WIP backup folder; dashboard worktree status was clean, so no dashboard WIP backup was needed. Safety refs were kept locally and were not pushed.

The dashboard scoring branch was rebuilt to retain Phase 4 scoring/alerts/dashboard/API changes while using the Phase 3b reporter commits; reporter-copy commits were excluded. App/styles conflicts were reviewed and resolved manually, preserving both feature sets. Final branch ancestry was verified linear before push.

## Outbound action ledger

- `cargo audit` fetched the RustSec advisory database from GitHub during local verification. The post-merge repeat used the local cache (`--no-fetch`).
- `npm audit` accessed the npm registry.
- Dependency resolution used the configured package registries.
- Git pushes: `codex/ui-terminal-glass` and `docs/readme-cover`; GitHub PR, CI, review-state and merge operations were used for PRs #25 and #26. Their CI logs are linked above.
- The release-report branch push and PR/CI/merge are recorded in its PR and action logs when complete.

## Manual follow-ups

- Upload `docs/assets/chinescan-social.png` under GitHub Settings → General → Social preview.
- Enable branch protection on `main` and require the appropriate status checks.

No module status, “Not assessed” list, or authorization guard was changed as part of the artwork release.

