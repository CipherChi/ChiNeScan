# Rust core and partial-module upgrade plan

## Phase 0 findings

- Backend: Python 3.12+ package with Typer CLI, service/core layers, and a local FastAPI dashboard in `chinescan/web`; SQLite-backed local state. Dashboard authentication is implemented in `chinescan/web/auth.py` and middleware/routes in `chinescan/web/app.py`.
- Frontend: React 19 + TypeScript + Vite 8 under `frontend/`; modules render capability records returned by the backend. `chinescan/core/capabilities.py` is the source of module status, `not_assessed`, and `authorization_guards`; `frontend/src/types.ts` models them.
- Existing Rust: `engine/` is already an optional PyO3 cdylib/rlib package named `chinescan-engine`, currently used for bounded text redaction. It is the lowest-risk bridge: extend it as a Python extension and keep Python's authenticated API, SQLite, and job queue authoritative. Do not add a listener or new network path.
- Existing file triage is Python in `chinescan/malware_analysis/analyzer.py`: it hashes a bounded file, identifies types, inspects PE/ELF/Mach-O metadata, scripts, and ZIP metadata. Archive names and extension mismatch are already partly supported; its gaps need tests before capability claims change.
- Dashboard auth/authorization and job controls live in the existing web app/services. Preserve these routes and guards; do not add new unauthenticated endpoints or alter domain authorization.
- Frontend tests use Vitest/Testing Library and Playwright; Python tests live in `tests/`. Rust has `engine/Cargo.lock` and fmt/clippy/test guidance. This phase-1 plan does not define its acceptance commands in a compact section; exact available commands and interpreter availability will be reported after running the documented checks.

## Implementation plan

1. Keep changes scoped to `C:\src\Chinescan`. Do not commit, push, or modify the parent checkout.
2. Extend the existing Rust engine as the bridge rather than creating an HTTP sidecar, preserving one authenticated backend and avoiding another listener/token lifecycle. Add focused Rust libraries for bounded static archive metadata and common findings only if their dependency and parser isolation limits can be supported by the current build environment. The first implementation is a dependency-free ZIP central-directory module inside the existing engine crate; it does not decompress members or run in a separate process. Rust parsing must forbid unsafe code, cap input/entries/depth/time, catch panics, and never extract or execute sample content.
3. Keep the current Python analyzer as the storage and orchestration boundary. Call native parsing only through a narrow, validated PyO3 interface with byte-size limits and structured, sample-controlled strings treated as evidence. Preserve existing hashes, findings, statuses, and operator-local sample handling.
4. Add inert synthetic parser fixtures and focused unit/integration tests first. Close a `Not assessed` bullet only when a test demonstrates the exact promised behavior. Keep comprehensive language vulnerability analysis and dynamic malware analysis explicitly unassessed.
5. Add reporter/scoring/alerts capabilities only where they can be persisted and shown through existing authenticated APIs. Do not invent an alternate data store or listener. Any dashboard UI work must preserve keyboard access, safe defaults, and existing deep links.
6. Add the requested architecture/threat-model/limits/run documentation and CI only for gates that are actually available and reproducible. Record unsupported gates (notably cargo-deny, cargo-audit, fuzzing, and exhaustive parser coverage) honestly; never report them as passing if not run.
7. Run the repository's documented Phase 1 acceptance commands with `py -3.12`, capture exact command/output/status in `docs/reports/phase-1-report.md`, then run targeted Rust/frontend checks for changed code. Do not commit.

## Planned touch points

- `engine/Cargo.toml`, `engine/Cargo.lock`, `engine/src/`: PyO3 bridge and safe Rust analysis components, including bounded ZIP metadata parsing.
- `chinescan/malware_analysis/analyzer.py`, focused tests under `tests/`: orchestration and safety limits.
- `chinescan/core/capabilities.py`, `frontend/src/ui/App.tsx` or related module UI, and component tests: only evidence-backed status/limit changes.
- `frontend/src/` reusable background/GlassSurface utilities and tests: isolated UI enhancement after core checks.
- `docs/RUST-ENGINE.md`, `docs/ARCHITECTURE.md`, new threat-model/limits docs, and `docs/reports/phase-1-report.md`.
- A repository CI workflow only after the concrete Rust/Python/frontend commands are established.

## Migration and risk notes

No database migration is planned unless alert/score persistence is implemented against the existing schema after inspection. Avoid an unreviewed parallel persistence model. The existing engine is optional; Python fallback behavior must remain correct. Parser crates increase supply-chain and malformed-input risk, so dependency review, deterministic limits, panic isolation, synthetic adversarial tests, and truthful coverage statements are release gates. Full scope in the prompt (multiple archive formats, YARA-X, eight Tree-sitter grammars, full reporting/CVSS/SARIF, persisted alerts/scores, live events, comprehensive CSP/CSRF/rate-limit review, 3D WebGL scene, liquid-glass rollout, fuzzing, and Lighthouse) is broader than one safe, reviewable change; the implementation must be staged and must not imply the unbuilt parts are complete.

