# Decisions

## ADR-001: Python package and managed dependencies

Use Python 3.12+, with `uv.lock` as the exact transitive resolution. Typer supplies the typed CLI; Pydantic and pydantic-settings validate records and environment-aware settings; SQLAlchemy and Alembic establish persistence and migration boundaries. `tomli-w` safely serializes initialized TOML rather than interpolating user-controlled values into TOML strings. Pytest/pytest-cov, Ruff, mypy, and pip-audit provide the project checks. The planned pytest `<9` range was widened to `<10` after pip-audit reported PYSEC-2026-1845 against 8.4.2, with 9.0.3 listed as a fix.

## ADR-002: Local configuration and data defaults

Configuration defaults to `~/.config/chinescan/config.toml`; SQLite defaults to `~/.local/share/chinescan/chinescan.sqlite3`. Explicit config paths and the `CHINESCAN_DATABASE_PATH` setting support local overrides. Config initialization never writes secret settings.

Reports default to `~/.local/share/chinescan/reports`, configurable through `CHINESCAN_REPORTS_DIR`, TOML, or global `--reports-dir`. Only code scans auto-save reports. Evidence grade is separate from confidence; verdicts use the four values `leads_found`, `no_matches_with_gaps`, `no_matches_in_scope`, and `scan_failed`.

## ADR-003: Versioned generic records

All canonical records inherit a shared `schema_version`. Code finding fingerprints derive from normalized target, category, rule ID, and location as described in `DEDUPLICATION.md`. SQLite stores JSON-compatible typed payloads behind a repository protocol.

## ADR-004: Local-first code assessment

The built-in heuristic scanner is the default and runs without subprocesses or network access. External SAST, secret, IaC, and dependency adapters are explicit choices, bounded by timeouts, and normalize metadata without source snippets. Semgrep needs a local rules file; Trivy skips database/policy updates and remote lookups. pip-audit and npm audit require `--allow-network-audits` because they submit dependency metadata to upstream advisory services. No scanner package dependency was added; adapters use installed CLIs through argument arrays with shell execution disabled.

## ADR-005: Safe local Sigma rule parsing

Add PyYAML for local Sigma YAML rule files. Its `safe_load` APIs construct only standard YAML values and reject arbitrary Python object constructors, which fits untrusted local rule content better than a hand-written YAML parser. ChiNeScan bounds file size and rule count and evaluates a documented condition/selector subset without `eval`; it does not claim full Sigma compatibility. See the [PyYAML safe loading documentation](https://pyyaml.org/wiki/PyYAMLDocumentation).

## ADR-006: Ephemeral malware static triage

Phase 5 initially implements only bounded static analysis of one local regular file. Hashes and
candidate metadata are returned to the caller but not stored in SQLite; sample bytes are never
copied or executed. Indicator values are omitted from summaries unless explicitly requested.
YARA and ClamAV are optional local subprocesses with no shell, restricted environment, output
caps, and timeouts. This avoids claiming a malware intake/storage system before encryption,
access control, retention, and audit requirements have been designed and implemented.

## ADR-007: Authenticated loopback dashboard foundation

The approved Slice 1 dashboard uses FastAPI to expose existing SQLite records, Uvicorn as an
explicit single-worker loopback server, and argon2-cffi for the local operator password hash.
Opaque session cookies are backed by in-process state so logout revocation is immediate and a
restart invalidates sessions. React, React DOM, TypeScript, and Vite provide the same-origin UI;
Vitest, jsdom, and Testing Library cover components. `httpx2` supplies the TestClient transport
compatible with the resolved Starlette release. Every direct dependency is locked in `uv.lock` or
`frontend/package-lock.json`. No CORS, TLS terminator, browser binaries, scanner, or job framework
was added.

## ADR-008: Offline project indicator scanning and report summaries

The new code indicator scanner accepts caller-supplied local indicator files and scans local
project files without network activity. This offline boundary applies to that scanner only; the
existing authorized `domain_assessment/probe.py` performs bounded network posture checks. Only code
scans auto-save JSON and Markdown reports. No external project was consulted or reused.
