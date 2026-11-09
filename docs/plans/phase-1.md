# Phase 1 plan: ChiNeScan platform foundation

## Repository assessment

Phase 1 creates a new, independent repository at `C:\src\Chinescan`. The parent checkout `C:\src` (`surface-security-toolkit`) and its untracked sibling projects are not part of ChiNeScan and will not be modified. Because ChiNeScan is nested in the parent working tree, the parent may report it as an untracked embedded repository. Do not stage ChiNeScan into the parent; adding it to the parent ignore list is optional and will not be done without a need. The new repository starts empty. The host default Python is 3.10.11, Docker CLI is 29.9.2, and pip is 23.0.1. `uv`, Semgrep, pytest, Ruff, mypy, and hadolint were not found on PATH. Python 3.12 or newer is required; Phase 1 implementation starts only after `py -0` and `py -3.12 --version` are recorded successfully in `docs/ENVIRONMENT.md`. Current probe finds Python 3.13, 3.11, and 3.10, but no 3.12; the start gate is unmet.

## Proposed Phase 1 file tree

Each listed file has a single planned purpose. Additional generated files should be limited to the lockfile, schema exports, and migration metadata required by the specified deliverables.

```text
AGENTS.md                                      Repository conventions inherited by future sessions
pyproject.toml                                 Build metadata, pinned direct dependencies, tool configuration
uv.lock                                       Reproducible resolved dependency lock
README.md                                     Product overview and quick-start documentation
LICENSE                                       Apache-2.0 license (unless owner specifies otherwise)
SECURITY.md                                   Vulnerability reporting process
CODE_OF_CONDUCT.md                            Community conduct policy
.dockerignore                                 Exclude local and sensitive files from container build context
docker/Dockerfile                             Pinned multi-stage, non-root application image
docker-compose.yml                            Local self-hosted service configuration
.github/workflows/ci.yml                      Lint, type-check, tests/coverage, dependency scan, container build
chinescan/__init__.py                         Package metadata exports
chinescan/cli/__init__.py                     CLI package
chinescan/cli/app.py                          Typer root app and command registration
chinescan/cli/commands.py                     Version, configuration, and explicit future-phase command stubs
chinescan/core/__init__.py                    Core package
chinescan/core/errors.py                      Typed exceptions and fixed CLI exit-code mapping
chinescan/core/models/__init__.py             Canonical model exports
chinescan/core/models/common.py               Shared schema-version and enum definitions
chinescan/core/models/finding.py              Finding and reference models
chinescan/core/models/investigation.py        Event, indicator, case, timeline, scan, target, artifact, report, authorization models
chinescan/core/orchestration/__init__.py       Orchestration package boundary
chinescan/core/orchestration/protocols.py      ScannerAdapter and Analyzer protocols
chinescan/core/storage/__init__.py             Storage package boundary
chinescan/core/storage/repository.py           Repository interface
chinescan/core/storage/sqlite.py               SQLite repository implementation
chinescan/core/config/__init__.py              Config package exports
chinescan/core/config/settings.py              Pydantic settings and environment overrides
chinescan/core/config/io.py                    TOML load, validate, and safe initialization
chinescan/core/logging/__init__.py             Logging package exports
chinescan/core/logging/redaction.py             Shared secret redaction function and filter
chinescan/core/logging/structured.py            Structured JSON formatter and logger setup
chinescan/scanners/__init__.py                 Scanner package boundary
chinescan/scanners/fake.py                     In-memory adapter for deterministic tests
configs/chinescan.example.toml                 Non-secret example configuration
alembic.ini                                    Alembic migration configuration
migrations/env.py                              Alembic environment setup
migrations/script.py.mako                     Migration template
migrations/versions/0001_initial.py            Initial storage schema migration
schemas/finding.schema.json                    Exported Finding JSON Schema
schemas/investigation.schema.json              Exported investigation-record JSON Schema
tests/conftest.py                              Shared isolated database/config fixtures
tests/unit/test_config.py                      Config initialization and validation coverage
tests/unit/test_redaction.py                   Secret redaction coverage
tests/unit/test_models.py                      Canonical model and schema coverage
tests/unit/test_storage.py                     SQLite repository coverage
tests/unit/test_cli.py                         CLI help, version, config, and stub contract coverage
docs/ARCHITECTURE.md                           Phase 1 component and data-flow architecture
docs/DEVELOPMENT.md                            Installation, local checks, and contribution workflow
docs/DECISIONS.md                              ADRs, including dependency rationale
docs/RESPONSIBLE_USE.md                        Authorization and safe-use boundaries
docs/ROADMAP.md                                Phases 2–8 scope and acceptance summary
docs/DEDUPLICATION.md                           Canonical fingerprint tuple contract for future use
docs/reports/phase-1-report.md                 Exact verification results and definition-of-done report
```

The package skeleton will create only Phase 1 modules. Future CLI operations will be explicit stubs that state their phase and exit with usage code 2; no later-phase scanning/reporting behavior will be implemented.

## Dependencies and versions

Pin exact direct dependency versions in project metadata and resolve every transitive dependency in `uv.lock`. Proposed compatible release pins below are the initial selection for Phase 1; confirm Python 3.12 metadata and package-index availability when generating the lock. A lockfile generated from the actual resolver is the authoritative complete pin set.

| Dependency | Proposed pin | Reason |
| --- | --- | --- |
| `typer` | `>=0.15,<1` | Typed CLI, help rendering, and exit handling required by the CLI contract. |
| `pydantic` | `>=2.11,<3` | Canonical validated models and JSON Schema generation. |
| `pydantic-settings` | `>=2.9,<3` | Typed configuration with `CHINESCAN_` environment overrides. |
| `sqlalchemy` | `>=2.0,<3` | Repository-backed SQLite persistence with a PostgreSQL-ready boundary. |
| `alembic` | `>=1.15,<2` | Versioned initial schema migration from the first database schema. |
| `tomli-w` | `>=1.2,<2` | Correctly serializes TOML config; hand-built TOML strings risk incorrect value escaping. |
| `pytest` | `>=8.3,<9` | Deterministic unit and integration test execution. |
| `pytest-cov` | `>=6.1,<7` | Core coverage measurement required for acceptance. |
| `ruff` | `>=0.11,<1` | Required lint and formatting checks. |
| `mypy` | `>=1.15,<2` | Strict static type checking required for acceptance. |
| `pip-audit` | `>=2.8,<3` | Audits the resolved Python dependency set for known vulnerabilities in CI and reports. |

Use Python 3.12+ as the project runtime (`requires-python = ">=3.12"`) and add `.python-version`. These are constraints in `pyproject.toml`; `uv lock` resolves exact versions into `uv.lock`, and the Phase 1 report records those versions and the `pip-audit` result. Runtime dependencies: Typer, Pydantic, pydantic-settings, SQLAlchemy, Alembic, and tomli-w. Development dependencies: pytest, pytest-cov, Ruff, mypy, and pip-audit. `uv` is a development and lockfile manager, not a runtime dependency. Exclude httpx, cryptography, FastAPI, and scanner packages until their phases. Record every dependency and rationale in `docs/DECISIONS.md`.

## Step-by-step implementation order

1. Confirm `py -0` and `py -3.12 --version` succeed and record both outputs in the new repository's `docs/ENVIRONMENT.md`; do not begin Phase 1 implementation until confirmed. Initialize a separate Git repository in `C:\src\Chinescan` and add root `AGENTS.md` with the brief's conventions and safety requirements.
2. Add `pyproject.toml` with Python 3.12+, exact direct dependency pins, entry point, and Ruff/mypy/pytest settings; resolve and commit `uv.lock`.
3. Create the typed error hierarchy and Pydantic v2 canonical models; export schemas under `schemas/` and document schema versioning and fingerprint fields.
4. Implement TOML configuration load/init/validate with environment overrides, secure treatment of secret settings, and exit-code behavior.
5. Implement shared redaction and structured JSON logging; add focused redaction/config/model tests.
6. Define adapter protocols, a deterministic in-memory fake, repository interface, SQLAlchemy SQLite implementation, and Alembic initial migration; test using temporary databases.
7. Implement the thin Typer CLI: `version`, `config init`, `config validate`, global help, and explicit phase-tagged stubs with documented exit codes.
8. Add the example config, architecture/development/responsible-use/roadmap/deduplication docs, ADRs, README, Apache-2.0 license, security policy, and code of conduct.
9. Add pinned multi-stage non-root Docker build, Compose file, `.dockerignore`, and CI for Ruff, strict mypy, pytest/core coverage, dependency scanning, and Docker build.
10. Run every Phase 1 acceptance command using Python 3.12+, correct issues, capture exact command text/output/exit status, and produce `docs/reports/phase-1-report.md`. If Docker or an interpreter is unavailable, record the exact constraint and mark the criterion NOT RUN; do not claim completion.

## Risks and assumptions

- **Nested repository:** ChiNeScan is an independent Git repository nested inside the parent `C:\src` worktree. Do not stage its contents into the parent repository.
- **Python mismatch:** Host default Python 3.10 cannot validate or install the declared Python 3.12+ project as-is. The required launcher check blocks Phase 1 implementation until it succeeds.
- **Resolver/network availability:** `uv` is absent and network access is package-index-only. Installing the tool and resolving exact dependency versions may fail; record exact output if so and never invent a lockfile.
- **Docker availability:** CLI exists but daemon availability and a base-image digest have not been verified. Use an immutable digest in the Dockerfile and run the requested build when possible; otherwise record the exact reason.
- **Windows security semantics:** POSIX mode-bit enforcement does not prove Windows ACL restriction. Phase 1 must avoid claiming malware sample storage is implemented; malware intake is out of scope. Path tests should exercise `pathlib` semantics and Windows path forms.
- **Schema scope:** Phase 1 defines forward-compatible canonical records without implementing later phase workflows. Avoid speculative fields beyond those identified in the brief.
- **Dependency drift/security:** Proposed pins must be resolved and checked against package metadata and dependency scanning before merge; update the ADR and pins if incompatible or unsafe.

## Applied owner decisions

- Project root is the new independent repository at `C:\src\Chinescan`; parent checkout is not part of this project and must not receive staged ChiNeScan content.
- Python 3.12+ is mandatory. Do not begin Phase 1 implementation until `py -0` and `py -3.12 --version` have succeeded and their output is captured in `docs/ENVIRONMENT.md`.
- Use dependency constraints and resolve exact versions with `uv lock`; add `pip-audit` and `tomli-w` for the reasons in the dependency table.
- Apache-2.0 license.
- Config file defaults to the platform user-config directory; SQLite defaults to platform user-data directory. Both accept explicit overrides; config initialization emits no secrets.
- Docker acceptance uses Option B: the phase may close with Docker build marked NOT RUN if the daemon is unreachable, including the exact daemon error in the report.

## Phase boundary

The owner has approved the plan with the applied decisions above. Phase 1 implementation may begin only after the Python 3.12 launcher checks pass and their output is recorded in `docs/ENVIRONMENT.md`. Docker build may be NOT RUN under Option B only when daemon unavailability is recorded exactly.
