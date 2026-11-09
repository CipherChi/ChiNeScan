# Phase 1 verification report

Recorded 2026-10-25. Python 3.12.10 was newly installed after the user authorized installation. The standalone repository is `C:\src\Chinescan`; the parent repository was not staged or changed.

## Outcome

Platform foundation implemented: package metadata and lock, versioned records and schemas, config, redaction and JSON logging, protocols and fake scanner, SQLite repository and Alembic migration, Typer CLI, tests, project policies/docs, Compose, and CI workflow.

The initial acceptance run had a Docker wheel-install failure and left the base image tag unpinned. On 2026-10-25, the Dockerfile was corrected to preserve the built wheel's filename and pinned to the verified Python image manifest digest. The complete Docker build and container CLI smoke check now pass. The latest Python acceptance rerun also passes lint, formatting, type checks, unit tests, dependency audit, CLI checks, and Compose validation. Exact rerun results are recorded below.

## Tasks and verification

| Plan task | Result | Verification / note |
| --- | --- | --- |
| 1. Python gate, standalone Git repository, conventions | PASS | `py -0` and `py -3.12 --version` passed; nested `git init` and status passed. |
| 2. Project metadata and lock | PASS | `uv lock --check`; `uv sync --locked --extra dev`; `pyproject.toml` and `uv.lock` committed as `50d04e9`. |
| 3. Typed errors, canonical models, schemas | PASS | Pydantic model tests and both JSON Schema JSON parse checks passed. |
| 4. TOML config, environment overrides, safe init | PASS | Configuration tests passed, including environment override and no-secret initialization. |
| 5. Redaction, structured logging, focused tests | PASS | Redaction and JSON formatter tests passed. |
| 6. Protocols, fake adapter, SQLite, Alembic | PASS | Fake adapter and temporary SQLite repository tests passed; migration created the `records` table. |
| 7. Typer CLI and future stubs | PASS | CLI tests, help, version, config commands, and Phase 3 stub exit code 2 passed. |
| 8. Example config, docs, decisions, license, policies | PASS | Files created; reviewed as source artifacts. |
| 9. Docker, Compose, `.dockerignore`, CI | PASS | `docker compose ... config --quiet` passed; digest-pinned Docker build and container `--help` smoke check passed. |
| 10. Acceptance checks and report | PASS | Python 3.12.10 checks, CLI/config, tests, lint/format, mypy, pip-audit, schemas, migration, Compose, and Docker build passed; see rerun results below. |

## Exact verification commands and results

### Python gate

`py -0` — exit 0:

```text
 -V:3.13 *        Python 3.13 (64-bit)
 -V:3.12          Python 3.12 (64-bit)
 -V:3.11          Python 3.11 (64-bit)
 -V:3.10          Python 3.10 (64-bit)
```

`py -3.12 --version` — exit 0:

```text
Python 3.12.10
```

### Python checks

| Command | Exit | Output |
| --- | ---: | --- |
| `\.venv312\Scripts\uv.exe sync --locked --extra dev` | 0 | `Using CPython 3.12.10`; `Resolved 54 packages`; installed locked project and development dependencies, including pytest 9.1.1. |
| `\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 54 packages in 2ms` |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\mypy.exe chinescan` | 0 | `Success: no issues found in 23 source files` |
| `\.venv\Scripts\pytest.exe --cov=chinescan --cov-report=term-missing --cov-fail-under=80` | 0 | 17 passed; total coverage 89.26%; required 80% reached. |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable local `chinescan` distribution skipped. |
| `\.venv\Scripts\chinescan.exe --help` | 0 | Help listed `version`, `scan`, `report`, and `config`. |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0` |
| `.\.venv\Scripts\python.exe -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON. |
| `.\.venv\Scripts\python.exe -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON. |

The first audit found `PYSEC-2026-1845` in pytest 8.4.2 (fix listed as 9.0.3). The dev dependency upper bound was widened from `<9` to `<10`, the lock was upgraded to pytest 9.1.1, and the audit then passed.

### Persistence and container configuration

| Command | Exit | Output |
| --- | ---: | --- |
| Temporary Alembic upgrade script using `alembic.command.upgrade(cfg, 'head')` | 0 | `migration upgrade head: OK; records table present` |
| `docker compose -f docker-compose.yml config --quiet` | 0 | No errors. |
| `docker info` | 0 | Docker Engine 29.9.2 server responded; daemon available. |
| `docker image inspect python:3.12-slim --format '{{json .RepoDigests}}'` | 1 | `Error response from daemon: No such image: python:3.12-slim` |
| Docker build | NOT RUN | Registry fetch was not attempted because network use is limited to package indexes. Therefore Docker daemon unavailability is not claimed. |

## Deviations and decisions

- The planned pytest `<9` range was unsafe per the audit result; it is now `>=8.3,<10`, with 9.1.1 locked.
- An existing `.venv` using Python 3.13.15 was unintentionally replaced by `uv sync` with the Python 3.12.10 project environment. `.venv312` contains the uv executable used for environment management. This local environment change is recorded in `docs/ENVIRONMENT.md`.
- The initial pytest runs used pytest's default system temporary directory for `tmp_path` fixtures. Before the final run, pytest was configured with `--basetemp=tests/.pytest-tmp` so subsequent test files are confined to the project. No cleanup was attempted outside the project directory.
- The initial Docker build failed because the built wheel was copied to `/tmp/chinescan.whl`, which is not a valid wheel filename. The Dockerfile now copies the wheel to `/tmp/` without renaming it. The Python 3.12 slim Bookworm base was resolved from Docker Hub and pinned by manifest digest in both stages; the digest-pinned build passes.
- Only `pyproject.toml` and `uv.lock` were committed, as directed by plan task 2. No other files were committed or pushed.

## Latest acceptance rerun — 2026-10-25

All commands below were run from `C:\src\Chinescan` after the Dockerfile fix and Ruff formatting. Exit 0 indicates success.

| Command | Exit | Result |
| --- | ---: | --- |
| `\.venv312\Scripts\python.exe --version` | 0 | `Python 3.12.10` |
| `\.venv312\Scripts\uv.exe sync --locked --extra dev` | 0 | `Resolved 54 packages in 2ms`; `Checked 54 packages in 35ms` |
| `\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 54 packages in 2ms` (recorded in the earlier run; lock unchanged) |
| `\.venv\Scripts\chinescan.exe --help` | 0 | Help listed `version`, `scan`, `report`, and `config` |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0` |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `49 files already formatted` |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 23 source files` |
| `\.venv\Scripts\pytest.exe --cov=chinescan.core --cov-report=term-missing --cov-fail-under=80` | 0 | `17 passed`; total coverage `91.05%` |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable project distribution skipped |
| `\.venv\Scripts\python.exe -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON |
| `\.venv\Scripts\python.exe -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON |
| `docker compose -f docker-compose.yml config --quiet` | 0 | No output; configuration valid |
| `docker build -f docker/Dockerfile -t chinescan:0.1.0 .` | 0 | Build succeeded; base `python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70`; image `chinescan:0.1.0` created |
| `docker run --rm chinescan:0.1.0 --help` | 0 | Container displayed CLI help |
| Config initialization, duplicate initialization, validation, and malformed TOML validation using a temporary `tests\phase1-config-check.toml` | 0 / 2 / 0 / 2 | Outputs respectively: created; already exists; valid; parse error. Error cases return documented application exit code 2. Temporary file removed. |

The earlier formatter failure has been corrected by applying Ruff formatting to the five reported files. Docker registry access was available for this rerun, so the prior package-index-only limitation no longer applies to the current verification.

## Rerun commands

From `C:\src\Chinescan` in PowerShell:

```powershell
\.venv312\Scripts\uv.exe sync --locked --extra dev
\.venv312\Scripts\uv.exe lock --check
\.venv\Scripts\ruff.exe check .
\.venv\Scripts\mypy.exe chinescan
\.venv\Scripts\pytest.exe --cov=chinescan --cov-report=term-missing --cov-fail-under=80
\.venv\Scripts\pip-audit.exe --skip-editable
\.venv\Scripts\chinescan.exe --help
\.venv\Scripts\chinescan.exe version
docker compose -f docker-compose.yml config --quiet
```

## Supplementary verification on 2026-10-31

The current repository acceptance run used the required `uv run` entry point and isolated pytest
storage under the operating-system temp directory. Exact commands and results:

| Command | Exit | Result |
| --- | ---: | --- |
| `uv run --no-sync ruff check .` | 0 | `All checks passed!` |
| `uv run --no-sync ruff format --check .` | 0 | `149 files already formatted` |
| `uv run --no-sync mypy --strict chinescan` | 0 | `Success: no issues found in 61 source files` |
| `uv run --no-sync pytest --cov=chinescan --cov-report=term --cov-fail-under=80 --basetemp "$env:TEMP\chinescan-phase4a-verified-final"` | 0 | `290 passed, 5 deselected`; total coverage `81.54%` (80% required) |
| `uv run --no-sync python -m compileall -q chinescan` | 0 | No output; compilation succeeded |
| `uv run --no-sync pip-audit --skip-editable` | 0 | `No known vulnerabilities found`; editable distribution skipped |
| `uv run --no-sync bandit --severity-level medium -r chinescan` | 0 | `No issues identified.` |

Project log end-to-end API flow was also run twice in separate pytest processes using separate
`--basetemp` directories: `1 passed in 6.61s` and `1 passed in 5.21s`. This uses FastAPI's
in-process test client, not the browser E2E harness.

Run the Alembic migration check through the pytest suite; pytest writes temporary databases under `tests/.pytest-tmp/`. The Docker image build command, after an authorized immutable base digest and registry access are available, is:

```powershell
docker build -f docker/Dockerfile -t chinescan:0.1.0 .
```

## Security and acceptance rerun — 2026-10-25

The following checks were rerun from `C:\src\Chinescan` with Python 3.12.10 after the secret-redaction and config-initialization fixes. The worktree also contains uncommitted Phase 2–4 code; results below describe that combined local worktree and do not make those features part of Phase 1.

| Command | Exit | Result |
| --- | ---: | --- |
| `py -0` | 0 | Registered interpreters: Python 3.13 (64-bit, default), 3.12 (64-bit), 3.11 (64-bit), 3.10 (64-bit) |
| `py -3.12 --version` | 0 | `Python 3.12.10` |
| `\.venv312\Scripts\uv.exe sync --locked --extra dev --python 3.12` | 0 | `Resolved 57 packages`; `Checked 57 packages` |
| `\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 57 packages in 3ms` |
| `uv run --locked --extra dev ruff check .` | 0 | `All checks passed!` |
| `uv run --locked --extra dev ruff format --check .` | 0 | `72 files already formatted` |
| `uv run --locked --extra dev mypy --strict chinescan` | 0 | `Success: no issues found in 33 source files` |
| `uv run --locked --extra dev pytest --cov=chinescan.core --cov-report=term-missing --cov-fail-under=80` | 0 | `44 passed`; core coverage `94.08%` |
| `uv run --locked --extra dev pip-audit --skip-editable` | 0 | `No known vulnerabilities found`; editable project distribution skipped |
| `uv run --locked --extra dev bandit --severity-level medium -r chinescan` | 0 | No medium/high issues; three low-severity items are triaged in `docs/reports/security-review.md` |
| PyYAML parse of `.github/workflows/ci.yml` and `.github/dependabot.yml` | 0 | Both YAML documents parsed; GitHub workflow execution remains pending a push |
| `actionlint -color .github/workflows/ci.yml` (actionlint 1.7.12) | 0 | Workflow syntax and expressions passed local validation |
| JSON parse of `schemas/*.json` | 0 | Both schemas valid |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Valid Compose configuration |
| `docker build -f docker/Dockerfile -t chinescan:security-review .` | 0 | Built using Python 3.12.15 slim Trixie digest `sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704`; runtime packages installed from hashed `uv.lock` export |
| `docker run --rm chinescan:security-review --help` | 0 | Container CLI help rendered |
| `trivy config --severity HIGH,CRITICAL --exit-code 1 .` | 0 | No high/critical Dockerfile misconfiguration; Trivy detected one config file (Dockerfile) |
| Trivy image scan with `--ignore-unfixed --severity HIGH,CRITICAL --exit-code 1` | 0 | No fixable high/critical image vulnerabilities |
| Trivy full image report without `--ignore-unfixed` | 0 (report-only) | 44 high OS findings: 43 `affected`, one `fix_deferred`, none had a fixed version; no critical or Python-library findings. See the temporary acceptance in `docs/reports/security-review.md`. |
| `gitleaks git . --log-opts=--all --redact --no-banner` | 0 | Two Git commits scanned; no leaks |
| Gitleaks scans of tracked/unignored source paths | 0 | No leaks in source paths. A broad scan including ignored `.venv` produced 202 potential matches, all under that generated environment; they were not confirmed as credentials and were not staged. |

The full Bandit run still reports three low-severity items in uncommitted later-phase code. The Trivy workflow reports all high/critical image findings and fails only when a fix is available; the accepted no-fix OS findings have owner `CipherChi` and review date `2026-11-25` in the security review report. No repository settings, visibility, commits, pushes, pull requests, or deployments were changed or created in this run.

Exact `py -0` output:

```text
 -V:3.13 *        Python 3.13 (64-bit)
 -V:3.12          Python 3.12 (64-bit)
 -V:3.11          Python 3.11 (64-bit)
 -V:3.10          Python 3.10 (64-bit)
```

## Acceptance rerun — 2026-10-26

This rerun validates the current combined worktree, which includes uncommitted later-phase modules;
it does not expand Phase 1's scope. Python commands explicitly used the 3.12 launcher. `PYTHONPATH`
was pointed at the repository virtual environment's installed dependencies because system Python
3.12 does not have the project dependencies installed.

| Command | Exit | Exact result |
| --- | ---: | --- |
| `py -0` | 0 | Python 3.13 (default), 3.12, 3.11, and 3.10 registered. |
| `py -3.12 --version` | 0 | `Python 3.12.10` |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `69 passed`; total coverage `82.26%`; required 80% reached. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `92 files already formatted` |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 41 source files` |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChiNeScan distribution skipped. |
| `\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | `No issues identified`; four low-severity subprocess findings are outside this threshold. |
| `py -3.12 -m uv lock --check` | 0 | `Resolved 57 packages in 2ms` |
| JSON parsing for `schemas\finding.schema.json` and `schemas\investigation.schema.json` | 0 | Both schema files valid JSON. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Compose configuration valid. |
| `docker build -f docker/Dockerfile -t chinescan:phase1-acceptance .` | 0 | Image built successfully using pinned Python 3.12.15 slim Trixie digest `sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704`. |
| `docker run --rm chinescan:phase1-acceptance --help` | 0 | Container CLI help rendered and listed commands. |
| `docker build -f docker/Dockerfile -t chinescan:phase8-trends .` | 0 | Updated image containing scan-history trends built from the pinned Python base. |
| `docker run --rm -e CHINESCAN_DATABASE_PATH=/tmp/chinescan-trends.sqlite3 chinescan:phase8-trends trends --days 2 --format json` | 0 | Returned two daily zero-count buckets from a fresh local SQLite database. |
| `\.venv\Scripts\chinescan.exe --help` | 0 | Help rendered; lists version, code, logs, scan, report, compare, domain, config, case, and malware. |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0` |
| `\.venv\Scripts\chinescan.exe trends --days 2 --format json` | 0 | Returned two daily zero-count buckets from an empty temporary local database. |
| `\.venv\Scripts\chinescan.exe scan` | 2 | `scan is planned for Phase 3 and is not implemented.` |
| Config init, validation, then malformed TOML validation using `tests\phase1-rerun-config.toml` | 0 / 0 / 2 | `Created configuration: tests\phase1-rerun-config.toml`; `Configuration is valid.`; `Unable to load configuration: Expected ']' at the end of a table declaration (at end of document)`. Temporary file removed. |

The initial Phase 1 report above retains its original dated results for audit history. This is the
latest full acceptance snapshot. No production target or external domain was contacted.

### Parser update acceptance — 2026-10-26

The full acceptance suite was rerun after adding support for classic syslog-prefixed CEF records.
This remains later-phase parser functionality in the combined worktree; Phase 1 scope is unchanged.

| Command | Exit | Exact result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `70 passed`; total coverage `82.50%`; required 80% reached. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `92 files already formatted` |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 41 source files` |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChiNeScan distribution skipped. |
| `\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | `No issues identified`; four low-severity subprocess findings are outside this threshold. |
| `py -3.12 -m uv lock --check` | 0 | `Resolved 57 packages in 70ms`. |
| `py -0` | 0 | Python 3.13 (default), 3.12, 3.11, and 3.10 registered. |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| Python 3.12 JSON parsing of `schemas\finding.schema.json` and `schemas\investigation.schema.json` | 0 | Both schema files valid JSON. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Compose configuration valid. |
| `docker run --rm chinescan:phase1-acceptance --help` | 0 | Container CLI help rendered and listed commands. |
| `\.venv\Scripts\chinescan.exe --help` | 0 | Help listed version, code, logs, scan, report, compare, trends, domain, config, case, and malware. |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0`. |
| `\.venv\Scripts\chinescan.exe trends --days 2 --format json` | 0 | Returned two daily buckets with `total_scans: 1` from the existing local database. |
| `\.venv\Scripts\chinescan.exe scan` | 2 | `scan is planned for Phase 3 and is not implemented.` |
| Config init, validation, and malformed TOML validation under `tests\phase1-rerun-config-continue.toml` | 0 / 0 / 2 | Created config; `Configuration is valid.`; `Unable to load configuration: Invalid value (at end of document)`. Temporary file removed. |
| `docker build -f docker/Dockerfile -t chinescan:phase4-syslog-cef .` | 0 | Image built from pinned Python 3.12.15 slim Trixie base. |
| `docker run --rm -v C:\src\Chinescan\fixtures\sample-logs:/logs:ro chinescan:phase4-syslog-cef logs /logs --format json` | 0 | `event_count: 21`, `source_count: 9`, `alert_count: 8`, `parse_error_count: 0`. |
| `docker run --rm -e CHINESCAN_DATABASE_PATH=/tmp/chinescan-trends.sqlite3 chinescan:phase1-acceptance trends --days 2 --format json` | 0 | Returned two daily zero-count buckets from a fresh local SQLite database. |

No production target or external domain was contacted.

## Current audit acceptance rerun — 2026-10-26

These results were collected during the read-only development-status audit of the current
combined worktree. No application code was edited. Tests used the existing installed
environment; no dependency installation or image build was performed.

| Command | Exit | Exact result |
| --- | ---: | --- |
| `py -0` | 0 | Python 3.13 (default), 3.12, 3.11, and 3.10 registered. |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `70 passed`; total coverage `82.27%`; 80% threshold reached. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!`. |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `92 files already formatted`. |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 41 source files`. |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChiNeScan distribution skipped. |
| `py -3.12 -m uv lock --check` | 0 | `Resolved 57 packages in 8ms`. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | No output; configuration valid. |
| `py -3.12 -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON. |
| `py -3.12 -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON. |
| `.\.venv\Scripts\chinescan.exe --help` | 0 | Help lists version, code, logs, scan, report, compare, trends, domain, config, case, and malware. |
| `.\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0`. |
| `.\.venv\Scripts\chinescan.exe scan` | 2 | `scan is planned for Phase 3 and is not implemented.` Expected explicit stub usage exit code. |
| `docker run --rm --network none chinescan:phase4-syslog-cef --help` | 0 | Existing local image rendered CLI help with no network. |

Not run: Docker image build (may fetch base/build dependencies from a registry), live domain
assessment, actual external-scanner binaries, YARA/ClamAV binaries, GitHub/GitLab remote CI,
and Bandit in this specific rerun. No production target or external domain was contacted.

## Local workflow hardening verification — 2026-10-26

The implementation run used the existing Python 3.12 environment and local tools. No
dependencies were installed and no images were fetched or built. The focused regression
suite first reported one test expectation error after missing explicitly selected config
files were made fatal; the test was corrected to cover the default-config-absent case. The
final full suite below passed.

| Command | Exit | Exact result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `86 passed in 12.27s`; total coverage `82.86%`; required 80% reached. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `93 files already formatted`. |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 41 source files`. |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChiNeScan distribution skipped. |
| `\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | `No issues identified`; five low-severity findings remain below the requested threshold. |
| `py -3.12 -m uv lock --check` | 0 | `Resolved 57 packages in 2ms`. |
| `py -3.12 -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON. |
| `py -3.12 -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | No output; valid Compose configuration. |
| `\.venv\Scripts\chinescan.exe --help` | 0 | Help includes global `--config` and `--database` options and existing commands. |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0`. |
| `\.venv\Scripts\chinescan.exe scan` | 2 | PowerShell `$LASTEXITCODE` was `2`; expected Phase 3 explicit stub. |
| `docker run --rm --network none chinescan:phase4-syslog-cef --help` | 0 | Existing local image rendered CLI help offline. The image was not rebuilt and does not include this worktree's new global options. |

Regression coverage added for shared archive expansion limits across multiple gzip inputs,
strict per-read byte bounds, an understated ZIP size declaration, malformed archives,
output overflow on both scanner streams, subprocess timeout/cancellation/JSON/exit paths,
settings precedence and secret redaction, validation before database creation, fresh and
legacy SQLite schemas, retained records, and incompatible-schema preservation. Ordinary
log fixture tests continue to pass. When the expanded-byte cap is reached, the member
using the remaining budget is rejected and all later inputs are skipped; previously parsed
events are retained.

Not run: Docker image build, remote CI, live domain probing, actual third-party scanner
binaries, or optional YARA/ClamAV binaries. The Docker build was skipped because it may
fetch images; no external targets or services were contacted. The timeout/cancel/output
tests use controlled local Python helpers or process doubles.

Known limits: output caps apply separately to stdout and stderr, and process termination
targets the direct scanner child (not an independently daemonized descendant). A legacy
database is accepted only for the exact initial table shape; other versions require an
explicit future migration. The migration downgrade in `0001_initial` still drops the
records table, so downgrade commands must not be used on data-bearing databases.


## Local investigation workflow verification — 2026-10-26

The local case workflow stage adds persisted case status and severity, typed links to existing
records, append-only notes and activity, ordered timelines, and redacted JSON/Markdown/HTML case
reports. `0002_case_workflow` is an application-payload revision over the existing generic JSON
record table; it does not rewrite payloads or change physical tables. Legacy unversioned stores
with the exact recognized initial schema are stamped at `0001_initial` and then upgraded to head.
Incompatible schemas are rejected without recreation. The report and schema are updated. No
production readiness is claimed.

| Command | Exit | Result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `93 passed in 30.80s`; total coverage `82.78%`; required 80% reached. |
| `& .\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `& .\.venv\Scripts\ruff.exe format --check .` | 0 | `96 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 42 source files`. |
| `& .\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable project skipped. |
| `& .\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | No medium/high findings; six low-severity findings remain below the selected threshold. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 57 packages in 112ms`; lock unchanged. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Valid Compose configuration. |
| `py -3.12 -m json.tool schemas\finding.schema.json > $null` and same for `investigation.schema.json` | 0 | Both schema files parse as JSON. |
| `& .\.venv\Scripts\chinescan.exe --help` and `case --help` | 0 | Existing CLI help and the new case commands render. |
| `& .\.venv\Scripts\chinescan.exe config init --path tests/.pytest-tmp/workflow-acceptance.toml` | 0 | Wrote local test configuration. |
| `& .\.venv\Scripts\chinescan.exe config validate --path tests/.pytest-tmp/workflow-acceptance.toml` | 0 | `Configuration is valid.` |

A direct `py -3.12 -m chinescan.cli.app --help` attempt returned exit 1 because the standalone
Python 3.12 interpreter does not have the project dependencies on its import path (`ModuleNotFoundError:
No module named 'typer'`). The equivalent existing-environment entry point, `& .\.venv\Scripts\chinescan.exe
--help` and `case --help`, passed as listed above. No JSON Schema metaschema validator was configured;
only JSON parsing was run.

The suite covers ordinary fixture-driven local ingestion, persisted/missing/dangling links, unsupported
non-persisted artifacts, invalid status transitions, note bounds, redaction and HTML escaping, deterministic
timelines and missing ingestion times, atomic report-write failures, fresh database creation, retained
legacy payloads through the supported upgrade, and incompatible schema preservation.

Docker image build was **NOT RUN** because it may fetch base images and the user did not authorize image
fetches. No live scanner, public target, malware execution, or upload was used. JSON parsing does not
establish full JSON Schema metaschema conformance. The migration stores notes/activity inside one JSON
case record; it has no relational foreign keys, and ingestion timestamps and structured remediation
content remain unavailable. Case author labels are unverified. This is local workflow validation, not a
production-readiness assessment.

Recommended next stage: define and test local data retention, backup/restore, and export handling for
case records, including recovery against a copied database and explicit policy for sensitive report files.


## Local data protection and recovery verification — 2026-10-26

Implemented a local recovery bundle and a dry-run backup retention planner. Backups use SQLite's
online backup API through a read-only source connection, stage a standalone database plus a
versioned manifest, verify them, and publish only at a new path. Manifest SHA-256 detects a mismatch
with the manifest; it is not authentication. Verification is read-only and distinguishes structural
errors, unsupported schema, and application consistency issues. It explicitly checks case links,
note/activity references, typed records, scan relationships, and other persisted links because case
links do not have SQL foreign keys. Restore requires a fully verified bundle, stages to a new file,
and runs existing Alembic migrations only on that staged copy. No database migration revision or
stored record format changed in this stage.

| Command | Exit | Result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `104 passed in 20.87s`; total coverage `81.85%`; required 80% reached. |
| `& .\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `& .\.venv\Scripts\ruff.exe format --check .` | 0 | `98 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 43 source files`. |
| `& .\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | No medium/high issues; six low-severity items remain below the configured threshold. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 57 packages in 2ms`; no lock changes. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Valid Compose configuration. |
| `py -3.12 -m json.tool schemas/finding.schema.json > $null` and `schemas/investigation.schema.json` | 0 | Both schema documents parse as JSON. |
| `git diff --check` | 0 | No whitespace errors; Git emitted its existing LF-to-CRLF working-copy notices. |

The recovery drill created local log-analysis records, a linked case, notes and status activity; created
and verified a backup; restored to a new path; reopened it through `SQLiteRepository`; compared case
IDs, status, links, notes, and activities; and rendered JSON, Markdown, and HTML reports. Separate
tests cover committed WAL data, missing source without accidental creation, existing destinations,
active database and hard-link aliases, cancellation and timeout staging cleanup, truncated/corrupt and
checksum-mismatched files, unsupported revisions, unversioned and 0001 legacy schemas, retained
payloads, dangling/invalid case relationships, invalid payloads, symlink-safe retention preview, and
case export no-overwrite behavior. CLI smoke checks completed `trends`, `db backup`, `db verify-backup`,
`db restore`, and `db retention-plan` using a temporary database; each exited 0 and the backup reported
`verified: true` at revision `0002_case_workflow`.

External dependency audit was **NOT RUN** because it would contact an advisory service and the request
forbids external requests without approval. No packages were installed. Docker image build was **NOT
RUN** because it may fetch images. No network target, external scanner, or malware sample was used.

Known limits: backups and exports are not encrypted. Checksums do not authenticate a bundle. Windows
mode-bit requests do not establish ACL protections; operators must review ACLs. Redaction is not
anonymization. Backup bundles preserve original sensitive records. Case links are checked at verify
time but remain without SQL foreign keys. Retention only previews; no backups or records are deleted.
A restore is published as a new file; active database replacement/cutover remains operator-controlled.
Case export publication uses same-directory hard links to prevent overwrite, so filesystems without
hard-link support fail closed. No production readiness is claimed.

Recommended next stage: conduct an operator-controlled cutover and rollback drill using a restored
copy, with documented downtime, database-path change, user verification, and recovery checkpoints.


## Recovery acceptance and operator cutover drill — 2026-10-26

Added `scripts/recovery_acceptance.py` and the operator sequence in `docs/RECOVERY-RUNBOOK.md`.
The script creates synthetic scan/log records and a case inside a temporary directory, closes the
repository before backup, creates and verifies a bundle, restores to a new database, and runs case
show, note list, timeline, and JSON/Markdown/HTML exports through the CLI with an explicit
`--database` path for each invocation. It adds a unique note only to the restored copy, selects the
original again, and verifies the original hash and case data remain intact. The restored-only note
remains divergent in the restored database; selecting the original does not merge it. The configuration
file is not changed, and neither the original nor backup bundle is replaced.

The drill refuses to invoke case commands against a missing selected file because ordinary
repository startup may initialize a database. This preflight prevents accidental creation within
the acceptance script; it does not change general CLI initialization behavior.

| Command | Exit | Result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `108 passed in 26.30s`; total coverage `82.44%`; required 80% reached. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest tests/unit/test_migration.py tests/unit/test_recovery.py -q` | 0 | `17 passed in 9.08s`. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 scripts/recovery_acceptance.py` | 0 | Completed; backup/case IDs emitted; JSON, Markdown, HTML generated; original intact; restored-only note stayed divergent. Temporary drill directory removed at process exit. |
| `& .\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `& .\.venv\Scripts\ruff.exe format --check .` | 0 | `100 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 43 source files`. |
| `& .\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | No medium/high issues; six low-severity findings remain below threshold. |
| `& .\.venv\Scripts\chinescan.exe --database tests/.pytest-tmp/cli-smoke-acceptance-20261026a/smoke.sqlite3 trends --days 1 --format json` | 0 | Empty temporary database returned zero scans. |
| `& .\.venv\Scripts\chinescan.exe --database tests/.pytest-tmp/cli-smoke-acceptance-20261026a/smoke.sqlite3 db backup --output tests/.pytest-tmp/cli-smoke-acceptance-20261026a/bundle --format json` | 0 | Created bundle at revision `0002_case_workflow`; verification true. |
| `& .\.venv\Scripts\chinescan.exe db verify-backup tests/.pytest-tmp/cli-smoke-acceptance-20261026a/bundle --format json` | 0 | `verified: true`, no structural/application issues. |
| `& .\.venv\Scripts\chinescan.exe --database tests/.pytest-tmp/cli-smoke-acceptance-20261026a/smoke.sqlite3 db restore tests/.pytest-tmp/cli-smoke-acceptance-20261026a/bundle --output tests/.pytest-tmp/cli-smoke-acceptance-20261026a/restored.sqlite3 --format json` | 0 | Restored to a distinct path; source/result revisions both `0002_case_workflow`. |
| `& .\.venv\Scripts\chinescan.exe --database tests/.pytest-tmp/cli-smoke-acceptance-20261026a/restored.sqlite3 trends --days 1 --format json` | 0 | Restored database opened and returned zero scans. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 57 packages in 4ms`; no lock changes. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Valid Compose configuration. |
| `py -3.12 -m json.tool schemas\finding.schema.json > $null` and `schemas\investigation.schema.json` | 0 | Both schema files parse as JSON. |
| `git diff --check` | 0 | No whitespace errors; existing LF-to-CRLF worktree notices were emitted. |

The suite also verifies a failed/corrupt backup cannot be restored, missing drill database selection
does not create a file, restored-only notes are absent from the original, original and restored paths
are not confused, and failed case-report publication removes its temporary file. Supported migration
behavior is covered by the focused migration/recovery tests. A permission-denied destination test was
not run because reliable ACL denial is environment and privilege dependent on this Windows host.

**Recovery acceptance verdict: PASS for the bounded local synthetic drill.** This verifies local
application behavior only. It does not prove that unrelated processes have closed the database, that
a backup is authentic or encrypted, or that an operational cutover is production ready. Backup and
reports remain unencrypted, Windows ACLs require separate review, links lack SQL foreign keys, report
publication needs same-directory hard-link support, retention is preview-only, and divergent writes
are not merged. No network-backed audit or image build was run; no dependency was installed or
external service contacted.

Recommended next stage: controlled real scanner integration verification with authorized local
fixtures and isolated helper processes.

## Separate-project scanning guide verification — 2026-10-26

Added `docs/SCANNING-ANOTHER-PROJECT.md` after inspecting the current CLI, code scanner, external adapters, settings/configuration, SQLite path handling, reporting, and development documentation. Verification used only `fixtures/sample-python-project`; no real separate project, external scanner, domain, advisory service, or downloaded database was used. The database and generated report were placed under `C:\scan-results\my-application`.

| Exact command | Exit | Exact relevant result |
| --- | ---: | --- |
| `& .\.venv\Scripts\chinescan.exe --help` | 0 | CLI help lists `code`, `report`, and global `--database`. |
| `& .\.venv\Scripts\chinescan.exe code --help` | 0 | Help confirms target argument, repeatable `--scanner`, `--semgrep-rules`, `--timeout-seconds`, `--fail-on`, and `--allow-network-audits`. |
| `& .\.venv\Scripts\chinescan.exe --database "C:\scan-results\my-application\chinescan.sqlite3" code .\fixtures\sample-python-project --format json` | 0 | Returned scan ID `62cacaf8-e059-4893-8c40-a1af6da186cd`; `finding_count: 3`; `failures: {}`; scanner `builtin`; target is the synthetic Python fixture. |
| `& .\.venv\Scripts\chinescan.exe --database "C:\scan-results\my-application\chinescan.sqlite3" report 62cacaf8-e059-4893-8c40-a1af6da186cd --format markdown --output "C:\scan-results\my-application\scan-62cacaf8-e059-4893-8c40-a1af6da186cd.md"` | 0 | Wrote Markdown report to the external results folder; file size 687 bytes. |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `108 passed, 5 deselected in 23.05s`; coverage `82.44%`, required 80% reached. |
| `& .\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!`. |
| `& .\.venv\Scripts\ruff.exe format --check .` | 0 | `104 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 43 source files`. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 57 packages in 3ms`. |
| `Get-Command semgrep,gitleaks,trivy,pip-audit,npm -ErrorAction SilentlyContinue | Format-Table Name,Source -AutoSize` | 0 | Only `npm.ps1` was found at `C:\Program Files\nodejs\npm.ps1`; Semgrep, Gitleaks, Trivy, and pip-audit were not found by this check. No external scanner was run. |

NOT RUN: dependency advisory audit because it contacts external advisory services; Docker build because it may fetch images; all actual external scanner executions; scanning from a separate live target; and runtime web assessment. The CLI invocations and outputs above verify local scan and Markdown report mechanics only. No application code was changed for this guide.

Additional exact working-directory check: from `C:\src\Chinescan\fixtures\sample-python-project`, `& $exe --database $db code . --format json` exited 0 and returned scan ID `0176dc24-673a-4472-b4ed-802104760390`, three findings, and no failures (`$exe` was the absolute ChiNeScan executable and `$db` the external database path). From that same working directory, `& $exe --database $db report 0176dc24-673a-4472-b4ed-802104760390 --format markdown --output 'C:\scan-results\my-application\scan-0176dc24-673a-4472-b4ed-802104760390.md'` exited 0 and wrote a 687-byte report outside the fixture.

## Offline verification — 2026-10-26

Commands ran from `C:\src\Chinescan` with Python 3.12.10. To use the existing Python 3.12
environment's installed tools without installing dependencies, PowerShell set
`$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'` before the commands below.

| Exact command | Exit | Exact result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | `Python 3.12.10` |
| `py -3.12 -m ruff check .` | 0 | `All checks passed!` |
| `py -3.12 -m ruff format --check .` | 0 | `105 files already formatted` |
| `py -3.12 -m mypy --strict chinescan` | 0 | `Success: no issues found in 43 source files` |
| `py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `108 passed, 5 deselected in 31.59s`; total coverage `82.44%`, required 80% reached. |

No dependencies were installed. Gitleaks was unavailable, so a local credential-pattern scan examined
147 intended files without printing matched contents. It reported three expected synthetic patterns
under `fixtures/real-scanners/gitleaks-positive/credential.txt`,
`fixtures/sample-python-project/app.py`, and `tests/integration/test_real_scanners.py`; no operational
database, backup, environment-secret, or investigation-export filenames were found. This pattern
scan is not a substitute for Gitleaks. Docker, external scanner, and network-backed checks were not
run.

## Merge verification — 2026-10-26

After resolving the merge of upstream `f06d43a`, checks ran from `C:\src\Chinescan` with Python
3.12.10 and the existing `.venv\Lib\site-packages` on `PYTHONPATH`. No dependencies were installed.

| Exact command | Exit | Exact result |
| --- | ---: | --- |
| `py -3.12 -m ruff check .` | 0 | `All checks passed!` |
| `py -3.12 -m ruff format --check .` | 0 | `106 files already formatted` |
| `py -3.12 -m mypy --strict chinescan` | 0 | `Success: no issues found in 43 source files` |
| `py -3.12 -m pytest --cov=chinescan --cov-report=term-missing --cov-fail-under=80` | 0 | `108 passed, 5 deselected in 22.65s`; total coverage `82.44%`, required 80% reached. |
| PyYAML parse of `.github/workflows/ci.yml` and `.github/dependabot.yml` | 0 | `YAML parse passed`. |
| `git diff --check` and `git diff --cached --check` | 0 | Both passed. |

## Authenticated dashboard Slice 1 verification — 2026-10-26

Added FastAPI, Uvicorn, argon2-cffi, and the Starlette-compatible `httpx2` API test transport to
the existing `uv` project environment. Added React/React DOM, Vite, TypeScript, React typings,
Vitest, jsdom, and Testing Library to `frontend/`. Direct dependencies are recorded in
`pyproject.toml` and `frontend/package.json`; exact resolutions are recorded in `uv.lock` and
`frontend/package-lock.json`. A lock comparison confirmed that no previously locked Python package
version changed; only dashboard dependencies and their transitive packages were added.

| Exact command | Exit | Exact result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | `Python 3.12.10` |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `115 passed, 5 deselected in 30.36s`; total coverage `83.05%`, required 80% reached. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m ruff check .` | 0 | `All checks passed!` |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m ruff format --check .` | 0 | `111 files already formatted`. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m mypy --strict chinescan` | 0 | `Success: no issues found in 46 source files`. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages in 2ms`. |
| `npm ci --no-audit; npm run typecheck; npm test -- --reporter=dot; npm run build` (from `frontend/`) | 0 | Clean lockfile install; TypeScript check passed; `1` Vitest file and `2` tests passed; Vite production build passed (`index.html` 0.47 kB, CSS 17.64 kB, JS 239.27 kB). |
| `& .\.venv\Scripts\chinescan.exe --help; ... web --help; ... web bootstrap --help; ... web serve --help` | 0 | Help lists explicit `web bootstrap` and `web serve`; server options have no host override. |
| Live loopback HTTP harness using `uvicorn.Server` on an ephemeral `127.0.0.1` socket | 0 | Served the built production shell; unauthenticated overview returned 401; sign-in set HttpOnly/SameSite=Strict cookie; persisted empty overview returned zero scans/findings; logout revoked access (subsequent request returned 401). Temporary credentials/database were removed. |
| `git diff --check` | 0 | Passed; Git emitted line-ending conversion notices only. |

The API tests exercise CLI bootstrap and repository-path rejection, protected reads, real SQLite
summary/detail data, bounded pagination and allowlisted filters/sorts, severity ordering, body and
validation limits, CSRF rejection, login throttling, host/origin rejection, session expiry, logout
revocation, new-application session invalidation, and fixed loopback/single-worker startup options.
The component tests exercise unauthorized login, backend-loaded metrics, and honest empty states.
Browser-level verification was **NOT RUN**; no browser binaries were downloaded. Domain probes,
external scanners, and other external services were not run.

`pip-audit` was **NOT RUN** because it queries an external advisory service, outside the approved
package-download scope. During initial npm package installation, npm also emitted its default
registry audit output (`0 vulnerabilities`); the final acceptance install used `--no-audit`.

## Chinetscan dashboard Slice 2 verification — 2026-10-26

The authenticated dashboard now exposes persisted cases and report downloads through the existing
`CaseWorkflow` and reporting renderers. No dependencies were installed or upgraded for Slice 2; the
existing lockfiles remain consistent.

| Exact command or check | Exit | Actual result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `116 passed, 5 deselected in 194.36s`; total coverage `83.28%`, above 80%. |
| `& .\\.venv312\\Scripts\\uv.exe run --offline ruff check .` | 0 | `All checks passed!` |
| `& .\\.venv312\\Scripts\\uv.exe run --offline ruff format --check .` | 0 | `111 files already formatted`. |
| `$env:PYTHONPATH='C:\\src\\Chinescan;.venv\\Lib\\site-packages'; py -3.12 -m mypy --strict chinescan` | 0 | `Success: no issues found in 46 source files`. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages`. |
| `npm --prefix frontend run typecheck` | 0 | TypeScript project build passed. |
| `npm --prefix frontend test -- --reporter=dot` | 0 | `2` test files, `5` tests passed (3 new case workflow tests plus the existing 2 dashboard tests). |
| `npm --prefix frontend run build` | 0 | Vite production build passed; CSS 20.43 kB and JS 248.96 kB (uncompressed). |
| Temporary live Uvicorn service bound to `127.0.0.1:8765`; HTTPX2 local smoke harness | 0 | Verified production shell, unauthenticated denial, sign-in, scan detail, filtered case listing, create/link/note/status, all case and scan report formats as attachments, logout revocation. Synthetic credentials/database were created under the user temp directory and removed afterward. |
| `git diff --check` | 0 | Passed; Git emitted line-ending conversion notices only. |

The five deselected tests are marked `real_scanner` by `tests/integration/test_real_scanners.py` and
are intentionally excluded by `tests/conftest.py`; they require external scanner binaries and
integration conditions that were not part of this local dashboard verification. No external
services were contacted.

Browser verification was **NOT PERFORMED**. The in-app browser control was available, but its local
browser view attach timed out. Checks for installed Chrome, Edge, Firefox, and Chromium executables
returned none. No browser binary was downloaded. To run the requested full browser smoke, approval is
needed to install a compatible Chromium-based browser binary and, if the existing browser control
remains unavailable, a Playwright-compatible browser test runtime and its browser package. The live
HTTP harness is API verification and is not represented as browser testing.

## Chinetscan dashboard browser acceptance — 2026-10-26

This section supersedes the earlier NOT PERFORMED note above. The user approved only the npm
registry packages required for `@playwright/test` and Playwright's official Chromium assets. The
frontend lockfile now resolves `@playwright/test` 1.64.1. `npx playwright install chromium` downloaded
Chrome for Testing 156.0.8078.4 and the matching Playwright headless shell from Playwright's official
distribution. No package or browser was installed globally. The `npm install` and clean `npm ci`
commands both used `--no-audit`.

The browser harness serves the actual built `frontend/dist` from `create_app` using a temporary
SQLite database containing synthetic scans, findings, and an event. It generates random operator
credentials under a unique temporary directory, starts two Python services on ephemeral
`127.0.0.1` ports, uses only loopback requests, and removes the services and temporary directories
after each run. Credential values, cookies, browser profiles, and Playwright artifacts are not
tracked. Browser traces and screenshots are configured for failures only; the successful run
produced no failure artifacts.

| Exact command/check | Exit | Actual result |
| --- | ---: | --- |
| `npm install --save-dev @playwright/test --no-audit` (from `frontend/`) | 0 | Added 3 packages; lockfile updated with `@playwright/test` 1.64.1. |
| `npx playwright install chromium` (from `frontend/`) | 0 | Installed official Chrome for Testing 156.0.8078.4 and matching headless shell. |
| `npm ci --no-audit` (from `frontend/`) | 0 | Clean lockfile install; added 106 packages. |
| `npm run test:e2e` (from `frontend/`) | 0 | Chromium: `3 passed` (production dashboard workflow, finding detail/XSS text handling, and a scan request held in flight until session expiry); `34.3s`. No tests skipped. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `116 passed, 5 deselected in 96.02s`; total coverage `83.28%`, above 80%. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m ruff check .` | 0 | `All checks passed!` |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m ruff format --check .` | 0 | `112 files already formatted`. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m mypy --strict chinescan` | 0 | `Success: no issues found in 46 source files`. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages in 60ms`; Python lockfile consistent. |
| `npm run typecheck` (from `frontend/`) | 0 | `tsc -b --pretty false` passed. |
| `npm test -- --reporter=dot` (from `frontend/`) | 0 | `2` component-test files and `5` tests passed. Vitest's test timeout was raised to tolerate this host's slow jsdom startup. |
| `npm run build` (from `frontend/`) | 0 | Production build passed; CSS 20.43 kB, JS 249.11 kB (uncompressed). |
| `git diff --check` | 0 | Passed; only existing LF-to-CRLF notices were printed. |

The five Python tests deselected by `tests/conftest.py` carry the `real_scanner` marker and require
external scanner binaries; they were not part of this local browser acceptance. No assessment job,
external target, advisory service, or external upload was used. The browser suite explicitly checked
that its intentional pre-login/session-expiry 401s and invalid-scan 404 were the only failed API
responses, with no unexpected browser console errors or server errors.

**Browser acceptance verdict: PASS** for the requested dashboard Slices 1 and 2 workflows against
the production frontend and local authenticated backend.

## Dashboard Slice 3A — local code-assessment jobs — 2026-10-26

Implemented an operator TOML project registry, authenticated and CSRF-protected job creation,
persisted job state, one worker with four waiting slots, startup interruption reconciliation, bounded
job listing/detail, and a dashboard form/list with two-second polling while active jobs are present.
The dashboard uses only `BuiltinRuleScanner` through `CodeScanService`; optional engines and
network-backed dependency checks cannot be requested. Jobs return a scan ID only after the service
has persisted the scan and result records. The UI opens the persisted scan and finding IDs and uses
the existing case workflow. Project IDs, names, and roots are operator configured outside the
browser; API responses omit full paths and raw logs.

Path validation resolves configured roots strictly and excludes the database directory, operator
credential file, and registry file. It rejects symlinked path components and symlink/junction entries
found during a preflight tree walk. The existing scanner does not follow directory symlinks and skips
symlink files. This remains vulnerable to a time-of-check/time-of-use change after validation; it is
not OS filesystem isolation. Built-in scanning has file-count and byte bounds but no safely
interruptible wall-clock timeout. Graceful shutdown waits for active work. A restarted server marks
persisted queued/running jobs interrupted without asserting that an OS process was terminated.

| Exact command | Exit | Result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | Final isolated run: `123 passed, 5 deselected in 193.86s`; total coverage `83.59%`, threshold 80% reached. |
| `& .\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `& .\.venv\Scripts\ruff.exe format --check .` | 0 | `115 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 47 source files`. |
| `npm run typecheck` (from `frontend/`) | 0 | TypeScript project check passed. |
| `npm test` (from `frontend/`) | 0 | `3` test files and `7` component tests passed. |
| `npm run build` (from `frontend/`) | 0 | Final Vite production build passed; CSS `21.21 kB`, JavaScript `254.67 kB` (uncompressed). |
| `npm run test:e2e` (from `frontend/`) | 0 | Full run after the case-selection race fix: `4 passed` in `2.3m`, including the complete job/result/case/refresh path and session-expiry coverage. A later run after registry hardening produced `3 passed, 1 failed` because the 15-second expiry fixture expired before the Overview page finished signing in on this slow host. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages in 3ms`; no lock changes. |
| `& .\.venv\Scripts\chinescan.exe web serve --help` | 0 | Help includes `--projects-file`, port, and credential options. |
| `git diff --check` | 0 | Passed; Git printed existing LF-to-CRLF working-copy notices. |

The five deselected Python tests require real optional scanner binaries. They were not run. No
dependency was installed, scanner or rules database downloaded, external target contacted, or
network-backed audit performed. Queue bounds, duplicate active project submission, failed scanner
and persistence outcomes, auth/CSRF, unknown project, missing/protected roots, symlink rejection,
restart reconciliation, and no fixture modification have focused backend tests. Browser acceptance
used only synthetic local fixture source and the existing Playwright installation.

Known limitations: queue depth is fixed at four waiting jobs; there is no cancellation or progress
percentage; built-in scans have no hard elapsed-time limit; abrupt filesystem changes can race the
preflight walk; scan writes are existing per-record repository operations rather than a new atomic
multi-record transaction. This slice does not claim comprehensive security coverage or production
readiness. Recommended next stage: design and verify a cancellable, resource-limited worker boundary
with atomic scan-result publication before adding additional assessment types.

The final isolated Playwright retry `npx playwright test -c playwright.config.ts --project=chromium-session-expiry`
exited 1 before executing tests: the Python dashboard fixture did
not start within its 60-second harness startup window (no server stderr was emitted). This is an
harness-level startup timeout with undetermined cause, separate from the 15-second session expiry
observed in the preceding full-suite rerun. The complete job workflow itself passed in both
full-suite reruns.

## Dashboard Slice 3A stabilization — 2026-10-26

Root cause separation: the earlier expiry failure happened in the dedicated 15-second session
fixture while the Overview transition was still in progress. The standard dashboard fixture has its
own 1,800-second TTL. The existing captured output does not establish why the separate local Python
fixture failed to announce readiness within 60 seconds; it emitted no stderr, so that event is
classified as an undiagnosed fixture startup failure, not attributed to the host. No authentication
bypass, retry, or longer production session lifetime was introduced.

The browser harness now captures bounded diagnostics (last 4,000 characters per output stream),
checks early process exit, confirms Python 3.12 and repository-root working directory through its
explicit `py -3.12` launch, uses the server's OS-assigned loopback port, and requires an actual HTTP
401 from `/api/auth/session` before declaring readiness. One reproduction printed its URL just after
the previous 60-second announcement bound; the bounded announcement window is now 120 seconds, with
a separate 10-second HTTP readiness bound. Failed setup and normal teardown terminate only the
test-owned process tree and remove its temporary data. The existing real 15-second expiry and
server-side 401 behavior are unchanged; expiry uses observable request/session conditions, not a
fixed sleep. Playwright retries remain disabled.

A later browser failure snapshot showed the production page still displaying `Signing in…` when the
test asserted Overview content. The production browser test now waits for a successful login
response and the visible Overview heading before checking stored records; it does not expand global
expectation or session timeouts.

Project roots automatically exclude the active SQLite parent directory (database and sidecars),
operator credentials, and registry. Operator `protected_paths` remains available for additional
backup/report storage. This dashboard has no managed backup or report/export directory; reports are
generated in memory. Roots are strictly resolved, link/junction entries are rejected where
supported, overlap checks work in both directions, and registry/tree checks run again before
execution. The filesystem check/open race remains and this is not sandbox isolation.

The scanner previously omitted individual source files over 1 MB, which could look like a clean
result. It now reports that input-limit exhaustion as a scan failure. Existing limits are 1 MB per
source, 20,000 source files, and 250 MB aggregate source bytes. The queue allows four waiting jobs;
one worker executes at a time. These are separate from elapsed-time limits and cancellation, neither
of which exists. Graceful shutdown waits for an active scan. Restart reconciliation marks unfinished
jobs interrupted but does not prove process termination. Failed scan-result persistence produces a
sanitized failed job record. A hard deadline needs a worker-process boundary and is outside this
stabilization.

The five deselected tests are the opt-in tests in `tests/integration/test_real_scanners.py`; they
require the actual Semgrep, Gitleaks, Trivy, YARA, and ClamAV executables, plus local Trivy/ClamAV
database assets. These are deliberately not installed or fetched during this run.

| Exact command | Exit | Result |
| --- | ---: | --- |
| `set PYTHONPATH=C:\src\Chinescan;.venv\Lib\site-packages&& py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `126 passed, 5 deselected in 156.59s`; total coverage `83.62%` (80% threshold met). |
| `.venv\Scripts\ruff.exe check . && .venv\Scripts\ruff.exe format --check .` | 0 | `All checks passed!`; `115 files already formatted`. |
| `.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 47 source files`. |
| `node_modules\.bin\tsc -b --pretty false` (from `frontend/`) | 0 | TypeScript project check passed. |
| `node_modules\.bin\vitest run` (from `frontend/`) | 0 | `3` files and `7` tests passed. |
| `node_modules\.bin\vite build` (from `frontend/`) | 0 | Production build passed; JS `254.67 kB`, CSS `21.21 kB`. |
| `node_modules\.bin\playwright test -c playwright.config.ts` (from `frontend/`), run 1 | 0 | `4 passed` in `2.4m`; expiry case `33.4s`. |
| Same complete Playwright command, run 2 | 0 | `4 passed` in `1.4m`; expiry case `24.7s`. |
| Same complete Playwright command, run 3 | 0 | `4 passed` in `53.6s`; expiry case `20.6s`. |
| `.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages in 4ms`; lock unchanged. |
| `git diff --check` | 0 | Passed; Git emitted existing LF-to-CRLF working-copy notices. |

No dependencies were installed, no external service was contacted, and no real scanner was run.
Browser acceptance is qualified to the local synthetic fixture and these three consecutive clean
suite runs. Worker execution still has no hard deadline or cancellation, and filesystem path checks
do not provide an OS sandbox.

## Dashboard release verification — 2026-10-26

Current local verification for the stabilized dashboard release scope. The five real-scanner tests
remain deselected; they require Semgrep, Gitleaks, Trivy, YARA, and ClamAV binaries (and local Trivy
or ClamAV data where applicable). No real scanner or remote target was used.

| Exact command/check | Exit | Actual result |
| --- | ---: | --- |
| `set PYTHONPATH=C:\src\Chinescan;C:\src\Chinescan\.venv\Lib\site-packages && py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `126 passed, 5 deselected in 160.08s`; total coverage `83.62%`, above 80%. |
| `.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `.venv\Scripts\ruff.exe format --check .` | 0 | `115 files already formatted` |
| `.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 47 source files` |
| `.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages in 250ms`; Python lock unchanged. |
| `npm ci --dry-run --no-audit` (from `frontend/`) | 0 | `up to date in 13s`; npm lockfile and manifest are consistent. No packages were installed. |
| `npm ls --depth=0` (from `frontend/`) | 0 | All 13 declared direct frontend dependencies resolved to the installed versions. |
| `npm run typecheck` (from `frontend/`) | 0 | `tsc -b --pretty false` passed. |
| `npm test -- --reporter=dot` (from `frontend/`) | 0 | `3` files and `7` component tests passed. |
| `npm run build` (from `frontend/`) | 0 | Production build passed; CSS `21.21 kB`, JavaScript `254.67 kB` (uncompressed). |
| `npm run test:e2e` (from `frontend/`) | 0 | `4 passed` in `1.3m` using local synthetic data and Chromium. |
| `.venv\Scripts\chinescan.exe web serve --help` | 0 | Confirms explicit startup, one worker on `127.0.0.1`, default port `8765`, and optional credential/project file paths. |
| `.venv\Scripts\chinescan.exe web bootstrap --help` | 0 | Confirms explicit operator bootstrap and required `--username`; password is entered interactively. |
| `.venv\Scripts\chinescan.exe code --help` | 0 | Confirms local project target, built-in default scanner, optional scanner selection, and network-audit consent flag. |
| `.venv\Scripts\chinescan.exe db --help` | 0 | Confirms backup, verify-backup, restore, and retention-plan commands. |

The first browser acceptance attempt failed before tests because the Windows Python launcher did not
inherit the project environment's Uvicorn dependency. The harness now adds the local Windows
environment only when using `py`; CI supplies its locked `.venv` interpreter explicitly. The
complete browser run above passed after that correction. Failure diagnostics omit the harness
stdout because it contains generated login credentials. `npm ci --no-audit` remains enforced in
CI; local verification used the already installed dependencies and did not reinstall packages.

## Dashboard Stage A — authenticated local log-analysis jobs — 2026-10-27

The web server now accepts an operator-selected log-source registry through the explicit
`--log-sources-file` option (default `~/.config/chinescan/log-sources.toml`). API clients submit
only a configured source ID. Jobs use `LogAnalysisService` directly with the existing parser,
normalization, local detection, IOC matching, and persistence path. The manager persists queue and
terminal states, partial diagnostics, and the actual result scan ID. One worker runs at a time with
four waiting jobs, and abandoned queued/running jobs reconcile as `interrupted` at startup. No new
database revision or package dependency was required.

Authenticated result routes expose bounded alert, event, and timeline pages and reviewed alert/event
details scoped to the selected log scan. Responses omit raw event references and full paths. The
frontend selects approved sources, starts and polls jobs, shows partial diagnostics, pages and filters
results, creates cases, links alerts/events, and retains stored records across refresh. The synthetic
browser fixture includes malformed content and verifies that the job is visibly `partial`; its
redacted case report still contains available evidence. Original fixture bytes are hash-checked by
the backend test. No original logs are modified or uploaded.

### Exact verification commands and results

| Command | Exit | Result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `129 passed, 5 deselected in 164.01s`; total coverage `83.32%` (80% threshold met). The five deselected tests require real Semgrep, Gitleaks, Trivy, YARA, and ClamAV assets. |
| `.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `.venv\Scripts\ruff.exe format --check .` | 0 | `118 files already formatted`. |
| `.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 48 source files`. |
| `.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages`; lock unchanged. |
| `npm run typecheck` (from `frontend/`) | 0 | `tsc -b --pretty false` passed. |
| `npm test -- --reporter=dot` (from `frontend/`) | 0 | `3` files and `7` component tests passed on rerun. An earlier rerun had one existing slow-session test timeout while rendering the initial session check; no retries were added. |
| `npm run build` (from `frontend/`) | 0 | Vite production build passed; JS `264.84 kB`, CSS `22.62 kB` uncompressed. |
| `npm run test:e2e` (from `frontend/`) | 0 | `5 passed` in `1.8m`, including approved project jobs, the Stage A partial-log workflow, protected reads, redaction, case links/report, refresh, and session expiry. The first run exposed and led to corrections in test expectations/report-link selection; the successful run used no retries. |
| `npm ci --dry-run --no-audit` (from `frontend/`) | 0 | `up to date in 9s`; no packages installed. |
| `.venv\Scripts\chinescan.exe web serve --help` | 0 | Help lists `--log-sources-file`; startup remains explicit. |
| `git diff --check` | 0 | Passed; Git emitted existing LF-to-CRLF working-copy notices. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest tests/unit/test_log_jobs.py tests/unit/test_web_api.py -q` | 0 | `11 passed in 48.04s`. |

The new tests exercise unknown source rejection, request path/additional-field rejection, unavailable
and protected roots, queue exhaustion, restart interruption reconciliation, protected unauthenticated
access, CSRF behavior, path-free API responses, pagination bounds, event case linking, report
download, and unchanged input hashes. Existing log-analysis tests cover bounded ingestion, compressed
archive expansion, parser errors, and event limits. A dedicated browser polling-expiry scenario was
not added; existing browser session-expiry coverage verifies protected action denial and return to
sign-in. Resource termination is not guaranteed after abrupt process loss, and the worker has no
cancellation or hard execution deadline. No external scanner, network collector, advisory service,
or remote target was used.

## Stage B1 backend verification — 2026-10-27

The fixtures were harmless synthetic files only. B1 is backend-only: no web routes, browser uploads,
case links, downloads, deletion controls, or external services were added. Five tests marked
`real_scanner` were deselected because they require Semgrep, Gitleaks, Trivy, YARA, and ClamAV
assets; no real scanner binary was verified or called by B1.

| Exact command/check | Exit | Actual result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | `Python 3.12.10` |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `149 passed, 5 deselected in 135.87s`; total coverage `82.97%` (80% threshold met). |
| `.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `.venv\Scripts\ruff.exe format --check .` | 0 | `124 files already formatted` |
| `.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 51 source files` |
| `.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages in 65ms`; lock unchanged. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 scripts\recovery_acceptance.py` | 0 | Backup/restore drill completed; JSON, Markdown, and HTML reports generated; original database remained intact and restored-only writes stayed divergent. |
| `git diff --check` | 0 | Passed; Git printed existing LF-to-CRLF working-copy notices. |

Windows test evidence is separated by type. Actual host tests passed for the fixed worker under a
configured Job Object, persisted analysis through that worker, and termination of a synthetic
Python parent/child process tree. Mocked tests separately passed timeout, output-overflow, and
pipe-cleanup control paths. Migration preservation, atomic queue claim, five-slot queue limit,
bounded intake, source/object mutation detection, publication-failure orphan handling, restart
reconciliation, and restore with a missing managed object passed in the Python suite.

**Worker guarantees:** On this Windows host, the implementation created and queried a Job Object,
applied 512 MiB per-process and 768 MiB aggregate committed-memory limits, a four-process tree cap,
a 60-second Job user CPU-time limit, and kill-on-last-handle-close. It assigned the worker and
verified assignment before sending the sample path. The parent enforces a 60-second wall deadline,
3 MiB output/result caps, and termination on timeout or overflow. The fixed child receives a minimal
environment, no shell, and no persistence responsibility. Non-Windows execution fails closed.

These controls do not restrict filesystem or network access, establish an OS sandbox, protect
managed files from a process with write access, or prove sample authenticity. Managed storage is not
authenticated chain of custody. A path/open race remains despite link/reparse checks and source
identity comparisons. ZIP central-directory parsing is skipped and reported partial; reaching
string/indicator caps is also partial. A database failure after exclusive object publication leaves
an unexplained object for operator review; reconciliation never deletes it. Recovery restores
metadata but never reconstructs missing sample bytes from registry originals. B1 has no retention
policy, route-level authorization surface, or sample-byte API. Job Object association does not cover
children launched through every alternate Windows system service; the tree claim covers processes
Windows associates with this Job Object.

## Stage B1 definition of done

- [x] Explicit local registry, configured managed storage, bounded managed-copy intake, and opaque
  non-overwriting object publication.
- [x] Additive Alembic revision, separate sample and analysis records, bounded result/audit records,
  atomic queue reservation/claim, and metadata-only backup/recovery behavior.
- [x] Fixed worker entry point with verified Windows Job Object controls, timeout, bounded output,
  cleanup paths, and fail-closed unsupported-host behavior.
- [x] Synthetic regression coverage for limits, mutation, publication failure, timeout/output,
  process-tree termination, migration, restart reconciliation, and missing-object recovery.
- [x] Operating documentation, audit, and verification report updated.
- [ ] B2 requires separate approval for authenticated routes, result disclosure, UI/case links,
  retention/deletion, queue shutdown/cancellation, and any browser transfer of sample bytes.

## Release verification — 2026-10-27

Release candidate includes Stage A log-analysis jobs and the backend-only B1 managed-copy worker.
No incomplete B2 routes, browser sample transfers, retention/deletion controls, or sandbox guarantees
are included. The CI workflow now has a scoped Windows worker-acceptance job for actual Job Object
checks and an explicit frontend dependency audit after `npm ci --no-audit`.

| Exact command/check | Exit | Actual result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80 --basetemp=tests/.pytest-tmp-release` | 0 | `149 passed, 5 deselected in 141.70s`; total coverage `82.97%`. The five opt-in tests require real Semgrep, Gitleaks, Trivy, YARA, and ClamAV binaries/assets; none were installed, fetched, or called. |
| `.venv\Scripts\pytest.exe tests/unit/test_managed_malware.py -q --basetemp=tests/.pytest-tmp-b1` | 0 | `19 passed in 16.39s` on Windows, including actual worker execution and synthetic Job Object process-tree termination. |
| `.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `.venv\Scripts\ruff.exe format --check .` | 0 | `124 files already formatted`. |
| `.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 51 source files`. |
| `.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 76 packages`; lock consistent. |
| `.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable project distribution skipped. |
| `.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | No medium/high issues; 12 low-severity findings remain documented in the security review. |
| `npm ci --dry-run --no-audit` (from `frontend/`) | 0 | `up to date in 9s`; frontend manifest and lock agree. |
| `npm audit --audit-level=moderate` (from `frontend/`) | 0 | `found 0 vulnerabilities`; same command is now a CI step. |
| `npm run typecheck` (from `frontend/`) | 0 | TypeScript project check passed. |
| `npm test -- --reporter=dot` (from `frontend/`) | 0 | 3 test files and 7 component tests passed. |
| `npm run build` (from `frontend/`) | 0 | Production build passed; JS `264.84 kB`, CSS `22.62 kB` uncompressed. |
| `npm run test:e2e` (from `frontend/`) | 0 | `5 passed (1.8m)` in Chromium against local synthetic fixtures. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 scripts\recovery_acceptance.py` | 0 | Backup/restore drill completed; JSON, Markdown, and HTML reports generated; original database remained intact and restored-only writes stayed divergent. |
| `git diff --check` | 0 | Passed after adding this release-verification section; rerun after final edits. |

An initial full Python run returned 146 passed and 3 failed (with the same five deselected): the
synthetic child-process tree did not start in one Job Object test, and two backup publication checks
hit Windows `WinError 5`. The managed-malware suite then passed all 19 tests in isolation, including
the actual synthetic process-tree check, and the complete sequential rerun passed all 149 selected
tests. A later diagnostic pair of simultaneous pytest invocations also collided because both used the
shared `tests/.pytest-tmp` path; those overlapping results were discarded. The browser suite passed on
its isolated rerun after one session-expiry login timeout during the first run.

The initial GitHub Actions run for `eb04cdfabae9be41409e4682e19a2f33b3c265eb` is recorded at
<https://github.com/CipherChi/Chinescan/actions/runs/40536275930>. Strict mypy failed on Linux because
`ctypes.WinDLL` is absent from Linux's ctypes stubs. The focused correction now resolves `WinDLL`
dynamically and fails closed if unavailable; Linux-platform mypy emulation passes locally. The same
run's Windows managed-malware job, secret scan, and container build/security job passed; the dashboard
browser job and overall workflow were still in progress when the initial failure was diagnosed. The
offline benchmark run for that SHA passed at
<https://github.com/CipherChi/Chinescan/actions/runs/40536275831>. Follow-up remote verification of
the correction is required before release checks can be called complete.

## Follow-up security review — 2026-10-27

The follow-up CI run for `480f020e96a97887d8429df3c038fbe1173f91e6` passed its quality,
Windows B1, dashboard, container, and secret-scan jobs. The matching CodeQL analyses and offline
benchmark run also completed successfully:

- CI: <https://github.com/CipherChi/Chinescan/actions/runs/40538024346>
- CodeQL: <https://github.com/CipherChi/Chinescan/actions/runs/40538024315>
- Offline benchmarks: <https://github.com/CipherChi/Chinescan/actions/runs/40538024313>

Review of that commit's CodeQL findings identified legacy TLS versions being permitted by the
domain probe and generated browser-test credentials being printed by the test harness. The current
follow-up changes explicitly require TLS 1.2 or newer and pass generated test credentials through
the harness's stdin pipe while printing only the loopback URL. Local regression and browser tests
pass; remote confirmation is pending for the follow-up commit.

The Trivy report step listed 44 high-severity package matches across eight Debian advisories in the
pinned `python:3.12.15-slim-trixie` image; the blocking policy step passes because none are marked
fixable in the current Trixie package set. Debian's tracker lists fixes only in newer or unstable
package lines for these findings: [ncurses](https://security-tracker.debian.org/tracker/CVE-2025-69720),
[systemd](https://security-tracker.debian.org/tracker/CVE-2026-16742),
[ACL](https://security-tracker.debian.org/tracker/CVE-2026-54369),
[util-linux](https://security-tracker.debian.org/tracker/source-package/util-linux), and
[Perl Archive::Tar](https://security-tracker.debian.org/tracker/CVE-2026-9538). Moving the base
image to a newer Debian release or carrying package backports needs a separate security decision.

## Stage B2 resume verification — 2026-10-27

This section records checks rerun against the resumed B2 worktree. It supersedes earlier B2
verification statements where these commands were rerun. Python checks were run in PowerShell with
`$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages';` before the listed `py -3.12`
command. The lock check used the repository's `.venv312` executable.

| Command | Result |
| --- | --- |
| `py -3.12 --version` | Python 3.12.10 |
| `py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | **Interrupted, not passed:** 105 passed, 5 deselected, then `KeyboardInterrupt` while entering malware worker-control tests; no coverage summary or threshold result was produced. Full-trace localized one interruption to `Thread.start()` waiting on its startup event. |
| `py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80 -k "not test_worker_control_path_timeout_and_output_overflow_close_pipes"` | **Interrupted, not passed:** 105 passed, 6 deselected, then `KeyboardInterrupt`; no coverage summary. |
| `py -3.12 -m pytest tests/unit/test_recovery.py -q` | **Passed:** 15 passed in 13.20s. Earlier sequential runs were 15 passed in 24.29s, then 13 passed / 2 failed in 25.98s due WinError 5 at backup publication. |
| `py -3.12 -m pytest tests/unit/test_web_api.py -q` | **Passed:** 10 passed in 17.89s, including B2 API authentication/redaction coverage. |
| `py -3.12 -m pytest tests/unit/test_migration.py tests/unit/test_cases.py tests/unit/test_reporting.py -q` | **Passed:** 11 passed in 6.17s. |
| `py -3.12 -m pytest tests/unit/test_managed_malware.py -q` | **Not passed:** one run was interrupted after 17 passes; another run filtered to non-process-control cases produced 16 passed / 1 failed / 4 deselected because the backup-with-malware-metadata case hit the same publication error. |
| `py -3.12 -m pytest tests/unit/test_managed_malware.py::test_worker_control_path_timeout_and_output_overflow_close_pipes -vv` | **Passed:** 1 passed in 0.66s when isolated. |
| `py -3.12 -m pytest tests/unit/test_managed_malware.py::test_actual_windows_contained_worker_returns_bounded_synthetic_result tests/unit/test_managed_malware.py::test_actual_windows_manager_persists_contained_synthetic_analysis -vv` | **Passed:** 2 actual Windows worker tests passed in 2.56s. |
| `py -3.12 -m pytest tests/unit/test_managed_malware.py::test_actual_job_object_terminates_synthetic_child_process_tree -vv` | **Passed:** 1 actual Windows Job Object process-tree test passed in 0.76s. |
| `py -3.12 -m pytest tests/unit/test_managed_malware.py::test_recovery_keeps_metadata_but_does_not_reconstruct_missing_sample -vv --tb=long` | **Passed in isolation:** 1 passed in 2.64s, after the same test failed during the filtered file run at backup publication. |
| `py -3.12 -m ruff check .` | **Passed:** All checks passed. |
| `py -3.12 -m ruff format --check .` | **Passed:** 125 files already formatted. |
| `py -3.12 -m mypy --strict chinescan` | **Passed:** no issues in 52 source files. |
| `& .\.venv312\Scripts\uv.exe lock --check` | **Passed:** resolved 76 packages; lock is consistent. |
| `npm run typecheck` | **Passed.** |
| `npm test -- --reporter=dot` | **Passed:** 4 files, 8 tests. |
| `npm run build` | **Passed:** Vite production build, 21 modules. |
| `npm run test:e2e` | **Passed on rerun:** 6 passed in 1.3m. Includes actual Windows contained-worker triage, persisted result/completeness, case linking, redacted JSON export, refresh persistence, and logout denial. The prior run had 4 passed / 2 failed: one stale Playwright APIRequestContext cookie assertion (corrected to use browser-context fetch) and one session-expiry fixture sign-in timeout; both passed on rerun. |
| `npm run test:e2e -- --grep "actual contained malware triage"` | **Passed:** 1 passed in 31.6s on current test code. This exercised the actual Windows built-in worker; it was not mocked. |
| `git diff --check` | Passed before this section was appended; rerun after final edits. |

### WinError 5 investigation

The captured exception is `PermissionError: [WinError 5] Access is denied` from
`os.rename(staging, output)` in `chinescan/core/storage/recovery.py` while publishing a complete
backup staging directory to a destination that did not exist. Two recovery tests in one sequential
run hit this operation. Source and database handles are closed before publication; verification
and hashing use closed file contexts, and failed staging cleanup completed. Pytest uses per-test
`tmp_path` directories. No concurrent Python test process was active during the initial isolated
reproductions; the same B2 recovery test failed once in a sequential focused file run and then passed
when isolated. The parent test directory ACL grants full access to owner, SYSTEM, and administrators;
the current user is non-administrator. The code's `chmod(0700/0600)` calls do not prove Windows ACL
enforcement. No evidence established an open handle, shared path collision, or specific permission
cause. An isolated formerly failing verification test and a later full recovery run passed, but
another earlier full recovery run had two publication failures. No retry or publication semantic
change was made. **Root cause remains unresolved; recovery publication is not fully verified.**

Five optional `real_scanner` cases were deselected by the configured suite because no YARA/ClamAV
binary and signature database were installed or verified. Neither engine was enabled or invoked.
No external submission, new dependency, commit, or push was performed. Windows Job Object controls
are process containment only; they do not provide an OS sandbox or remove filesystem race conditions.

### Release-blocker diagnosis — 2026-10-27

| Status | Result |
| --- | --- |
| B2 browser acceptance | **Passed:** 6/6 in the final full Playwright run; actual Windows contained worker, persisted analysis, case link, redacted report export, refresh, and logout protection. |
| Full Python acceptance | **Incomplete:** every attempted full run ended with `KeyboardInterrupt`; no completed full-suite coverage percentage or threshold result exists. |
| Backup publication reliability | **Unresolved:** earlier recovery tests raised WinError 5 at publication; no root cause or code change established. |
| Release readiness | **Blocked** pending a completed full Python acceptance run and backup publication reliability resolution. |

The verbose managed-malware trace identifies the active item and stack, not a test assertion failure:
17 tests completed, then `KeyboardInterrupt` arrived on the main thread while
`threading.Thread.start()` waited for its new reader thread to initialize. The test patches
`subprocess.Popen` and uses a fake process and fake Job Object; it launches and terminates no real
worker. A temporary signal observer recorded SIGINT (signal 2), with only the main thread present,
within milliseconds of that item's setup hook. In a separate detached run, SIGINT arrived during the
SQLite backup progress callback at `recovery.py` line 562 after 14 tests, so the event is not specific
to the reader-thread test. Repository searches found no signal or console-control operation in this
test file; the explicit fake `KeyboardInterrupt` in `test_external_scanners.py` is unrelated and is
not part of the isolated reproduction. A 20-second Python sleep completed with exit code 0. A
PowerShell background-job attempt ended with Windows status `-1073741510` (`STATUS_CONTROL_C_EXIT`)
before it wrote its exit file. Console process-list diagnostics showed the pytest process and its
`py.exe` parent attached to a console, but did not identify which host component generated the
control event. Thus a real external/control SIGINT is evidenced; whether its source is the Codex
execution host, its console lifecycle, or another host process is not established. No signal was
suppressed and no worker-control tests were skipped.

A corrected diagnostic loop ran 500 B2-shaped backups serially, each using a unique temporary
directory under the pytest temporary root and valid managed sample/job metadata. It exited 0 with
zero publication errors. Earlier diagnostic wrappers saw two `OSError` events at the wrapped rename
but then raised their own formatting `TypeError`, so they did not preserve the error code or a valid
state snapshot and are excluded as diagnostic evidence. The recorded real test trace from the prior
recovery runs remains `PermissionError: [WinError 5] Access is denied` at
`os.rename(staging, output)`. It occurred while the staging directory existed and the destination
was absent; the backup function's cleanup removed staging and left the destination absent. Handles
to the source and destination SQLite connections are closed before publication by code inspection.
The 500-run probe found no failure at which to capture file attributes, same-volume state, or an
OS-level holder list. The cause remains unestablished; no retry, overwrite, weakened integrity
check, or skipped recovery test was introduced.

Smallest next diagnostic action: run the managed-malware focused suite from an independent,
persistent Windows PowerShell session outside the Codex command process group, and return its exit
code plus the failing item/trace if SIGINT recurs. For backup publication, the next failing event
must be captured before cleanup with Windows file attributes and Restart Manager's resource-holder
list; the current isolated 500-run reproduction did not trigger it. Until both signals are resolved,
do not mark the release checks complete.

## CI failure follow-up — 2026-10-28

The screenshot corresponds to GitHub Actions run `40656496453` at commit
`2f5b03500bc93411c3c795901a0e43337ba85a99`. Its three failing checks had distinct causes:

- `quality`: `test_malware_api_fail_closed_and_redacted_case_linking` expected HTTP 422 for an
  unknown registered sample, but got 503 on Linux because the containment-unavailable check ran
  before sample validation. `MalwareDashboardManager.submit` now validates the approved registry
  entry before reporting service/containment availability. A valid sample still fails closed when
  containment is unavailable.
- `dashboard`: the production build passed; one real contained-worker browser test exceeded the
  global 90-second Playwright timeout. That test now has a 180-second budget, above its existing
  120-second job wait.
- `Windows managed malware worker acceptance`: pytest received `KeyboardInterrupt` at
  `threading.Thread.start()` after 17 tests, without an assertion failure. The focused test uses
  synchronous in-memory `BytesIO` streams, so its pipe reader now runs inline; real worker tests
  continue to exercise the actual Windows worker and Job Object.

Local verification after these changes (PowerShell, Python 3.12.10):

| Exact command | Exit | Result |
| --- | ---: | --- |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest tests/unit/test_web_api.py::test_malware_api_fail_closed_and_redacted_case_linking -q` | 0 | 1 passed in 11.67s. |
| `npm run test:e2e -- --grep "actual contained malware triage"` (from `frontend/`) | 0 | 1 passed in 36.3s; actual Windows contained worker, persistence, case link, report redaction, refresh, and logout checks completed. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest tests/unit/test_managed_malware.py -q` | 2 | `KeyboardInterrupt` still recurred after 18 passed while entering the next real-worker test. No assertion failed; the source of the interrupt remains unidentified. |
| `$env:PYTHONPATH='C:\src\Chinescan;.venv\Lib\site-packages'; py -3.12 -m pytest tests/unit/test_managed_malware.py::test_actual_windows_contained_worker_returns_bounded_synthetic_result -vv --full-trace` | 0 | 1 passed in 0.73s. |
| `.venv\Scripts\ruff.exe check tests/unit/test_managed_malware.py chinescan/web/malware_jobs.py` | 0 | All checks passed. |
| `.venv\Scripts\ruff.exe format --check tests/unit/test_managed_malware.py chinescan/web/malware_jobs.py` | 0 | 2 files already formatted. |
| `git diff --check` | 0 | Passed. |

The full Windows worker acceptance remains unresolved because of the reproducible external-looking
`KeyboardInterrupt`; the focused real-worker acceptance passes in isolation. No workflow rerun was
started and no commit or push was made.

## CI repair investigation — 2026-10-28

### Baseline

Before edits, `main`, `HEAD`, and `origin/main` were identical at
`a7008f7ec7c6d0db228a02f0e0308af5c6b92aba`; the working tree was clean. The branch had no
protection rule. The earlier screenshot commit was `2f5b03500bc93411c3c795901a0e43337ba85a99`,
but the newest CI run was `40657868171`:

- CI: <https://github.com/CipherChi/Chinescan/actions/runs/40657868171>
- Offline benchmarks: <https://github.com/CipherChi/Chinescan/actions/runs/40657868201>
- Newer push workflow: <https://github.com/CipherChi/Chinescan/actions/runs/40659082070>

At `a7008f7`, Linux quality, container, and secret-scan jobs passed; the benchmark and push
workflows passed. The Windows managed-malware job and Linux dashboard/browser job failed.

### Actual failure evidence

| Check | Runner and command | Failure evidence |
| --- | --- | --- |
| Windows managed malware worker acceptance | Windows Server 2025; Python 3.12.10 installed by locked `uv sync`; `uv run --locked --extra dev pytest tests/unit/test_managed_malware.py -q` | Exit 1. Pytest printed 18 passes, then `KeyboardInterrupt` at `threading.py:355` as the first real worker test started its stdout-reader thread. No assertion failed. The Actions command omitted `--full-trace`; a local full-trace reproduction places the interrupt in `process.py` at `reader.start()` / `threading.Event.wait()`. Its origin remains unknown. |
| Dashboard build and browser acceptance | Ubuntu; Node 22.22.0; `npm run test:e2e` after successful install, audit, typecheck, component tests, build, and Chromium installation | Exit 1. Five tests passed. The malware UI workflow timed out at 180 seconds while clicking a button that the Linux application correctly disables because verified Windows Job Object execution is unavailable. The UI already exposes that capability state. |

GitHub returned no uploaded artifacts for this run, so the referenced Playwright screenshot, error
context, and trace were not retrievable from Actions. No process assertion or backup `WinError 5`
was present in these failure logs.

### Changes in this repair

- The browser acceptance now checks `/api/malware/capability`. On platforms without verified
  containment it asserts the unavailable state and disabled control. When containment is available,
  it continues through the real analysis, persistence, case link, redaction, refresh, and logout
  checks.
- Worker launch now creates the Job Object first, launches the child suspended, verifies its Job
  Object assignment, starts the bounded output reader, and resumes exactly one verified primary
  thread. If thread discovery or resume verification fails, cleanup terminates the assigned child.
  The helper verifies the original process remains alive and that the opened primary thread belongs to that process before resuming it. This ensures the static parser cannot start before containment.
- Added portable Win32 API-control tests for primary-thread discovery/resume and a regression
  assertion that launch uses `CREATE_SUSPENDED` and resumes only after Job assignment.
- CI now runs mocked/control-path tests and the three real Windows worker tests in separate pytest
  processes. All real Windows tests remain enabled; the second step uses `--full-trace`.

### Local verification after the repair

| Exact command | Exit | Result |
| --- | ---: | --- |
| `npm run typecheck` (from `frontend/`) | 0 | Passed. |
| `npm test -- --reporter=dot` (from `frontend/`) | 0 | 4 files, 8 tests passed. |
| `npm run build` (from `frontend/`) | 0 | Vite production build passed. |
| `npm run test:e2e` (from `frontend/`, Windows host) | 0 | 6 passed in 3.1m, including the real contained Windows malware workflow. |
| `npm run test:e2e -- --grep "malware triage requires Windows containment"` (from `frontend/`) | 0 | 1 passed in 20.1s on the final suspended-worker launch code. |
| `npm audit --audit-level=moderate` (from `frontend/`) | 0 | 0 vulnerabilities. |
| `.venv\Scripts\pytest.exe tests/unit/test_managed_malware.py -q -k "test_worker_control_path_timeout_and_output_overflow_close_pipes or test_resume_suspended_process_requires_one_resumable_primary_thread or test_actual_windows_contained_worker_returns_bounded_synthetic_result or test_actual_windows_manager_persists_contained_synthetic_analysis or test_actual_job_object_terminates_synthetic_child_process_tree" --full-trace --basetemp=tests/.pytest-tmp-codex-winlast` | 0 | 12 passed, 17 deselected in 2.29s. Actual worker, manager, process-tree, ordering, and API-control tests ran on Windows. |
| `.venv\Scripts\pytest.exe tests/unit/test_recovery.py -q` | 0 | 15 passed in 8.91s. |
| `.venv\Scripts\ruff.exe check .` | 0 | All checks passed. |
| `.venv\Scripts\ruff.exe format --check .` | 0 | 125 files already formatted. |
| `.venv\Scripts\mypy.exe --strict chinescan` | 0 | No issues in 52 source files. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | 76 packages resolved; lock is consistent. |
| `.venv\Scripts\pip-audit.exe --skip-editable` | 0 | No known vulnerabilities; editable project distribution skipped. |
| `.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | No medium or high findings; existing 12 low findings remain. |
| `py -3.12 -m pytest --cov=chinescan --cov-report=term-missing --cov-fail-under=80` | 1 | Locally interrupted after 106 passed and 5 optional scanner tests were deselected; the Windows worker suite received `KeyboardInterrupt`, so no coverage result was produced. On the prior SHA, Linux CI quality passed with 80.40% coverage; the new SHA still needs CI verification. |

Optional real YARA/ClamAV scanner tests remain separately deselected because the required local
binaries and signature data are not installed. No sample was executed outside the fixed static
worker, uploaded, or sent for external enrichment.

This report records investigation and local results only. Remote CI results for the repair commit
must be added after that exact SHA completes.

### First repair commit follow-up — `52c019bbfeea52da7c1d645c9c45f3dcf7548984`

The first repair commit was pushed normally to `main`. Its workflows completed as follows:

- [CI run 40662092608](https://github.com/CipherChi/Chinescan/actions/runs/40662092608): dashboard/browser, container, and secret scan passed. Quality failed because four parameter cases in the new Win32 thread-control test used `ctypes.wintypes` fields whose widths vary by host ABI; all four failed on Linux.
- The Windows worker job also failed on that run. The mocked step printed `26 passed, 3 deselected in 1.50s` and then Actions reported exit 1 without a traceback or pytest failure summary. The real-worker step did not run. This differs from the earlier logged `KeyboardInterrupt`; its cause is still unknown.
- [Offline benchmarks run 40662092742](https://github.com/CipherChi/Chinescan/actions/runs/40662092742) passed.
- [Push/security run 40662092322](https://github.com/CipherChi/Chinescan/actions/runs/40662092322) passed, including CodeQL analyses for JavaScript/TypeScript, Python, and Actions.

The Win32 `THREADENTRY32` mock now uses fixed-width 32-bit fields, matching the Windows API structure on Linux test hosts. The Windows mocked acceptance command now also requests `--full-trace` to capture any hidden pytest interruption on the hosted runner.

Follow-up verification on the working tree:

| Exact command | Exit | Result |
| --- | ---: | --- |
| Linux container: `uv run --locked --extra dev python -c "import pytest; raise SystemExit(pytest.main(['tests/unit/test_managed_malware.py::test_resume_suspended_process_requires_one_resumable_primary_thread', '-q']))"` | 0 | 8 passed; fixed-width Win32 structure cases pass on Linux. Container used Python 3.12.16; pytest emitted only the expected cache warning because the repository mount was read-only. |
| `.venv\Scripts\pytest.exe tests/unit/test_managed_malware.py -q --full-trace -k "not test_actual_windows_contained_worker_returns_bounded_synthetic_result and not test_actual_windows_manager_persists_contained_synthetic_analysis and not test_actual_job_object_terminates_synthetic_child_process_tree"` | 0 | 26 passed, 3 deselected. |
| `.venv\Scripts\pytest.exe tests/unit/test_managed_malware.py -q --full-trace -k "test_actual_windows_contained_worker_returns_bounded_synthetic_result or test_actual_windows_manager_persists_contained_synthetic_analysis or test_actual_job_object_terminates_synthetic_child_process_tree"` | 0 | 3 passed, 26 deselected on Windows. |

### Second repair commit verification — `23f4e6103ee072d6086fc0dbf7747389c8d8cf1d`

The second repair commit was pushed normally to `main`. Its workflows completed as follows:

- [CI run 40663199017](https://github.com/CipherChi/Chinescan/actions/runs/40663199017): quality passed, including coverage; dashboard/browser, container, and secret scan passed. Windows managed-malware acceptance failed.
- [Offline benchmarks run 40663199001](https://github.com/CipherChi/Chinescan/actions/runs/40663199001) passed.
- [Push/security run 40663198825](https://github.com/CipherChi/Chinescan/actions/runs/40663198825) passed, including CodeQL analyses for Actions, Python, and JavaScript/TypeScript.

The Windows job ran on Windows Server 2025 with Python 3.12.10. Exact failed command:

`uv run --locked --extra dev pytest tests/unit/test_managed_malware.py -q -k "not test_actual_windows_contained_worker_returns_bounded_synthetic_result and not test_actual_windows_manager_persists_contained_synthetic_analysis and not test_actual_job_object_terminates_synthetic_child_process_tree" --full-trace`

It printed `26 passed, 3 deselected in 1.22s`, then Actions reported exit code 1. `--full-trace`
produced no traceback or pytest failure. The actual Windows containment tests did not run because
the first step failed. Reproduction on the local Windows host also prints passing summaries and
returns exit 1 for some multi-test selections, while individual selections return 0. The pytest
session reports exit code 0 when invoked via `pytest.main`, so the exit-status change occurs outside
pytest's reported result. Its source remains unidentified; no workaround was applied.

Current verification is therefore incomplete: the Windows managed-malware acceptance check is
still failing on the pushed SHA. This report does not claim that all required checks passed.

### Windows liveness fix — local verification before push

The Windows exit-status failure was traced to `MalwareJobManager.reconcile()` calling
`_pid_is_alive()`, which used `os.kill(pid, 0)`. Python documents that on Windows signal value `0`
is `CTRL_C_EVENT`, which targets console processes sharing a console; it is not a no-signal process
probe ([Python `os.kill` documentation](https://docs.python.org/3/library/os.html#os.kill)). This
explains the observed `KeyboardInterrupt` during the prior worker acceptance run and the exit 1
after a passing pytest summary. The Windows path now opens the PID with `SYNCHRONIZE` access and
checks its state using `WaitForSingleObject`; inconclusive access or wait errors preserve the job
as potentially active. POSIX retains its `os.kill(pid, 0)` liveness check. Portable API tests cover
running, exited, inaccessible, and inconclusive states. The implementation requests only the
`SYNCHRONIZE` process right required by [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
and uses [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
with a zero timeout.

The full Windows Python acceptance also exposed a separate test timing issue: logout and CSRF
assertions shared a one-second session TTL with the expiry test, so on the slower full-suite run
the session expired before logout. The tests are now separated: logout uses the normal TTL, while
actual expiry remains checked independently.

Local verification after these changes (Windows Server 2025 host, Python 3.12.10):

| Exact command | Exit | Result |
| --- | ---: | --- |
| `& .\.venv312\Scripts\uv.exe run --locked --extra dev pytest --cov=chinescan --cov-report=term-missing --cov-fail-under=80` | 0 | 168 passed, 5 optional scanner tests deselected; 82.62% total coverage. |
| `& .\.venv312\Scripts\uv.exe run --locked --extra dev pytest tests/unit/test_managed_malware.py -q -k "not test_actual_windows_contained_worker_returns_bounded_synthetic_result and not test_actual_windows_manager_persists_contained_synthetic_analysis and not test_actual_job_object_terminates_synthetic_child_process_tree" --full-trace` | 0 | 32 passed, 3 deselected. This is the CI worker-control step. |
| `& .\.venv312\Scripts\uv.exe run --locked --extra dev pytest tests/unit/test_managed_malware.py -q -k "test_actual_windows_contained_worker_returns_bounded_synthetic_result or test_actual_windows_manager_persists_contained_synthetic_analysis or test_actual_job_object_terminates_synthetic_child_process_tree" --full-trace` | 0 | 3 passed, 32 deselected; real contained worker and process-tree checks ran on Windows. |
| `& .\.venv312\Scripts\uv.exe run --locked --extra dev ruff check .` | 0 | Passed. |
| `& .\.venv312\Scripts\uv.exe run --locked --extra dev ruff format --check .` | 0 | 125 files formatted. |
| `& .\.venv312\Scripts\uv.exe run --locked --extra dev mypy --strict chinescan` | 0 | No issues in 52 source files. |
| `& .\.venv312\Scripts\uv.exe lock --check` | 0 | 76 packages resolved; lock is consistent. |
| `& .\.venv312\Scripts\uv.exe run --locked --extra dev pip-audit --skip-editable` | 0 | No known vulnerabilities; editable project distribution skipped. |
| `& .\.venv312\Scripts\uv.exe run --locked --extra dev bandit --severity-level medium -r chinescan` | 0 | No medium or high findings; 12 low findings remain. |
| `npm run typecheck` (from `frontend/`) | 0 | Passed. |
| `npm test -- --reporter=dot` (from `frontend/`) | 0 | 4 files, 8 tests passed. |
| `npm run build` (from `frontend/`) | 0 | Vite production build passed. |
| `npm run test:e2e` (from `frontend/`) | 0 | 6 passed in 54.2s, including the actual Windows malware workflow and separate session-expiry test. |
| `npm audit --audit-level=moderate` (from `frontend/`) | 0 | 0 vulnerabilities. |
| `git diff --check` | 0 | Passed. |

The last pushed SHA `d806d55e9f31542de42ab4be4f00bf642d36f260` passed quality, dashboard/browser,
container, secret scan, offline benchmarks, and all CodeQL analyses; its Windows worker step failed
before this liveness fix. Remote verification for the next SHA is pending and must complete before
claiming the Windows failure is fixed in CI.

### First liveness-fix CI run — `095be27430a79a4cfbce41b60f66df626d6576f7`

- [CI run 40709926208](https://github.com/CipherChi/Chinescan/actions/runs/40709926208): Windows managed-malware acceptance passed, including the mocked-control step and all three actual Windows containment tests. Dashboard/browser, container, and secret scan passed. Quality failed at Linux mypy before running pytest: Linux ctypes type stubs do not declare `WinDLL` or `get_last_error`.
- [Offline benchmarks run 40709925897](https://github.com/CipherChi/Chinescan/actions/runs/40709925897) passed.
- [Push/security run 40709926727](https://github.com/CipherChi/Chinescan/actions/runs/40709926727) passed all three CodeQL analyses.

The Windows API symbols now use guarded `getattr` lookups. If the API is unavailable or an error
is inconclusive, recovery conservatively treats the process as alive instead of marking its job
interrupted. After this adjustment, local mypy passes for all 52 source files, Ruff passes, and the
complete managed-malware test file passes (35 passed on Windows). Remote verification of the
corrected typing and final SHA is recorded below.

### Verified liveness-fix SHA — `791cf7266333db10cd95fadda121311ebf7a23e2`

The final code commit was pushed normally to `main`; all configured workflows passed for this exact
SHA:

- [CI run 40710401322](https://github.com/CipherChi/Chinescan/actions/runs/40710401322): quality (including coverage), Windows managed-malware acceptance, dashboard/browser acceptance, container, and secret scan all passed.
- [Offline benchmarks run 40710401288](https://github.com/CipherChi/Chinescan/actions/runs/40710401288) passed.
- [Push/security run 40710398300](https://github.com/CipherChi/Chinescan/actions/runs/40710398300) passed CodeQL for JavaScript/TypeScript, Python, and Actions.

The Windows job completed both mocked/control-path acceptance and all three actual contained
worker/process-tree tests. The Linux quality job completed Ruff, strict mypy, 168 unit tests with
the 80% coverage threshold, pip-audit, and Bandit. The dashboard job completed npm audit,
typecheck, component tests, production build, and Playwright acceptance. Five optional real-scanner
tests remained deselected because scanner binaries/signature data were unavailable; no scanner
execution or malware upload was performed.

This report-only change creates a new SHA; its Actions runs must also complete before final delivery.

## 2026-11-02 chain_trace implementation verification addendum

The chain_trace feature work used the repository's locked development environment. Commands and exact results:

| Command | Result |
| --- | --- |
| `uv run --locked --extra dev ruff check .` | Exit 0 — `All checks passed!` |
| `uv run --locked --extra dev mypy --strict chinescan` | Exit 0 — `Success: no issues found in 79 source files` |
| `uv run --locked --extra dev pytest tests/unit/test_chain_trace.py -q` | Exit 0 — `4 passed` |
| `npm run typecheck` (from `frontend/`) | Exit 0 |
| `npm test -- --run` (from `frontend/`) | Exit 0 — `9` files and `48` tests passed |
| `uv run --locked --extra dev pytest --basetemp C:\ct -q` | Exit 1 — `426 passed, 1 failed, 5 deselected`; pre-existing timing-sensitive `test_each_scan_bound_marks_partial_with_skipped_counts[malware_per_file_seconds-files3]` returned `succeeded` instead of `partial`. The malware path was not changed. |

No live provider was called during verification. An earlier pytest run also exposed a Windows `path_too_long` failure in the existing GitHub import test with pytest's deeply nested default temporary directory; the short `C:\ct` rerun cleared that failure.

Final current-tree rerun after the chain hardening edits:

| Command | Result |
| --- | --- |
| `uv run --locked --extra dev pytest --basetemp C:\ct -q` | Exit 0 — `427 passed, 5 deselected, 2 warnings in 170.05s`. |

This successful short-temp rerun supersedes the prior timing-sensitive failure above. No live provider was called.

## 2026-11-02 chain_trace completion follow-up

This follow-up completes the reported gaps: detector coverage now includes all ten specified rules (including address poisoning and approval/sweep drainer behavior), with findings tested for heuristic identity, false-positive caveats, confidence, and evidence mapping. EVM provider handling uses bounded retries and fixed coverage-gap codes for HTTP 429, timeouts, malformed responses, provider errors, invalid rows, and truncated pages. Provider exception text is discarded, keys are refused if reflected in transaction rows, and service persistence order is tested. Web tests cover authentication/CSRF, server network policy, input validation and size limits, queued/running/succeeded/failed states, restart reconciliation, and graph/export 404s. The graph now lays nodes out by hop depth and supports keyboard-accessible node selection, a transfer/label/findings panel, Escape close, and a 500-node rendering cap.

Verification on 2026-11-02:

| Command | Result |
| --- | --- |
| `uv run --locked --extra dev ruff check chinescan tests` | Exit 0 — `All checks passed!` |
| `uv run --locked --extra dev mypy --strict chinescan` | Exit 0 — `Success: no issues found in 79 source files` |
| `uv run --locked --extra dev pytest --basetemp C:\ct -q` | Exit 0 — `445 passed, 5 deselected, 2 warnings in 236.18s` |
| `npm run typecheck` from `frontend/` | Exit 0 |
| `npm test -- --run` from `frontend/` | Exit 0 — `10` files and `50` tests passed |
| `uv run --locked --extra dev pytest tests/unit/test_malware_project_scan.py::test_each_scan_bound_marks_partial_with_skipped_counts --basetemp C:\ct -q` | The pre-existing timing-sensitive `malware_per_file_seconds` parameter failed in isolation (`succeeded` instead of `partial`); no malware code or test was changed. |

The exact repository-wide Ruff gate could not be verified after test temporary directories were accidentally placed under the checkout and became Ruff inputs. Automatic filesystem review rejected removal of the generated `ct-chaintrace-final` tree; cleanup was not bypassed. Ruff passed when scoped to the actual source and test directories. No live provider was called.
# Chain trace hardening follow-up

The chain-trace provider uses an explicit host allowlist, HTTPS-only URL policy, public-address
validation with DNS pinning, same-host redirect checks, bounded response/request/deadline limits,
and fixed-code provider failures. On-chain networking remains disabled by default. Details and
the generated-artifact inventory are recorded in [chain-trace-report.md](chain-trace-report.md).

## 2026-11-04 Windows CLI launch and configuration diagnostics

Added a `python -m chinescan` entry point so the CLI can be launched through the selected Python
interpreter without relying on the installed console-script directory being on `PATH`. TOML syntax
errors now report their line and column without echoing configuration contents.

Verification from the repository root using Python 3.12:

| Command | Result |
| --- | --- |
| `py -3.12 -m chinescan --help` | Exit 0 — displayed CLI help. |
| `py -3.12 -m chinescan config init --path <temporary-file>` | Exit 0 — created temporary default configuration. |
| `py -3.12 -m chinescan config validate --path <temporary-file>` | Exit 0 — `Configuration is valid.` Temporary file removed. |
| `py -3.12 -m chinescan config validate --path C:\Users\CipherChi\.config\chinescan\config.toml` | Exit 1 — `Unable to load configuration (TOMLDecodeError); check TOML syntax near line 1, column 9.` No file contents printed. The existing user configuration remains unchanged. |
| `py -3.12 -m ruff check chinescan\__main__.py chinescan\core\config\io.py` | Exit 0 — all checks passed. |
| `py -3.12 -m ruff format --check chinescan\__main__.py chinescan\core\config\io.py` | Exit 0 — both files formatted. |
| `git diff --check` | Exit 0. |

## 2026-11-04 Operator-approved local folder selection

Replaced the dashboard's preconfigured-root requirement with authenticated, loopback-only local
folder browsing and explicit approval. Selection tokens are session-bound; the approval request
does not accept a filesystem path. The backend revalidates approved paths at creation and assessment
submission, stores dashboard-approved projects in SQLite, and supports optional `allowed_roots`
restrictions. The shared UI flow is available to code assessments, log analysis, malware triage, and
the Projects page.

Verification from the repository root:

| Command | Result |
| --- | --- |
| `py -3.12 -m pytest -q --basetemp C:\pt` | Exit 0 — 515 passed, 5 deselected, 3 dependency deprecation warnings in 215.71s. |
| `npm test -- --run` (from `frontend`) | Exit 0 — 54 tests passed across 11 files. |
| `npm run build` (from `frontend`) | Exit 0 — TypeScript check and Vite production build passed. |
| `py -3.12 -m ruff check .` | Exit 0 — all checks passed. |
| `py -3.12 -m ruff format --check .` | Exit 0 — 177 files already formatted. |
| `py -3.12 -m mypy --strict chinescan` | Exit 0 — no issues in 81 source files. |
| `git diff --check` | Exit 0. |

The default Windows pytest temp path caused the existing GitHub import test to fail with
`path_too_long`. The isolated test passed with `--basetemp C:\pt`, and the complete suite passed
with that short temp base.

## ChiNeScan implementation validation — 2026-11-06

The following checks were run from `C:\src\Chinescan` against the ChiNeScan improvements. These are implementation validation results, not a rerun of the historical Docker/dependency audit acceptance matrix.

| Command | Exit | Result |
| --- | ---: | --- |
| `py -3.12 -m pytest --basetemp C:\shortpytest -q` | 0 | `607 passed, 5 deselected, 3 warnings in 188.49s` |
| `npm test -- --run` (from `frontend`) | 0 | `12` files and `57` tests passed |
| `npm run typecheck` (from `frontend`) | 0 | TypeScript project check passed |
| `npm run build` (from `frontend`) | 0 | Vite production build passed; output: `frontend/dist` |
| `py -3.12 -m ruff check .` | 0 | `All checks passed!` |
| `py -3.12 -m ruff format --check .` | 0 | `188 files already formatted` |
| `py -3.12 -m mypy chinescan` | 0 | `Success: no issues found in 84 source files` |
| `py -3.12 -m json.tool schemas\finding.schema.json` | 0 | Valid JSON |
| `py -3.12 -m json.tool schemas\investigation.schema.json` | 0 | Valid JSON |
| `git diff --check` | 0 | No whitespace errors; Git printed CRLF-to-LF normalization notices for edited model/schema files |

The full Python run emitted three dependency deprecation warnings (Starlette/httpx and Pydantic serialization); the earlier focused run additionally emitted pytest-asyncio and Windows temporary-directory cleanup warnings. No test failures were observed. The full frontend run also reported its existing jsdom-per-file performance notice. No dependency advisory audit or Docker build was run for this implementation change.

## ChiNeScan continuation acceptance — 2026-11-06

Repository revision checked: `2ad86b05ca82181da78b3eb6bfee5598d63dc8af`. The repository remains a standalone nested Git checkout; no parent or sibling checkout was changed. Existing dirty work from the previous implementation was retained. The old `docs/GNET-SCAN-IMPROVEMENTS.md` path is absent and its content is now `docs/ChiNeScan-improvements.md`.

| Command | Exit | Result |
| --- | ---: | --- |
| `py -3.12 -m pytest --basetemp C:\shortpytest -q` | 0 | 615 passed, 5 deselected, 3 warnings in 545.03s. |
| `py -3.12 -m pytest tests/unit/test_web_api.py tests/unit/test_reporting.py tests/unit/test_code_rules_behavior.py -q --basetemp C:\shortpytest` | 0 | 104 passed, 3 warnings in 142.61s. |
| `py -3.12 -m pytest tests/unit/test_web_api.py::test_scan_cli_api_and_complete_export_share_normalized_values tests/unit/test_web_api.py::test_legacy_score_without_ledger_stays_unavailable_in_api_and_export tests/unit/test_reporting.py -q --basetemp C:\shortpytest` | 0 | 10 passed, 3 warnings in 20.56s. |
| `npm test -- --run` (from `frontend`) | 0 | 12 files, 61 tests passed. |
| `npm run typecheck` (from `frontend`) | 0 | TypeScript check passed. |
| `npm run build` (from `frontend`) | 0 | Vite production build passed; 29 modules transformed. |
| `npm run test:e2e -- --project=chromium-production` (from `frontend`) | 0 | Final rerun: 14 passed in 1.8m using isolated local app and repository fixtures. The preceding full run had one transient initial-loading timeout in the degraded-readiness test (13 passed); that test then passed in isolation and again in the final full run. |
| `npm run test:e2e -- --project=chromium-production -g "degraded readiness"` (from `frontend`) | 0 | 1 passed in 37.5s. |
| `py -3.12 -m ruff check chinescan tests` | 0 | All checks passed. |
| `py -3.12 -m ruff format --check chinescan tests` | 0 | 133 files already formatted. |
| `py -3.12 -m mypy chinescan` | 0 | No issues in 84 source files. |
| `py -3.12 scripts/export_schemas.py` and `py -3.12 -m json.tool` on both schemas and the shared fixture | 0 | Schema export and all JSON validation passed. |
| `py -3.12 -m pip_audit --skip-editable` | 0 | Reported “No known vulnerabilities found”; editable ChiNeScan distribution was skipped. |
| `git diff --check` | 0 | No whitespace errors; Git emitted only CRLF-to-LF normalization notices for edited files. |

Remaining verification gaps: no mobile browser viewport run or real browser reduced-motion preference run; no full screen-reader audit, load/fuzz assessment, Docker build, external advisory result for the editable project itself, or independent penetration test. Vitest covers animation preference migration/pause/ARIA-hidden behavior; Chromium covers basic keyboard navigation and text-safe/redacted finding display. These checks do not establish that ChiNeScan is vulnerability-free.

## ChiNeScan signal-quality continuation — 2026-11-09

Current implementation verification was run from `C:\src\Chinescan` on the active worktree;
the repository is on `feature/signal-quality` and no commit was created.

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10 selected; Ruff passed; local Rust redaction extension built; 203 focused Python tests passed with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed; 10 frontend tests passed; frontend build, configured lint, and typecheck passed; `Overall: PASS`. |
| `.\.venv\Scripts\python.exe -m pytest tests/unit/test_code_scan.py::test_synthetic_flutter_supabase_382_file_regression -q --durations=1 --disable-warnings` | 0 | `1 passed`; test call took `7.06s` and total process took `9.34s`. The synthetic fixture had exactly 382 scanned files. |
| `.\.venv\Scripts\python.exe -c "..."` creating 20,000 synthetic Dart files and running `CodeScanService([BuiltinRuleScanner()]).scan(root)` | 0 | File creation: `9.807s`; scan: `165.284s`; total: `175.091s`; examined `20,000` files and `320,000` bytes; `0` findings. The exact executable command and result were captured in the continuation session. |

The user-referenced `latest scan.json` is not present under this repository, so the 382-file result
is a synthetic Flutter/Supabase regression and not a timing of the original golden project. The
synthetic checks exercise RLS resolution for `device_pairings` and `child_devices`, request source
and sink evidence, controlled error text, Firebase API-key informational classification, and Dart
and Android findings. No real project code or secrets were used. The 20,000-file timing uses the
built-in local code scanner only; it does not verify a timing for every separate analysis module.

Follow-up implementation validation on the same date added bounded PE import extraction and
suspicious API combinations, rule-based malware triage labels with evidence/caveat, broad Android
intent-filter detection, explicit service-role-only RLS policy information, distributed
credential-stuffing and backwards-time log leads, and extracted IOC persistence from normalized log
fields. Current verifier result after these changes:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10; Ruff passed; Rust redaction extension built; 204 focused Python tests passed with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed; 10 frontend tests passed; frontend build, configured lint, and typecheck passed; `Overall: PASS`. |
| `.\.venv\Scripts\python.exe -m pytest tests/unit/test_log_analysis.py -q --tb=short` | 0 | `30 passed`. |
| `.\.venv\Scripts\python.exe -m pytest tests/unit/test_malware_analysis.py tests/unit/test_managed_malware.py -q --tb=short` | 0 | `51 passed`. |

These checks validate synthetic fixtures. They do not substitute for the absent original `latest
scan.json`, a full native Windows/macOS/Linux executable corpus, comprehensive offline package
advisories, or a complete request-to-sink/static taint analysis.

The verifier's Python selection was expanded to include log analysis, managed malware, and code
actionability regression suites. Following bounded ELF dynamic-symbol and Mach-O undefined-symbol
parsing, its latest result is:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Latest rerun after structural Android XML parsing and wildcard-host handling: Python 3.12.10; Ruff passed; Rust extension built; 284 focused Python tests passed in 371.46s with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed; 13 frontend tests passed; frontend build, configured lint, and typecheck passed; `Overall: PASS`. |
| `.\.venv\Scripts\python.exe -m pytest tests/unit/test_malware_analysis.py::test_elf_and_macho_undefined_imports_are_parsed tests/unit/test_malware_analysis.py::test_rule_based_verdict_has_indicator_evidence_and_never_claims_safe -q --tb=short` | 0 | `2 passed`. |

The ELF/Mach-O import support parses undefined symbols with bounded tables and sanitized names;
Mach-O timestamp and section metadata, PE/ELF/Mach-O code-signature verification, and broad native
binary disassembly remain unimplemented.

The verifier now includes the malware workspace tests. Static triage verdict,
bounded verdict evidence, entropy metadata, imports, suspicious API combinations,
and the compile timestamp are exposed through the authenticated analysis API and
rendered in the workspace. The API response test confirms these values are
returned from synthetic persisted analysis data. On this rerun, the focused
Python suite completed in 95.73s, and both frontend files selected by the
verifier passed (13 tests total). The malware-workspace-only run passed 3 tests;
the API file passed 60 tests.

The immediate pre-fix verifier run failed Ruff on five newly added overlong
lines in `chinescan/web/app.py`; those lines were wrapped, and the subsequent
full verifier run passed. No test was changed or removed to obtain that result.

The report parity fixture now includes a lead with request source and query sink
locations, controls considered, project impact, observed-code before/after patch,
verification step, and confidence-limit explanations. Full JSON carries the
same model data, Markdown renders it, and the authenticated finding API plus
dashboard detail view expose it through explicit response allowlists. This
renderer pass's final verifier run selected 283 Python, 46 Rust, and 13 frontend
tests; all passed. The UI-only finding display regression passed 10 tests, and
the report/API parity pair passed 2 tests independently.

Coverage summaries now enumerate the targeted Dart/Flutter, Deno/TypeScript,
Supabase migration, and Android XML checks and state the remaining parser/data
flow limits. Languages with only generic first-pass rules retain that explicit
status; the report renders those gaps before “Fix first.” The 382-file synthetic
regression asserts the per-language descriptions, and a report regression checks
the gap placement. The latest full verifier passed 284 Python, 46 Rust, and 13
frontend tests.

Android manifest and network-security-config checks now parse XML structure
instead of matching tags in raw text. The parser keeps element line references,
recognizes inherited application permissions, ignores commented-out examples,
and rejects DTD/entity declarations. Android positive, mitigation, comment, and
DTD near-miss checks passed. The 382-file synthetic project still passed its
RLS, Deno, Dart, and Android assertions. Latest verifier totals: 284 Python,
46 Rust, and 13 frontend tests; `Overall: PASS`.
Wildcard subdomain hosts in browsable intent filters are now classified as broad;
an exact host remains the tested mitigation.

Windows Event Log CSV and XML exports now normalize target accounts, source IPs,
hosts, timestamps, process command lines, and event outcomes while retaining the
numeric Event ID for Sigma compatibility. XML records carry their physical
`<Event>` line as the evidence reference. DTD/entity declarations and unrelated
XML documents are rejected. Focused parser/Sigma regression checks passed:
`4 passed, 78 warnings in 27.90s` (warnings are existing Pydantic deprecations).

The next full `.\scripts\verify-signal.ps1` run selected Python 3.12.10, passed
Ruff, built the Rust extension, and passed all 286 focused Python tests in
536.42s with 2 Pydantic deprecation warnings. Rust formatting and Clippy passed.
The Rust suite reported 45 passed and 1 failed: the existing
`adversarial_repeated_delimiters_remain_linear_and_safe` test exceeded its
2-second runtime assertion in both the full run and a standalone retry. The
frontend checks therefore did not run in this verifier attempt; the overall
result was `FAIL` (Rust test exit 101). No test was weakened or removed.

That runtime failure exposed a quadratic UTF-8 backward scan in Rust's
assignment key parser. Backward character lookup now steps at most four bytes
to the previous UTF-8 boundary, and ASCII key classification avoids invoking
Unicode regular expressions for ASCII input. The parity performance regression
then found the corresponding Python colon path was matching the entire
remaining suffix on each delimiter. Python now scans numeric line values only
when a colon is followed by a digit and tracks the prior whitespace boundary
incrementally. Existing thresholds and test assertions remain unchanged.

The verifier's 2-second Rust stress assertion passed alone in 1.62s, but failed
under the default parallel Rust test load. The full verifier passed with Rust
tests serialized through `RUST_TEST_THREADS=1` and test debug symbols disabled
to avoid the Windows linker PDB failure. Exact successful result:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10; Ruff passed; Rust extension built; 286 focused Python tests passed in 657.68s with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed serially in 14.24s; 13 frontend tests passed; frontend build, configured lint step, and typecheck passed; `Overall: PASS`. |

The prior non-serialized retry passed 286 Python tests in 1508.86s and passed
formatting and Clippy, but failed the same timing assertion with 45 Rust tests
passing. This records the effect of test concurrency rather than hiding it.

Authentication spray and distributed credential-stuffing windows now maintain
incremental account/source counters. They create the matched event slice only
after the threshold is reached, avoiding repeated copies and set construction
on large near-miss streams. HTTP 5xx bursts likewise check window length before
materializing the matching slice. A 4,000-event single-account near-miss
regression confirms this remains a spray/stuffing near-miss. The detector
module was added to the verifier's Ruff selection and its existing long text
literals were wrapped without changing their content. Latest verifier result:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10; Ruff passed including `chinescan/log_analysis/detections.py`; Rust extension built; 287 focused Python tests passed in 79.83s with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed serially in 4.22s; 13 frontend tests passed; frontend build, configured lint step, and typecheck passed; `Overall: PASS`. |

The focused spray, stuffing, and error-burst run passed `6 passed, 27 deselected`
in 20.01s. The original benchmark `latest scan.json` remains absent from the
repository; benchmark-dependent end-to-end acceptance claims remain limited to
synthetic project fixtures.

Mach-O static metadata now walks bounded 32-bit and 64-bit segment load
commands to report section entropy and detects an in-bounds code-signature
blob. It explicitly reports that Mach-O has no standard compile timestamp and
that blob presence does not mean cryptographic validity was checked. Malformed
load-command and section bounds are diagnosed. The former test asserting this
parser was unimplemented was replaced with assertions for the current explicit
timestamp limitation; new tests cover section entropy, signature-presence
reporting, and malformed commands. Latest verifier result after these changes:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10; Ruff passed; Rust extension built; 288 focused Python tests passed in 121.34s with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed serially in 6.55s; 13 frontend tests passed; frontend build, configured lint step, and typecheck passed; `Overall: PASS`. |

Focused Mach-O metadata and import checks passed `2 passed` in 3.65s. The
malware analyzer still does not cryptographically verify PE, ELF, or Mach-O
signatures, unpack packed samples, or disassemble native code. Nested ZIP
contents are now opened in memory, listed without disk extraction, and
inspected through a maximum depth of two nested levels. A shared 1,000-member
cap and 8 MiB decompressed-byte budget bound traversal; encrypted, malformed,
over-budget, and too-deep children are reported as uninspected. Unsupported
nested formats remain listed but are not opened.

Archive regression tests cover nested traversal, nested content listing,
depth-limit reporting, ordinary archives as a near-miss, and encrypted or
malformed entries. The focused archive suite passed `4 passed, 16 deselected`
in 6.84s. Latest full verifier after the boundary regressions:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10; Ruff passed; Rust extension built; 290 focused Python tests passed in 102.56s with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed serially in 4.07s; 13 frontend tests passed; frontend build, configured lint step, and typecheck passed; `Overall: PASS`. |

Offline advisory reachability now requires a call-shaped reference to the
affected API in production source after comments are masked; tests and fixtures
remain excluded. The npm regression covers a string literal, a comment, and a
test-only call as near-misses, and a production call as the positive case. Lock
version ordering now ranks prereleases below the corresponding final release,
so `4.17.21-beta.1` remains affected by an advisory fixed in `4.17.21`. The
bundled advisory snapshot remains a curated subset dated `2026-10-28`, and its
90-day staleness threshold is reported in findings and coverage metadata.

The dependency advisory regression passed (`1 passed`) and the latest full
verifier after these changes reported:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10; Ruff passed; Rust extension built; 290 focused Python tests passed in 95.06s with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed serially in 4.90s; 13 frontend tests passed; frontend build, configured lint step, and typecheck passed; `Overall: PASS`. |

The ordered migration state now includes explicit table GRANT and REVOKE
statements. A table without RLS whose remaining explicit migration grants are
only to `service_role` is emitted as a confirmed informational item instead of
a client-facing RLS vulnerability. A later client-role grant returns the
confirmed missing-RLS finding; a subsequent revoke restores informational
status. DROP TABLE removes prior RLS, grant, and policy state, so recreation
cannot inherit stale controls. Regression tests cover each ordered transition.

Latest verifier result for this RLS update:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10; Ruff passed; Rust extension built; 291 focused Python tests passed in 93.22s with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed serially in 4.58s; 13 frontend tests passed; frontend build, configured lint step, and typecheck passed; `Overall: PASS`. |

Grouped log alerts now order evidence references by ascending physical line
number when every match comes from one file. For correlations across multiple
files, references use event time and stable tie-breakers. This keeps the first
and last refs aligned with the raw file when input timestamps are out of order
or the detector sorts events into a time window. A scanner regression with
reverse-ordered timestamps confirms physical lines remain 1 through 3. Latest
verifier result:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10; Ruff passed; Rust extension built; 292 focused Python tests passed in 97.64s with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed serially in 4.93s; 13 frontend tests passed; frontend build, configured lint step, and typecheck passed; `Overall: PASS`. |

Windows Event exports now retain subject actor, target account, and target
privileged group as separate fields. Account creation alerts correlate a
Windows 4720 event with a 4728/4732/4756 administrative group assignment for
the same host and account within 24 hours. Both source lines are included in
physical order; a group assignment alone does not imply that the account is
new. The parser and detection regressions cover the positive correlation, an
ordinary group, and a pre-existing account. Focused log analysis passed `36
passed` in 7.86s (pytest also reported Windows temp cleanup warnings). The
latest full signal verifier result is:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10; Ruff passed; Rust extension built; 294 focused Python tests passed in 94.61s with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed serially in 3.81s; 13 frontend tests passed; frontend build, configured lint step, and typecheck passed; `Overall: PASS`. |

The 382-file acceptance fixture now asserts the evidence verdicts as well as
file count and coverage: the request flow is likely with source and sink,
the service-role handler is confirmed with both endpoints, RLS is resolved by
later migrations, and the Firebase client API key stays informational with
explicit non-authentication reasoning. The newest full verifier after these
assertions passed:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10; Ruff passed; Rust extension built; 294 focused Python tests passed in 110.00s with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed serially in 5.56s; 13 frontend tests passed; frontend build, configured lint step, and typecheck passed; `Overall: PASS`. |

A local performance probe recreated the checked-in Flutter/Supabase fixture
shape without real project code or secrets, then scanned it and a tree of
20,000 small Python files. Results (scan timing excludes tree/file creation):

| Synthetic input | Files examined | Scan seconds |
| --- | ---: | ---: |
| Flutter/Supabase-shaped project | 382 | 4.366 |
| Python source tree | 20,000 | 299.656 |

The named golden `latest scan.json` was not available anywhere in this
repository, so these timings do not represent the real 382-file benchmark.
The scaling probe confirms the configured 20,000-file cap can be scanned, but
its roughly five-minute runtime merits optimization before treating large
project performance as satisfactory.

Large-scan profiling identified repeated project discovery and repeated
ancestor/junction checks as major costs. The built-in scanner now consumes the
profile already created by `CodeScanService`; directory reparse points are
checked at traversal boundaries, source entries are checked directly, and
Windows reparse attributes are checked from the `lstat` result without a
second junction query. Regression coverage verifies the built-in scan performs
project discovery once and that file and directory symlinks are not followed.
The focused code scan suite passed `15 passed` in 8.97s (pytest emitted
Windows temporary-directory cleanup warnings).

After the optimization, the same scan-only timing probes examined all files:

| Synthetic input | Files examined | Before (seconds) | After (seconds) |
| --- | ---: | ---: | ---: |
| Flutter/Supabase-shaped project | 382 | 4.366 | 1.707 |
| Python source tree | 20,000 | 299.656 | 73.193 |

The 20,000-file scan is about 4.1x faster, though still takes over a minute on
this Windows host. Latest full signal verifier after these code and regression
test changes:

| Command | Exit | Exact result |
| --- | ---: | --- |
| `.\scripts\verify-signal.ps1` | 0 | Python 3.12.10; Ruff passed; Rust extension built; 296 focused Python tests passed in 191.46s with 2 Pydantic deprecation warnings; Rust formatting and Clippy passed; 46 Rust tests passed serially in 5.23s; 13 frontend tests passed; frontend build, configured lint step, and typecheck passed; `Overall: PASS`. |

## Signal quality verifier run (2026-11-09)

Command: `scripts\verify-signal.ps1` (PowerShell, repository root).

```text
Repository: C:\src\Chinescan
PASS 1. Select Python 3.12 and temporary cache paths
PASS 2. Ruff on touched Python files
PASS 2b. Build local Rust redaction extension
PASS 3. Focused Python tests
296 passed, 2 warnings in 115.96s (0:01:55)
PASS 4a. Rust formatting check
PASS 4b. Rust Clippy
PASS 4c. Rust tests
46 passed; 0 failed; 0 ignored
PASS 5. Frontend unit tests for touched UI
2 test files passed; 13 tests passed
PASS 6. Frontend build
PASS 7. Frontend lint (when configured)
PASS 8. Frontend typecheck
Overall: PASS
```

The two Python warnings were Pydantic `json_encoders` deprecation warnings. Vite also printed a jsdom “Not implemented: navigation to another Document” notice during frontend tests; the test run passed.

## Final committed-candidate verifier run (2026-11-09)

Command: `scripts\verify-signal.ps1` (PowerShell, repository root).

```text
Repository: C:\src\Chinescan
PASS 1. Select Python 3.12 and temporary cache paths
PASS 2. Ruff on touched Python files
PASS 2b. Build local Rust redaction extension
PASS 3. Focused Python tests
296 passed, 2 warnings in 101.58s (0:01:41)
PASS 4a. Rust formatting check
PASS 4b. Rust Clippy
PASS 4c. Rust tests
46 passed; 0 failed; 0 ignored
PASS 5. Frontend unit tests for touched UI
2 test files passed; 13 tests passed
PASS 6. Frontend build
PASS 7. Frontend lint (when configured)
PASS 8. Frontend typecheck
Overall: PASS
```

Strict mypy also passed: `Success: no issues found in 85 source files`. The two Python warnings were Pydantic `json_encoders` deprecations. Vite printed a jsdom navigation notice during frontend tests; all tests passed.

## Verifier after API evidence-reference path fix (2026-11-09)

Command: `scripts\verify-signal.ps1` (PowerShell, repository root).

```text
Repository: C:\src\Chinescan
PASS 1. Select Python 3.12 and temporary cache paths
PASS 2. Ruff on touched Python files
PASS 2b. Build local Rust redaction extension
PASS 3. Focused Python tests
296 passed, 2 warnings in 103.09s (0:01:43)
PASS 4a. Rust formatting check
PASS 4b. Rust Clippy
PASS 4c. Rust tests
46 passed; 0 failed; 0 ignored
PASS 5. Frontend unit tests for touched UI
2 test files passed; 13 tests passed
PASS 6. Frontend build
PASS 7. Frontend lint (when configured)
PASS 8. Frontend typecheck
Overall: PASS
```

The two Python warnings were Pydantic `json_encoders` deprecations. Vite printed a jsdom navigation notice during frontend tests; all tests passed.
