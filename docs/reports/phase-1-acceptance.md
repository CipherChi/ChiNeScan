# Phase 1 Acceptance Results

Run date: 2026-10-25

## Governing specification

The requested `docs/BRIEF.md` was not present, and no file with that name was found under the repository. The checks below follow the acceptance commands explicitly listed in the request. Section 9's individual Definition of Done entries could not be read or itemized; its status is **NOT RUN** because the governing source is unavailable. No claim is made about unprovided items.

## Step 1: Acceptance checks

| Command | Exit | Result |
| --- | ---: | --- |
| `\.venv312\Scripts\python.exe --version` | 0 | `Python 3.12.10` |
| `\.venv312\Scripts\uv.exe sync --locked --extra dev` | 0 | `Resolved 54 packages in 3ms`; `Checked 54 packages in 28ms` |
| `\.venv\Scripts\chinescan.exe --help` | 0 | Help lists `version`, `scan`, `report`, and `config` |
| `\.venv\Scripts\chinescan.exe version` | 0 | `0.1.0` |
| `\.venv\Scripts\chinescan.exe config init --path C:\Users\CIPHER~1\AppData\Local\Temp\chinescan-phase1-acceptance\cs.toml` | 0 | `Created configuration: ...\cs.toml` |
| Same `config init` command again, without `--force` | 2 | `Configuration already exists: ...\cs.toml`; expected exit 3, actual exit 2 |
| `\.venv\Scripts\chinescan.exe config validate --path C:\Users\CIPHER~1\AppData\Local\Temp\chinescan-phase1-acceptance\cs.toml` | 0 | `Configuration is valid.` |
| Same `config validate` command after writing malformed TOML (`[malformed`) | 2 | `Unable to load configuration: Expected ']' at the end of a table declaration (at end of document)`; expected exit 3, actual exit 2 |
| `\.venv\Scripts\pytest.exe --cov=chinescan.core --cov-report=term-missing --cov-fail-under=80` | 0 | `17 passed`; `TOTAL 190 17 91%`; exact total coverage `91.05%`; 80% threshold reached |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!` |
| `\.venv\Scripts\ruff.exe format --check .` | 1 | `5 files would be reformatted, 43 files already formatted`; files: `chinescan/core/logging/structured.py`, `chinescan/core/models/__init__.py`, `chinescan/core/storage/sqlite.py`, `migrations/env.py`, `tests/unit/test_redaction.py` |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 23 source files` |
| `\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 54 packages in 2ms` |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable `chinescan` distribution skipped |
| `rg -n -A 5 '^name = "pytest"' uv.lock` | 0 | Locked pytest version is `9.1.1`; pip-audit reported no known vulnerability in the checked environment |
| `docker compose -f docker-compose.yml config --quiet` | 0 | No output; configuration valid |
| `docker build -f docker/Dockerfile -t chinescan:0.1.0 .` | 1 | Wheel built, but runtime install failed: `ERROR: ChiNeScan.whl is not a valid wheel filename.` |

The config commands used the temporary directory `C:\Users\CIPHER~1\AppData\Local\Temp\chinescan-phase1-acceptance`. The malformed TOML validation did produce a clear parse error, but returned exit 2 rather than the expected 3.

## Step 2: Base image digest

Neither Dockerfile base line is pinned to an immutable digest:

```dockerfile
FROM python:3.12-slim-bookworm AS build
FROM python:3.12-slim-bookworm AS runtime
```

No digest was looked up or added.

## Step 3: Repository state

`git -C C:\src\Chinescan status --short` produced no output. `git -C C:\src\Chinescan diff --stat` produced no output.

The existing `.venv`, `.venv312`, `.pytest_cache`, `tests/.pytest-tmp`, `.ruff_cache`, and `.mypy_cache` paths are covered by `.gitignore`. No unexpected unignored files were found.

## Section 9 Definition of Done

**NOT RUN** — `docs/BRIEF.md` was absent, so the individual Section 9 criteria were unavailable and could not be accurately enumerated or assessed.
