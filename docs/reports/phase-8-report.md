# Phase 8 verification report

Recorded 2026-10-26 in `C:\src\Chinescan` with Python 3.12.10.

## Outcome and boundary

This is a partial Phase 8 delivery. GitHub Actions now enforces the 80% coverage floor over the
full `chinescan` package. A GitLab CI example runs the lockfile, lint, format, type, full-coverage,
dependency-audit, and Bandit checks from a digest-pinned Python image. Deployment remains disabled
because no target, registry, credentials, health endpoint, or environment-specific backup and
rollback procedure is configured. Local backup/restore and operational limitations are documented
in `docs/DEPLOYMENT.md`. The offline code/log benchmark is recorded by revision-keyed GitHub Actions
artifacts; the environment does not provide GitHub history data for cross-revision timing analysis.

`chinescan code --fail-on` supports `critical`, `high`, `medium`, `low`, `info`, and `never`. It
returns exit 1 when candidate findings meet or exceed the selected threshold. The default is
`never`, preserving existing behavior. Scanner failures still return exit 1 regardless of the
finding threshold.

`chinescan trends --days N` reports daily scan, finding, and alert counts from local SQLite for a
1–366 day window. Findings and alerts count per scan occurrence. Summaries omit target names and
raw evidence.

Phase 7 remains pending because the repository instructions prohibit a network listener. See the
[Phase 7 plan](../plans/phase-7.md) for the constraint and required policy change.

## Verification results

| Command | Exit | Result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!`. |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `92 files already formatted`. |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 41 source files`. |
| `$env:PYTHONPATH='C:\src\Chinescan\.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `69 passed`; total coverage `82.26%` (required 80%). |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChiNeScan distribution skipped. |
| `\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | No medium/high issues; four low-severity subprocess notices remain in the local all-severity scan. |
| `py -3.12 -m uv lock --check` | 0 | `Resolved 57 packages in 4ms`. |
| Parse `.gitlab-ci.yml` with PyYAML | 0 | `GitLab CI YAML parsed`; GitLab's remote semantic linter was not run. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Compose configuration valid. |
| `docker build -f docker/Dockerfile -t chinescan:phase8-trends .` | 0 | Image built from the repository's digest-pinned Python 3.12.15 slim Trixie base. |
| `docker run --rm -e CHINESCAN_DATABASE_PATH=/tmp/chinescan-trends.sqlite3 chinescan:phase8-trends trends --days 2 --format json` | 0 | Returned two daily zero-count buckets from a fresh local SQLite database. |
| `tests/unit/test_code_scan.py` CLI threshold cases | 0 | HIGH finding threshold exits 1; CRITICAL threshold exits 0; invalid threshold exits 2. |
| `py -3.12 -m scripts.benchmark_local --iterations 5 --warmup 1` | 0 | Python `3.12.10`, Windows 11; revision `null` because this checkout has no CI revision variable. Code scan: 187-byte fixture, 3 findings, median `0.0033771s`, p95 `0.0037677s`, `296.11` ops/s. JSONL: 639-byte fixture, 3 events, median `0.0010173s`, p95 `0.0011175s`, `982.99` ops/s. Nginx: 236-byte fixture, 2 events, median `0.0010441s`, p95 `0.0011581s`, `957.76` ops/s. |

The current acceptance rerun after adding classic syslog-prefixed CEF support passed 70 tests at
82.50% coverage. The updated Docker image built and parsed the synthetic logs with 21 events, nine
sources, eight alerts, and no parse errors. Detailed parser verification is recorded in the
Phase 4 report addendum.

The benchmark timings are a local baseline from five measured runs after one warmup; they are
machine-specific and should not be compared with CI timings. The full test suite is offline. The
threshold tests use the synthetic local Python fixture and a temporary SQLite database. No domain,
production endpoint, registry, or deployment target was
contacted. GitLab configuration received YAML parsing only; GitLab-hosted execution is not
available in this environment.

## Definition of done

- [x] GitHub CI checks full-package coverage at the established 80% floor.
- [x] Code-scan severity thresholds are configurable and have tested CI exit behavior.
- [x] Local scan-history trends summarize stored scans, findings, and alerts by day.
- [x] Local backup, restore, upgrade, retention, and incident-handling guidance is documented with
  implementation limits.
- [x] Add a pinned GitLab quality-pipeline example.
- [x] Ruff, strict mypy, tests/coverage, pip-audit, Bandit threshold, lock, YAML, Compose, and Docker
  checks pass.
- [x] Add offline code/log benchmarks and revision-keyed 90-day GitHub Actions artifacts.
- [ ] Cross-revision performance trend analysis remains pending until CI artifacts accumulate.
- [ ] Production publishing/deployment remains disabled until a deployment environment is defined.
- [ ] Phase 7 dashboard remains pending under the no-listener repository constraint.
