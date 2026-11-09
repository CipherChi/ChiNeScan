# Phase 5 verification report

Recorded 2026-10-26 in `C:\src\Chinescan` with Python 3.12.10.

## Outcome and boundary

This is a partial Phase 5 delivery. `chinescan malware analyze <path>` performs bounded,
non-executing static triage of one local regular file up to 64 MiB. It reports MD5, SHA-1,
SHA-256, best-effort PE/ELF/PDF/OLE/ZIP/TAR/GZIP signatures, a printable-string count without
string contents, bounded ZIP member metadata without extraction, and candidate IP/domain/URL/email
indicators. Indicator values are hidden unless `--include-indicators` is provided. YARA and
ClamAV are optional local integrations selected explicitly with `--yara-rules` and `--clamav`.

The repository instruction says not to claim malware intake/storage is implemented. The analyzer
therefore does not copy, quarantine, encrypt, retain, or persist samples or results. This phase
does not meet the complete original Phase 5 acceptance requirement for safe sample intake and
storage. Memory analysis and dynamic detonation remain explicit exit-2 stubs.

## Verification results

| Command | Exit | Result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!`. |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `78 files already formatted`. |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 36 source files`. |
| `py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `50 passed`; total coverage `82.23%` (required 80%). Python dependencies were exposed from `.venv\Lib\site-packages` for the launcher. |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChiNeScan distribution skipped. |
| `\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 57 packages in 3ms`. |
| `\.venv\Scripts\bandit.exe --severity-level medium -r chinescan` | 0 | No medium/high issues identified. |
| `\.venv\Scripts\bandit.exe -r chinescan` | 1 | Five low issues reported: one existing `assert_used`, two existing code-scanner subprocess notices, and two notices for the new local malware scanner subprocess integration. No findings were suppressed; details and controls are recorded in `docs/reports/security-review.md`. |
| `\.venv\Scripts\python.exe -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON; no schema change was needed. |
| `\.venv\Scripts\python.exe -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON; no schema change was needed. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Compose configuration valid. |
| `docker build -f docker/Dockerfile -t chinescan:0.1.0 .` | 0 | Image built from pinned Python 3.12.15 slim Trixie digest `sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704`; runtime dependencies installed from hashed `uv.lock` export. |
| `docker run --rm chinescan:0.1.0 --help` | 0 | Container help lists `malware`. |
| `docker run --rm -v "${PWD}\fixtures\sample-malware:/samples:ro" chinescan:0.1.0 malware analyze /samples/synthetic-indicators.txt --format json` | 0 | Read-only mounted synthetic fixture analyzed; JSON summary omitted indicator values and file paths. |
| `\.venv\Scripts\chinescan.exe malware analyze C:\src\Chinescan\fixtures\sample-malware\synthetic-indicators.txt --format json` | 0 | Synthetic fixture identified as generic data; 204 bytes; 5 printable runs; 5 candidate indicators; default JSON omitted indicator values and path. |
| Same CLI command with `--include-indicators` | 0 | Explicitly emitted synthetic fixture candidate values. |
| `\.venv\Scripts\chinescan.exe malware memory memory.dmp` | 2 | `malware memory is planned for Phase 5 and is not implemented.` |
| `\.venv\Scripts\chinescan.exe malware detonate sample.bin` | 2 | `malware detonate is planned for Phase 5 and is not implemented.` |
| `git diff --check` | 0 | No whitespace errors; Git emitted standard LF-to-CRLF working-tree notices. |

YARA and ClamAV executables were not installed on PATH in this environment. Their adapter behavior
was checked with mocked executable discovery and process results, including match-name filtering
and timeout handling; no real signature engine run was performed.

## Security and limitations

- The analyzer rejects symlinks, non-regular files, and files exceeding 64 MiB, hashes data read
  once in bounded chunks, and checks file identity/size/modification time before and after the
  read. The file remains only in memory for metadata extraction; no output contains arbitrary
  extracted strings.
- ZIP member listing is capped at 1,000 entries. No archive member is extracted or recursively
  analyzed. File signatures and PDF/Office markers are heuristic indicators, not parser-grade
  validation or a malware verdict.
- External engines are opt-in, local-only adapters using argument vectors, no shell, a restricted
  environment, 30-second timeouts, and bounded merged output. Their rule definitions and database
  freshness are the operator's responsibility.
- Extracted indicators and scanner matches are candidate evidence requiring analyst validation.
- Malware intake/storage, encrypted sample retention, strict sample access control, YARA recursive
  archive analysis, rich PE/ELF/Office/PDF parsers, memory analysis, IOC enrichment, and sandbox
  execution are not implemented.

## Definition of done

- [x] Bounded local hashing and common signature identification are implemented without executing
  a submitted file.
- [x] Candidate static indicators, printable-string counts, and bounded ZIP metadata are
  available without storing analysis records.
- [x] Optional YARA/ClamAV adapters use explicit opt-in and bounded local subprocess controls.
- [x] CLI exposes static analysis and keeps memory/detonation as usage-code-2 stubs.
- [x] Python 3.12, Ruff, strict mypy, tests/coverage, pip-audit, Bandit's CI threshold, Compose,
  fixture CLI, and Docker image checks pass.
- [ ] Safe sample intake and storage remain unimplemented by design and block completion of the
  full Phase 5 definition of done.

## Stage B1 superseding addendum — 2026-10-27

The original report describes the pre-B1 implementation. Stage B1 now adds the approved backend-only
operator registry, managed-copy intake, persisted malware records, recovery reconciliation, and
fixed Windows Job Object worker. ZIP central-directory inspection is skipped and reported as partial;
the earlier claim of bounded ZIP metadata is no longer current. Browser intake/download routes,
case-link UI, retention/deletion controls, memory analysis, and dynamic analysis remain outside this
slice. Exact B1 acceptance is recorded in `phase-1-report.md`; backend operations are in
`../MALWARE-BACKEND.md`.
