# Phase 4 verification report

Recorded 2026-10-25 in `C:\src\Chinescan` with Python 3.12.10.

## Outcome

Local exported-log analysis is implemented. The `chinescan logs` command reads bounded files,
directories, gzip, ZIP, and tar archives without extracting them. Parsers support JSON, JSONL,
CSV, Linux auth/syslog, common nginx/Apache and IIS access logs, CEF, and LEEF. Cloud and
Windows event exports can be supplied as JSON or CSV. Events are normalized and stored with
source references, alerts, local IOC relationships, and a timestamp-sorted timeline in SQLite.
No live collectors, network listener, uploads, or raw-log persistence were added.

## Verification results

| Command | Exit | Result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!`. |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `69 files already formatted`. |
| `\.venv\Scripts\mypy.exe --strict chinescan` | 0 | `Success: no issues found in 33 source files`. |
| `py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `41 passed`; total coverage `84.10%` (required 80%). Python dependencies were exposed from `.venv\Lib\site-packages` for the launcher. |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChiNeScan distribution skipped. |
| `\.venv312\Scripts\uv.exe lock --check` | 0 | `Resolved 55 packages in 4ms`. |
| `\.venv\Scripts\python.exe -m json.tool schemas\finding.schema.json > $null` | 0 | Valid JSON. |
| `\.venv\Scripts\python.exe -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON, regenerated with Phase 4 event and alert fields. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Compose configuration valid. |
| `docker build -f docker/Dockerfile -t chinescan:0.1.0 .` | 0 | Image built from pinned Python 3.12 slim Bookworm digest `sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70`; runtime includes PyYAML 6.0.3. |
| `docker run --rm chinescan:0.1.0 --help` | 0 | Container help includes `logs`; container smoke check passed. |
| `\.venv\Scripts\chinescan.exe logs .\fixtures\sample-logs --rules .\fixtures\sample-logs --ioc-file .\fixtures\sample-iocs.txt --format json` | 0 | `21` events, `9` sources, `11` candidate alerts, `0` parse/rule errors. Summary omits usernames and source IPs. |
| `\.venv\Scripts\chinescan.exe scan` | 2 | Explicit planned-phase stub; usage exit code as required. |
| `git diff --check` | 0 | No whitespace errors. Git emitted only its standard CRLF conversion notices for files in the working tree. |

The CLI check used `CHINESCAN_DATABASE=tests\phase4-cli.sqlite3`; the temporary SQLite database
was removed after the check. `py -3.12 -m chinescan` is not a supported entry point; invoke the
installed `chinescan` command instead.

## Security and scope

- File, archive, line, record, rule, IOC, decompression, and rule/IOC comparison limits bound
  local processing. Symbolic links are skipped and archive members are streamed without writing
  them to disk.
- Sigma YAML is loaded with PyYAML's safe loader. Only the documented selector and condition
  subset is evaluated; temporal `timeframe` rules and full Sigma semantics are not implemented.
- Built-in detections and IOC matches are candidate alerts for analyst review. IOC matching uses
  only operator-supplied local files and makes no external enrichment requests.
- Normalized fields and source path/line references are stored; raw log lines and access query
  strings are not persisted. CLI summaries avoid exposing source IPs and usernames.
- Native EVTX, journald APIs, live collection, malware intake/storage, and network services remain
  outside this phase. Windows/cloud sources require exported JSON or CSV.

## Definition of done

- [x] Bounded local parsing and event normalization cover the planned export formats.
- [x] Timelines, built-in detections, safe-subset Sigma rules, local IOC matches, and persistence
  are implemented.
- [x] The `logs` CLI supports human and JSON summaries, deterministic fixtures, and partial-input
  reporting.
- [x] Python 3.12, Ruff, strict mypy, pytest/coverage, pip-audit, schema/lock checks, Compose,
  fixture CLI ingestion, and Docker image checks pass.

## CEF/LEEF parser hardening addendum — 2026-10-26

CEF parsing now honors escaped pipes in the seven-field header, decodes escaped backslash/pipe/
equals/newline characters, retains spaces in extension values by finding subsequent key/value
boundaries, and accepts classic syslog-prefixed CEF lines with the transport timestamp and host.
LEEF 2.0 parsing now requires and resolves its attribute delimiter field, including one-character
and `x`/`0x` hexadecimal forms; LEEF 1.0 remains tab-delimited. The synthetic LEEF 2.0 fixture
now declares its tab delimiter as `x09`.

The implemented CEF escapes and LEEF 2.0 delimiter rules follow the vendor specifications:
[ArcSight CEF implementation standard](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm)
and [IBM LEEF event components](https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components).

Focused verification: `py -3.12 -m pytest tests\unit\test_log_analysis.py -q` passed 17 tests.
The full suite passed 70 tests with 82.50% total coverage; Ruff, strict mypy, pip-audit, and the
medium/high Bandit threshold passed. The updated Docker image built successfully and its fixture
smoke test exited 0 with `event_count: 21`, `source_count: 9`, `alert_count: 8`, and
`parse_error_count: 0`. This remains a bounded parser, not a full vendor-specific CEF/LEEF
normalization implementation.
