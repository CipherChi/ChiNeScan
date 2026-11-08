# Scan another project with ChiNeScan

ChiNeScan can be run from a separate target project's directory. Its CLI can be the installed `chinescan` command or the executable in ChiNeScan's own environment. The target project does not need a copy of ChiNeScan, and its Python/Node environment does not need to be activated for the built-in assessment.

Run the setup commands from the ChiNeScan repository root. Set `$RepoRoot` to that checkout's path, and choose a results directory outside the target repository. The product name is **ChiNeScan**.

## PowerShell quick start

First confirm which CLI PowerShell will run and inspect its help. If it is already installed on `PATH`, `Get-Command chinescan` should show its location. The checked-out repository also has this direct executable path:

```powershell
$RepoRoot = (Resolve-Path .).Path
$ChiNeScan = Join-Path $RepoRoot '.venv\Scripts\chinescan.exe'
Test-Path $ChiNeScan
& $ChiNeScan --help
& $ChiNeScan version
```

If `Test-Path` is false, this checkout does not have that executable. An operator can install the project in its own environment from `$RepoRoot` using the documented `uv sync --extra dev` setup. That is an instruction only; it changes the ChiNeScan environment and is not needed when an installed CLI is available. Do not activate ChiNeScan's environment over the target project's environment: invoking its executable directly is sufficient.

Create an external results folder, enter the target, and run the built-in local scanner against `.`:

```powershell
$Target = '<path-to-target-project>'
$Results = '<path-outside-target-repository-for-results>'
$Database = Join-Path $Results 'chinescan.sqlite3'

New-Item -ItemType Directory -Force -Path $Results | Out-Null
Set-Location $Target

# Global --database comes before the command. The returned JSON contains scan_id.
$Scan = & $ChiNeScan --database $Database code . --format json | ConvertFrom-Json
$ScanExit = $LASTEXITCODE
$Scan | ConvertTo-Json -Depth 10
"Scan exit code: $ScanExit"
"Scan ID: $($Scan.scan_id)"
```

The same command works with an installed CLI by replacing `& $ChiNeScan` with `chinescan`. Keep using the same `--database` value for later report commands so they can find the saved scan. A relative target such as `.` is resolved from the current terminal directory. Relative database, config, and report paths are also resolved from the process working directory; the examples use absolute paths to avoid ambiguity.

Generate a report for the returned scan ID:

```powershell
$ScanId = $Scan.scan_id
& $ChiNeScan --database $Database report $ScanId `
  --format markdown `
  --output (Join-Path $Results "scan-$ScanId.md")
```

The supported report formats are `json`, `markdown`, `html`, `csv`, and `sarif`. For example, change `--format markdown` and the output extension to `json`, `html`, `csv`, or `sarif`. Without `--output`, report content is written to standard output. The parent directory of an explicit report output path is created if needed; an existing report file can be overwritten. Review the destination before using it.

The JSON result includes `scan_id`, `target`, `project_types`, `scanners`, `finding_count`, `severity_counts`, `findings`, and `failures`. The regular human output also prints the scan ID. `trends` can inspect aggregate counts in the selected local database, but it does not list an individual scan's findings; use `report <SCAN_ID>` for those.

## Scan profiles

### A. Basic local assessment

`code .` selects the built-in scanner by default. It reads supported source files locally and applies four small heuristic checks: dynamic `eval`, selected Python subprocess calls with `shell=True`, disabled TLS verification, and credential-like literals. It does not execute project code, start a service, contact an advisory service, or provide comprehensive vulnerability coverage. Treat every result as a candidate for review.

The scan records its target, scan, and findings in the configured local SQLite database. The built-in scan does not write into the target directory. Set `--database` before `code` as shown above, or set `CHINESCAN_DATABASE_PATH`; otherwise the default is under the current user's data directory. The database parent directory is created when needed.

Configuration precedence is explicit global CLI options, then `CHINESCAN_...` environment values, then the selected TOML config, then defaults. `--config` selects a TOML file and `CHINESCAN_CONFIG_PATH` can select one through the environment. A missing explicitly selected config is an error. `config init` writes defaults but no secret values. Do not put the database inside the target if you want all scan artifacts outside it.

### B. Optional local external scanners

Selection is by repeatable `--scanner` options. Selecting any scanner replaces the default selection, so include `builtin` explicitly if you want it alongside an external scanner:

```powershell
& $ChiNeScan --database $Database code . --scanner builtin --scanner gitleaks --format json
```

Supported external names are `semgrep`, `gitleaks`, and `trivy`. ChiNeScan locates their executables on `PATH` at runtime. The subprocess runs with the target directory as its working directory and inherits a restricted environment that includes `PATH` and basic OS/temp/locale variables, not arbitrary cloud or package-registry credentials. The target project's virtual environment is not activated or loaded by ChiNeScan. If its `Scripts`/`bin` directory is already on `PATH`, a matching scanner executable may be found there; otherwise install/configure the tool for the shell that runs ChiNeScan. ChiNeScan does not install these tools.

- **Semgrep:** requires an existing local rules file. Pass `--scanner semgrep --semgrep-rules 'C:\rules\local.yml'`. Network rules are disabled, metrics are turned off, and this adapter passes `--no-git-ignore`.
- **Gitleaks:** pass `--scanner gitleaks`. The adapter requests JSON findings and emits a generic secret description without the matched secret value.
- **Trivy:** pass `--scanner trivy`. It uses filesystem vulnerability, misconfiguration, and secret checks with database/check updates disabled and offline scan mode. Required local vulnerability data must already be cached; ChiNeScan will not download it.
- **Multiple engines:** repeat `--scanner` for each one. Each selected engine has a 120-second default timeout, configurable with `--timeout-seconds` (0.1–3600). It applies per engine.

This guide does not verify that any external scanner or local rules/cache are installed. A missing executable, invalid local rules, absent Trivy data, timeout, or scanner failure is reported as a scanner failure; other selected scanners may still have run.

### C. Advisory-service dependency checks

`pip-audit` and `npm-audit` are also accepted scanner names, but they are network-backed and excluded from the default scan. ChiNeScan requires explicit CLI consent:

```powershell
& $ChiNeScan --database $Database code . `
  --scanner pip-audit `
  --allow-network-audits `
  --format json
```

For npm, select `--scanner npm-audit` instead; it requires both `package.json` and `package-lock.json`. The pip adapter reads `requirements.txt`. These checks send dependency names/version metadata derived from the target's dependency files to the advisory service used by the installed tool. Do not use the consent flag if that disclosure is not acceptable. Merely having manifests in the project does not cause these checks to run. Do not combine these checks with the local-only profile unless you deliberately grant this consent.

The separate `domain` command performs a bounded network posture check only with its explicit ownership assertion or a matching authorization file. It is not part of code scanning and does not assess a running web application. ChiNeScan has no runtime web application assessment workflow here.

## What gets read and what is excluded

The built-in scanner's implementation walks the target tree without following directory symlinks. It excludes directories named `.git`, `.venv`, `venv`, `node_modules`, `__pycache__`, `dist`, and `build`. It only reads source files with these extensions: `.py`, `.pyi`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.java`, `.go`, and `.rb`. It skips source files larger than 1,000,000 bytes and aborts if the configured source-file or total-byte limit is exceeded. It does not honor `.gitignore` rules. Other build/generated directories are not automatically excluded unless their name is in that list.

Consequently, the built-in scanner does not read `.env` files as source, and it does not directly scan dependency manifests such as `pyproject.toml` or `package.json` for vulnerabilities. It does inspect supported source files even if Git ignores those files. The heuristic credential check omits the matched literal from its finding description; this is a narrow redaction behavior, not a guarantee that all source text is scrubbed from all external tools or logs.

External engines have their own traversal and exclusion rules. The explicit Semgrep `--no-git-ignore` option means Git ignore rules do not filter its scan. Gitleaks and Trivy are not given a shared ChiNeScan exclusion list. Do not assume `.env`, generated files, or ignored paths are skipped by those engines; review each engine's own behavior and configuration before selecting it. Reports/database remain outside the project only when you give them external paths.

Scanning does not authorize ChiNeScan or an external scanner to execute project code, install dependencies, run project scripts, or start its server. Do not run local-project commands that install or execute target code as part of this workflow. ChiNeScan does not scan `localhost` automatically.

## Results and exit codes

- **Exit 0:** command completed. Findings may be present; a successful scan is not a clean bill of health.
- **Exit 1:** a scanner execution failed, or a requested `--fail-on` threshold was met. The scan can still have been persisted; inspect the JSON `scan_id`/`failures` or human output and query the same database. `--fail-on` accepts `critical`, `high`, `medium`, `low`, `info`, or `never`; default is `never`.
- **Exit 2:** usage, validation, or report lookup errors; for example, a missing Semgrep rules file, an unconsented network audit, or an unknown persisted scan ID. CLI help and the displayed error identify the problem.

Candidate findings do not make the default invocation fail. Empty findings mean no configured rule matched the files that scanner actually inspected, not that the project is free of vulnerabilities.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `chinescan` is not recognized | Use `Get-Command chinescan`; if unavailable, invoke `$ChiNeScan` if it exists. Do not rely on the target project's activated Python environment to contain ChiNeScan. |
| Wrong Python environment | Check the executable path. A direct executable runs using the environment in which that CLI was installed. The `pyproject.toml` requires Python 3.12+. `chinescan version` confirms the CLI responds but does not print its Python interpreter. |
| Wrong working directory | Run `Get-Location`; set it to the target root. `code .` scans the current directory. A nonexistent/non-directory target is an error. |
| Paths contain spaces | Quote paths, as in `--database 'C:\scan results\app.sqlite3'` and `--output 'C:\scan results\report.md'`. PowerShell's `&` call operator invokes a quoted executable path. |
| Missing external scanner | Check `Get-Command semgrep`, `Get-Command gitleaks`, or `Get-Command trivy`. The executable must be discoverable on `PATH`; ChiNeScan does not install it. The scan reports a failure and exits 1. |
| Semgrep rules missing | Supply an existing local file with `--semgrep-rules`; downloaded/network rules are not supported by this adapter. |
| Trivy database/cache missing | Populate its cache through an independently approved process, then rerun without update flags. This guide's verification did not download a database. |
| Invalid config | Check the path and TOML values. Use `& $ChiNeScan config validate --path 'C:\path\config.toml'`. An explicitly selected but absent config is an error. |
| Database/report permission error | Confirm the current user can create/write under `$Results`; use absolute external paths. The database directory is created automatically; report output's parent directory is created automatically. |
| Empty findings | Confirm the intended source extensions are present and no relevant files are in one of the built-in excluded directories. The built-in checks are intentionally narrow. |
| Scanner timeout | Increase `--timeout-seconds` up to 3600 or run fewer scanners. The option is per engine. |
| Network audit refused | Add `--allow-network-audits` only after accepting that dependency metadata may be sent to advisory services; otherwise remove `pip-audit`/`npm-audit` from scanner selection. |

## Verification record and limits

Verified on 2026-10-26 using the existing CLI executable and the repository's synthetic `fixtures/sample-python-project`. Help checks ran from the repository root; the `code .` scan ran with the terminal inside the fixture directory. Database and report output were under an external results directory, not in the fixture. The recorded sample scan ID below is a placeholder. No real separate project was scanned, no package was installed, and no external service, live domain, or third-party scanner was invoked.

| Exact command | Working directory | Exit | Result |
| --- | --- | ---: | --- |
| `& .\.venv\Scripts\chinescan.exe --help` | `<repo-root>` | 0 | Help listed the `code`, `report`, and global `--database` commands/options. |
| `& .\.venv\Scripts\chinescan.exe code --help` | `<repo-root>` | 0 | Help confirmed target argument, repeatable `--scanner`, `--semgrep-rules`, `--timeout-seconds`, `--fail-on`, `--allow-network-audits`, and `--format`. |
| `& $exe --database $db code . --format json` | `<repo-root>\fixtures\sample-python-project` | 0 | With `$exe` set to the ChiNeScan environment executable and `$db` set to a database in the selected external results directory, returned scan ID `SYNTHETIC-SCAN-ID`, `finding_count: 3`, `failures: {}`, `scanners: ["builtin"]`; saved scan to the selected database. |
| `& $exe --database $db report SYNTHETIC-SCAN-ID --format markdown --output (Join-Path $Results 'scan-report.md')` | `<repo-root>\fixtures\sample-python-project` | 0 | Wrote a 687-byte Markdown report to the selected external path. |
| `py -3.12 --version` | `<repo-root>` | 0 | `Python 3.12.10`. |
| `$env:PYTHONPATH='<repo-root>;.venv\Lib\site-packages'; py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | `<repo-root>` | 0 | `108 passed, 5 deselected`; total coverage `82.44%`, required 80% reached. |
| `& .\.venv\Scripts\ruff.exe check .` | `<repo-root>` | 0 | `All checks passed!` |
| `& .\.venv\Scripts\ruff.exe format --check .` | `<repo-root>` | 0 | `104 files already formatted`. |
| `& .\.venv\Scripts\mypy.exe --strict chinescan` | `<repo-root>` | 0 | `Success: no issues found in 43 source files`. |
| `& .\.venv312\Scripts\uv.exe lock --check` | `<repo-root>` | 0 | `Resolved 57 packages in 3ms`. |

**NOT VERIFIED:** invocation from a separate live project directory, installed system-wide CLI, actual Semgrep/Gitleaks/Trivy execution, external binaries' file exclusions, Trivy cache contents, scanner timeout behavior against a real engine, network-backed dependency checks, report formats other than Markdown, and runtime web assessment. No real separate target was scanned. The generated synthetic scan artifacts are in the selected external results folder.
