# Phase 6 verification report

Recorded 2026-10-26 in `C:\src\Chinescan` with Python 3.12.10.

## Outcome and boundary

This is a partial Phase 6 delivery. `chinescan domain <hostname>` supports an explicit
`--i-own-this-target --operator ...` ownership assertion or a local JSON authorization grant with
an exact normalized hostname, granting operator, timezone-aware validity window, and matching
profile. The authorization record and a running scan record are saved in the configured local
SQLite database before the probe is called.

The built-in assessor resolves the exact hostname and connects only to public addresses, capped at
five. The light profile sends one HTTPS HEAD request to one selected address. Deep sends one HTTPS
HEAD request to each selected address. If every HTTPS request fails, the probe makes one HTTP HEAD
fallback per selected address. It reads only bounded response headers, does not follow redirects,
and does not read response bodies. DNS and connect/TLS/HTTP timeouts are configurable from 0.1 to
10 seconds (default three seconds); the deep-profile address cap is configurable from one to five,
and sequential request spacing from zero to five seconds. These values are persisted in the scan
record before probing. No ports, subdomains, or vulnerability templates are scanned.

Broader external scanner adapters from the original Phase 6 scope are deferred. Their traffic and
scope need a separate review. They have not been represented as implemented here.

## Verification results

| Command | Exit | Result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | `Python 3.12.10`. |
| `\.venv\Scripts\ruff.exe check .` | 0 | `All checks passed!`. |
| `\.venv\Scripts\ruff.exe format --check .` | 0 | `85 files already formatted`. |
| `\.venv\Scripts\mypy.exe chinescan` | 0 | `Success: no issues found in 40 source files`. |
| `py -3.12 -m pytest --cov=chinescan --cov-report=term --cov-fail-under=80` | 0 | `60 passed`; total coverage `81.64%` (required 80%). |
| `\.venv\Scripts\pip-audit.exe --skip-editable` | 0 | `No known vulnerabilities found`; editable ChiNeScan distribution skipped. |
| `py -3.12 -m uv lock --check` | 0 | `Resolved 57 packages in 5ms`. |
| `\.venv\Scripts\python.exe -m json.tool schemas\investigation.schema.json > $null` | 0 | Valid JSON; schema includes `AuthorizationRecord`. |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Compose configuration valid. |
| `docker build -f docker/Dockerfile -t chinescan:0.1.0 .` | 0 | Image built using the pinned Python 3.12.15 slim Trixie digest `sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704`. |
| `docker run --rm chinescan:0.1.0 --help` | 0 | Container help lists the `domain` command. |
| `\.venv\Scripts\chinescan.exe domain example.com` | 2 | Rejected for missing explicit authorization before database creation or network access. |
| `docker run --rm chinescan:0.1.0 domain example.com` | 2 | Rejected for missing explicit authorization; no live target was contacted. |
| `git diff --check` | 0 | No whitespace errors; Git printed standard LF-to-CRLF working-tree notices. |

The offline domain tests cover IDNA normalization and invalid targets, ownership assertions,
authorization-file scope and expiry, rejection before database/network access, audit persistence
before probing, public-address filtering, the five-address ceiling, profile request counts,
configurable limits and request spacing, and header-only HTTP parsing. All network functions are
mocked; no live domain was assessed.

## Definition of done

- [x] Add exact-host authorization inputs and persist authorization before network activity.
- [x] Add a bounded DNS/TLS/HTTP HEAD assessor with public-address filtering and no body reads.
- [x] Make timeouts, request spacing, and the address cap configurable and persist them with scans.
- [x] Add JSON/human CLI output and reject unauthorized requests with usage exit code 2.
- [x] Add offline tests, schema, docs, and roadmap updates.
- [x] Python 3.12, Ruff, strict mypy, tests/coverage, pip-audit, lock, schema, Compose, and Docker
  checks pass.
- [ ] Broad external scanner adapters remain deferred pending a separate scope and traffic review.

## Public GitHub import work — 2026-11-01

This is an incomplete implementation checkpoint on `hardening/github-import`, based on main at
`1548986`. The required Phase 5A report cleanup was committed separately as `82b2989`; the Phase 1
report now matches commit `ac1a6f4`, and the moved notes are in `phase-5a-report.md`.

Implemented in this checkpoint: a pure ASCII URL/ref validator with rejection coverage for unsafe
schemes, hosts, credentials, ports, encoded path separators/dots, Unicode, extra path segments,
malformed owners/repositories, and Git reference syntax; bounded configuration fields; authenticated
API paths and CLI commands that return `feature_disabled` while the default flag is false; and a
diagnostics check for the flag and local Git availability. No network or subprocess is used by URL
preview validation.

The feature is not complete and must remain disabled. With the flag set true, API/CLI import paths
return `import_unavailable`; there is no clone runner, background job store, session-bound preview
registry, project creation/removal integration, or frontend dialog. Therefore clone options and
redirect behavior have not been verified, and this branch must not be enabled or treated as ready
for import. There are no frontend or E2E results or screenshots for this checkpoint.

| Exact command | Exit | Result |
| --- | ---: | --- |
| `uv run pytest tests/unit/test_github_import.py tests/unit/test_projects.py::test_github_import_api_is_stably_disabled_by_default -q --basetemp <OS-temp>` | 0 | 41 passed. |
| `uv run pytest --cov=chinescan --cov-report=term --cov-fail-under=80 --basetemp <OS-temp>` | 0 | 381 passed, 5 deselected; 81.62% total coverage. |
| `uv run ruff check .` | 0 | All checks passed. |
| `uv run ruff format --check .` | 0 | 158 files already formatted. |
| `uv run mypy --strict chinescan` | 0 | No issues in 65 source files. |
| `uv run bandit --severity-level medium -r chinescan` | 0 | No medium/high findings; 12 low findings remain; no `nosec` exclusions. |
| `uv run python -m compileall -q chinescan` | 0 | Passed. |

No feature-specific frontend/E2E, Git clone-flag/redirect verification, or screenshot was completed.
Git is `2.56.0.windows.4`; because there is no clone runner, the requested clone flags and redirect
behavior were not tested. Gitleaks is unavailable locally; the PR's CI secret scan passed. The
branch was pushed and opened as [draft PR #13](https://github.com/CipherChi/Chinescan/pull/13).
Configured checks for the tested PR head `9783c1c0bd6eb8445c9fddf4dd3624ac7226c4f9` all passed:
quality, dashboard build/browser acceptance, container, Windows managed-malware worker acceptance,
secret scan, and CodeQL (Actions, JavaScript/TypeScript, Python, and aggregate CodeQL).

Remaining work includes the full managed-copy lifecycle and all Phase 6 acceptance gates in the task
request. The passing repository checks validate this partial code and do not make GitHub import usable.

## Phase 6B Git option verification and implementation checkpoint — 2026-11-01

Git verification was performed before editing the runner, using Git `2.56.0.windows.4`, a local
runtime-created bare repository, and temporary directories under the OS temp directory.

| Option / behavior | Result | Evidence / decision |
| --- | --- | --- |
| `--depth 1` | Supported; local-path clone behavior differs | Git accepted it, then warned `--depth is ignored in local clones; use file:// instead`. HTTPS server behavior depends on the server. |
| `--single-branch` | Supported | Accepted in the successful local clone. |
| `--no-tags` | Supported | Accepted in the successful local clone. |
| `--no-recurse-submodules` | Supported | Accepted in the successful local clone. |
| `--filter=blob:limit=16m` | Supported with a server caveat | Git accepted it, then warned the filter is ignored for a local-path clone. Partial clone filtering only takes effect when the remote server supports it. |
| `-c core.symlinks=false` | Supported | `git -c core.symlinks=false --version` exited 0. |
| `-c core.hooksPath=<empty dir>` | Supported | `git -c core.hooksPath=<temp empty dir> --version` exited 0. |
| `-c protocol.allow=never`, `-c protocol.https.allow=always` | Supported | Both assignments parsed; production `GIT_ALLOW_PROTOCOL=https` rejected a local bare repo with `fatal: transport 'file' not allowed`. |
| Test-only local `file://` transport | Supported only with explicit test override | The verification clone succeeded with `protocol.file.allow=always` and `GIT_ALLOW_PROTOCOL=https:file`. Production code uses HTTPS only. The source URL validator continues rejecting `file://`. |
| `-c core.fsmonitor=false` | Supported | Config assignment parsed successfully. |
| `-c credential.helper=` | Supported | Config assignment parsed successfully; environment is constructed from the allowlisted keys rather than inherited. |
| `-c http.followRedirects=false` | Supported; chosen setting | Config assignment parsed. A local HTTP server returned 302 to a second local host; Git exited 128 with HTTP 302 and the destination recorded zero requests. Redirects are disabled to prevent moving fetches to an unvalidated host. |
| `-c advice.detachedHead=false` | Supported | Config assignment parsed successfully. |
| `GIT_TERMINAL_PROMPT=0` | Supported | Included in the tested environment. |
| `GIT_LFS_SKIP_SMUDGE=1` | Supported | Included in the tested environment. |
| `GIT_CONFIG_NOSYSTEM=1` | Supported | Included in the tested environment. |
| `GIT_CONFIG_GLOBAL=NUL` | Supported on Windows | Included in the tested environment; `NUL` is Windows' null device. |
| `GIT_ALLOW_PROTOCOL=https` | Supported | Local `file` transport was rejected. The test-only seam adds `file` and a per-command `protocol.file.allow=always`; it is not reachable through production URL validation. |

## Phase 6B managed runner, preview, jobs, and verification — 2026-11-01

### Failure diagnostics and root fixes

The two failures reported for the normal bare-repository import had different causes and were
diagnosed independently before their fixes:

| Failure | Diagnostic evidence before the fix | Cause and fix |
| --- | --- | --- |
| `quota_exceeded` | At the failing poll the configured worktree cap was `524,288,000` bytes and `50,000` files. The ordinary repository had about 27–30 KB of `.git` metadata and zero worktree files while checkout was still in progress. | A race in the old size walk translated a transient `OSError` while Git was writing/removing entries into `cap + 1`, falsely reporting quota exceeded. Worktree bytes and `.git` bytes are now measured separately; the worktree is bounded by the configured cap and `.git` has its own bounded allowance (8–64 MiB, selected from one quarter of the configured cap within those bounds). The poller kills the child if either component or the combined cap-plus-allowance is exceeded. Verification applies the project content cap separately from the metadata allowance. |
| `unsafe_entries` | The reported candidate was an ordinary nested `.git` directory under the long Windows temp path; it was not an 8.3 alias. No reserved/trailing/ADS name rule fired. `.git`, `HEAD`, `config`, and `hooks` are allowed Git metadata names during verification. | `_prove_managed_target` incorrectly required every target's parent to be the managed import directory, so it rejected the nested `.git` directory. Containment now canonicalizes both managed storage and every candidate with the same `Path.resolve`, normalized case/path, and NFC Unicode function before comparing. Reparse checks inspect the managed directory itself and entries inside a clone, not temp-directory ancestors. |
| `incomplete` observed after the containment fix | Removal raised Windows `WinError 5` on a read-only `.git/objects/pack/*.idx` file. | Git metadata and failed clone cleanup now use a containment-checked remover that clears read-only attributes before retrying deletion and does not traverse links/reparse points. |

The short-path regression now resolves the temporary directory through `GetShortPathNameW`, runs a
normal bare-repository import from that alias, and gives the worktree cap only eight bytes above
the content size. It passed, including `.git` removal and recorded commit SHA.

### Hostile fixture results

All fixtures are built at runtime. The local bare repository uses the guarded test-only `file://`
transport; production URL validation still rejects it.

| Fixture | Result |
| --- | --- |
| Normal repository, including a read-only `.git` pack and a hook canary | Succeeded; SHA and fetch time recorded, `.git` removed, hook canary absent. |
| Pinned full commit SHA | Succeeded with shallow fetch; the recorded SHA matched the requested commit. |
| Committed symlink | Neutralized by `core.symlinks=false`; accepted as ordinary file content, with no link created. |
| Hostile `.git/hooks` content | Never executed; canary was not created. |
| Submodule entry | Not fetched because recurse-submodules is disabled. |
| LFS pointer | Pointer remained ordinary content; LFS smudge was skipped. |
| Oversized worktree file / too many files | Failed with `quota_exceeded`; clone cleanup removed the target. |
| Windows reserved name, trailing dot, ADS | Failed with `unsafe_entries`. Runtime raw-tree objects are used because Git for Windows' normal index rejects those names before they can become fixtures. |
| Overlong nested path | Failed with `unsafe_entries`; runtime raw tree objects bypass the host filesystem's inability to create the fixture. |
| Symlink/reparse entry and forced outside-root resolution | Failed with `unsafe_entries`; outside canary remained unchanged. |
| File removed during verification | Job became `incomplete` with `quarantined_or_missing_files`. |
| Timeout / explicit cancel / quota breach during a live child | Each ended in its expected stable code and the started child PID was no longer running. |
| Poisoned clone target pointing outside managed storage | Cleanup refused it; outside canary remained unchanged. |
| Git stderr containing a path and canary | Response and captured logs contained neither. |
| Test-only file transport without the test guard | Refused. |

Preview is local-only and makes no network or subprocess call. Preview IDs are session-bound,
expire after ten minutes, and are single-use. The bounded queue accepts four queued jobs and a
single worker runs jobs serially. API controls remain behind the existing authentication, CSRF,
Origin/Host, bounded-body, and rate-limit middleware. CLI import prints the preview before requiring
`--yes`; exit codes remain 0 for success and 2 for failure.

### Local verification

| Exact command | Exit | Result |
| --- | ---: | --- |
| `uv run pytest tests/unit/test_github_import.py -q --basetemp <OS-temp-run-1>` | 0 | 66 passed in 204.53s after the cross-platform follow-up. |
| `uv run pytest tests/unit/test_github_import.py -q --basetemp <OS-temp-run-2>` | 0 | 66 passed in 79.22s after the cross-platform follow-up. |
| Focused short-path import | 0 | 1 passed in 6.51s. |
| Focused timeout/cancel/byte-quota/file-count tests | 0 | 4 passed, including live-child termination on both quota dimensions. |
| Focused bounded-queue and poisoned-path cleanup tests | 0 | 2 passed. |
| Focused Git stderr/path canary test | 0 | 1 passed. |
| `uv run pytest --cov=chinescan --cov-report=term --cov-fail-under=80 --basetemp <OS-temp>` | 0 | 407 passed, 5 deselected in 665.82s; 82.01% total coverage (80% required). This Windows run preceded the cross-platform-only test guard and ADS message adjustment. |
| `uv run ruff check .` | 0 | All checks passed. |
| `uv run ruff format --check .` | 0 | 158 files already formatted. |
| `uv run mypy --strict chinescan` | 0 | No issues in 65 source files. |
| `uv run bandit --severity-level medium -r chinescan` | 0 | No medium/high findings; 17 low findings. A narrow inline B603 comment documents the validated Git argv, canonical URL, fixed options, and confined UUID target. Bandit reports the rule was not triggered by the injected process-factory call. |
| `uv run python -m compileall -q chinescan` | 0 | Passed. |

Gitleaks was not run locally; PR CI remains the secret-scan gate. There is no frontend, project
integration, or private-repository support in this phase. GitHub-side content cannot be verified
beyond the static checks described here; DNS and TLS rely on the operating system. The feature flag
remains false by default. PR #13 remains a draft and must stay unmerged until Phase 6C is implemented.

### Published commits and CI

| Commit | Change |
| --- | --- |
| `50a979d` | Managed runner, preview/job service, route and CLI adapters. |
| `046e964` | Runner, validation, security, CLI/API parity, and hostile fixture tests. |
| `56fa4c3` | Git option verification and Phase 6B report. |
| `be7daf6` | Linux CI fixes: skip the Windows-only short-path helper off Windows and clarify the ADS/Windows-name validation reason. |

The first CI run on `56fa4c3` had one failing check: quality reported `2 failed, 399 passed, 6
skipped, 5 deselected in 58.49s` at 80.22% coverage. Exact failures were
`test_local_bare_repository_import_verifies_sha_and_removes_git` (`AttributeError: module 'ctypes'
has no attribute 'WinDLL'` on Ubuntu) and
`test_ads_is_detected_and_incomplete_when_a_tracked_file_vanishes` (expected `alternate data
stream`; got `The repository contains an unsafe Windows file name.`). Commit `be7daf6` fixed both;
the updated Windows import suite passed twice and the subsequent Linux quality job passed.

On PR #13 head `be7daf6`, `gh pr checks 13 --watch` completed with every configured check passing:
quality (`400 passed, 7 skipped, 5 deselected`; 80.23% coverage), dashboard build and browser
acceptance, container, Windows managed malware worker acceptance, secret scan, CodeQL, and the
Actions, JavaScript/TypeScript, and Python analysis jobs. The draft remains open and unmerged.

## Phase 6C status

The seven skips in the Phase 6B CI quality run are all platform-conditional:

| Test | Skip reason |
| --- | --- |
| `test_actual_windows_contained_worker_returns_bounded_synthetic_result` | Requires Windows Job Objects. |
| `test_actual_windows_manager_persists_contained_synthetic_analysis` | Requires Windows Job Objects. |
| `test_actual_job_object_terminates_synthetic_child_process_tree` | Requires Windows Job Objects. |
| `test_scanner_rechecks_policy_after_project_root_junction_swap` | Requires NTFS directory junction support. |
| `test_windows_short_name_is_expanded_before_deny_check` | Requires Windows 8.3 short names. |
| `test_windows_drive_type_remote_is_denied` | Requires Windows `GetDriveTypeW`. |
| `test_local_bare_repository_import_verifies_sha_and_removes_git` | The short-path alias assertion applies only on Windows. |

The realistic `.git` quota regression is
`tests/unit/test_github_import.py::test_local_bare_repository_import_verifies_sha_and_removes_git`.
It imports a runtime-built ordinary bare repository with about 27–30 KiB of Git metadata and
sets the worktree content cap to exactly the content length plus 8 bytes. The worktree stays under
its cap while `.git` uses its separate bounded allowance.

### Phase 6C URL seam diagnosis and verification — 2026-11-02

The original E2E import failure was caused by the browser harness encoding the runtime fixture
path twice. Node's `pathToFileURL` output contained an escaped percent sequence for the Windows
short-path component; Python treated that escaped text as a literal filesystem path and then
encoded the percent again. The runner consequently passed Git
`file:///C:/Users/CIPHER%25257E1/AppData/Local/Temp/chinescan-playwright-kIbuIJ/instance-5-ttl-1800/public-repository.git`
instead of the fixture's canonical local file URL. Git exited 128 and stderr said the source
“does not appear to be a git repository”; this came from the local path not existing. It was not a
protocol denial, nor a GitHub 404/private response. The child environment included
`GIT_ALLOW_PROTOCOL=https:file`, the test-only `protocol.file.allow=always` override, and no
`SystemRoot`; Git ran successfully, so the missing variable was not the cause.

The passing unit fixture previously used `Path.as_uri()` directly and therefore did not traverse
the Node URL conversion. The fix centralizes canonical local test URL creation in the guarded
`guarded_test_file_repository_url` helper, uses that helper in both the browser server announcement
and unit tests, and converts a parsed file URL with `url2pathname` before canonicalizing it. The
production URL validator remains HTTPS GitHub-only, and construction of the file transport seam
still requires the test guard.

The error table had also classified Git's generic “could not read from remote repository” as
`repo_not_found_or_private`. That text also describes invalid local paths and protocol failures.
The mapping now limits `repo_not_found_or_private` to explicit repository-not-found/HTTP 404
messages and maps local path/protocol errors to `import_unavailable`. Parametrized mapping tests
cover both outcomes.

| Verification | Result |
| --- | --- |
| Focused public GitHub import E2E | 1 passed; preview, import, project assessment, malware VM guidance, typed removal, and clone deletion completed. |
| Full browser E2E run 1 | 17 passed. |
| Full browser E2E run 2 | 17 passed. |
| Frontend typecheck and production build | Passed in the OS-temp frontend copy. |
| Frontend unit suite, three earlier runs | 47 passed per run. The final suite has 48 tests after the `path_too_long` dialog state was added. |
| Screenshot files | `%TEMP%\chinescan-phase6c-screenshots\github-preview.png`, `github-progress.png`, `github-success.png`, and `github-disabled.png`. |
| `uv run --locked --extra dev ruff check .` | Passed. |
| `uv run --locked --extra dev ruff format --check .` | Passed; 159 files formatted. |
| `uv run --locked --extra dev mypy --strict chinescan` | Passed; 65 source files. |
| `uv run --locked --extra dev bandit --severity-level medium -r chinescan` | Passed; no medium/high findings. |
| `uv run python -m compileall -q chinescan` | Passed. |
| Full backend suite with 80% coverage floor, two historical diagnostic runs | Each run: 412 passed, 6 failed, 5 deselected; 81.47% coverage. The subsequent short-basetemp runs documented below resolved the temp-path issue; the final path-code follow-up and verification results are recorded at the end of this report. |

The first backend gate invocation used a pre-existing `--basetemp` folder and failed at fixture
setup with `FileExistsError`. The follow-up investigation showed that the test temp path itself was
the trigger, rather than order-dependent state: with the long
`chinescan-phase6c-pytest-<GUID>` base, Git emits `filename too long` while checking out under the
nested API test directory, and the mapper returns the stable external code `unsafe_entries`. The
same API test failed once in isolation with coverage and that long base, proving there is no
polluter/victim pair. With a short unique OS-temp base (`c6a-<4 hex>` etc.), three complete backend
runs each passed 418 tests with 5 platform deselections and 81.61% coverage. A fourth run with all
test modules supplied in reverse path order also passed 418 tests with 5 deselections and 81.61%
coverage. `-p no:cacheprovider -x` baseline also passed 418 tests with 5 deselections. No module
global caches, queues, environment mutations, or cwd changes were found in the GitHub importer,
filesystem policy, or project modules. Temporary raw stderr instrumentation was removed; it wrote
only under a test's OS-temp directory and its log was deleted. No product code or tests were changed
for this investigation. No new commit or push was made, and no current-head CI status is available.

### Phase 6C path-length handling — 2026-11-02

The prior full-suite failures were not caused by order-dependent state. Long Windows pytest temp
paths caused Git to report `filename too long`; that was being classified as `unsafe_entries`. The
error table now maps Git filename/path-too-long diagnostics to `path_too_long`, with the safe
message to shorten the managed import directory. Actual unsafe names remain `unsafe_entries`.
Before starting Git, the importer checks that the managed root plus a 160-character checkout-path
budget stays within the conservative 260-character Windows limit. The default managed directory
is now the short `gh` child of the data directory. Doctor and API diagnostics report only `ok` or
`at-risk`, and warn only when imports are enabled. CI pytest uses the short OS-temp path
`${RUNNER_TEMP}/c6`; GitHub unit fixtures use an isolated short OS-temp clone root so their
test-function directory names do not consume the product's checkout budget.

Initial focused tests correctly revealed that the preflight budget also rejected imports whose
*test* managed root inherited a long pytest function-name path. After moving those test clone roots
to short OS-temp directories, the focused GitHub import and project suites plus the doctor warning
test passed: 81 passed. A smaller targeted rerun covering path-too-long mapping/preflight, the
genuinely hostile symlink/reparse fixture, and doctor warning passed: 12 passed. The Windows
overlong repository fixture now expects `path_too_long` (Git cannot materialize that tree before
post-clone verification); reserved device names, trailing dots/spaces, ADS, links/reparse points,
and outside-root entries remain `unsafe_entries`.

### Phase 6C CI follow-up — 2026-11-02

The first CI run on `c2d959f` passed the frontend/browser, secret scan, CodeQL, Windows managed
malware worker, and container checks. CI quality failed in
`tests/unit/test_github_import.py::test_overlong_repository_path_is_rejected`: on Linux Git
materialized the deep fixture, then `_verify_tree` classified its 260-character path as
`unsafe_entries`. The Windows run fails during checkout and correctly exercises Git stderr
mapping, while Linux reaches the verifier; both environments need the same stable
`path_too_long` result. The verifier now maps that path-length rule to `path_too_long` and uses the
same safe shorter-managed-directory message. Other entry safety checks remain `unsafe_entries`.
The focused cross-platform regression test and stderr mapping test passed locally (2 passed).

### Phase 6C final verification — 2026-11-02

The verifier-side path-length rule now returns `path_too_long`, closing the Linux-only route that
the initial CI run exposed. The later CI quality run passed the complete backend suite. Final
local gates on commit `939f9f0`:

| Gate | Result |
| --- | --- |
| Backend suite with coverage floor | 422 passed, 5 platform deselections, 81.67% coverage (80% required). |
| Ruff check and format check | Passed. |
| Strict mypy | Passed; 65 source files. |
| Bandit medium+ | Passed; no medium/high findings. |
| Compileall and `git diff --check` | Passed. |
| Frontend typecheck and build | Passed in the full OS-temp repository copy. |
| Frontend unit suite | 48 passed on each of 3 runs. |
| Frontend browser suite | 17 passed on each of 2 runs. |

The first e2e attempt against the temp copy failed before loading the dashboard because that
attempt copied only `frontend/` and omitted the sibling backend harness and built `frontend/dist`.
No application tests ran in that attempt. The corrected gate synced the full repository into
`%TEMP%\\c6-phase6c`, excluded credentials, local configuration, databases, `.git`, and
`node_modules`, built the frontend in that copy, and then passed both complete e2e runs.

The PR #13 check run for `939f9f0` passed all checks: `quality`, `dashboard build and browser
acceptance`, `Windows managed malware worker acceptance`, `container`, `secret scan`, CodeQL, and
the CodeQL Actions/JavaScript-TypeScript/Python analyses. The PR is open and ready for review;
it was not merged or approved.
