# Security hardening candidate validation

Date: 2026-10-25

This report covers the isolated, uncommitted worktree on branch `codex/security-hardening`, based on `6e7c002e22add574825f85338c0d8545cd74aaf0`. It does not describe the original dirty worktree or its Phase 2–4 changes. The branch contains only the security candidate, CI/dependency/container changes, deployment-status note, and the formatting needed for the new format check to pass on the Phase 1 baseline.

## Tool versions

| Tool | Version / identity |
| --- | --- |
| Python | 3.12.10 (`py -3.12`) |
| uv | 0.13.5 |
| Ruff | 0.17.2 |
| mypy | 1.20.2 |
| pytest | 9.1.1 |
| pip-audit | 2.10.1 |
| Bandit | 1.9.4 |
| Gitleaks | 8.30.1, `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` |
| actionlint | 1.7.12, `rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667` |
| Trivy | 0.76.1, `ghcr.io/aquasecurity/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c` |
| Container base | `python:3.12.15-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704` |

## Checks

| Command / check | Exit | Result |
| --- | ---: | --- |
| `py -3.12 --version` | 0 | Python 3.12.10 |
| `uv sync --locked --extra dev --python 3.12` | 0 | Resolved 57 packages; installed locked development environment |
| `uv lock --check` | 0 | Lockfile current |
| `uv run --locked --extra dev ruff check .` | 0 | All checks passed |
| `uv run --locked --extra dev ruff format --check .` | 0 | 50 files already formatted |
| `uv run --locked --extra dev mypy --strict chinescan` | 0 | No issues in 23 source files |
| `uv run --locked --extra dev pytest --cov=chinescan.core --cov-report=term-missing --cov-fail-under=80` | 0 | 19 passed; 91.24% core coverage |
| `uv run --locked --extra dev pip-audit --skip-editable` | 0 | No known vulnerabilities; editable ChiNeScan distribution excluded by the command |
| `uv run --locked --extra dev bandit --severity-level medium -r chinescan` | 0 | No medium/high findings; 350 lines scanned |
| `uv run --locked --extra dev bandit -r chinescan` | 0 | No Bandit findings; 350 lines scanned |
| actionlint 1.7.12 on `.github/workflows/ci.yml` | 0 | Workflow valid; initial shellcheck warning fixed and rechecked |
| `docker compose -f docker-compose.yml config --quiet` | 0 | Valid Compose configuration |
| `py -3.12 -m json.tool` on both committed schemas | 0 | Both schemas parse as JSON |
| `git diff --check` | 0 | No whitespace errors |
| Docker build, `docker build -f docker/Dockerfile -t chinescan:security-only .` | 0 | Built local image `sha256:0d3ef470e1448dfea13fc55468934411e2cc8983eea4ccc753a8622cbb770d9d` |
| `docker run --rm chinescan:security-only --help` | 0 | Container CLI starts and prints Phase 1 help; later-phase commands remain stubs |
| `trivy config --severity HIGH,CRITICAL --exit-code 1 /repo` | 0 | One Dockerfile detected; zero high/critical misconfigurations |

## Secret scanning

Gitleaks output was redacted. Version 8.30.1 was obtained from the official Gitleaks GHCR image and pinned by the registry digest shown above.

- Current source scan: exit 0, no leaks in `ChiNeScan`, `tests`, `docs`, `.github`, `docker`, `migrations`, `schemas`, `configs`, or the root manifest/config/document files. Generated `.venv` and `.git` directories were excluded from this source scan.
- Git history scan: `gitleaks git --log-opts=--all`, exit 0, two commits scanned, no leaks. The security candidate is uncommitted, so it is covered by the source scan rather than the history scan.
- Pre-commit recheck: the approved candidate's `.github`, `chinescan/core`, `docker`, deployment/validation documents, `migrations`, `pyproject.toml`, both changed unit-test files, and `uv.lock` were each rescanned with the same pinned Gitleaks 8.30.1 image; all passed with no leaks. A fresh Git-history scan from the primary worktree also passed: two commits, no leaks.
- A Docker-mounted linked worktree cannot resolve its Windows `.git` pointer from inside Linux. That attempt scanned zero commits and is not counted as a pass; the history scan was rerun from the primary worktree with valid repository metadata.

## Image vulnerability scan

The exact `chinescan:security-only` image (image ID `sha256:0d3ef470e1448dfea13fc55468934411e2cc8983eea4ccc753a8622cbb770d9d`) was exported with `docker save` and scanned from that tar input using Trivy 0.76.1 with vulnerability scanning only. A fresh full-report JSON scan on 2026-10-25 exited 0 and found 44 High Debian OS package findings: 43 `affected` and one `fix_deferred`; none has a fixed version reported. It found no Critical or Python library findings. The vulnerability database was freshly downloaded on 2026-10-25. The grouped advisory and affected-package list is:

| Advisory | Severity / status | Affected Debian packages | Fixed version reported |
| --- | --- | --- | --- |
| CVE-2025-69720 | High / affected | `libncursesw6`, `libtinfo6`, `ncurses-base`, `ncurses-bin` | None |
| CVE-2026-16742 | High / affected | `libsystemd0`, `libudev1` | None |
| CVE-2026-54369 | High / affected | `libacl1` | None |
| CVE-2026-76642 | High / affected | `bsdutils`, `libblkid1`, `liblastlog2-2`, `libmount1`, `libsmartcols1`, `libuuid1`, `login`, `mount`, `util-linux` | None |
| CVE-2026-78408 | High / affected | `bsdutils`, `libblkid1`, `liblastlog2-2`, `libmount1`, `libsmartcols1`, `libuuid1`, `login`, `mount`, `util-linux` | None |
| CVE-2026-78409 | High / affected | `bsdutils`, `libblkid1`, `liblastlog2-2`, `libmount1`, `libsmartcols1`, `libuuid1`, `login`, `mount`, `util-linux` | None |
| CVE-2026-78410 | High / affected | `bsdutils`, `libblkid1`, `liblastlog2-2`, `libmount1`, `libsmartcols1`, `libuuid1`, `login`, `mount`, `util-linux` | None |
| CVE-2026-9538 | High / fix_deferred | `perl-base` | None |

These are package/advisory pairs, so the table groups 44 findings under eight advisory identifiers. The reported absence of a fixed version does not mean the findings are harmless. The workflow reports all findings and gates on fixable High/Critical findings with `--ignore-unfixed`; that gate exited 0. No findings were suppressed or relabeled.

Trivy config scanning detected one file (`docker/Dockerfile`) and found zero High/Critical misconfigurations. Compose was separately syntax-validated above; Trivy did not detect the Compose file as a configuration target.

## GitHub state after the approved visibility change

Repository API confirmed `CipherChi/Chinescan` is private, `has_pages` is false, and the Pages endpoint returns 404. There is no root `CNAME` file. No Pages/custom-domain deployment is configured.

GitHub's documented public-to-private behavior erases the repository's stars and watchers and leaves any existing public forks public but detached into a separate network. The repository API now reports zero stars, watchers, subscribers, and forks. I did not capture the pre-change counts, so I cannot say whether there were stars/watchers/forks before the change; I did not delete forks or alter collaborator access.

- Secret scanning and repository push protection are disabled for the private repository; the secret-scanning API reports that the feature is disabled.
- Dependabot alerts are disabled. The API reports this state; GitHub documentation lists Dependabot alerts/security updates as available across plans, so the proposal is to enable both after approval. Weekly version updates for `pip` and GitHub Actions are configured in the candidate `.github/dependabot.yml`.
- `main` has no branch protection. The protection API says this private-repository feature requires GitHub Pro or a higher plan. No upgrade or purchase was made.
- GitHub code scanning is unavailable for private repositories on Free/Pro; GitHub documents it for private repositories with Team/Enterprise and GitHub Code Security. Independent Gitleaks, Trivy, pip-audit, and Bandit checks remain in the candidate CI workflow.
- The private vulnerability reporting endpoint returned 404. The existing `SECURITY.md` only says to contact project maintainers and supplies no address or reporting link; no contact or route was invented.
- Existing GitHub run `40195117001` is for the base commit: `quality` succeeded and `container` failed in its old wheel build step. The candidate workflow's proposed check names are `quality`, `secret scan`, and `container`; they cannot be verified as remote checks until this branch is pushed and run.

## Remote validation and limits

- At the time of the initial isolated validation, no commit, push, pull request, or GitHub Actions run had occurred. The candidate was later committed as `e27449fdc24016813223977cd5e57b2ded17ae83` and opened as PR [#1](https://github.com/CipherChi/Chinescan/pull/1).
- The PR update triggered GitHub Actions run [40228513966](https://github.com/CipherChi/Chinescan/actions/runs/40228513966) for that commit. `quality` passed; `container` passed, including the Docker build, Trivy configuration scan, vulnerability report (44 High, 0 Critical), and fixable-finding gate; `secret scan` failed during `go install` because the requested module path did not match the module path declared by Gitleaks v8.30.1. The subsequent Gitleaks scan step was skipped and did not execute. These GitHub results are separate from the successful local Gitleaks source and two-commit history scans recorded above.
- The failing installation command used `github.com/gitleaks/gitleaks/v8@v8.30.1`; Go reported that the module declares `github.com/zricethezav/gitleaks/v8`. The approved correction to that module path was verified locally with Go 1.25.0 and completed `go install` successfully. No GitHub rerun has occurred at this report's commit point.
- Existing GitHub run `40195117001` is the earlier base-commit run; `quality` succeeded and its old Docker build failed because it renamed the wheel file. The candidate Docker build and container smoke check pass locally.
- Production deployment remains disabled. [DEPLOYMENT.md](../DEPLOYMENT.md) lists the infrastructure details required before a CD workflow can be configured.
- This validation excludes preserved Phase 2–4 implementations. Two fixes in those feature files—the external-scanner environment allowlist and CSV formula neutralization—are deferred with their implementations/tests rather than imported without the phase work.
