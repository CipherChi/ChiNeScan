# API security hardening report

Audit performed on branch `hardening/api-security`. `.env` files and secret values were
not opened, printed, or logged.

| Feature | Status | What changed / audit result | Tests added or inspected | Known gaps |
| --- | --- | --- | --- | --- |
| F1 SQL injection | APPLY | SQLAlchemy expressions, bound values, and per-record field allowlists are covered with attack strings in path IDs, scanner/search-like filters, sort, and severity filters. | `test_sql_injection_inputs_cannot_change_record_queries` checks both payloads and unchanged row counts. | Search is represented by the supported scanner/list filter because no free-text search parameter exists. |
| F2 unsafe deserialization | APPLY | Handles JSON/TOML recursion errors; config files are capped at 1 MiB. No unsafe deserializers or `shell=True` found. YAML rules use `safe_load_all`. | `test_parser_hardening.py`: 7 tests for malicious YAML, 10,000-level JSON/TOML, and oversized indicator/log/chain/config inputs. | Format-specific domain validation remains the parser contract; this does not add a universal YAML parser. |
| F3 request filtering / mass assignment | APPLY | Every mutating route with a request model was inventoried; each model rejects `role`, `is_admin`, `permissions`, and `owner_id`. | `test_mutating_body_models_reject_privileged_fields_from_route_inventory` checks models and submits each field to every body-bearing write route, asserting `extra_forbidden` and unchanged record count. | Bodyless write routes have no writable request schema and are checked to reject unauthenticated/no-CSRF submissions. The initial failure was test introspection: FastAPI exposes a body parameter's annotation through `ModelField.field_info.annotation`; the test looked at nonexistent `.annotation`/`.type_` fields and incorrectly concluded the route had no model. |
| F4 response filtering / sensitive data | APPLY | Shared redaction, path-free models, and safe error logging are verified across the GET route inventory. | `test_get_routes_do_not_expose_settings_or_credential_secrets` seeds a settings/password sentinel and checks all GET bodies plus captured logs for the sentinel and Argon2 hash pattern. | Every GET route is exercised with placeholder path IDs; not every route can return a populated object in this fixture. |
| F5 XSS / output encoding | APPLY | HTML/Markdown escaping verified; React title text remains inert; API-built local links pass through `safeLocalUrl`; security headers cover API and download responses. | `test_render_all_formats_redacts_and_escapes`, `test_security_headers_are_present_on_api_and_downloads`, App Vitest title test, and `api.test.ts` scheme rejection tests. | `safeLocalUrl` only accepts same-origin local paths by design. |
| F6 authentication | APPLY | Configurable 10-minute idle and 30-minute absolute session expiry; account/IP lockout and generic errors verified; optional TOTP supports local enrollment (10-minute expiry), single-use/replay rejection, hashed recovery codes, and verification rate limiting. | `test_session_idle_and_absolute_expiry_use_independent_fake_clock`, `test_session_lifetime_settings_have_ten_minute_idle_default`, `test_successful_login_resets_backoff_and_failures_are_generic`, and `tests/unit/test_totp.py`. | TOTP remains opt-in; seed is shown only by the local CLI during enrollment. |
| F7 rate limiting | APPLY | Added configurable auth/job-start/export/read limits; bounded in-process sliding windows; 429 `Retry-After` and `{detail:{code,message}}`; forwarded IP is used only with `trusted_proxy=true`. | `test_rate_limit.py` covers hit/reset, bounded buckets, 429 shape, and forwarded-IP trust; existing auth-hardening suite passes with default limits. | Limits are per process; deployments with multiple workers need proxy-side limits as documented. |
| F8 authorization / IDOR | APPLY | Route inventory verifies session protection and CSRF rejection; typed record ID and traversal behavior are tested. | `test_route_security_inventory.py` covers all GET/WRITE API routes, chain and v1 aliases, wrong record type, and report/filesystem traversal. | A future multi-user model still requires owner fields and per-object checks. |
| F9 gateway / routing / versioning | APPLY | `/api/v1/*` aliases `/api/*`; version header and versioning/deployment policy are documented. Gateway and JWT replacement are not applicable. | `test_v1_api_alias_uses_existing_auth_and_reports_version` verifies the 401 parity and rejects `/api/v2`. | Authenticated payload parity is not separately asserted. |

F9 gateway and JWT replacement are NOT-APPLICABLE: ChineScan is a single local operator
application with server-side revocable cookie sessions and no downstream services to protect.
The deployment example is documentation only; it does not change the loopback default.

Multi-user support would require an owner field on each object plus per-object ownership checks
on every read, write, export, and job-control route before adding additional accounts.

## Final verification

| Command | Result |
| --- | --- |
| `ruff check .` | PASS — `All checks passed!` |
| `mypy --strict chinescan` | PASS — `Success: no issues found in 84 source files` |
| `py -3.12 -m pytest -q --run-real-scanners --basetemp=C:\t-final` | PASS — `592 passed, 5 skipped, 0 deselected, 3 warnings in 275.36s` |
| `npm run typecheck` (`frontend/`) | PASS |
| `npm test -- --run` (`frontend/`) | PASS — 12 files, 57 tests |
| `npm test -- --run src/ui/ProjectsWorkspace.test.tsx` (`frontend/`) | Not rerun in isolation; full Vitest passed all 57 tests. |

The earlier backend command was `py -3.12 -m pytest -q --basetemp=C:\t` (from the previous
pass). It omitted `--run-real-scanners`; `tests/conftest.py` therefore deselected every test
marked `real_scanner`. `pyproject.toml` sets only `--strict-markers` in `addopts`; it has no
other selection rule. In the final run, all five were collected and each skipped at the
availability guard because the executable was not installed or on PATH:

| Skipped test | Reason |
| --- | --- |
| `test_semgrep_real_local_positive_negative_persistence_and_report` | Semgrep executable unavailable. |
| `test_gitleaks_real_local_positive_negative_persistence_and_redaction` | Gitleaks executable unavailable. |
| `test_trivy_real_offline_local_database_positive_negative_and_persistence` | Trivy executable unavailable. |
| `test_yara_real_local_positive_and_negative` | YARA executable unavailable. |
| `test_clamav_real_local_clean_fixture` | ClamAV `clamscan` executable unavailable. |

No tests were deselected in the final run. T3 and T6 now pass; TOTP remains optional and off by
default. No changes were made to `phase-1-report.md`.
