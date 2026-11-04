# Local dashboard API

The API is served by `chinescan web serve` on loopback only. OpenAPI and interactive docs are
disabled in this stage; response models are declared in `chinescan/web/app.py` and the stable
JSON contract is summarized here. Public authentication routes are loopback and same-origin
guarded. Protected routes require the `chinescan_session` HttpOnly cookie, which maps to an
in-memory session. Authenticated POSTs also require `X-CSRF-Token` returned by login/session. API
responses use `Cache-Control: private, no-store`.

## Authentication

| Method and path | Access | Contract |
| --- | --- | --- |
| `POST /api/auth/signup` | Public, loopback and same-origin guarded | JSON body `{ "email": string, "password": string }`; email is trimmed and lowercased; password minimum is 12 characters. Creates the single local Argon2id operator only when no credential file exists, returns `{ "email": string, "csrf_token": string }`, and sets an HttpOnly SameSite=Strict cookie. Existing accounts return a generic 409 conflict. |
| `POST /api/auth/login` | Public, loopback and same-origin guarded | JSON body `{ "email": string, "password": string }`; returns `{ "email": string, "csrf_token": string }` and sets an HttpOnly SameSite=Strict cookie. Failures are generic and rate limited. |
| `POST /api/auth/forgot-password` | Public, loopback and same-origin guarded | JSON body `{ "email": string }`; returns the same generic 202 response whether or not the account exists. The UI directs the operator to the local `web reset-password` command, which displays the one-time token only in the local terminal. |
| `POST /api/auth/reset-password` | Public, loopback and same-origin guarded | JSON body `{ "email": string, "token": string, "password": string }`; accepts only a matching, unexpired, single-use token. Password minimum is 12 characters. Success replaces the Argon2id hash and invalidates sessions. |
| `GET /api/auth/session` | Authenticated | Returns the operator email and CSRF token. |
| `POST /api/auth/logout` | Authenticated + CSRF | Revokes the active session and clears its cookie. |

Reset tokens contain 256 bits of random entropy, are stored only as SHA-256 digests, expire after
15 minutes, and are invalidated when used or replaced by another local reset request. Repeated CLI
requests are rate limited to one per minute. Password reset invalidates sessions in the current
process and changes the credential authorization epoch so sessions in other running processes are
rejected on their next request. No SMTP service is used.

## Persisted records

| Method and path | Access | Response |
| --- | --- | --- |
| `GET /api/overview` | Authenticated | Stored scan/finding counts, persisted finding counts grouped by severity, and up to five recent scan summaries. |
| `GET /api/scans` | Authenticated | `{ items: ScanSummary[], total, limit, offset }`; `limit` is 1–100 (default 25), `offset` is 0–100000. `status` supports `complete`, `partial`, `failed`, or `running`; `scanner` is at most 100 characters. `sort` allows `started_at`, `status`, or `scanner`; `order` allows `asc` or `desc`. |
| `GET /api/scans/{scan_id}` | Authenticated | A path-free `ScanSummary` plus linked stable `finding_ids`. |
| `GET /api/findings` | Authenticated | `{ items: FindingSummary[], total, limit, offset }`; pagination bounds match scans. `severity` must be one of `critical`, `high`, `medium`, `low`, or `info`; `category` is at most 80 characters; `scanner` is at most 100 characters. `sort` allows `severity`, `title`, `scanner`, or `category`; severity ordering follows critical, high, medium, low, info. `order` allows `asc` or `desc`. |
| `GET /api/findings/{finding_id}` | Authenticated | A reviewed `FindingDetail` schema with redacted description/location text, never a raw persisted payload. |

All unknown sort fields, unsupported severity/status values, oversized bodies, invalid page bounds,
cross-origin requests, and non-loopback Host/client values are rejected. The API does not accept
filesystem paths in requests, malware intake, domain assessment, database selection, restore, or
deletion routes.

## Local log-analysis jobs

The operator configures local sources outside the browser in `~/.config/chinescan/log-sources.toml`
or supplies `chinescan web serve --log-sources-file PATH`. The browser sends only a `source_id`.
Every route below requires the authenticated session; job creation also requires same-origin and
CSRF validation.

| Method and path | Contract |
| --- | --- |
| `GET /api/log/sources` | Available configured source IDs and display names only. Unsafe, missing, protected, or invalid roots are omitted. |
| `POST /api/log/jobs` | `{source_id}` starts bounded local analysis; unknown/unavailable source is `422`, full queue is `429`. Additional request fields are rejected. |
| `GET /api/log/jobs` | Persisted jobs, bounded `limit` 1–100 and `offset` 0–100000. States: `queued`, `running`, `succeeded`, `partial`, `failed`, `interrupted`. |
| `GET /api/log/jobs/{job_id}` | Persisted state, sanitized error, counts, and optional actual result `scan_id`. |
| `GET /api/log/analyses/{scan_id}/alerts` | Alerts belonging to that persisted log scan; optional validated `severity`; bounded pagination. |
| `GET /api/log/analyses/{scan_id}/alerts/{alert_id}` | Reviewed, redacted alert detail. The ID must belong to the given log scan. |
| `GET /api/log/analyses/{scan_id}/events` | Events belonging to that persisted log scan; optional bounded `source` filter; bounded pagination. Raw references and full paths are omitted. |
| `GET /api/log/analyses/{scan_id}/events/{event_id}` | Reviewed event detail. The ID must belong to the given log scan. |
| `GET /api/log/analyses/{scan_id}/timeline` | Persisted source timeline entries with bounded pagination. |

Log-source TOML is operator-controlled. Each source has `id`, `name`, and absolute `root`; optional
`rules` points to a local Sigma rules directory and optional `iocs` to a local IOC list. Paths are
validated against the active database directory, credentials, and registry files. Symlinks and
Windows junctions within the selected tree are rejected where detected. Ingestion is read-only and
uses existing limits: up to 10,000 files, 25 MB per file, 250 MB aggregate input/expanded data,
1,000 archive members, 100 MB per archive, and 100,000 events. Archives are never extracted.
The single worker allows one active job and four waiting jobs. Partial jobs retain available results
but are explicitly marked `partial` and include an error count; they must not be interpreted as a
complete analysis. Restart reconciliation marks unfinished jobs `interrupted`. There is no cancellation
or hard wall-clock deadline. The filesystem can change after validation, so this is not OS sandboxing.

Log alerts are candidate detections. Built-in rules are limited heuristics. The Sigma evaluator
uses safe YAML loading and supports normalized field aliases, case-insensitive glob matching,
`contains`, `startswith`, and `endswith`, optional `all` value matching, Boolean `and`/`or`/`not`,
parentheses, and `all`/`any`/`1 of` selector patterns. It does not support the full Sigma specification,
timeframes, pipelines, or arbitrary executable logic. Rule/selector work is
bounded, and unsupported conditions produce diagnostics that make the scan partial. There are no
network collectors, enrichment requests, or uploads.

## Approved local code-assessment jobs (Slice 3A)

Projects come from the operator-controlled TOML registry described in [Project operations](PROJECTS.md).
The browser submits only a project ID. Jobs use the existing `CodeScanService` with the built-in
scanner; request bodies reject additional fields. External scanners and network-backed dependency
checks cannot be selected through this API.

| Method and path | Access | Contract |
| --- | --- | --- |
| `GET /api/code/projects` | Authenticated | Approved project IDs and display names only; unavailable or invalid roots are omitted. |
| `POST /api/code/jobs` | Authenticated + CSRF | `{project_id}`; returns `202` with a queued job. Unknown/unavailable project is `422`, duplicate active project is `409`, full queue is `429`. |
| `GET /api/code/jobs` | Authenticated | Bounded page (`limit` 1–100, `offset` 0–100000) of persisted job summaries. |
| `GET /api/code/jobs/{job_id}` | Authenticated | Persisted status, timestamps, optional actual `scan_id`, and sanitized error. |

States are `queued`, `running`, and terminal `succeeded`, `failed`, or `interrupted`. Creation sets
`created_at`; transition to running sets `started_at`; any terminal transition sets `finished_at`.
On startup, previous queued/running jobs become `interrupted`; that records application state and
does not establish that any OS process was terminated. One job runs at a time, with four waiting
slots. There is no cancellation endpoint. Built-in synchronous scanning rejects a project containing
a source file over 1 MB, more than 20,000 source files, or more than 250 MB of source data; queue
bounds, concurrency, and input bounds do not impose an execution deadline. Shutdown waits for an
in-flight scan; an abrupt process loss is reconciled next start. Filesystem validation rejects
symbolic links and Windows junctions found during the preflight walk where supported, and the
scanner itself does not follow directory links and skips symlink files. A change between preflight
and file open remains a filesystem race; this is not an OS sandbox. The active database directory
(including SQLite sidecars), operator credential, and project-registry paths are excluded
automatically. Operator-selected backup or report directories can also be listed in the registry's
`protected_paths`; this dashboard has no managed backup/export directory and report downloads are
generated in memory. Raw scanner logs and source text are not sent to the browser.

## Public GitHub imports (Phase 6C)

Public imports remain disabled unless `github_import_enabled = true` is set in local configuration.
Preview makes no network request; importing requires a separate explicit request with a valid
session-bound preview. The service uses a short `gh` subdirectory under the configured data
directory, rejects Windows checkout paths that exceed its conservative MAX_PATH budget before Git
starts, and returns `path_too_long` with the safe message “The import location path is too long; use
a shorter managed import directory.” Git filename-length errors use the same code. The CLI's
`github preview|import|status|cancel` commands print stable error codes and safe messages to stderr
(or JSON with `--json`) and exit with status 2 on failure. `chinescan doctor` and
`GET /api/diagnostics` report the import-path budget as `ok` or `at-risk` without revealing any
path; the import check is WARN for an at-risk path only while imports are enabled.

| Method and path | Access | Contract |
| --- | --- | --- |
| `POST /api/github/previews` | Authenticated + CSRF + same-origin | `{url, ref?}`; validates a public GitHub URL and returns a session-bound preview and configured caps, without network access. |
| `POST /api/github/imports` | Authenticated + CSRF + same-origin | `{preview_id, name}`; consumes a preview once and returns `202` with a queued job. |
| `GET /api/github/imports/{job_id}` | Authenticated | Session-owned job status, phase, safe message/code, and verified metadata on success. |
| `POST /api/github/imports/{job_id}/cancel` | Authenticated + CSRF + same-origin | Requests cancellation of a session-owned job. |

Job failures use stable codes including `path_too_long`, `unsafe_entries`, `quota_exceeded`,
`repo_not_found_or_private`, and `network_unreachable`. `path_too_long` means the configured managed
import location leaves insufficient room for a safe checkout path; shorten the configured data
directory and retry. It is distinct from `unsafe_entries`, which indicates a repository entry
violated a file-system safety rule.

## Cases and report downloads (Slice 2)

Every case route requires an authenticated session. Case creation, status changes, notes, and links
also require the same-origin `Origin` check and current `X-CSRF-Token` as logout.

| Method and path | Contract |
| --- | --- |
| `GET /api/cases` | Bounded page (`limit` 1–100, `offset` 0–100000), filters `status` and `severity`, sorts `created_at`, `updated_at`, `status`, `severity`, `title`, and `order=asc|desc`. Returns persisted case summaries with total/page metadata. |
| `POST /api/cases` | `{scan_id, title?, description?, severity?}` creates through `CaseWorkflow.create_from_scan`; title is at most 200 characters, description 8000, and severity is an enumerated value. The scan must already be persisted. |
| `GET /api/cases/{case_id}` | Case status, severity, notes, validated persisted link metadata, reviewed linked-record summaries, chronological activity/source timeline, warnings, and severity counts. Evidence is text and passed through shared redaction. |
| `POST /api/cases/{case_id}/status` | `{status}` uses the workflow transition table. Closed cases cannot transition further. |
| `POST /api/cases/{case_id}/notes` | `{body}` appends a note (1–8000 characters). The authenticated operator is not written into the legacy unverified author-label field. Notes are not editable or deleted through the API. |
| `POST /api/cases/{case_id}/links` | `{record_type, record_id}` validates supported persisted records through `CaseWorkflow`; repeating an existing link is idempotent. Supported malware types are `malware_sample` (stable identity) and `malware_analysis` (one result). |
| `GET /api/cases/{case_id}/report/{json|markdown|html}` | Generates a redacted report in memory, capped at 2 MB, and returns it as an attachment. HTML uses `Content-Disposition: attachment` and is not rendered inline. |
| `GET /api/scans/{scan_id}/report/{json|markdown|html|csv|sarif}` | Uses the existing scan report renderer and formats. The report is a download attachment with a server-chosen filename. |

Case report generation rejects cases above configured link/note/activity limits; scan exports reject
more than 10,000 findings. All IDs are opaque record IDs, never paths. Unsupported format segments
are rejected by route validation. Case persistence still uses the existing JSON payload schema and
does not add SQL foreign keys. Missing legacy references remain warnings. No artifacts or
backup/restore controls are exposed.

## Malware dashboard (Stage B2)

All malware routes require the same authenticated local session, loopback/Host guard, body bounds,
and same-origin policy as the rest of the dashboard. Mutating job and case-link requests require
`X-CSRF-Token`. The API accepts operator registry IDs or persisted managed sample IDs only. Unknown
request keys are rejected; paths, object keys, executable names, scanner arguments, and environment
values are never accepted from the browser.

| Method and path | Contract |
| --- | --- |
| `GET /api/malware/capability` | Whether execution is supported, a bounded diagnostic, and whether persisted historical views are available. |
| `GET /api/malware/samples` | Operator registry entries and persisted sample identities; states distinguish `registered` (not ingested), `managed`, and `unavailable`. No original path or managed key is returned. An un-ingested entry has no verified hash. |
| `GET /api/malware/samples/{sample_id}` | Reviewed persisted identity metadata only. |
| `POST /api/malware/jobs` | `{"registry_id":"...","profile":"builtin_static"}` ingests an approved entry and queues it, or `{"sample_id":"...","profile":"builtin_static"}` reuses an available managed identity. Exactly one ID is required. Returns `202`; queue full is `429`, unsupported execution is `503`, invalid/unavailable ID is `422`. Duplicate active submissions for the same managed identity are `409`. |
| `GET /api/malware/jobs` | Bounded page (`limit` 1–100, `offset` 0–100000) with job state, timestamps, linked analysis ID, and separate analysis completeness. |
| `GET /api/malware/jobs/{job_id}` | Persisted job state and linked analysis completeness. Job `succeeded` does not imply analysis `complete`. |
| `GET /api/malware/analyses/{analysis_id}` | Allowlisted hashes, actual byte count/type, architecture, bounded candidate indicators, warning list, and YARA/ClamAV availability/verification states. Values are inert text; no external links are created. |

The service uses one application-owned queue thread, but analysis runs only in the fixed child worker
after Windows Job Object assignment and queried-limit verification. One job is active and four may
wait. HTTP submission returns without waiting for analysis. Unsupported hosts keep historical views
available and disable execution; no thread-based or uncontained fallback exists. Shutdown stops new
submissions, waits through the worker's bounded deadline, records unfinished jobs as interrupted
where persistence remains available, and then closes the repository. Restart reconciliation marks
stale queued/running work interrupted and preserves jobs owned by another live manager. No user
cancellation is provided. There is no sample-byte or object-key serving endpoint.

The built-in worker runs only on Windows and only after Job Object setup, assignment, and limits are
verified. This limits worker process-tree resources and lifetime but does not isolate filesystem or
network access; it is not an OS sandbox. Registry/path checks retain filesystem race limitations.
YARA and ClamAV remain unrequested, uninstalled/unverified by this profile; their status is visible
as `not_checked`/`not_run`, never as verified. SQLite backups include sample identity metadata and
persisted results but exclude managed sample bytes.

Analysis results can be linked independently from sample identities. Case JSON, Markdown, and HTML
reports include reviewed malware metadata and completeness, redact secrets, and omit sample bytes,
source paths, managed keys, arbitrary printable strings, archive names, and raw worker output. Scan
report formats and SARIF remain unchanged. No migration was needed: case links and malware records
use the existing generic typed-record store; backup verification now validates sample/analysis/job
relationships.

## Session and transport limits

## On-chain tracing API

Authenticated operators can list `/api/chain/chains`, submit `/api/chain/jobs` with CSRF protection, poll `/api/chain/jobs` and `/api/chain/jobs/{job_id}`, and read `/api/chain/traces/{scan_id}/graph`. A create request accepts `address`, `chain`, `depth` (1–6), non-negative decimal `min_amount`, and `allow_network`; it may include `import_text` with `import_format` of `csv` or `json`. Import text is capped at 2 MB. Invalid chain addresses and depths return 422; disabled network opt-in returns 403 with code `chain_network_disabled`. Network traces require both request opt-in and the server's `chain_network_enabled` setting; offline imports need neither.

Graph JSON contains `scan_id`, `chain`, `nodes` (`address`, hop `depth`, optional provenance-bearing `label`), `edges` (transaction hash, time, endpoints, asset, amount, and kind), and `findings` (finding identifiers and evidence references). Graph exports are available as `graph-json`, `graphml`, `transfers-csv`, and `indicators`. Etherscan-family chains use API V2 at `https://api.etherscan.io/v2/api`, sending the configured numeric `chainid`; built-ins are Ethereum (1), BNB Smart Chain (56), Polygon (137), Arbitrum (42161), Optimism (10), Base (8453), and Avalanche (43114). Operator TOML chain entries may set `chain_id` for another EVM network while reusing the same V2 endpoint. The Etherscan adapter allows the built-in `api.etherscan.io` host; custom registry endpoints require an explicit host allowlist, HTTPS, public DNS addresses, no user information, and port 443 unless configured otherwise. DNS resolution has a bounded 2 second wait, revalidates every result before connecting, and pins the validated address. Redirects are limited to two HTTPS redirects on the same host. Each trace has a 120 second deadline, a 100 request cap, a 2 MB response cap, and a 500 address cap by default; settings may lower or raise these within validated limits. Hitting a cap marks the scan partial and records a coverage gap. The transport does not use environment proxies. Etherscan keys are read only from the configured environment variable and sent in the POST body; they are never placed in the URL. Responses, persisted records, diagnostics, and logs expose only whether a key is configured. Provider gaps include `rate_limited`, `invalid_api_key`, and `provider_error` with a short redacted reason, as well as timeout, endpoint rejection, malformed response, and unsupported online family codes. “No transactions found” is treated as an empty result. Findings are investigative leads, not proof of ownership or attribution.

`GET /api/diagnostics` and `chinescan doctor --json` include `chain_network_enabled` and the boolean `chain_provider_key_configured`. Offline readiness remains passing while network tracing is disabled; enabled network tracing without a key is reported as a warning.

Sessions expire after 30 minutes and are held only in process memory. Logout revokes the current
session; a process restart discards all sessions. Run one application worker. The included server
uses plain HTTP with `Secure` cookies disabled. Setting `Secure` on an HTTP cookie would prevent
normal browsers from sending it. HTTPS termination and trusted proxy headers are not configured.
# API versioning and transport headers

`/api/v1/*` is an alias for the corresponding `/api/*` route. Both prefixes use the
same cookie session, CSRF, authorization, and in-process throttles. Existing `/api/*`
paths remain supported. Responses include `X-API-Version: 1`; standard security headers
include CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and
`Referrer-Policy: no-referrer`. API responses are private and non-cacheable.

Changes within v1 are additive. Breaking request or response changes require `/api/v2`.
When a route is deprecated, responses will include `Deprecation` and `Sunset` headers
with a published removal date. Rate-limit failures use HTTP 429, a `Retry-After` header,
and the usual `{"detail":{"code":"...","message":"..."}}` error form where the
limiter generates the response. Authentication lockouts return a generic response and
apply a temporary increasing delay to the operator account and client address.

