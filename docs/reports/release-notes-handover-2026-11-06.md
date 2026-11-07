# ChiNeScan release notes — handover snapshot, 2026-11-06

**Status:** prepared for review; unpublished, untagged, and based on an uncommitted working-tree
snapshot. Its identity is the base commit plus
[the release snapshot manifest](release-snapshot-manifest-2026-11-06.json), not the base commit
alone.

## What changed

- Narrowed built-in source-pattern candidates for dynamic SQL, JWT `alg=none`, public client
  configuration names, headers, cookies, and rate-limit handlers. Several rules now use
  same-file/context checks and safer parameter-binding recognition to reduce common false
  positives. These are still static text heuristics without full AST, taint, or cross-file analysis.
- Added versioned evidence explanations that distinguish observed matches from inference, describe
  prerequisites and conditional impact, and provide false-positive considerations and verification
  steps. Severity is potential impact under the static classification policy; it is not an
  exploitability verdict. Confidence categories are not calibrated probabilities.
- Preserved the legacy code-pattern score arithmetic while exposing the contributing signals,
  counts, weights, adjustments, and redacted evidence. This score is not an AI-authorship
  determination. Legacy scores without a stored ledger remain unavailable.
- Contract-tested representative scan fields across CLI, authenticated API, complete reports, and
  dashboard views. Preview/dashboard metadata now separates stored, available, grouped, returned,
  omitted, filtered, and failed results where known. Unknown legacy totals remain unknown.
- Refreshed the dashboard while preserving existing workspaces, added persistent ambient-motion
  controls and reduced-motion support, bounded displayed finding links, and improved readiness
  endpoint outcome reporting. The historical readiness timeout cause remains unresolved. The
  Windows start helper now uses the project `uv` environment and rejects a backend port that would
  disagree with Vite's fixed proxy target.
- Completed R1 redaction remediation: forward delimiter scanning replaces repeated expensive
  matching; imported text is clipped before redaction; documented per-operation bounds fail
  closed; synthetic canary tests cover CLI/API failure output.
- Kept `full-json` bounded at 10,000 findings and 20 MiB. Added a distinct streamed JSONL retrieval
  format for larger retained scans. It batches records, redacts each record, and ends with a count
  and SHA-256 completion record. An output without valid completion evidence is incomplete.

## Supported profile and security assumptions

The validated profile is local, single-operator use with the built-in scanner, a local SQLite
database, and an explicitly started loopback dashboard. Scanned application code is not executed.
Domain posture checks require explicit authorization. Malware handling is static triage, not
detonation or an OS sandbox. Authenticated application routes protect scans, cases, evidence,
reports, and job controls. Redaction and resource bounds reduce exposure and exhaustion risk but do
not establish that all sensitive formats or hostile inputs are harmless. The security review is not
a penetration test or a proof that the application is vulnerability-free.

## Optional integrations and known limitations

Semgrep, Gitleaks, Trivy, YARA, and ClamAV are not enabled or verified in this handover
environment. Their real local integration tests require the executable and, for Trivy/ClamAV,
already-local database/signatures. No scanners were installed and no databases or signatures were
downloaded. Fixture-based adapter tests are not real integration results.

Remote and multi-user deployment is unsupported. The app remains loopback-bound and single
operator, with process-local state and no tenant isolation. The historical readiness-timeout cause
is unknown because its trace and server timing evidence are unavailable. No load test, formal
regex-complexity proof, exhaustive accessibility audit, or penetration test is claimed. Legacy
records may lack explanations or contribution ledgers; full JSON remains bounded; JSONL reads the
scan ID list at the start and fetches record batches as it proceeds, rather than providing a
whole-database transaction snapshot.

## Compatibility and upgrade notes

The lowercase `chinescan` package/CLI identifiers, existing JSON full-export format, API route
family, and SQLite payload compatibility are retained. JSONL is a new format and is not a single
JSON object. Follow the documented local upgrade process: back up and verify the local database,
test the candidate against a copy, and preserve the previous working database until the upgrade is
confirmed. No deployment or production migration was performed for this handover.
