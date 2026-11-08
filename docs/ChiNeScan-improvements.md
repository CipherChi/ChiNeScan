# ChiNeScan improvement notes

The dashboard presents the product as **ChiNeScan**. Python imports, the installed
`chinescan` command, SQLite record format, and `/api` plus `/api/v1` routes remain
unchanged for compatibility.

## Built-in rule behavior

The built-in rules remain local text heuristics. `builtin-2` adds a constrained SQL
candidate check: a recognized database method (`query`, `execute`, `raw`, or an
unsafe Prisma raw method) must appear with SQL statement text and direct interpolation
or concatenation. It ignores comments and ordinary quoted strings and accepts common
bound placeholders with a separate parameter argument. A Prisma `$queryRaw` tagged
template with interpolation is considered a candidate. It still does not build a
language AST, trace tainted values across functions/files, resolve custom database
wrappers, or execute a query. Input provenance is recorded only as a request-like
identifier in the same query arguments, which is not taint proof. SQL candidates are
`POSSIBLE`; rule severity remains a potential impact label, not a verified exploit
rating.

`NEXT-PUBLIC-SECRET` now reports a medium, possible review candidate based on the
public prefix and a sensitive-looking suffix. It does not infer privilege from the
name and does not universally trust a provider. The report cannot verify provider
permissions, access policies, production configuration, or emitted bundles. A
client-component secret-like name is a possible candidate; actual bundle inclusion
is not tested. When both rules match the same variable on the same source line, the
finding retains both contributing rule IDs as one record.

The missing-header rule only runs for Next.js config and middleware files containing
a header configuration expression. It checks whether the familiar CSP, frame,
MIME-sniffing, and referrer names appear within that file. This does not establish
header values or effective deployment behavior. Rate-limit matching is constrained
to handler-shaped files and no longer treats arbitrary page text, links, metadata,
or redirects as a handler. It recognizes same-file limiter terms only; imported
middleware and hosted controls remain unresolved. Cookie checks inspect a literal
options object or a simple same-file object variable. Runtime defaults, multi-line
calls, imported helpers, cookie purpose, and browser policy are not comprehensively
modeled. Security-TODO deliberately scans comments; other built-in source rules mask
comments before matching.

## Finding explanations and compatibility

Finding records optionally contain `explanation` (version `1.0`),
`contributing_rule_ids`, and `evidence`. These fields are additive to schema 1.0 and
older SQLite payloads remain readable. Legacy findings render an explicit
“Explanation unavailable” state; no historical rationale is manufactured. New
built-in findings use `pattern_match` evidence. Explanation fields distinguish
observed text, established facts, inferences, static severity/configuration rationale,
heuristic confidence rationale, prerequisites, conditional impact, verification,
false-positive considerations, and analysis limits. For rules without a tailored
explanation, text states that the configured rule was matched and contextual
behavior was not verified.

The `CONFIRMED` enum remains for compatibility with other scanners, but this
built-in regex ruleset does not emit it based on a match. Confidence labels are
categories, not probabilities. Rule-level severity indicates potential impact and
does not automatically adjust to deployment context.

## Code pattern risk score

The existing arithmetic is preserved as `legacy-pattern-v1`; the score is presented
as **Code pattern risk**. The previous `vibe_coding_risk` record and summary score
remain compatibility aliases. The disclaimer that the score is not proof of AI
authorship remains.

For each file, each text signal counts at most once. Its contribution is
`weight × min(raw_file_count, 3)`. Weights are: placeholder credentials 20, leftover
TODO/production guidance 8, tutorial-style insecure default 18, mock/dummy data 8,
raw error returned 12, commented-out code 5, and client-side validation without a
server-action marker 8. A one-time 12 point bonus applies at four or more route
declarations when at least one base signal exists and no checked auth/schema/limiter
word occurs in the combined source. A one-time 6 point bonus applies when all three
request styles (`fetch`, `axios`, `apiRequest`) are found. The total is capped at 100.
There is no size normalization or finding-severity input. Score confidence remains
the historical signal-count threshold: zero signals is informational, fewer than
three is possible, and three or more is likely. This threshold is not calibrated.

The score now returns a contribution ledger including identifiers, descriptions,
raw/effective counts, weights, adjustments, contributions, and up to three redacted
source examples per capped signal. Bonus conditions and evidence are explicit.
There is no repository-rescan of prior scores; old persisted records without a
ledger display as legacy/unavailable.

## Reports, API, and dashboard

At this continuation baseline, the existing JSON report was a bounded preview with the legacy
`likely_real_issues` field and additive `classification_labels`. `full-json` returned the normalized
finding list within its 20 MiB and API 10,000-finding bounds. The subsequent release closure added
separate JSONL retrieval for retained findings above those bounds; see the closure-status section
below for the current retrieval contract.

Finding details now pass redacted excerpts, remediation, evidence kind, exposure,
CWE identifiers, explanation fields, and contributing rule IDs through an explicit
authenticated API schema. Finding titles/descriptions and excerpts are redacted
before transmission. The dashboard renders all source text as text, keeps a
truthful legacy explanation state, shows the score ledger and coverage limitations,
and offers preview and complete JSON exports. Its synthetic ambient terminal layer
contains no source or scan content; a persistent control disables it, it pauses while
the document is hidden, and reduced-motion preference disables animation. Existing
API routes, single-operator authorization model, and local-only assumptions remain.

## Remaining limits

No full AST/data-flow engine, cross-file control graph, provider credential
privilege checker, deployment-header observer, global rate-limit verifier, complete
cookie framework model, or client/server validation proof has been added. The
explanation fields expose these limits and avoid claiming those analyses occurred.
The dashboard is a restyle of the existing React application, not a replacement for
its existing functional workspaces. External scanner lifecycle, imported finding
verification, and broader product security require separate review and regression
coverage.

## Acceptance matrix — continuation baseline (2026-11-06)

| Requirement | Current implementation | Evidence | Remaining gap |
| --- | --- | --- | --- |
| Branding | **Implemented**, current UI/CLI/report labels now use ChiNeScan; lowercase technical identifiers remain | `frontend/src/ui/App.tsx`, `frontend/index.html`, `chinescan/core/reporting.py`; regression assertion in `frontend/src/ui/App.test.tsx` | One legacy localStorage preference key is read only to migrate the previous setting |
| SQL heuristic improvements | Implemented and covered by positive/negative fixture table | `chinescan/core/orchestration/code_rules.py`; `tests/unit/test_code_rules_behavior.py` | Heuristic only; no AST, taint propagation, or custom wrapper support |
| Public key and context heuristics | Partially implemented, tests cover names and overlap | Same rule module and behavior tests | No provider privilege/access-policy, deployment bundle, or comprehensive cross-file framework analysis |
| Versioned findings | Implemented; explanation includes classification policy version and evidence limits | `chinescan/core/models/finding.py`; detail/API tests | No calibrated confidence or context-driven severity service across external scanners |
| Classification policy | Partially implemented; documented static-impact policy; JWT `none` now high/possible instead of critical from text alone | `docs/ChiNeScan-improvements.md`; JWT rule and regression test | Other rule severities remain configured potential impact, not resolved exploitability; no central ruleset registry |
| Score auditability | Implemented ledger and corrected client-side validation wording | `vibe_risk` in `code_rules.py`; `tests/unit/test_code_rules_behavior.py`; human `detail` report | Old persisted scores without contributions remain legacy/unavailable; historical supplied score cannot be reconstructed without original inputs |
| CLI/API/dashboard/export consistency | **Implemented and contract-tested** for a deterministic shared fixture through persisted CLI detail/full JSON, authenticated API finding/scan/complete JSON, and dashboard API-shaped records | Shared fixture `frontend/src/test-fixtures/report-parity.json`; `test_scan_cli_api_and_complete_export_share_normalized_values`; dashboard parity test in `frontend/src/ui/App.test.tsx` | Tests cover representative fields, not every filter, pagination, unusual imported scanner payload, or export failure path; API remains single local operator, not multi-tenant |
| Export limits — continuation baseline (superseded) | At that baseline, API byte limit aligned with the 20 MiB complete-JSON bound and CLI/API shared the 10,000 finding cap | `MAX_COMPLETE_FINDINGS`, `MAX_COMPLETE_JSON_BYTES`, `MAX_SCAN_REPORT_*`; boundary API tests | This row's retrieval gap is superseded by the JSONL closure work below. Full JSON remains bounded; JSONL is streamed with bounded record batches and is not a whole-database transaction snapshot. |
| Dashboard | Real API data and current screens remain; successful/error export path and legacy states exist | `frontend/src/ui/App.tsx`; component tests | Not all loading, partial, mobile, reduced-motion, or export success flows have automated browser-level coverage; one local Chromium finding-detail test separately verified text rendering and redaction after its stale canary expectation was corrected |
| Product security | **Source/test review completed for applicable surfaces**, with statuses and limitations recorded in the review | `docs/ChiNeScan-security-review.md`; backend and frontend security regression tests; configured `pip-audit` check | Not a penetration test; no load/fuzz campaign, complete browser accessibility audit, exhaustive platform race analysis, or advisory check of the editable project distribution |

## Classification policy: `static-impact-v1`

- **Observed evidence** is a redacted source pattern or artifact, identified by `evidence=pattern_match` and a ruleset version. It describes what matched, not whether an attacker can exploit it.
- **Potential impact severity** remains the configured rule severity. High means the rule describes a potentially serious impact if the listed prerequisites hold; it does not mean those prerequisites were proven. Medium/low likewise describe the rule's potential consequence. No built-in text-only pattern emits Critical as of `builtin-2`; `JWT-ALG-NONE` now reports High/Possible because a literal could refer to signing, tests, or documentation rather than a verifier. Critical requires verified high-impact behavior and exposure in an analysis surface capable of establishing them; the built-in source-text matcher cannot establish this.
- **Confidence** is a named heuristic category, not a probability. `POSSIBLE` means matching evidence exists but behavior or provenance is unresolved. `LIKELY` is reserved by individual rules for tighter same-context patterns; it is still not exploit verification. `CONFIRMED` is not assigned by this built-in ruleset from a static text match.
- **Exploitability** is represented through prerequisites and conditional impact, independently from severity. A reachability test, caller control, or deployment exposure remains unknown unless a separate evidence source establishes it.
- **Exposure** is a separate field/rationale. Unknown is retained when static source context cannot show runtime exposure.
- **Remediation priority** is a report ordering heuristic, not severity. Existing priority math remains unchanged in this continuation.
- **Legacy records** retain null explanation/score-ledger behavior; the UI says unavailable instead of reconstructing old rationales.

The model field `classification_policy_version` is additive and present on newly constructed explanation objects. Policy changes that alter severity semantics must increment this version; the ruleset identifier remains independent.

## Subsequent release-closure status — 2026-11-06

The acceptance matrix and export-retrieval section in this document describe an earlier
continuation baseline. The subsequent [release-closure report](reports/release-closure-2026-11-06.md) supersedes
the conflicting current-state claims:

- The R1 redaction issue was remediated: delimiter scanning is forward, imported text is clipped
  before redaction, operation bounds fail closed, and canary tests cover failure paths. This is not
  a formal complexity proof or a general load guarantee.
- `full-json` remains capped at 10,000 findings and 20 MiB. Existing larger scans can now be
  retrieved through the distinct authenticated/CLI JSONL format with bounded record batches and a
  required final count/hash completion row. It is no longer necessary to reduce or rescan a scan
  merely to retrieve its retained findings.
- Preview metadata distinguishes stored, available, grouped, returned, omitted, and failed results;
  the dashboard displays known counts and labels legacy totals unknown.
- The earlier browser readiness timeout's cause remains unresolved. Current endpoint requests have
  bounded timeouts and report independent outcomes, but later passing runs do not establish the
  historical cause.

Use the release-closure and release-handover reports for the latest validation evidence and
supported-profile decision. The historical validation report remains preserved as an account of the
earlier state.

## Export retrieval contract — continuation baseline (superseded)

At this continuation baseline, `json` was a grouped/bounded preview and `full-json` was limited to 10,000 findings and 20 MiB. Retrieval above those limits was unavailable at that time. The dated release-closure addendum above supersedes that retrieval status. The API does not attach an error body as a report file.
