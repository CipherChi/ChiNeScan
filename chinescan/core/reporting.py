"""Render persisted scan findings in portable analyst-facing formats."""

import csv
import getpass
import html
import io
import json
import re
from pathlib import Path
from typing import Any, cast

from chinescan import __version__
from chinescan.core.cases import CaseWorkflow
from chinescan.core.logging.redaction import redact
from chinescan.core.models.common import Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Alert, Scan
from chinescan.core.storage.repository import Repository
from chinescan.core.verdict import VERDICT_CAVEAT
from chinescan.malware_analysis.managed import safe_display_name


class ReportingError(ValueError):
    """Requested scan data is missing or malformed."""


_CHAIN_HEX_IDENTIFIER = re.compile(
    r"(?i)(?<![A-Za-z0-9])0x(?:[0-9a-f]{40}|[0-9a-f]{64})(?![A-Za-z0-9])"
)


def _redact_finding(finding: Finding, *, chain_scan: bool) -> dict[str, Any]:
    payload = finding.model_dump(mode="json")
    if not chain_scan:
        return cast(dict[str, Any], redact(payload))

    protected: dict[str, str] = {}
    marker_prefix = "CHAINHEXPLACEHOLDER"

    def shield(value: Any) -> Any:
        if isinstance(value, str):
            def replace(match: re.Match[str]) -> str:
                marker = f"{marker_prefix}{len(protected)}"
                protected[marker] = match.group(0)
                return marker

            return _CHAIN_HEX_IDENTIFIER.sub(replace, value)
        if isinstance(value, list):
            return [shield(item) for item in value]
        if isinstance(value, dict):
            return {key: shield(item) for key, item in value.items()}
        return value

    safe = redact(shield(payload))

    def restore(value: Any) -> Any:
        if isinstance(value, str):
            for marker, identifier in protected.items():
                value = value.replace(marker, identifier)
            return value
        if isinstance(value, list):
            return [restore(item) for item in value]
        if isinstance(value, dict):
            return {key: restore(item) for key, item in value.items()}
        return value

    restored = restore(safe)
    return cast(dict[str, Any], restored) if isinstance(restored, dict) else {}


def scan_data(repository: Repository, scan_id: str) -> tuple[Scan, list[Finding]]:
    """Load and validate the scan and its normalized findings."""
    payload = repository.get("scan", scan_id)
    if payload is None:
        raise ReportingError(f"Scan not found: {scan_id}")
    try:
        scan = Scan.model_validate(payload)
        findings: list[Finding] = []
        for finding_id in scan.finding_ids:
            finding_payload = repository.get("finding", finding_id)
            if finding_payload is not None:
                findings.append(Finding.model_validate(finding_payload))
    except (ValueError, TypeError) as exc:
        raise ReportingError("Stored scan data is invalid.") from exc
    return scan, findings


def render_report(scan: Scan, findings: list[Finding], output_format: str) -> str:
    """Render one scan using JSON, Markdown, HTML, CSV, or SARIF 2.1.0."""
    if output_format not in {"json", "markdown", "html", "csv", "sarif", "share-summary"}:
        raise ReportingError("Unsupported report format.")
    chain_scan = "chain" in scan.project_types or scan.scanner == "chain_trace"
    safe_findings = [_redact_finding(item, chain_scan=chain_scan) for item in findings]
    caveat = VERDICT_CAVEAT.get(scan.verdict) if scan.verdict is not None else None
    if output_format == "share-summary":
        return _share_summary(scan, findings, caveat)
    if output_format == "json":
        return json.dumps(
            {
                "scan": redact(scan.model_dump(mode="json")),
                "findings": safe_findings,
                "verdict": scan.verdict.value if scan.verdict else None,
                "caveat": caveat,
                "coverage": scan.coverage.model_dump(mode="json") if scan.coverage else None,
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
    if output_format == "csv":
        buffer = io.StringIO(newline="")
        columns = [
            "finding_id",
            "title",
            "severity",
            "category",
            "confidence",
            "scanner",
            "rule_id",
            "location",
            "fingerprint",
            "description",
            "evidence",
        ]
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(
            {key: _csv_safe(value) for key, value in item.items() if key in columns}
            for item in safe_findings
        )
        return buffer.getvalue()
    if output_format == "sarif":
        return _sarif(findings)

    title = f"ChineScan report: {scan.scan_id}"
    if output_format == "markdown":
        lines = [f"# {title}", "", f"Status: `{scan.status}`", "", f"Findings: {len(findings)}", ""]
        if scan.verdict is not None:
            lines.extend(["## Verdict", "", f"**{scan.verdict.value}** — {caveat}", ""])
        if scan.coverage is not None:
            lines.extend(
                [
                    "## Coverage",
                    "",
                    "Examined: "
                    + ", ".join(f"{k}: {v}" for k, v in scan.coverage.examined.items()),
                    "",
                ]
            )
            lines.extend(["Coverage gaps:", ""])
            lines.extend(
                [f"- {gap.code}: {gap.reason} (count: {gap.count})" for gap in scan.coverage.gaps]
                or ["- None recorded."]
            )
            lines.append("")
        for item in safe_findings:
            lines.extend(
                [
                    f"## {_markdown(str(item['title']))}",
                    "",
                    f"- Severity: **{item['severity']}**",
                    f"- Category: `{item['category']}`",
                    f"- Confidence: `{item['confidence']}`",
                    *([f"- Evidence: `{item['evidence']}`"] if item.get("evidence") else []),
                    f"- Rule: `{_markdown_code(str(item['rule_id']))}`",
                    f"- Location: `{_markdown_code(str(item.get('location') or 'unspecified'))}`",
                    "",
                    _markdown(str(item["description"])),
                    "",
                ]
            )
        return "\n".join(lines)
    rows = []
    for item in safe_findings:
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(item.get(key) or ''))}</td>"
                for key in (
                    "severity",
                    "category",
                    "title",
                    "rule_id",
                    "location",
                    "description",
                    "evidence",
                )
            )
            + "</tr>"
        )
    coverage_html = ""
    if scan.coverage is not None:
        gaps = (
            "".join(
                f"<li>{html.escape(g.code)}: {html.escape(g.reason)} ({g.count})</li>"
                for g in scan.coverage.gaps
            )
            or "<li>None recorded.</li>"
        )
        examined = ", ".join(f"{k}: {v}" for k, v in scan.coverage.examined.items())
        coverage_html = f"<h2>Coverage</h2><p>{html.escape(examined)}</p><ul>{gaps}</ul>"
    verdict_html = (
        "<h2>Verdict</h2><p><strong>"
        + html.escape(scan.verdict.value)
        + "</strong> — "
        + html.escape(caveat or "")
        + "</p>"
        if scan.verdict
        else ""
    )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>'
        + html.escape(title)
        + "</title><h1>"
        + html.escape(title)
        + "</h1><p>Findings: "
        + str(len(findings))
        + "</p>"
        + verdict_html
        + coverage_html
        + "<table><thead><tr><th>Severity</th><th>Category</th>"
        + (
            "<th>Title</th><th>Rule</th><th>Location</th><th>Description</th>"
            "<th>Evidence</th></tr></thead><tbody>"
        )
        + "".join(rows)
        + "</tbody></table></html>"
    )


_CASE_PRIVATE_FIELDS = {
    "source_ip",
    "destination_ip",
    "user",
    "command_line",
    "url",
    "user_agent",
    "raw_ref",
    "value",
    "target",
}


def _redact_case_value(value: Any) -> Any:
    """Apply shared secret redaction and hide direct identifiers from case exports."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if key in _CASE_PRIVATE_FIELDS and not isinstance(item, (dict, list))
            else _redact_case_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_case_value(item) for item in value]
    if isinstance(value, str):
        return redact(value)
    return value


def render_case_report(repository: Repository, case_id: str, output_format: str) -> str:
    """Render a redacted, schema-versioned report from persisted case-linked records."""
    if output_format not in {"json", "markdown", "html"}:
        raise ReportingError("Case report format must be json, markdown, or html.")
    workflow = CaseWorkflow(repository)
    context = workflow.context(case_id)
    case = context.case
    _, timeline, timeline_warnings = workflow.timeline(case)
    records: dict[str, list[dict[str, Any]]] = {
        record_type: []
        for record_type in (
            "scan",
            "target",
            "finding",
            "alert",
            "event",
            "timeline_entry",
            "indicator",
            "authorization_record",
            "malware_sample",
            "malware_analysis",
        )
    }
    persisted_link_sources = {
        (link.record_type, link.record_id): link.source for link in context.links
    }
    for (record_type, record_id), record in sorted(context.records.items()):
        payload = record.model_dump(mode="json")
        if record_type in {"malware_sample", "malware_analysis"}:
            payload = _reviewed_malware_case_record(record_type, payload)
        records.setdefault(record_type, []).append(
            {
                "record_id": record_id,
                "source": persisted_link_sources.get(
                    (record_type, record_id), _record_source(record_type, record)
                ),
                "record": payload,
            }
        )
    counts_by_severity = {severity.value: 0 for severity in Severity}
    for record_type in ("finding", "alert"):
        for item in records.get(record_type, []):
            severity = item["record"].get("severity")
            if severity in counts_by_severity:
                counts_by_severity[severity] += 1
    counts_by_type = {record_type: len(items) for record_type, items in sorted(records.items())}
    warnings = list(dict.fromkeys([*context.warnings, *timeline_warnings]))
    limitations = [
        (
            "Record ingestion timestamps are not persisted; source occurrence time and "
            "case activity time are distinct, but ingestion time is unavailable."
        ),
        "Artifacts are not persisted in this release and cannot be attached or exported.",
    ]
    if records.get("finding"):
        limitations.append(
            "No structured remediation guidance is stored for findings in this release."
        )
    payload = _redact_case_value(
        {
            "schema_version": "1.0",
            "case": case.model_dump(mode="json"),
            "summary": {
                "linked_record_count": len(context.links),
                "counts_by_type": counts_by_type,
                "counts_by_severity": counts_by_severity,
            },
            "links": [link.model_dump(mode="json") for link in context.links],
            "records": records,
            "timeline": [item.model_dump(mode="json") for item in timeline],
            "notes": [note.model_dump(mode="json") for note in case.notes],
            "warnings": warnings,
            "limitations": limitations,
        }
    )
    if output_format == "json":
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
    if output_format == "markdown":
        return _case_markdown(payload)
    return _case_html(payload)


def _reviewed_malware_case_record(record_type: str, value: dict[str, Any]) -> dict[str, Any]:
    """Allowlist malware case fields; never export opaque storage keys or sample bytes."""
    if record_type == "malware_sample":
        return {
            "sample_id": value.get("sample_id"),
            "display_name": safe_display_name(str(value.get("display_name", ""))),
            "sha256": value.get("sha256"),
            "size_bytes": value.get("size_bytes"),
            "availability": value.get("availability"),
            "withheld": "Original path, managed object key, and sample bytes are not included.",
        }
    raw_result = value.get("result")
    result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
    raw_indicators = result.get("indicators")
    indicators: list[Any] = raw_indicators if isinstance(raw_indicators, list) else []
    raw_warnings = result.get("warnings")
    warnings: list[Any] = raw_warnings if isinstance(raw_warnings, list) else []
    raw_hashes = result.get("hashes")
    hashes: dict[str, Any] = raw_hashes if isinstance(raw_hashes, dict) else {}
    engines_value = value.get("engines")
    engines: dict[str, Any] = engines_value if isinstance(engines_value, dict) else {}
    safe_engines: dict[str, dict[str, str]] = {}
    for engine_name in ("yara", "clamav"):
        engine_value = engines.get(engine_name)
        if not isinstance(engine_value, dict):
            continue
        safe_engines[engine_name] = {
            key: redact(str(engine_value.get(key, "not_checked"))[:40])
            for key in (
                "requested",
                "installation",
                "configuration",
                "real_binary_verification",
            )
        }
    return {
        "analysis_id": value.get("analysis_id"),
        "sample_id": value.get("sample_id"),
        "profile": value.get("profile"),
        "status": value.get("status"),
        "created_at": value.get("created_at"),
        "size_bytes": result.get("size_bytes"),
        "hashes": {
            key: hashes[key]
            for key in ("md5", "sha1", "sha256")
            if isinstance(hashes.get(key), str)
            and len(hashes[key]) == {"md5": 32, "sha1": 40, "sha256": 64}[key]
            and all(character in "0123456789abcdef" for character in hashes[key].lower())
        },
        "file_type": redact(str(result.get("file_type", "unknown"))[:120]),
        "architecture": result.get("architecture")
        if isinstance(result.get("architecture"), str)
        else None,
        "indicator_count": result.get("indicator_count", len(indicators)),
        "indicators": [
            {
                "kind": redact(str(item.get("kind", ""))[:40]),
                "value": redact(str(item.get("value", ""))[:2048]),
            }
            for item in indicators[:500]
            if isinstance(item, dict)
        ],
        "warnings": [redact(str(item)[:500]) for item in warnings[:50]],
        "engines": safe_engines,
        "evidence_note": (
            "Indicators are untrusted candidate evidence, not confirmed maliciousness. "
            "Sample bytes, arbitrary strings, archive names, paths, credentials, and raw "
            "worker output are withheld."
        ),
    }


def _record_source(record_type: str, record: Any) -> str:
    return str(
        getattr(record, "source", None)
        or getattr(record, "scanner", None)
        or getattr(record, "kind", None)
        or getattr(record, "method", None)
        or (f"rule:{record.rule_id}" if isinstance(record, Alert) else record_type)
    )


def _case_markdown(payload: dict[str, Any]) -> str:
    case = payload["case"]
    summary = payload["summary"]
    lines = [
        f"# Case report: {_markdown(str(case['title']))}",
        "",
        f"- Case ID: `{_markdown_code(case['case_id'])}`",
        f"- Status: **{_markdown(str(case['status']))}**",
        f"- Severity: **{_markdown(str(case['severity']))}**",
        f"- Created: `{_markdown_code(case['created_at'])}`",
        f"- Updated: `{_markdown_code(case['updated_at'])}`",
        "",
        _markdown(str(case.get("description") or "No description.")),
        "",
        "## Summary",
        "",
        f"Linked records: {summary['linked_record_count']}",
        "",
        "Counts by type: "
        + ", ".join(f"{key} {value}" for key, value in summary["counts_by_type"].items()),
        "",
        "Counts by severity: "
        + ", ".join(f"{key} {value}" for key, value in summary["counts_by_severity"].items()),
        "",
        "## Linked records",
        "",
    ]
    if not payload["links"]:
        lines.append("No records linked.")
    for link in payload["links"]:
        lines.append(
            f"- `{_markdown_code(link['record_type'])}` `{_markdown_code(link['record_id'])}` "
            f"from `{_markdown_code(link['source'])}`"
        )
    for record_type in ("finding", "alert"):
        if payload["records"].get(record_type):
            lines.extend(["", f"### {record_type.title()} details", ""])
            for item in payload["records"][record_type]:
                record = item["record"]
                lines.extend(
                    [
                        f"- `{_markdown_code(item['record_id'])}` — "
                        f"**{_markdown(str(record.get('severity', 'unknown')))}** "
                        f"{_markdown(str(record.get('title', '')))}",
                        f"  - Source: `{_markdown_code(item['source'])}`; "
                        f"rule: `{_markdown_code(str(record.get('rule_id', 'unspecified')))}`",
                        f"  - {_markdown(str(record.get('description') or 'No description.'))}",
                    ]
                )
    other_records = [
        (record_type, item)
        for record_type, items in payload["records"].items()
        if record_type not in {"finding", "alert"}
        for item in items
    ]
    lines.extend(["", "### Other linked record details", ""])
    if other_records:
        for record_type, item in other_records:
            serialized = json.dumps(item["record"], ensure_ascii=False, sort_keys=True)
            lines.append(
                f"- **{_markdown(record_type)}** `{_markdown_code(item['record_id'])}`: "
                f"{_markdown(serialized)}"
            )
    else:
        lines.append("No other linked record details.")
    lines.extend(["", "## Timeline", ""])
    if payload["timeline"]:
        for item in payload["timeline"]:
            time_value = (
                item.get("event_occurred_at") or item.get("case_activity_at") or "time unavailable"
            )
            lines.append(
                f"- `{_markdown_code(str(time_value))}` **{_markdown(str(item['category']))}** "
                f"{_markdown(str(item['description']))}"
            )
    else:
        lines.append("No timeline entries.")
    lines.extend(["", "## Analyst notes", ""])
    if payload["notes"]:
        for note in payload["notes"]:
            author = (
                f" — {_markdown(str(note['author_label']))} (local label, unverified)"
                if note.get("author_label")
                else ""
            )
            lines.extend(
                [
                    f"### `{_markdown_code(note['created_at'])}`{author}",
                    "",
                    _markdown(str(note["body"])),
                    "",
                ]
            )
    else:
        lines.append("No analyst notes.")
    lines.extend(["", "## Warnings and limitations", ""])
    for warning in payload["warnings"] + payload["limitations"]:
        lines.append(f"- {_markdown(str(warning))}")
    return "\n".join(lines) + "\n"


def _case_html(payload: dict[str, Any]) -> str:
    case = payload["case"]
    summary = payload["summary"]

    def e(value: object) -> str:
        return html.escape(str(value), quote=True)

    link_rows = (
        "".join(
            "<tr>"
            + "".join(f"<td>{e(link[key])}</td>" for key in ("record_type", "record_id", "source"))
            + "</tr>"
            for link in payload["links"]
        )
        or '<tr><td colspan="3">No records linked.</td></tr>'
    )
    timeline_rows = (
        "".join(
            "<li><time>"
            + e(item.get("event_occurred_at") or item.get("case_activity_at") or "time unavailable")
            + "</time> <strong>"
            + e(item["category"])
            + "</strong> "
            + e(item["description"])
            + "</li>"
            for item in payload["timeline"]
        )
        or "<li>No timeline entries.</li>"
    )
    notes = (
        "".join(
            "<li><time>"
            + e(note["created_at"])
            + "</time>"
            + (
                " <span>(local author label, unverified)</span> " + e(note["author_label"])
                if note.get("author_label")
                else ""
            )
            + "<p>"
            + e(note["body"])
            + "</p></li>"
            for note in payload["notes"]
        )
        or "<li>No analyst notes.</li>"
    )
    findings = (
        "".join(
            "<li><strong>"
            + e(item["record"].get("severity", "unknown"))
            + "</strong> "
            + e(item["record"].get("title", ""))
            + "<p>"
            + e(item["record"].get("description", ""))
            + "</p></li>"
            for item in payload["records"].get("finding", [])
        )
        or "<li>This case has no linked finding records.</li>"
    )
    alerts = (
        "".join(
            "<li><strong>"
            + e(item["record"].get("severity", "unknown"))
            + "</strong> "
            + e(item["record"].get("title", ""))
            + "<p>"
            + e(item["record"].get("description", ""))
            + "</p></li>"
            for item in payload["records"].get("alert", [])
        )
        or "<li>No alerts linked.</li>"
    )
    other_records = (
        "".join(
            "<li><strong>"
            + e(record_type)
            + "</strong> <code>"
            + e(item["record_id"])
            + "</code><pre>"
            + e(json.dumps(item["record"], ensure_ascii=False, sort_keys=True, indent=2))
            + "</pre></li>"
            for record_type, items in payload["records"].items()
            if record_type not in {"finding", "alert"}
            for item in items
        )
        or "<li>No other linked record details.</li>"
    )
    warnings = "".join(
        f"<li>{e(item)}</li>" for item in payload["warnings"] + payload["limitations"]
    )
    type_counts = "".join(
        f"<li>{e(record_type)}: {e(count)}</li>"
        for record_type, count in summary["counts_by_type"].items()
    )
    severity_counts = "".join(
        f"<li>{e(severity)}: {e(count)}</li>"
        for severity, count in summary["counts_by_severity"].items()
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>Case report: {e(case['title'])}</title></head><body>"
        f"<h1>{e(case['title'])}</h1><p>Case ID: <code>{e(case['case_id'])}</code></p>"
        f"<p>Status: {e(case['status'])}; severity: {e(case['severity'])}</p>"
        f"<p>{e(case.get('description') or 'No description.')}</p>"
        f"<h2>Summary</h2><p>Linked records: {e(summary['linked_record_count'])}</p>"
        f"<h3>Counts by type</h3><ul>{type_counts}</ul>"
        f"<h3>Counts by severity</h3><ul>{severity_counts}</ul>"
        "<h2>Linked records</h2><table><thead><tr><th>Type</th><th>ID</th>"
        "<th>Source</th></tr></thead>"
        f"<tbody>{link_rows}</tbody></table><h2>Findings</h2><ul>{findings}</ul>"
        f"<h2>Alerts</h2><ul>{alerts}</ul><h2>Other linked record details</h2>"
        f"<ul>{other_records}</ul><h2>Timeline</h2><ol>{timeline_rows}</ol>"
        f"<h2>Analyst notes</h2><ul>{notes}</ul>"
        f"<h2>Warnings and limitations</h2><ul>{warnings}</ul>"
        "</body></html>"
    )


def _sarif(findings: list[Finding]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    for finding in findings:
        rule_id = str(redact(finding.rule_id))
        title = str(redact(finding.title))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
            },
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level_map[finding.severity.value],
            "message": {"text": str(redact(finding.description))},
            "properties": {
                "findingId": finding.finding_id,
                "severity": finding.severity.value,
                "category": finding.category.value,
                "confidence": finding.confidence.value,
                "fingerprint": finding.fingerprint,
                "scanner": finding.scanner,
                **({"evidence": finding.evidence.value} if finding.evidence is not None else {}),
            },
        }
        if finding.location:
            path, separator, line = finding.location.rpartition(":")
            if separator and line.isdigit():
                uri, line_number = path, int(line)
            else:
                uri, line_number = finding.location, 1
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": line_number},
                    }
                }
            ]
        results.append(result)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ChineScan", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)


def _share_summary(scan: Scan, findings: list[Finding], caveat: str | None) -> str:
    """Build a short allowlisted summary without descriptions, contents, or absolute paths."""
    evidence_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for finding in findings:
        evidence = finding.evidence.value if finding.evidence else "unspecified"
        evidence_counts[evidence] = evidence_counts.get(evidence, 0) + 1
        severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
    home = str(Path.home())
    username = getpass.getuser()

    def relative_location(value: str | None) -> str:
        if not value:
            return "<path>"
        candidate = value.replace("\\", "/")
        if candidate.startswith("/") or re.match(r"^[A-Za-z]:/", candidate):
            return "<path>"
        for private in (home, username):
            if private:
                candidate = re.sub(
                    re.escape(private.replace("\\", "/")), "<path>", candidate, flags=re.I
                )
        candidate = re.sub(r"(?i)(?:[A-Z]:/|//)[^\s:]+", "<path>", candidate)
        return str(redact(candidate))

    def share_text(value: str) -> str:
        cleaned = value.replace("\\", "/")
        for private in (home, username):
            if private:
                cleaned = re.sub(
                    re.escape(private.replace("\\", "/")), "<path>", cleaned, flags=re.I
                )
        cleaned = re.sub(r"(?i)(?:[A-Z]:/|//)[^\s:]+", "<path>", cleaned)
        return str(redact(cleaned))

    lines = [
        f"# ChineScan share summary — {share_text(scan.scan_id)}",
        "",
        f"- Tool version: {__version__}",
        f"- Verdict: {scan.verdict.value if scan.verdict else 'not recorded'}",
        "- Caveat: "
        + (caveat or "Matches are leads rather than proof; no matches do not prove safety."),
        "- Evidence counts: "
        + (", ".join(f"{k}: {v}" for k, v in sorted(evidence_counts.items())) or "none"),
        "- Severity counts: "
        + (", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items())) or "none"),
        "- Coverage gaps: "
        + (
            ", ".join(f"{share_text(gap.reason)} ({gap.count})" for gap in scan.coverage.gaps)
            if scan.coverage and scan.coverage.gaps
            else "none recorded"
        ),
        "- Indicator files: "
        + (
            ", ".join(
                f"{share_text(str(scan.scan_options.get(key, 'indicator file')))} (SHA-256 "
                f"{scan.scan_options.get(key.replace('file_name', 'sha256'), 'unavailable')})"
                for key in sorted(scan.scan_options)
                if key.startswith("indicator_file_name_")
            )
            or "none recorded"
        ),
        "",
        "## Leads",
    ]
    for finding in findings[:10]:
        title = share_text(finding.title)
        location = relative_location(finding.location)
        if "chain" in scan.project_types or scan.scanner == "chain_trace":
            title = re.sub(
                r"(?i)0x[a-f0-9]{40}|[1-9A-HJ-NP-Za-km-z]{32,44}",
                lambda m: m.group(0)[:6] + "..." + m.group(0)[-4:],
                finding.title,
            )
            title = re.sub(r"(?i)0x[a-f0-9]{64}", "transaction hash omitted", title)
            title = share_text(title)
            if not (finding.location or "").startswith("chain:"):
                location = "transaction reference omitted"
            else:
                raw_location = re.sub(
                    r"(?i)(0x[a-f0-9]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})",
                    lambda m: m.group(0)[:6] + "..." + m.group(0)[-4:],
                    finding.location or "",
                )
                location = relative_location(raw_location)
        if any(
            indicator_id in title
            for indicator_id in (item for item in finding.tags if item.startswith("indicator:"))
        ):
            title = "Indicator reference"
        lines.append(
            f"- {title} — {finding.evidence.value if finding.evidence else 'unspecified'} — "
            f"{location}"
        )
    if not findings:
        lines.append("- No leads recorded.")
    return str(redact("\n".join(lines))) + "\n"


def _markdown(value: str) -> str:
    """Escape raw HTML and common Markdown metacharacters in untrusted text."""
    escaped = html.escape(value, quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", escaped)


def _csv_safe(value: object) -> object:
    """Prevent spreadsheet formula evaluation in analyst-provided CSV cells."""
    if isinstance(value, str) and value:
        first = value.lstrip(" \t\r\n")[:1]
        if value[0] in "\t\r\n" or first in {"=", "+", "-", "@"}:
            return "'" + value
    return value


def _markdown_code(value: str) -> str:
    """Escape values placed inside a Markdown inline-code span."""
    return value.replace("\\", "\\\\").replace("`", "\\`").replace("\n", " ")
