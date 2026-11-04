"""Bounded, inert import of external JSON and SARIF security reports."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from chinescan.core.logging.redaction import redact
from chinescan.core.models.common import Confidence, EvidenceKind, Severity
from chinescan.core.models.finding import Finding, Reference
from chinescan.core.orchestration.code_scan import make_finding

MAX_EXTERNAL_REPORT_BYTES = 2 * 1024 * 1024
MAX_EXTERNAL_FINDINGS = 5_000
MAX_EXTERNAL_TEXT = 2_000


class ExternalReportError(ValueError):
    """The external report is malformed or exceeds import bounds."""


def parse_scanity_export(
    content: bytes, *, target: Path, project_id: str | None = None
) -> list[Finding]:
    """Parse supported JSON/SARIF without executing or trusting imported content."""
    if len(content) > MAX_EXTERNAL_REPORT_BYTES:
        raise ExternalReportError("Report exceeds the 2 MB import limit.")
    try:
        payload = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExternalReportError("Report must be valid UTF-8 JSON or SARIF.") from exc
    if not isinstance(payload, dict):
        raise ExternalReportError("Report root must be a JSON object.")
    records = (
        _sarif_records(payload) if payload.get("version") == "2.1.0" else _json_records(payload)
    )
    if not records:
        raise ExternalReportError("No supported findings were found in the report.")
    if len(records) > MAX_EXTERNAL_FINDINGS:
        raise ExternalReportError("Report exceeds the 5,000 finding import limit.")
    result = [_map_record(item, target, project_id) for item in records]
    return result


def _sarif_records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise ExternalReportError("SARIF report is missing runs.")
    records: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            continue
        rules: dict[str, dict[str, Any]] = {}
        driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
        for rule in driver.get("rules", []) if isinstance(driver, dict) else []:
            if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                rules[rule["id"]] = rule
        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = _text(result.get("ruleId") or "external-finding", 160)
            rule_info = rules.get(rule_id, {})
            message = result.get("message", {})
            message_text = (
                message.get("text", "External scanner finding")
                if isinstance(message, dict)
                else "External scanner finding"
            )
            locations = result.get("locations", [])
            physical = (
                locations[0].get("physicalLocation", {})
                if locations and isinstance(locations[0], dict)
                else {}
            )
            artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
            region = physical.get("region", {}) if isinstance(physical, dict) else {}
            snippet = region.get("snippet", {}) if isinstance(region, dict) else {}
            properties = result.get("properties", {})
            if not isinstance(properties, dict):
                properties = {}
            records.append(
                {
                    "rule_id": rule_id,
                    "title": _nested_text(rule_info.get("shortDescription"), "text") or rule_id,
                    "description": message_text,
                    "severity": properties.get("severity") or result.get("level"),
                    "confidence": properties.get("confidence"),
                    "path": artifact.get("uri") if isinstance(artifact, dict) else None,
                    "line": region.get("startLine") if isinstance(region, dict) else None,
                    "excerpt": snippet.get("text") if isinstance(snippet, dict) else None,
                    "cwe": properties.get("cwe") or properties.get("cwe_id"),
                    "remediation": properties.get("remediation"),
                }
            )
    return records


def _json_records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    records: Any = payload.get("findings")
    if records is None:
        records = payload.get("results")
    if records is None:
        records = payload.get("issues")
    if records is None:
        records = payload.get("vulnerabilities")
    if not isinstance(records, list):
        raise ExternalReportError(
            "Unsupported JSON report. Expected SARIF 2.1.0 or a findings/results/issues array."
        )
    return [item for item in records if isinstance(item, dict)]


def _map_record(item: dict[str, Any], target: Path, project_id: str | None) -> Finding:
    rule_id = _text(
        item.get("rule_id") or item.get("ruleId") or item.get("id") or "external-finding", 160
    )
    title = _text(item.get("title") or item.get("name") or rule_id, 240)
    description = _text(
        item.get("description") or item.get("message") or "External scanner finding.",
        MAX_EXTERNAL_TEXT,
    )
    severity = _severity(item.get("severity") or item.get("level"))
    confidence = _confidence(item.get("confidence"))
    location_value = item.get("location")
    path_value: Any = item.get("path") or item.get("file")
    line_value: Any = item.get("line") or item.get("line_number")
    if isinstance(location_value, dict):
        path_value = location_value.get("path") or location_value.get("uri") or path_value
        line_value = location_value.get("line") or location_value.get("startLine") or line_value
    elif isinstance(location_value, str) and path_value is None:
        path_value, _, tail = location_value.rpartition(":")
        line_value = line_value or tail
    safe_path = _safe_relative_path(path_value)
    line = (
        line_value
        if isinstance(line_value, int)
        else int(line_value)
        if str(line_value).isdigit()
        else None
    )
    line = line if line is not None and 1 <= line <= 10_000_000 else None
    location = safe_path + (f":{line}" if line else "")
    cwes = _cwes(item.get("cwe_ids") or item.get("cwe") or item.get("cwe_id"))
    excerpt = (
        _text(item.get("code_excerpt") or item.get("snippet") or item.get("code"), 360) or None
    )
    remediation = (
        _text(
            item.get("remediation") or item.get("fix") or item.get("recommendation"),
            MAX_EXTERNAL_TEXT,
        )
        or None
    )
    fingerprint = hashlib.sha256(
        f"scanity\0{rule_id.casefold()}\0{location.casefold()}\0{title.casefold()}".encode()
    ).hexdigest()
    finding = make_finding(
        target=target,
        scanner="scanity",
        rule_id=rule_id,
        title=title,
        severity=severity,
        category="SAST",
        confidence=confidence.value,
        location=location,
        description=description,
        tags=["external", "untrusted-import"],
        evidence=EvidenceKind.PATTERN_MATCH,
    )
    refs = [
        Reference(
            title=cwe,
            url=f"https://cwe.mitre.org/data/definitions/{cwe.removeprefix('CWE-')}.html",
        )
        for cwe in cwes
    ]
    return finding.model_copy(
        update={
            "finding_id": fingerprint[:8]
            + "-"
            + fingerprint[8:12]
            + "-5"
            + fingerprint[13:16]
            + "-a"
            + fingerprint[17:20]
            + "-"
            + fingerprint[20:32],
            "fingerprint": fingerprint,
            "source": "scanity",
            "project_id": project_id,
            "line_numbers": [line] if line else [],
            "code_excerpt": excerpt,
            "remediation": remediation,
            "cwe_ids": cwes,
            "exposure": "unknown",
            "references": refs,
        }
    )


def _safe_relative_path(value: Any) -> str:
    if not isinstance(value, str):
        return "external-path-omitted"
    normalized = value.replace("\\", "/").removeprefix("./")
    if not normalized or normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return "external-path-omitted"
    if any(part in {"", ".."} for part in normalized.split("/")):
        return "external-path-omitted"
    return _text(normalized, 300)


def _severity(value: Any) -> Severity:
    text = str(value or "").casefold()
    mapping = {
        "critical": Severity.CRITICAL,
        "error": Severity.HIGH,
        "high": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "note": Severity.LOW,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(text, Severity.MEDIUM)


def _confidence(value: Any) -> Confidence:
    text = str(value or "").upper()
    try:
        return Confidence(text)
    except ValueError:
        return Confidence.POSSIBLE


def _cwes(value: Any) -> list[str]:
    items = value if isinstance(value, list) else [value]
    result: list[str] = []
    for item in items:
        match = re.search(r"CWE[- ]?(\d{1,5})", str(item), re.I)
        if match:
            cwe = f"CWE-{int(match.group(1))}"
            if cwe not in result:
                result.append(cwe)
    return result[:10]


def _text(value: Any, limit: int) -> str:
    if isinstance(value, dict):
        value = value.get("text") or value.get("message")
    if not isinstance(value, str):
        return ""
    cleaned = "".join(char for char in value if char in "\n\t" or ord(char) >= 32)
    return str(redact(cleaned)).strip()[:limit]


def _nested_text(value: Any, key: str) -> str:
    return _text(value.get(key), 240) if isinstance(value, dict) else ""
