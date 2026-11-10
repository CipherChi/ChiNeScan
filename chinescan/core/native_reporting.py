"""Bounded optional dispatch to the Rust report renderer."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

from chinescan.malware_analysis.process import WorkerFailure, run_native_parser_worker

MAX_REPORT_REQUEST_BYTES = 16 * 1024 * 1024
MAX_LOCAL_INTEL_BYTES = 2 * 1024 * 1024


def _local_intel() -> dict[str, object]:
    """Read an explicitly configured operator file; never fetch intel remotely."""
    source = os.environ.get("CHINESCAN_REPORTER_LOCAL_DATA")
    if not source:
        return {}
    try:
        path = Path(source)
        if path.stat().st_size > MAX_LOCAL_INTEL_BYTES:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}
    cwe = value.get("cwe", {})
    epss = value.get("epss_by_rule", {})
    kev = value.get("kev_rules", [])
    if not isinstance(cwe, dict) or not isinstance(epss, dict) or not isinstance(kev, list):
        return {}
    cwe_map = {
        key: label
        for key, label in cwe.items()
        if isinstance(key, str) and len(key) <= 32 and isinstance(label, str) and len(label) <= 256
    }
    epss_map = {
        key: score
        for key, score in epss.items()
        if isinstance(key, str)
        and len(key) <= 128
        and isinstance(score, (int, float))
        and 0 <= score <= 1
    }
    kev_rules = [rule for rule in kev if isinstance(rule, str) and len(rule) <= 128]
    return {"cwe_map": cwe_map, "epss_by_rule": epss_map, "kev_rules": kev_rules}


def render_native_report(request: dict[str, object]) -> str | None:
    mode = os.environ.get("CHINESCAN_RUST_REPORTER", "off").strip().casefold()
    if mode in {"off", "false", "0", "disabled"}:
        return None
    try:
        if importlib.util.find_spec("chinescan_engine") is None:
            return None
        import chinescan_engine  # type: ignore[import-untyped]

        if not hasattr(chinescan_engine, "render_report_json"):
            return None
    except (ImportError, ValueError):
        return None
    try:
        local_intel = _local_intel()
        request = dict(request)
        request.update(local_intel)
        findings = request.get("findings")
        if isinstance(findings, list):
            epss_map = local_intel.get("epss_by_rule", {})
            kev_rules = local_intel.get("kev_rules", [])
            if isinstance(epss_map, dict) and isinstance(kev_rules, list):
                for finding in findings:
                    if isinstance(finding, dict):
                        rule = finding.get("rule_id")
                        if isinstance(rule, str):
                            if rule in epss_map:
                                finding["epss"] = epss_map[rule]
                            finding["kev"] = rule in kev_rules
        body = json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        encoded = body.encode("utf-8")
        if len(encoded) > MAX_REPORT_REQUEST_BYTES:
            return None
        result = run_native_parser_worker("report", encoded)
    except (WorkerFailure, TypeError, ValueError, UnicodeError):
        return None
    content = result.get("report")
    return (
        content
        if isinstance(content, str) and len(content.encode("utf-8")) <= 3 * 1024 * 1024
        else None
    )
