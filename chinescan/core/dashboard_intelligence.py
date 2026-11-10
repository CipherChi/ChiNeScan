"""Local record aggregation for the isolated Rust scoring and alert-rule workers."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from chinescan.core.capabilities import module_capabilities
from chinescan.core.dashboard_alerts import DashboardAlerts
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.malware_analysis.process import WorkerFailure, run_native_parser_worker

CONFIDENCE = {"confirmed": 1.0, "likely": 0.8, "possible": 0.55, "informational": 0.25}
SEVERITY_WEIGHT = {"critical": 40.0, "high": 25.0, "medium": 14.0, "low": 6.0, "info": 2.0}
SCORE_FORMULA = (
    "weights: critical=40, high=25, medium=14, low=6, info=2; "
    "clamp(round(100 - sum(severity_weight × confidence × 2^(-age_days/60)) "
    "- 50 × (1 - checks_completed/checks_total)), 0, 100); "
    "not scored until at least one check completes"
)


def _module_for_scanner(scanner: str) -> str:
    normalized = scanner.casefold()
    if "malware" in normalized:
        return "Malware Triage"
    if "log" in normalized:
        return "Log Analysis"
    if "chain" in normalized or "trace" in normalized:
        return "On-chain Tracing"
    return "Code Assessment"


def _not_assessed_count(module: dict[str, object]) -> int:
    items = module.get("not_assessed")
    return len(items) if isinstance(items, list) else 0


class DashboardIntelligence:
    def __init__(self, repository: SQLiteRepository, alerts: DashboardAlerts) -> None:
        self.repository = repository
        self.alerts = alerts

    def score_modules(self) -> list[dict[str, Any]]:
        capabilities = module_capabilities()
        completed: dict[str, int] = {}
        not_assessed: dict[str, int] = {}
        findings: dict[str, list[dict[str, Any]]] = {
            str(module["name"]): [] for module in capabilities
        }
        for scan in self.repository.list_records("scan"):
            module = _module_for_scanner(str(scan.get("scanner", "")))
            if str(scan.get("status", "")).casefold() in {
                "complete",
                "completed",
                "succeeded",
                "partial",
            }:
                assessment = scan.get("code_assessment") or {}
                coverage = scan.get("coverage") or {}
                checks = max(1, int(assessment.get("files_scanned", 0) or 0))
                gaps = sum(
                    max(1, int(gap.get("count", 1) or 1))
                    for gap in coverage.get("gaps", [])
                    if isinstance(gap, dict)
                )
                excluded = max(0, int(assessment.get("files_excluded", 0) or 0))
                not_assessed[module] = (
                    not_assessed.get(module, 0)
                    + gaps
                    + excluded
                    + len(coverage.get("not_assessed", []))
                )
                completed[module] = completed.get(module, 0) + checks
        for finding in self.repository.list_records("finding"):
            module_name = _module_for_scanner(str(finding.get("scanner", "")))
            occurred = (
                finding.get("created_at")
                or finding.get("detected_at")
                or finding.get("occurred_at")
            )
            try:
                created = (
                    datetime.fromisoformat(str(occurred).replace("Z", "+00:00"))
                    if occurred
                    else datetime.now(UTC)
                )
                if created.tzinfo is None:
                    created = created.replace(tzinfo=UTC)
                age = max(
                    0.0, (datetime.now(UTC) - created.astimezone(UTC)).total_seconds() / 86400
                )
            except ValueError:
                age = 0.0
            confidence = str(finding.get("confidence", "possible")).casefold()
            if module_name not in findings:
                findings[module_name] = []
            findings[module_name].append(
                {
                    "severity": str(finding.get("severity", "info")),
                    "confidence": CONFIDENCE.get(confidence, 0.55),
                    "age_days": age,
                }
            )
        for analysis in self.repository.list_records("malware_analysis"):
            status = str(analysis.get("status", "")).casefold()
            if status not in {"complete", "completed", "partial", "succeeded"}:
                continue
            module_name = "Malware Triage"
            completed[module_name] = completed.get(module_name, 0) + 1
            result = analysis.get("result")
            if isinstance(result, dict):
                warnings = result.get("warnings", [])
                if isinstance(warnings, list):
                    not_assessed[module_name] = not_assessed.get(module_name, 0) + len(warnings)
                verdict = str(result.get("verdict", "")).casefold()
                severity = {
                    "likely-malicious": "critical",
                    "suspicious": "high",
                }.get(verdict)
                if severity:
                    findings.setdefault(module_name, []).append(
                        {
                            "severity": severity,
                            "confidence": 0.8 if severity == "critical" else 0.65,
                            "age_days": 0.0,
                        }
                    )
        inputs: list[dict[str, Any]] = []
        for module_row in capabilities:
            name = str(module_row["name"])
            done = completed.get(name, 0)
            missing = module_row.get("not_assessed", [])
            unassessed_default = len(missing) if isinstance(missing, list) else 0
            unassessed = not_assessed.get(name, unassessed_default)
            inputs.append(
                {
                    "module": name,
                    "checks_completed": done,
                    "checks_total": done + unassessed,
                    "findings": findings.get(name, []),
                }
            )
        try:
            encoded = json.dumps(inputs, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            response = run_native_parser_worker("score", encoded)
            results = response.get("result")
            if not isinstance(results, list) or len(results) != len(inputs):
                raise WorkerFailure("Scoring worker returned an invalid result.")
            return [dict(result) for result in results if isinstance(result, dict)]
        except (WorkerFailure, ValueError, TypeError):
            return [
                self._unavailable_score(item) for item in inputs
            ]

    @staticmethod
    def _unavailable_score(item: dict[str, Any]) -> dict[str, Any]:
        completed = int(item.get("checks_completed", 0) or 0)
        total = max(completed, int(item.get("checks_total", completed) or 0))
        not_assessed = total - completed
        coverage = completed / total if total else 0.0
        coverage_penalty = 50.0 * (1.0 - coverage)
        breakdown: list[dict[str, Any]] = []
        raw_findings = item.get("findings", [])
        for finding in raw_findings if isinstance(raw_findings, list) else []:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity", "info")).casefold()
            confidence = min(1.0, max(0.0, float(finding.get("confidence", 0.55))))
            age = max(0.0, float(finding.get("age_days", 0.0)))
            decay = 2.0 ** (-age / 60.0)
            weight = SEVERITY_WEIGHT.get(severity, 0.0)
            breakdown.append(
                {
                    "severity": severity,
                    "severity_weight": weight,
                    "confidence": confidence,
                    "age_days": age,
                    "decay_factor": decay,
                    "penalty": weight * confidence * decay,
                    "explanation": (
                        f"{severity} severity × {confidence:.2f} confidence × "
                        f"{decay:.3f} 60-day half-life decay"
                    ),
                }
            )
        finding_penalty = min(100.0, sum(item["penalty"] for item in breakdown))
        return {
            "module": item["module"],
            "score": None,
            "checks_completed": completed,
            "checks_total": total,
            "checks_not_assessed": not_assessed,
            "coverage_fraction": coverage,
            "coverage_penalty": coverage_penalty,
            "finding_penalty": finding_penalty,
            "findings": breakdown,
            "formula": SCORE_FORMULA,
            "inputs": {**item, "reason": "scoring_worker_unavailable"},
            "why_this_score": (
                "Not scored: the isolated scoring engine is unavailable. "
                f"Based on {completed} checks, {not_assessed} not assessed."
            ),
        }

    def refresh_alerts(
        self, extra_signals: list[dict[str, str]] | None = None
    ) -> list[dict[str, Any]]:
        repeated_signals = list(extra_signals or [])
        signals = list(repeated_signals)
        for finding in self.repository.list_records("finding"):
            if str(finding.get("severity", "")).casefold() == "critical":
                identifier = str(finding.get("finding_id", ""))[:255]
                if identifier:
                    signals.append(
                        {
                            "key": "critical:" + identifier,
                            "kind": "critical_finding",
                            "summary": "A critical finding was recorded for a local assessment.",
                            "module": _module_for_scanner(str(finding.get("scanner", ""))),
                        }
                    )
        for scan in self.repository.list_records("scan"):
            if str(scan.get("status", "")).casefold() in {"failed", "error", "scan_failed"}:
                identifier = str(scan.get("scan_id", ""))[:255]
                if identifier:
                    signals.append(
                        {
                            "key": "scan-failure:" + identifier,
                            "kind": "scan_failure",
                            "summary": "A local assessment did not complete successfully.",
                            "module": _module_for_scanner(str(scan.get("scanner", ""))),
                        }
                    )
        for analysis in self.repository.list_records("malware_analysis"):
            result = analysis.get("result") or {}
            if isinstance(result, dict) and (
                result.get("findings")
                or int(result.get("indicator_count", 0) or 0) > 0
                or str(result.get("verdict", "")).casefold() in {"likely-malicious", "malicious"}
            ):
                identifier = str(analysis.get("analysis_id", ""))[:255]
                if identifier:
                    signals.append(
                        {
                            "key": "malware-hit:" + identifier,
                            "kind": "malware_hit",
                            "summary": "Static malware triage produced one or more indicators.",
                            "module": "Malware Triage",
                        }
                    )
        for record in self.repository.list_records("authorization_guard_block"):
            identifier = str(record.get("event_id", record.get("record_id", "")))[:255]
            if identifier:
                signals.append(
                    {
                        "key": "authorization-block:" + identifier,
                        "kind": "authorization_block",
                        "summary": "A local authorization guard blocked an operation.",
                        "module": str(record.get("module", "Security Dashboard"))[:80],
                    }
                )
        if not signals:
            return []
        try:
            response = run_native_parser_worker(
                "alert-rules", json.dumps(signals, separators=(",", ":")).encode("utf-8")
            )
            results = response.get("result")
            if not isinstance(results, list):
                return []
        except (WorkerFailure, ValueError, TypeError):
            return []
        repeated_keys = {signal.get("key") for signal in repeated_signals}
        return [
            self.alerts.create_once(
                item,
                count_duplicate=any(
                    str(item["fingerprint"]).endswith(":" + str(key))
                    for key in repeated_keys
                    if key
                ),
            )
            for item in results
            if isinstance(item, dict) and item.get("fingerprint")
        ]

    @staticmethod
    def repeated_auth_signal(scope_key: str) -> dict[str, str]:
        digest = hashlib.sha256(scope_key.encode("utf-8", errors="replace")).hexdigest()[:32]
        return {
            "key": "auth-failures:" + digest,
            "kind": "repeated_auth_failure",
            "summary": "Repeated unsuccessful local sign-in attempts were observed.",
            "module": "Security Dashboard",
        }
