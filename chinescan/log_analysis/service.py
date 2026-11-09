"""Orchestration for local log parsing, detection, correlation, and persistence."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from chinescan.core.logging.redaction import redact
from chinescan.core.models.investigation import Alert, Event, Indicator, Scan, Target, TimelineEntry
from chinescan.core.storage.repository import Repository
from chinescan.log_analysis.detections import (
    load_sigma_rules,
    run_builtin_detections,
    run_sigma_rules,
)
from chinescan.log_analysis.ingest import IngestResult, ingest_path
from chinescan.log_analysis.ioc_matching import correlate_iocs, extract_event_iocs, load_iocs


@dataclass
class LogAnalysisResult:
    """Privacy-conscious summary and persisted identifiers for one log analysis."""

    scan_id: str
    target: str
    events: int
    alerts: list[Alert]
    errors: list[str]
    source_count: int

    def summary(self) -> dict[str, object]:
        counts: dict[str, int] = {}
        for alert in self.alerts:
            counts[alert.severity.value] = counts.get(alert.severity.value, 0) + 1
        verdict_counts = {verdict: 0 for verdict in ("confirmed", "likely", "lead")}
        for alert in self.alerts:
            verdict_counts[alert.verdict.value] += 1
        return {
            "scan_id": self.scan_id,
            "source_count": self.source_count,
            "event_count": self.events,
            "alert_count": len(self.alerts),
            "severity_counts": counts,
            "verdict_counts": verdict_counts,
            "parse_error_count": len(self.errors),
            "alerts": [
                {
                    "alert_id": alert.alert_id,
                    "title": redact(alert.title),
                    "severity": alert.severity.value,
                    "rule_id": redact(alert.rule_id),
                    "event_count": len(alert.event_ids),
                    "verdict": alert.verdict.value,
                    "match_count": alert.match_count,
                    "first_match_ref": alert.first_match_ref,
                    "last_match_ref": alert.last_match_ref,
                    "log_limitations": alert.log_limitations,
                }
                for alert in self.alerts
            ],
        }


class LogAnalysisService:
    """Analyze bounded local log inputs and persist normalized records when configured."""

    def __init__(self, repository: Repository | None = None) -> None:
        self.repository = repository

    def analyze(
        self, path: Path, *, rules_path: Path | None = None, ioc_path: Path | None = None
    ) -> LogAnalysisResult:
        started = datetime.now(UTC)
        ingestion: IngestResult = ingest_path(path)
        errors = list(ingestion.errors)
        indicators, ioc_errors = load_iocs(ioc_path)
        errors.extend(ioc_errors)
        sigma_rules, sigma_load_errors = load_sigma_rules(rules_path)
        errors.extend(sigma_load_errors)

        correlated = correlate_iocs(ingestion.events, indicators)
        errors.extend(correlated.errors)
        events = correlated.events
        alerts = run_builtin_detections(events)
        sigma_alerts, sigma_errors = run_sigma_rules(events, sigma_rules)
        errors.extend(sigma_errors)
        alerts.extend(sigma_alerts)
        alerts.extend(correlated.alerts)
        alerts = _deduplicate_alerts(alerts)

        techniques_by_event: dict[str, set[str]] = {}
        for alert in alerts:
            for event_id in alert.event_ids:
                techniques_by_event.setdefault(event_id, set()).update(
                    alert.mitre_attack_techniques
                )
        events = [
            event.model_copy(
                update={
                    "mitre_attack_techniques": sorted(
                        set(event.mitre_attack_techniques)
                        | techniques_by_event.get(event.event_id, set())
                    )
                }
            )
            for event in events
        ]

        finished = datetime.now(UTC)
        scan_id = str(uuid.uuid4())
        target = str(path.expanduser().resolve())
        target_id = str(uuid.uuid5(uuid.NAMESPACE_URL, os.path.normcase(target)))
        timeline = [
            TimelineEntry(
                entry_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{scan_id}:{event.event_id}")),
                occurred_at=event.occurred_at,
                description=event.summary[:500],
                event_id=event.event_id,
                scan_id=scan_id,
            )
            for event in sorted(events, key=lambda item: (item.occurred_at, item.event_id))
        ]
        result = LogAnalysisResult(
            scan_id, target, len(events), alerts, errors, ingestion.source_count
        )
        if self.repository is not None:
            self._persist(
                scan_id=scan_id,
                target_id=target_id,
                target=target,
                started=started,
                finished=finished,
                events=events,
                alerts=alerts,
                timeline=timeline,
                indicators=[*correlated.indicators, *extract_event_iocs(events)],
                errors=errors,
                sources=sorted({event.source for event in events}),
            )
        return result

    def _persist(
        self,
        *,
        scan_id: str,
        target_id: str,
        target: str,
        started: datetime,
        finished: datetime,
        events: list[Event],
        alerts: list[Alert],
        timeline: list[TimelineEntry],
        indicators: list[Indicator],
        errors: list[str],
        sources: list[str],
    ) -> None:
        if self.repository is None:
            raise RuntimeError("repository is required to persist log analysis results")
        self.repository.save(
            "target", target_id, Target(value=target, kind="logs").model_dump(mode="json")
        )
        scan = Scan(
            scan_id=scan_id,
            target_id=target_id,
            scanner="chinescan-log-analysis",
            started_at=started,
            finished_at=finished,
            status="partial" if errors else "complete",
            project_types=sources,
            event_ids=[event.event_id for event in events],
            alert_ids=[alert.alert_id for alert in alerts],
            timeline_entry_ids=[entry.entry_id for entry in timeline],
            failures={f"parse_{index}": message for index, message in enumerate(errors, start=1)},
        )
        self.repository.save("scan", scan_id, scan.model_dump(mode="json"))
        for event in events:
            self.repository.save("event", event.event_id, event.model_dump(mode="json"))
        for alert in alerts:
            self.repository.save("alert", alert.alert_id, alert.model_dump(mode="json"))
        for entry in timeline:
            self.repository.save("timeline_entry", entry.entry_id, entry.model_dump(mode="json"))
        for indicator in indicators:
            self.repository.save(
                "indicator", indicator.indicator_id, indicator.model_dump(mode="json")
            )


def _deduplicate_alerts(alerts: list[Alert]) -> list[Alert]:
    unique = {alert.fingerprint: alert for alert in alerts}
    return sorted(
        unique.values(), key=lambda item: (item.severity.value, item.rule_id, item.alert_id)
    )
