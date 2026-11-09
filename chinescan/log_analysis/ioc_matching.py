"""Local parsing and matching for caller-supplied indicators of compromise."""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import uuid
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from chinescan.core.logging.redaction import redact
from chinescan.core.models.common import Confidence, Severity
from chinescan.core.models.investigation import Alert, Event, Indicator
from chinescan.log_analysis.detections import make_alert

MAX_IOC_FILE_BYTES = 10_000_000
MAX_INDICATORS = 10_000
MAX_IOC_COMPARISONS = 5_000_000
MAX_EXTRACTED_IOCS = 10_000
_HASH = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_URL_IN_TEXT = re.compile(r"https?://[^\s\x00<>\"']{1,2048}", re.I)
_DOMAIN_IN_TEXT = re.compile(
    r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9.-])",
    re.I,
)


@dataclass
class IOCResult:
    events: list[Event]
    indicators: list[Indicator]
    alerts: list[Alert]
    errors: list[str]


def load_iocs(path: Path | None) -> tuple[list[Indicator], list[str]]:
    """Load newline text, CSV, or JSON indicators without network enrichment."""
    if path is None:
        return [], []
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_IOC_FILE_BYTES:
        return [], [f"{path}: indicator file missing or exceeds safety limits"]
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        return [], [f"{path}: indicator file could not be read"]
    rows: list[dict[str, Any]] = []
    try:
        if path.suffix.lower() == ".json":
            document = json.loads(text)
            if isinstance(document, dict):
                document = document.get("indicators", [document])
            if not isinstance(document, list):
                raise ValueError("expected JSON array")
            rows = [item for item in document if isinstance(item, dict)]
        elif path.suffix.lower() == ".csv":
            rows = list(csv.DictReader(text.splitlines()))
        else:
            for line in text.splitlines():
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                if ":" in value and value.split(":", 1)[0].lower() in {
                    "ip",
                    "ipv4",
                    "ipv6",
                    "domain",
                    "url",
                    "hash",
                    "sha256",
                    "email",
                    "user_agent",
                }:
                    kind, value = value.split(":", 1)
                    rows.append({"kind": kind, "value": value.strip()})
                else:
                    rows.append({"value": value})
    except (json.JSONDecodeError, csv.Error, ValueError, RecursionError):
        return [], [f"{path}: malformed indicator file"]
    indicators: dict[tuple[str, str], Indicator] = {}
    errors: list[str] = []
    for index, row in enumerate(rows[:MAX_INDICATORS], start=1):
        value = str(row.get("value", "")).strip()
        explicit_kind = str(row.get("kind", row.get("type", row.get("indicator_type", "")))).lower()
        inferred = _normalize_ioc(value, explicit_kind)
        if inferred is None:
            errors.append(f"{path}: invalid indicator at row {index}")
            continue
        kind, normalized = inferred
        indicators[(kind, normalized)] = Indicator(
            indicator_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"ioc:{kind}:{normalized}")),
            kind=kind,
            value=normalized,
            source=str(row.get("source", path.name))[:200],
            context=str(row.get("context", ""))[:500],
            confidence=0.8,
        )
    if len(rows) > MAX_INDICATORS:
        errors.append(f"{path}: indicator count limit reached")
    return list(indicators.values()), errors


def correlate_iocs(events: list[Event], indicators: list[Indicator]) -> IOCResult:
    """Match local IOC values against selected normalized fields and attach event IDs."""
    if len(events) * len(indicators) > MAX_IOC_COMPARISONS:
        return IOCResult(
            events,
            indicators,
            [],
            ["IOC comparison limit reached; local indicator matching was skipped"],
        )
    hits: dict[str, list[Event]] = defaultdict(list)
    updated_events: list[Event] = []
    for event in events:
        matched: list[str] = []
        for indicator in indicators:
            if _event_matches(event, indicator):
                matched.append(indicator.indicator_id)
                hits[indicator.indicator_id].append(event)
        updated_events.append(event.model_copy(update={"indicator_matches": sorted(matched)}))
    updated_indicators: list[Indicator] = []
    alerts: list[Alert] = []
    for indicator in indicators:
        matching_events = hits.get(indicator.indicator_id, [])
        times = [event.occurred_at for event in matching_events]
        updated_indicators.append(
            indicator.model_copy(
                update={
                    "related_events": sorted(event.event_id for event in matching_events),
                    "first_seen": min(times) if times else None,
                    "last_seen": max(times) if times else None,
                    "occurrence_count": len(matching_events),
                }
            )
        )
        if matching_events:
            alert = make_alert(
                rule_id="CHINESCAN-IOC-001",
                title=f"Local IOC match ({indicator.kind})",
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                events=matching_events,
                description="An event matched an operator-supplied local indicator.",
                indicator_ids=[indicator.indicator_id],
            )
            alerts.append(alert)
    return IOCResult(updated_events, updated_indicators, alerts, [])


def extract_event_iocs(events: Iterable[Event]) -> list[Indicator]:
    """Extract bounded observable IOCs from normalized event fields, with counts and references."""
    occurrences: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        candidates: set[tuple[str, str]] = set()
        for value in (event.source_ip, event.destination_ip):
            if value:
                normalized = _normalize_ioc(value, "ip")
                if normalized:
                    candidates.add(normalized)
        if event.url:
            for match in _URL_IN_TEXT.finditer(event.url):
                normalized = _normalize_ioc(match.group().rstrip(".,);]}"), "url")
                if normalized:
                    candidates.add(normalized)
            for match in _DOMAIN_IN_TEXT.finditer(event.url):
                normalized = _normalize_ioc(match.group(), "domain")
                if normalized:
                    candidates.add(normalized)
        for value in (event.sha256, *event.file_hashes):
            if value:
                normalized = _normalize_ioc(value, "hash")
                if normalized:
                    candidates.add(normalized)
        if event.user_agent:
            value = str(redact(event.user_agent))[:300].strip()
            if value:
                candidates.add(("user_agent", value))
        for candidate in candidates:
            occurrences[candidate].append(event)
            if len(occurrences) >= MAX_EXTRACTED_IOCS:
                break
        if len(occurrences) >= MAX_EXTRACTED_IOCS:
            break

    indicators: list[Indicator] = []
    for (kind, value), matching in sorted(occurrences.items()):
        ordered = sorted(matching, key=lambda item: (item.occurred_at, item.event_id))
        indicators.append(
            Indicator(
                indicator_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"log-ioc:{kind}:{value}")),
                kind=kind,
                value=value,
                source="log_extraction",
                context=(
                    "Extracted from normalized log fields; no threat-intelligence lookup "
                    "was performed."
                ),
                first_seen=ordered[0].occurred_at,
                last_seen=ordered[-1].occurred_at,
                occurrence_count=len(ordered),
                related_events=sorted({event.event_id for event in ordered}),
            )
        )
    return indicators


def _normalize_ioc(value: str, kind: str = "") -> tuple[str, str] | None:
    lowered_kind = kind.casefold().replace("-", "_")
    value = value.strip()
    if lowered_kind in {"ip", "ipv4", "ipv6"} or not lowered_kind:
        try:
            return "ip", str(ipaddress.ip_address(value))
        except ValueError:
            if lowered_kind in {"ip", "ipv4", "ipv6"}:
                return None
    if lowered_kind in {"sha256", "hash", "md5", "sha1"} or not lowered_kind:
        if _HASH.fullmatch(value):
            return "hash", value.lower()
        if lowered_kind in {"sha256", "hash", "md5", "sha1"}:
            return None
    if lowered_kind == "url" or (
        not lowered_kind and value.lower().startswith(("http://", "https://"))
    ):
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            username = parsed.username
            password = parsed.password
            port = parsed.port
        except ValueError:
            return None
        if (
            parsed.scheme.lower() in {"http", "https"}
            and hostname
            and not username
            and not password
        ):
            netloc = hostname.lower()
            if port:
                netloc += f":{port}"
            return "url", urlunsplit((parsed.scheme.lower(), netloc, parsed.path, parsed.query, ""))
        return None
    if lowered_kind in {"domain", "hostname"} or (not lowered_kind and _DOMAIN.fullmatch(value)):
        try:
            domain = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        return ("domain", domain) if _DOMAIN.fullmatch(domain) else None
    if lowered_kind in {"user_agent", "useragent"}:
        return "user_agent", value.casefold()
    if lowered_kind == "email":
        return ("email", value.casefold()) if "@" in value else None
    return None


def _event_matches(event: Event, indicator: Indicator) -> bool:
    if indicator.kind == "ip":
        for value in (event.source_ip, event.destination_ip):
            try:
                if value and str(ipaddress.ip_address(value)) == indicator.value:
                    return True
            except ValueError:
                continue
        return False
    if indicator.kind == "hash":
        return indicator.value in {
            (event.sha256 or "").casefold(),
            *(value.casefold() for value in event.file_hashes),
        }
    if indicator.kind == "url":
        return _normalize_ioc(event.url or "", "url") == ("url", indicator.value)
    if indicator.kind == "domain":
        try:
            url_host = urlsplit(event.url or "").hostname or ""
        except ValueError:
            url_host = ""
        normalized_host = url_host.casefold().rstrip(".")
        return (
            normalized_host == indicator.value
            or normalized_host.endswith("." + indicator.value)
            or any(
                value
                and (
                    value.casefold().rstrip(".") == indicator.value
                    or value.casefold().rstrip(".").endswith("." + indicator.value)
                )
                for value in (event.host,)
            )
        )
    if indicator.kind == "user_agent":
        return indicator.value in (event.user_agent or "").casefold()
    if indicator.kind == "email":
        return indicator.value in " ".join(filter(None, (event.user, event.summary))).casefold()
    return False
