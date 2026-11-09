"""Normalize common exported log fields into canonical events."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from chinescan.core.models.investigation import Event

_ALIASES: dict[str, tuple[str, ...]] = {
    "occurred_at": (
        "@timestamp",
        "timestamp",
        "eventtime",
        "eventtimestamp",
        "event_time",
        "systemtime",
        "devtime",
        "time",
        "date",
        "datetime",
    ),
    "kind": (
        "eventtype",
        "event_type",
        "eventid",
        "eventname",
        "event_name",
        "operationname",
        "methodname",
        "action",
        "activity",
        "type",
    ),
    "summary": ("message", "description", "eventmessage", "summary", "msg"),
    "source_ip": (
        "sourceip",
        "source_ip",
        "srcip",
        "src_ip",
        "src",
        "sourceipaddress",
        "clientip",
        "client_ip",
        "remote_addr",
        "ipaddress",
        "clientipaddress",
        "callerip",
        "calleripaddress",
    ),
    "destination_ip": (
        "destinationip",
        "destination_ip",
        "dstip",
        "dst_ip",
        "dst",
        "serverip",
        "server_ip",
    ),
    "user": (
        "username",
        "user_name",
        "usrname",
        "account",
        "targetusername",
        "subjectusername",
        "principalemail",
        "caller",
    ),
    "actor": (
        "actor",
        "subject",
        "subjectusername",
        "subject_user",
        "initiator",
        "initiatedby",
    ),
    "target": ("target", "targetuser", "targetusername", "accountname"),
    "target_group": ("targetgroup", "targetgroupname", "groupname"),
    "host": ("hostname", "computer", "computername", "host"),
    "process": ("processname", "process_name", "procname", "image", "newprocessname", "process"),
    "command_line": ("commandline", "processcommandline", "process_command_line", "command_line"),
    "file": ("filename", "filepath", "file_name", "file"),
    "sha256": ("sha256",),
    "file_hashes": ("hash", "filehash", "md5", "sha1", "file_hashes"),
    "url": ("request_uri", "requesturi", "uri", "url", "path"),
    "user_agent": ("useragent", "user_agent", "http_user_agent"),
    "event_outcome": (
        "outcome",
        "event_outcome",
        "result",
        "status",
        "status_code",
        "consolelogin",
        "loginresult",
        "authenticationresult",
    ),
    "direction": ("direction", "network_direction", "traffic_direction"),
    "bytes_out": ("bytes_out", "bytes_sent", "sent_bytes", "outbound_bytes"),
}
_FIELD_BY_ALIAS = {
    re.sub(r"[^a-z0-9]", "", alias.lower()): field
    for field, aliases in _ALIASES.items()
    for alias in (field, *aliases)
}
_SECRET = re.compile(r"(?i)(password|passwd|token|api[_-]?key|secret)(\s*[:=]\s*)([^\s,;]+)")


def normalize_record(
    record: dict[str, Any], *, source: str, raw_ref: str, fallback_time: datetime | None = None
) -> Event:
    """Map common field aliases to an Event without retaining unrecognized raw data."""
    values: dict[str, Any] = {}
    for key, value in _flatten_record(record).items():
        canonical = _FIELD_BY_ALIAS.get(re.sub(r"[^a-z0-9]", "", key.lower()))
        if canonical and value is not None and str(value).strip():
            if canonical == "file_hashes":
                existing = values.setdefault(canonical, [])
                hash_values = value if isinstance(value, list) else [value]
                existing.extend(hash_values)
            else:
                values.setdefault(canonical, value)
    occurred_at = _parse_time(values.get("occurred_at"), fallback_time)
    kind = _safe_text(values.get("kind") or "log_event", 100)
    summary = _safe_text(values.get("summary") or kind.replace("_", " ").title(), 500)
    event_fields: dict[str, Any] = {
        "occurred_at": occurred_at,
        "kind": kind.lower().replace(" ", "_"),
        "summary": summary,
        "source": _safe_text(source, 100),
        "raw_ref": raw_ref,
    }
    for field in _ALIASES:
        if field in {"occurred_at", "kind", "summary"}:
            continue
        value = values.get(field)
        if value is not None:
            if field == "file_hashes":
                hash_values = value if isinstance(value, list) else [value]
                event_fields[field] = [_safe_text(item, 200) for item in hash_values]
            else:
                event_fields[field] = _safe_text(value, 2000)
    identity = json.dumps(
        [raw_ref, event_fields],
        ensure_ascii=True,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    event_fields["event_id"] = str(
        uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(identity.encode()).hexdigest())
    )
    return Event(**event_fields)


def canonical_field_name(key: str) -> str:
    """Resolve a provider or Sigma field alias to a canonical Event field."""
    return _FIELD_BY_ALIAS.get(re.sub(r"[^a-z0-9]", "", key.lower()), key)


def _flatten_record(record: dict[str, Any]) -> dict[str, Any]:
    """Flatten provider-specific JSON detail dictionaries to the expected shallow depth."""
    flattened: dict[str, Any] = {}

    def add(mapping: dict[str, Any], depth: int = 0) -> None:
        for key, value in mapping.items():
            if isinstance(value, dict) and depth < 4:
                if str(key).casefold() == "status":
                    status = value.get("value", value.get("message"))
                    if status is not None:
                        flattened.setdefault("status", status)
                add(value, depth + 1)
            elif not isinstance(value, (dict, list)):
                flattened.setdefault(str(key), value)

    add(record)
    return flattened


def _parse_time(value: Any, fallback: datetime | None) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (float, int)):
        try:
            timestamp = float(value)
            if abs(timestamp) > 100_000_000_000:
                timestamp /= 1000
            parsed = datetime.fromtimestamp(timestamp, UTC)
        except (OverflowError, OSError, ValueError):
            parsed = fallback or datetime.now(UTC)
    elif isinstance(value, str):
        text = value.strip()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            parsed = fallback or datetime.now(UTC)
    else:
        parsed = fallback or datetime.now(UTC)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _safe_text(value: Any, limit: int) -> str:
    text = str(value).replace("\x00", "")[:limit]
    text = _SECRET.sub(r"\1\2[REDACTED]", text)
    return text
