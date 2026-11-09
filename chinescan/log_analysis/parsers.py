"""Small, dependency-light parsers for common exported security log formats."""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any
from xml.parsers import expat

from chinescan.core.models.investigation import Event
from chinescan.log_analysis.normalization import normalize_record

MAX_LINE_BYTES = 1_000_000
MAX_RECORDS_PER_SOURCE = 100_000
MAX_LINES_PER_SOURCE = 200_000
_ACCESS = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<date>[^]]+)\] "
    r'"(?P<request>[^\"]*)" (?P<status>\d{3}) \S+(?: "[^\"]*" "(?P<agent>[^\"]*)")?'
)
_AUTH_PATTERNS = (
    (
        re.compile(
            r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        "authentication_failure",
        "failure",
    ),
    (
        re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
        "authentication_failure",
        "failure",
    ),
    (
        re.compile(
            r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        "authentication_success",
        "success",
    ),
    (
        re.compile(r"sudo: +(?P<user>\S+) : .*COMMAND=(?P<command>.+)"),
        "privilege_escalation",
        "success",
    ),
)
_SYSLOG = re.compile(
    r"^(?P<date>[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d) "
    r"(?P<host>\S+) (?P<process>[^:[]+)(?:\[\d+\])?: (?P<message>.*)$"
)
_CEF_SYSLOG = re.compile(
    r"^(?P<date>[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d) "
    r"(?P<host>\S+) (?P<cef>CEF:\d+\|.*)$"
)


@dataclass
class ParseBatch:
    """Valid normalized events and safe, source-referenced parser diagnostics."""

    events: list[Event] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def parse_log_data(data: bytes, name: str, source_ref: str) -> ParseBatch:
    """Parse one bounded file or archive member without preserving raw lines."""
    suffix = PurePosixPath(name.lower()).suffix
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return ParseBatch(errors=[f"{source_ref}: invalid UTF-8 input"])
    if suffix in {".json", ".jsonl", ".ndjson"}:
        return _parse_json(text, suffix, source_ref)
    if suffix == ".csv":
        return _parse_csv(text, source_ref)
    if suffix == ".xml":
        return _parse_windows_event_xml(text, source_ref)
    iis_batch = _parse_iis_access(text, source_ref)
    if iis_batch is not None:
        return iis_batch
    batch = ParseBatch()
    for line_number, line in enumerate(io.StringIO(text), start=1):
        if line_number > MAX_LINES_PER_SOURCE:
            batch.errors.append(f"{source_ref}: line count limit reached")
            break
        if len(batch.events) >= MAX_RECORDS_PER_SOURCE:
            batch.errors.append(f"{source_ref}: event count limit reached")
            break
        ref = f"{source_ref}:{line_number}"
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            batch.errors.append(f"{ref}: line exceeds size limit")
            continue
        if not line.strip():
            continue
        try:
            event = _parse_cef(line, ref)
            if event is None:
                event = _parse_leef(line, ref)
            if event is None:
                event = _parse_access(line, ref)
            if event is None:
                event = _parse_auth_or_syslog(line, ref)
        except (TypeError, ValueError):
            event = None
        if event is None:
            batch.errors.append(f"{ref}: malformed or unsupported log line")
        else:
            batch.events.append(event)
    return batch


def _parse_json(text: str, suffix: str, source_ref: str) -> ParseBatch:
    batch = ParseBatch()
    if suffix == ".json":
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            parsed = None
        if parsed is not None:
            values = parsed if isinstance(parsed, list) else [parsed]
            for index, item in enumerate(values, start=1):
                if len(batch.events) >= MAX_RECORDS_PER_SOURCE:
                    batch.errors.append(f"{source_ref}: event count limit reached")
                    break
                batch.events.extend(_json_item(item, source_ref, index, batch))
            return batch
    for line_number, line in enumerate(io.StringIO(text), start=1):
        if line_number > MAX_LINES_PER_SOURCE:
            batch.errors.append(f"{source_ref}: line count limit reached")
            break
        if len(batch.events) >= MAX_RECORDS_PER_SOURCE:
            batch.errors.append(f"{source_ref}: event count limit reached")
            break
        ref = f"{source_ref}:{line_number}"
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            batch.errors.append(f"{ref}: line exceeds size limit")
            continue
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            batch.errors.append(f"{ref}: malformed JSON record")
            continue
        batch.events.extend(_json_item(item, source_ref, line_number, batch))
    return batch


def _json_item(
    item: Any, source_ref: str, line_number: int, batch: ParseBatch, depth: int = 0
) -> list[Event]:
    if depth > 4:
        batch.errors.append(f"{source_ref}:{line_number}: JSON nesting limit reached")
        return []
    if isinstance(item, dict) and isinstance(item.get("Records"), list):
        output: list[Event] = []
        for index, record in enumerate(item["Records"], start=1):
            if len(batch.events) + len(output) >= MAX_RECORDS_PER_SOURCE:
                batch.errors.append(f"{source_ref}:{line_number}: event count limit reached")
                break
            output.extend(_json_item(record, source_ref, index, batch, depth + 1))
        return output
    if not isinstance(item, dict):
        batch.errors.append(f"{source_ref}:{line_number}: expected a JSON object")
        return []
    try:
        event = normalize_record(
            item,
            source=_source_type(PurePosixPath(source_ref).name),
            raw_ref=f"{source_ref}:{line_number}",
        )
    except (TypeError, ValueError):
        batch.errors.append(f"{source_ref}:{line_number}: invalid normalized event fields")
        return []
    return [event]


def _parse_csv(text: str, source_ref: str) -> ParseBatch:
    batch = ParseBatch()
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if not reader.fieldnames:
            return ParseBatch(errors=[f"{source_ref}: CSV header is missing"])
        if _is_windows_event_csv(reader.fieldnames):
            return _parse_windows_event_csv(text, source_ref)
        for line_number, row in enumerate(reader, start=2):
            if len(batch.events) >= MAX_RECORDS_PER_SOURCE:
                batch.errors.append(f"{source_ref}: event count limit reached")
                break
            if None in row:
                batch.errors.append(f"{source_ref}:{line_number}: malformed CSV row")
                continue
            try:
                event = normalize_record(
                    dict(row),
                    source=_source_type(PurePosixPath(source_ref).name),
                    raw_ref=f"{source_ref}:{line_number}",
                )
            except (TypeError, ValueError):
                batch.errors.append(f"{source_ref}:{line_number}: invalid normalized event fields")
                continue
            batch.events.append(event)
    except csv.Error:
        batch.errors.append(f"{source_ref}: malformed CSV input")
    return batch


def _is_windows_event_csv(fieldnames: Sequence[str | None]) -> bool:
    normalized = {re.sub(r"[^a-z0-9]", "", (name or "").casefold()) for name in fieldnames}
    timestamp_fields = {"timecreated", "systemtime", "timestamp", "dateandtime", "datetime", "time"}
    return "eventid" in normalized and bool(normalized & timestamp_fields)


def _windows_event_kind(event_id: str) -> tuple[str, str | None, str]:
    messages = {
        "4624": ("authentication_success", "success", "logon succeeded"),
        "4625": ("authentication_failure", "failure", "logon failed"),
        "4634": ("session_ended", None, "logoff"),
        "4648": ("explicit_credentials", None, "explicit credentials used"),
        "4672": ("privilege_change", "success", "special privileges assigned"),
        "1102": ("log_cleared", "success", "security audit log cleared"),
        "4720": ("user_created", "success", "user created"),
        "4722": ("user_enabled", "success", "user account enabled"),
        "4724": ("password_reset", "success", "password reset attempted"),
        "4726": ("user_deleted", "success", "user account deleted"),
        "4728": ("privilege_change", "success", "user added to a security group"),
        "4732": ("privilege_change", "success", "user added to a local security group"),
        "4756": ("privilege_change", "success", "user added to a universal security group"),
    }
    return messages.get(
        event_id, (f"windows_event_{event_id or 'unknown'}", None, "event recorded")
    )


def _event_record(record: dict[str, Any], source_ref: str, line_number: int) -> Event:
    event_id = str(record.get("event_id") or "")
    kind, outcome, action = _windows_event_kind(event_id)
    user = record.get("target_user") or record.get("subject_user")
    group = record.get("target_group") or record.get("group_name")
    details = " ".join(str(value) for value in (user, group) if value)
    summary = f"Windows Event {event_id}: {action}"
    if details:
        summary += f" ({details})"
    normalized: dict[str, Any] = {
        "occurred_at": record.get("occurred_at"),
        "kind": event_id or kind,
        "summary": summary,
        "source_ip": record.get("source_ip"),
        "destination_ip": record.get("destination_ip"),
        "user": user,
        "actor": record.get("subject_user"),
        "target": record.get("target_user"),
        "target_group": group,
        "host": record.get("host"),
        "process": record.get("process"),
        "command_line": record.get("command_line"),
        "file": record.get("file"),
        "event_outcome": outcome or record.get("event_outcome"),
    }
    return normalize_record(
        normalized,
        source="windows_event_export",
        raw_ref=f"{source_ref}:{line_number}",
    )


def _parse_windows_event_csv(text: str, source_ref: str) -> ParseBatch:
    batch = ParseBatch()
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        for line_number, row in enumerate(reader, start=2):
            if line_number > MAX_LINES_PER_SOURCE:
                batch.errors.append(f"{source_ref}: line count limit reached")
                break
            if len(batch.events) >= MAX_RECORDS_PER_SOURCE:
                batch.errors.append(f"{source_ref}: event count limit reached")
                break
            if None in row:
                batch.errors.append(f"{source_ref}:{line_number}: malformed CSV row")
                continue
            values = {
                re.sub(r"[^a-z0-9]", "", (key or "").casefold()): value
                for key, value in row.items()
            }
            event_id = values.get("eventid", "")
            kind, outcome, action = _windows_event_kind(event_id)
            target_user = values.get("targetusername") or values.get("accountname")
            subject_user = values.get("subjectusername") or values.get("username")
            group = values.get("targetgroupname") or values.get("groupname")
            member_user = values.get("membername") or values.get("member")
            if event_id in {"4728", "4732", "4756"}:
                group = group or target_user
                target_user = member_user or values.get("membername") or values.get("member")
                if target_user and target_user.casefold().startswith("cn="):
                    target_user = target_user[3:].split(",", maxsplit=1)[0]
            summary = f"Windows Event {event_id}: {action}"
            details = " ".join(
                str(value) for value in (target_user or subject_user, group) if value
            )
            if details:
                summary += f" ({details})"
            record = {
                "occurred_at": (
                    values.get("timecreated")
                    or values.get("systemtime")
                    or values.get("timestamp")
                    or values.get("dateandtime")
                    or values.get("datetime")
                    or values.get("time")
                ),
                "kind": event_id or kind,
                "summary": summary,
                "source_ip": values.get("ipaddress") or values.get("sourceipaddress"),
                "destination_ip": values.get("destinationipaddress"),
                "user": target_user or subject_user,
                "actor": subject_user,
                "target": target_user,
                "target_group": group,
                "host": values.get("computer") or values.get("computername"),
                "process": values.get("processname") or values.get("newprocessname"),
                "command_line": values.get("commandline") or values.get("processcommandline"),
                "file": values.get("targetfilename") or values.get("filename"),
                "event_outcome": outcome or values.get("level"),
            }
            try:
                batch.events.append(
                    normalize_record(
                        record,
                        source="windows_event_export",
                        raw_ref=f"{source_ref}:{line_number}",
                    )
                )
            except (TypeError, ValueError):
                batch.errors.append(f"{source_ref}:{line_number}: invalid Windows event fields")
    except csv.Error:
        batch.errors.append(f"{source_ref}: malformed CSV input")
    return batch


def _parse_windows_event_xml(text: str, source_ref: str) -> ParseBatch:
    batch = ParseBatch()
    lines = text.splitlines()
    if len(lines) > MAX_LINES_PER_SOURCE:
        return ParseBatch(errors=[f"{source_ref}: line count limit reached"])
    for number, line in enumerate(lines, start=1):
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            return ParseBatch(errors=[f"{source_ref}:{number}: line exceeds size limit"])

    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    current: dict[str, Any] | None = None
    current_line = 1
    capture_tag: str | None = None
    capture_name: str | None = None
    capture_text: list[str] = []
    found_event = False

    def reject_doctype(*_args: object) -> None:
        raise ValueError("DTD and entity declarations are not accepted in Windows event XML")

    parser.StartDoctypeDeclHandler = reject_doctype
    parser.EntityDeclHandler = reject_doctype
    parser.ExternalEntityRefHandler = lambda *_args: 0

    def local_name(value: str) -> str:
        return value.rsplit("}", 1)[-1].rsplit(":", 1)[-1].casefold()

    def start(tag: str, attributes: dict[str, str]) -> None:
        nonlocal current, current_line, capture_tag, capture_name, capture_text, found_event
        element = local_name(tag)
        attrs = {local_name(key): value for key, value in attributes.items()}
        if element == "event":
            current = {"data": {}}
            current_line = parser.CurrentLineNumber
            found_event = True
        elif current is not None:
            if element == "provider":
                current["provider"] = attrs.get("name")
            elif element == "timecreated":
                current["occurred_at"] = attrs.get("systemtime")
            elif element == "security":
                current["subject_user"] = attrs.get("userid")
            elif element == "data":
                capture_tag = element
                capture_name = attrs.get("name", "").casefold()
                capture_text = []
            elif element in {"eventid", "computer", "eventrecordid"}:
                capture_tag = element
                capture_name = None
                capture_text = []

    def characters(value: str) -> None:
        if capture_tag:
            capture_text.append(value)

    def end(tag: str) -> None:
        nonlocal current, capture_tag, capture_name, capture_text
        element = local_name(tag)
        if current is not None and capture_tag == element:
            value = "".join(capture_text).strip()
            if capture_tag == "data":
                data = current["data"]
                if isinstance(data, dict) and capture_name:
                    data[capture_name] = value
            else:
                current[element] = value
            capture_tag = None
            capture_name = None
            capture_text = []
        if element == "event" and current is not None:
            data = current.pop("data", {})
            if not isinstance(data, dict):
                data = {}
            event_id = str(current.get("eventid", ""))
            member_user = data.get("membername") or data.get("member")
            if member_user and member_user.casefold().startswith("cn="):
                member_user = member_user[3:].split(",", maxsplit=1)[0]
            try:
                if len(batch.events) >= MAX_RECORDS_PER_SOURCE:
                    raise OverflowError
                batch.events.append(
                    _event_record(
                        {
                            "event_id": event_id,
                            "occurred_at": current.get("occurred_at"),
                            "target_user": (
                                member_user
                                if event_id in {"4728", "4732", "4756"}
                                else data.get("targetusername") or data.get("accountname")
                            ),
                            "subject_user": data.get("subjectusername")
                            or current.get("subject_user"),
                            "target_group": (
                                data.get("targetgroupname")
                                or data.get("groupname")
                                or (
                                    data.get("targetusername")
                                    if event_id in {"4728", "4732", "4756"}
                                    else None
                                )
                            ),
                            "source_ip": data.get("ipaddress") or data.get("sourceipaddress"),
                            "destination_ip": data.get("destinationipaddress"),
                            "host": current.get("computer"),
                            "process": data.get("processname") or data.get("newprocessname"),
                            "command_line": data.get("commandline"),
                            "file": data.get("targetfilename") or data.get("filename"),
                        },
                        source_ref,
                        current_line,
                    )
                )
            except OverflowError:
                batch.errors.append(f"{source_ref}:{current_line}: event count limit reached")
            except (TypeError, ValueError):
                batch.errors.append(f"{source_ref}:{current_line}: invalid Windows event fields")
            current = None

    parser.StartElementHandler = start
    parser.CharacterDataHandler = characters
    parser.EndElementHandler = end
    try:
        parser.Parse(text, True)
    except (expat.ExpatError, ValueError):
        return ParseBatch(errors=[f"{source_ref}: malformed or unsafe Windows Event XML"])
    if not found_event:
        return ParseBatch(errors=[f"{source_ref}: no Windows Event records found in XML export"])
    return batch


def _parse_access(line: str, ref: str) -> Event | None:
    match = _ACCESS.match(line)
    if not match:
        return None
    fields = match.groupdict()
    request = fields["request"].split()
    target = request[1] if len(request) > 1 else ""
    path = target.split("?", maxsplit=1)[0]
    suspicious = _suspicious_web_kind(target)
    try:
        occurred_at = datetime.strptime(fields["date"].split()[0], "%d/%b/%Y:%H:%M:%S").replace(
            tzinfo=UTC
        )
    except ValueError:
        occurred_at = datetime.now(UTC)
    status = fields["status"]
    return normalize_record(
        {
            "timestamp": occurred_at,
            "event_type": suspicious[0] if suspicious else "web_request",
            "message": suspicious[1] if suspicious else "Web request",
            "source_ip": fields["ip"],
            "user": None if fields["user"] == "-" else fields["user"],
            "request_uri": path,
            "status_code": status,
            "user_agent": fields.get("agent"),
        },
        source="web_access",
        raw_ref=ref,
    )


def _parse_iis_access(text: str, source_ref: str) -> ParseBatch | None:
    fields: list[str] | None = None
    batch = ParseBatch()
    saw_fields = False
    for line_number, line in enumerate(io.StringIO(text), start=1):
        if line_number > MAX_LINES_PER_SOURCE:
            batch.errors.append(f"{source_ref}: line count limit reached")
            break
        if len(batch.events) >= MAX_RECORDS_PER_SOURCE:
            batch.errors.append(f"{source_ref}: event count limit reached")
            break
        ref = f"{source_ref}:{line_number}"
        if line.startswith("#Fields:"):
            fields = line[len("#Fields:") :].strip().split()
            saw_fields = True
            continue
        if not line.strip() or line.startswith("#"):
            continue
        if fields is None:
            return None
        values = line.split()
        if len(values) != len(fields):
            batch.errors.append(f"{ref}: malformed IIS W3C row")
            continue
        row = dict(zip(fields, values, strict=True))
        path = row.get("cs-uri-stem", "")
        query = row.get("cs-uri-query", "")
        target = path + (f"?{query}" if query not in {"", "-"} else "")
        suspicious = _suspicious_web_kind(target)
        try:
            timestamp = datetime.fromisoformat(f"{row['date']}T{row['time']}+00:00")
        except (KeyError, ValueError):
            batch.errors.append(f"{ref}: malformed IIS timestamp")
            continue
        batch.events.append(
            normalize_record(
                {
                    "timestamp": timestamp,
                    "event_type": suspicious[0] if suspicious else "web_request",
                    "message": suspicious[1] if suspicious else "Web request",
                    "source_ip": row.get("c-ip"),
                    "username": row.get("cs-username"),
                    "url": path,
                    "status_code": row.get("sc-status"),
                    "user_agent": row.get("cs(User-Agent)"),
                },
                source="web_access",
                raw_ref=ref,
            )
        )
    return batch if saw_fields else None


def _suspicious_web_kind(target: str) -> tuple[str, str] | None:
    lowered = target.casefold()
    return next(
        (
            (kind, description)
            for needle, kind, description in (
                ("union select", "web_sqli_candidate", "SQL injection pattern candidate"),
                ("union%20select", "web_sqli_candidate", "SQL injection pattern candidate"),
                ("<script", "web_xss_candidate", "Cross-site scripting pattern candidate"),
                ("%3cscript", "web_xss_candidate", "Cross-site scripting pattern candidate"),
                ("../", "web_traversal_candidate", "Path traversal pattern candidate"),
                ("%2e%2e", "web_traversal_candidate", "Path traversal pattern candidate"),
            )
            if needle in lowered
        ),
        None,
    )


def _parse_auth_or_syslog(line: str, ref: str) -> Event | None:
    match = _SYSLOG.match(line)
    if not match:
        return None
    fields = match.groupdict()
    try:
        occurred_at = datetime.strptime(fields["date"], "%b %d %H:%M:%S").replace(
            year=datetime.now(UTC).year, tzinfo=UTC
        )
    except ValueError:
        occurred_at = datetime.now(UTC)
    message = fields["message"]
    for pattern, kind, outcome in _AUTH_PATTERNS:
        auth = pattern.search(message)
        if auth:
            values = auth.groupdict()
            return normalize_record(
                {
                    "timestamp": occurred_at,
                    "event_type": kind,
                    "message": kind.replace("_", " ").title(),
                    "source_ip": values.get("ip"),
                    "username": values.get("user"),
                    "hostname": fields["host"],
                    "process_name": fields["process"].strip(),
                    "command_line": values.get("command"),
                    "outcome": outcome,
                },
                source="linux_auth",
                raw_ref=ref,
            )
    return normalize_record(
        {
            "timestamp": occurred_at,
            "event_type": "system_log",
            "message": "System log event",
            "hostname": fields["host"],
            "process_name": fields["process"].strip(),
        },
        source="syslog",
        raw_ref=ref,
    )


def _parse_cef(line: str, ref: str) -> Event | None:
    syslog = _CEF_SYSLOG.match(line)
    syslog_timestamp: datetime | None = None
    syslog_host: str | None = None
    if syslog:
        syslog_fields = syslog.groupdict()
        line = syslog_fields["cef"]
        syslog_host = syslog_fields["host"]
        try:
            syslog_timestamp = datetime.strptime(syslog_fields["date"], "%b %d %H:%M:%S").replace(
                year=datetime.now(UTC).year, tzinfo=UTC
            )
        except ValueError:
            return None
    if not line.startswith("CEF:"):
        return None
    fields = _split_cef_fields(line)
    if len(fields) < 7 or not re.fullmatch(r"CEF:\d+", fields[0]):
        return None
    header = [_unescape_cef(value) for value in fields[:7]]
    extension_text = fields[7] if len(fields) > 7 else ""
    extension = {
        key: _unescape_cef(value) for key, value in _parse_cef_extension(extension_text).items()
    }
    return normalize_record(
        {
            "timestamp": syslog_timestamp,
            "event_type": header[4],
            "message": extension.get("msg") or header[5],
            "source_ip": extension.get("src"),
            "destination_ip": extension.get("dst"),
            "username": extension.get("suser") or extension.get("duser"),
            "hostname": extension.get("dvchost") or extension.get("dhost") or syslog_host,
            "url": extension.get("request"),
        },
        source="cef",
        raw_ref=ref,
    )


def _parse_leef(line: str, ref: str) -> Event | None:
    if not line.startswith("LEEF:"):
        return None
    parts = line.split("|", maxsplit=6)
    if parts[0] == "LEEF:2.0":
        if len(parts) != 7:
            return None
        delimiter = _leef_delimiter(parts[5])
        if delimiter is None:
            return None
        extension_text = parts[6]
    elif parts[0] == "LEEF:1.0":
        if len(parts) < 6:
            return None
        delimiter = "\t"
        extension_text = parts[5]
    else:
        return None
    extension: dict[str, str] = {}
    for token in extension_text.split(delimiter):
        key, separator, value = token.partition("=")
        if separator and key.strip():
            extension[key.strip()] = value
    return normalize_record(
        {
            **extension,
            "event_type": extension.get("cat") or parts[4],
            "message": extension.get("msg") or parts[4],
            "timestamp": extension.get("devTime"),
        },
        source="leef",
        raw_ref=ref,
    )


def _split_cef_fields(line: str) -> list[str]:
    """Split the seven CEF header separators while honoring escaped pipes."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line:
        if character == "|" and not escaped and len(fields) < 7:
            fields.append("".join(current))
            current = []
            continue
        current.append(character)
        if character == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
    fields.append("".join(current))
    return fields


def _parse_cef_extension(extension: str) -> dict[str, str]:
    """Parse CEF key/value fields whose values may contain spaces."""
    starts = list(re.finditer(r"(?:^|\s)([A-Za-z][A-Za-z0-9]*)=", extension))
    parsed: dict[str, str] = {}
    for index, match in enumerate(starts):
        value_end = starts[index + 1].start() if index + 1 < len(starts) else len(extension)
        key = match.group(1).casefold()
        parsed[key] = extension[match.end() : value_end].strip()
    return parsed


def _unescape_cef(value: str) -> str:
    """Decode CEF's escaped backslash, pipe, equals, and line breaks."""
    replacements = {"\\": "\\", "|": "|", "=": "=", "n": "\n", "r": "\r"}
    return re.sub(r"\\([\\|=nr])", lambda match: replacements[match.group(1)], value)


def _leef_delimiter(value: str) -> str | None:
    """Resolve the LEEF 2.0 delimiter field, including x/0x hex notation."""
    if len(value) == 1:
        return value
    match = re.fullmatch(r"(?:0x|x)([0-9A-Fa-f]{1,4})", value)
    if match is None:
        return None
    codepoint = int(match.group(1), 16)
    if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
        return None
    return chr(codepoint)


def _source_type(name: str) -> str:
    lower = name.lower()
    if "cloudtrail" in lower:
        return "cloud_audit"
    if "windows" in lower or "event" in lower or "security" in lower:
        return "windows_event_export"
    return "json" if lower.endswith((".json", ".jsonl", ".ndjson")) else "csv"
