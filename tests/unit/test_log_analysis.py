"""Fixture-driven tests for local log parsing, detections, correlation, and persistence."""

import gzip
import io
import json
import tarfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.models.common import Severity
from chinescan.core.models.investigation import Event, Indicator
from chinescan.log_analysis import detections as detections_module
from chinescan.log_analysis import ingest as ingest_module
from chinescan.log_analysis import ioc_matching as ioc_module
from chinescan.log_analysis.detections import (
    SigmaRule,
    load_sigma_rules,
    run_builtin_detections,
    run_sigma_rules,
)
from chinescan.log_analysis.ingest import ingest_path
from chinescan.log_analysis.ioc_matching import (
    correlate_iocs,
    extract_event_iocs,
    load_iocs,
)
from chinescan.log_analysis.normalization import normalize_record
from chinescan.log_analysis.parsers import parse_log_data
from chinescan.log_analysis.service import LogAnalysisService

runner = CliRunner()
FIXTURE_ROOT = Path(__file__).parents[2] / "fixtures" / "sample-logs"


def test_fixture_parsers_and_builtin_detections() -> None:
    ingested = ingest_path(FIXTURE_ROOT)
    assert ingested.source_count == 9
    assert not ingested.errors
    assert len(ingested.events) == 21
    sources = {event.source for event in ingested.events}
    assert {
        "linux_auth",
        "syslog",
        "web_access",
        "windows_event_export",
        "cloud_audit",
        "cef",
        "leef",
    } <= sources
    assert sum(event.kind == "authentication_failure" for event in ingested.events) == 5
    assert any(event.kind == "4625" for event in ingested.events)
    cloud_events = [event for event in ingested.events if event.source == "cloud_audit"]
    assert len(cloud_events) == 3
    assert {event.source_ip for event in cloud_events} == {
        "198.51.100.25",
        "198.51.100.26",
        "198.51.100.27",
    }
    assert any(event.process == "powershell.exe" for event in ingested.events)
    assert any(event.url == "/search" for event in ingested.events)
    alerts = run_builtin_detections(ingested.events)
    rule_ids = {alert.rule_id for alert in alerts}
    assert {
        "CHINESCAN-AUTH-001",
        "CHINESCAN-AUTH-002",
        "CHINESCAN-PRIV-001",
        "CHINESCAN-WEB-001",
        "CHINESCAN-PS-001",
        "CHINESCAN-LATERAL-001",
        "CHINESCAN-NET-001",
    } <= rule_ids
    assert all(alert.severity in Severity for alert in alerts)


def test_windows_event_csv_and_xml_normalize_target_user_and_physical_lines() -> None:
    csv_batch = parse_log_data(
        (
            b"EventID,TimeCreated,Computer,SubjectUserName,TargetUserName,IpAddress\n"
            b"4625,2026-11-09T10:00:00Z,WORKSTATION,SYSTEM,alice,203.0.113.9\n"
        ),
        "security.csv",
        "security.csv",
    )
    assert not csv_batch.errors
    csv_event = csv_batch.events[0]
    assert csv_event.kind == "4625"
    assert csv_event.source == "windows_event_export"
    assert csv_event.user == "alice"
    assert csv_event.actor == "SYSTEM"
    assert csv_event.target == "alice"
    assert csv_event.source_ip == "203.0.113.9"
    assert csv_event.host == "WORKSTATION"
    assert csv_event.event_outcome == "failure"
    assert csv_event.raw_ref == "security.csv:2"

    def record(event_id: str, timestamp: str, user: str) -> str:
        return (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
            "  <System>\n"
            '    <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
            f"    <EventID>{event_id}</EventID>\n"
            f'    <TimeCreated SystemTime="{timestamp}"/>\n'
            "    <Computer>WORKSTATION</Computer>\n"
            "  </System>\n"
            "  <EventData>\n"
            '    <Data Name="SubjectUserName">SYSTEM</Data>\n'
            f'    <Data Name="TargetUserName">{user}</Data>\n'
            '    <Data Name="IpAddress">203.0.113.9</Data>\n'
            "  </EventData>\n"
            "</Event>"
        )

    rows = [record("4625", f"2026-11-09T10:00:0{index}Z", "alice") for index in range(3)]
    rows.append(record("4624", "2026-11-09T10:00:04Z", "alice"))
    xml_batch = parse_log_data(
        ("<Events>\n" + "\n".join(rows) + "\n</Events>\n").encode(),
        "security.xml",
        "security.xml",
    )
    assert not xml_batch.errors
    assert len(xml_batch.events) == 4
    assert xml_batch.events[0].raw_ref == "security.xml:2"
    assert xml_batch.events[1].raw_ref == "security.xml:15"
    assert xml_batch.events[0].kind == "4625"
    assert xml_batch.events[-1].kind == "4624"
    assert xml_batch.events[0].user == "alice"
    assert xml_batch.events[0].actor == "SYSTEM"
    assert xml_batch.events[0].target == "alice"
    assert xml_batch.events[0].source_ip == "203.0.113.9"
    alerts = run_builtin_detections(xml_batch.events)
    brute_force = next(item for item in alerts if item.rule_id == "CHINESCAN-AUTH-002")
    assert brute_force.first_match_ref == "security.xml:2"
    assert brute_force.last_match_ref == "security.xml:41"
    assert brute_force.match_count == 4


def test_windows_event_xml_rejects_dtd_and_non_event_xml() -> None:
    dtd = (
        b'<!DOCTYPE Events [<!ENTITY x "4625">]>'
        b"<Events><Event><EventID>&x;</EventID></Event></Events>"
    )
    rejected = parse_log_data(dtd, "security.xml", "security.xml")
    assert not rejected.events
    assert rejected.errors == ["security.xml: malformed or unsafe Windows Event XML"]
    unsupported = parse_log_data(
        b"<config><value>true</value></config>", "security.xml", "security.xml"
    )
    assert not unsupported.events
    assert unsupported.errors == ["security.xml: no Windows Event records found in XML export"]


def test_oversized_plain_log_streams_bounded_prefix_and_reports_truncation(
    tmp_path: Path, monkeypatch
) -> None:
    first = b'192.0.2.1 - - [10/Oct/2000:13:55:36 -0700] "GET /first HTTP/1.1" 200 12 "-" "agent"\n'
    second = (
        b'192.0.2.2 - - [10/Oct/2000:13:55:37 -0700] "GET /second HTTP/1.1" 200 12 "-" "agent"\n'
    )
    path = tmp_path / "access.log"
    path.write_bytes(first + second)
    monkeypatch.setattr(ingest_module, "MAX_FILE_BYTES", len(first))

    result = ingest_path(path)
    assert len(result.events) == 1
    assert result.events[0].url == "/first"
    assert any(f"after reading {len(first)} bytes" in error for error in result.errors)
    assert any("remaining log data was not analyzed" in error for error in result.errors)


def test_log_at_exact_per_file_limit_is_not_reported_as_truncated(
    tmp_path: Path, monkeypatch
) -> None:
    line = b'192.0.2.1 - - [10/Oct/2000:13:55:36 -0700] "GET /only HTTP/1.1" 200 12 "-" "agent"\n'
    path = tmp_path / "access.log"
    path.write_bytes(line)
    monkeypatch.setattr(ingest_module, "MAX_FILE_BYTES", len(line))

    result = ingest_path(path)
    assert len(result.events) == 1
    assert not any("truncated after" in error for error in result.errors)


def test_password_spraying_and_scanner_user_agent_are_grouped_with_exact_refs() -> None:
    now = datetime.now(UTC)
    spray_events = [
        Event(
            occurred_at=now,
            kind="authentication_failure",
            summary="Authentication failed",
            source="linux_auth",
            source_ip="198.51.100.90",
            user=f"account-{index}",
            raw_ref=f"auth.log:{index + 1}",
        )
        for index in range(5)
    ]
    scanner_events = [
        Event(
            occurred_at=now,
            kind="http_request",
            summary="GET /robots.txt",
            source="web_access",
            source_ip="198.51.100.91",
            url="/robots.txt",
            user_agent="Nikto/2.5.0",
            raw_ref=f"access.log:{index + 1}",
        )
        for index in range(3)
    ]
    alerts = run_builtin_detections([*spray_events, *scanner_events])
    spray = next(alert for alert in alerts if alert.rule_id == "CHINESCAN-AUTH-003")
    scanner = next(alert for alert in alerts if alert.rule_id == "CHINESCAN-WEB-002")
    assert spray.verdict.value == "likely"
    assert spray.match_count == 5
    assert spray.first_match_ref == "auth.log:1"
    assert spray.last_match_ref == "auth.log:5"
    assert spray.remediation
    assert spray.verification_step
    assert spray.controls_considered
    assert spray.why_not_higher
    assert spray.what_would_raise_it
    assert scanner.match_count == 3
    assert scanner.first_match_ref == "access.log:1"
    assert scanner.last_match_ref == "access.log:3"
    assert scanner.project_impact
    assert scanner.log_limitations


def test_grouped_alert_line_evidence_uses_physical_order_not_event_time() -> None:
    now = datetime.now(UTC)
    events = [
        Event(
            occurred_at=now - timedelta(seconds=line),
            kind="http_request",
            summary="GET /robots.txt",
            source="web_access",
            source_ip="198.51.100.93",
            url="/robots.txt",
            user_agent="Nikto/2.5.0",
            raw_ref=f"access.log:{line}",
        )
        for line in (1, 2, 3)
    ]

    scanner = next(
        alert for alert in run_builtin_detections(events) if alert.rule_id == "CHINESCAN-WEB-002"
    )

    assert scanner.matching_refs == ["access.log:1", "access.log:2", "access.log:3"]
    assert scanner.first_match_ref == "access.log:1"
    assert scanner.last_match_ref == "access.log:3"
    assert scanner.match_count == 3


def test_distributed_credential_stuffing_signature_requires_distinct_sources_and_accounts() -> None:
    now = datetime.now(UTC)

    def make_failures(source_count: int) -> list[Event]:
        return [
            Event(
                occurred_at=now,
                kind="authentication_failure",
                summary="Authentication failed",
                source="identity_audit",
                source_ip=f"198.51.100.{index + 1}",
                user=f"account-{index % 5}",
                raw_ref=f"auth.csv:{index + 1}",
            )
            for index in range(source_count)
        ]

    alerts = run_builtin_detections(make_failures(10))
    stuffing = next(alert for alert in alerts if alert.rule_id == "CHINESCAN-AUTH-004")
    assert stuffing.title == "Distributed credential stuffing pattern"
    assert stuffing.verdict.value == "likely"
    assert stuffing.match_count == 10
    assert stuffing.first_match_ref == "auth.csv:1"
    assert stuffing.last_match_ref == "auth.csv:10"
    assert "do not show whether reused passwords were attempted" in stuffing.description

    near_miss = run_builtin_detections(make_failures(9))
    assert "CHINESCAN-AUTH-004" not in {alert.rule_id for alert in near_miss}


def test_impossible_time_sequence_is_a_lead_and_monotonic_log_is_not() -> None:
    now = datetime.now(UTC)
    backwards = [
        Event(
            occurred_at=now - offset,
            kind="system_event",
            summary="Synthetic event",
            source="syslog",
            raw_ref=f"system.log:{line}",
        )
        for line, offset in ((1, timedelta()), (2, timedelta(minutes=20)))
    ]
    alert = next(
        alert
        for alert in run_builtin_detections(backwards)
        if alert.rule_id == "CHINESCAN-TIME-001"
    )
    assert alert.verdict.value == "lead"
    assert alert.first_match_ref == "system.log:1"
    assert alert.last_match_ref == "system.log:2"
    assert alert.match_count == 2
    assert "Clock skew" in alert.description

    monotonic = [
        backwards[0].model_copy(update={"occurred_at": now, "raw_ref": "system.log:1"}),
        backwards[1].model_copy(
            update={"occurred_at": now + timedelta(minutes=20), "raw_ref": "system.log:2"}
        ),
    ]
    assert "CHINESCAN-TIME-001" not in {item.rule_id for item in run_builtin_detections(monotonic)}


def test_password_spray_and_scanner_near_misses_do_not_alert() -> None:
    now = datetime.now(UTC)
    events = [
        Event(
            occurred_at=now,
            kind="authentication_failure",
            summary="Authentication failed",
            source="linux_auth",
            source_ip="198.51.100.90",
            user="same-account",
            raw_ref=f"auth.log:{index + 1}",
        )
        for index in range(5)
    ]
    events += [
        Event(
            occurred_at=now,
            kind="http_request",
            summary="GET /",
            source="web_access",
            source_ip="198.51.100.91",
            url="/",
            user_agent="ordinary browser",
            raw_ref="access.log:1",
        )
    ]
    rule_ids = {alert.rule_id for alert in run_builtin_detections(events)}
    assert "CHINESCAN-AUTH-003" not in rule_ids
    assert "CHINESCAN-WEB-002" not in rule_ids


def test_large_single_account_failure_stream_stays_a_spray_near_miss() -> None:
    now = datetime.now(UTC)
    events = [
        Event(
            occurred_at=now + timedelta(seconds=index % 30),
            kind="authentication_failure",
            summary="Authentication failed",
            source="linux_auth",
            source_ip="198.51.100.92",
            user="same-account",
            raw_ref=f"auth.log:{index + 1}",
        )
        for index in range(4_000)
    ]

    rule_ids = {alert.rule_id for alert in run_builtin_detections(events)}

    assert "CHINESCAN-AUTH-003" not in rule_ids
    assert "CHINESCAN-AUTH-004" not in rule_ids


def test_error_burst_new_admin_and_log_clear_have_line_evidence() -> None:
    now = datetime.now(UTC)
    events = [
        Event(
            occurred_at=now,
            kind="web_request",
            summary="Web request",
            source="web_access",
            source_ip="198.51.100.92",
            url="/health",
            event_outcome="500",
            raw_ref=f"access.log:{index + 1}",
        )
        for index in range(5)
    ]
    events += [
        Event(
            occurred_at=now,
            kind="account_created",
            summary="New administrator account created",
            source="windows_event_export",
            user="operator",
            raw_ref="security.csv:20",
        ),
        Event(
            occurred_at=now,
            kind="1102",
            summary="The audit log was cleared",
            source="windows_event_export",
            raw_ref="security.csv:21",
        ),
    ]
    alerts = run_builtin_detections(events)
    ids = {alert.rule_id for alert in alerts}
    assert {"CHINESCAN-WEB-003", "CHINESCAN-ACCOUNT-001", "CHINESCAN-LOG-001"} <= ids
    burst = next(alert for alert in alerts if alert.rule_id == "CHINESCAN-WEB-003")
    assert burst.match_count == 5
    assert burst.first_match_ref == "access.log:1"
    assert burst.last_match_ref == "access.log:5"
    account_alert = next(alert for alert in alerts if alert.rule_id == "CHINESCAN-ACCOUNT-001")
    assert account_alert.matching_refs == ["security.csv:20"]


def test_error_burst_near_miss_and_unrelated_user_creation_do_not_alert() -> None:
    now = datetime.now(UTC)
    events = [
        Event(
            occurred_at=now,
            kind="web_request",
            summary="Web request",
            source="web_access",
            source_ip="198.51.100.92",
            url="/health",
            event_outcome="200",
            raw_ref=f"access.log:{index + 1}",
        )
        for index in range(6)
    ]
    events.append(
        Event(
            occurred_at=now,
            kind="account_created",
            summary="New user account created",
            source="windows_event_export",
            raw_ref="security.csv:20",
        )
    )
    rule_ids = {alert.rule_id for alert in run_builtin_detections(events)}
    assert "CHINESCAN-WEB-003" not in rule_ids
    assert "CHINESCAN-ACCOUNT-001" not in rule_ids


def test_windows_new_account_correlation_uses_creation_and_admin_group_lines() -> None:
    batch = parse_log_data(
        b"EventID,TimeCreated,Computer,SubjectUserName,TargetUserName,MemberName\n"
        b"4720,2026-11-09T10:00:00Z,DC01,admin-operator,bob,\n"
        b"4732,2026-11-09T10:05:00Z,DC01,admin-operator,Administrators,CN=bob\n",
        "security.csv",
        "security.csv",
    )
    assert not batch.errors
    created, assigned = batch.events
    assert created.actor == assigned.actor == "admin-operator"
    assert created.target == assigned.target == "bob"
    assert assigned.target_group == "Administrators"
    alert = next(
        item
        for item in run_builtin_detections(batch.events)
        if item.rule_id == "CHINESCAN-ACCOUNT-001"
    )
    assert alert.matching_refs == ["security.csv:2", "security.csv:3"]
    assert alert.match_count == 2
    assert "admin-operator" in alert.description
    assert "Administrators" in alert.description


def test_windows_privileged_group_near_miss_and_existing_account_mitigation() -> None:
    now = datetime.now(UTC)
    created = Event(
        occurred_at=now,
        kind="4720",
        summary="user created",
        source="windows_event_export",
        host="DC01",
        target="bob",
        raw_ref="security.csv:2",
    )
    ordinary_group = created.model_copy(
        update={
            "occurred_at": now + timedelta(minutes=1),
            "kind": "4732",
            "summary": "user added to group",
            "target_group": "Users",
            "raw_ref": "security.csv:3",
        }
    )
    assert "CHINESCAN-ACCOUNT-001" not in {
        alert.rule_id for alert in run_builtin_detections([created, ordinary_group])
    }
    existing_account_admin_add = ordinary_group.model_copy(
        update={"target_group": "Administrators"}
    )
    assert "CHINESCAN-ACCOUNT-001" not in {
        alert.rule_id for alert in run_builtin_detections([existing_account_admin_add])
    }


def test_cef_escaped_headers_spaced_extensions() -> None:
    data = (
        rb"CEF:0|Fixture\|Vendor|Firewall|1.0|DENY|Blocked a \| request|9|"
        rb"suser=Jane Doe src=198.51.100.40 dst=203.0.113.40 "
        rb"request=/search?q=one\=two msg=Firewall connection denied"
        b"\n"
        rb"CEF:0|FixtureVendor|Firewall|1.0|ALLOW|Low-priority \| event|3|"
    )

    batch = parse_log_data(data, "firewall.cef", "firewall.cef")

    assert not batch.errors
    assert len(batch.events) == 2
    event, low_severity = batch.events
    assert event.summary == "Firewall connection denied"
    assert event.user == "Jane Doe"
    assert event.source_ip == "198.51.100.40"
    assert event.destination_ip == "203.0.113.40"
    assert event.url == "/search?q=one=two"
    assert low_severity.summary == "Low-priority | event"


def test_cef_with_classic_syslog_prefix_uses_transport_timestamp_and_host() -> None:
    batch = parse_log_data(
        b"Jan 18 11:07:53 firewall.example "
        b"CEF:0|FixtureVendor|Firewall|1.0|DENY|Blocked|8|src=198.51.100.41\n",
        "firewall.log",
        "firewall.log",
    )

    assert not batch.errors
    assert len(batch.events) == 1
    event = batch.events[0]
    assert event.source == "cef"
    assert event.host == "firewall.example"
    assert event.source_ip == "198.51.100.41"
    assert event.occurred_at == datetime(datetime.now(UTC).year, 1, 18, 11, 7, 53, tzinfo=UTC)


def test_leef_2_custom_hex_delimiter_and_spaced_values() -> None:
    data = (
        b"LEEF:2.0|FixtureVendor|Firewall|1.0|NETWORK_CONNECTION|x5e|"
        b"src=198.51.100.60^cat=network_connection^usrName=Fixture Analyst^"
        b"msg=Firewall connection blocked"
    )

    batch = parse_log_data(data, "firewall.leef", "firewall.leef")

    assert not batch.errors
    assert len(batch.events) == 1
    event = batch.events[0]
    assert event.user == "Fixture Analyst"
    assert event.source_ip == "198.51.100.60"
    assert event.summary == "Firewall connection blocked"


def test_leef_2_rejects_invalid_delimiter() -> None:
    batch = parse_log_data(
        b"LEEF:2.0|Vendor|Product|1.0|event|xZZ|src=198.51.100.1",
        "invalid.leef",
        "invalid.leef",
    )
    assert not batch.events
    assert batch.errors == ["invalid.leef:1: malformed or unsupported log line"]


def test_sigma_safe_subset_and_ioc_correlation() -> None:
    events = ingest_path(FIXTURE_ROOT).events
    rules, rule_errors = load_sigma_rules(FIXTURE_ROOT / "windows-failed-login.yml")
    assert not rule_errors
    sigma_alerts, sigma_errors = run_sigma_rules(events, rules)
    assert not sigma_errors
    assert len(sigma_alerts) == 1
    assert sigma_alerts[0].rule_id == "fixture-windows-4625"
    iocs, ioc_errors = load_iocs(Path(__file__).parents[2] / "fixtures" / "sample-iocs.txt")
    assert not ioc_errors
    correlated = correlate_iocs(events, iocs)
    assert len(correlated.alerts) == 2
    assert any(event.indicator_matches for event in correlated.events)
    assert all(indicator.related_events for indicator in correlated.indicators)


def test_ioc_json_csv_validation_and_field_matching(tmp_path: Path) -> None:
    json_path = tmp_path / "indicators.json"
    json_path.write_text(
        json.dumps(
            [
                {"type": "domain", "value": "example.test"},
                {"type": "url", "value": "https://EXAMPLE.test/A?x=1#ignored"},
                {"type": "email", "value": "analyst@example.test"},
                {"type": "user_agent", "value": "Fixture Agent"},
            ]
        ),
        encoding="utf-8",
    )
    indicators, errors = load_iocs(json_path)
    assert not errors
    event = Event(
        occurred_at="2026-10-25T10:00:00Z",
        kind="web_request",
        summary="Request by analyst@example.test",
        host="api.example.test",
        url="https://example.test/A?x=1",
        user_agent="Fixture Agent/1.0",
    )
    correlated = correlate_iocs([event], indicators)
    assert len(correlated.alerts) == 4
    assert len(correlated.events[0].indicator_matches) == 4

    csv_path = tmp_path / "hashes.csv"
    md5 = "0123456789abcdef0123456789abcdef"
    csv_path.write_text(f"type,value\nmd5,{md5}\n", encoding="utf-8")
    hash_iocs, hash_errors = load_iocs(csv_path)
    assert not hash_errors
    hash_event = normalize_record(
        {"timestamp": "2026-10-25T10:00:00Z", "event_type": "file", "md5": md5},
        source="test",
        raw_ref="hashes.csv:1",
    )
    assert correlate_iocs([hash_event], hash_iocs).alerts


def test_log_ioc_extraction_tracks_counts_context_and_normalized_near_misses() -> None:
    start = datetime(2026, 10, 25, 10, tzinfo=UTC)
    events = [
        Event(
            occurred_at=start + timedelta(minutes=index),
            kind="web_request",
            summary="Synthetic request",
            source="web_access",
            source_ip="198.51.100.55",
            destination_ip="203.0.113.8",
            url="https://updates.example.invalid/path",
            user_agent="SyntheticScanner/1.0",
            sha256="a" * 64,
            raw_ref=f"access.log:{index + 1}",
        )
        for index in range(2)
    ]
    indicators = extract_event_iocs(events)
    by_key = {(item.kind, item.value): item for item in indicators}
    ip = by_key[("ip", "198.51.100.55")]
    assert ip.occurrence_count == 2
    assert ip.first_seen == start
    assert ip.last_seen == start + timedelta(minutes=1)
    assert len(ip.related_events) == 2
    assert "no threat-intelligence lookup" in ip.context
    assert by_key[("domain", "updates.example.invalid")].occurrence_count == 2
    assert by_key[("hash", "a" * 64)].occurrence_count == 2
    assert by_key[("user_agent", "SyntheticScanner/1.0")].occurrence_count == 2
    assert not any(value == "path" for _kind, value in by_key)


def test_invalid_ioc_file_is_diagnosed(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("not-json", encoding="utf-8")
    indicators, errors = load_iocs(path)
    assert not indicators
    assert errors


def test_malformed_jsonl_is_skipped_without_losing_valid_events(tmp_path: Path) -> None:
    path = tmp_path / "mixed.jsonl"
    path.write_text(
        '{"timestamp":"2026-10-25T10:00:00Z","message":"valid one"}\n'
        "{malformed record}\n"
        '{"timestamp":"2026-10-25T10:00:30Z","message":"bad field","bytes_out":"unknown"}\n'
        '{"timestamp":"2026-10-25T10:01:00Z","message":"valid two"}\n',
        encoding="utf-8",
    )
    result = ingest_path(path)
    assert len(result.events) == 2
    assert len(result.errors) == 2
    assert ":2:" in result.errors[0]
    assert ":3:" in result.errors[1]


def test_malformed_csv_row_does_not_discard_valid_rows(tmp_path: Path) -> None:
    path = tmp_path / "events.csv"
    path.write_text(
        "timestamp,event_type,bytes_sent\n"
        "2026-10-25T10:00:00Z,network,not-a-number\n"
        "2026-10-25T10:01:00Z,network,1024\n",
        encoding="utf-8",
    )
    result = ingest_path(path)
    assert len(result.events) == 1
    assert result.events[0].bytes_out == 1024
    assert len(result.errors) == 1


def test_zip_and_gzip_are_read_without_extracting(tmp_path: Path) -> None:
    log_text = '{"timestamp":"2026-10-25T10:00:00Z","message":"archived event"}\n'
    archive_path = tmp_path / "input.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escaped.jsonl", log_text)
    zip_result = ingest_path(archive_path)
    assert len(zip_result.events) == 1
    assert not (tmp_path.parent / "escaped.jsonl").exists()

    gzip_path = tmp_path / "input.jsonl.gz"
    gzip_path.write_bytes(gzip.compress(log_text.encode("utf-8")))
    gzip_result = ingest_path(gzip_path)
    assert len(gzip_result.events) == 1
    assert gzip_result.events[0].source == "json"

    tar_path = tmp_path / "input.tar.gz"
    payload = log_text.encode("utf-8")
    with tarfile.open(tar_path, "w:gz") as archive:
        member = tarfile.TarInfo("events/archived.jsonl")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    tar_result = ingest_path(tar_path)
    assert len(tar_result.events) == 1


def test_archive_decompression_limit_is_enforced(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "oversized.jsonl.gz"
    path.write_bytes(gzip.compress(b"x" * 100))
    monkeypatch.setattr(ingest_module, "MAX_FILE_BYTES", 16)
    result = ingest_path(path)
    assert not result.events
    assert len(result.errors) == 1


def test_expanded_byte_budget_is_shared_across_archives_and_stops_at_limit(
    tmp_path: Path, monkeypatch
) -> None:
    payload = b'{"timestamp":"2026-10-25T10:00:00Z","message":"' + b"x" * 2_000 + b'"}\n'
    paths = [tmp_path / "one.jsonl.gz", tmp_path / "two.jsonl.gz"]
    for path in paths:
        path.write_bytes(gzip.compress(payload))
    monkeypatch.setattr(ingest_module, "MAX_TOTAL_BYTES", len(payload) + 3)

    result = ingest_path(tmp_path)

    assert result.bytes_processed == len(payload)
    assert len(result.events) == 1
    assert any("total expanded-byte limit reached" in error for error in result.errors)


def test_zip_declared_size_does_not_replace_bounded_stream_read(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "lying.zip"
    payload = b"x" * 64
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("event.jsonl", payload)
    monkeypatch.setattr(ingest_module, "MAX_FILE_BYTES", 16)
    original = zipfile.ZipFile.infolist

    def infolist_with_false_size(self):
        infos = original(self)
        infos[0].file_size = 1
        return infos

    monkeypatch.setattr(zipfile.ZipFile, "infolist", infolist_with_false_size)
    result = ingest_path(path)
    assert not result.events
    assert result.errors


def test_malformed_archive_is_reported_without_raising(tmp_path: Path) -> None:
    path = tmp_path / "broken.zip"
    path.write_bytes(b"not a zip archive")
    result = ingest_path(path)
    assert not result.events
    assert result.errors


def test_bounded_reader_never_reads_past_limit() -> None:
    class CountingReader:
        def __init__(self) -> None:
            self.read_bytes = 0

        def read(self, size: int = -1) -> bytes:
            amount = min(size, 100 - self.read_bytes)
            self.read_bytes += amount
            return b"x" * amount

    stream = CountingReader()
    try:
        ingest_module._read_stream(stream, 10)
    except ValueError as exc:
        assert "limit" in str(exc)
    else:
        raise AssertionError("limit exhaustion should abort the member")
    assert stream.read_bytes == 10


def test_service_persists_events_alerts_and_sorted_timeline(repository) -> None:
    result = LogAnalysisService(repository).analyze(
        FIXTURE_ROOT,
        rules_path=FIXTURE_ROOT / "windows-failed-login.yml",
        ioc_path=Path(__file__).parents[2] / "fixtures" / "sample-iocs.txt",
    )
    scan = repository.get("scan", result.scan_id)
    assert scan is not None
    assert scan["status"] == "complete"
    assert len(scan["event_ids"]) == result.events
    assert len(scan["alert_ids"]) == len(result.alerts)
    entries = [
        repository.get("timeline_entry", entry_id) for entry_id in scan["timeline_entry_ids"]
    ]
    times = [entry["occurred_at"] for entry in entries if entry]
    assert times == sorted(times)
    assert repository.get("event", scan["event_ids"][0]) is not None
    assert repository.get("indicator", "missing") is None
    persisted_iocs = repository.list_records("indicator")
    extracted = [item for item in persisted_iocs if item["source"] == "log_extraction"]
    assert extracted
    assert all(item["first_seen"] and item["last_seen"] for item in extracted)
    assert all(item["occurrence_count"] >= 1 for item in extracted)


def test_logs_cli_summary_and_malformed_partial_exit(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "logs.sqlite3"
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(database))
    result = runner.invoke(
        app,
        [
            "logs",
            str(FIXTURE_ROOT),
            "--rules",
            str(FIXTURE_ROOT),
            "--ioc-file",
            str(Path(__file__).parents[2] / "fixtures" / "sample-iocs.txt"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.stdout)
    assert summary["event_count"] == 21
    assert summary["alert_count"] >= 8
    assert "203.0.113.5" not in result.stdout
    assert "fixture-user" not in result.stdout

    malformed = tmp_path / "malformed.jsonl"
    malformed.write_text("not json\n", encoding="utf-8")
    partial = runner.invoke(app, ["logs", str(malformed)])
    assert partial.exit_code == 1
    assert "Parser or rule warnings: 1" in partial.stderr


def test_sigma_yaml_uses_safe_loader(tmp_path: Path) -> None:
    path = tmp_path / "unsafe.yml"
    path.write_text("!!python/object/apply:os.system ['echo unsafe']\n", encoding="utf-8")
    rules, errors = load_sigma_rules(path)
    assert not rules
    assert len(errors) == 1


def test_normalized_secret_field_is_redacted() -> None:
    event = normalize_record(
        {
            "timestamp": "2026-10-25T10:00:00Z",
            "event_type": "process_start",
            "message": "password=fixture-secret",
            "command_line": "--api-key=fixture-key",
        },
        source="test",
        raw_ref="test.log:1",
    )
    assert "fixture-secret" not in event.summary
    assert "fixture-key" not in event.command_line


def test_expensive_rule_and_ioc_comparisons_are_bounded(monkeypatch) -> None:
    event = normalize_record(
        {"timestamp": "2026-10-25T10:00:00Z", "event_type": "login"},
        source="test",
        raw_ref="test.log:1",
    )
    monkeypatch.setattr(detections_module, "MAX_SIGMA_COMPARISONS", 0)
    rules = [SigmaRule("rule", "Rule", Severity.LOW, {"sel": {}}, "sel")]
    alerts, errors = run_sigma_rules([event], rules)
    assert not alerts
    assert "comparison limit" in errors[0]

    monkeypatch.setattr(ioc_module, "MAX_IOC_COMPARISONS", 0)
    indicator = Indicator(indicator_id="ioc", kind="domain", value="example.com")
    result = correlate_iocs([event], [indicator])
    assert result.events == [event]
    assert not result.alerts
    assert "comparison limit" in result.errors[0]
