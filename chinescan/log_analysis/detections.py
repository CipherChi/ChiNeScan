"""Built-in and safe-subset Sigma detections for normalized events."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from chinescan.core.models.common import Confidence, FindingVerdict, Severity
from chinescan.core.models.investigation import Alert, Event
from chinescan.log_analysis.normalization import canonical_field_name

MAX_SIGMA_RULE_BYTES = 1_000_000
MAX_SIGMA_RULES = 500
MAX_SIGMA_COMPARISONS = 5_000_000
MAX_SIGMA_CONDITION_TOKENS = 200
_COND_TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_*.-]*", re.IGNORECASE)


def _ordered_event_refs(events: list[Event]) -> list[str]:
    """Order single-file evidence by physical line, otherwise by event time."""
    referenced = [(event, event.raw_ref) for event in events if event.raw_ref]
    if not referenced:
        return []
    parsed = [
        (event, ref, ref.rpartition(":")[0], ref.rpartition(":")[2])
        for event, ref in referenced
    ]
    if len({item[2] for item in parsed}) == 1 and all(item[3].isdecimal() for item in parsed):
        parsed.sort(key=lambda item: (int(item[3]), item[0].event_id))
    else:
        parsed.sort(key=lambda item: (item[0].occurred_at, item[1], item[0].event_id))
    return [item[1] for item in parsed]


def make_alert(
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    events: list[Event],
    description: str = "Candidate activity requires analyst validation.",
    indicator_ids: list[str] | None = None,
    techniques: list[str] | None = None,
) -> Alert:
    """Create an idempotent grouped alert from normalized event identifiers."""
    event_ids = sorted({event.event_id for event in events})
    matching_refs = _ordered_event_refs(events)
    indicator_ids = sorted(set(indicator_ids or []))
    fingerprint = hashlib.sha256(
        "|".join([rule_id, *event_ids, *indicator_ids]).encode("utf-8")
    ).hexdigest()
    fixes = {
        "CHINESCAN-AUTH-001": (
            "Apply rate limits and progressive lockouts to the affected authentication endpoint; "
            "reset credentials if compromise is confirmed.",
            "Review the identity-provider audit trail for the same source and account, then "
            "confirm "
            "rate limiting and lockout behavior.",
        ),
        "CHINESCAN-AUTH-002": (
            "Revoke active sessions and rotate the affected account credentials after "
            "verifying the "
            "successful login with the account owner.",
            "Check the identity-provider session and MFA audit records and verify the account's "
            "sessions have been revoked if unauthorized.",
        ),
        "CHINESCAN-AUTH-003": (
            "Enable per-source throttling and MFA protections for the affected login service; "
            "review "
            "targeted accounts for unauthorized access.",
            "Confirm throttling is enforced and inspect identity-provider records for successful "
            "logins to the listed accounts.",
        ),
        "CHINESCAN-WEB-001": (
            "Validate and parameterize the affected request handling, and reject traversal or "
            "injection syntax at the application boundary.",
            "Replay the sanitized request in an authorized test environment and verify it is "
            "rejected or safely parameterized.",
        ),
        "CHINESCAN-WEB-002": (
            "Review the referenced requests and restrict automated scanning at the edge if it is "
            "unauthorized.",
            "Check the corresponding edge or application logs for follow-on requests and confirm "
            "any approved scanner source.",
        ),
        "CHINESCAN-WEB-003": (
            "Inspect the affected endpoint's error path, restore the dependency or configuration "
            "causing 5xx responses, and avoid returning internal details.",
            "Repeat the affected request after the fix and verify a non-5xx response while "
            "checking "
            "server-side diagnostics.",
        ),
        "CHINESCAN-ACCOUNT-001": (
            "Confirm the account creation was authorized; remove the account or reduce its "
            "privileges "
            "if it was not, and rotate exposed credentials.",
            "Review the identity directory audit record and verify the account's owner, "
            "approval, and "
            "assigned roles.",
        ),
        "CHINESCAN-LOG-001": (
            "Preserve remaining evidence, restrict log-administration rights, and restore "
            "centralized "
            "tamper-resistant audit forwarding.",
            "Verify remote audit collection is receiving events and review administrative access "
            "around the recorded clearing time.",
        ),
    }
    remediation, verification = fixes.get(
        rule_id,
        (
            "Validate the recorded activity with the system owner and apply the relevant "
            "access or "
            "configuration control if unauthorized.",
            "Compare the referenced event with the authoritative application or identity audit "
            "source and confirm the control is operating.",
        ),
    )
    return Alert(
        alert_id=str(uuid.uuid5(uuid.NAMESPACE_URL, fingerprint)),
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        rule_id=rule_id,
        event_ids=event_ids,
        indicator_ids=indicator_ids,
        mitre_attack_techniques=sorted(set(techniques or [])),
        fingerprint=fingerprint,
        verdict=(
            FindingVerdict.LIKELY
            if confidence in {Confidence.LIKELY, Confidence.CONFIRMED}
            else FindingVerdict.LEAD
        ),
        matching_refs=matching_refs,
        first_match_ref=matching_refs[0] if matching_refs else None,
        last_match_ref=matching_refs[-1] if matching_refs else None,
        match_count=len(event_ids),
        log_limitations=(
            [
                "Access logs contain no response body; outcome is inferred from the recorded "
                "status code."
            ]
            if any(event.source == "web_access" for event in events)
            else [
                "The log does not establish whether the recorded action completed "
                "successfully "
                "outside this event source."
            ]
        ),
        project_impact=(
            description
            if description != "Candidate activity requires analyst validation."
            else None
        ),
        exploitability_conditions=[
            "The event records this activity; impact depends on the target action succeeding."
        ],
        controls_considered=[
            "Looked only at the parsed event fields and referenced log lines; application "
            "controls, "
            "identity policy, and response bodies are not visible unless separately logged."
        ],
        remediation=remediation,
        verification_step=verification,
        why_not_higher=(
            "The event pattern is supported by the referenced logs, but those logs alone do not "
            "establish unauthorized access or resulting impact."
            if confidence in {Confidence.LIKELY, Confidence.CONFIRMED}
            else "This pattern is a lead because the available event fields do not confirm the "
            "activity's outcome."
        ),
        what_would_raise_it=(
            "Correlate with an authoritative application, identity, or endpoint record that "
            "confirms "
            "the outcome and affected account or resource."
        ),
    )


def run_builtin_detections(events: list[Event]) -> list[Alert]:
    """Apply conservative local detections to normalized auth, process, web, and network events."""
    alerts: list[Alert] = []
    failures: dict[tuple[str, str], list[Event]] = defaultdict(list)
    successes: dict[tuple[str, str], list[Event]] = defaultdict(list)
    failures_by_source: dict[str, list[Event]] = defaultdict(list)
    failed_auth_events: list[Event] = []
    scanner_events: dict[tuple[str, str], list[Event]] = defaultdict(list)
    server_errors: dict[str, list[Event]] = defaultdict(list)
    administrative_changes: list[Event] = []
    account_creations: dict[tuple[str, str], list[Event]] = defaultdict(list)
    privileged_group_additions: dict[tuple[str, str], list[Event]] = defaultdict(list)
    log_clears: list[Event] = []
    for event in events:
        key = (event.source_ip or "unknown", (event.user or "unknown").casefold())
        kind = event.kind.casefold()
        outcome = (event.event_outcome or "").casefold()
        auth_kind = "auth" in kind or "login" in kind or "signin" in kind
        if (auth_kind or kind == "4625") and (
            "fail" in kind
            or outcome in {"failure", "failed", "denied", "0"}
            or "denied" in outcome
            or "failure" in outcome
            or kind == "4625"
        ):
            failures[key].append(event)
            failed_auth_events.append(event)
            if key[0] != "unknown" and key[1] != "unknown":
                failures_by_source[key[0]].append(event)
        if (auth_kind or kind == "4624") and (
            "success" in kind
            or outcome in {"success", "succeeded", "accepted", "1"}
            or kind == "4624"
        ):
            successes[key].append(event)
        agent = (event.user_agent or "").casefold()
        scanner_marker = next(
            (
                marker
                for marker in (
                    "sqlmap",
                    "nikto",
                    "nmap",
                    "masscan",
                    "acunetix",
                    "nessus",
                    "wpscan",
                    "gobuster",
                )
                if marker in agent
            ),
            None,
        )
        if event.source == "web_access" and scanner_marker:
            scanner_events[(event.source_ip or "unknown", scanner_marker)].append(event)
        if event.source == "web_access" and (event.event_outcome or "").startswith("5"):
            server_errors[event.source_ip or "unknown"].append(event)

        activity_text = f"{kind} {event.summary}".casefold()
        host = (event.host or "unknown").casefold()
        account = (event.target or event.user or "").casefold()
        if kind in {"4720", "user_created", "account_created"} and account:
            account_creations[(host, account)].append(event)
        if kind in {"4728", "4732", "4756"}:
            group = (event.target_group or "").casefold()
            if account and any(
                marker in group
                for marker in ("admin", "privileged", "enterprise admins", "schema admins")
            ):
                privileged_group_additions[(host, account)].append(event)
        if any(
            marker in activity_text
            for marker in ("log cleared", "clear log", "eventlog cleared", "1102", "104")
        ):
            log_clears.append(event)
        if kind in {"account_created", "user_created"} and any(
            marker in activity_text
            for marker in ("user created", "created user", "account created", "new user")
        ) and any(marker in activity_text for marker in ("admin", "administrator", "privileged")):
            administrative_changes.append(event)

        if "privilege" in kind or (event.process or "").casefold() in {"sudo", "su"}:
            alerts.append(
                make_alert(
                    rule_id="CHINESCAN-PRIV-001",
                    title="Privilege escalation activity",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.POSSIBLE,
                    events=[event],
                    techniques=["T1548"],
                )
            )
        suspicious_web = {
            "web_sqli_candidate": ("SQL injection pattern in web request", "T1190"),
            "web_xss_candidate": ("Cross-site scripting pattern in web request", "T1190"),
            "web_traversal_candidate": ("Path traversal pattern in web request", "T1190"),
        }
        if event.kind in suspicious_web:
            title, technique = suspicious_web[event.kind]
            alerts.append(
                make_alert(
                    rule_id="CHINESCAN-WEB-001",
                    title=title,
                    severity=Severity.HIGH,
                    confidence=Confidence.POSSIBLE,
                    events=[event],
                    techniques=[technique],
                )
            )
        if event.source == "web_access" and event.url:
            path = event.url.casefold()
            patterns = (
                ("union select", "SQL injection pattern in web request", "T1190"),
                ("<script", "Cross-site scripting pattern in web request", "T1190"),
                ("../", "Path traversal pattern in web request", "T1190"),
                ("%2e%2e", "Encoded path traversal pattern in web request", "T1190"),
            )
            matched = next(
                ((title, technique) for needle, title, technique in patterns if needle in path),
                None,
            )
            if matched:
                alerts.append(
                    make_alert(
                        rule_id="CHINESCAN-WEB-001",
                        title=matched[0],
                        severity=Severity.HIGH,
                        confidence=Confidence.POSSIBLE,
                        events=[event],
                        techniques=[matched[1]],
                    )
                )
        process = (event.process or "").casefold()
        command_line = (event.command_line or "").casefold()
        if ("powershell" in process or "powershell" in command_line) and any(
            marker in command_line
            for marker in (
                " -enc",
                " -e ",
                "frombase64string",
                "downloadstring",
                "invoke-expression",
                " iex",
            )
        ):
            alerts.append(
                make_alert(
                    rule_id="CHINESCAN-PS-001",
                    title="Suspicious PowerShell command pattern",
                    severity=Severity.HIGH,
                    confidence=Confidence.POSSIBLE,
                    events=[event],
                    techniques=["T1059.001"],
                )
            )
        remote_execution = (
            "psexec" in process
            or ("wmic" in process and "/node:" in command_line)
            or ("winrs" in process and "-r:" in command_line)
            or "invoke-command -computername" in command_line
            or "enter-pssession" in command_line
        )
        if remote_execution:
            alerts.append(
                make_alert(
                    rule_id="CHINESCAN-LATERAL-001",
                    title="Remote execution tool pattern",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.POSSIBLE,
                    events=[event],
                    techniques=["T1021"],
                )
            )
        if (
            event.direction
            and event.direction.casefold() in {"outbound", "egress"}
            and event.bytes_out is not None
            and event.bytes_out >= 100_000_000
        ):
            alerts.append(
                make_alert(
                    rule_id="CHINESCAN-NET-001",
                    title="Large outbound data transfer",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.POSSIBLE,
                    events=[event],
                    techniques=["T1041"],
                )
            )

    for source_ip, group in failures_by_source.items():
        ordered = sorted(group, key=lambda event: event.occurred_at)
        left = 0
        user_counts: Counter[str] = Counter()
        for right, current in enumerate(ordered):
            if current.user:
                user_counts[current.user.casefold()] += 1
            while current.occurred_at - ordered[left].occurred_at > timedelta(minutes=10):
                expired_user = ordered[left].user
                if expired_user:
                    normalized_user = expired_user.casefold()
                    user_counts[normalized_user] -= 1
                    if user_counts[normalized_user] == 0:
                        del user_counts[normalized_user]
                left += 1
            if len(user_counts) >= 5:
                window_events = ordered[left : right + 1]
                alerts.append(
                    make_alert(
                        rule_id="CHINESCAN-AUTH-003",
                        title="Password spraying across multiple accounts",
                        severity=Severity.HIGH,
                        confidence=Confidence.LIKELY,
                        events=window_events,
                        description=(
                            f"At least five accounts received failed authentication attempts "
                            f"from {source_ip} within ten minutes."
                        ),
                        techniques=["T1110.003"],
                    )
                )
                break

    distributed_failures = sorted(failed_auth_events, key=lambda event: event.occurred_at)
    left = 0
    source_counts: Counter[str] = Counter()
    distributed_user_counts: Counter[str] = Counter()
    for right, current in enumerate(distributed_failures):
        if current.source_ip:
            source_counts[current.source_ip] += 1
        if current.user:
            distributed_user_counts[current.user.casefold()] += 1
        while current.occurred_at - distributed_failures[left].occurred_at > timedelta(minutes=10):
            expired = distributed_failures[left]
            if expired.source_ip:
                source_counts[expired.source_ip] -= 1
                if source_counts[expired.source_ip] == 0:
                    del source_counts[expired.source_ip]
            if expired.user:
                normalized_user = expired.user.casefold()
                distributed_user_counts[normalized_user] -= 1
                if distributed_user_counts[normalized_user] == 0:
                    del distributed_user_counts[normalized_user]
            left += 1
        if len(source_counts) >= 10 and len(distributed_user_counts) >= 5:
            matching = distributed_failures[left : right + 1]
            alerts.append(
                make_alert(
                    rule_id="CHINESCAN-AUTH-004",
                    title="Distributed credential stuffing pattern",
                    severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    events=matching,
                    description=(
                        f"Failed authentication attempts targeted {len(distributed_user_counts)} "
                        f"accounts from {len(source_counts)} source addresses within ten minutes. "
                        "This "
                        "distributed pattern is consistent with credential stuffing; the logs "
                        "do not show whether reused passwords were attempted."
                    ),
                    techniques=["T1110.004"],
                )
            )
            break

    for (source_ip, marker), group in scanner_events.items():
        if len(group) >= 3:
            alerts.append(
                make_alert(
                    rule_id="CHINESCAN-WEB-002",
                    title="Known web scanner user agent",
                    severity=Severity.LOW,
                    confidence=Confidence.POSSIBLE,
                    events=sorted(group, key=lambda event: event.occurred_at),
                    description=(
                        f"The user agent contains the scanner signature {marker!r} "
                        f"across {len(group)} requests from {source_ip}."
                    ),
                    techniques=["T1595"],
                )
            )

    for source_ip, group in server_errors.items():
        ordered = sorted(group, key=lambda event: event.occurred_at)
        left = 0
        for right, current in enumerate(ordered):
            while current.occurred_at - ordered[left].occurred_at > timedelta(minutes=5):
                left += 1
            if right - left + 1 >= 5:
                matching = ordered[left : right + 1]
                alerts.append(
                    make_alert(
                        rule_id="CHINESCAN-WEB-003",
                        title="HTTP server error burst",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.POSSIBLE,
                        events=matching,
                        description=(
                            f"At least five HTTP 5xx responses from {source_ip} occurred "
                            "within five minutes. Access logs cannot establish the response body."
                        ),
                        techniques=["T1499"],
                    )
                )
                break

    account_evidence = list(administrative_changes)
    for key, creations in account_creations.items():
        for addition in privileged_group_additions.get(key, []):
            eligible = [
                creation
                for creation in creations
                if timedelta(0)
                <= addition.occurred_at - creation.occurred_at
                <= timedelta(hours=24)
            ]
            if eligible:
                creation = min(eligible, key=lambda item: item.occurred_at)
                account_evidence.append((creation, addition))

    for creation_or_pair in account_evidence:
        matched_events = (
            list(creation_or_pair)
            if isinstance(creation_or_pair, tuple)
            else [creation_or_pair]
        )
        actors = sorted({event.actor for event in matched_events if event.actor})
        accounts = sorted(
            {
                event.target or event.user
                for event in matched_events
                if event.target or event.user
            }
        )
        groups = sorted({event.target_group for event in matched_events if event.target_group})
        detail = "; ".join(
            value for value in (
                f"account {', '.join(accounts)}" if accounts else "",
                f"group {', '.join(groups)}" if groups else "",
                f"actor {', '.join(actors)}" if actors else "",
            ) if value
        )
        alerts.append(
            make_alert(
                rule_id="CHINESCAN-ACCOUNT-001",
                title="New privileged account created",
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                events=matched_events,
                description=(
                    f"The account creation and later privileged-group assignment are present in "
                    f"the export{': ' + detail if detail else ''}. Verify authorization; these "
                    "events do not establish who controlled the account afterward."
                ),
                techniques=["T1136.001"],
            )
        )

    for event in log_clears:
        alerts.append(
            make_alert(
                rule_id="CHINESCAN-LOG-001",
                title="Log clearing activity",
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                events=[event],
                description=(
                    "The event text records log clearing; confirm the actor and whether "
                    "evidence was removed."
                ),
                techniques=["T1070.001"],
            )
        )

    records_by_file: dict[str, list[tuple[int, Event]]] = defaultdict(list)
    for event in events:
        if not event.raw_ref:
            continue
        source_ref, separator, raw_line = event.raw_ref.rpartition(":")
        if separator and raw_line.isdecimal():
            records_by_file[source_ref].append((int(raw_line), event))
    for source_ref, records in records_by_file.items():
        ordered = sorted(records, key=lambda item: item[0])
        anomalous_events: list[Event] = []
        anomalous_pairs = 0
        for (previous_line, previous), (current_line, current) in zip(
            ordered, ordered[1:], strict=False
        ):
            if (
                current_line > previous_line
                and previous.occurred_at - current.occurred_at >= timedelta(minutes=10)
            ):
                anomalous_events.extend((previous, current))
                anomalous_pairs += 1
        if anomalous_pairs:
            unique_events = list({event.event_id: event for event in anomalous_events}.values())
            alerts.append(
                make_alert(
                    rule_id="CHINESCAN-TIME-001",
                    title="Log timestamps move backwards",
                    severity=Severity.LOW,
                    confidence=Confidence.POSSIBLE,
                    events=unique_events,
                    description=(
                        f"{anomalous_pairs} adjacent record pair(s) in {source_ref} move backward "
                        "by at least ten minutes in file order. Clock skew, buffering, or log "
                        "merging can cause this; verify the source and time synchronization."
                    ),
                )
            )

    for (source_ip, user), group in failures.items():
        group.sort(key=lambda event: event.occurred_at)
        window = timedelta(minutes=10)
        left = 0
        for right, current in enumerate(group):
            while current.occurred_at - group[left].occurred_at > window:
                left += 1
            if right - left + 1 >= 5:
                matching = group[left : right + 1]
                alerts.append(
                    make_alert(
                        rule_id="CHINESCAN-AUTH-001",
                        title="Repeated authentication failures",
                        severity=Severity.HIGH,
                        confidence=Confidence.LIKELY,
                        events=matching,
                        description=(
                            f"At least five failed authentication events from {source_ip} "
                            "for one account within ten minutes."
                        ),
                        techniques=["T1110"],
                    )
                )
                break
        left = 0
        ordered_successes = sorted(
            successes.get((source_ip, user), []), key=lambda event: event.occurred_at
        )
        for success in ordered_successes:
            while left < len(group) and success.occurred_at - group[left].occurred_at > window:
                left += 1
            end = left
            while end < len(group) and group[end].occurred_at <= success.occurred_at:
                end += 1
            related = group[left:end]
            if len(related) >= 3:
                alerts.append(
                    make_alert(
                        rule_id="CHINESCAN-AUTH-002",
                        title="Authentication succeeded after repeated failures",
                        severity=Severity.HIGH,
                        confidence=Confidence.LIKELY,
                        events=[*related, success],
                        techniques=["T1110", "T1078"],
                    )
                )
                break
    return _deduplicate_alerts(alerts)


@dataclass(frozen=True)
class SigmaRule:
    """Validated Sigma rule fields used by the supported subset evaluator."""

    rule_id: str
    title: str
    severity: Severity
    detection: dict[str, Any]
    condition: str
    tags: tuple[str, ...] = ()


def load_sigma_rules(path: Path | None) -> tuple[list[SigmaRule], list[str]]:
    """Load bounded YAML rules using safe YAML construction; return rule-level diagnostics."""
    if path is None:
        return [], []
    if path.is_symlink() or not path.exists() or not (path.is_file() or path.is_dir()):
        return [], [f"{path}: rule path is missing or a symbolic link"]
    if path.is_file():
        paths = [path]
    else:
        paths = []
        for directory, dirnames, filenames in os.walk(path, followlinks=False):
            dirnames[:] = sorted(
                name for name in dirnames if not (Path(directory) / name).is_symlink()
            )
            for filename in sorted(filenames):
                candidate = Path(directory) / filename
                if candidate.suffix.lower() in {".yml", ".yaml"} and not candidate.is_symlink():
                    paths.append(candidate)
                    if len(paths) >= MAX_SIGMA_RULES:
                        break
            if len(paths) >= MAX_SIGMA_RULES:
                break
    rules: list[SigmaRule] = []
    errors: list[str] = []
    for rule_path in paths[:MAX_SIGMA_RULES]:
        try:
            if rule_path.is_symlink() or rule_path.stat().st_size > MAX_SIGMA_RULE_BYTES:
                errors.append(f"{rule_path}: rule file exceeds safety limits")
                continue
            documents = yaml.safe_load_all(rule_path.read_text(encoding="utf-8"))
            for document in documents:
                if not isinstance(document, dict):
                    raise ValueError("rule document must be a mapping")
                detection = document.get("detection")
                condition = detection.get("condition") if isinstance(detection, dict) else None
                selectors = (
                    {key: val for key, val in detection.items() if key != "condition"}
                    if isinstance(detection, dict)
                    else {}
                )
                if (
                    not isinstance(document.get("title"), str)
                    or not selectors
                    or not isinstance(condition, str)
                    or (isinstance(detection, dict) and "timeframe" in detection)
                    or len(selectors) > 100
                    or len(condition) > 4096
                ):
                    raise ValueError("rule requires title, detection selectors, and a condition")
                rule_id = str(document.get("id") or rule_path.stem)
                level = str(document.get("level", "medium")).casefold()
                severity = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                    "informational": Severity.INFO,
                }.get(level, Severity.MEDIUM)
                raw_tags = document.get("tags", [])
                tags = tuple(str(tag) for tag in raw_tags) if isinstance(raw_tags, list) else ()
                rules.append(
                    SigmaRule(rule_id, document["title"], severity, selectors, condition, tags)
                )
                if len(rules) >= MAX_SIGMA_RULES:
                    break
        except (OSError, UnicodeError, yaml.YAMLError, ValueError, RecursionError) as exc:
            errors.append(f"{rule_path}: invalid Sigma rule ({type(exc).__name__})")
    return rules, errors


def run_sigma_rules(events: list[Event], rules: list[SigmaRule]) -> tuple[list[Alert], list[str]]:
    alerts: list[Alert] = []
    errors: list[str] = []
    if len(events) * len(rules) > MAX_SIGMA_COMPARISONS:
        return [], ["Sigma comparison limit reached; rules were not evaluated"]
    for rule in rules:
        try:
            matched = [
                event for event in events if _condition(rule.condition, rule.detection, event)
            ]
        except ValueError as exc:
            errors.append(f"{rule.rule_id}: unsupported condition ({exc})")
            continue
        if matched:
            techniques = [tag for tag in rule.tags if tag.upper().startswith("ATT&CK.T")]
            alerts.append(
                make_alert(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=Confidence.POSSIBLE,
                    events=matched,
                    techniques=[tag.split(".", 1)[-1] for tag in techniques],
                )
            )
    return _deduplicate_alerts(alerts), errors


def _condition(condition: str, selectors: dict[str, Any], event: Event) -> bool:
    expression = condition.strip()
    for quantifier, pattern in re.findall(
        r"\b(all|1|any)\s+of\s+([A-Za-z0-9_*.-]+)", expression, re.I
    ):
        names = sorted(name for name in selectors if fnmatch.fnmatchcase(name, pattern))
        if not names:
            raise ValueError(f"no selector matches {pattern}")
        replacement = " and ".join(names) if quantifier.casefold() == "all" else " or ".join(names)
        if len(names) > 1:
            replacement = f"({replacement})"
        expression = re.sub(
            rf"\b{re.escape(quantifier)}\s+of\s+{re.escape(pattern)}\b",
            replacement,
            expression,
            count=1,
            flags=re.IGNORECASE,
        )
    tokens = _COND_TOKEN.findall(expression)
    if len(tokens) > MAX_SIGMA_CONDITION_TOKENS:
        raise ValueError("condition token limit reached")
    if "".join(tokens).casefold() != re.sub(r"\s+", "", expression).casefold():
        raise ValueError("invalid condition syntax")
    position = 0

    def parse_or() -> bool:
        nonlocal position
        value = parse_and()
        while position < len(tokens) and tokens[position].casefold() == "or":
            position += 1
            other = parse_and()
            value = value or other
        return value

    def parse_and() -> bool:
        nonlocal position
        value = parse_not()
        while position < len(tokens) and tokens[position].casefold() == "and":
            position += 1
            other = parse_not()
            value = value and other
        return value

    def parse_not() -> bool:
        nonlocal position
        if position < len(tokens) and tokens[position].casefold() == "not":
            position += 1
            return not parse_not()
        if position < len(tokens) and tokens[position] == "(":
            position += 1
            value = parse_or()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("unclosed parenthesis")
            position += 1
            return value
        if position >= len(tokens):
            raise ValueError("missing selector")
        selector = tokens[position]
        position += 1
        if selector.casefold() in {"and", "or"} or selector not in selectors:
            raise ValueError(f"unknown selector {selector}")
        return _matches_selector(selectors[selector], event)

    result = parse_or()
    if position != len(tokens):
        raise ValueError("unexpected condition token")
    return result


def _matches_selector(selector: Any, event: Event) -> bool:
    if isinstance(selector, list):
        return any(_matches_selector(value, event) for value in selector)
    if not isinstance(selector, dict):
        raise ValueError("selector must be a mapping or list of mappings")
    values = event.model_dump(mode="json")
    for raw_field, expected in selector.items():
        field, *modifiers = str(raw_field).split("|")
        canonical = canonical_field_name(field)
        actual = values.get(canonical)
        if actual is None:
            return False
        actual_text = str(actual).casefold()
        expected_values = expected if isinstance(expected, list) else [expected]
        matches: list[bool] = []
        for candidate in expected_values:
            candidate_text = str(candidate).casefold()
            if "contains" in modifiers:
                matches.append(candidate_text in actual_text)
            elif "startswith" in modifiers:
                matches.append(actual_text.startswith(candidate_text))
            elif "endswith" in modifiers:
                matches.append(actual_text.endswith(candidate_text))
            elif any(modifier not in {"all"} for modifier in modifiers):
                raise ValueError("unsupported Sigma field modifier")
            else:
                matches.append(fnmatch.fnmatchcase(actual_text, candidate_text))
        field_matches = all(matches) if "all" in modifiers else any(matches)
        if not field_matches:
            return False
    return True


def _deduplicate_alerts(alerts: list[Alert]) -> list[Alert]:
    unique = {alert.fingerprint: alert for alert in alerts}
    return sorted(
        unique.values(), key=lambda alert: (alert.severity.value, alert.rule_id, alert.alert_id)
    )
