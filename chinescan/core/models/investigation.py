"""Distinct, typed top-level investigation records."""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from chinescan.core.models.common import Confidence, ScanVerdict, SchemaRecord, Severity


class CoverageGap(SchemaRecord):
    code: str
    reason: str
    count: int = 1
    source: str = ""
    example: str | None = None

    @field_validator("example")
    @classmethod
    def example_is_project_relative(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or ":" in normalized or ".." in normalized.split("/"):
            raise ValueError("coverage examples must be project-relative paths")
        return value


class CoverageReport(SchemaRecord):
    examined: dict[str, int] = Field(default_factory=dict)
    excluded: dict[str, int] = Field(default_factory=dict)
    gaps: list[CoverageGap] = Field(default_factory=list)


class ScoreEvidence(SchemaRecord):
    file: str
    line_numbers: list[int] = Field(default_factory=list)
    code_excerpt: str | None = None


class ScoreContribution(SchemaRecord):
    signal_id: str
    description: str
    raw_count: int = Field(ge=0)
    effective_count: int = Field(ge=0)
    weight: int = Field(ge=0)
    adjustment: str
    contribution: int
    evidence: list[ScoreEvidence] = Field(default_factory=list)


class VibeCodingRisk(SchemaRecord):
    score: int = Field(ge=0, le=100)
    confidence: Confidence
    signals: list[str] = Field(default_factory=list)
    disclaimer: str = "Heuristic risk indicators only; this score is not proof of AI authorship."
    name: str = "Code pattern risk"
    direction: str = "Higher scores mean more configured code patterns were observed."
    interpretation: str = (
        "A deterministic heuristic indicator, not a vulnerability or authorship verdict."
    )
    algorithm_version: str | None = None
    contributions: list[ScoreContribution] = Field(default_factory=list)
    coverage_limitations: list[str] = Field(default_factory=list)
    confidence_rationale: str | None = None


class CodeAssessmentSummary(SchemaRecord):
    files_scanned: int = Field(default=0, ge=0)
    files_excluded: int = Field(default=0, ge=0)
    excluded_paths: list[str] = Field(default_factory=list)
    vibe_coding_risk: VibeCodingRisk | None = None


class Event(SchemaRecord):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime
    kind: str
    summary: str
    source: str = "unknown"
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    host: str | None = None
    process: str | None = None
    command_line: str | None = None
    file: str | None = None
    sha256: str | None = None
    file_hashes: list[str] = Field(default_factory=list)
    url: str | None = None
    user_agent: str | None = None
    event_outcome: str | None = None
    direction: str | None = None
    bytes_out: int | None = Field(default=None, ge=0)
    mitre_attack_techniques: list[str] = Field(default_factory=list)
    indicator_matches: list[str] = Field(default_factory=list)
    raw_ref: str | None = None


class Alert(SchemaRecord):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.POSSIBLE
    rule_id: str
    event_ids: list[str] = Field(default_factory=list)
    indicator_ids: list[str] = Field(default_factory=list)
    mitre_attack_techniques: list[str] = Field(default_factory=list)
    fingerprint: str = Field(min_length=1)


class Indicator(SchemaRecord):
    indicator_id: str = Field(default_factory=lambda: str(uuid4()))
    kind: str
    value: str
    confidence: float = Field(default=0.5, ge=0, le=1)
    source: str = "local"
    context: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    related_findings: list[str] = Field(default_factory=list)
    related_events: list[str] = Field(default_factory=list)


class CaseStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CaseActivityType(StrEnum):
    CREATED = "created"
    STATUS_CHANGED = "status_changed"
    RECORD_LINKED = "record_linked"
    NOTE_ADDED = "note_added"


class CaseRecordLink(SchemaRecord):
    record_type: str = Field(min_length=1, max_length=80)
    record_id: str = Field(min_length=1, max_length=255)
    source: str = Field(min_length=1, max_length=200)
    linked_at: datetime | None = None


class CaseNote(SchemaRecord):
    note_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str = Field(min_length=1, max_length=255)
    body: str = Field(min_length=1, max_length=8_000)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    author_label: str | None = Field(default=None, max_length=100)


class CaseActivity(SchemaRecord):
    activity_id: str = Field(default_factory=lambda: str(uuid4()))
    activity_type: CaseActivityType
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    details: dict[str, str] = Field(default_factory=dict)


class Case(SchemaRecord):
    schema_version: str = "2.0"
    case_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str = ""
    status: CaseStatus = CaseStatus.OPEN
    severity: Severity = Severity.MEDIUM
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    project_id: str | None = None
    project_removed: bool = False
    scan_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    links: list[CaseRecordLink] = Field(default_factory=list)
    notes: list[CaseNote] = Field(default_factory=list)
    activities: list[CaseActivity] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_note_ownership(self) -> "Case":
        if any(note.case_id != self.case_id for note in self.notes):
            raise ValueError("case notes must belong to their containing case")
        if len({note.note_id for note in self.notes}) != len(self.notes):
            raise ValueError("case note IDs must be unique")
        return self


class CaseTimelineItem(SchemaRecord):
    item_id: str
    category: str
    description: str
    event_occurred_at: datetime | None = None
    record_ingested_at: datetime | None = None
    case_activity_at: datetime | None = None
    record_type: str | None = None
    record_id: str | None = None
    source: str | None = None


class TimelineEntry(SchemaRecord):
    entry_id: str = Field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime
    description: str
    event_id: str | None = None
    scan_id: str | None = None


class Scan(SchemaRecord):
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    project_id: str | None = None
    project_removed: bool = False
    target_id: str
    scanner: str
    started_at: datetime
    finished_at: datetime | None = None
    status: str = "complete"
    project_types: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    timeline_entry_ids: list[str] = Field(default_factory=list)
    location_ids: list[str] = Field(default_factory=list)
    failures: dict[str, str] = Field(default_factory=dict)
    scan_options: dict[str, str | int | float | bool] = Field(default_factory=dict)
    coverage: CoverageReport | None = None
    code_assessment: CodeAssessmentSummary | None = None
    verdict: ScanVerdict | None = None


class Target(SchemaRecord):
    value: str
    kind: str


class Artifact(SchemaRecord):
    name: str
    sha256: str | None = None
    media_type: str | None = None


class Report(SchemaRecord):
    title: str
    generated_at: datetime
    finding_ids: list[str] = Field(default_factory=list)


class Authorization(SchemaRecord):
    scope: list[str]
    granted_by: str
    valid_from: datetime
    valid_until: datetime | None = None


class AuthorizationRecord(SchemaRecord):
    """Audit record tying a domain assessment to an explicit authorization method."""

    authorization_id: str = Field(default_factory=lambda: str(uuid4()))
    target: str
    method: str
    operator: str
    authorized_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    valid_until: datetime | None = None
    scan_profile: str
    scan_id: str
