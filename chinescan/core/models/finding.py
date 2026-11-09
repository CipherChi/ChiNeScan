"""Finding and external reference records."""

from uuid import uuid4

from pydantic import Field, HttpUrl

from chinescan.core.models.common import (
    Confidence,
    EvidenceKind,
    FindingVerdict,
    FindingCategory,
    SchemaRecord,
    Severity,
)


class FindingExplanation(SchemaRecord):
    """Versioned, evidence-bounded explanation for a finding.

    Empty or unavailable fields are intentionally omitted rather than filled with
    retrospective claims for legacy findings.
    """

    version: str = "1.0"
    classification_policy_version: str | None = None
    observed: str | None = None
    match_reason: str | None = None
    established: list[str] = Field(default_factory=list)
    inferred: list[str] = Field(default_factory=list)
    severity_rationale: str | None = None
    confidence_rationale: str | None = None
    exposure_rationale: str | None = None
    attack_prerequisites: list[str] = Field(default_factory=list)
    conditional_impact: str | None = None
    controls_considered: list[str] = Field(default_factory=list)
    false_positive_considerations: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    remediation_rationale: str | None = None
    limitations: list[str] = Field(default_factory=list)
    ruleset_version: str | None = None


class Reference(SchemaRecord):
    title: str
    url: HttpUrl | None = None


class EvidenceLocation(SchemaRecord):
    """Project-relative location for a source or sink in a finding."""

    file: str
    line: int = Field(ge=1)
    excerpt: str | None = None


class Finding(SchemaRecord):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    project_id: str | None = None
    project_removed: bool = False
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    fingerprint: str = Field(min_length=1)
    category: FindingCategory = FindingCategory.SAST
    confidence: Confidence = Confidence.POSSIBLE
    # Evidence describes the evidence type and is independent of severity and confidence.
    evidence: EvidenceKind | None = None
    scanner: str = "unknown"
    source: str = "builtin"
    rule_id: str = "unknown"
    location: str | None = None
    line_numbers: list[int] = Field(default_factory=list)
    code_excerpt: str | None = None
    remediation: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    exposure: str = "unknown"
    references: list[Reference] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    contributing_rule_ids: list[str] = Field(default_factory=list)
    explanation: FindingExplanation | None = None
    verdict: FindingVerdict = FindingVerdict.LEAD
    entry_point: EvidenceLocation | None = None
    source_location: EvidenceLocation | None = None
    sink_location: EvidenceLocation | None = None
    controls_considered: list[str] = Field(default_factory=list)
    exploitability_conditions: list[str] = Field(default_factory=list)
    project_impact: str | None = None
    remediation_before: str | None = None
    remediation_after: str | None = None
    verification_step: str | None = None
    why_not_higher: str | None = None
    what_would_raise_it: str | None = None
