"""Finding and external reference records."""

from uuid import uuid4

from pydantic import Field, HttpUrl

from chinescan.core.models.common import (
    Confidence,
    EvidenceKind,
    FindingCategory,
    SchemaRecord,
    Severity,
)


class Reference(SchemaRecord):
    title: str
    url: HttpUrl | None = None


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
