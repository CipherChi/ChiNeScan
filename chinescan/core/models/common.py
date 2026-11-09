"""Shared model fields and enums."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(StrEnum):
    SAST = "SAST"
    SCA = "SCA"
    SECRETS = "SECRETS"
    IAC = "IAC"
    CONTAINER = "CONTAINER"
    NETWORK = "NETWORK"
    WEB = "WEB"
    TLS = "TLS"
    DNS = "DNS"
    LOG = "LOG"
    MALWARE = "MALWARE"
    MEMORY = "MEMORY"
    THREAT_INTEL = "THREAT_INTEL"


class Confidence(StrEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    INFORMATIONAL = "INFORMATIONAL"


class EvidenceKind(StrEnum):
    CONFIRMED_ARTIFACT = "confirmed_artifact"
    PATTERN_MATCH = "pattern_match"
    REFERENCE_ONLY = "reference_only"
    CONTEXT_ONLY = "context_only"


class FindingVerdict(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    LEAD = "lead"


class ScanVerdict(StrEnum):
    LEADS_FOUND = "leads_found"
    NO_MATCHES_WITH_GAPS = "no_matches_with_gaps"
    NO_MATCHES_IN_SCOPE = "no_matches_in_scope"
    SCAN_FAILED = "scan_failed"


class SchemaRecord(BaseModel):
    """Base for versioned JSON-compatible records."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    schema_version: str = "1.0"
