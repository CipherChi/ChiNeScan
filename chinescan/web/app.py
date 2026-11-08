"""Same-origin authenticated API and production frontend serving."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import shutil
import threading
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.middleware.base import RequestResponseEndpoint

from chinescan.chain_trace.export import export_graph
from chinescan.chain_trace.registry import load_registry, normalize_address
from chinescan.core.cases import (
    CaseNotFoundError,
    CaseRecordNotFoundError,
    CaseWorkflow,
    CaseWorkflowError,
)
from chinescan.core.config.settings import Settings
from chinescan.core.diagnostics import build_report, health_report
from chinescan.core.external_reports import (
    MAX_EXTERNAL_REPORT_BYTES,
    ExternalReportError,
    parse_scanity_export,
)
from chinescan.core.fs_policy import (
    FilesystemBrowserService,
    folder_approval_error,
    policy_paths,
)
from chinescan.core.github_import import GitHubImportError, GitHubImportService, session_binding
from chinescan.core.log_locations import LogLocationService
from chinescan.core.logging.redaction import redact
from chinescan.core.logging.structured import configure_logging
from chinescan.core.malware_ack import MalwareAcknowledgementError, MalwareAcknowledgements
from chinescan.core.malware_project_scan import ProjectMalwareJobs, ProjectMalwareScanner
from chinescan.core.models.common import (
    Confidence,
    EvidenceKind,
    FindingCategory,
    ScanVerdict,
    Severity,
)
from chinescan.core.models.finding import Finding, FindingExplanation
from chinescan.core.models.investigation import (
    Alert,
    Case,
    CaseStatus,
    CodeAssessmentSummary,
    CoverageReport,
    Event,
    Scan,
    TimelineEntry,
)
from chinescan.core.orchestration.code_scan import ScanBounds
from chinescan.core.projects import ProjectError, ProjectService
from chinescan.core.report_store import ReportStoreError, save_scan_reports
from chinescan.core.reporting import (
    ReportingError,
    redact_finding_payload,
    render_case_report,
    render_report,
    scan_data,
)
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.malware_analysis.managed import (
    ManagedSampleError,
    create_backend,
    safe_display_name,
)
from chinescan.web.auth import (
    CredentialError,
    LoginThrottle,
    ProgressiveLockout,
    Session,
    SessionStore,
    create_operator,
    migrate_legacy_operator,
    normalize_email,
    operator_auth_epoch,
    operator_status,
    operator_totp_enabled,
    perform_dummy_verification,
    reset_operator_password,
    verify_operator,
    verify_operator_totp,
)
from chinescan.web.chain_trace_jobs import ChainTraceJobManager
from chinescan.web.code_jobs import CodeJobManager, ProjectConfigurationError, ProjectRegistry
from chinescan.web.log_jobs import LogJobManager, LogSourceError, LogSourceRegistry
from chinescan.web.malware_jobs import MalwareDashboardManager
from chinescan.web.rate_limit import InProcessRateLimiter

COOKIE_NAME = "chinescan_session"
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
MAX_SCAN_REPORT_FINDINGS = 10_000
MAX_SCAN_REPORT_BYTES = 20 * 1024 * 1024


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)
    totp_code: str | None = Field(default=None, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class SignupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=1024)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class ForgotPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class ResetPasswordRequest(ForgotPasswordRequest):
    token: str = Field(min_length=32, max_length=256)
    password: str = Field(min_length=12, max_length=1024)


class AuthSessionResponse(BaseModel):
    """Authenticated operator identity and in-memory CSRF token."""

    model_config = ConfigDict(extra="forbid")
    email: str
    csrf_token: str = Field(description="Keep in memory and send in X-CSRF-Token for writes.")


class AuthStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    authenticated: bool
    email_masked: str | None
    signup_available: bool


class ScanSummaryResponse(BaseModel):
    """Path-free persisted scan summary identified by its stable scan ID."""

    model_config = ConfigDict(extra="forbid")
    scan_id: str
    started_at: datetime
    finished_at: datetime | None
    status: str
    scanner: str
    project_types: list[str]
    finding_count: int
    verdict: ScanVerdict | None = None
    coverage_gap_count: int = 0


class ScanDetailResponse(ScanSummaryResponse):
    schema_version: str = "1.0"
    project_id: str | None = None
    project_removed: bool = False
    target_id: str
    finding_ids: list[str]
    event_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    timeline_entry_ids: list[str] = Field(default_factory=list)
    location_ids: list[str] = Field(default_factory=list)
    scan_options: dict[str, str | int | float | bool] = Field(default_factory=dict)
    coverage: CoverageReport | None = None
    failures: dict[str, str] = Field(default_factory=dict)
    code_assessment: CodeAssessmentSummary | None = None


class FindingSummaryResponse(BaseModel):
    """Reviewed, redacted finding fields approved for dashboard display."""

    model_config = ConfigDict(extra="forbid")
    finding_id: str
    title: str
    severity: Severity
    category: FindingCategory
    confidence: Confidence
    scanner: str
    rule_id: str
    contributing_rule_ids: list[str] = Field(default_factory=list)


class FindingDetailResponse(FindingSummaryResponse):
    description: str = ""
    location: str | None = None
    tags: list[str] = Field(default_factory=list)
    evidence: EvidenceKind | None = None
    line_numbers: list[int] = Field(default_factory=list)
    code_excerpt: str | None = None
    remediation: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    exposure: str = "unknown"
    explanation: FindingExplanation | None = None


class OverviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_count: int
    finding_count: int
    findings_by_severity: dict[Severity, int]
    recent_scans: list[ScanSummaryResponse]


class ScanPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[ScanSummaryResponse]
    total: int
    limit: int
    offset: int


class FindingPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[FindingSummaryResponse]
    total: int
    total_stored: int
    limit: int
    offset: int


class CaseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: str = Field(min_length=1, max_length=255)
    title: str | None = Field(default=None, max_length=200)
    description: str = Field(default="", max_length=8000)
    severity: Severity = Severity.MEDIUM


class CaseNoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(min_length=1, max_length=8000)


class CaseLinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_type: str = Field(min_length=1, max_length=80)
    record_id: str = Field(min_length=1, max_length=255)


class CaseStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: CaseStatus


class GitHubPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=300)
    ref: str | None = Field(default=None, max_length=100)


class GitHubImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preview_id: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=120)
    replace_project_id: str | None = Field(default=None, max_length=80)
    replace_confirmation: str | None = Field(default=None, max_length=120)


class CodeJobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str = Field(min_length=1, max_length=80)


class ProjectCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    directory_id: str = Field(min_length=32, max_length=128)


class FolderApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    directory_id: str = Field(min_length=32, max_length=128)
    approved: bool
    name: str | None = Field(default=None, min_length=1, max_length=120)
    purpose: Literal["project", "logs", "malware"] = "project"


class ProjectRemoveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation: str = Field(min_length=1, max_length=120)


class LogJobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str = Field(min_length=1, max_length=80)


class ProjectLogLocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    directory_id: str = Field(min_length=32, max_length=128)
    scope: Literal["project", "external"] = "project"


class ProjectLogLocationRemoveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation: str = Field(min_length=1, max_length=120)


class ProjectLogJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    location_ids: list[str] | None = Field(default=None, max_length=20)


class LogSuggestionConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suggestion_id: str = Field(min_length=16, max_length=128)
    name: str = Field(min_length=1, max_length=120)


class MalwareJobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    registry_id: str | None = Field(default=None, min_length=1, max_length=80)
    sample_id: str | None = Field(default=None, min_length=1, max_length=255)
    profile: Literal["builtin_static"] = "builtin_static"


class MalwareAcknowledgementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str = Field(min_length=1, max_length=80)
    confirmed: bool = False
    typed_phrase: str | None = Field(default=None, max_length=80)


class ProjectMalwareJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    acknowledgement_token: str | None = Field(default=None, min_length=32, max_length=128)
    profile: Literal["builtin_static"]


class MalwareSampleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    registry_id: str | None
    display_name: str
    state: Literal["registered", "managed", "unavailable"]
    source_available: bool
    source_size_bytes: int | None
    sample_id: str | None
    sha256: str | None
    managed_size_bytes: int | None
    availability: str | None


class MalwareJobResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str
    sample_id: str
    status: Literal["queued", "running", "succeeded", "failed", "interrupted"]
    created_at: str
    started_at: str | None
    finished_at: str | None
    analysis_id: str | None
    warning: str | None
    analysis_status: Literal["complete", "partial"] | None = None


class MalwareJobPageResponse(BaseModel):
    items: list[MalwareJobResponse]
    total: int
    limit: int
    offset: int


class MalwareAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_id: str
    sample_id: str
    profile: str
    status: Literal["complete", "partial"]
    created_at: str
    size_bytes: int
    hashes: dict[str, str]
    file_type: str
    architecture: str | None
    printable_string_count: int
    indicator_count: int
    indicators: list[dict[str, str]]
    warnings: list[str]
    engines: dict[str, dict[str, Any]]
    evidence_note: str


class CodeProjectResponse(BaseModel):
    project_id: str
    display_name: str


class CodeJobResponse(BaseModel):
    job_id: str
    project_id: str
    project_name: str
    status: Literal["queued", "running", "succeeded", "failed", "interrupted"]
    created_at: str
    started_at: str | None
    finished_at: str | None
    scan_id: str | None
    error: str | None
    warning: str | None = None


class CodeJobPageResponse(BaseModel):
    items: list[CodeJobResponse]
    total: int
    limit: int
    offset: int


class LogSourceResponse(BaseModel):
    source_id: str
    display_name: str


class LogJobResponse(BaseModel):
    job_id: str
    source_id: str
    source_name: str
    status: Literal["queued", "running", "succeeded", "partial", "failed", "interrupted"]
    created_at: str
    started_at: str | None
    finished_at: str | None
    scan_id: str | None
    event_count: int
    alert_count: int
    error_count: int
    error: str | None
    diagnostics: list[str] = Field(default_factory=list)
    project_id: str | None = None
    location_ids: list[str] = Field(default_factory=list)
    skipped_counts: dict[str, int] = Field(default_factory=dict)
    error_code: str | None = None


class LogJobPageResponse(BaseModel):
    items: list[LogJobResponse]
    total: int
    limit: int
    offset: int


class AlertResponse(BaseModel):
    alert_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    rule_id: str
    event_ids: list[str]
    indicator_ids: list[str]
    mitre_attack_techniques: list[str]


class EventResponse(BaseModel):
    event_id: str
    occurred_at: datetime
    kind: str
    summary: str
    source: str
    source_ip: str | None
    destination_ip: str | None
    user: str | None
    host: str | None
    process: str | None
    url: str | None
    event_outcome: str | None
    mitre_attack_techniques: list[str]


class TimelineResponse(BaseModel):
    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class AlertPageResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    limit: int
    offset: int


class EventPageResponse(BaseModel):
    items: list[EventResponse]
    total: int
    limit: int
    offset: int


def _loopback_host(host: str) -> bool:
    value = host.strip().lower()
    hostname = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    return hostname in {"127.0.0.1", "localhost"}


def create_app(
    database_path: Path | str,
    credential_path: Path | str,
    *,
    session_ttl_seconds: int | None = None,
    secure_cookie: bool = False,
    serve_frontend: bool = True,
    projects_path: Path | str | None = None,
    log_sources_path: Path | str | None = None,
    malware_registry_path: Path | str | None = None,
    settings: Settings | None = None,
    github_import_test_file_transport: bool = False,
    project_operation_rate_limit: int = 20,
) -> FastAPI:
    """Create an application instance; sessions and throttling live in this process."""
    configure_logging()
    active_settings = settings or Settings(_env_file=None)
    repository = SQLiteRepository(database_path)
    db_lock = threading.RLock()
    absolute_ttl_seconds = (
        session_ttl_seconds
        if session_ttl_seconds is not None
        else active_settings.session_absolute_ttl_seconds
    )
    idle_ttl_seconds = active_settings.session_idle_ttl_seconds
    sessions = SessionStore(absolute_ttl_seconds, idle_ttl_seconds)
    credentials = Path(credential_path)
    try:
        migrate_legacy_operator(credentials)
    except CredentialError:
        logging.getLogger("chinescan.auth").warning("operator_credentials_need_recovery")
    registry = ProjectRegistry(
        projects_path,
        [
            Path(database_path).parent,
            credentials,
            Path(projects_path)
            if projects_path
            else Path.home() / ".config" / "chinescan" / "projects.toml",
        ],
    )
    log_registry = LogSourceRegistry(
        log_sources_path,
        [
            Path(database_path).parent,
            credentials,
            Path(projects_path)
            if projects_path
            else Path.home() / ".config" / "chinescan" / "projects.toml",
            Path(log_sources_path)
            if log_sources_path
            else Path.home() / ".config" / "chinescan" / "log-sources.toml",
        ],
    )
    malware_jobs: MalwareDashboardManager | None = None
    malware_diagnostic = (
        "Execution unavailable: configure managed storage and an operator registry."
    )
    rate_limiter = InProcessRateLimiter(
        {
            "auth": (active_settings.auth_rate_limit, active_settings.rate_limit_window_seconds),
            "job_start": (
                active_settings.job_start_rate_limit,
                active_settings.rate_limit_window_seconds,
            ),
            "exports": (
                active_settings.export_rate_limit,
                active_settings.rate_limit_window_seconds,
            ),
            "reads": (
                active_settings.read_rate_limit,
                active_settings.rate_limit_window_seconds,
            ),
        }
    )
    hard_denied, soft_denied = policy_paths(active_settings)
    fs_browser = FilesystemBrowserService(
        list(active_settings.allowed_roots),
        hard_denied,
        soft_denied,
        active_settings.allow_soft_denied,
    )
    github_managed_directory = Path(database_path).expanduser().resolve(strict=False).parent / "gh"
    project_service = ProjectService(
        repository,
        fs_browser,
        registry,
        allowed_roots=list(active_settings.allowed_roots),
        hard_denied=hard_denied,
        soft_denied=soft_denied,
        allow_soft_denied=active_settings.allow_soft_denied,
        managed_import_directory=github_managed_directory,
    )
    log_location_service = LogLocationService(repository, project_service)
    log_jobs = LogJobManager(
        repository, db_lock, log_registry, project_locations=log_location_service
    )
    malware_acknowledgements = MalwareAcknowledgements(repository)
    project_malware_jobs = ProjectMalwareJobs(
        repository, ProjectMalwareScanner(repository, project_service, active_settings)
    )
    github_imports = GitHubImportService(
        repository,
        active_settings,
        github_managed_directory,
        test_file_transport=github_import_test_file_transport,
        project_service=project_service,
    )
    jobs = CodeJobManager(
        repository,
        db_lock,
        project_service,
        reports_dir=active_settings.reports_dir,
        bounds=ScanBounds(
            max_files=active_settings.max_files,
            max_total_bytes=active_settings.max_total_bytes,
            max_file_bytes=active_settings.max_file_bytes,
            max_depth=active_settings.max_depth,
            per_file_seconds=active_settings.per_file_seconds,
            job_deadline_seconds=active_settings.job_deadline_seconds,
            excluded_paths=tuple(active_settings.code_excluded_paths),
        ),
    )
    chain_jobs = ChainTraceJobManager(repository, active_settings)
    project_throttle = LoginThrottle(limit=project_operation_rate_limit, window_seconds=60)
    fs_browse_throttle = LoginThrottle(limit=60, window_seconds=60)
    malware_config = (
        Path(malware_registry_path)
        if malware_registry_path
        else Path.home() / ".config" / "chinescan" / "malware-samples.toml"
    )
    try:
        backend, sample_registry = create_backend(
            repository,
            active_settings,
            malware_config,
            additional_protected_paths=[
                credentials,
                Path(projects_path)
                if projects_path
                else Path.home() / ".config" / "chinescan" / "projects.toml",
                Path(log_sources_path)
                if log_sources_path
                else Path.home() / ".config" / "chinescan" / "log-sources.toml",
            ],
        )
        malware_jobs = MalwareDashboardManager(repository, backend, sample_registry)
        malware_diagnostic = (
            "Execution unavailable: Windows Job Object containment is required."
            if not malware_jobs.execution_available
            else ""
        )
    except (ManagedSampleError, OSError, ValueError):
        malware_diagnostic = "Managed storage or operator registry configuration is unavailable."

    @asynccontextmanager
    async def lifespan(_application: FastAPI) -> AsyncIterator[None]:
        jobs.start()
        chain_jobs.start()
        log_jobs.start()
        project_malware_jobs.start()
        github_imports.start_worker()
        if malware_jobs is not None:
            malware_jobs.start()
        try:
            yield
        finally:
            if malware_jobs is not None:
                malware_jobs.stop()
            log_jobs.stop()
            project_malware_jobs.stop()
            github_imports.stop_worker()
            jobs.stop()
            chain_jobs.stop()
        repository.close()

    application = FastAPI(
        title="ChiNeScan local dashboard", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    application.state.repository = repository
    application.state.project_registry = registry
    application.state.chain_job_manager = chain_jobs
    application.state.project_service = project_service
    application.state.log_location_service = log_location_service
    application.state.log_source_registry = log_registry
    application.state.log_job_manager = log_jobs
    application.state.malware_job_manager = malware_jobs
    application.state.project_malware_job_manager = project_malware_jobs
    application.state.github_import_manager = github_imports
    application.state.started_at = time.monotonic()
    application.state.diagnostic_errors = []

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError) -> Response:
        # Pydantic errors may contain submitted values (including login passwords).
        details = [
            {
                "type": item.get("type", "invalid_request"),
                "loc": item.get("loc", []),
                "msg": redact(item.get("msg", "Invalid request.")),
            }
            for item in exc.errors()
        ]
        return Response(
            content=json.dumps({"detail": details}),
            status_code=422,
            media_type="application/json",
        )

    @application.exception_handler(HTTPException)
    async def safe_http_error_handler(_request: Request, exc: HTTPException) -> Response:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": redact(exc.detail)},
            headers=exc.headers,
        )

    @application.exception_handler(Exception)
    async def safe_internal_error_handler(request: Request, _exc: Exception) -> Response:
        route = request.scope.get("route")
        logging.getLogger("chinescan.errors").error(
            "request_failed",
            extra={
                "request_id": getattr(request.state, "request_id", "unknown"),
                "route": getattr(route, "path", "unmatched"),
            },
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "The request could not be completed."},
        )

    @application.middleware("http")
    async def loopback_and_origin_guard(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # The version prefix is an alias only; all existing route dependencies,
        # authentication checks, and response filtering remain shared.
        if request.url.path.startswith("/api/v1/"):
            rewritten = "/api/" + request.url.path[len("/api/v1/") :]
            request.scope["path"] = rewritten
            request.scope["raw_path"] = rewritten.encode("ascii", errors="ignore")
        request_id = str(uuid4())
        request.state.request_id = request_id
        started = time.monotonic()
        host = request.headers.get("host", "")
        client_ip = request.client.host if request.client else ""
        if not _loopback_host(host) or not _loopback_host(client_ip):
            result = Response("Local loopback access required.", status_code=400)
            result.headers["X-Request-ID"] = request_id
            return result
        if request.url.path.startswith("/api/fs/"):
            origin = request.headers.get("origin")
            if origin:
                parsed_origin = urlsplit(origin)
                if (
                    parsed_origin.scheme != request.url.scheme
                    or parsed_origin.netloc.lower() != host.lower()
                    or parsed_origin.path not in {"", "/"}
                    or parsed_origin.query
                    or parsed_origin.fragment
                    or parsed_origin.username
                    or parsed_origin.password
                ):
                    result = Response("Same-origin request required.", status_code=403)
                    result.headers["X-Request-ID"] = request_id
                    return result
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                maximum_body = (
                    2_100_000
                    if request.url.path == "/api/chain/jobs"
                    else MAX_EXTERNAL_REPORT_BYTES
                    if request.url.path.endswith("/external-reports")
                    else 8192
                )
                if int(content_length) > maximum_body:
                    result = Response("Request body is too large.", status_code=413)
                    result.headers["X-Request-ID"] = request_id
                    return result
            except ValueError:
                result = Response("Invalid request framing.", status_code=400)
                result.headers["X-Request-ID"] = request_id
                return result
        if request.headers.get("transfer-encoding"):
            result = Response("Chunked request bodies are not accepted.", status_code=400)
            result.headers["X-Request-ID"] = request_id
            return result
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if not origin:
                result = Response("Same-origin request required.", status_code=403)
                result.headers["X-Request-ID"] = request_id
                return result
            parsed = urlsplit(origin)
            origin_authority = parsed.netloc
            if (
                parsed.scheme != request.url.scheme
                or origin_authority.lower() != host.lower()
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
            ):
                result = Response("Same-origin request required.", status_code=403)
                result.headers["X-Request-ID"] = request_id
                return result
        if request.url.path.startswith("/api/"):
            path = request.url.path
            if path in {
                "/api/auth/login",
                "/api/auth/signup",
                "/api/auth/forgot-password",
                "/api/auth/reset-password",
            }:
                category = "auth"
            elif "/report/" in path or "/export/" in path or "/exports/" in path:
                category = "exports"
            elif request.method == "GET":
                category = "reads"
            else:
                category = "job_start"
            client_key = request.client.host if request.client else "unknown"
            if active_settings.trusted_proxy:
                forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
                if forwarded:
                    client_key = forwarded[:64]
            retry = rate_limiter.check(category, client_key)
            if retry:
                limited = JSONResponse(
                    status_code=429,
                    content={
                        "detail": {
                            "code": "rate_limited",
                            "message": "Request limit reached; retry shortly.",
                        }
                    },
                    headers={"Retry-After": str(retry)},
                )
                limited.headers["X-Request-ID"] = request_id
                limited.headers["X-API-Version"] = "1"
                limited.headers["X-Content-Type-Options"] = "nosniff"
                limited.headers["X-Frame-Options"] = "DENY"
                limited.headers["Referrer-Policy"] = "no-referrer"
                limited.headers["Content-Security-Policy"] = (
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                    "base-uri 'self'; frame-ancestors 'none'"
                )
                return limited
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-API-Version"] = "1"
        route = request.scope.get("route")
        if response.status_code >= 400 and request.url.path.startswith("/api/"):
            error_ring = application.state.diagnostic_errors
            error_ring.append(
                {
                    "error_code": f"http_{response.status_code}",
                    "route": str(getattr(route, "path", "unmatched"))[:120],
                    "request_id": request_id,
                    "timestamp": datetime.now().astimezone().isoformat(),
                    "message": "Request could not be completed."
                    if response.status_code >= 500
                    else "Request was rejected.",
                }
            )
            del error_ring[:-50]
        duration_ms = round((time.monotonic() - started) * 1000, 2)
        access_logger = logging.getLogger("chinescan.access")
        access_logger.info(
            "request_complete",
            extra={
                "request_id": request_id,
                "method": request.method,
                "route": getattr(route, "path", request.url.path),
                "status": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        if duration_ms >= 1000:
            access_logger.warning(
                "slow_request",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "route": getattr(route, "path", request.url.path),
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                },
            )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "private, no-store"
        return response

    def current_session(token: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> Session:
        session = sessions.get(token)
        if session is None:
            raise HTTPException(status_code=401, detail="Authentication required.")
        try:
            if not secrets.compare_digest(session.auth_epoch, operator_auth_epoch(credentials)):
                sessions.revoke(token)
                raise HTTPException(status_code=401, detail="Authentication required.")
        except CredentialError:
            sessions.revoke(token)
            raise HTTPException(status_code=401, detail="Authentication required.") from None
        return session

    diagnostics_throttle = LoginThrottle(limit=12, window_seconds=60)

    def allow_diagnostics(request: Request) -> None:
        key = "diagnostics:" + (request.client.host if request.client else "unknown")
        if not diagnostics_throttle.allowed(key):
            raise HTTPException(
                status_code=429, detail="Diagnostics rate limit reached; retry shortly."
            )

    @application.get("/api/health")
    def health() -> dict[str, Any]:
        return health_report(started_at=application.state.started_at, bind_address="127.0.0.1")

    @application.get("/api/ready")
    def ready(request: Request, _session: Session = Depends(current_session)) -> Response:  # noqa: B008
        allow_diagnostics(request)
        report = build_report(
            settings=active_settings,
            database_path=database_path,
            credential_path=credentials,
            frontend_dist=FRONTEND_DIST,
            errors=application.state.diagnostic_errors,
        )
        readiness_ids = {
            "config",
            "credentials",
            "database",
            "directories",
            "frontend",
            "filesystem-policy",
            "managed-malware",
        }
        checks = [dict(item) for item in report["checks"] if item["id"] in readiness_ids]
        if report["operator_state"] != "active":
            for item in checks:
                if item["id"] == "credentials":
                    item["state"] = "FAIL"
                    item["detail"] = "Credential store is not active and schema-valid."
                    item["action_hint"] = "Create or migrate the local operator credential store."
        failures = any(item["state"] == "FAIL" for item in checks)
        warnings = any(item["state"] == "WARN" for item in checks)
        state = "failed" if failures else "degraded" if warnings else "ok"
        response = JSONResponse(
            {"state": state, "checks": checks, "allowed_roots": report["allowed_roots"]},
            status_code=503 if failures else 200,
        )
        return response

    @application.get("/api/diagnostics")
    def diagnostics(
        request: Request,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        allow_diagnostics(request)
        return build_report(
            settings=active_settings,
            database_path=database_path,
            credential_path=credentials,
            frontend_dist=FRONTEND_DIST,
            errors=application.state.diagnostic_errors,
        )

    def require_csrf(
        session: Session = Depends(current_session),  # noqa: B008
        token: str | None = Cookie(default=None, alias=COOKIE_NAME),
        csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
    ) -> Session:
        import secrets

        if not csrf_header or not secrets.compare_digest(session.csrf_token, csrf_header):
            raise HTTPException(status_code=403, detail="CSRF validation failed.")
        return session

    def github_import_enabled() -> None:
        if not active_settings.github_import_enabled:
            raise HTTPException(
                status_code=403,
                detail={"code": "feature_disabled", "message": "GitHub import is disabled."},
            )

    github_import_throttle = LoginThrottle(limit=10, window_seconds=60)

    def github_import_error(exc: GitHubImportError) -> HTTPException:
        status_code = (
            422
            if exc.code in {"invalid_url", "invalid_ref", "invalid_name"}
            else 429
            if exc.code in {"queue_full", "rate_limited"}
            else 404
            if exc.code == "job_not_found"
            else 409
            if exc.code.startswith("preview_")
            else 503
            if exc.code == "git_missing"
            else 400
        )
        return HTTPException(status_code, detail={"code": exc.code, "message": str(exc)})

    def allow_github_import(request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        if not github_import_throttle.allowed("github-import:" + client_ip):
            raise HTTPException(
                status_code=429,
                detail={"code": "rate_limited", "message": "GitHub import rate limit reached."},
            )

    @application.get("/api/github/status")
    def github_import_status_info(
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        return {
            "enabled": active_settings.github_import_enabled,
            "git_available": shutil.which("git") is not None,
            "max_bytes": active_settings.github_import_max_bytes,
            "max_files": active_settings.github_import_max_files,
            "max_projects": active_settings.github_import_max_projects,
            "timeout_seconds": active_settings.github_import_timeout_seconds,
        }

    @application.post("/api/github/previews")
    def github_preview(
        payload: GitHubPreviewRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        github_import_enabled()
        allow_github_import(request)
        try:
            return github_imports.preview(
                session_binding(session.csrf_token), payload.url, payload.ref
            )
        except GitHubImportError as exc:
            raise github_import_error(exc) from exc

    @application.post("/api/github/imports", status_code=202)
    def github_import(
        payload: GitHubImportRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        github_import_enabled()
        allow_github_import(request)
        try:
            return github_imports.start(
                session_binding(session.csrf_token),
                payload.preview_id,
                payload.name,
                replace_project_id=payload.replace_project_id,
                replace_confirmation=payload.replace_confirmation,
            )
        except GitHubImportError as exc:
            raise github_import_error(exc) from exc

    @application.get("/api/github/imports/{job_id}")
    def github_import_status(
        job_id: str,
        session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        github_import_enabled()
        try:
            return github_imports.get(session_binding(session.csrf_token), job_id)
        except GitHubImportError as exc:
            raise github_import_error(exc) from exc

    @application.post("/api/github/imports/{job_id}/cancel")
    def github_import_cancel(
        job_id: str,
        _request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        github_import_enabled()
        allow_github_import(_request)
        try:
            return github_imports.cancel(session_binding(session.csrf_token), job_id)
        except GitHubImportError as exc:
            raise github_import_error(exc) from exc

    auth_lockout = ProgressiveLockout()

    def lockout_keys(request: Request, email: str) -> list[str]:
        ip = request.client.host if request.client else "unknown"
        return [f"ip:{ip}", f"email:{email.casefold()}"]

    def lockout_response(retry: int) -> HTTPException:
        return HTTPException(
            status_code=429,
            detail="Authentication request could not be completed. Try again later.",
            headers={"Retry-After": str(max(1, retry))},
        )

    @application.get("/api/auth/session", response_model=AuthStatusResponse)
    def auth_session(token: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> dict[str, Any]:
        session = sessions.get(token)
        if session is not None:
            try:
                if not secrets.compare_digest(session.auth_epoch, operator_auth_epoch(credentials)):
                    session = None
            except CredentialError:
                session = None
        email = session.email if session else None
        local, separator, domain = email.partition("@") if email else ("", "", "")
        masked = f"{local[:1]}***{separator}{domain}" if separator else None
        return {
            "authenticated": session is not None,
            "email_masked": masked,
            "signup_available": operator_status(credentials) == "none",
        }

    @application.get("/api/auth/csrf")
    def auth_csrf(session: Session = Depends(current_session)) -> dict[str, str]:  # noqa: B008
        return {"csrf_token": session.csrf_token}

    @application.post("/api/auth/login", response_model=AuthSessionResponse)
    def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, str]:
        keys = lockout_keys(request, payload.email)
        retry = auth_lockout.retry_after(keys)
        if retry:
            raise lockout_response(retry)
        try:
            valid = verify_operator(credentials, payload.email, payload.password)
            if valid and operator_totp_enabled(credentials):
                valid = bool(payload.totp_code) and verify_operator_totp(
                    credentials, payload.totp_code or ""
                )
        except Exception:
            valid = False
        if not valid:
            retry = auth_lockout.fail(keys)
            if retry:
                raise lockout_response(retry)
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        auth_lockout.succeed(keys)
        sessions.revoke(request.cookies.get(COOKIE_NAME))
        stored_email = normalize_email(payload.email)
        opaque, session = sessions.create(stored_email, operator_auth_epoch(credentials))
        response.set_cookie(
            COOKIE_NAME,
            opaque,
            httponly=True,
            secure=secure_cookie,
            samesite="strict",
            max_age=absolute_ttl_seconds,
            path="/",
        )
        return {"email": session.email, "csrf_token": session.csrf_token}

    @application.post("/api/auth/signup", response_model=AuthSessionResponse, status_code=201)
    def signup(payload: SignupRequest, request: Request, response: Response) -> dict[str, str]:
        keys = lockout_keys(request, payload.email)
        retry = auth_lockout.retry_after(keys)
        if retry:
            raise lockout_response(retry)
        try:
            create_operator(credentials, payload.email, payload.password)
        except CredentialError:
            retry = auth_lockout.fail(keys)
            if retry:
                raise lockout_response(retry) from None
            raise HTTPException(
                status_code=400, detail="Account cannot be created with these details."
            ) from None
        auth_lockout.succeed(keys)
        opaque, session = sessions.create(payload.email, operator_auth_epoch(credentials))
        response.set_cookie(
            COOKIE_NAME,
            opaque,
            httponly=True,
            secure=secure_cookie,
            samesite="strict",
            max_age=absolute_ttl_seconds,
            path="/",
        )
        return {"email": session.email, "csrf_token": session.csrf_token}

    @application.post("/api/auth/forgot-password", response_model=dict[str, str], status_code=202)
    def forgot_password(payload: ForgotPasswordRequest, request: Request) -> dict[str, str]:
        keys = lockout_keys(request, payload.email)
        retry = auth_lockout.retry_after(keys)
        if retry:
            raise lockout_response(retry)
        perform_dummy_verification(payload.email)
        auth_lockout.fail(keys)
        return {
            "status": (
                "If the account exists, reset instructions are prepared. Run "
                "`uv run chinescan web reset-password --email <email>` on this machine."
            )
        }

    @application.post("/api/auth/reset-password", response_model=dict[str, str])
    def reset_password(payload: ResetPasswordRequest, request: Request) -> dict[str, str]:
        keys = lockout_keys(request, payload.email)
        retry = auth_lockout.retry_after(keys)
        if retry:
            raise lockout_response(retry)
        if not reset_operator_password(credentials, payload.email, payload.token, payload.password):
            retry = auth_lockout.fail(keys)
            if retry:
                raise lockout_response(retry)
            raise HTTPException(
                status_code=400, detail="Reset could not be completed. Request a new local token."
            )
        auth_lockout.succeed(keys)
        sessions.revoke_all()
        return {"status": "Password reset. Sign in with your new password."}

    @application.post("/api/auth/logout", response_model=dict[str, str])
    def logout(
        response: Response,
        _session: Session = Depends(require_csrf),  # noqa: B008
        token: str | None = Cookie(default=None, alias=COOKIE_NAME),
    ) -> dict[str, str]:
        sessions.revoke(token)
        response.delete_cookie(
            COOKIE_NAME, path="/", secure=secure_cookie, httponly=True, samesite="strict"
        )
        return {"status": "logged_out"}

    @application.get("/api/overview", response_model=OverviewResponse)
    def overview(_session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        with db_lock:
            scan_page, scan_count = repository.page_records(
                "scan", limit=5, offset=0, sort_by="started_at", descending=True
            )
            finding_count = repository.count_records("finding")
            grouped = repository.count_records("finding", group_by="severity")
        counts = {severity.value: int(grouped.get(severity.value, 0)) for severity in Severity}
        recent = [Scan.model_validate(item) for item in scan_page]
        return {
            "scan_count": scan_count,
            "finding_count": finding_count,
            "findings_by_severity": counts,
            "recent_scans": [_scan_summary(scan) for scan in recent],
        }

    @application.get("/api/projects")
    def list_projects(_session: Session = Depends(current_session)) -> list[dict[str, Any]]:  # noqa: B008
        return project_service.list()

    @application.get("/api/projects/{project_id}")
    def get_project(
        project_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        try:
            return project_service.get(project_id)
        except ProjectError as exc:
            raise HTTPException(
                status_code=404, detail={"code": exc.code, "message": str(exc)}
            ) from exc

    @application.get("/api/projects/{project_id}/browse")
    def browse_project_directory(
        project_id: str,
        request: Request,
        directory_id: Annotated[str | None, Query(min_length=32, max_length=128)] = None,
        session: Session = Depends(current_session),  # noqa: B008
        cursor: Annotated[str | None, Query(max_length=128)] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        try:
            if directory_id is None:
                _, root = project_service.resolve(project_id)
                return fs_browser.project_root_view(session.csrf_token, root)
            selection = fs_browser.resolve_selection(
                session.csrf_token, "project_directory", directory_id
            )
            _, root = project_service.resolve(project_id)
            try:
                selection.relative_to(root)
            except ValueError as exc:
                raise ValueError("directory_unavailable") from exc
            return fs_browser.list_view(
                session.csrf_token, "project_directory", directory_id, cursor=cursor, limit=limit
            )
        except (ProjectError, ValueError) as exc:
            raise HTTPException(
                status_code=404, detail="Directory selection is unavailable."
            ) from exc

    @application.get("/api/projects/{project_id}/log-locations")
    def list_project_log_locations(
        project_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> list[dict[str, Any]]:  # noqa: B008
        try:
            return log_location_service.list(project_id)
        except ProjectError as exc:
            raise HTTPException(
                status_code=404, detail={"code": exc.code, "message": str(exc)}
            ) from exc

    @application.post("/api/projects/{project_id}/log-locations", status_code=201)
    def add_project_log_location(
        project_id: str,
        payload: ProjectLogLocationRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            capability: Literal["project_directory", "log_location"] = (
                "project_directory" if payload.scope == "project" else "log_location"
            )
            selected = fs_browser.resolve_selection(
                session.csrf_token, capability, payload.directory_id
            )
            return log_location_service.add(project_id, payload.name, selected, payload.scope)
        except (ProjectError, ValueError) as exc:
            code = exc.code if isinstance(exc, ProjectError) else "directory_unavailable"
            raise HTTPException(
                status_code=422,
                detail={
                    "code": code,
                    "message": str(exc)
                    if isinstance(exc, ProjectError)
                    else "The selected folder is unavailable.",
                },
            ) from exc

    @application.delete("/api/projects/{project_id}/log-locations/{location_id}")
    def remove_project_log_location(
        project_id: str,
        location_id: str,
        payload: ProjectLogLocationRemoveRequest,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, str]:  # noqa: B008
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            location = next(
                item
                for item in log_location_service.list(project_id)
                if item["location_id"] == location_id
            )
            if payload.confirmation != location["name"]:
                raise ProjectError(
                    "confirmation_mismatch",
                    "Type the log location name exactly to confirm removal.",
                )
            log_location_service.remove(project_id, location_id)
        except ProjectError as exc:
            raise HTTPException(
                status_code=409 if exc.code == "confirmation_mismatch" else 404,
                detail={"code": exc.code, "message": str(exc)},
            ) from exc
        except StopIteration as exc:
            raise HTTPException(status_code=404, detail="Log location not found.") from exc
        return {"status": "removed"}

    @application.post("/api/projects/{project_id}/log-suggestions")
    def project_log_suggestions(
        project_id: str,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            return log_location_service.suggestions(project_id, _session.csrf_token)
        except ProjectError as exc:
            raise HTTPException(
                status_code=404, detail={"code": exc.code, "message": str(exc)}
            ) from exc

    @application.post("/api/projects/{project_id}/log-suggestions/confirm", status_code=201)
    def confirm_project_log_suggestion(
        project_id: str,
        payload: LogSuggestionConfirmRequest,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            return log_location_service.confirm(
                project_id, payload.suggestion_id, payload.name, _session.csrf_token
            )
        except ProjectError as exc:
            raise HTTPException(
                status_code=422, detail={"code": exc.code, "message": str(exc)}
            ) from exc

    @application.post(
        "/api/projects/{project_id}/log-jobs",
        response_model=LogJobResponse,
        status_code=202,
    )
    def create_project_log_job(
        project_id: str,
        payload: ProjectLogJobRequest,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            return log_jobs.submit_project(project_id, payload.location_ids)
        except ProjectError as exc:
            raise HTTPException(
                status_code=422, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        except LogSourceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail="The log analysis queue is full.") from exc

    @application.post("/api/malware/acknowledgements", status_code=201)
    def issue_malware_acknowledgement(
        payload: MalwareAcknowledgementRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, str]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("malware-ack:" + client_ip):
            raise HTTPException(
                status_code=429, detail={"code": "rate_limited", "message": "Try again shortly."}
            )
        try:
            project_service.resolve(payload.project_id)
            return malware_acknowledgements.issue(
                payload.project_id, session.csrf_token, payload.confirmed
            )
        except ProjectError as exc:
            raise HTTPException(
                status_code=404, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        except MalwareAcknowledgementError as exc:
            raise HTTPException(
                status_code=422, detail={"code": exc.code, "message": str(exc)}
            ) from exc

    @application.get("/api/malware/host-hint")
    def malware_host_hint(_session: Session = Depends(current_session)) -> dict[str, str | bool]:  # noqa: B008
        import os
        import platform

        signals = " ".join(
            (
                platform.platform(),
                os.environ.get("PROCESSOR_IDENTIFIER", ""),
                os.environ.get("COMPUTERNAME", ""),
            )
        ).casefold()
        virtualized: bool | str = (
            True
            if any(
                token in signals for token in ("virtual", "vmware", "hyper-v", "kvm", "qemu", "xen")
            )
            else "unknown"
        )
        return {"virtualized": virtualized, "confidence": "low"}

    @application.post("/api/projects/{project_id}/malware-jobs", status_code=202)
    def start_project_malware_job(
        project_id: str,
        payload: ProjectMalwareJobRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("malware-job:" + client_ip):
            raise HTTPException(
                status_code=429, detail={"code": "rate_limited", "message": "Try again shortly."}
            )
        if not payload.acknowledgement_token:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "invalid_acknowledgement",
                    "message": "A valid project VM-risk acknowledgement is required.",
                },
            )
        try:
            malware_acknowledgements.consume(
                payload.acknowledgement_token, project_id, session.csrf_token
            )
            job = project_malware_jobs.submit(project_id)
            return _safe_project_malware_job(job)
        except MalwareAcknowledgementError as exc:
            raise HTTPException(
                status_code=403, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        except ProjectError as exc:
            raise HTTPException(
                status_code=422, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        except OverflowError as exc:
            raise HTTPException(
                status_code=429,
                detail={"code": "queue_full", "message": "The project scan queue is full."},
            ) from exc

    @application.get("/api/projects/{project_id}/malware-jobs/{job_id}")
    def get_project_malware_job(
        project_id: str,
        job_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        job = project_malware_jobs.get(job_id)
        if job is None or job.get("project_id") != project_id:
            raise HTTPException(
                status_code=404,
                detail={"code": "job_not_found", "message": "Project malware job not found."},
            )
        return _safe_project_malware_job(job)

    @application.post("/api/projects", status_code=201)
    def add_project(
        payload: ProjectCreateRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            return project_service.create_from_selection(
                payload.name, session.csrf_token, payload.directory_id
            )
        except (ProjectError, ValueError) as exc:
            code = exc.code if isinstance(exc, ProjectError) else "directory_unavailable"
            raise HTTPException(
                status_code=422,
                detail={
                    "code": code,
                    "message": str(exc)
                    if isinstance(exc, ProjectError)
                    else "The selected folder is unavailable.",
                },
            ) from exc

    @application.post("/api/projects/approve-folder", status_code=201)
    def approve_project_folder(
        payload: FolderApprovalRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        if payload.approved is not True:
            raise HTTPException(
                status_code=400,
                detail={"code": "approval_required", "message": "Explicit approval is required."},
            )
        try:
            project = project_service.create_from_folder_approval(
                session.csrf_token, payload.directory_id, payload.name
            )
            if payload.purpose == "logs":
                location = log_location_service.add_approved_root(str(project["project_id"]))
                return {**project, "log_location_id": location["location_id"]}
            return project
        except ProjectError as exc:
            raise HTTPException(
                status_code=422,
                detail={"code": exc.code, "message": str(exc)},
            ) from exc
        except ValueError as exc:
            code = str(exc)
            raise HTTPException(
                status_code=422,
                detail={"code": code, "message": folder_approval_error(code)},
            ) from exc

    @application.delete("/api/projects/{project_id}")
    def remove_project(
        project_id: str,
        payload: ProjectRemoveRequest,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, str]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            project_service.remove(project_id, payload.confirmation)
        except ProjectError as exc:
            raise HTTPException(
                status_code=409, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        return {"status": "removed"}

    @application.post(
        "/api/projects/{project_id}/code-jobs", response_model=CodeJobResponse, status_code=202
    )
    def create_project_code_job(
        project_id: str,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            return jobs.submit(project_id)
        except ProjectError as exc:
            raise HTTPException(
                status_code=422, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        except OverflowError as exc:
            raise HTTPException(
                status_code=429, detail="The code assessment queue is full."
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=409, detail="An assessment is already queued or running."
            ) from exc

    @application.get("/api/code/projects", response_model=list[CodeProjectResponse])
    def code_projects(_session: Session = Depends(current_session)) -> list[dict[str, str]]:  # noqa: B008
        return project_service.code_projects()

    @application.post("/api/code/jobs", response_model=CodeJobResponse, status_code=202)
    def create_code_job(
        payload: CodeJobCreateRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        try:
            return jobs.submit(payload.project_id)
        except ProjectConfigurationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except OverflowError as exc:
            raise HTTPException(
                status_code=429, detail="The code assessment queue is full."
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=409,
                detail="An assessment for this project is already queued or running.",
            ) from exc

    @application.get("/api/code/jobs", response_model=CodeJobPageResponse)
    def list_code_jobs(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, Any]:
        items, total = jobs.list(limit, offset)
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @application.get("/api/code/jobs/{job_id}", response_model=CodeJobResponse)
    def get_code_job(job_id: str, _session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        item = jobs.get(job_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Code assessment job not found.")
        return item

    @application.get("/api/malware/capability")
    def malware_capability(_session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        return {
            "execution_available": bool(malware_jobs and malware_jobs.execution_available),
            "diagnostic": (
                malware_jobs.execution_diagnostic if malware_jobs else malware_diagnostic
            ),
            "historical_views_available": True,
        }

    @application.get("/api/malware/samples", response_model=list[MalwareSampleResponse])
    def malware_samples(_session: Session = Depends(current_session)) -> list[dict[str, Any]]:  # noqa: B008
        if malware_jobs is None:
            raise HTTPException(status_code=503, detail="Sample registry is unavailable.")
        try:
            entries = malware_jobs.entries()
        except ManagedSampleError as exc:
            raise HTTPException(status_code=503, detail="Sample registry is unavailable.") from exc
        return [
            {**entry, "display_name": safe_display_name(str(entry["display_name"]))}
            for entry in entries
        ]

    @application.get("/api/malware/samples/{sample_id}", response_model=MalwareSampleResponse)
    def malware_sample_detail(
        sample_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        if len(sample_id) > 255:
            raise HTTPException(status_code=404, detail="Managed sample not found.")
        raw = repository.get("malware_sample", sample_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Managed sample not found.")
        availability = str(raw.get("availability", "unavailable"))
        if malware_jobs is None:
            availability = "unavailable"
        elif availability == "available":
            try:
                malware_jobs.manager.store.verify(
                    str(raw.get("object_key", "")), str(raw.get("sha256", ""))
                )
            except ManagedSampleError:
                availability = "unavailable"
                raw["availability"] = availability
                repository.save("malware_sample", sample_id, raw)
        return {
            "registry_id": str(raw.get("registry_id", ""))[:80],
            "display_name": safe_display_name(str(raw.get("display_name", "Sample"))),
            "state": "managed" if availability == "available" else "unavailable",
            "source_available": False,
            "source_size_bytes": None,
            "sample_id": str(raw.get("sample_id", "")),
            "sha256": str(raw.get("sha256", "")),
            "managed_size_bytes": raw.get("size_bytes")
            if isinstance(raw.get("size_bytes"), int)
            else None,
            "availability": availability,
        }

    @application.post("/api/malware/jobs", response_model=MalwareJobResponse, status_code=202)
    def create_malware_job(
        _payload: MalwareJobCreateRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        raise HTTPException(
            status_code=410,
            detail={
                "code": "sample_workflow_deprecated",
                "message": (
                    "New sample-based jobs are deprecated. Scan an approved project after "
                    "acknowledging VM risk."
                ),
            },
        )

    @application.get("/api/malware/jobs", response_model=MalwareJobPageResponse)
    def list_malware_jobs(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, Any]:  # noqa: B008
        rows, total = repository.page_records(
            "malware_job", limit=limit, offset=offset, sort_by="created_at", descending=True
        )
        return {
            "items": [_malware_job_view(row, repository) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/malware/jobs/{job_id}", response_model=MalwareJobResponse)
    def get_malware_job(
        job_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        row = repository.get("malware_job", job_id) if len(job_id) <= 255 else None
        if row is None:
            raise HTTPException(status_code=404, detail="Malware job not found.")
        return _malware_job_view(row, repository)

    @application.get("/api/malware/analyses/{analysis_id}", response_model=MalwareAnalysisResponse)
    def get_malware_analysis(
        analysis_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        raw = repository.get("malware_analysis", analysis_id) if len(analysis_id) <= 255 else None
        if raw is None:
            raise HTTPException(status_code=404, detail="Malware analysis not found.")
        return _malware_analysis_view(raw)

    @application.get("/api/log/sources", response_model=list[LogSourceResponse])
    def log_sources(_session: Session = Depends(current_session)) -> list[dict[str, str]]:  # noqa: B008
        return log_registry.entries()

    @application.get("/api/log/sources/status")
    def log_sources_status(_session: Session = Depends(current_session)) -> dict[str, str]:  # noqa: B008
        status = log_registry.status()
        return {"status": status["status"], "reason": status["reason"]}

    @application.post("/api/log/jobs", response_model=LogJobResponse, status_code=202)
    def create_log_job(
        payload: LogJobCreateRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            return log_jobs.submit(payload.source_id)
        except LogSourceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail="The log analysis queue is full.") from exc

    @application.get("/api/log/jobs", response_model=LogJobPageResponse)
    def list_log_jobs(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, Any]:
        items, total = log_jobs.list(limit, offset)
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @application.get("/api/log/jobs/{job_id}", response_model=LogJobResponse)
    def get_log_job(job_id: str, _session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        item = log_jobs.get(job_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Log analysis job not found.")
        return item

    def log_scan(scan_id: str) -> Scan:
        if len(scan_id) > 255:
            raise HTTPException(status_code=404, detail="Log analysis not found.")
        with db_lock:
            raw = repository.get("scan", scan_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Log analysis not found.")
        scan = Scan.model_validate(raw)
        if scan.scanner != "chinescan-log-analysis":
            raise HTTPException(status_code=404, detail="Log analysis not found.")
        return scan

    @application.get("/api/log/analyses/{scan_id}/alerts", response_model=AlertPageResponse)
    def log_alerts(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        severity: Annotated[str | None, Query(max_length=20)] = None,
    ) -> dict[str, Any]:
        if severity and severity not in {item.value for item in Severity}:
            raise HTTPException(status_code=422, detail="Unsupported severity filter.")
        scan = log_scan(scan_id)
        with db_lock:
            records = repository.get_many("alert", scan.alert_ids)
        alerts = [Alert.model_validate(records[item]) for item in scan.alert_ids if item in records]
        if severity:
            alerts = [x for x in alerts if x.severity.value == severity]
        alerts.sort(key=lambda x: (x.severity.value, x.title.casefold(), x.alert_id))
        page = alerts[offset : offset + limit]
        return {
            "items": [_alert_summary(x) for x in page],
            "total": len(alerts),
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/log/analyses/{scan_id}/alerts/{alert_id}", response_model=AlertResponse)
    def log_alert_detail(
        scan_id: str,
        alert_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        scan = log_scan(scan_id)
        if alert_id not in scan.alert_ids:
            raise HTTPException(status_code=404, detail="Alert not found.")
        with db_lock:
            raw = repository.get("alert", alert_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        return _alert_summary(Alert.model_validate(raw))

    @application.get("/api/log/analyses/{scan_id}/events", response_model=EventPageResponse)
    def log_events(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        source: Annotated[str | None, Query(max_length=100)] = None,
    ) -> dict[str, Any]:
        scan = log_scan(scan_id)
        with db_lock:
            records = repository.get_many("event", scan.event_ids)
        events = [Event.model_validate(records[item]) for item in scan.event_ids if item in records]
        if source:
            events = [x for x in events if x.source.casefold() == source.casefold()]
        events.sort(key=lambda x: (x.occurred_at, x.event_id), reverse=True)
        page = events[offset : offset + limit]
        return {
            "items": [_event_summary(x) for x in page],
            "total": len(events),
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/log/analyses/{scan_id}/events/{event_id}", response_model=EventResponse)
    def log_event_detail(
        scan_id: str,
        event_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        scan = log_scan(scan_id)
        if event_id not in scan.event_ids:
            raise HTTPException(status_code=404, detail="Event not found.")
        with db_lock:
            raw = repository.get("event", event_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Event not found.")
        return _event_summary(Event.model_validate(raw))

    @application.get("/api/log/analyses/{scan_id}/timeline", response_model=TimelineResponse)
    def log_timeline(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, Any]:
        scan = log_scan(scan_id)
        with db_lock:
            records = repository.get_many("timeline_entry", scan.timeline_entry_ids)
        timeline = [
            TimelineEntry.model_validate(records[item])
            for item in scan.timeline_entry_ids
            if item in records
        ]
        timeline.sort(key=lambda x: (x.occurred_at, x.entry_id), reverse=True)
        page = timeline[offset : offset + limit]
        values = [x.model_dump(mode="json") for x in page]
        return {"items": values, "total": len(timeline), "limit": limit, "offset": offset}

    @application.get("/api/scans", response_model=ScanPageResponse)
    def list_scans(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        status: Literal["complete", "partial", "failed", "running"] | None = None,
        scanner: Annotated[str | None, Query(max_length=100)] = None,
        sort: Literal["started_at", "status", "scanner"] = "started_at",
        order: Literal["asc", "desc"] = "desc",
    ) -> dict[str, Any]:
        filters = {
            key: value for key, value in {"status": status, "scanner": scanner}.items() if value
        }
        with db_lock:
            page, total = repository.page_records(
                "scan",
                limit=limit,
                offset=offset,
                sort_by=sort,
                descending=order == "desc",
                filters=filters,
            )
        scans = [Scan.model_validate(item) for item in page]
        return {
            "items": [_scan_summary(scan) for scan in scans],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/scans/{scan_id}", response_model=ScanDetailResponse)
    def get_scan(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        if len(scan_id) > 255:
            raise HTTPException(status_code=404, detail="Scan not found.")
        with db_lock:
            raw = repository.get("scan", scan_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        scan = Scan.model_validate(raw)
        return _scan_summary(scan) | {
            "schema_version": scan.schema_version,
            "project_id": scan.project_id,
            "project_removed": scan.project_removed,
            "target_id": scan.target_id,
            "finding_ids": scan.finding_ids,
            "event_ids": scan.event_ids,
            "alert_ids": scan.alert_ids,
            "timeline_entry_ids": scan.timeline_entry_ids,
            "location_ids": scan.location_ids,
            "scan_options": scan.scan_options,
            "coverage": scan.coverage.model_dump(mode="json") if scan.coverage else None,
            "failures": scan.failures,
            "code_assessment": scan.code_assessment.model_dump(mode="json")
            if scan.code_assessment
            else None,
        }

    @application.get("/api/findings", response_model=FindingPageResponse)
    def list_findings(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        severity: Annotated[str | None, Query(max_length=20)] = None,
        category: Annotated[str | None, Query(max_length=80)] = None,
        scanner: Annotated[str | None, Query(max_length=100)] = None,
        sort: Literal["severity", "title", "scanner", "category"] = "severity",
        order: Literal["asc", "desc"] = "desc",
    ) -> dict[str, Any]:
        if severity and severity not in {item.value for item in Severity}:
            raise HTTPException(status_code=422, detail="Unsupported severity filter.")
        filters = {
            key: value
            for key, value in {
                "severity": severity,
                "category": category,
                "scanner": scanner,
            }.items()
            if value
        }
        with db_lock:
            page, total = repository.page_records(
                "finding",
                limit=limit,
                offset=offset,
                sort_by=sort,
                descending=order == "desc",
                filters=filters,
            )
            _all_rows, total_stored = repository.page_records(
                "finding", limit=1, offset=0, sort_by="severity", descending=True
            )
        return {
            "items": [_finding_summary(Finding.model_validate(item)) for item in page],
            "total": total,
            "total_stored": total_stored,
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/findings/{finding_id}", response_model=FindingDetailResponse)
    def get_finding(
        finding_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        if len(finding_id) > 255:
            raise HTTPException(status_code=404, detail="Finding not found.")
        with db_lock:
            raw = repository.get("finding", finding_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Finding not found.")
        return _finding_summary(Finding.model_validate(raw), detail=True)

    def case_view(case_id: str) -> dict[str, Any]:
        workflow = CaseWorkflow(repository)
        stored_case = workflow.get_case(case_id)
        _enforce_case_limits(stored_case)
        context = workflow.context(stored_case)
        case = context.case
        _, timeline, warnings = workflow.timeline(case)
        severities = {item.value: 0 for item in Severity}
        linked = []
        for (record_type, record_id), record in sorted(context.records.items()):
            raw_severity = getattr(record, "severity", None)
            if raw_severity is not None and raw_severity.value in severities:
                severities[raw_severity.value] += 1
            linked.append(
                {
                    "record_type": record_type,
                    "record_id": record_id,
                    "source": str(
                        getattr(record, "source", None)
                        or getattr(record, "scanner", None)
                        or record_type
                    ),
                    "title": str(getattr(record, "title", "")),
                    "severity": raw_severity.value if raw_severity is not None else None,
                    "sample_id": getattr(record, "sample_id", None),
                    "completeness": getattr(record, "status", None)
                    if record_type == "malware_analysis"
                    else None,
                }
            )
        view = {
            "case": case.model_dump(mode="json"),
            "links": [item.model_dump(mode="json") for item in context.links],
            "records": linked,
            "timeline": [item.model_dump(mode="json") for item in timeline],
            "warnings": list(dict.fromkeys([*context.warnings, *warnings])),
            "counts_by_severity": severities,
        }
        return view

    @application.get("/api/cases")
    def list_cases(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        status: CaseStatus | None = None,
        severity: Severity | None = None,
        sort: Literal["created_at", "updated_at", "status", "severity", "title"] = "updated_at",
        order: Literal["asc", "desc"] = "desc",
    ) -> dict[str, Any]:
        filters = {
            key: value.value
            for key, value in {"status": status, "severity": severity}.items()
            if value
        }
        with db_lock:
            page, total = repository.page_records(
                "case",
                limit=limit,
                offset=offset,
                sort_by=sort,
                descending=order == "desc",
                filters=filters,
            )
        case_items = [
            {
                "case_id": item["case_id"],
                "title": item["title"],
                "description": item["description"],
                "status": item["status"],
                "severity": item["severity"],
                "created_at": item["created_at"],
                "updated_at": item["updated_at"],
                "note_count": len(item.get("notes", [])),
                "linked_record_count": len(item.get("links", [])),
            }
            for item in page
        ]
        return {
            "items": case_items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.post("/api/cases", status_code=201)
    def create_case(
        payload: CaseCreateRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                case, warnings = CaseWorkflow(repository).create_from_scan(
                    payload.scan_id,
                    title=payload.title,
                    description=payload.description,
                    severity=payload.severity.value,
                )
                result = case_view(case.case_id)
            result["warnings"] = list(dict.fromkeys([*result["warnings"], *warnings]))
            return result
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.get("/api/cases/{case_id}")
    def get_case(case_id: str, _session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.post("/api/cases/{case_id}/status")
    def update_case_status(
        case_id: str,
        payload: CaseStatusRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                CaseWorkflow(repository).update_status(case_id, payload.status)
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.post("/api/cases/{case_id}/notes", status_code=201)
    def add_case_note(
        case_id: str,
        payload: CaseNoteRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                # The session identity is deliberately not stored as a legacy author label.
                CaseWorkflow(repository).add_note(case_id, payload.body)
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.post("/api/cases/{case_id}/links")
    def link_case_record(
        case_id: str,
        payload: CaseLinkRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                CaseWorkflow(repository).link_record(
                    case_id, payload.record_type, payload.record_id
                )
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.get("/api/cases/{case_id}/report/{output_format}")
    def case_report(
        case_id: str,
        output_format: Literal["json", "markdown", "html"],
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> Response:  # noqa: B008
        try:
            with db_lock:
                case = CaseWorkflow(repository).get_case(case_id)
                _enforce_case_limits(case)
                body = render_case_report(repository, case_id, output_format)
            return _download_response(body, f"case-report.{output_format}", output_format)
        except (CaseWorkflowError, ReportingError) as exc:
            raise _case_http_error(exc) from exc

    @application.get("/api/scans/{scan_id}/report/{output_format}")
    def scan_report(
        scan_id: str,
        output_format: Literal[
            "json", "full-json", "detail", "markdown", "html", "csv", "sarif", "share-summary"
        ],
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> Response:  # noqa: B008
        try:
            with db_lock:
                scan, findings = scan_data(repository, scan_id)
                if len(findings) > MAX_SCAN_REPORT_FINDINGS:
                    raise HTTPException(
                        status_code=413, detail="Scan report exceeds configured finding limits."
                    )
                body = render_report(scan, findings, output_format)
                if len(body.encode("utf-8")) > MAX_SCAN_REPORT_BYTES:
                    raise HTTPException(
                        status_code=413, detail="Complete report exceeds the 20 MB export limit."
                    )
            return _download_response(
                body,
                f"scan-report.{output_format}",
                output_format,
                max_bytes=MAX_SCAN_REPORT_BYTES if output_format == "full-json" else 2_000_000,
            )
        except ReportingError as exc:
            if output_format == "full-json" and "Complete JSON report exceeds" in str(exc):
                raise HTTPException(
                    status_code=413,
                    detail="Complete JSON report exceeds the configured count or byte limit.",
                ) from exc
            raise _case_http_error(exc) from exc

    @application.get("/api/scans/{scan_id}/findings.jsonl")
    def scan_findings_jsonl(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> StreamingResponse:
        if len(scan_id) > 255:
            raise HTTPException(status_code=404, detail="Scan not found.")
        with db_lock:
            stored = repository.get("scan", scan_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        scan = Scan.model_validate(stored)
        finding_ids = list(scan.finding_ids)
        if len(finding_ids) != len(set(finding_ids)):
            raise HTTPException(
                status_code=409,
                detail="Scan contains duplicate finding IDs; export was not started.",
            )
        chain_scan = "chain" in scan.project_types or scan.scanner == "chain_trace"

        def stream() -> Iterator[str]:
            manifest = {
                "type": "manifest",
                "schema": "chinescan.findings/1",
                "scan_id": scan_id,
                "total_findings": len(finding_ids),
                "ordering": "scan.finding_ids order",
                "consistency": "scan ID list captured at request start",
                "processing_failure_count": len(scan.failures),
            }
            yield json.dumps(manifest, ensure_ascii=False, sort_keys=True) + "\n"
            digest = hashlib.sha256()
            returned = 0
            for start in range(0, len(finding_ids), 100):
                ids = finding_ids[start : start + 100]
                with db_lock:
                    records = repository.get_many("finding", ids)
                try:
                    if len(records) != len(ids):
                        raise ValueError("finding unavailable")
                    for finding_id in ids:
                        finding = Finding.model_validate(records[finding_id])
                        row = {
                            "type": "finding",
                            "finding": redact_finding_payload(finding, chain_scan=chain_scan),
                        }
                        line = json.dumps(row, ensure_ascii=False, sort_keys=True)
                        digest.update((line + "\n").encode("utf-8"))
                        returned += 1
                        yield line + "\n"
                except Exception:
                    yield (
                        json.dumps(
                            {"type": "error", "code": "record_unavailable_or_unsafe"},
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    return
            yield (
                json.dumps(
                    {
                        "type": "complete",
                        "returned_findings": returned,
                        "sha256": digest.hexdigest(),
                    },
                    sort_keys=True,
                )
                + "\n"
            )

        return StreamingResponse(
            stream(),
            media_type="application/x-ndjson",
            headers={
                "Content-Disposition": f'attachment; filename="scan-{scan_id}-findings.jsonl"',
                "Cache-Control": "no-store",
            },
        )

    @application.post("/api/scans/{scan_id}/external-reports", status_code=201)
    async def import_scanity_report(
        scan_id: str,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_EXTERNAL_REPORT_BYTES:
            raise HTTPException(status_code=413, detail="Report exceeds the 2 MB import limit.")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_EXTERNAL_REPORT_BYTES:
                raise HTTPException(status_code=413, detail="Report exceeds the 2 MB import limit.")
        try:
            with db_lock:
                scan_payload = repository.get("scan", scan_id)
                if scan_payload is None:
                    raise HTTPException(status_code=404, detail="Scan not found.")
                scan_record = Scan.model_validate(scan_payload)
                if not scan_record.code_assessment and not (
                    {kind.casefold() for kind in scan_record.project_types or []}
                    & {"python", "node"}
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="External reports can only be imported into code assessments.",
                    )
                if scan_record.code_assessment is None:
                    scan_record.code_assessment = CodeAssessmentSummary()
                target_record = repository.get("target", scan_record.target_id)
                target_root = Path(str(target_record["value"])) if target_record else Path.cwd()
                imported = parse_scanity_export(
                    bytes(body), target=target_root, project_id=scan_record.project_id
                )
                existing_ids = set(scan_record.finding_ids)
                existing_fingerprints = {
                    str(item.get("fingerprint"))
                    for item in repository.list_records("finding")
                    if item.get("source") == "scanity" and item.get("finding_id") in existing_ids
                }
                added = [item for item in imported if item.fingerprint not in existing_fingerprints]
                for item in added:
                    repository.save("finding", item.finding_id, item.model_dump(mode="json"))
                scan_record.finding_ids = list(
                    dict.fromkeys([*scan_record.finding_ids, *(item.finding_id for item in added)])
                )
                repository.save("scan", scan_id, scan_record.model_dump(mode="json"))
                try:
                    save_scan_reports(repository, scan_id, active_settings.reports_dir)
                except ReportStoreError:
                    pass
            return {"scan_id": scan_id, "imported": len(added), "source": "scanity"}
        except ExternalReportError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.get("/api/fs/roots")
    def filesystem_roots(
        request: Request,
        capability: Literal["project_directory", "log_location"] = Query(...),
        session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        return fs_browser.roots_view(session.csrf_token, capability)

    @application.get("/api/fs/picker-roots")
    def folder_picker_roots(
        request: Request,
        session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, object]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        return fs_browser.picker_roots_view(session.csrf_token)

    @application.get("/api/fs/picker-list")
    def folder_picker_list(
        request: Request,
        directory_id: Annotated[str, Query(min_length=32, max_length=128)],
        session: Session = Depends(current_session),  # noqa: B008
        cursor: Annotated[str | None, Query(max_length=128)] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> dict[str, object]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        try:
            return fs_browser.list_view(
                session.csrf_token,
                "folder_approval",
                directory_id,
                cursor=cursor,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail={"code": "directory_unavailable", "message": "Folder is unavailable."},
            ) from exc

    @application.get("/api/fs/picker-preview")
    def folder_picker_preview(
        request: Request,
        directory_id: Annotated[str, Query(min_length=32, max_length=128)],
        session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, str]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        try:
            return fs_browser.preview_folder_approval(session.csrf_token, directory_id)
        except ValueError as exc:
            code = str(exc)
            raise HTTPException(
                status_code=422,
                detail={"code": code, "message": folder_approval_error(code)},
            ) from exc

    @application.get("/api/fs/list")
    def filesystem_list(
        request: Request,
        directory_id: Annotated[str, Query(min_length=32, max_length=128)],
        capability: Literal["project_directory", "log_location"] = Query(...),
        session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        cursor: Annotated[str | None, Query(max_length=128)] = None,
    ) -> dict[str, object]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        try:
            return fs_browser.list_view(
                session.csrf_token,
                capability,
                directory_id,
                cursor=cursor,
                limit=limit,
            )
        except ValueError as exc:
            code = str(exc)
            raise HTTPException(
                status_code=400 if code == "invalid_page_size" else 404,
                detail="Directory selection is unavailable.",
            ) from exc

    if serve_frontend and FRONTEND_DIST.is_dir():

        @application.get("/signup", include_in_schema=False)
        def signup_page() -> FileResponse:
            return FileResponse(FRONTEND_DIST / "index.html")

        @application.get("/forgot-password", include_in_schema=False)
        def forgot_password_page() -> FileResponse:
            return FileResponse(FRONTEND_DIST / "index.html")

        @application.get("/reset-password", include_in_schema=False)
        def reset_password_page() -> FileResponse:
            return FileResponse(FRONTEND_DIST / "index.html")

    @application.post("/api/chain/jobs", status_code=202)
    async def start_chain_job(
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            body = await request.json()
            if len(json.dumps(body).encode()) > 2_000_000:
                raise HTTPException(
                    413, detail={"code": "import_too_large", "message": "Import text exceeds 2 MB."}
                )
            chain = str(body["chain"]).lower()
            selected_chain = load_registry().get(chain)
            if selected_chain is None:
                raise HTTPException(
                    422, detail={"code": "unknown_chain", "message": "Unknown chain."}
                )
            try:
                normalize_address(selected_chain, str(body["address"]))
            except ValueError:
                raise HTTPException(
                    422,
                    detail={
                        "code": "invalid_address",
                        "message": "Wallet address is invalid for the selected chain.",
                    },
                ) from None
            try:
                depth = int(body.get("depth", 3))
                if not 1 <= depth <= 6:
                    raise ValueError
            except (TypeError, ValueError):
                raise HTTPException(
                    422,
                    detail={"code": "invalid_depth", "message": "Depth must be between 1 and 6."},
                ) from None
            try:
                minimum = Decimal(str(body.get("min_amount", "0")))
                if not minimum.is_finite() or minimum < 0:
                    raise ValueError
            except (InvalidOperation, TypeError, ValueError):
                raise HTTPException(
                    422,
                    detail={
                        "code": "invalid_min_amount",
                        "message": "Minimum amount must be a non-negative decimal.",
                    },
                ) from None
            if body.get("allow_network") and not active_settings.chain_network_enabled:
                raise HTTPException(
                    403,
                    detail={
                        "code": "chain_network_disabled",
                        "message": "Network chain lookups are disabled by server settings.",
                    },
                )
            if not body.get("import_text") and not body.get("allow_network"):
                raise HTTPException(
                    422,
                    detail={
                        "code": "offline_import_required",
                        "message": "Provide an explorer export or explicitly allow network lookup.",
                    },
                )
            job = chain_jobs.submit(
                {
                    "address": str(body["address"]),
                    "chain": chain,
                    "depth": depth,
                    "min_amount": str(minimum),
                    "allow_network": bool(body.get("allow_network")),
                    "import_text": body.get("import_text"),
                    "import_format": body.get("import_format", "csv"),
                }
            )
            return _safe_chain_job(job)
        except HTTPException:
            raise
        except (KeyError, TypeError, ValueError):
            raise HTTPException(
                422,
                detail={"code": "invalid_chain_request", "message": "Invalid chain job request."},
            ) from None
        except OverflowError:
            raise HTTPException(
                429, detail={"code": "chain_queue_full", "message": "Chain job queue is full."}
            ) from None

    @application.get("/api/chain/jobs")
    def list_chain_jobs(
        limit: int = 50,
        offset: int = 0,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        items, total = chain_jobs.list(max(1, min(100, limit)), max(0, offset))
        return {
            "items": [_safe_chain_job(item) for item in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/chain/jobs/{job_id}")
    def get_chain_job(
        job_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        item = chain_jobs.get(job_id)
        if item is None:
            raise HTTPException(404, detail="Chain job not found.")
        return _safe_chain_job(item)

    @application.get("/api/chain/chains")
    def list_chains(
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> list[dict[str, Any]]:
        return [
            {
                "name": item.name,
                "family": item.family,
                "native_asset": item.native_asset,
                "credential_configured": bool(
                    item.api_key_env and __import__("os").getenv(item.api_key_env)
                ),
            }
            for item in load_registry().values()
        ]

    @application.get("/api/chain/traces/{scan_id}/graph")
    def chain_graph(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        graph = repository.get("chain_graph", scan_id)
        if graph is None:
            raise HTTPException(404, detail="Chain graph not found.")
        return graph

    @application.get("/api/chain/traces/{scan_id}/export/{fmt}")
    def chain_export(
        scan_id: str,
        fmt: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> Response:  # noqa: B008
        graph = repository.get("chain_graph", scan_id)
        if graph is None:
            raise HTTPException(404, detail="Chain graph not found.")
        if fmt not in {"graph-json", "graphml", "transfers-csv", "indicators"}:
            raise HTTPException(404, detail="Unknown export format.")
        media = (
            "application/json"
            if fmt in {"graph-json", "indicators"}
            else "text/csv"
            if fmt == "transfers-csv"
            else "application/graphml+xml"
        )
        return Response(export_graph(graph, fmt), media_type=media)

    if serve_frontend and FRONTEND_DIST.is_dir():
        application.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")

    return application


def _safe_chain_job(raw: dict[str, Any]) -> dict[str, Any]:
    return {key: raw.get(key) for key in ("job_id", "status", "created_at", "scan_id", "error")}


def _safe_project_malware_job(raw: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "job_id",
        "project_id",
        "status",
        "profile",
        "created_at",
        "started_at",
        "finished_at",
        "scan_id",
        "finding_count",
        "files_seen",
        "skipped_counts",
        "coverage_notes",
        "error_code",
        "error",
    )
    return {key: raw.get(key) for key in keys if key in raw}


def _malware_job_view(raw: dict[str, Any], repository: SQLiteRepository) -> dict[str, Any]:
    analysis_id = raw.get("analysis_id")
    analysis = repository.get("malware_analysis", str(analysis_id)) if analysis_id else None
    return {
        "job_id": str(raw.get("job_id", "")),
        "sample_id": str(raw.get("sample_id", "")),
        "status": raw.get("status", "failed"),
        "created_at": str(raw.get("created_at", "")),
        "started_at": raw.get("started_at"),
        "finished_at": raw.get("finished_at"),
        "analysis_id": raw.get("analysis_id"),
        "warning": str(raw.get("warning"))[:500] if raw.get("warning") else None,
        "analysis_status": analysis.get("status") if analysis else None,
    }


def _malware_analysis_view(raw: dict[str, Any]) -> dict[str, Any]:
    raw_result = raw.get("result")
    result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
    raw_hashes = result.get("hashes")
    hashes: dict[str, Any] = raw_hashes if isinstance(raw_hashes, dict) else {}
    raw_indicators = result.get("indicators")
    indicators: list[Any] = raw_indicators if isinstance(raw_indicators, list) else []
    raw_warnings = result.get("warnings")
    warnings: list[Any] = raw_warnings if isinstance(raw_warnings, list) else []
    raw_engines = raw.get("engines")
    engines: dict[str, Any] = raw_engines if isinstance(raw_engines, dict) else {}
    safe_indicators = []
    for item in indicators[:500]:
        if (
            isinstance(item, dict)
            and isinstance(item.get("kind"), str)
            and isinstance(item.get("value"), str)
        ):
            safe_indicators.append({"kind": item["kind"][:40], "value": item["value"][:2048]})
    safe_engines = {}
    for name in ("yara", "clamav"):
        state = engines.get(name, {})
        if isinstance(state, dict):
            safe_engines[name] = {
                key: str(state.get(key, "not_checked"))[:40]
                for key in (
                    "requested",
                    "installation",
                    "configuration",
                    "real_binary_verification",
                )
            }
    return {
        "analysis_id": str(raw.get("analysis_id", "")),
        "sample_id": str(raw.get("sample_id", "")),
        "profile": str(raw.get("profile", "builtin_static"))[:40],
        "status": raw.get("status", "partial"),
        "created_at": str(raw.get("created_at", "")),
        "size_bytes": result.get("size_bytes", 0),
        "hashes": {
            key: str(hashes[key])
            for key in ("md5", "sha1", "sha256")
            if isinstance(hashes.get(key), str)
            and len(hashes[key]) == {"md5": 32, "sha1": 40, "sha256": 64}[key]
            and all(character in "0123456789abcdef" for character in hashes[key].lower())
        },
        "file_type": str(result.get("file_type", "unknown"))[:120],
        "architecture": str(result["architecture"])[:80]
        if isinstance(result.get("architecture"), str)
        else None,
        "printable_string_count": result.get("printable_string_count", 0),
        "indicator_count": result.get("indicator_count", len(safe_indicators)),
        "indicators": safe_indicators,
        "warnings": [str(item)[:500] for item in warnings[:50]],
        "engines": safe_engines,
        "evidence_note": (
            "Indicators are untrusted candidate evidence, not confirmed maliciousness. "
            "URLs and HTML-like values are inert text. Sample bytes, printable strings, "
            "archive names, paths, and raw worker output are withheld."
        ),
    }


def _scan_summary(scan: Scan) -> dict[str, Any]:
    return {
        "scan_id": scan.scan_id,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "status": scan.status,
        "scanner": scan.scanner,
        "project_types": scan.project_types,
        "finding_count": len(scan.finding_ids),
        "verdict": scan.verdict,
        "coverage_gap_count": len(scan.coverage.gaps) if scan.coverage else 0,
    }


def _finding_summary(finding: Finding, *, detail: bool = False) -> dict[str, Any]:
    # Explicit schema allowlist: never send raw evidence or arbitrary persisted JSON to the browser.
    value: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "title": redact(finding.title),
        "severity": finding.severity.value,
        "category": finding.category.value,
        "confidence": finding.confidence.value,
        "scanner": finding.scanner,
        "rule_id": redact(finding.rule_id),
        "contributing_rule_ids": finding.contributing_rule_ids or [finding.rule_id],
    }
    if detail:
        value["description"] = redact(finding.description)
        value["location"] = safe_display_name(finding.location) if finding.location else None
        value["tags"] = finding.tags
        value["evidence"] = finding.evidence.value if finding.evidence else None
        value["line_numbers"] = finding.line_numbers
        value["code_excerpt"] = redact(finding.code_excerpt) if finding.code_excerpt else None
        value["remediation"] = redact(finding.remediation) if finding.remediation else None
        value["cwe_ids"] = finding.cwe_ids
        value["exposure"] = finding.exposure
        value["explanation"] = (
            redact(finding.explanation.model_dump(mode="json")) if finding.explanation else None
        )
    return value


def _alert_summary(alert: Alert) -> dict[str, Any]:
    value = {
        "alert_id": alert.alert_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity.value,
        "confidence": alert.confidence.value,
        "rule_id": alert.rule_id,
        "event_ids": alert.event_ids,
        "indicator_ids": alert.indicator_ids,
        "mitre_attack_techniques": alert.mitre_attack_techniques,
    }
    return value


def _event_summary(event: Event) -> dict[str, Any]:
    # Raw refs may contain full local paths; browser schemas intentionally omit them.
    value = {
        "event_id": event.event_id,
        "occurred_at": event.occurred_at,
        "kind": event.kind,
        "summary": event.summary,
        "source": event.source,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "user": event.user,
        "host": event.host,
        "process": event.process,
        "url": event.url,
        "event_outcome": event.event_outcome,
        "mitre_attack_techniques": event.mitre_attack_techniques,
    }
    return value


def _case_http_error(exc: ValueError) -> HTTPException:
    if isinstance(exc, (CaseNotFoundError, CaseRecordNotFoundError)):
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=422, detail=str(exc))


def _enforce_case_limits(case: Case) -> None:
    if len(case.links) > 2_000 or len(case.notes) > 1_000 or len(case.activities) > 5_000:
        raise HTTPException(status_code=413, detail="Case exceeds configured record limits.")


def _download_response(
    body: str, filename: str, output_format: str, *, max_bytes: int = 2_000_000
) -> Response:
    # Reports are generated in memory from bounded stored records, never via a user path.
    encoded = body.encode("utf-8")
    if len(encoded) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Generated report exceeds the {max_bytes // (1024 * 1024)} MB limit.",
        )
    media_type = {
        "json": "application/json; charset=utf-8",
        "full-json": "application/json; charset=utf-8",
        "detail": "text/markdown; charset=utf-8",
        "markdown": "text/markdown; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "csv": "text/csv; charset=utf-8",
        "sarif": "application/sarif+json; charset=utf-8",
    }[output_format]
    safe_name = filename.replace('"', "")
    disposition = "attachment"
    return Response(
        content=encoded,
        media_type=media_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
        },
    )
