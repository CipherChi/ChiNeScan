"""User-facing CLI commands."""

import json
import os
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from getpass import getpass
from pathlib import Path
from typing import cast
from uuid import uuid4

import typer
from sqlalchemy.exc import SQLAlchemyError

from chinescan import __version__
from chinescan.core.cases import CaseWorkflow, CaseWorkflowError
from chinescan.core.config.io import init_config, load_settings, validate_config
from chinescan.core.config.settings import Settings
from chinescan.core.errors import ConfigurationError, StorageError
from chinescan.core.fs_policy import (
    FilesystemBrowserService,
    RootValidation,
    decide_path,
    policy_paths,
)
from chinescan.core.github_import import GitHubImportService
from chinescan.core.log_locations import LogLocationService
from chinescan.core.logging.redaction import redact
from chinescan.core.malware_ack import MalwareAcknowledgementError, MalwareAcknowledgements
from chinescan.core.malware_project_scan import ProjectMalwareScanner
from chinescan.core.models.common import Severity
from chinescan.core.models.investigation import CaseStatus
from chinescan.core.orchestration.code_scan import (
    BuiltinRuleScanner,
    CodeScanService,
    FindingScanner,
    ScanBounds,
    ScannerError,
)
from chinescan.core.projects import ProjectError, ProjectFileRegistry, ProjectService
from chinescan.core.report_store import ReportStoreError, save_scan_reports
from chinescan.core.reporting import (
    ReportingError,
    iter_scan_findings_jsonl,
    render_case_report,
    render_report,
    scan_data,
)
from chinescan.core.storage.recovery import (
    RecoveryError,
    backup_database,
    plan_retention,
    restore_backup,
    verify_backup,
)
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.core.trends import scan_history_trends
from chinescan.core.verdict import VERDICT_CAVEAT
from chinescan.domain_assessment.authorization import AuthorizationError, authorize_target
from chinescan.domain_assessment.probe import NetworkDomainProbe, ProbeSettings
from chinescan.domain_assessment.service import DomainAssessmentService
from chinescan.log_analysis.ingest import LogIngestionError
from chinescan.log_analysis.service import LogAnalysisService
from chinescan.malware_analysis.analyzer import AnalysisError, analyze_file
from chinescan.malware_analysis.engines import EngineResult, run_clamav, run_yara
from chinescan.scanners.external import (
    GitleaksScanner,
    NpmAuditScanner,
    PipAuditScanner,
    SemgrepScanner,
    TrivyScanner,
)
from chinescan.scanners.indicators import IndicatorScanner
from chinescan.web.app import create_app
from chinescan.web.auth import (
    CredentialError,
    confirm_totp_enrollment,
    create_operator,
    disable_operator_totp,
    issue_reset_token,
    migrate_legacy_operator,
    migrate_operator_email_for_reset,
    normalize_email,
    operator_identity_summary,
    operator_status,
    set_operator_password,
    start_totp_enrollment,
    timestamped_credential_backup,
)


def version() -> None:
    typer.echo(__version__)


def _operator_credential_path(path: Path | None) -> Path:
    selected = (path or Path.home() / ".config" / "chinescan" / "operator.json").expanduser()
    resolved = selected.resolve(strict=False)
    if any((parent / ".git").exists() for parent in resolved.parents):
        raise CredentialError("Operator credentials must be stored outside Git repositories.")
    return resolved


web_app = typer.Typer(help="Start or bootstrap the authenticated loopback dashboard.")


@web_app.command("bootstrap")
def web_bootstrap(
    email: str = typer.Option(..., prompt=True),
    credential_file: Path | None = typer.Option(None, "--credential-file"),  # noqa: B008
    json_output: bool = typer.Option(False, "--json"),  # noqa: B008
) -> None:
    """Create the one local operator account; passwords are entered without echo."""
    try:
        path = _operator_credential_path(credential_file)
    except CredentialError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    password = getpass("Operator password (12+ characters): ")
    confirmation = getpass("Confirm operator password: ")
    if password != confirmation:
        typer.echo("Passwords do not match.", err=True)
        raise typer.Exit(code=2)
    try:
        create_operator(path, email, password)
    except CredentialError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        json.dumps({"status": "active"}) if json_output else "Local operator account created."
    )


@web_app.command("reset-password")
def web_reset_password(
    email: str = typer.Option(..., "--email", prompt=True),
    credential_file: Path | None = typer.Option(None, "--credential-file"),  # noqa: B008
    issue_link: bool = typer.Option(False, "--issue-link"),  # noqa: B008
    json_output: bool = typer.Option(False, "--json"),  # noqa: B008
) -> None:
    """Set a password locally or issue a one-time reset URL for the local UI."""
    try:
        path = _operator_credential_path(credential_file)
        migrate_legacy_operator(path)
    except CredentialError:
        typer.echo("Password reset could not be completed.", err=True)
        raise typer.Exit(code=2) from None
    if issue_link:
        try:
            token = issue_reset_token(path, email)
        except CredentialError:
            typer.echo("Password reset could not be completed.", err=True)
            raise typer.Exit(code=2) from None
        reset_url = f"http://127.0.0.1:8765/reset-password?token={token}"
        typer.echo(json.dumps({"reset_url": reset_url}) if json_output else reset_url)
        return
    password = getpass("New password (12-128 characters): ")
    confirmation = getpass("Confirm new password: ")
    if password != confirmation:
        typer.echo("Passwords do not match.", err=True)
        raise typer.Exit(code=2)
    try:
        set_operator_password(path, email, password)
    except CredentialError:
        typer.echo("Password reset could not be completed.", err=True)
        raise typer.Exit(code=2) from None
    typer.echo(json.dumps({"status": "password_reset"}) if json_output else "Password updated.")


@web_app.command("operator-status")
def web_operator_status(
    credential_file: Path | None = typer.Option(None, "--credential-file"),  # noqa: B008
    json_output: bool = typer.Option(False, "--json"),  # noqa: B008
) -> None:
    """Report only the local operator credential state."""
    state = operator_status(_operator_credential_path(credential_file))
    typer.echo(json.dumps({"status": state}) if json_output else state)


@web_app.command("totp-enroll")
def web_totp_enroll(
    credential_file: Path | None = typer.Option(None, "--credential-file"),  # noqa: B008
) -> None:
    """Enroll authenticator-based MFA from this local terminal."""
    try:
        path = _operator_credential_path(credential_file)
        secret = start_totp_enrollment(path)
    except CredentialError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from None
    typer.echo("Add this key to your authenticator now; it is not shown again:")
    typer.echo(secret)
    code = getpass("Enter the current six-digit authenticator code: ")
    recovery_codes = confirm_totp_enrollment(path, code)
    if recovery_codes is None:
        typer.echo("Authenticator enrollment failed or expired.", err=True)
        raise typer.Exit(code=2)
    typer.echo("Recovery codes (each works once; store them securely):")
    for recovery_code in recovery_codes:
        typer.echo(recovery_code)


@web_app.command("totp-disable")
def web_totp_disable(
    credential_file: Path | None = typer.Option(None, "--credential-file"),  # noqa: B008
) -> None:
    """Disable authenticator-based MFA from this local terminal."""
    try:
        path = _operator_credential_path(credential_file)
        code = getpass("Enter an unused authenticator or recovery code: ")
        if not disable_operator_totp(path, code):
            raise CredentialError("Authenticator verification could not be completed.")
    except CredentialError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from None
    typer.echo("Authenticator verification disabled.")


@web_app.command("recover-operator")
def web_recover_operator(
    credential_file: Path | None = typer.Option(None, "--credential-file"),  # noqa: B008
) -> None:
    """Back up, then migrate/reset or retire the local operator identity."""
    try:
        path = _operator_credential_path(credential_file)
        timestamped_credential_backup(path)
    except CredentialError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    typer.echo("A timestamped credential backup was created.")
    action = typer.prompt("Choose action (reset or retire)", default="reset").strip().lower()
    if action not in {"reset", "retire"}:
        typer.echo("Unknown recovery action. No changes made.", err=True)
        raise typer.Exit(code=2)
    confirmation = typer.prompt("Type RECOVER to confirm")
    if confirmation != "RECOVER":
        typer.echo("No changes made.")
        return
    if action == "retire":
        path.unlink()
        typer.echo("Operator credential retired. Application data was not changed.")
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        current = data.get("email")
        if not isinstance(current, str):
            current = data.get("username", data.get("legacy_username", ""))
        try:
            current_email = normalize_email(current)
        except CredentialError:
            current_email = ""
        prompted = typer.prompt("Operator email", default=current_email)
        email = normalize_email(prompted)
        token = migrate_operator_email_for_reset(path, email)
    except (CredentialError, OSError, ValueError, TypeError):
        typer.echo(
            "Recovery could not be completed. The timestamped backup is preserved.", err=True
        )
        raise typer.Exit(code=2) from None
    typer.echo("Email identity updated. Set a new password on /reset-password within 15 minutes.")
    typer.echo(f"http://127.0.0.1:8765/reset-password?token={token}")


def _operator_archive_path(active: Path, kind: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = active.with_name(f"{active.name}.{kind}-{stamp}")
    counter = 1
    while candidate.exists():
        candidate = active.with_name(f"{active.name}.{kind}-{stamp}-{counter}")
        counter += 1
    return candidate


def _backup_operator_file(active: Path) -> Path:
    backup = _operator_archive_path(active, "bak")
    temporary: Path | None = None
    try:
        record = json.loads(active.read_text(encoding="utf-8"))
        email = record.get("email", "")
        try:
            normalized = normalize_email(str(email))
            local, _, domain = normalized.partition("@")
            masked = f"{local[:1]}***@{domain}"
        except CredentialError:
            masked = "unavailable"
        record["_backup_metadata"] = {
            "id": uuid4().hex,
            "timestamp": datetime.now(UTC).isoformat(),
            "schema_version": record.get("schema_version", "legacy"),
            "email_masked": masked,
        }
        descriptor, temporary_name = tempfile.mkstemp(prefix=".operator-backup-", dir=active.parent)
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(record, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(temporary, backup)
    except (OSError, ValueError, TypeError):
        with suppress(OSError):
            backup.unlink(missing_ok=True)
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
        raise
    return backup


def _operator_archives(active: Path) -> list[Path]:
    parent = active.parent
    patterns = (
        f"{active.name}.retired-*",
        f"{active.name}.bak-*",
        f"{active.name}.*.bak",
    )
    candidates: set[Path] = set()
    for pattern in patterns:
        for candidate in parent.glob(pattern):
            if candidate.is_file() and not candidate.is_symlink():
                candidates.add(candidate)
    return sorted(candidates, key=lambda item: item.name.casefold())


@web_app.command("retire-operator")
def web_retire_operator(
    credential_file: Path | None = typer.Option(None, "--credential-file"),  # noqa: B008
    json_output: bool = typer.Option(False, "--json"),  # noqa: B008
) -> None:
    """Back up and retire only the active operator credential file."""
    try:
        active = _operator_credential_path(credential_file)
    except CredentialError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    if not active.is_file():
        typer.echo("There is no active operator account to retire.")
        return
    try:
        backup = _backup_operator_file(active)
        operator_username, has_email = operator_identity_summary(active)
    except (OSError, CredentialError):
        # If identity inspection fails, do not change the active credential.
        if "backup" in locals():
            try:
                backup.unlink()
            except OSError:
                pass
        typer.echo(
            "Could not safely prepare operator retirement. The active credential is unchanged.",
            err=True,
        )
        raise typer.Exit(code=2) from None

    retired = _operator_archive_path(active, "retired")
    if json_output:
        typer.echo(json.dumps({"status": "awaiting_confirmation"}))
    else:
        typer.echo(f"Operator username: {operator_username}")
        typer.echo(f"Email field present: {'yes' if has_email else 'no'}")
        typer.echo("Active operator will be disabled. A timestamped backup will be retained.")
        typer.echo("WARNING: this will disable the existing operator login.")
    try:
        confirmation = typer.prompt("Type RETIRE OPERATOR to confirm")
    except (typer.Abort, KeyboardInterrupt, EOFError):
        confirmation = ""
    if confirmation != "RETIRE OPERATOR":
        try:
            backup.unlink()
        except OSError:
            typer.echo("Retirement canceled; the original is unchanged. The backup was retained.")
            return
        typer.echo("Retirement canceled; no changes were made.")
        return
    try:
        os.replace(active, retired)
    except OSError:
        typer.echo("Could not retire the operator. The original credential is unchanged.", err=True)
        typer.echo("A timestamped backup was retained.")
        raise typer.Exit(code=2) from None
    if json_output:
        typer.echo(json.dumps({"status": "retired"}))
    else:
        typer.echo("Operator retired. A timestamped backup was retained.")


@web_app.command("restore-operator")
def web_restore_operator(
    credential_file: Path | None = typer.Option(None, "--credential-file"),  # noqa: B008
    json_output: bool = typer.Option(False, "--json"),  # noqa: B008
) -> None:
    """Restore a selected retired or backed-up operator credential file."""
    try:
        active = _operator_credential_path(credential_file)
    except CredentialError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    candidates = _operator_archives(active)
    if not candidates:
        typer.echo("No retired or backup operator credential files are available.")
        return
    typer.echo("Available retired/backup credential files:")
    for index, candidate in enumerate(candidates, 1):
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
            metadata = data.get("_backup_metadata", {})
            backup_id = metadata.get("id", "unknown")
            timestamp = metadata.get("timestamp", "unknown")
            masked = metadata.get("email_masked", "unknown")
            schema = metadata.get("schema_version", "legacy")
        except (OSError, ValueError, TypeError, CredentialError):
            backup_id, timestamp, masked, schema = (
                "unavailable",
                "unknown",
                "unavailable",
                "invalid",
            )
        typer.echo(f"{index}. id={backup_id} timestamp={timestamp} schema={schema} email={masked}")
    choice = typer.prompt("Select a file number")
    try:
        selected_index = int(choice) - 1
        selected = candidates[selected_index]
    except (ValueError, IndexError):
        typer.echo("Invalid selection. No changes were made.", err=True)
        raise typer.Exit(code=2) from None
    if selected.parent != active.parent or selected.is_symlink() or not selected.is_file():
        typer.echo("Selected credential file is unavailable. No changes were made.", err=True)
        raise typer.Exit(code=2)
    if not json_output:
        typer.echo("Selected credential backup will replace the active operator record.")
    try:
        confirmation = typer.prompt("Type RESTORE OPERATOR to confirm")
    except (typer.Abort, KeyboardInterrupt, EOFError):
        confirmation = ""
    if confirmation != "RESTORE OPERATOR":
        typer.echo("Restore canceled; no changes were made.")
        return

    descriptor, temporary_name = tempfile.mkstemp(prefix=".operator-restore-", dir=active.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    current_backup: Path | None = None
    try:
        restored = json.loads(selected.read_text(encoding="utf-8"))
        restored.pop("_backup_metadata", None)
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(restored, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        if active.exists() or active.is_symlink():
            if not active.is_file() or active.is_symlink():
                raise OSError("Active credential destination is not a regular file.")
            current_backup = _backup_operator_file(active)
        else:
            current_backup = None
        os.replace(temporary, active)
    except OSError:
        try:
            temporary.unlink()
        except OSError:
            pass
        typer.echo(
            "Could not safely restore the operator credential. No replacement was made.", err=True
        )
        if current_backup is not None:
            typer.echo("A backup of the current credential was retained.")
        raise typer.Exit(code=2) from None
    if json_output:
        typer.echo(
            json.dumps({"status": "restored", "current_backup_created": current_backup is not None})
        )
    else:
        typer.echo("Operator credential restored. Any replaced credential was backed up.")


@web_app.command("serve")
def web_serve(
    port: int = typer.Option(8765, min=1024, max=65535),
    credential_file: Path | None = typer.Option(None, "--credential-file"),  # noqa: B008
    projects_file: Path | None = typer.Option(None, "--projects-file"),  # noqa: B008
    log_sources_file: Path | None = typer.Option(None, "--log-sources-file"),  # noqa: B008
    malware_samples_file: Path | None = typer.Option(None, "--malware-samples-file"),  # noqa: B008
) -> None:
    """Explicitly start one local dashboard worker on 127.0.0.1."""
    from uvicorn import run

    settings = _settings()
    try:
        credentials = _operator_credential_path(credential_file)
    except CredentialError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    from chinescan.web.app import FRONTEND_DIST

    project_config = projects_file or Path.home() / ".config" / "chinescan" / "projects.toml"
    log_config = log_sources_file or Path.home() / ".config" / "chinescan" / "log-sources.toml"
    malware_config = (
        malware_samples_file or Path.home() / ".config" / "chinescan" / "malware-samples.toml"
    )
    application = create_app(
        settings.database_path,
        credentials,
        projects_path=project_config,
        log_sources_path=log_config,
        malware_registry_path=malware_config,
        settings=settings,
    )
    if (FRONTEND_DIST / "index.html").is_file():
        typer.echo(f"ChiNeScan dashboard available at http://127.0.0.1:{port}")
    else:
        typer.echo(f"ChiNeScan API listening at http://127.0.0.1:{port}")
        typer.echo("Run `npm run dev` in frontend for the development dashboard.")
    run(
        application,
        host="127.0.0.1",
        port=port,
        workers=1,
        access_log=False,
        proxy_headers=False,
    )


_cli_config_path: Path | None = None
_cli_database_path: Path | None = None
_cli_reports_dir: Path | None = None


def configure_settings(
    config_path: Path | None, database_path: Path | None, reports_dir: Path | None = None
) -> None:
    global _cli_config_path, _cli_database_path, _cli_reports_dir
    _cli_config_path = config_path
    _cli_database_path = database_path
    _cli_reports_dir = reports_dir


def doctor(
    json_output: bool = typer.Option(
        False, "--json", help="Emit the full diagnostics report as JSON."
    ),
) -> None:
    """Check local ChiNeScan readiness without changing local state."""
    from chinescan.core.diagnostics import build_report

    report = build_report(
        config_path=_cli_config_path,
        database_path=_cli_database_path,
        reports_dir=_cli_reports_dir,
    )
    _emit_diagnostics(report, json_output, short=False)


def status(
    json_output: bool = typer.Option(False, "--json", help="Emit the diagnostics summary as JSON."),
) -> None:
    """Show a short summary of local ChiNeScan readiness."""
    from chinescan.core.diagnostics import build_report

    report = build_report(
        config_path=_cli_config_path,
        database_path=_cli_database_path,
        reports_dir=_cli_reports_dir,
    )
    _emit_diagnostics(report, json_output, short=True)


def _emit_diagnostics(report: dict[str, object], json_output: bool, *, short: bool) -> None:
    import json

    checks = report["checks"]
    if not isinstance(checks, list):
        raise typer.Exit(code=2)
    selected = checks[:5] if short else checks
    if json_output:
        typer.echo(
            json.dumps(
                {"status": report["status"], "checks": selected} if short else report, indent=2
            )
        )
    else:
        for check in selected:
            if isinstance(check, dict):
                typer.echo(f"[{check['state']}] {check['label']}: {check['detail']}")
                if check.get("action_hint"):
                    typer.echo(f"  Action: {check['action_hint']}")
        typer.echo(f"Summary: {report['status']} ({len(checks)} checks)")
    states = {str(item.get("state")) for item in checks if isinstance(item, dict)}
    raise typer.Exit(code=2 if "FAIL" in states else 1 if "WARN" in states else 0)


def _settings() -> Settings:
    options: dict[str, object] = {}
    if _cli_database_path is not None:
        options["database_path"] = _cli_database_path
    if _cli_reports_dir is not None:
        options["reports_dir"] = _cli_reports_dir
    try:
        return load_settings(_cli_config_path, cli_overrides=options)
    except ConfigurationError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=exc.exit_code) from exc


def _github_service(
    settings: Settings,
) -> tuple[SQLiteRepository, GitHubImportService]:
    from chinescan.core.fs_policy import FilesystemBrowserService
    from chinescan.core.projects import ProjectFileRegistry

    repository = SQLiteRepository(settings.database_path)
    hard, soft = policy_paths(settings)
    managed_directory = settings.database_path.expanduser().resolve(strict=False).parent / "gh"
    projects = ProjectService(
        repository,
        FilesystemBrowserService(settings.allowed_roots, hard, soft, settings.allow_soft_denied),
        ProjectFileRegistry(None, []),
        allowed_roots=settings.allowed_roots,
        hard_denied=hard,
        soft_denied=soft,
        allow_soft_denied=settings.allow_soft_denied,
        managed_import_directory=managed_directory,
    )
    service = GitHubImportService(
        repository,
        settings,
        managed_directory,
        project_service=projects,
    )
    return repository, service


def _github_emit(value: dict[str, object], json_output: bool) -> None:
    if json_output:
        typer.echo(json.dumps(value))
    else:
        for key, item in value.items():
            if item is not None:
                typer.echo(f"{key}: {item}")


def _github_error(exc: Exception, json_output: bool) -> None:
    from chinescan.core.github_import import GitHubImportError

    code = exc.code if isinstance(exc, GitHubImportError) else "import_unavailable"
    message = (
        str(exc)
        if isinstance(exc, GitHubImportError)
        else "The GitHub import could not be completed."
    )
    typer.echo(
        json.dumps({"code": code, "message": message}) if json_output else f"{code}: {message}",
        err=True,
    )
    raise typer.Exit(code=2) from exc


def github_preview(
    url: str = typer.Argument(...),
    ref: str | None = typer.Option(None, "--ref"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Preview a public repository import without network access."""
    from chinescan.core.github_import import GitHubImportError

    settings = _settings()
    if not settings.github_import_enabled:
        _github_error(
            GitHubImportError("feature_disabled", "Public GitHub import is disabled."),
            json_output,
        )
    repository, service = _github_service(settings)
    try:
        preview = service.preview("cli", url, ref)
        _github_emit(preview, json_output)
    except Exception as exc:
        _github_error(exc, json_output)
    finally:
        repository.close()


def github_import(
    url: str = typer.Argument(...),
    name: str = typer.Option(..., "--name"),
    ref: str | None = typer.Option(None, "--ref"),
    yes: bool = typer.Option(False, "--yes"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Import a public repository after explicit confirmation."""
    settings = _settings()
    from chinescan.core.github_import import GitHubImportError, session_binding

    if not settings.github_import_enabled:
        _github_error(
            GitHubImportError("feature_disabled", "Public GitHub import is disabled."),
            json_output,
        )
    repository, service = _github_service(settings)
    try:
        preview = service.preview(session_binding("local-cli"), url, ref)
        _github_emit(preview, json_output)
        if not yes:
            typer.echo("Import not started. Re-run with --yes to confirm.", err=True)
            raise typer.Exit(code=2)
        service.start_worker()
        job = service.start(session_binding("local-cli"), str(preview["preview_id"]), name)
        import time

        while True:
            current = service.get(session_binding("local-cli"), str(job["job_id"]))
            if current["status"] in {"succeeded", "failed", "cancelled", "incomplete"}:
                _github_emit(current, json_output)
                if current["status"] != "succeeded":
                    raise typer.Exit(code=2)
                return
            time.sleep(0.1)
    except typer.Exit:
        raise
    except Exception as exc:
        _github_error(exc, json_output)
    finally:
        service.stop_worker()
        repository.close()


def github_status(
    job_id: str = typer.Argument(...),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Show a GitHub import job status."""
    settings = _settings()
    from chinescan.core.github_import import GitHubImportError, session_binding

    if not settings.github_import_enabled:
        _github_error(
            GitHubImportError("feature_disabled", "Public GitHub import is disabled."),
            json_output,
        )
    repository, service = _github_service(settings)
    try:
        _github_emit(service.get(session_binding("local-cli"), job_id), json_output)
    except Exception as exc:
        _github_error(exc, json_output)
    finally:
        repository.close()


def github_cancel(
    job_id: str = typer.Argument(...),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Cancel a GitHub import job."""
    settings = _settings()
    from chinescan.core.github_import import GitHubImportError, session_binding

    if not settings.github_import_enabled:
        _github_error(
            GitHubImportError("feature_disabled", "Public GitHub import is disabled."),
            json_output,
        )
    repository, service = _github_service(settings)
    try:
        _github_emit(service.cancel(session_binding("local-cli"), job_id), json_output)
    except Exception as exc:
        _github_error(exc, json_output)
    finally:
        repository.close()


config_app = typer.Typer(help="Initialize and validate local configuration.")


@config_app.command("init")
def config_init(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", help="Configuration file path."
    ),
) -> None:
    try:
        created = init_config(path)
    except ConfigurationError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=exc.exit_code) from exc
    typer.echo(f"Created configuration: {created}")


@config_app.command("validate")
def config_validate(
    path: Path = typer.Option(  # noqa: B008
        ..., "--path", help="Configuration file path."
    ),
) -> None:
    try:
        validate_config(path)
    except ConfigurationError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=exc.exit_code) from exc
    typer.echo("Configuration is valid.")


def code_scan(
    target: Path = typer.Argument(..., help="Local project directory to scan."),  # noqa: B008
    scanner_names: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--scanner",
        help="Scanner to run; repeat for multiple. Defaults to the built-in local rules.",
    ),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
    semgrep_rules: Path | None = typer.Option(  # noqa: B008
        None, "--semgrep-rules", help="Local Semgrep YAML rules file (required for Semgrep)."
    ),  # noqa: B008
    timeout_seconds: float = typer.Option(120.0, min=0.1, max=3600.0, help="Per-engine timeout."),  # noqa: B008
    fail_on: str = typer.Option(
        "never",
        "--fail-on",
        help=("Exit 1 at this severity: critical, high, medium, low, info, or never."),
    ),  # noqa: B008
    allow_network_audits: bool = typer.Option(
        False,
        "--allow-network-audits",
        help="Allow pip-audit/npm audit to send dependency metadata to advisory services.",
    ),  # noqa: B008
    no_save_report: bool = typer.Option(
        False, "--no-save-report", help="Disable report auto-save."
    ),
    fail_on_gaps: bool = typer.Option(
        False, "--fail-on-gaps", help="Exit 1 when coverage gaps are recorded."
    ),
    indicator_files: list[Path] | None = typer.Option(  # noqa: B008
        None, "--indicator-file", help="Local indicator file; repeat as needed."
    ),  # noqa: B008
) -> None:
    """Assess a local code project with the selected local scanners."""
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be 'human' or 'json'")
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if fail_on != "never" and fail_on not in severity_order:
        raise typer.BadParameter("--fail-on must be critical, high, medium, low, info, or never")
    selected = scanner_names or ["builtin"]
    known = {"builtin", "semgrep", "gitleaks", "trivy", "pip-audit", "npm-audit", "indicators"}
    unknown = sorted(set(selected) - known)
    if unknown:
        raise typer.BadParameter(f"unknown scanner(s): {', '.join(unknown)}")
    if len(set(selected)) != len(selected):
        raise typer.BadParameter("scanner names must be unique")
    if "semgrep" in selected and (semgrep_rules is None or not semgrep_rules.is_file()):
        raise typer.BadParameter("--scanner semgrep requires a readable local --semgrep-rules file")
    if "indicators" in selected and not indicator_files:
        raise typer.BadParameter("--scanner indicators requires at least one --indicator-file")
    if {"pip-audit", "npm-audit"}.intersection(selected) and not allow_network_audits:
        typer.echo(
            "Error: pip-audit and npm-audit require explicit --allow-network-audits consent.",
            err=True,
        )
        raise typer.Exit(code=2)

    settings = _settings()
    scanners: list[FindingScanner] = []
    for name in selected:
        if name == "builtin":
            scanners.append(
                BuiltinRuleScanner(ScanBounds(excluded_paths=tuple(settings.code_excluded_paths)))
            )
        elif name == "semgrep":
            scanners.append(
                SemgrepScanner(config_path=semgrep_rules, timeout_seconds=timeout_seconds)
            )
        elif name == "gitleaks":
            scanners.append(GitleaksScanner(timeout_seconds))
        elif name == "trivy":
            scanners.append(TrivyScanner(timeout_seconds))
        elif name == "pip-audit":
            scanners.append(PipAuditScanner(timeout_seconds))
        elif name == "indicators":
            scanners.append(IndicatorScanner(indicator_files or []))
        else:
            scanners.append(NpmAuditScanner(timeout_seconds))
    repository = SQLiteRepository(settings.database_path)
    try:
        result = CodeScanService(scanners, repository).scan(target)
    except ScannerError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=1) from exc
    finally:
        repository.close()

    saved_reports: list[Path] = []
    if not no_save_report:
        report_repository = SQLiteRepository(settings.database_path)
        try:
            saved_reports = save_scan_reports(
                report_repository, result.scan_id, settings.reports_dir
            )
        except ReportStoreError as exc:
            typer.echo(f"Warning: {redact(str(exc))}", err=True)
        finally:
            report_repository.close()

    summary = result.summary()
    if output_format == "json":
        typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        for path in saved_reports:
            typer.echo(f"Saved report: {path}", err=True)
    else:
        typer.echo(f"Scan {result.scan_id}: {len(result.findings)} candidate finding(s)")
        typer.echo(f"Target: {result.target}")
        typer.echo("Project types: " + (", ".join(result.project_types) or "unknown"))
        if result.verdict:
            typer.echo(f"Verdict: {result.verdict.value.replace('_', ' ').capitalize()}")
            typer.echo(VERDICT_CAVEAT[result.verdict])
        gaps = len(result.coverage.gaps) if result.coverage else 0
        files = result.coverage.examined.get("files_scanned", 0) if result.coverage else 0
        typer.echo(f"Coverage: {files} files examined; {gaps} coverage gap(s).")
        risk_summary = result.code_assessment.vibe_coding_risk if result.code_assessment else None
        if risk_summary:
            typer.echo(
                f"Code pattern risk: {risk_summary.score}/100 "
                f"({risk_summary.confidence.value}; "
                f"{risk_summary.algorithm_version or 'legacy score'})."
            )
        typer.echo(
            "Next: review leads and investigate coverage gaps in the authorized project scope."
        )
        for path in saved_reports:
            typer.echo(f"Saved report: {path}")
        for severity in ("critical", "high", "medium", "low", "info"):
            count = sum(finding.severity.value == severity for finding in result.findings)
            if count:
                typer.echo(f"{severity.upper()}: {count}")
    if result.failures:
        typer.echo("Scanner failures: " + ", ".join(sorted(result.failures)), err=True)
        raise typer.Exit(code=1)
    if fail_on_gaps and result.coverage and result.coverage.gaps:
        typer.echo("Failing because coverage gaps were recorded (--fail-on-gaps).", err=True)
        raise typer.Exit(code=1)
    if fail_on != "never":
        threshold = severity_order[fail_on]
        failing_findings = [
            finding
            for finding in result.findings
            if severity_order[finding.severity.value] >= threshold
        ]
        if failing_findings:
            typer.echo(
                f"Failing threshold {fail_on}: {len(failing_findings)} candidate finding(s).",
                err=True,
            )
            raise typer.Exit(code=1)


def not_implemented(phase: int, command: str) -> None:
    typer.echo(f"{command} is planned for Phase {phase} and is not implemented.", err=True)
    raise typer.Exit(code=2)


report_formats = (
    "json",
    "full-json",
    "jsonl",
    "detail",
    "markdown",
    "html",
    "csv",
    "sarif",
    "share-summary",
)


def report(
    scan_id: str = typer.Argument(..., help="Persisted scan ID."),  # noqa: B008
    output_format: str = typer.Option(  # noqa: B008
        "json",
        "--format",
        help="json (preview), full-json (complete within limits), jsonl (bounded complete stream), detail (human-readable findings and score ledger), markdown, html, csv, sarif, or share-summary.",  # noqa: E501
    ),  # noqa: B008
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", help="Write to this path instead of stdout."
    ),  # noqa: B008
) -> None:
    if output_format not in report_formats:
        raise typer.BadParameter(
            "must be json, full-json, jsonl, detail, markdown, html, csv, sarif, or share-summary"
        )
    repository = SQLiteRepository(_settings().database_path)
    try:
        if output_format == "jsonl":
            if output is None:
                for line in iter_scan_findings_jsonl(repository, scan_id):
                    typer.echo(line, nl=False)
            else:
                output.parent.mkdir(parents=True, exist_ok=True)
                with output.open("w", encoding="utf-8", newline="") as stream:
                    for line in iter_scan_findings_jsonl(repository, scan_id):
                        stream.write(line)
                typer.echo(f"Wrote {output_format} report: {output}")
            return
        scan, findings = scan_data(repository, scan_id)
        content = render_report(scan, findings, output_format)
    except ReportingError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    finally:
        repository.close()
    if output is None:
        typer.echo(content, nl=False)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8", newline="")
        typer.echo(f"Wrote {output_format} report: {output}")


def compare_scans(
    baseline_scan_id: str = typer.Argument(..., help="Earlier scan ID."),  # noqa: B008
    current_scan_id: str = typer.Argument(..., help="Later scan ID."),  # noqa: B008
) -> None:
    repository = SQLiteRepository(_settings().database_path)
    try:
        _, baseline = scan_data(repository, baseline_scan_id)
        _, current = scan_data(repository, current_scan_id)
    except ReportingError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    finally:
        repository.close()
    before = {item.fingerprint: item for item in baseline}
    after = {item.fingerprint: item for item in current}
    result = {
        "baseline_scan_id": baseline_scan_id,
        "current_scan_id": current_scan_id,
        "added": sorted(after.keys() - before.keys()),
        "resolved": sorted(before.keys() - after.keys()),
        "unchanged": sorted(before.keys() & after.keys()),
    }
    typer.echo(json.dumps(result, sort_keys=True, indent=2))


def scan_trends(
    days: int = typer.Option(30, min=1, max=366, help="History window in days."),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
) -> None:
    """Summarize local scan, finding, and alert counts by day."""
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be 'human' or 'json'")
    repository = SQLiteRepository(_settings().database_path)
    try:
        summary = scan_history_trends(
            repository.list_records("scan"),
            repository.list_records("finding"),
            repository.list_records("alert"),
            days=days,
        )
    finally:
        repository.close()
    if output_format == "json":
        typer.echo(json.dumps(summary, sort_keys=True))
        return
    typer.echo(
        f"Scan trends ({summary['start_date']} through {summary['end_date']}): "
        f"{summary['total_scans']} scan(s)"
    )
    typer.echo("Date       Scans  Findings  Alerts")
    for item in summary["daily"]:
        typer.echo(
            f"{item['date']}  {item['scans']:>5}  {item['findings']:>8}  {item['alerts']:>6}"
        )


def logs_ingest(
    target: Path = typer.Argument(..., help="Local log file, directory, or supported archive."),  # noqa: B008
    rules: Path | None = typer.Option(  # noqa: B008
        None, "--rules", help="Local directory or file of Sigma YAML rules."
    ),  # noqa: B008
    ioc_file: Path | None = typer.Option(  # noqa: B008
        None, "--ioc-file", help="Local JSON, CSV, or text IOC list."
    ),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
) -> None:
    """Analyze local exported logs without executing or uploading their contents."""
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be 'human' or 'json'")
    if rules is not None and not rules.exists():
        raise typer.BadParameter("--rules path does not exist")
    if ioc_file is not None and not ioc_file.is_file():
        raise typer.BadParameter("--ioc-file must be a local file")
    repository = SQLiteRepository(_settings().database_path)
    try:
        result = LogAnalysisService(repository).analyze(target, rules_path=rules, ioc_path=ioc_file)
    except LogIngestionError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    finally:
        repository.close()
    summary = result.summary()
    if output_format == "json":
        typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        typer.echo(f"Log scan {result.scan_id}: {result.events} normalized event(s)")
        typer.echo(f"Sources: {result.source_count}; alerts: {len(result.alerts)}")
        for severity in ("critical", "high", "medium", "low", "info"):
            count = sum(alert.severity.value == severity for alert in result.alerts)
            if count:
                typer.echo(f"{severity.upper()}: {count}")
        if result.errors:
            typer.echo(f"Parser or rule warnings: {len(result.errors)}", err=True)
    if result.errors:
        raise typer.Exit(code=1)


def malware_analyze(
    sample: Path = typer.Argument(..., help="Local file for bounded static analysis."),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
    yara_rules: Path | None = typer.Option(  # noqa: B008
        None, "--yara-rules", help="Explicit local YARA rules file; requires yara on PATH."
    ),  # noqa: B008
    clamav: bool = typer.Option(False, "--clamav", help="Opt in to local clamscan analysis."),  # noqa: B008
    include_indicators: bool = typer.Option(
        False, "--include-indicators", help="Include extracted indicator values in output."
    ),  # noqa: B008
) -> None:
    """Inspect one local file without executing, copying, or persisting sample bytes."""
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be 'human' or 'json'")
    try:
        result = analyze_file(sample)
    except AnalysisError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc

    engines: list[EngineResult] = []
    if yara_rules is not None:
        engines.append(run_yara(Path(result.sample_path), yara_rules))
    if clamav:
        engines.append(run_clamav(Path(result.sample_path)))
    summary = result.summary(include_indicators=include_indicators)
    summary["engines"] = [
        {"engine": engine.engine, "matches": list(engine.matches), "warning": engine.warning}
        for engine in engines
    ]
    if output_format == "json":
        typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        typer.echo("Static file analysis complete; sample was not executed or retained.")
        typer.echo(f"Type: {result.file_type}; size: {result.size_bytes} bytes")
        typer.echo(f"SHA-256: {result.sha256}")
        typer.echo(f"Candidate indicators: {result.indicator_count}")
        for engine in engines:
            typer.echo(f"{engine.engine}: {len(engine.matches)} match(es)")
            if engine.warning:
                typer.echo(f"{engine.engine} warning: {redact(engine.warning)}", err=True)
    if any(engine.warning for engine in engines):
        raise typer.Exit(code=1)


def domain_assess(
    target: str = typer.Argument(..., help="Fully qualified hostname to assess."),  # noqa: B008
    profile: str = typer.Option("light", "--profile", help="Assessment profile: light or deep."),  # noqa: B008
    operator: str | None = typer.Option(
        None, "--operator", help="Operator name for ownership assertion."
    ),  # noqa: B008
    i_own_this_target: bool = typer.Option(
        False, "--i-own-this-target", help="Explicitly assert that you own this exact hostname."
    ),
    authorization_file: Path | None = typer.Option(  # noqa: B008
        None, "--authorization-file", help="Local JSON authorization for this exact hostname."
    ),  # noqa: B008
    timeout_seconds: float = typer.Option(
        3.0, "--timeout", help="DNS/connect timeout in seconds (0.1 to 10)."
    ),  # noqa: B008
    max_addresses: int = typer.Option(
        5, "--max-addresses", help="Deep-profile public address limit (1 to 5)."
    ),  # noqa: B008
    request_interval_seconds: float = typer.Option(
        0.0, "--request-interval", help="Minimum seconds between requests (0 to 5)."
    ),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
) -> None:
    """Assess one hostname only after explicit, auditable authorization."""
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be 'human' or 'json'")
    try:
        grant = authorize_target(
            target,
            profile=profile,
            operator=operator,
            assert_ownership=i_own_this_target,
            authorization_file=authorization_file,
        )
    except AuthorizationError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    try:
        probe_settings = ProbeSettings(
            timeout_seconds=timeout_seconds,
            max_addresses=max_addresses,
            request_interval_seconds=request_interval_seconds,
        )
    except ValueError as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    scan_options: dict[str, str | int | float | bool] = probe_settings.as_dict()
    repository = SQLiteRepository(_settings().database_path)
    try:
        result = DomainAssessmentService(
            repository,
            NetworkDomainProbe(probe_settings),
            scan_options=scan_options,
        ).assess(grant)
    finally:
        repository.close()
    if output_format == "json":
        typer.echo(json.dumps(result.summary(), ensure_ascii=False, sort_keys=True))
    else:
        typer.echo(f"Domain assessment {result.scan_id}: {result.target} ({result.status})")
        typer.echo(f"Authorization record: {result.authorization_id}; profile: {result.profile}")
        typer.echo(f"Resolved public addresses: {len(result.probe.addresses)}")
        typer.echo(f"HTTP status: {result.probe.http_status or 'unavailable'}")
        typer.echo(f"Candidate findings: {len(result.findings)}")
        for error in result.probe.errors:
            typer.echo(str(redact(error)), err=True)
    if result.status != "complete":
        raise typer.Exit(code=1)


case_app = typer.Typer(help="Create and manage investigation cases.")
case_note_app = typer.Typer(help="Add and review append-only analyst notes.")
case_app.add_typer(case_note_app, name="note")

db_app = typer.Typer(help="Create, verify, and restore local SQLite backups.")


def _recovery_error(exc: RecoveryError) -> None:
    typer.echo(str(redact(str(exc))), err=True)
    raise typer.Exit(code=exc.exit_code) from exc


@db_app.command("backup")
def database_backup(
    output: Path = typer.Option(..., "--output", help="New backup bundle directory."),  # noqa: B008
    output_format: str = typer.Option(  # noqa: B008
        "human", "--format", help="Output format: human or json."
    ),  # noqa: B008
) -> None:
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be human or json")
    settings = _settings()
    try:
        result = backup_database(
            settings.database_path,
            output,
        )
    except RecoveryError as exc:
        _recovery_error(exc)
    if output_format == "json":
        typer.echo(
            json.dumps(
                {
                    "backup_id": result.backup_id,
                    "backup_directory": str(result.backup_directory),
                    "verification": result.verification.as_dict(),
                },
                sort_keys=True,
            )
        )
    else:
        typer.echo(f"Created backup {result.backup_id}: {result.backup_directory}")
        typer.echo(
            "Verification: "
            + ("passed" if result.verification.verified else "application consistency issues")
        )
    if not result.verification.verified:
        raise typer.Exit(code=1)


@db_app.command("verify-backup")
def database_verify_backup(
    backup_directory: Path = typer.Argument(..., help="Backup bundle directory."),  # noqa: B008
    output_format: str = typer.Option(  # noqa: B008
        "human", "--format", help="Output format: human or json."
    ),  # noqa: B008
) -> None:
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be human or json")
    try:
        result = verify_backup(backup_directory)
    except RecoveryError as exc:
        _recovery_error(exc)
    if output_format == "json":
        typer.echo(json.dumps(result.as_dict(), sort_keys=True))
    else:
        state = "verified" if result.verified else "verification incomplete"
        typer.echo(f"Backup {result.backup_id or 'unknown'}: {state}")
        if result.structural_errors:
            typer.echo(
                f"Structural errors: {redact(', '.join(result.structural_errors))}", err=True
            )
        if result.unsupported_schema:
            typer.echo(f"Unsupported schema: {result.unsupported_schema}", err=True)
        if result.application_issues:
            typer.echo(
                f"Application consistency issues: {', '.join(result.application_issues)}", err=True
            )
    if not result.verified:
        raise typer.Exit(
            code=(
                1
                if result.application_issues
                and not result.structural_errors
                and result.unsupported_schema is None
                else 2
            )
        )


@db_app.command("restore")
def database_restore(
    backup_directory: Path = typer.Argument(..., help="Verified backup bundle directory."),  # noqa: B008
    output: Path = typer.Option(..., "--output", help="New SQLite database path; must not exist."),  # noqa: B008
    output_format: str = typer.Option(  # noqa: B008
        "human", "--format", help="Output format: human or json."
    ),  # noqa: B008
) -> None:
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be human or json")
    settings = _settings()
    try:
        result = restore_backup(
            backup_directory,
            output,
            active_database_path=settings.database_path,
        )
    except RecoveryError as exc:
        _recovery_error(exc)
    payload = {
        "backup_id": result.backup_id,
        "destination": str(result.destination),
        "original_revision": result.original_revision,
        "resulting_revision": result.resulting_revision,
    }
    if output_format == "json":
        typer.echo(json.dumps(payload, sort_keys=True))
    else:
        typer.echo(
            f"Restored backup {result.backup_id} to new database {result.destination} "
            f"(schema {result.original_revision or 'unversioned'} -> "
            f"{result.resulting_revision or 'unversioned'})."
        )


@db_app.command("retention-plan")
def database_retention_plan(
    directory: Path = typer.Option(  # noqa: B008
        ..., "--directory", help="Explicit managed backup directory."
    ),  # noqa: B008
    keep_last: int = typer.Option(5, min=1, help="Retain up to this many newest verified bundles."),  # noqa: B008
    max_age_days: int = typer.Option(
        90, min=1, help="Retain bundles no older than this many days."
    ),  # noqa: B008
    output_format: str = typer.Option(  # noqa: B008
        "human", "--format", help="Output format: human or json."
    ),  # noqa: B008
) -> None:
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be human or json")
    try:
        plan = plan_retention(directory, keep_last=keep_last, max_age_days=max_age_days)
    except RecoveryError as exc:
        _recovery_error(exc)
    if output_format == "json":
        typer.echo(json.dumps(plan.as_dict(), sort_keys=True, indent=2))
    else:
        typer.echo(
            f"Preview only: {len(plan.entries)} entries; keep last {keep_last}, "
            f"maximum age {max_age_days} days. No files were deleted."
        )
        for entry in plan.entries:
            typer.echo(f"{entry.disposition.upper():8} {entry.name}: {entry.reason}")


def _case_repository() -> SQLiteRepository:
    try:
        return SQLiteRepository(_settings().database_path)
    except (StorageError, SQLAlchemyError, OSError) as exc:
        typer.echo("Case storage could not be opened.", err=True)
        raise typer.Exit(code=1) from exc


def _case_storage_error(exc: Exception) -> None:
    typer.echo("Case storage operation failed; no partial case update was saved.", err=True)
    raise typer.Exit(code=1) from exc


def _case_workflow_error(exc: CaseWorkflowError) -> None:
    typer.echo(str(redact(str(exc))), err=True)
    raise typer.Exit(code=exc.exit_code) from exc


def _case_warnings(warnings: list[str]) -> None:
    for warning in warnings:
        typer.echo(str(redact(warning)), err=True)


@case_app.command("create")
def case_create(
    scan_id: str = typer.Option(..., "--from-scan", help="Attach a persisted scan."),  # noqa: B008
    title: str | None = typer.Option(None, "--title", help="Case title; defaults to scan ID."),  # noqa: B008
    description: str = typer.Option("", "--description", help="Case description."),  # noqa: B008
    severity: Severity = typer.Option(Severity.MEDIUM, "--severity", help="Case severity."),  # noqa: B008
) -> None:
    repository = _case_repository()
    try:
        case, warnings = CaseWorkflow(repository).create_from_scan(
            scan_id, title=title, description=description, severity=severity.value
        )
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    typer.echo(f"Created case {case.case_id} ({case.status.value})")
    _case_warnings(warnings)


@case_app.command("show")
def case_show(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    output_format: str = typer.Option("json", "--format", help="Output format: json or human."),  # noqa: B008
) -> None:
    if output_format not in {"json", "human"}:
        raise typer.BadParameter("must be json or human")
    repository = _case_repository()
    try:
        workflow = CaseWorkflow(repository)
        case = workflow.get_case(case_id)
        context = workflow.context(case)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    if output_format == "json":
        typer.echo(json.dumps(case.model_dump(mode="json"), sort_keys=True, indent=2))
    else:
        typer.echo(f"Case {case.case_id}: {case.title}")
        typer.echo(f"Status: {case.status.value}; severity: {case.severity.value}")
        typer.echo(f"Linked records: {len(context.links)}; notes: {len(case.notes)}")
        if case.description:
            typer.echo(case.description)
    _case_warnings(context.warnings)


@case_app.command("update")
def case_update(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    status: CaseStatus = typer.Option(  # noqa: B008
        ..., "--status", help="open, in_progress, resolved, or closed."
    ),  # noqa: B008
) -> None:
    repository = _case_repository()
    try:
        case, changed = CaseWorkflow(repository).update_status(case_id, status)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    verb = "Updated" if changed else "Already at"
    typer.echo(f"{verb} case {case.case_id}: {case.status.value}")


@case_app.command("link")
def case_link(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    record_type: str = typer.Option(..., "--type", help="Persisted record type."),  # noqa: B008
    record_id: str = typer.Option(..., "--id", help="Persisted record ID."),  # noqa: B008
) -> None:
    repository = _case_repository()
    try:
        _, added, warnings = CaseWorkflow(repository).link_record(case_id, record_type, record_id)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    typer.echo(("Linked" if added else "Already linked") + f" {record_type} {record_id}.")
    _case_warnings(warnings)


@case_note_app.command("add")
def case_note_add(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    text: str = typer.Option(..., "--text", help="Analyst note text; maximum 8000 characters."),  # noqa: B008
    author: str | None = typer.Option(None, "--author", help="Unverified local author label."),  # noqa: B008
) -> None:
    repository = _case_repository()
    try:
        note = CaseWorkflow(repository).add_note(case_id, text, author)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    typer.echo(f"Added note {note.note_id} to case {case_id}.")


@case_note_app.command("list")
def case_note_list(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    output_format: str = typer.Option("json", "--format", help="Output format: json or human."),  # noqa: B008
) -> None:
    if output_format not in {"json", "human"}:
        raise typer.BadParameter("must be json or human")
    repository = _case_repository()
    try:
        case = CaseWorkflow(repository).get_case(case_id)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    notes = [note.model_dump(mode="json") for note in case.notes]
    if output_format == "json":
        typer.echo(json.dumps(notes, sort_keys=True, indent=2))
    else:
        for note in notes:
            label = (
                f" — {note['author_label']} (unverified local label)"
                if note.get("author_label")
                else ""
            )
            typer.echo(f"{note['created_at']}{label}: {note['body']}")


@case_app.command("timeline")
def case_timeline(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),  # noqa: B008
) -> None:
    if output_format not in {"json", "human"}:
        raise typer.BadParameter("must be json or human")
    repository = _case_repository()
    try:
        _, items, warnings = CaseWorkflow(repository).timeline(case_id)
    except CaseWorkflowError as exc:
        _case_workflow_error(exc)
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    if output_format == "json":
        typer.echo(
            json.dumps([item.model_dump(mode="json") for item in items], sort_keys=True, indent=2)
        )
    else:
        for item in items:
            timestamp = item.event_occurred_at or item.case_activity_at
            shown_time = timestamp.isoformat() if timestamp else "time unavailable"
            typer.echo(f"{shown_time} [{item.category}] {item.description}")
    _case_warnings(warnings)


@case_app.command("export")
def case_export(
    case_id: str = typer.Argument(..., help="Case ID."),  # noqa: B008
    output_format: str = typer.Option(
        "json", "--format", help="Output format: json, markdown, or html."
    ),  # noqa: B008
    output: Path | None = typer.Option(None, "--output", help="Write atomically to this path."),  # noqa: B008
) -> None:
    if output_format not in {"json", "markdown", "html"}:
        raise typer.BadParameter("must be json, markdown, or html")
    if output is not None and (output.exists() or output.is_symlink()):
        typer.echo("Case report destination already exists.", err=True)
        raise typer.Exit(code=2)
    repository = _case_repository()
    try:
        content = render_case_report(repository, case_id, output_format)
    except (CaseWorkflowError, ReportingError) as exc:
        typer.echo(str(redact(str(exc))), err=True)
        raise typer.Exit(code=2) from exc
    except (SQLAlchemyError, StorageError, OSError) as exc:
        _case_storage_error(exc)
    finally:
        repository.close()
    if output is None:
        typer.echo(content, nl=False)
        return
    temporary: Path | None = None
    published = False
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, output)
        published = True
        temporary.unlink()
    except OSError as exc:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
        if published:
            with suppress(OSError):
                output.unlink(missing_ok=True)
        typer.echo("Case report could not be published safely.", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Wrote {output_format} case report: {output}")


fs_app = typer.Typer(help="Check configured local filesystem scope without listing contents.")


@fs_app.command("check")
def fs_check(
    path: Path = typer.Argument(...),  # noqa: B008
    json_output: bool = typer.Option(False, "--json"),  # noqa: B008
) -> None:
    settings = _settings()
    hard, soft = policy_paths(settings)
    result = decide_path(
        path,
        allowed_roots=settings.allowed_roots,
        hard_denied=hard,
        soft_denied=soft,
        allow_soft_denied=settings.allow_soft_denied,
    )
    output = {"allowed": result.allowed, "tier": result.tier, "reason_code": result.reason_code}
    message = f"{'ALLOWED' if result.allowed else 'DENIED'} {result.tier} {result.reason_code}"
    typer.echo(json.dumps(output) if json_output else message)
    if not result.allowed:
        raise typer.Exit(code=2)


@fs_app.command("roots")
def fs_roots(json_output: bool = typer.Option(False, "--json")) -> None:
    settings = _settings()
    validations = cast(list[RootValidation], settings.allowed_root_validation)
    values = [
        {
            "index": item.index,
            "status": "valid" if item.valid else "invalid",
            "reason_code": item.reason_code,
        }
        for item in validations
    ]
    output = {"roots": values, "count": len(values)}
    valid_count = sum(item.valid for item in validations)
    typer.echo(
        json.dumps(output)
        if json_output
        else f"Configured roots: {len(values)}; valid: {valid_count}"
    )
    if any(not item.valid for item in validations):
        raise typer.Exit(code=2)


projects_app = typer.Typer(help="Manage locally approved code projects.")
project_logs_app = typer.Typer(help="Manage project log locations and analyze local logs.")
project_malware_app = typer.Typer(help="Static malware leads for approved projects.")
projects_app.add_typer(project_logs_app, name="logs")
projects_app.add_typer(project_malware_app, name="malware")


def _project_service() -> ProjectService:
    settings = _settings()
    hard, soft = policy_paths(settings)
    legacy = ProjectFileRegistry(
        Path.home() / ".config" / "chinescan" / "projects.toml",
        [
            settings.database_path.parent,
            settings.database_path,
            settings.reports_dir,
            Path.home() / ".config" / "chinescan" / "operator.json",
        ],
    )
    return ProjectService(
        SQLiteRepository(settings.database_path),
        FilesystemBrowserService(settings.allowed_roots, hard, soft, settings.allow_soft_denied),
        legacy,
        allowed_roots=settings.allowed_roots,
        hard_denied=hard,
        soft_denied=soft,
        allow_soft_denied=settings.allow_soft_denied,
    )


@projects_app.command("list")
def projects_list(json_output: bool = typer.Option(False, "--json")) -> None:
    service = _project_service()
    try:
        items = service.list()
        typer.echo(
            json.dumps({"projects": items}, sort_keys=True)
            if json_output
            else "\n".join(
                f"{item['name']} ({item['configured_by']}) — {item['project_id']}" for item in items
            )
            or "No projects configured."
        )
    finally:
        service.repository.close()


@projects_app.command("add")
def projects_add(
    name: str = typer.Option(..., "--name"),
    path: Path | None = typer.Option(None, "--path", help="Absolute approved project folder."),  # noqa: B008
    directory_id: str | None = typer.Option(
        None, "--directory-id", help="Browser capability ID (session-bound)."
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    if path is None or directory_id is not None:
        code = "directory_id_session_bound" if directory_id is not None else "project_path_required"
        message = (
            "Use --path here; folder-browser IDs are short-lived and bound to a web session."
            if directory_id is not None
            else "Provide an approved local folder with --path."
        )
        typer.echo(json.dumps({"error": code}) if json_output else message, err=True)
        raise typer.Exit(code=2)
    service = _project_service()
    try:
        item = service.create(name, service.resolve_path(path))
        typer.echo(
            json.dumps(item, sort_keys=True)
            if json_output
            else f"Added project {item['name']} ({item['project_id']})."
        )
    except ProjectError as exc:
        typer.echo(
            json.dumps({"error": exc.code}) if json_output else f"Project add failed: {exc.code}.",
            err=True,
        )
        raise typer.Exit(code=2) from exc
    finally:
        service.repository.close()


@projects_app.command("show")
def projects_show(
    project_id: str = typer.Argument(...), json_output: bool = typer.Option(False, "--json")
) -> None:
    service = _project_service()
    try:
        item = service.get(project_id)
        typer.echo(
            json.dumps(item, sort_keys=True)
            if json_output
            else f"{item['name']} · {item['kind']} · configured by {item['configured_by']}"
        )
    except ProjectError as exc:
        typer.echo(f"Project show failed: {exc.code}.", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        service.repository.close()


@projects_app.command("remove")
def projects_remove(
    project_id: str = typer.Argument(...),
    yes: bool = typer.Option(False, "--yes", help="Confirm removal of this project record."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    if not yes:
        typer.echo("Pass --yes to remove a UI-created project record.", err=True)
        raise typer.Exit(code=2)
    service = _project_service()
    try:
        item = next((value for value in service.list() if value["project_id"] == project_id), None)
        if item is None:
            raise ProjectError("project_not_found", "Project not found.")
        service.remove(project_id, str(item["name"]))
        typer.echo(
            json.dumps({"status": "removed"})
            if json_output
            else "Project record removed; folder contents were not changed."
        )
    except ProjectError as exc:
        typer.echo(f"Project removal failed: {exc.code}.", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        service.repository.close()


@project_malware_app.command("scan")
def project_malware_scan(
    project: str = typer.Option(..., "--project"),
    i_understand_vm_risk: bool = typer.Option(False, "--i-understand-vm-risk"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    if not i_understand_vm_risk:
        typer.echo("Refusing project malware scan without --i-understand-vm-risk.", err=True)
        raise typer.Exit(code=2)
    service = _project_service()
    try:
        ack = MalwareAcknowledgements(service.repository)
        issued = ack.issue(project, "cli", True)
        ack.consume(issued["token"], project, "cli")
        result = ProjectMalwareScanner(service.repository, service, _settings()).scan(project)
        typer.echo(
            json.dumps(result, sort_keys=True)
            if json_output
            else (
                f"Static project scan {result['status']}; "
                f"{result['finding_count']} heuristic leads."
            )
        )
    except (ProjectError, MalwareAcknowledgementError) as exc:
        typer.echo(
            json.dumps({"error": getattr(exc, "code", "scan_failed")})
            if json_output
            else f"Project malware scan failed: {getattr(exc, 'code', 'scan_failed')}.",
            err=True,
        )
        raise typer.Exit(code=2) from exc
    finally:
        service.repository.close()


@project_malware_app.command("list")
def project_malware_list(
    project: str = typer.Option(..., "--project"), json_output: bool = typer.Option(False, "--json")
) -> None:
    service = _project_service()
    try:
        service.resolve(project)
        items = [
            row
            for row in service.repository.list_records("project_malware_job")
            if row.get("project_id") == project
        ]
        items.sort(key=lambda row: str(row.get("created_at", "")), reverse=True)
        typer.echo(
            json.dumps(items, sort_keys=True)
            if json_output
            else "\n".join(
                f"{row['job_id']} {row['status']} {row.get('finding_count', 0)} findings"
                for row in items
            )
            or "No project malware scans."
        )
    except ProjectError as exc:
        typer.echo(f"Project malware list failed: {exc.code}.", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        service.repository.close()


@project_malware_app.command("show")
def project_malware_show(
    job_id: str = typer.Argument(...),
    project: str = typer.Option(..., "--project"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    service = _project_service()
    try:
        row = service.repository.get("project_malware_job", job_id)
        if row is None or row.get("project_id") != project:
            raise ProjectError("job_not_found", "Project malware job not found.")
        typer.echo(
            json.dumps(row, sort_keys=True)
            if json_output
            else f"{row['status']} · {row.get('finding_count', 0)} heuristic leads"
        )
    except ProjectError as exc:
        typer.echo(f"Project malware detail failed: {exc.code}.", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        service.repository.close()


@project_logs_app.command("list")
def project_logs_list(
    project: str = typer.Option(..., "--project"), json_output: bool = typer.Option(False, "--json")
) -> None:
    service = _project_service()
    try:
        items = LogLocationService(service.repository, service).list(project)
        typer.echo(
            json.dumps(items, sort_keys=True)
            if json_output
            else "\n".join(
                f"{item['name']} [{item['scope']}] {item['location_id']}" for item in items
            )
            or "No log locations linked."
        )
    except ProjectError as exc:
        typer.echo(f"Log locations unavailable: {exc.code}.", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        service.repository.close()


@project_logs_app.command("add")
def project_logs_add(
    project: str = typer.Option(..., "--project"),
    name: str = typer.Option(..., "--name"),
    path: Path | None = typer.Option(None, "--path"),  # noqa: B008
    directory_id: str | None = typer.Option(None, "--directory-id"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    if path is None or directory_id is not None:
        typer.echo("CLI location add requires --path; browser IDs are session-bound.", err=True)
        raise typer.Exit(code=2)
    service = _project_service()
    try:
        selected = service.resolve_path(path)
        item = LogLocationService(service.repository, service).add_project_selection(
            project, name, selected
        )
        typer.echo(
            json.dumps(item, sort_keys=True)
            if json_output
            else f"Added log location {item['name']}. "
        )
    except ProjectError as exc:
        typer.echo(f"Log location add failed: {exc.code}.", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        service.repository.close()


@project_logs_app.command("remove")
def project_logs_remove(
    location_id: str = typer.Argument(...),
    project: str = typer.Option(..., "--project"),
    yes: bool = typer.Option(False, "--yes"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    if not yes:
        typer.echo("Pass --yes to remove the association; files are never touched.", err=True)
        raise typer.Exit(code=2)
    service = _project_service()
    try:
        LogLocationService(service.repository, service).remove(project, location_id)
        typer.echo(
            json.dumps({"status": "removed"})
            if json_output
            else "Removed log location association; files are untouched."
        )
    except ProjectError as exc:
        typer.echo(f"Log location removal failed: {exc.code}.", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        service.repository.close()


@project_logs_app.command("suggest")
def project_logs_suggest(
    project: str = typer.Option(..., "--project"), json_output: bool = typer.Option(False, "--json")
) -> None:
    service = _project_service()
    try:
        result = LogLocationService(service.repository, service).suggestions(project)
        typer.echo(
            json.dumps(result, sort_keys=True)
            if json_output
            else "\n".join(
                f"{row['label']}"
                + (" [unsupported format]" if row["unsupported"] else " [confirm in dashboard]")
                for row in result["items"]
            )
            or "No log location suggestions."
        )
    except ProjectError as exc:
        typer.echo(f"Log suggestions failed: {exc.code}.", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        service.repository.close()


@project_logs_app.command("analyze")
def project_logs_analyze(
    project: str = typer.Option(..., "--project"),
    location: list[str] = typer.Option([], "--location"),  # noqa: B008
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    service = _project_service()
    try:
        locations = LogLocationService(service.repository, service)
        available = locations.list(project)
        chosen = location or [str(item["location_id"]) for item in available]
        if not chosen:
            raise ProjectError("no_locations", "Link at least one log location first.")
        roots = [locations.resolve_location(project, identifier) for identifier in chosen]
        results = [LogAnalysisService(service.repository).analyze(root) for root in roots]
        for result, identifier in zip(results, chosen, strict=True):
            raw = service.repository.get("scan", result.scan_id)
            if raw is not None:
                raw.update(project_id=project, location_ids=[identifier])
                service.repository.save("scan", result.scan_id, raw)
        output = {
            "project_id": project,
            "scan_ids": [result.scan_id for result in results],
            "event_count": sum(result.events for result in results),
            "alert_count": sum(len(result.alerts) for result in results),
            "partial": any(result.errors for result in results),
        }
        typer.echo(
            json.dumps(output, sort_keys=True)
            if json_output
            else (
                f"Analyzed project logs: {output['event_count']} events, "
                f"{output['alert_count']} alerts."
            )
        )
    except ProjectError as exc:
        typer.echo(
            json.dumps({"error": exc.code}) if json_output else f"Log analysis failed: {exc.code}.",
            err=True,
        )
        raise typer.Exit(code=2) from exc
    finally:
        service.repository.close()
