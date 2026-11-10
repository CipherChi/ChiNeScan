"""Local SQLite backup, verification, restore, and preview-only retention."""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import sqlite3
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from alembic.script import ScriptDirectory
from pydantic import BaseModel, ValidationError

from chinescan import __version__
from chinescan.core.cases import SUPPORTED_CASE_RECORDS
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import (
    Artifact,
    Authorization,
    AuthorizationRecord,
    Case,
    CaseActivity,
    CaseNote,
    Event,
    Indicator,
    Report,
    Scan,
    Target,
    TimelineEntry,
)
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.malware_analysis.managed import (
    MalwareAnalysisRecord,
    MalwareJobRecord,
    MalwareSampleRecord,
)

BACKUP_FORMAT_VERSION = 1
DATABASE_FILENAME = "database.sqlite3"
MANIFEST_FILENAME = "manifest.json"
MAX_BACKUP_BYTES = 16 * 1024**3
BACKUP_TIMEOUT_SECONDS = 120.0
BACKUP_MAX_BUSY_RETRIES = 8
PAGE_BATCH_SIZE = 128
RECORD_MODELS: dict[str, type[BaseModel]] = {
    "alert": SUPPORTED_CASE_RECORDS["alert"],
    "artifact": Artifact,
    "authorization": Authorization,
    "authorization_record": AuthorizationRecord,
    "case": Case,
    "event": Event,
    "finding": Finding,
    "indicator": Indicator,
    "report": Report,
    "scan": Scan,
    "target": Target,
    "timeline_entry": TimelineEntry,
}


class MalwareMetadataRecord(BaseModel):
    """Backup validates malware records as JSON metadata and never includes sample bytes."""

    model_config = {"extra": "allow"}


RECORD_MODELS.update(
    {
        "malware_job": MalwareJobRecord,
        "malware_audit": MalwareMetadataRecord,
        "malware_sample": MalwareSampleRecord,
        "malware_analysis": MalwareAnalysisRecord,
    }
)
RECORD_ID_FIELDS = {
    "alert": "alert_id",
    "authorization_record": "authorization_id",
    "case": "case_id",
    "event": "event_id",
    "finding": "finding_id",
    "indicator": "indicator_id",
    "scan": "scan_id",
    "timeline_entry": "entry_id",
}
RECORD_ID_FIELDS.update(
    {
        "malware_sample": "sample_id",
        "malware_job": "job_id",
        "malware_analysis": "analysis_id",
    }
)


class RecoveryError(Exception):
    """Safe, user-facing recovery operation error."""

    exit_code = 1


class RecoveryInputError(RecoveryError):
    """Invalid or unsafe recovery input."""

    exit_code = 2


@dataclass(frozen=True)
class VerificationResult:
    backup_id: str | None
    verified: bool
    structural_errors: tuple[str, ...]
    unsupported_schema: str | None
    application_issues: tuple[str, ...]
    migration_revision: str | None
    database_size_bytes: int | None
    checksum_sha256: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "verified": self.verified,
            "structural_errors": list(self.structural_errors),
            "unsupported_schema": self.unsupported_schema,
            "application_issues": list(self.application_issues),
            "migration_revision": self.migration_revision,
            "database_size_bytes": self.database_size_bytes,
            "checksum_sha256": self.checksum_sha256,
        }


@dataclass(frozen=True)
class BackupResult:
    backup_id: str
    backup_directory: Path
    verification: VerificationResult


@dataclass(frozen=True)
class RestoreResult:
    backup_id: str
    destination: Path
    original_revision: str | None
    resulting_revision: str | None


@dataclass(frozen=True)
class RetentionEntry:
    name: str
    disposition: str
    reason: str


@dataclass(frozen=True)
class RetentionPlan:
    directory: Path
    keep_last: int
    max_age_days: int
    entries: tuple[RetentionEntry, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "directory": str(self.directory),
            "preview_only": True,
            "keep_last": self.keep_last,
            "max_age_days": self.max_age_days,
            "entries": [
                {"name": entry.name, "disposition": entry.disposition, "reason": entry.reason}
                for entry in self.entries
            ],
        }


def _uri(path: Path, mode: str) -> str:
    absolute = path.resolve(strict=True)
    return f"file:{quote(absolute.as_posix(), safe='/:')}?mode={mode}"


def _connect_readonly(path: Path, *, immutable: bool = False) -> sqlite3.Connection:
    if not path.is_file() or path.is_symlink():
        raise RecoveryInputError("Database file is missing or is not a regular managed file.")
    query = _uri(path, "ro") + ("&immutable=1" if immutable else "")
    try:
        connection = sqlite3.connect(query, uri=True, timeout=5.0)
        connection.row_factory = sqlite3.Row
        return connection
    except sqlite3.Error as exc:
        raise RecoveryError("Database could not be opened read-only.") from exc


def _migration_heads() -> set[str]:
    root_config = SQLiteRepository._alembic_config("sqlite://")
    return set(ScriptDirectory.from_config(root_config).get_heads())


def _schema_revision(connection: sqlite3.Connection) -> tuple[str | None, str | None]:
    tables = {
        row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    if "records" not in tables:
        return None, "required records table is missing"
    dashboard_tables = {"dashboard_alerts", "dashboard_alert_audit"}
    extras = tables - {"records", "alembic_version"}
    app_extras = extras - {"sqlite_sequence"}
    if app_extras - dashboard_tables:
        return None, "database contains an unsupported table layout"
    columns = connection.execute("PRAGMA table_info(records)").fetchall()
    signature = [(row["name"], row["type"].upper(), row["notnull"], row["pk"]) for row in columns]
    expected = [
        ("record_type", "VARCHAR(80)", 1, 1),
        ("record_id", "VARCHAR(255)", 1, 2),
        ("payload", "JSON", 1, 0),
    ]
    if signature != expected:
        return None, "records table does not match the supported schema"
    if "alembic_version" not in tables:
        if extras:
            return None, "unversioned database contains unsupported tables"
        return None, None
    version_columns = connection.execute("PRAGMA table_info(alembic_version)").fetchall()
    if len(version_columns) != 1 or version_columns[0]["name"] != "version_num":
        return None, "migration version table is malformed"
    try:
        revisions = [
            row[0] for row in connection.execute("SELECT version_num FROM alembic_version")
        ]
        if len(revisions) != 1:
            return None, "migration version table is empty or ambiguous"
        revision = str(revisions[0])
    except sqlite3.Error:
        return None, "migration revision cannot be read"
    supported = _migration_heads() | {"0001_initial"}
    if revision not in supported:
        return revision, "unsupported migration revision"
    if revision == "0004_dashboard_alerts" and app_extras != dashboard_tables:
        return revision, "dashboard alert tables are missing"
    if revision != "0004_dashboard_alerts" and extras:
        return revision, "dashboard alert tables do not match migration revision"
    for table_name in dashboard_tables if revision == "0004_dashboard_alerts" else ():
        column_names = {
            row["name"] for row in connection.execute(f'PRAGMA table_info("{table_name}")')
        }
        required = (
            {"alert_id", "fingerprint", "state", "created_at"}
            if table_name == "dashboard_alerts"
            else {"audit_id", "alert_id", "action", "occurred_at"}
        )
        if not required <= column_names:
            return revision, "dashboard alert table does not match the supported schema"
    return revision, None


def _record_rows(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    return connection.execute("SELECT record_type, record_id, payload FROM records").fetchall()


def _application_issues(connection: sqlite3.Connection) -> tuple[str, ...]:
    issues: list[str] = []
    payloads: dict[tuple[str, str], dict[str, Any]] = {}
    cases: dict[str, Case] = {}
    records: dict[tuple[str, str], Any] = {}
    rows = _record_rows(connection)
    for row in rows:
        record_type, record_id = str(row["record_type"]), str(row["record_id"])
        try:
            payload = json.loads(row["payload"])
        except (json.JSONDecodeError, TypeError):
            issues.append("invalid_record_payload")
            continue
        if not isinstance(payload, dict):
            issues.append("invalid_record_payload")
            continue
        payloads[(record_type, record_id)] = payload
        model = RECORD_MODELS.get(record_type)
        if model is None:
            if record_type in {"case_note", "case_activity"}:
                continue
            issues.append("unsupported_record_type")
            continue
        try:
            record = model.model_validate(payload)
        except (ValidationError, ValueError, TypeError):
            issues.append("invalid_record_payload")
            continue
        id_field = RECORD_ID_FIELDS.get(record_type)
        if id_field is not None and getattr(record, id_field) != record_id:
            issues.append("record_key_mismatch")
        records[(record_type, record_id)] = record
        if isinstance(record, Case):
            if record.case_id != record_id:
                issues.append("record_key_mismatch")
            cases[record_id] = record

    for case in cases.values():
        links = {(link.record_type, link.record_id) for link in case.links}
        links.update(("scan", item) for item in case.scan_ids)
        links.update(("finding", item) for item in case.finding_ids)
        for record_type, record_id in links:
            model = SUPPORTED_CASE_RECORDS.get(record_type)
            if model is None:
                issues.append("invalid_case_link_type")
                continue
            payload = payloads.get((record_type, record_id))
            if payload is None:
                matching_types = [kind for kind, key in payloads if key == record_id]
                issues.append("invalid_case_link_type" if matching_types else "dangling_case_link")
                continue
            try:
                model.model_validate(payload)
            except (ValidationError, ValueError, TypeError):
                issues.append("invalid_linked_record_payload")

    relationships: list[tuple[str, str]] = []
    for (record_type, _), record in records.items():
        if isinstance(record, Scan):
            relationships.append(("target", record.target_id))
            relationships.extend(("finding", item) for item in record.finding_ids)
            relationships.extend(("alert", item) for item in record.alert_ids)
            relationships.extend(("event", item) for item in record.event_ids)
            relationships.extend(("timeline_entry", item) for item in record.timeline_entry_ids)
        elif record_type == "alert":
            relationships.extend(("event", item) for item in record.event_ids)
            relationships.extend(("indicator", item) for item in record.indicator_ids)
        elif isinstance(record, Indicator):
            relationships.extend(("finding", item) for item in record.related_findings)
            relationships.extend(("event", item) for item in record.related_events)
        elif isinstance(record, TimelineEntry):
            if record.event_id:
                relationships.append(("event", record.event_id))
            if record.scan_id:
                relationships.append(("scan", record.scan_id))
        elif isinstance(record, AuthorizationRecord):
            relationships.append(("scan", record.scan_id))
        elif isinstance(record, Report):
            relationships.extend(("finding", item) for item in record.finding_ids)
        elif isinstance(record, MalwareAnalysisRecord):
            relationships.append(("malware_sample", record.sample_id))
        elif isinstance(record, MalwareJobRecord):
            relationships.append(("malware_sample", record.sample_id))
            if record.analysis_id:
                relationships.append(("malware_analysis", record.analysis_id))
    for record_type, record_id in relationships:
        if (record_type, record_id) not in payloads:
            issues.append("dangling_record_relationship")

    for case in cases.values():
        note_ids = {note.note_id for note in case.notes}
        for activity in case.activities:
            details = activity.details
            if (
                activity.activity_type.value == "note_added"
                and details.get("note_id") not in note_ids
            ):
                issues.append("activity_reference_missing_note")
            elif activity.activity_type.value == "record_linked":
                link = (details.get("record_type", ""), details.get("record_id", ""))
                if link not in links:
                    issues.append("activity_reference_missing_link")
            elif activity.activity_type.value == "created":
                scan_id = details.get("from_scan")
                if scan_id and ("scan", scan_id) not in payloads:
                    issues.append("activity_reference_missing_scan")

    for (record_type, record_id), payload in payloads.items():
        if record_type == "case_note":
            try:
                note = CaseNote.model_validate(payload)
            except (ValidationError, ValueError, TypeError):
                issues.append("invalid_case_note")
                continue
            if note.note_id != record_id:
                issues.append("record_key_mismatch")
            if note.case_id not in cases:
                issues.append("orphan_case_note")
        elif record_type == "case_activity":
            try:
                activity = CaseActivity.model_validate(
                    {key: value for key, value in payload.items() if key != "case_id"}
                )
            except (ValidationError, ValueError, TypeError):
                issues.append("invalid_case_activity")
                continue
            if payload.get("case_id") not in cases:
                issues.append("orphan_case_activity")
            if activity.activity_id != record_id:
                issues.append("record_key_mismatch")
    return tuple(sorted(set(issues)))


def _verify_database(
    path: Path, *, immutable: bool = False
) -> tuple[tuple[str, ...], str | None, tuple[str, ...], str | None]:
    structural: list[str] = []
    revision: str | None = None
    unsupported: str | None = None
    issues: tuple[str, ...] = ()
    if not path.is_file() or path.is_symlink():
        return ("database_file_missing",), None, (), None
    try:
        connection = _connect_readonly(path, immutable=immutable)
    except RecoveryError:
        return ("database_open_failed",), None, (), None
    try:
        result = connection.execute("PRAGMA integrity_check").fetchone()
        if result is None or result[0] != "ok":
            structural.append("integrity_check_failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            structural.append("foreign_key_check_failed")
        revision, unsupported = _schema_revision(connection)
        if unsupported is None:
            issues = _application_issues(connection)
    except sqlite3.Error:
        structural.append("sqlite_verification_failed")
    finally:
        connection.close()
    return tuple(structural), revision, issues, unsupported


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest(path: Path) -> dict[str, Any]:
    manifest_path = path / MANIFEST_FILENAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise RecoveryInputError("Backup manifest is missing or unsafe.")
    if manifest_path.stat().st_size > 1024 * 1024:
        raise RecoveryInputError("Backup manifest exceeds the supported size.")
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryInputError("Backup manifest is malformed.") from exc
    if (
        not isinstance(value, dict)
        or isinstance(value.get("format_version"), bool)
        or value.get("format_version") != BACKUP_FORMAT_VERSION
    ):
        raise RecoveryInputError("Backup manifest format is unsupported.")
    try:
        parsed_backup_id = str(value["backup_id"])
        from uuid import UUID

        UUID(parsed_backup_id)
        created = datetime.fromisoformat(str(value["created_at"]).replace("Z", "+00:00"))
        if created.tzinfo is None or created.utcoffset() != timedelta(0):
            raise ValueError
        if not isinstance(value["chinescan_version"], str):
            raise ValueError
        revision = value.get("migration_revision")
        if revision is not None and not isinstance(revision, str):
            raise ValueError
        database = value["database"]
        if not isinstance(database, dict):
            raise ValueError
        size = database.get("size_bytes")
        checksum = database.get("sha256")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not (1 <= size <= MAX_BACKUP_BYTES)
        ):
            raise ValueError
        if not isinstance(checksum, str) or len(checksum) != 64:
            raise ValueError
        int(checksum, 16)
        verification = value.get("verification")
        if (
            not isinstance(verification, dict)
            or verification.get("integrity_check") != "ok"
            or verification.get("foreign_key_check") != "ok"
            or verification.get("schema_supported") is not True
            or verification.get("application_consistency") not in {"ok", "issues"}
            or not isinstance(verification.get("application_issue_codes"), list)
            or not all(isinstance(code, str) for code in verification["application_issue_codes"])
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise RecoveryInputError("Backup manifest fields are malformed.") from exc
    database = value.get("database")
    if not isinstance(database, dict) or database.get("file") != DATABASE_FILENAME:
        raise RecoveryInputError("Backup manifest database entry is invalid.")
    return value


def verify_backup(backup_directory: Path | str) -> VerificationResult:
    """Verify a bundle read-only. Never migrates or repairs its database."""
    directory = Path(backup_directory)
    if directory.is_symlink() or not directory.is_dir():
        raise RecoveryInputError("Backup directory is missing or unsafe.")
    manifest = _manifest(directory)
    backup_id = manifest.get("backup_id") if isinstance(manifest.get("backup_id"), str) else None
    database = directory / DATABASE_FILENAME
    structural: list[str] = []
    try:
        entries = {entry.name for entry in directory.iterdir()}
    except OSError:
        entries = set()
    if entries != {DATABASE_FILENAME, MANIFEST_FILENAME}:
        structural.append("unexpected_bundle_entry")
    checksum: str | None = None
    size: int | None = None
    if database.is_symlink() or not database.is_file():
        structural.append("database_file_missing_or_unsafe")
    else:
        size = database.stat().st_size
        if size < 1 or size > MAX_BACKUP_BYTES:
            structural.append("database_size_out_of_range")
        declared_size = manifest.get("database", {}).get("size_bytes")
        if declared_size != size:
            structural.append("database_size_mismatch")
        try:
            checksum = _sha256(database)
        except OSError:
            structural.append("database_read_failed")
        if checksum is not None and checksum != manifest.get("database", {}).get("sha256"):
            structural.append("checksum_mismatch")
        if (directory / f"{DATABASE_FILENAME}-wal").exists() or (
            directory / f"{DATABASE_FILENAME}-shm"
        ).exists():
            structural.append("unexpected_sqlite_sidecar")
    revision: str | None = None
    unsupported: str | None = None
    issues: tuple[str, ...] = ()
    if not any(
        code.startswith("database_file") or code == "database_read_failed" for code in structural
    ):
        db_structural, revision, issues, unsupported = _verify_database(database, immutable=True)
        structural.extend(db_structural)
    manifest_revision = manifest.get("migration_revision")
    if manifest_revision != revision:
        structural.append("manifest_revision_mismatch")
    manifest_verification = manifest.get("verification", {})
    expected_consistency = "issues" if issues else "ok"
    if manifest_verification.get(
        "application_consistency"
    ) != expected_consistency or manifest_verification.get("application_issue_codes") != list(
        issues
    ):
        structural.append("manifest_verification_mismatch")
    ok = not structural and unsupported is None and not issues
    return VerificationResult(
        backup_id=backup_id,
        verified=ok,
        structural_errors=tuple(sorted(set(structural))),
        unsupported_schema=unsupported,
        application_issues=issues,
        migration_revision=revision,
        database_size_bytes=size,
        checksum_sha256=checksum,
    )


def _set_restrictive_permissions(path: Path, *, directory: bool = False) -> None:
    try:
        os.chmod(path, 0o700 if directory else 0o600)
    except OSError as exc:
        raise RecoveryError("Restrictive file permissions could not be applied.") from exc


def _run_backup(
    source: sqlite3.Connection,
    destination: sqlite3.Connection,
    *,
    cancel_event: threading.Event | None,
    timeout_seconds: float,
) -> None:
    started = time.monotonic()
    busy_retries = 0

    def progress(status: int, remaining: int, total: int) -> None:
        nonlocal busy_retries
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("Backup cancelled.")
        if time.monotonic() - started > timeout_seconds:
            raise TimeoutError("Backup exceeded its time limit.")
        if status in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            busy_retries += 1
            if busy_retries > BACKUP_MAX_BUSY_RETRIES:
                raise RecoveryError("Database remained busy during backup.")
        else:
            busy_retries = 0
        page_size = source.execute("PRAGMA page_size").fetchone()[0]
        if total * page_size > MAX_BACKUP_BYTES:
            raise RecoveryError("Database exceeds the supported backup size.")

    try:
        source.backup(
            destination,
            pages=PAGE_BATCH_SIZE,
            progress=progress,
            sleep=0.1,
        )
    except InterruptedError as exc:
        raise RecoveryError("Backup was cancelled; incomplete output was removed.") from exc
    except TimeoutError as exc:
        raise RecoveryError(
            "Backup exceeded its time limit; incomplete output was removed."
        ) from exc
    except sqlite3.Error as exc:
        raise RecoveryError("SQLite backup failed; incomplete output was removed.") from exc


def _same_existing_file(first: Path, second: Path) -> bool:
    try:
        return os.path.samefile(first, second)
    except (OSError, FileNotFoundError):
        return first.resolve(strict=False) == second.resolve(strict=False)


def backup_database(
    source_path: Path | str,
    backup_directory: Path | str,
    *,
    cancel_event: threading.Event | None = None,
    timeout_seconds: float = BACKUP_TIMEOUT_SECONDS,
) -> BackupResult:
    """Create a verified self-contained SQLite bundle without modifying its source."""
    if not math.isfinite(timeout_seconds) or not (0 < timeout_seconds <= 3600):
        raise RecoveryInputError("Backup time limit must be between 0 and 3600 seconds.")
    source_path = Path(source_path)
    output = Path(backup_directory)
    if not source_path.is_file():
        raise RecoveryInputError("Source database does not exist as a regular file.")
    if source_path.is_symlink():
        source_path = source_path.resolve(strict=True)
    if output.exists() or output.is_symlink():
        raise RecoveryInputError("Backup destination already exists.")
    if output.name in {"", ".", ".."} or not output.parent.exists():
        raise RecoveryInputError("Backup destination parent must exist.")
    if _same_existing_file(source_path, output):
        raise RecoveryInputError("Backup destination aliases the source database.")
    output_parent = output.parent.resolve(strict=True)
    output = output_parent / output.name
    staging: Path | None = None
    source: sqlite3.Connection | None = None
    target: sqlite3.Connection | None = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output_parent))
        _set_restrictive_permissions(staging, directory=True)
        staging_database = staging / DATABASE_FILENAME
        try:
            source = sqlite3.connect(_uri(source_path, "ro"), uri=True, timeout=5.0)
            target = sqlite3.connect(staging_database)
            _set_restrictive_permissions(staging_database)
            _run_backup(source, target, cancel_event=cancel_event, timeout_seconds=timeout_seconds)
        finally:
            if target is not None:
                target.close()
            if source is not None:
                source.close()
        if staging_database.stat().st_size > MAX_BACKUP_BYTES:
            raise RecoveryError("Database exceeds the supported backup size.")
        structural, revision, issues, unsupported = _verify_database(
            staging_database, immutable=True
        )
        if structural or unsupported:
            raise RecoveryError("Completed backup failed structural verification.")
        backup_id = str(uuid4())
        manifest = {
            "format_version": BACKUP_FORMAT_VERSION,
            "backup_id": backup_id,
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "chinescan_version": __version__,
            "migration_revision": revision,
            "database": {
                "file": DATABASE_FILENAME,
                "size_bytes": staging_database.stat().st_size,
                "sha256": _sha256(staging_database),
            },
            "verification": {
                "integrity_check": "ok",
                "foreign_key_check": "ok",
                "schema_supported": True,
                "application_consistency": "issues" if issues else "ok",
                "application_issue_codes": list(issues),
            },
        }
        manifest_path = staging / MANIFEST_FILENAME
        with manifest_path.open("x", encoding="utf-8", newline="") as stream:
            json.dump(manifest, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        _set_restrictive_permissions(manifest_path)
        result = verify_backup(staging)
        # A bundle with application-level issues is preserved and reported, not repaired.
        if result.structural_errors or result.unsupported_schema:
            raise RecoveryError("Completed backup failed bundle verification.")
        try:
            os.rename(staging, output)
        except OSError as exc:
            raise RecoveryInputError("Backup destination could not be published safely.") from exc
        staging = None
        return BackupResult(backup_id, output, result)
    except RecoveryError:
        raise
    except Exception as exc:
        raise RecoveryError("Backup failed; incomplete output was removed.") from exc
    finally:
        if source is not None:
            source.close()
        if target is not None:
            target.close()
        if staging is not None and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _revision_for_path(path: Path) -> str | None:
    connection = _connect_readonly(path, immutable=True)
    try:
        revision, unsupported = _schema_revision(connection)
        if unsupported:
            raise RecoveryInputError("Database schema is not supported for restore.")
        return revision
    finally:
        connection.close()


def restore_backup(
    backup_directory: Path | str,
    destination_path: Path | str,
    *,
    active_database_path: Path | str | None = None,
    cancel_event: threading.Event | None = None,
    timeout_seconds: float = BACKUP_TIMEOUT_SECONDS,
) -> RestoreResult:
    """Restore a verified bundle to a new database path and migrate only its staged copy."""
    if not math.isfinite(timeout_seconds) or not (0 < timeout_seconds <= 3600):
        raise RecoveryInputError("Restore time limit must be between 0 and 3600 seconds.")
    backup_directory = Path(backup_directory)
    destination = Path(destination_path)
    verification = verify_backup(backup_directory)
    if not verification.verified:
        raise RecoveryInputError("Backup is not fully verified; restore was not started.")
    if active_database_path is not None:
        active = Path(active_database_path)
        if destination.resolve(strict=False) == active.resolve(strict=False):
            raise RecoveryInputError("Restore destination aliases the active database path.")
        if active.exists() and _same_existing_file(active, destination):
            raise RecoveryInputError("Restore destination aliases the active database.")
    if destination.exists() or destination.is_symlink():
        raise RecoveryInputError("Restore destination already exists; restore requires a new path.")
    if _same_existing_file(backup_directory / DATABASE_FILENAME, destination):
        raise RecoveryInputError("Restore destination aliases the backup database.")
    for suffix in ("-wal", "-shm"):
        if Path(f"{destination}{suffix}").exists() or Path(f"{destination}{suffix}").is_symlink():
            raise RecoveryInputError("Restore destination has an existing SQLite sidecar.")
    if not destination.parent.exists():
        raise RecoveryInputError("Restore destination parent must exist.")
    destination = destination.parent.resolve(strict=True) / destination.name
    staging_dir: Path | None = None
    staging_database: Path | None = None
    try:
        staging_dir = Path(
            tempfile.mkdtemp(prefix=f".{destination.name}.restore-", dir=destination.parent)
        )
        _set_restrictive_permissions(staging_dir, directory=True)
        staging_database = staging_dir / DATABASE_FILENAME
        source = sqlite3.connect(_uri(backup_directory / DATABASE_FILENAME, "ro"), uri=True)
        target = sqlite3.connect(staging_database)
        try:
            _run_backup(source, target, cancel_event=cancel_event, timeout_seconds=timeout_seconds)
        finally:
            target.close()
            source.close()
        _set_restrictive_permissions(staging_database)
        original_revision = _revision_for_path(staging_database)
        structural, _, issues, unsupported = _verify_database(staging_database, immutable=True)
        if structural or unsupported or issues:
            raise RecoveryError("Staged restore failed verification.")
        repository = SQLiteRepository(staging_database)
        repository.close()
        resulting_revision = _revision_for_path(staging_database)
        structural, _, issues, unsupported = _verify_database(staging_database, immutable=True)
        if structural or unsupported or issues:
            raise RecoveryError("Migrated restore failed verification.")
        _set_restrictive_permissions(staging_database)
        try:
            os.link(staging_database, destination)
        except FileExistsError as exc:
            raise RecoveryInputError("Restore destination already exists.") from exc
        except OSError as exc:
            raise RecoveryError("Restored database could not be published safely.") from exc
        return RestoreResult(
            backup_id=verification.backup_id or "unknown",
            destination=destination,
            original_revision=original_revision,
            resulting_revision=resulting_revision,
        )
    except RecoveryError:
        raise
    except Exception as exc:
        raise RecoveryError("Restore failed; no completed destination was published.") from exc
    finally:
        if staging_dir is not None and staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)


def plan_retention(
    directory: Path | str,
    *,
    keep_last: int = 5,
    max_age_days: int = 90,
    now: datetime | None = None,
) -> RetentionPlan:
    """Preview managed backup retention. This function never deletes files."""
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise RecoveryInputError("Managed backup directory must be an existing real directory.")
    if keep_last < 1 or max_age_days < 1:
        raise RecoveryInputError("Retention requires keep_last and max_age_days to be at least 1.")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    cutoff = current.astimezone(UTC) - timedelta(days=max_age_days)
    candidates: list[tuple[Path, datetime, VerificationResult]] = []
    entries: list[RetentionEntry] = []
    for child in sorted(root.iterdir(), key=lambda item: item.name.casefold()):
        if child.is_symlink():
            entries.append(RetentionEntry(child.name, "skipped", "symlink is never followed"))
            continue
        if not child.is_dir() or not (child / MANIFEST_FILENAME).is_file():
            entries.append(RetentionEntry(child.name, "skipped", "not a manifest-managed bundle"))
            continue
        try:
            manifest = _manifest(child)
            result = verify_backup(child)
            created_raw = manifest.get("created_at")
            created = datetime.fromisoformat(str(created_raw).replace("Z", "+00:00"))
            if created.tzinfo is None:
                raise ValueError
        except (RecoveryError, ValueError, TypeError):
            entries.append(RetentionEntry(child.name, "skipped", "manifest or bundle is invalid"))
            continue
        if not result.verified:
            entries.append(
                RetentionEntry(child.name, "skipped", "backup verification did not pass")
            )
            continue
        candidates.append((child, created.astimezone(UTC), result))
    candidates.sort(key=lambda item: (item[1], item[0].name.casefold()), reverse=True)
    retained_ids: set[str] = set()
    for index, (child, created, result) in enumerate(candidates):
        young_enough = created >= cutoff
        within_count = index < keep_last
        if young_enough and within_count:
            retained_ids.add(result.backup_id or child.name)
            entries.append(RetentionEntry(child.name, "retained", "within age and count rules"))
        else:
            entries.append(RetentionEntry(child.name, "remove", "outside age or count rules"))
    if candidates and not retained_ids:
        newest, _, result = candidates[0]
        entries = [
            RetentionEntry(entry.name, "retained", "kept as the newest verified backup")
            if entry.name == newest.name
            else entry
            for entry in entries
        ]
    entries.sort(key=lambda item: item.name.casefold())
    return RetentionPlan(root.resolve(strict=True), keep_last, max_age_days, tuple(entries))
