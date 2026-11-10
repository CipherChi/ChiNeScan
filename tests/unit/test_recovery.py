"""Offline backup, restore, verification, and retention regressions."""

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.cases import CaseWorkflow
from chinescan.core.models.investigation import (
    Case,
    CaseActivity,
    CaseNote,
    CaseRecordLink,
    CaseStatus,
    Target,
)
from chinescan.core.reporting import render_case_report
from chinescan.core.storage import recovery as recovery_module
from chinescan.core.storage.recovery import (
    RecoveryError,
    RecoveryInputError,
    backup_database,
    plan_retention,
    restore_backup,
    verify_backup,
)
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.log_analysis.service import LogAnalysisService

runner = CliRunner()
FIXTURE_ROOT = Path(__file__).parents[2] / "fixtures" / "sample-logs"


def _source(path: Path) -> None:
    repo = SQLiteRepository(path)
    target = Target(value="fixture-host", kind="local")
    repo.save("target", "target-fixture", target.model_dump(mode="json"))
    repo.close()


def _manifest(path: Path) -> dict[str, object]:
    return json.loads((path / "manifest.json").read_text(encoding="utf-8"))


def _write_manifest(path: Path, value: dict[str, object]) -> None:
    (path / "manifest.json").write_text(
        json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def test_backup_verify_and_restore_preserve_a_complete_case_recovery_drill(tmp_path: Path) -> None:
    source = tmp_path / "working.sqlite3"
    repository = SQLiteRepository(source)
    log_result = LogAnalysisService(repository).analyze(FIXTURE_ROOT)
    workflow = CaseWorkflow(repository)
    case, warnings = workflow.create_from_scan(log_result.scan_id, title="Recovery drill")
    assert not warnings
    workflow.add_note(case.case_id, "Retain this local analyst note.", "Recovery analyst")
    workflow.update_status(case.case_id, CaseStatus.IN_PROGRESS)
    workflow.update_status(case.case_id, CaseStatus.RESOLVED)
    original = workflow.get_case(case.case_id)
    repository.close()

    bundle = tmp_path / "backup-one"
    source_before = hashlib.sha256(source.read_bytes()).hexdigest()
    backup = backup_database(source, bundle)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_before
    assert backup.verification.verified
    manifest = _manifest(bundle)
    assert set(manifest) == {
        "format_version",
        "backup_id",
        "created_at",
        "chinescan_version",
        "migration_revision",
        "database",
        "verification",
    }
    assert "path" not in json.dumps(manifest).lower()
    verified = verify_backup(bundle)
    assert verified.verified and verified.migration_revision == "0004_dashboard_alerts"

    restored_path = tmp_path / "restored.sqlite3"
    restored = restore_backup(bundle, restored_path, active_database_path=source)
    assert restored.original_revision == restored.resulting_revision == "0004_dashboard_alerts"
    restored_repository = SQLiteRepository(restored_path)
    try:
        recovered = CaseWorkflow(restored_repository).get_case(original.case_id)
        assert recovered.case_id == original.case_id
        assert recovered.status == CaseStatus.RESOLVED
        assert recovered.scan_ids == original.scan_ids
        assert recovered.links == original.links
        assert recovered.notes == original.notes
        assert recovered.activities == original.activities
        for report_format in ("json", "markdown", "html"):
            report = render_case_report(restored_repository, recovered.case_id, report_format)
            assert "Recovery drill" in report
            assert "Retain this local analyst note" in report
    finally:
        restored_repository.close()
    assert bundle.is_dir() and verify_backup(bundle).verified


def test_backup_includes_committed_wal_data_and_never_creates_missing_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "wal.sqlite3"
    _source(source)
    connection = sqlite3.connect(source)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
        connection.execute(
            "INSERT INTO records VALUES ('target', 'wal-target', ?)",
            (json.dumps({"value": "committed-in-wal", "kind": "local"}),),
        )
        connection.commit()
        bundle = tmp_path / "wal-backup"
        result = backup_database(source, bundle)
        assert result.verification.verified
        restored = tmp_path / "wal-restored.sqlite3"
        restore_backup(bundle, restored)
        reopened = sqlite3.connect(f"file:{restored.as_posix()}?mode=ro", uri=True)
        try:
            row = reopened.execute(
                "SELECT payload FROM records WHERE record_id='wal-target'"
            ).fetchone()
            assert json.loads(row[0])["value"] == "committed-in-wal"
        finally:
            reopened.close()
    finally:
        connection.close()

    missing = tmp_path / "missing.sqlite3"
    with pytest.raises(RecoveryInputError, match="does not exist"):
        backup_database(missing, tmp_path / "missing-backup")
    assert not missing.exists()


def test_backup_refuses_existing_destination_and_cleans_cancelled_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.sqlite3"
    _source(source)
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(RecoveryInputError, match="already exists"):
        backup_database(source, existing)

    import threading

    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(RecoveryError, match="cancelled"):
        backup_database(source, tmp_path / "cancelled", cancel_event=cancelled)
    assert not (tmp_path / "cancelled").exists()
    assert not list(tmp_path.glob(".cancelled.staging-*"))
    with pytest.raises(RecoveryInputError, match="time limit"):
        backup_database(source, tmp_path / "bad-timeout", timeout_seconds=0)
    ticks = iter((0.0, 2.0))
    monkeypatch.setattr(recovery_module.time, "monotonic", lambda: next(ticks))
    with pytest.raises(RecoveryError, match="time limit"):
        backup_database(source, tmp_path / "timed-out", timeout_seconds=1)
    assert not list(tmp_path.glob(".timed-out.staging-*"))


def test_verification_separates_checksum_corruption_and_unsupported_schema(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite3"
    _source(source)
    truncated_bundle = tmp_path / "truncated"
    backup_database(source, truncated_bundle)
    database = truncated_bundle / "database.sqlite3"
    database.write_bytes(database.read_bytes()[:64])
    result = verify_backup(truncated_bundle)
    assert not result.verified
    assert "checksum_mismatch" in result.structural_errors

    corrupt_bundle = tmp_path / "corrupt"
    backup_database(source, corrupt_bundle)
    database = corrupt_bundle / "database.sqlite3"
    content = bytearray(database.read_bytes())
    content[0] ^= 0xFF
    database.write_bytes(content)
    result = verify_backup(corrupt_bundle)
    assert not result.verified
    assert "checksum_mismatch" in result.structural_errors
    assert "sqlite_verification_failed" in result.structural_errors

    checksum_bundle = tmp_path / "checksum-mismatch"
    backup_database(source, checksum_bundle)
    manifest = _manifest(checksum_bundle)
    database_metadata = manifest["database"]
    assert isinstance(database_metadata, dict)
    database_metadata["sha256"] = "0" * 64
    _write_manifest(checksum_bundle, manifest)
    result = verify_backup(checksum_bundle)
    assert not result.verified
    assert "checksum_mismatch" in result.structural_errors
    assert "sqlite_verification_failed" not in result.structural_errors

    unsupported_bundle = tmp_path / "unsupported"
    backup_database(source, unsupported_bundle)
    database = unsupported_bundle / "database.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute("UPDATE alembic_version SET version_num='9999_unknown'")
        connection.commit()
    finally:
        connection.close()
    manifest = _manifest(unsupported_bundle)
    database_metadata = manifest["database"]
    assert isinstance(database_metadata, dict)
    database_metadata["size_bytes"] = database.stat().st_size
    database_metadata["sha256"] = hashlib.sha256(database.read_bytes()).hexdigest()
    manifest["migration_revision"] = "9999_unknown"
    _write_manifest(unsupported_bundle, manifest)
    result = verify_backup(unsupported_bundle)
    assert result.unsupported_schema == "unsupported migration revision"
    with pytest.raises(RecoveryInputError, match="not fully verified"):
        restore_backup(unsupported_bundle, tmp_path / "not-restored.sqlite3")
    assert not (tmp_path / "not-restored.sqlite3").exists()


def test_cancelled_restore_and_stale_sidecars_leave_no_destination(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite3"
    _source(source)
    bundle = tmp_path / "bundle"
    backup_database(source, bundle)

    import threading

    cancelled = threading.Event()
    cancelled.set()
    destination = tmp_path / "cancelled-restore.sqlite3"
    with pytest.raises(RecoveryError, match="cancelled"):
        restore_backup(bundle, destination, cancel_event=cancelled)
    assert not destination.exists()
    assert not list(tmp_path.glob(".cancelled-restore.sqlite3.restore-*"))

    destination.with_name(destination.name + "-wal").write_bytes(b"unrelated sidecar")
    with pytest.raises(RecoveryInputError, match="sidecar"):
        restore_backup(bundle, destination)
    assert not destination.exists()


def test_verifier_reports_dangling_links_and_invalid_payloads_without_repair(
    tmp_path: Path,
) -> None:
    source = tmp_path / "inconsistent.sqlite3"
    repository = SQLiteRepository(source)
    case = Case(
        case_id="case-dangling",
        title="Dangling link",
        links=[
            CaseRecordLink(record_type="finding", record_id="missing", source="test"),
            CaseRecordLink(record_type="not-a-record", record_id="typed-wrong", source="test"),
        ],
    )
    repository.save("case", case.case_id, case.model_dump(mode="json"))
    repository.save("finding", "malformed", {"title": "missing required fields"})
    repository.save(
        "case_note",
        "orphan-note",
        CaseNote(case_id="missing-case", body="orphan").model_dump(mode="json"),
    )
    activity = CaseActivity(activity_type="created")
    repository.save(
        "case_activity",
        activity.activity_id,
        {**activity.model_dump(mode="json"), "case_id": "missing-case"},
    )
    repository.close()

    bundle = tmp_path / "inconsistent-backup"
    result = backup_database(source, bundle)
    assert not result.verification.verified
    assert "dangling_case_link" in result.verification.application_issues
    assert "invalid_case_link_type" in result.verification.application_issues
    assert "invalid_record_payload" in result.verification.application_issues
    assert "orphan_case_note" in result.verification.application_issues
    assert "orphan_case_activity" in result.verification.application_issues
    assert verify_backup(bundle).application_issues == result.verification.application_issues
    restored = SQLiteRepository(source)
    try:
        assert restored.get("case", "case-dangling")["links"][0]["record_id"] == "missing"
    finally:
        restored.close()


def test_restore_upgrades_only_the_copy_and_rejects_existing_or_active_destinations(
    tmp_path: Path,
) -> None:
    source = tmp_path / "legacy.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{source.as_posix()}")
    command.upgrade(config, "0001_initial")
    engine = sqlite3.connect(source)
    try:
        engine.execute(
            "INSERT INTO records(record_type,record_id,payload) VALUES(?,?,?)",
            (
                "case",
                "legacy-case",
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "case_id": "legacy-case",
                        "title": "Legacy retained",
                        "description": "",
                        "status": "open",
                        "created_at": "2025-01-01T00:00:00Z",
                        "updated_at": "2025-01-01T00:00:00Z",
                        "scan_ids": [],
                        "finding_ids": [],
                    }
                ),
            ),
        )
        engine.commit()
    finally:
        engine.close()
    bundle = tmp_path / "legacy-backup"
    assert backup_database(source, bundle).verification.verified

    destination = tmp_path / "restored-legacy.sqlite3"
    restored = restore_backup(bundle, destination, active_database_path=source)
    assert restored.original_revision == "0001_initial"
    assert restored.resulting_revision == "0004_dashboard_alerts"
    repo = SQLiteRepository(destination)
    try:
        assert repo.get("case", "legacy-case")["title"] == "Legacy retained"
    finally:
        repo.close()
    with pytest.raises(RecoveryInputError, match="already exists"):
        restore_backup(bundle, destination)
    with pytest.raises(RecoveryInputError, match="active database"):
        restore_backup(bundle, source, active_database_path=source)
    hard_link = tmp_path / "hard-link-to-active.sqlite3"
    os.link(source, hard_link)
    with pytest.raises(RecoveryInputError, match="active database"):
        restore_backup(bundle, hard_link, active_database_path=source)
    assert verify_backup(bundle).migration_revision == "0001_initial"


def test_unversioned_supported_schema_verifies_read_only_and_migrates_restored_copy(
    tmp_path: Path,
) -> None:
    source = tmp_path / "unversioned.sqlite3"
    connection = sqlite3.connect(source)
    try:
        connection.execute(
            "CREATE TABLE records (record_type VARCHAR(80) NOT NULL, "
            "record_id VARCHAR(255) NOT NULL, payload JSON NOT NULL, "
            "PRIMARY KEY (record_type, record_id))"
        )
        connection.execute(
            "INSERT INTO records VALUES ('target', 'unversioned-target', ?)",
            (json.dumps({"value": "retained", "kind": "local"}),),
        )
        connection.commit()
    finally:
        connection.close()
    bundle = tmp_path / "unversioned-backup"
    assert backup_database(source, bundle).verification.verified
    assert verify_backup(bundle).migration_revision is None
    original = sqlite3.connect(source)
    try:
        assert "alembic_version" not in {
            row[0] for row in original.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    finally:
        original.close()

    destination = tmp_path / "unversioned-restored.sqlite3"
    restored = restore_backup(bundle, destination)
    assert restored.original_revision is None
    assert restored.resulting_revision == "0004_dashboard_alerts"
    repository = SQLiteRepository(destination)
    try:
        assert repository.get("target", "unversioned-target")["value"] == "retained"
    finally:
        repository.close()


def test_retention_preview_uses_manifests_and_skips_unrelated_and_symlink_entries(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.sqlite3"
    _source(source)
    backups = [tmp_path / f"bundle-{index}" for index in range(3)]
    for bundle in backups:
        backup_database(source, bundle)
    now = datetime.now(UTC)
    for index, bundle in enumerate(backups):
        manifest = _manifest(bundle)
        manifest["created_at"] = (
            (now - timedelta(days=index * 40)).isoformat().replace("+00:00", "Z")
        )
        _write_manifest(bundle, manifest)
    (tmp_path / "arbitrary-export.html").write_text("not a backup", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    symlink = tmp_path / "linked-backup"
    try:
        symlink.symlink_to(outside, target_is_directory=True)
    except OSError:
        symlink = None

    plan = plan_retention(tmp_path, keep_last=1, max_age_days=90, now=now)
    assert all(path.exists() is not False for path in backups)
    assert sum(entry.disposition == "retained" for entry in plan.entries) == 1
    assert sum(entry.disposition == "remove" for entry in plan.entries) == 2
    assert (
        next(item for item in plan.entries if item.name == "arbitrary-export.html").disposition
        == "skipped"
    )
    if symlink is not None:
        assert (
            next(item for item in plan.entries if item.name == symlink.name).disposition
            == "skipped"
        )
    assert plan.as_dict()["preview_only"] is True


def test_retention_does_not_follow_symlink_to_an_outside_directory(tmp_path: Path) -> None:
    managed = tmp_path / "managed"
    managed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    symlink = managed / "outside-bundle"
    try:
        symlink.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    plan = plan_retention(managed)
    assert len(plan.entries) == 1
    assert plan.entries[0].name == "outside-bundle"
    assert plan.entries[0].disposition == "skipped"


def test_cli_database_commands_and_case_export_never_overwrite(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "active.sqlite3"
    repository = SQLiteRepository(source)
    case = Case(case_id="case-cli-recovery", title="CLI recovery")
    repository.save("case", case.case_id, case.model_dump(mode="json"))
    repository.close()
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(source))

    bundle = tmp_path / "cli-backup"
    created = runner.invoke(app, ["db", "backup", "--output", str(bundle)])
    assert created.exit_code == 0, created.output
    verified = runner.invoke(app, ["db", "verify-backup", str(bundle), "--format", "json"])
    assert verified.exit_code == 0 and json.loads(verified.stdout)["verified"]
    restored_path = tmp_path / "cli-restored.sqlite3"
    restored = runner.invoke(app, ["db", "restore", str(bundle), "--output", str(restored_path)])
    assert restored.exit_code == 0, restored.output
    plan = runner.invoke(
        app, ["db", "retention-plan", "--directory", str(tmp_path), "--format", "json"]
    )
    assert plan.exit_code == 0 and json.loads(plan.stdout)["preview_only"]

    first_report = tmp_path / "case.html"
    exported = runner.invoke(
        app,
        ["case", "export", case.case_id, "--format", "html", "--output", str(first_report)],
    )
    assert exported.exit_code == 0, exported.output
    original_content = first_report.read_text(encoding="utf-8")
    overwrite = runner.invoke(
        app,
        ["case", "export", case.case_id, "--format", "html", "--output", str(first_report)],
    )
    assert overwrite.exit_code == 2
    assert first_report.read_text(encoding="utf-8") == original_content
    assert not list(tmp_path.glob(".case.html.*.tmp"))


def test_cli_cutover_and_rollback_drill_uses_explicit_paths_and_preserves_divergence(
    tmp_path: Path,
) -> None:
    from scripts.recovery_acceptance import ROLLBACK_NOTE, run_drill

    result = run_drill(tmp_path / "offline-drill")
    original = Path(result["original_database"])
    restored = Path(result["restored_database"])
    assert "divergent" in result["rollback"]
    assert all(
        (tmp_path / "offline-drill" / name).is_file()
        for name in ("case-report.json", "case-report.md", "case-report.html")
    )

    case_id = result["case_id"]
    original_repository = SQLiteRepository(original)
    restored_repository = SQLiteRepository(restored)
    try:
        original_case = CaseWorkflow(original_repository).get_case(case_id)
        restored_case = CaseWorkflow(restored_repository).get_case(case_id)
        assert all(note.body != ROLLBACK_NOTE for note in original_case.notes)
        assert any(note.body == ROLLBACK_NOTE for note in restored_case.notes)
    finally:
        original_repository.close()
        restored_repository.close()


def test_drill_refuses_missing_database_before_cli_can_create_it(tmp_path: Path) -> None:
    from scripts.recovery_acceptance import _invoke

    missing = tmp_path / "never-created.sqlite3"
    with pytest.raises(RuntimeError, match="refusing CLI initialization"):
        _invoke(CliRunner(), missing, "case", "show", "case-missing")
    assert not missing.exists()


def test_failed_backup_verification_blocks_restore_and_preserves_original(tmp_path: Path) -> None:
    source = tmp_path / "original.sqlite3"
    _source(source)
    original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    bundle = tmp_path / "bundle"
    backup_database(source, bundle)
    database = bundle / "database.sqlite3"
    database.write_bytes(database.read_bytes() + b"tampered")

    result = runner.invoke(app, ["--database", str(source), "db", "verify-backup", str(bundle)])
    assert result.exit_code == 2
    destination = tmp_path / "must-not-cut-over.sqlite3"
    with pytest.raises(RecoveryInputError, match="not fully verified"):
        restore_backup(bundle, destination, active_database_path=source)
    assert not destination.exists()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original_hash


def test_case_export_publication_failure_cleans_temporary_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from chinescan.cli import commands

    source = tmp_path / "export-failure.sqlite3"
    repository = SQLiteRepository(source)
    case = Case(case_id="case-publish-failure", title="Publish failure")
    repository.save("case", case.case_id, case.model_dump(mode="json"))
    repository.close()
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(source))

    def fail_link(*args: object, **kwargs: object) -> None:
        raise OSError("controlled publication failure")

    monkeypatch.setattr(commands.os, "link", fail_link)
    destination = tmp_path / "failed-report.json"
    result = runner.invoke(
        app,
        ["case", "export", case.case_id, "--format", "json", "--output", str(destination)],
    )
    assert result.exit_code == 1
    assert "could not be published safely" in result.output
    assert not destination.exists()
    assert not list(tmp_path.glob(".failed-report.json.*.tmp"))
