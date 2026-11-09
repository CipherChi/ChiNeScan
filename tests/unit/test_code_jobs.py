from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.web.app import create_app
from chinescan.web.auth import create_operator
from chinescan.web.code_jobs import (
    CodeJobManager,
    ProjectConfigurationError,
    ProjectRegistry,
    _transition,
    safe_project_tree,
)


def _registry(tmp_path: Path, root: Path) -> tuple[Path, Path]:
    config = tmp_path / "projects.toml"
    config.write_text(
        f'[[projects]]\nid = "fixture"\nname = "Fixture project"\nroot = "{root.as_posix()}"\n',
        encoding="utf-8",
    )
    return config, root


def test_registry_hides_invalid_roots_and_protected_data(tmp_path: Path) -> None:
    protected = tmp_path / "private"
    protected.mkdir()
    config, _ = _registry(tmp_path, protected)
    registry = ProjectRegistry(config, [protected])
    assert registry.list() == []
    with pytest.raises(ProjectConfigurationError):
        registry.resolve("fixture")


def test_registry_excludes_operator_declared_backup_and_report_storage(tmp_path: Path) -> None:
    protected = tmp_path / "case-reports"
    protected.mkdir()
    config = tmp_path / "projects.toml"
    config.write_text(
        f'protected_paths = ["{protected.as_posix()}"]\n'
        f'[[projects]]\nid = "fixture"\nname = "Fixture"\nroot = "{protected.as_posix()}"\n',
        encoding="utf-8",
    )
    assert ProjectRegistry(config, []).list() == []


def test_registry_excludes_application_data_directory_automatically(tmp_path: Path) -> None:
    project = tmp_path / "data" / "project"
    project.mkdir(parents=True)
    config = tmp_path / "data" / "projects.toml"
    config.write_text(
        f'[[projects]]\nid = "fixture"\nname = "Fixture"\nroot = "{project.as_posix()}"\n',
        encoding="utf-8",
    )
    from chinescan.web.app import create_app

    credentials = tmp_path / "data" / "operator.json"
    create_operator(credentials, "analyst@example.test", "long-test-password")
    app = create_app(
        tmp_path / "data" / "records.sqlite3",
        credentials,
        serve_frontend=False,
        projects_path=config,
    )
    assert app.state.project_registry.list() == []
    app.state.repository.close()


def test_registry_rejects_missing_root_and_state_machine_rejects_invalid_transition(
    tmp_path: Path,
) -> None:
    config, _ = _registry(tmp_path, tmp_path / "missing")
    assert ProjectRegistry(config, []).list() == []
    job = {"status": "queued", "created_at": "now"}
    _transition(job, "running")
    assert job["started_at"]
    _transition(job, "failed")
    assert job["finished_at"]
    with pytest.raises(ValueError, match="Invalid code job state transition"):
        _transition(job, "succeeded")


def test_tree_fails_closed_for_internal_symlink(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.py").write_text("secret = 'not read'", encoding="utf-8")
    try:
        (root / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation is unavailable for this Windows account.")
    assert not safe_project_tree(root)


def test_authenticated_job_persists_scan_and_rejects_duplicate(tmp_path: Path, monkeypatch) -> None:
    import threading

    from chinescan.core.orchestration.code_scan import CodeScanService

    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    config, _ = _registry(tmp_path, fixture)
    database = tmp_path / "data" / "records.sqlite3"
    credential = tmp_path / "data" / "operator.json"
    create_operator(credential, "analyst@example.test", "long-test-password")
    app = create_app(database, credential, serve_frontend=False, projects_path=config)
    entered = threading.Event()
    release = threading.Event()
    original_scan = CodeScanService.scan

    def delayed_scan(service, target):
        entered.set()
        assert release.wait(5)
        return original_scan(service, target)

    monkeypatch.setattr(CodeScanService, "scan", delayed_scan)
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 1234)) as client:
        assert client.get("/api/code/projects").status_code == 401
        session = client.post(
            "/api/auth/login",
            json={"email": "analyst@example.test", "password": "long-test-password"},
            headers={"Origin": str(client.base_url).rstrip("/")},
        )
        csrf = session.json()["csrf_token"]
        headers = {"Origin": str(client.base_url).rstrip("/"), "X-CSRF-Token": csrf}
        assert (
            client.post(
                "/api/code/jobs",
                json={"project_id": "fixture"},
                headers={"Origin": headers["Origin"]},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/code/jobs", json={"project_id": "unknown"}, headers=headers
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/code/jobs",
                json={"project_id": "fixture", "path": str(fixture)},
                headers=headers,
            ).status_code
            == 422
        )
        response = client.post("/api/code/jobs", json={"project_id": "fixture"}, headers=headers)
        assert response.status_code == 202
        job_id = response.json()["job_id"]
        assert entered.wait(5)
        duplicate = client.post("/api/code/jobs", json={"project_id": "fixture"}, headers=headers)
        release.set()
        assert duplicate.status_code == 409
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            job = client.get(f"/api/code/jobs/{job_id}").json()
            if job["status"] in {"succeeded", "failed"}:
                break
            time.sleep(0.02)
        assert job["status"] == "succeeded"
        assert client.get(f"/api/scans/{job['scan_id']}").status_code == 200
        assert client.get("/api/findings?limit=20&offset=0").json()["total"] == 1
        assert (fixture / "app.py").read_text(encoding="utf-8") == "eval(user_input)\n"
    app.state.repository.close()


def test_queue_bound_and_restart_interruption(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    config, _ = _registry(tmp_path, fixture)
    repo = SQLiteRepository(tmp_path / "records.sqlite3")
    import threading

    manager = CodeJobManager(repo, threading.RLock(), ProjectRegistry(config, []), queue_limit=0)
    with pytest.raises(OverflowError):
        manager.submit("fixture")
    old = {"job_id": "unfinished", "status": "running", "created_at": "old", "started_at": "old"}
    repo.save("code_job", "unfinished", old)
    manager.start()
    assert manager.get("unfinished")["status"] == "interrupted"
    manager.stop()
    repo.close()


def test_completed_code_job_saves_reports(tmp_path: Path) -> None:
    import threading

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    config, _ = _registry(tmp_path, project)
    repository = SQLiteRepository(tmp_path / "reports.sqlite3")
    reports_dir = tmp_path / "reports"
    manager = CodeJobManager(
        repository,
        threading.RLock(),
        ProjectRegistry(config, []),
        reports_dir=reports_dir,
    )
    manager.start()
    submitted = manager.submit("fixture")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and manager.get(submitted["job_id"])["status"] in {
        "queued",
        "running",
    }:
        time.sleep(0.02)
    completed = manager.get(submitted["job_id"])
    assert completed["status"] == "succeeded"
    assert len(list(reports_dir.glob("*.json"))) == 1
    assert len(list(reports_dir.glob("*.md"))) == 1
    manager.stop()
    repository.close()


def test_report_store_failure_warns_without_failing_completed_job(tmp_path: Path) -> None:
    import threading

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    config, _ = _registry(tmp_path, project)
    repository = SQLiteRepository(tmp_path / "reports-error.sqlite3")
    reports_file = tmp_path / "not-a-directory"
    reports_file.write_text("fixture", encoding="utf-8")
    manager = CodeJobManager(
        repository,
        threading.RLock(),
        ProjectRegistry(config, []),
        reports_dir=reports_file / "child",
    )
    manager.start()
    submitted = manager.submit("fixture")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and manager.get(submitted["job_id"])["status"] in {
        "queued",
        "running",
    }:
        time.sleep(0.02)
    completed = manager.get(submitted["job_id"])
    assert completed["status"] == "succeeded"
    assert completed["warning"] == "Scan reports could not be saved."
    manager.stop()
    repository.close()


def test_scanner_and_persistence_failures_have_distinct_persisted_outcomes(
    tmp_path: Path, monkeypatch
) -> None:
    import threading

    from chinescan.core.orchestration.code_scan import BuiltinRuleScanner, ScannerError

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    config, _ = _registry(tmp_path, project)
    repository = SQLiteRepository(tmp_path / "records.sqlite3")
    manager = CodeJobManager(repository, threading.RLock(), ProjectRegistry(config, []))

    def broken_scanner(_scanner, _profile):
        raise ScannerError("synthetic scanner problem")

    monkeypatch.setattr(BuiltinRuleScanner, "scan_profile", broken_scanner)
    manager.start()
    scan_job = manager.submit("fixture")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and manager.get(scan_job["job_id"])["status"] in {
        "queued",
        "running",
    }:
        time.sleep(0.02)
    completed = manager.get(scan_job["job_id"])
    assert completed["status"] == "succeeded"
    assert repository.get("scan", completed["scan_id"])["status"] == "partial"

    from chinescan.core.storage.sqlite import SQLiteRepository as RepositoryClass

    original_save = RepositoryClass.save

    def fail_scan_save(self, record_type, record_id, payload):
        if record_type == "scan":
            raise RuntimeError("database failure details")
        return original_save(self, record_type, record_id, payload)

    monkeypatch.setattr(RepositoryClass, "save", fail_scan_save)
    failed = manager.submit("fixture")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and manager.get(failed["job_id"])["status"] in {
        "queued",
        "running",
    }:
        time.sleep(0.02)
    outcome = manager.get(failed["job_id"])
    assert outcome["status"] == "failed"
    assert outcome["scan_id"] is None
    assert outcome["error"] == "Assessment failed; details were withheld."
    manager.stop()
    repository.close()


def test_shutdown_waits_for_active_scan_and_persists_terminal_state(
    tmp_path: Path, monkeypatch
) -> None:
    import threading

    from chinescan.core.orchestration.code_scan import CodeScanService

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    config, _ = _registry(tmp_path, project)
    repository = SQLiteRepository(tmp_path / "records.sqlite3")
    manager = CodeJobManager(repository, threading.RLock(), ProjectRegistry(config, []))
    entered, release = threading.Event(), threading.Event()
    original_scan = CodeScanService.scan

    def held_scan(service, target):
        entered.set()
        assert release.wait(5)
        return original_scan(service, target)

    monkeypatch.setattr(CodeScanService, "scan", held_scan)
    manager.start()
    submitted = manager.submit("fixture")
    assert entered.wait(5)
    stopper = threading.Thread(target=manager.stop)
    stopper.start()
    assert stopper.is_alive()
    release.set()
    stopper.join(5)
    assert not stopper.is_alive()
    assert manager.get(submitted["job_id"])["status"] == "succeeded"
    repository.close()
