from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from chinescan.cli.app import app as cli_app
from chinescan.core import diagnostics
from chinescan.core.accounts import Session
from chinescan.core.config.settings import Settings
from chinescan.core.diagnostics import (
    _npm_dependency_issues,
    build_report,
    health_report,
)
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.web import app as web_app_module
from chinescan.web.app import create_app
from chinescan.web.auth import create_operator


def _app_fixture(
    tmp_path: Path,
    *,
    credential_state: Literal["active", "corrupt", "missing"] = "active",
    reports_present: bool = True,
    managed_storage: bool = False,
    allowed_roots: list[Path] | None = None,
) -> tuple[FastAPI, Settings, Path, Path]:
    database = tmp_path / "data" / "records.sqlite3"
    credential = tmp_path / "private" / "operator.json"
    credential.parent.mkdir(parents=True, exist_ok=True)
    if credential_state == "active":
        create_operator(credential, "analyst@example.test", "safe local password")
    elif credential_state == "corrupt":
        credential.write_text("{", encoding="utf-8")
    reports = tmp_path / "reports"
    if reports_present:
        reports.mkdir(parents=True, exist_ok=True)
    managed = tmp_path / "managed-malware" if managed_storage else None
    if managed is not None:
        managed.mkdir(parents=True, exist_ok=True)
    settings = Settings(
        _env_file=None,
        database_path=database,
        reports_dir=reports,
        malware_managed_directory=managed,
        allowed_roots=allowed_roots or [],
    )
    application = create_app(
        database,
        credential,
        projects_path=tmp_path / "projects.toml",
        log_sources_path=tmp_path / "logs.toml",
        malware_registry_path=tmp_path / "malware.toml",
        settings=settings,
        serve_frontend=False,
    )
    return application, settings, database, credential


def _override_session(application: FastAPI, path: str) -> None:
    route = next(
        item for item in application.routes if isinstance(item, APIRoute) and item.path == path
    )
    dependency = next(item.call for item in route.dependant.dependencies)
    application.dependency_overrides[dependency] = lambda: Session(
        email="test@example.test",
        csrf_token="test-csrf-token",
        expires_at=1_000_000_000_000.0,
        auth_epoch="fixture-auth-epoch",
    )


def _check_fixture(state: Literal["PASS", "WARN", "FAIL"]) -> dict[str, str]:
    return {
        "id": "fixture-check",
        "label": "Fixture check",
        "state": state,
        "detail": "Fixture detail.",
        "action_hint": "Fixture action.",
    }


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for file in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(file.relative_to(root).as_posix().encode("utf-8"))
        digest.update(file.read_bytes())
    return digest.hexdigest()


def _port_is_free(
    address: tuple[str, int],
    timeout: float | None = None,
    *args: object,
    **kwargs: object,
) -> None:
    assert address[0] == "127.0.0.1"
    assert timeout is None or timeout > 0
    assert not args
    assert not kwargs
    raise OSError("fixture port is free")


def test_report_is_path_free_and_checks_database_read_only(tmp_path: Path) -> None:
    database = tmp_path / "private" / "records.sqlite3"
    repository = SQLiteRepository(database)
    repository.save("project", "project-one", {"status": "active"})
    repository.close()
    settings = Settings(
        _env_file=None,
        database_path=database,
        reports_dir=tmp_path / "reports",
    )
    settings.reports_dir.mkdir(parents=True)
    before = database.read_bytes()
    secret = "api_key_" + ("q7" * 16)

    report = build_report(
        settings=settings,
        database_path=database,
        credential_path=tmp_path / "operator.json",
        config_path=tmp_path / "config.toml",
        frontend_dist=tmp_path / "missing-frontend",
        errors=[
            {
                "error_code": secret,
                "route": str(tmp_path / secret),
                "request_id": secret,
                "timestamp": secret,
                "message": secret,
            }
        ],
    )

    encoded = json.dumps(report)
    assert str(tmp_path) not in encoded
    assert secret not in encoded
    assert report["recent_errors"][0]["message"] == "Request was rejected."
    assert report["counts"]["project"] == {"active": 1}
    assert report["storage_status"] == "available"
    assert database.read_bytes() == before
    assert all(
        set(check) == {"id", "label", "state", "detail", "action_hint"}
        for check in report["checks"]
    )


def test_health_report_is_minimal_and_path_free() -> None:
    report = health_report(started_at=0, bind_address="127.0.0.1")

    assert set(report) == {
        "status",
        "app_name",
        "version",
        "uptime_seconds",
        "bind_address",
        "timestamp",
    }


def _write_frontend_install(tmp_path: Path, *, marker: bool = True) -> tuple[Path, Path]:
    package_lock = tmp_path / "package-lock.json"
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    expected = {"lockfileVersion": 3, "packages": {"node_modules/react": {"version": "19.3.1"}}}
    package_lock.write_text(json.dumps(expected), encoding="utf-8")
    react = node_modules / "react"
    react.mkdir()
    (react / "package.json").write_text(
        json.dumps({"name": "react", "version": "19.3.1"}), encoding="utf-8"
    )
    if marker:
        (node_modules / ".package-lock.json").write_text(json.dumps(expected), encoding="utf-8")
    return package_lock, node_modules


def test_frontend_dependency_check_matching_install_passes(tmp_path: Path) -> None:
    package_lock, node_modules = _write_frontend_install(tmp_path)
    assert _npm_dependency_issues(package_lock, node_modules) == []


def test_frontend_dependency_check_missing_package_warns_with_count(tmp_path: Path) -> None:
    package_lock, node_modules = _write_frontend_install(tmp_path)
    (node_modules / "react" / "package.json").unlink()
    issues = _npm_dependency_issues(package_lock, node_modules)
    assert issues == ["react"]
    assert "1 missing or mismatched packages" in diagnostics._frontend_dependency_detail(issues)


def test_frontend_dependency_check_version_mismatch_warns(tmp_path: Path) -> None:
    package_lock, node_modules = _write_frontend_install(tmp_path)
    (node_modules / "react" / "package.json").write_text(
        json.dumps({"name": "react", "version": "19.0.0"}), encoding="utf-8"
    )
    assert _npm_dependency_issues(package_lock, node_modules) == ["react"]


def test_frontend_dependency_check_missing_node_modules_warns(tmp_path: Path) -> None:
    package_lock = tmp_path / "package-lock.json"
    package_lock.write_text(json.dumps({"packages": {}}), encoding="utf-8")
    assert _npm_dependency_issues(package_lock, tmp_path / "node_modules") is None


def test_frontend_dependency_check_missing_lockfile_warns(tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    assert _npm_dependency_issues(tmp_path / "package-lock.json", node_modules) is None


def test_frontend_dependency_check_does_not_require_npm_marker(tmp_path: Path) -> None:
    package_lock, node_modules = _write_frontend_install(tmp_path, marker=False)
    assert _npm_dependency_issues(package_lock, node_modules) == []


def test_diagnostics_routes_are_loopback_guarded_and_authenticated(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "data" / "records.sqlite3"
    credential = tmp_path / "private" / "operator.json"
    create_operator(credential, "analyst@example.test", "safe local password")
    settings = Settings(
        _env_file=None,
        database_path=database,
        reports_dir=tmp_path / "reports",
    )
    settings.reports_dir.mkdir(parents=True)
    frontend_dist = tmp_path / "frontend-dist"
    frontend_dist.mkdir()
    monkeypatch.setattr(web_app_module, "FRONTEND_DIST", frontend_dist)
    application = create_app(
        database,
        credential,
        projects_path=tmp_path / "projects.toml",
        log_sources_path=tmp_path / "logs.toml",
        malware_registry_path=tmp_path / "malware.toml",
        settings=settings,
        serve_frontend=False,
    )

    with TestClient(
        application,
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 49321),
    ) as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert set(health.json()) == {
            "status",
            "app_name",
            "version",
            "uptime_seconds",
            "bind_address",
            "timestamp",
        }
        assert client.get("/api/ready").status_code == 401
        assert client.get("/api/diagnostics").status_code == 401
        login = client.post(
            "/api/auth/login",
            json={"email": "analyst@example.test", "password": "safe local password"},
            headers={"Origin": str(client.base_url).rstrip("/")},
        )
        assert login.status_code == 200

        readiness = client.get("/api/ready")
        diagnostics = client.get("/api/diagnostics")

    assert readiness.status_code == 200
    assert all(
        set(check) == {"id", "label", "state", "detail", "action_hint"}
        for check in readiness.json()["checks"]
    )
    diagnostic_json = json.dumps(diagnostics.json())
    assert diagnostics.status_code == 200
    assert str(tmp_path) not in diagnostic_json
    assert diagnostics.json()["operator_state"] == "active"


def test_ready_healthy_returns_all_pass_and_diagnostics_matches_cli(
    tmp_path: Path, monkeypatch
) -> None:
    project_root = tmp_path / "approved"
    project_root.mkdir()
    application, settings, database, credential = _app_fixture(
        tmp_path,
        managed_storage=True,
        allowed_roots=[project_root],
    )
    frontend_dist = tmp_path / "frontend-dist"
    frontend_dist.mkdir()
    monkeypatch.setattr(web_app_module, "FRONTEND_DIST", frontend_dist)
    monkeypatch.setattr(diagnostics, "_FRONTEND_DIST", frontend_dist)
    monkeypatch.setattr(diagnostics.socket, "create_connection", _port_is_free)
    monkeypatch.setattr(diagnostics, "_tool_version", lambda *_args: "fixture-version")
    monkeypatch.setattr(diagnostics, "_npm_dependency_issues", lambda *_args: [])
    _override_session(application, "/api/ready")
    _override_session(application, "/api/diagnostics")
    config = tmp_path / "config.toml"
    config_values = (
        "database_path = "
        + json.dumps(str(database))
        + "\nreports_dir = "
        + json.dumps(str(settings.reports_dir))
        + "\nallowed_roots = ["
        + json.dumps(str(project_root))
        + "]\n"
    )
    if settings.malware_managed_directory is not None:
        config_values += (
            "malware_managed_directory = "
            + json.dumps(str(settings.malware_managed_directory))
            + "\n"
        )
    config.write_text(config_values, encoding="utf-8")
    credentials_at_default = config.parent / "operator.json"
    credentials_at_default.parent.mkdir(parents=True, exist_ok=True)
    credentials_at_default.write_bytes(credential.read_bytes())

    with TestClient(
        application, base_url="http://127.0.0.1", client=("127.0.0.1", 49322)
    ) as client:
        ready_response = client.get("/api/ready")
        diagnostics_response = client.get("/api/diagnostics")
    cli_response = CliRunner().invoke(
        cli_app,
        [
            "--config",
            str(config),
            "--database",
            str(database),
            "--reports-dir",
            str(settings.reports_dir),
            "doctor",
            "--json",
        ],
    )

    assert ready_response.status_code == 200
    assert ready_response.json()["state"] == "ok"
    assert {item["state"] for item in ready_response.json()["checks"]} == {"PASS"}
    assert diagnostics_response.status_code == 200
    assert cli_response.exit_code == 0, cli_response.stdout + cli_response.stderr
    api_checks = {item["id"]: item["state"] for item in diagnostics_response.json()["checks"]}
    cli_checks = {item["id"]: item["state"] for item in json.loads(cli_response.stdout)["checks"]}
    assert api_checks == cli_checks


def test_doctor_warns_when_enabled_github_import_path_budget_is_at_risk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(
        _env_file=None,
        database_path=tmp_path / "records.sqlite3",
        github_import_enabled=True,
    )
    monkeypatch.setattr(diagnostics, "import_path_at_risk", lambda _root: True)
    report = build_report(
        settings=settings,
        database_path=settings.database_path,
        config_path=tmp_path / "config.toml",
        credential_path=tmp_path / "operator.json",
        frontend_dist=tmp_path / "frontend-dist",
    )
    github_check = next(item for item in report["checks"] if item["id"] == "github-import")
    assert github_check["state"] == "WARN"
    assert report["github_import_path_budget"] == "at-risk"
    assert "shorter data directory" in github_check["action_hint"]
    assert str(tmp_path) not in json.dumps(report)


def test_chain_trace_diagnostics_report_only_key_presence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics.socket, "create_connection", _port_is_free)
    monkeypatch.setattr(diagnostics, "_tool_version", lambda *_args: "fixture-version")
    monkeypatch.setattr(diagnostics, "_npm_dependency_issues", lambda *_args: [])
    monkeypatch.delenv("CHINESCAN_ETHERSCAN_KEY", raising=False)
    settings = Settings(
        _env_file=None,
        database_path=tmp_path / "records.sqlite3",
        chain_network_enabled=False,
    )
    offline = build_report(
        settings=settings,
        credential_path=tmp_path / "operator.json",
        frontend_dist=tmp_path / "frontend-dist",
    )
    offline_check = next(item for item in offline["checks"] if item["id"] == "chain-trace")
    assert offline["chain_network_enabled"] is False
    assert offline["chain_provider_key_configured"] is False
    assert offline_check["state"] == "PASS"
    assert offline_check["detail"] == "enabled=false; provider_key_configured=false"
    monkeypatch.setenv("CHINESCAN_ETHERSCAN_KEY", "DIAGNOSTIC_KEY_CANARY")
    enabled = build_report(
        settings=settings.model_copy(update={"chain_network_enabled": True}),
        credential_path=tmp_path / "operator.json",
        frontend_dist=tmp_path / "frontend-dist",
    )
    enabled_check = next(item for item in enabled["checks"] if item["id"] == "chain-trace")
    assert enabled["chain_network_enabled"] is True
    assert enabled["chain_provider_key_configured"] is True
    assert enabled_check["state"] == "PASS"
    assert "DIAGNOSTIC_KEY_CANARY" not in json.dumps(enabled)
    monkeypatch.delenv("CHINESCAN_ETHERSCAN_KEY")
    warning = build_report(
        settings=settings.model_copy(update={"chain_network_enabled": True}),
        credential_path=tmp_path / "operator.json",
        frontend_dist=tmp_path / "frontend-dist",
    )
    warning_check = next(item for item in warning["checks"] if item["id"] == "chain-trace")
    assert warning_check["state"] == "WARN"


def test_ready_degraded_for_invalid_allowed_root_and_missing_optional_storage(
    tmp_path: Path, monkeypatch
) -> None:
    missing_root = tmp_path / "configured-but-missing"
    application, _settings, _database, _credential = _app_fixture(
        tmp_path, allowed_roots=[missing_root]
    )
    frontend_dist = tmp_path / "frontend-dist"
    frontend_dist.mkdir()
    monkeypatch.setattr(web_app_module, "FRONTEND_DIST", frontend_dist)
    _override_session(application, "/api/ready")

    with TestClient(
        application, base_url="http://127.0.0.1", client=("127.0.0.1", 49323)
    ) as client:
        response = client.get("/api/ready")

    assert response.status_code == 200
    assert response.json()["state"] == "degraded"
    checks = {item["id"]: item for item in response.json()["checks"]}
    assert checks["filesystem-policy"]["state"] == "WARN"
    assert checks["managed-malware"]["state"] == "WARN"
    assert response.json()["allowed_roots"] == {
        "valid": 0,
        "ignored": 1,
        "reason_codes": {"unavailable": 1},
    }


def test_ready_fails_for_corrupt_credentials_unwritable_database_missing_dirs_and_frontend(
    tmp_path: Path, monkeypatch
) -> None:
    corrupt_app, _settings, _database, _credential = _app_fixture(
        tmp_path / "corrupt", credential_state="corrupt"
    )
    _override_session(corrupt_app, "/api/ready")
    with TestClient(
        corrupt_app, base_url="http://127.0.0.1", client=("127.0.0.1", 49324)
    ) as client:
        corrupt_response = client.get("/api/ready")
    assert corrupt_response.status_code == 503
    corrupt_checks = {item["id"]: item["state"] for item in corrupt_response.json()["checks"]}
    assert corrupt_checks["credentials"] == "FAIL"

    missing_directories, _settings, _database, _credential = _app_fixture(
        tmp_path / "missing-dirs", reports_present=False
    )
    _override_session(missing_directories, "/api/ready")
    with TestClient(
        missing_directories, base_url="http://127.0.0.1", client=("127.0.0.1", 49325)
    ) as client:
        directory_response = client.get("/api/ready")
    assert directory_response.status_code == 503
    assert any(
        check["id"] == "directories" and check["state"] == "FAIL"
        for check in directory_response.json()["checks"]
    )

    monkeypatch.setattr(web_app_module, "FRONTEND_DIST", tmp_path / "no-frontend-build")
    missing_frontend, _settings, _database, _credential = _app_fixture(tmp_path / "no-frontend")
    _override_session(missing_frontend, "/api/ready")
    with TestClient(
        missing_frontend, base_url="http://127.0.0.1", client=("127.0.0.1", 49326)
    ) as client:
        frontend_response = client.get("/api/ready")
    assert frontend_response.status_code == 503
    assert any(
        check["id"] == "frontend" and check["state"] == "FAIL"
        for check in frontend_response.json()["checks"]
    )

    writable, _settings, _database, _credential = _app_fixture(tmp_path / "unwritable")
    _override_session(writable, "/api/ready")
    monkeypatch.setattr(diagnostics.os, "access", lambda _path, _mode: False)
    with TestClient(writable, base_url="http://127.0.0.1", client=("127.0.0.1", 49327)) as client:
        database_response = client.get("/api/ready")
    assert database_response.status_code == 503
    assert any(
        check["id"] == "database" and check["state"] == "FAIL"
        for check in database_response.json()["checks"]
    )


def test_diagnostics_error_ring_is_bounded_and_excludes_request_data(tmp_path: Path) -> None:
    application, _settings, _database, _credential = _app_fixture(tmp_path)
    _override_session(application, "/api/diagnostics")
    canary = "auth_token_" + ("r4" * 18)

    with TestClient(
        application, base_url="http://127.0.0.1", client=("127.0.0.1", 49328)
    ) as client:
        for index in range(60):
            client.get(f"/api/not-a-route?token={canary}&request={index}")
        client.post(
            "/api/auth/login",
            headers={"Origin": str(client.base_url).rstrip("/")},
            json={"email": canary, "password": canary},
        )
        response = client.get("/api/diagnostics")

    errors = response.json()["recent_errors"]
    assert response.status_code == 200
    assert len(errors) == 50
    assert canary not in json.dumps(errors)
    assert all(
        set(error) == {"error_code", "route", "request_id", "timestamp", "message"}
        for error in errors
    )
    assert all(
        error["route"] == "unmatched" or error["route"].startswith("/api/") for error in errors
    )


def test_diagnostics_rate_limit_host_and_origin_guards(tmp_path: Path, monkeypatch) -> None:
    application, _settings, _database, _credential = _app_fixture(tmp_path)
    _override_session(application, "/api/diagnostics")
    monkeypatch.setattr(
        "chinescan.web.app.build_report",
        lambda **_kwargs: {"status": "ok", "checks": []},
    )

    with TestClient(
        application, base_url="http://127.0.0.1", client=("127.0.0.1", 49329)
    ) as client:
        assert client.get("/api/health", headers={"Host": "outside.invalid"}).status_code == 400
        assert client.post("/api/auth/logout").status_code == 403
        responses = [client.get("/api/diagnostics") for _ in range(13)]

    assert [response.status_code for response in responses[:12]] == [200] * 12
    assert responses[-1].status_code == 429


@pytest.mark.parametrize(
    ("state", "exit_code"),
    [("PASS", 0), ("WARN", 1), ("FAIL", 2)],
)
def test_doctor_exit_codes_json_shape_and_no_color(
    state: Literal["PASS", "WARN", "FAIL"], exit_code: int, monkeypatch
) -> None:
    report = {
        "status": "ok" if exit_code == 0 else "degraded" if exit_code == 1 else "failed",
        "checks": [_check_fixture(state)],
    }
    monkeypatch.setattr(diagnostics, "build_report", lambda **_kwargs: report)
    environment = {"NO_COLOR": "1"}

    doctor = CliRunner().invoke(cli_app, ["doctor", "--json"], env=environment)
    status = CliRunner().invoke(cli_app, ["status", "--json"], env=environment)

    assert doctor.exit_code == exit_code
    assert "\x1b[" not in doctor.stdout
    assert set(json.loads(doctor.stdout)) == set(report)
    assert status.exit_code == exit_code
    assert set(json.loads(status.stdout)) == {"status", "checks"}


def test_doctor_local_probes_and_python_environment_mocks(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "db" / "records.sqlite3"
    repository = SQLiteRepository(database)
    repository.close()
    reports = tmp_path / "reports"
    reports.mkdir()
    settings = Settings(_env_file=None, database_path=database, reports_dir=reports)

    def tool_version(command: str, _argument: str) -> str:
        return "" if command in {"node", "npm"} else "v1"

    monkeypatch.setattr(diagnostics, "_tool_version", tool_version)
    monkeypatch.setattr(diagnostics, "_npm_dependency_issues", lambda *_args: None)
    connection_calls: list[tuple[str, int]] = []

    class LocalListener:
        def __enter__(self) -> LocalListener:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def loopback_only(address: tuple[str, int], timeout: float) -> LocalListener:
        assert address[0] == "127.0.0.1"
        connection_calls.append(address)
        if address[1] == 5173:
            return LocalListener()
        raise OSError("fixture port is free")

    monkeypatch.setattr(diagnostics.socket, "create_connection", loopback_only)
    monkeypatch.setenv("UV_PROJECT_ENVIRONMENT", str(tmp_path / "external-env"))

    report = build_report(
        settings=settings,
        database_path=database,
        credential_path=tmp_path / "operator.json",
        frontend_dist=tmp_path / "missing-build",
    )
    checks = {item["id"]: item for item in report["checks"]}

    assert checks["node-npm"]["state"] == "WARN"
    assert checks["frontend-dependencies"]["state"] == "WARN"
    assert checks["port-5173"]["state"] == "WARN"
    assert checks["port-8765"]["state"] == "PASS"
    assert checks["python-environment"]["state"] == "FAIL"
    assert connection_calls == [("127.0.0.1", 5173), ("127.0.0.1", 8765)]
    repository_root = Path(diagnostics.__file__).resolve().parents[2]
    monkeypatch.setenv(
        "UV_PROJECT_ENVIRONMENT", str(repository_root / ".diagnostics-missing-pyvenv")
    )
    broken_pyvenv = build_report(
        settings=settings,
        database_path=database,
        credential_path=tmp_path / "operator.json",
        frontend_dist=tmp_path / "missing-build",
    )
    assert (
        next(check for check in broken_pyvenv["checks"] if check["id"] == "python-environment")[
            "state"
        ]
        == "FAIL"
    )


def test_doctor_is_read_only_and_does_not_make_remote_socket_calls(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "db" / "records.sqlite3"
    repository = SQLiteRepository(database)
    repository.close()
    reports = tmp_path / "reports"
    reports.mkdir()
    credential = tmp_path / "operator.json"
    create_operator(credential, "analyst@example.test", "safe local password")
    config = tmp_path / "config.toml"
    config.write_text(
        "database_path = "
        + json.dumps(str(database))
        + "\nreports_dir = "
        + json.dumps(str(reports))
        + "\n",
        encoding="utf-8",
    )
    socket_calls: list[tuple[str, int]] = []

    def local_socket_guard(address: tuple[str, int], timeout: float) -> None:
        assert address[0] == "127.0.0.1", "doctor attempted a non-loopback socket call"
        socket_calls.append(address)
        raise OSError("fixture port is free")

    monkeypatch.setattr(diagnostics.socket, "create_connection", local_socket_guard)
    frontend_dist = tmp_path / "frontend-dist"
    frontend_dist.mkdir()
    monkeypatch.setattr(diagnostics, "_FRONTEND_DIST", frontend_dist)
    before = _tree_digest(tmp_path)
    result = CliRunner().invoke(
        cli_app,
        [
            "--config",
            str(config),
            "--database",
            str(database),
            "--reports-dir",
            str(reports),
            "doctor",
            "--json",
        ],
    )
    after = _tree_digest(tmp_path)

    assert result.exit_code == 1
    assert socket_calls == [("127.0.0.1", 5173), ("127.0.0.1", 8765)]
    assert before == after


def test_canary_does_not_appear_in_api_or_cli_outputs_or_errors(
    tmp_path: Path, monkeypatch
) -> None:
    canary = "runtime_secret_" + ("m8" * 18)
    application, settings, database, credential = _app_fixture(tmp_path, managed_storage=True)
    monkeypatch.setattr(diagnostics.socket, "create_connection", _port_is_free)
    settings.api_token = canary
    _override_session(application, "/api/ready")
    _override_session(application, "/api/diagnostics")
    config = tmp_path / "config.toml"
    config.write_text(
        "database_path = "
        + json.dumps(str(database))
        + "\nreports_dir = "
        + json.dumps(str(settings.reports_dir))
        + "\napi_token = "
        + json.dumps(canary)
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "operator.json").write_bytes(credential.read_bytes())

    with TestClient(
        application, base_url="http://127.0.0.1", client=("127.0.0.1", 49330)
    ) as client:
        health = client.get("/api/health")
        ready = client.get("/api/ready")
        diagnostic = client.get("/api/diagnostics")
        error = client.post(
            "/api/auth/login",
            headers={"Origin": str(client.base_url).rstrip("/")},
            json={"email": canary, "password": canary},
        )
    doctor = CliRunner().invoke(
        cli_app,
        ["--config", str(config), "--database", str(database), "doctor", "--json"],
    )
    status = CliRunner().invoke(
        cli_app,
        ["--config", str(config), "--database", str(database), "status"],
    )

    for body in (
        health.text,
        ready.text,
        diagnostic.text,
        error.text,
        doctor.stdout,
        status.stdout,
    ):
        assert canary not in body
        assert str(tmp_path) not in body
