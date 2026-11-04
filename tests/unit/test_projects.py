from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import chinescan.core.fs_policy as fs_policy
from chinescan.core.accounts import create_operator
from chinescan.core.config.settings import Settings
from chinescan.core.models.common import Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Case, Scan
from chinescan.core.orchestration.code_scan import (
    BuiltinRuleScanner,
    ProjectProfile,
    ScanBounds,
    detect_project,
)
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.web.app import create_app


def _client(tmp_path: Path, roots: list[Path], *, hard_denied: list[Path] | None = None):
    private = tmp_path / "private"
    private.mkdir()
    db = private / "records.sqlite3"
    credentials = private / "operator.json"
    create_operator(credentials, "projects@example.test", "project-test-password-123")
    settings = Settings(
        _env_file=None,
        database_path=db,
        reports_dir=private / "reports",
        allowed_roots=roots,
        extra_denied_paths=hard_denied or [],
    )
    app = create_app(db, credentials, settings=settings, serve_frontend=False)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50131))
    response = client.post(
        "/api/auth/login",
        json={"email": "projects@example.test", "password": "project-test-password-123"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert response.status_code == 200
    return (
        app,
        client,
        {"Origin": "http://127.0.0.1", "X-CSRF-Token": response.json()["csrf_token"]},
    )


def _selection(client: TestClient) -> str:
    roots = client.get("/api/fs/roots?capability=project_directory")
    assert roots.status_code == 200
    return roots.json()["items"][0]["directory_id"]


def test_folder_picker_requires_auth_and_approval_creates_dashboard_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "selected web project"
    folder.mkdir()
    monkeypatch.setattr(fs_policy, "_local_filesystem_roots", lambda: [folder])
    _app, client, headers = _client(tmp_path, [])

    assert client.get("/api/fs/picker-roots").status_code == 200
    client.cookies.clear()
    assert client.get("/api/fs/picker-roots").status_code == 401
    unauthenticated_approval = client.post(
        "/api/projects/approve-folder",
        json={"directory_id": "x" * 40, "approved": True},
        headers=headers,
    )
    assert unauthenticated_approval.status_code == 401
    login = client.post(
        "/api/auth/login",
        json={"email": "projects@example.test", "password": "project-test-password-123"},
        headers={"Origin": "http://127.0.0.1"},
    )
    headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]}
    root = client.get("/api/fs/picker-roots").json()["items"][0]
    assert root["selectable"] is True
    preview = client.get("/api/fs/picker-preview", params={"directory_id": root["directory_id"]})
    assert preview.status_code == 200
    assert preview.json()["resolved_path"] == str(folder.resolve())

    rejected = client.post(
        "/api/projects/approve-folder",
        json={"directory_id": root["directory_id"], "approved": False},
        headers=headers,
    )
    assert rejected.status_code == 400
    body_path = client.post(
        "/api/projects/approve-folder",
        json={"path": str(folder), "approved": True},
        headers=headers,
    )
    assert body_path.status_code == 422

    approved = client.post(
        "/api/projects/approve-folder",
        json={"directory_id": root["directory_id"], "approved": True},
        headers=headers,
    )
    assert approved.status_code == 201
    assert approved.json()["configured_by"] == "dashboard"
    assert approved.json()["name"] == folder.name
    assert client.get("/api/code/projects").json() == [
        {"project_id": approved.json()["project_id"], "display_name": folder.name}
    ]
    detail = client.get(f"/api/projects/{approved.json()['project_id']}").json()
    removed = client.request(
        "DELETE",
        f"/api/projects/{approved.json()['project_id']}",
        json={"confirmation": folder.name},
        headers=headers,
    )
    assert removed.status_code == 200
    assert folder.is_dir()
    assert detail["configured_by"] == "dashboard"


def test_folder_picker_endpoints_enforce_loopback_host(tmp_path: Path) -> None:
    _app, client, _headers = _client(tmp_path, [])
    response = client.get("/api/fs/picker-roots", headers={"Host": "127.0.0.1.evil.test"})
    assert response.status_code == 400


def test_github_import_api_is_stably_disabled_by_default(tmp_path: Path) -> None:
    _app, client, headers = _client(tmp_path, [])
    preview = client.post(
        "/api/github/previews", json={"url": "https://github.com/a/b"}, headers=headers
    )
    assert preview.status_code == 403
    assert preview.json()["detail"]["code"] == "feature_disabled"
    imported = client.post(
        "/api/github/imports", json={"preview_id": "fixture", "name": "Fixture"}, headers=headers
    )
    assert imported.status_code == 403
    assert imported.json()["detail"]["code"] == "feature_disabled"
    status = client.get("/api/github/imports/fixture")
    assert status.status_code == 403
    assert status.json()["detail"]["code"] == "feature_disabled"


def test_project_log_locations_are_path_free_and_removal_keeps_files(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    logs = root / "logs"
    logs.mkdir(parents=True)
    candidate = logs / "auth.jsonl"
    candidate.write_text('{"event":"failed login"}\n', encoding="utf-8")
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    _app, client, headers = _client(tmp_path, [root])
    project_response = client.post(
        "/api/projects", json={"name": "Logs", "directory_id": _selection(client)}, headers=headers
    )
    project_id = project_response.json()["project_id"]
    initial = client.get(f"/api/projects/{project_id}/browse")
    assert initial.status_code == 200
    page = client.get(
        f"/api/projects/{project_id}/browse?directory_id={initial.json()['directory_id']}"
    )
    logs_id = next(item["directory_id"] for item in page.json()["items"] if item["name"] == "logs")
    added = client.post(
        f"/api/projects/{project_id}/log-locations",
        json={"name": "Application logs", "directory_id": logs_id},
        headers=headers,
    )
    assert added.status_code == 201
    assert str(root) not in added.text and str(logs) not in added.text
    assert (
        client.get(f"/api/projects/{project_id}").json()["log_locations"][0]["scope"] == "project"
    )
    suggestions = client.post(f"/api/projects/{project_id}/log-suggestions", headers=headers)
    assert suggestions.status_code == 200
    assert any(item["label"] == "logs" for item in suggestions.json()["items"])
    removed = client.request(
        "DELETE",
        f"/api/projects/{project_id}/log-locations/{added.json()['location_id']}",
        headers=headers,
        json={"confirmation": "Application logs"},
    )
    assert removed.status_code == 200
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() == digest


def test_project_logs_api_end_to_end(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    logs = root / "logs"
    logs.mkdir(parents=True)
    candidate = logs / "auth.log"
    candidate.write_text(
        "\n".join(
            f"Oct 25 10:{minute:02}:00 host sshd[{101 + minute - 0}]: Failed password "
            f"for alice from 203.0.113.5 port {40001 + minute} ssh2"
            for minute in range(5)
        )
        + "\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    app, _client_without_lifespan, _ = _client(tmp_path, [root])
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50132)) as client:
        login = client.post(
            "/api/auth/login",
            json={"email": "projects@example.test", "password": "project-test-password-123"},
            headers={"Origin": "http://127.0.0.1"},
        )
        headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]}
        root_id = client.get("/api/fs/roots?capability=project_directory").json()["items"][0][
            "directory_id"
        ]
        project = client.post(
            "/api/projects", json={"name": "Log fixture", "directory_id": root_id}, headers=headers
        ).json()
        project_id = project["project_id"]
        suggestion_page = client.post(
            f"/api/projects/{project_id}/log-suggestions", headers=headers
        ).json()
        logs_suggestion = next(item for item in suggestion_page["items"] if item["label"] == "logs")
        linked = client.post(
            f"/api/projects/{project_id}/log-suggestions/confirm",
            json={"suggestion_id": logs_suggestion["suggestion_id"], "name": "logs"},
            headers=headers,
        ).json()
        submitted = client.post(
            f"/api/projects/{project_id}/log-jobs",
            json={"location_ids": [linked["location_id"]]},
            headers=headers,
        )
        assert submitted.status_code == 202
        job_id = submitted.json()["job_id"]
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            job = client.get(f"/api/log/jobs/{job_id}").json()
            if job["status"] in {"succeeded", "partial", "failed"}:
                break
            time.sleep(0.05)
        assert job["status"] in {"succeeded", "partial"}
        project_detail = client.get(f"/api/projects/{project_id}").json()
        assert project_detail["log_alerts"]
        assert project_detail["log_events"]
        assert project_detail["log_timeline"]
        assert project_detail["log_events"][0]["file_hashes"] == []
        assert str(root) not in client.get(f"/api/projects/{project_id}").text
        assert job["scan_id"]
        persisted_finding = Finding(
            finding_id="location-removal-finding",
            title="Persisted fixture finding",
            severity=Severity.LOW,
            fingerprint="location-removal-fingerprint",
            scanner="fixture",
            rule_id="fixture",
            project_id=project_id,
        )
        app.state.repository.save(
            "finding", persisted_finding.finding_id, persisted_finding.model_dump(mode="json")
        )
        assert (
            client.request(
                "DELETE",
                f"/api/projects/{project_id}/log-locations/{linked['location_id']}",
                headers=headers,
                json={"confirmation": "logs"},
            ).status_code
            == 200
        )
        after_remove = client.get(f"/api/projects/{project_id}").json()
        assert after_remove["log_locations"] == []
        assert after_remove["recent_scans"][0]["scan_id"] == job["scan_id"]
        assert (
            after_remove["log_alerts"]
            and after_remove["log_events"]
            and after_remove["log_timeline"]
        )
        assert after_remove["findings_count"] == 1
        assert after_remove["findings"][0]["finding_id"] == persisted_finding.finding_id
        assert hashlib.sha256(candidate.read_bytes()).hexdigest() == digest


def test_project_log_aggregation_isolated_between_two_projects(tmp_path: Path) -> None:
    roots = [tmp_path / "approved-a", tmp_path / "approved-b"]
    sha256_value = "a" * 64
    md5_value = "b" * 32
    sha1_value = "c" * 40
    token_value = "".join(("runtime", "built", "token", "segment", "value", "unique", "canary"))
    for root, user in zip(roots, ("analyst-a", "analyst-b"), strict=True):
        logs = root / "logs"
        logs.mkdir(parents=True)
        (logs / "auth.jsonl").write_text(
            "\n".join(
                json.dumps(
                    {
                        "timestamp": f"2026-10-25T10:{minute:02}:00Z",
                        "event_type": "authentication_failure",
                        "message": f"Repeated authentication failure evidence {token_value}",
                        "event_outcome": "failure",
                        "user": user,
                        "source_ip": f"203.0.113.{5 if user.endswith('a') else 6}",
                        "sha256": sha256_value,
                        "md5": md5_value,
                        "sha1": sha1_value,
                    }
                )
                for minute in range(5)
            )
            + "\n",
            encoding="utf-8",
        )
    app, unused_client, _headers = _client(tmp_path, roots)
    unused_client.close()
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50134)) as client:
        login = client.post(
            "/api/auth/login",
            json={"email": "projects@example.test", "password": "project-test-password-123"},
            headers={"Origin": "http://127.0.0.1"},
        )
        headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]}
        root_ids = [
            item["directory_id"]
            for item in client.get("/api/fs/roots?capability=project_directory").json()["items"]
        ]
        projects = []
        for index, root_id in enumerate(root_ids):
            project = client.post(
                "/api/projects",
                json={"name": f"Isolated project {index}", "directory_id": root_id},
                headers=headers,
            ).json()
            project_id = project["project_id"]
            root_view = client.get(f"/api/projects/{project_id}/browse").json()
            children = client.get(
                f"/api/projects/{project_id}/browse?directory_id={root_view['directory_id']}"
            ).json()["items"]
            logs_id = next(item["directory_id"] for item in children if item["name"] == "logs")
            linked = client.post(
                f"/api/projects/{project_id}/log-locations",
                json={"name": "logs", "directory_id": logs_id},
                headers=headers,
            ).json()
            submitted = client.post(
                f"/api/projects/{project_id}/log-jobs",
                json={"location_ids": [linked["location_id"]]},
                headers=headers,
            )
            assert submitted.status_code == 202
            projects.append((project_id, submitted.json()["job_id"]))
        for _project_id, job_id in projects:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                job = client.get(f"/api/log/jobs/{job_id}").json()
                if job["status"] in {"succeeded", "partial", "failed"}:
                    break
                time.sleep(0.05)
            assert job["status"] in {"succeeded", "partial"}
        details = [client.get(f"/api/projects/{project_id}").json() for project_id, _ in projects]
        for index, detail in enumerate(details):
            assert detail["log_alerts"]
            assert detail["log_events"]
            assert detail["log_timeline"]
            own_user = f"analyst-{('a', 'b')[index]}"
            other_user = f"analyst-{('b', 'a')[index]}"
            assert all(own_user in event["user"] for event in detail["log_events"])
            assert all(other_user not in event["user"] for event in detail["log_events"])
            assert all(token_value in event["summary"] for event in detail["log_events"])
            assert all(event["sha256"] == sha256_value for event in detail["log_events"])
            assert all(
                set(event["file_hashes"]) == {md5_value, sha1_value}
                for event in detail["log_events"]
            )
            assert all(token_value in entry["description"] for entry in detail["log_timeline"])
            assert str(roots[index]) not in json.dumps(detail)


def test_project_suggestions_do_not_open_candidate_files(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "approved"
    logs = root / "logs"
    logs.mkdir(parents=True)
    candidates = [logs / "auth.jsonl", root / "archive.csv"]
    for candidate in candidates:
        candidate.write_text("synthetic fixture data\n", encoding="utf-8")
    app, client, _headers = _client(tmp_path, [root])
    opened: list[str] = []
    original_builtin_open = open
    original_path_open = Path.open
    original_os_open = os.open

    def track_builtin(file, *args, **kwargs):
        opened.append(str(file))
        return original_builtin_open(file, *args, **kwargs)

    def track_path(path, *args, **kwargs):
        opened.append(str(path))
        return original_path_open(path, *args, **kwargs)

    def track_os(path, *args, **kwargs):
        opened.append(str(path))
        return original_os_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", track_builtin)
    monkeypatch.setattr(Path, "open", track_path)
    monkeypatch.setattr(os, "open", track_os)
    project = client.post(
        "/api/projects",
        json={"name": "Metadata only", "directory_id": _selection(client)},
        headers=_headers,
    ).json()
    suggestions = app.state.log_location_service.suggestions(
        project["project_id"], "suggestion-spy-session"
    )
    assert {item["label"] for item in suggestions["items"]} >= {
        "logs",
        "logs/auth.jsonl",
        "archive.csv",
    }
    assert all(str(candidate) not in opened for candidate in candidates)
    client.close()


def test_project_browse_rejects_traversal_and_unbound_directory_ids(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    (root / "inside").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    app, client, headers = _client(tmp_path, [root])
    project = client.post(
        "/api/projects",
        json={"name": "Browse boundary", "directory_id": _selection(client)},
        headers=headers,
    ).json()
    root_view = client.get(f"/api/projects/{project['project_id']}/browse").json()
    inside_id = next(
        item["directory_id"]
        for item in client.get(
            f"/api/projects/{project['project_id']}/browse?directory_id={root_view['directory_id']}"
        ).json()["items"]
        if item["name"] == "inside"
    )
    for value in ("..", "%2e%2e", "%252e%252e"):
        response = client.get(f"/api/projects/{project['project_id']}/browse?directory_id={value}")
        assert response.status_code in {404, 422}
        assert str(root) not in response.text and str(outside) not in response.text
    second_client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50135))
    second_login = second_client.post(
        "/api/auth/login",
        json={"email": "projects@example.test", "password": "project-test-password-123"},
        headers={"Origin": "http://127.0.0.1"},
    )
    second_response = second_client.get(
        f"/api/projects/{project['project_id']}/browse?directory_id={inside_id}"
    )
    assert second_login.status_code == 200 and second_response.status_code == 404
    wrong_capability = client.post(
        f"/api/projects/{project['project_id']}/log-locations",
        json={"name": "wrong capability", "directory_id": inside_id, "scope": "external"},
        headers=headers,
    )
    assert wrong_capability.status_code == 422
    forged = client.get(f"/api/projects/{project['project_id']}/browse?directory_id={'f' * 32}")
    assert forged.status_code == 404
    assert str(root) not in forged.text and str(outside) not in forged.text
    second_client.close()
    client.close()


def test_external_log_location_requires_allowed_root_and_hard_deny_wins(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    project_root = allowed / "project"
    external_logs = allowed / "external-logs"
    denied_logs = allowed / "private"
    project_root.mkdir(parents=True)
    external_logs.mkdir()
    denied_logs.mkdir()
    (external_logs / "auth.log").write_text("safe fixture\n", encoding="utf-8")
    app, client, headers = _client(tmp_path, [allowed], hard_denied=[denied_logs])
    roots_page = client.get("/api/fs/roots?capability=project_directory").json()
    project_id_value = next(
        item["directory_id"]
        for item in client.get(
            f"/api/fs/list?capability=project_directory&directory_id={roots_page['items'][0]['directory_id']}"
        ).json()["items"]
        if item["name"] == "project"
    )
    project = client.post(
        "/api/projects",
        json={"name": "External location", "directory_id": project_id_value},
        headers=headers,
    ).json()
    external_roots = client.get("/api/fs/roots?capability=log_location").json()["items"]
    external_root = external_roots[0]["directory_id"]
    external_page = client.get(
        f"/api/fs/list?capability=log_location&directory_id={external_root}"
    ).json()
    external_id = next(
        item["directory_id"] for item in external_page["items"] if item["name"] == "external-logs"
    )
    linked = client.post(
        f"/api/projects/{project['project_id']}/log-locations",
        json={"name": "External logs", "directory_id": external_id, "scope": "external"},
        headers=headers,
    )
    assert linked.status_code == 201
    assert str(allowed) not in linked.text and str(external_logs) not in linked.text
    with pytest.raises(ValueError, match="no longer approved") as denied:
        app.state.log_location_service.add(project["project_id"], "Denied", denied_logs, "external")
    assert str(denied_logs) not in str(denied.value)
    assert str(denied_logs) not in json.dumps({"detail": {"message": str(denied.value)}})
    client.close()


def test_log_location_swap_to_outside_link_fails_browse_and_job_without_reads(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "approved"
    logs = root / "logs"
    outside = tmp_path / "outside"
    logs.mkdir(parents=True)
    outside.mkdir()
    secret_file = outside / "outside.log"
    secret_file.write_text("outside sentinel\n", encoding="utf-8")
    app, client, headers = _client(tmp_path, [root])
    project = client.post(
        "/api/projects",
        json={"name": "Swapped location", "directory_id": _selection(client)},
        headers=headers,
    ).json()
    root_view = client.get(f"/api/projects/{project['project_id']}/browse").json()
    logs_id = next(
        item["directory_id"]
        for item in client.get(
            f"/api/projects/{project['project_id']}/browse?directory_id={root_view['directory_id']}"
        ).json()["items"]
        if item["name"] == "logs"
    )
    linked = client.post(
        f"/api/projects/{project['project_id']}/log-locations",
        json={"name": "logs", "directory_id": logs_id},
        headers=headers,
    ).json()
    import shutil

    shutil.rmtree(logs)
    if os.name == "nt":
        safe_logs = str(logs).replace("'", "''")
        safe_outside = str(outside).replace("'", "''")
        subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    f"New-Item -ItemType Junction -Path '{safe_logs}' "
                    f"-Target '{safe_outside}' | Out-Null"
                ),
            ],
            check=True,
            capture_output=True,
        )
    else:
        try:
            logs.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"Could not create the temporary directory link: {type(exc).__name__}.")
    opened: list[str] = []
    original_open = open
    original_path_open = Path.open
    original_os_open = os.open

    def track_open(path, *args, **kwargs):
        opened.append(str(path))
        return original_open(path, *args, **kwargs)

    def track_path_open(path, *args, **kwargs):
        opened.append(str(path))
        return original_path_open(path, *args, **kwargs)

    def track_os_open(path, *args, **kwargs):
        opened.append(str(path))
        return original_os_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", track_open)
    monkeypatch.setattr(Path, "open", track_path_open)
    monkeypatch.setattr(os, "open", track_os_open)
    browse = client.get(f"/api/projects/{project['project_id']}/browse?directory_id={logs_id}")
    job = client.post(
        f"/api/projects/{project['project_id']}/log-jobs",
        json={"location_ids": [linked["location_id"]]},
        headers=headers,
    )
    assert browse.status_code == 404
    assert job.status_code == 422 and "location_denied" in job.text
    assert str(outside) not in browse.text + job.text
    assert str(secret_file) not in opened
    client.close()


def test_project_api_create_show_remove_keeps_files_scans_findings_and_cases(
    tmp_path: Path,
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    (root / "main.py").write_text("print('safe')\n", encoding="utf-8")
    before = hashlib.sha256((root / "main.py").read_bytes()).hexdigest()
    app, client, headers = _client(tmp_path, [root])
    assert client.get("/api/projects").status_code == 200
    selected = _selection(client)
    response = client.post(
        "/api/projects", json={"name": "Demo", "directory_id": selected}, headers=headers
    )
    assert response.status_code == 201
    project = response.json()
    assert project["configured_by"] == "dashboard"
    assert str(root) not in response.text
    detail = client.get(f"/api/projects/{project['project_id']}")
    assert detail.status_code == 200 and str(root) not in detail.text
    repository: SQLiteRepository = app.state.repository
    scan = Scan(
        scan_id="project-scan",
        target_id="internal-root",
        scanner="fixture",
        started_at=datetime.now(UTC),
        project_id=project["project_id"],
    )
    finding = Finding(
        finding_id="project-finding",
        title="Fixture finding",
        severity=Severity.LOW,
        fingerprint="fp",
        scanner="fixture",
        rule_id="fixture",
        project_id=project["project_id"],
    )
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    repository.save("finding", finding.finding_id, finding.model_dump(mode="json"))
    case = Case(
        case_id="project-case",
        title="Project case",
        project_id=project["project_id"],
        scan_ids=[scan.scan_id],
    )
    repository.save("case", case.case_id, case.model_dump(mode="json"))
    assert (
        client.request(
            "DELETE",
            f"/api/projects/{project['project_id']}",
            headers=headers,
            json={"confirmation": "wrong"},
        ).status_code
        == 409
    )
    assert (
        client.request(
            "DELETE",
            f"/api/projects/{project['project_id']}",
            headers=headers,
            json={"confirmation": "Demo"},
        ).status_code
        == 200
    )
    assert (root / "main.py").exists()
    assert hashlib.sha256((root / "main.py").read_bytes()).hexdigest() == before
    assert repository.get("project", project["project_id"]) is None
    assert repository.get("scan", scan.scan_id)["project_removed"] is True
    assert repository.get("finding", finding.finding_id)["project_removed"] is True
    assert repository.get("case", case.case_id)["project_removed"] is True
    client.close()


def test_project_creation_is_operator_approval_and_names_are_unique(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    app, client, headers = _client(tmp_path, [root])
    selected = _selection(client)
    created = client.post(
        "/api/projects", json={"name": "Café", "directory_id": selected}, headers=headers
    )
    assert created.status_code == 201
    duplicate = client.post(
        "/api/projects", json={"name": "CAFE\u0301", "directory_id": selected}, headers=headers
    )
    assert duplicate.status_code == 422
    app.state.project_service.allowed_roots.clear()
    submitted = client.post(
        f"/api/projects/{created.json()['project_id']}/code-jobs", headers=headers
    )
    assert submitted.status_code == 202
    assert created.json()["configured_by"] == "dashboard"
    client.close()


def test_project_job_rejects_root_swapped_to_junction(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    app, client, headers = _client(tmp_path, [root])
    selected = _selection(client)
    created = client.post(
        "/api/projects", json={"name": "Swapped root", "directory_id": selected}, headers=headers
    )
    assert created.status_code == 201
    moved = tmp_path / "moved-root"
    root.rename(moved)
    if os.name == "nt":
        safe_root = str(root).replace("'", "''")
        safe_target = str(moved).replace("'", "''")
        command = (
            f"New-Item -ItemType Junction -Path '{safe_root}' -Target '{safe_target}' | Out-Null"
        )
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            check=True,
            capture_output=True,
        )
    else:
        try:
            root.symlink_to(moved, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"Could not create a temporary directory link: {type(exc).__name__}.")
    response = client.post(
        f"/api/projects/{created.json()['project_id']}/code-jobs", headers=headers
    )
    assert response.status_code == 422
    assert '"code":"reparse_point"' in response.text
    assert str(root) not in response.text and str(moved) not in response.text
    client.close()


def test_project_route_requires_auth_csrf_and_same_origin(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    credential = private / "operator.json"
    create_operator(credential, "projects@example.test", "project-test-password-123")
    app = create_app(
        private / "records.sqlite3",
        credential,
        settings=Settings(
            _env_file=None,
            database_path=private / "records.sqlite3",
            reports_dir=private / "reports",
            allowed_roots=[root],
        ),
        serve_frontend=False,
    )
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50132))
    assert client.get("/api/projects").status_code == 401
    logged = client.post(
        "/api/auth/login",
        json={"email": "projects@example.test", "password": "project-test-password-123"},
        headers={"Origin": "http://127.0.0.1"},
    )
    token = logged.json()["csrf_token"]
    assert (
        client.post(
            "/api/projects",
            json={"name": "Demo", "directory_id": "x"},
            headers={"Origin": "http://127.0.0.1"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/projects",
            json={"name": "Demo", "directory_id": "x"},
            headers={"Origin": "http://evil.test", "X-CSRF-Token": token},
        ).status_code
        == 403
    )
    client.close()


def test_legacy_file_projects_are_read_only_and_path_free(tmp_path: Path) -> None:
    root = tmp_path / "legacy-root"
    root.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    config = private / "projects.toml"
    config.write_text(
        f'[[projects]]\nid = "legacy"\nname = "Legacy"\nroot = "{root.as_posix()}"\n',
        encoding="utf-8",
    )
    credential = private / "operator.json"
    create_operator(credential, "projects@example.test", "project-test-password-123")
    app = create_app(
        private / "records.sqlite3",
        credential,
        projects_path=config,
        settings=Settings(
            _env_file=None,
            database_path=private / "records.sqlite3",
            reports_dir=private / "reports",
            allowed_roots=[],
        ),
        serve_frontend=False,
    )
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50133))
    logged = client.post(
        "/api/auth/login",
        json={"email": "projects@example.test", "password": "project-test-password-123"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert logged.status_code == 200
    listed = client.get("/api/projects")
    assert listed.status_code == 200 and listed.json()[0]["configured_by"] == "file"
    assert str(root) not in listed.text
    deleted = client.request(
        "DELETE",
        "/api/projects/legacy",
        headers={"Origin": "http://127.0.0.1", "X-CSRF-Token": logged.json()["csrf_token"]},
        json={"confirmation": "Legacy"},
    )
    assert deleted.status_code == 409
    assert root.exists()
    client.close()


def test_scan_bounds_report_each_skip_reason_and_ignore_default_directories(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "code"
    (root / "nested" / "deep").mkdir(parents=True)
    (root / "node_modules" / "pkg").mkdir(parents=True)
    (root / "one.py").write_text("eval(input)\n", encoding="utf-8")
    (root / "two.py").write_text("exec(input)\n", encoding="utf-8")
    (root / "nested" / "deep" / "three.py").write_text("eval(input)\n", encoding="utf-8")
    (root / "node_modules" / "pkg" / "ignored.py").write_text("eval(input)\n", encoding="utf-8")
    ignored_dirs = (".git", ".venv", "venv", "dist", "build", "__pycache__")
    for name in ignored_dirs:
        ignored = root / name
        ignored.mkdir()
        (ignored / "ignored.py").write_text("eval(input)\n", encoding="utf-8")

    file_profile = detect_project(root, ScanBounds(max_files=1))
    assert file_profile.skipped_counts["max_files"] >= 1
    assert all(item.name != "ignored.py" for item in file_profile.source_files)
    assert not any(
        part in ignored_dirs for path in file_profile.source_files for part in path.parts
    )
    byte_profile = detect_project(root, ScanBounds(max_total_bytes=1))
    assert byte_profile.skipped_counts["max_total_bytes"] >= 1
    size_profile = detect_project(root, ScanBounds(max_file_bytes=1))
    assert size_profile.skipped_counts["max_file_bytes"] >= 1
    depth_profile = detect_project(root, ScanBounds(max_depth=1))
    assert depth_profile.skipped_counts["max_depth"] >= 1
    deadline_profile = detect_project(root, ScanBounds(job_deadline_seconds=0))
    assert deadline_profile.skipped_counts["job_deadline"] >= 1

    profile = ProjectProfile(
        root=root,
        kinds=("python",),
        source_files=(root / "one.py",),
        skipped_counts={},
        deadline_at=100,
    )
    times = iter([0.0, 0.0, 1.0, 1.0])
    monkeypatch.setattr(
        "chinescan.core.orchestration.code_scan.time.monotonic", lambda: next(times)
    )
    BuiltinRuleScanner(ScanBounds(per_file_seconds=0.1)).scan_profile(profile)
    assert profile.skipped_counts["per_file_seconds"] == 1
