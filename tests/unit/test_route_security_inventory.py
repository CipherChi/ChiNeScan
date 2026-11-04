import re
from pathlib import Path

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.web.app import create_app
from chinescan.web.auth import create_operator


def _route_url(path: str) -> str:
    return re.sub(r"\{[^}:]+(?::path)?\}", "unknown-id", path)


def test_api_read_routes_require_session_including_versioned_alias(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "analyst@example.test", "Synthetic secure passphrase 71!")
    app = create_app(tmp_path / "db.sqlite3", credential, serve_frontend=False)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    allowed = {"/api/health", "/api/auth/session"}
    try:
        routes = [route for route in app.routes if isinstance(route, APIRoute)]
        for route in routes:
            if not route.path.startswith("/api/") or "GET" not in (route.methods or set()):
                continue
            if route.path in allowed:
                continue
            response = client.get(_route_url(route.path))
            assert response.status_code == 401, (route.path, response.status_code)
        assert client.get("/api/v1/scans").status_code == 401
        assert client.get("/api/v1/chain/jobs").status_code == 401
    finally:
        client.close()


def test_mutating_routes_reject_missing_csrf_and_wrong_typed_record_ids(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "analyst@example.test", "Synthetic secure passphrase 71!")
    database = tmp_path / "db.sqlite3"
    repository = SQLiteRepository(database)
    repository.save("chain_job", "shared-job-id", {"job_id": "shared-job-id"})
    repository.close()
    app = create_app(database, credential, serve_frontend=False)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    try:
        login = client.post(
            "/api/auth/login",
            json={"email": "analyst@example.test", "password": "Synthetic secure passphrase 71!"},
            headers={"Origin": "http://127.0.0.1"},
        )
        csrf = login.json()["csrf_token"]
        headers = {"Origin": "http://127.0.0.1"}
        routes = [route for route in app.routes if isinstance(route, APIRoute)]
        auth_mutations = {
            "/api/auth/login",
            "/api/auth/signup",
            "/api/auth/forgot-password",
            "/api/auth/reset-password",
        }
        for route in routes:
            if not route.path.startswith("/api/") or not (route.methods or set()).intersection(
                {"POST", "PUT", "PATCH", "DELETE"}
            ):
                continue
            if route.path in auth_mutations:
                continue
            method = next(
                iter((route.methods or set()).intersection({"POST", "PUT", "PATCH", "DELETE"}))
            )
            response = client.request(
                method,
                _route_url(route.path),
                headers=headers,
                json={},
            )
            assert response.status_code in {401, 403}, (route.path, response.status_code)
        assert csrf
        versioned_write = client.post(
            "/api/v1/cases", json={}, headers={"Origin": "http://127.0.0.1"}
        )
        assert versioned_write.status_code == 403
        wrong_type = client.get("/api/code/jobs/shared-job-id")
        assert wrong_type.status_code == 404
        traversal = client.get("/api/scans/scan-1/report/../../private")
        assert traversal.status_code in {404, 422}
        fs_traversal = client.get(
            "/api/fs/list",
            params={"directory_id": "../../..", "capability": "project_directory"},
        )
        assert fs_traversal.status_code == 422
    finally:
        client.close()
