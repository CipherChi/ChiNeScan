from pathlib import Path

from fastapi.testclient import TestClient

from chinescan.core.config.settings import Settings
from chinescan.web.app import create_app
from chinescan.web.auth import create_operator
from chinescan.web.rate_limit import InProcessRateLimiter


def test_limiter_enforces_window_reset_and_bounded_memory() -> None:
    now = [0.0]
    limiter = InProcessRateLimiter({"read": (2, 10)}, max_buckets=2, clock=lambda: now[0])
    assert limiter.check("read", "a") == 0
    assert limiter.check("read", "a") == 0
    assert limiter.check("read", "a") > 0
    now[0] = 11
    assert limiter.check("read", "a") == 0
    limiter.check("read", "b")
    limiter.check("read", "c")
    assert len(limiter._buckets) <= 2


def test_auth_route_limit_returns_retry_after_error_shape(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "known@example.test", "Synthetic secure passphrase 71!")
    app = create_app(
        tmp_path / "db.sqlite3",
        credential,
        settings=Settings(auth_rate_limit=1),
        serve_frontend=False,
    )
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    headers = {"Origin": "http://127.0.0.1"}
    try:
        first = client.post("/api/auth/login", json={"email": "x@example.test", "password": "wrong"}, headers=headers)
        limited = client.post("/api/auth/login", json={"email": "x@example.test", "password": "wrong"}, headers=headers)
        assert first.status_code == 401
        assert limited.status_code == 429
        assert int(limited.headers["retry-after"]) >= 1
        assert limited.json()["detail"]["code"] == "rate_limited"
        assert limited.json()["detail"]["message"]
    finally:
        client.close()


def test_forwarded_ip_is_ignored_until_trusted_proxy_is_enabled(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "known@example.test", "Synthetic secure passphrase 71!")
    for trusted, second_status in ((False, 429), (True, 401)):
        app = create_app(
            tmp_path / f"{trusted}.sqlite3",
            credential,
            settings=Settings(auth_rate_limit=1, trusted_proxy=trusted),
            serve_frontend=False,
        )
        client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
        try:
            for forwarded in ("198.51.100.1", "198.51.100.2"):
                response = client.post(
                    "/api/auth/login",
                    json={"email": "unknown@example.test", "password": "wrong"},
                    headers={"Origin": "http://127.0.0.1", "X-Forwarded-For": forwarded},
                )
            assert response.status_code == second_status
        finally:
            client.close()
