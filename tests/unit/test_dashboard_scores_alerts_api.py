import re
import secrets
from pathlib import Path

from chinescan.core.capabilities import module_capabilities
from chinescan.web.app import COOKIE_NAME
from tests.unit.test_web_api import _fixture, _login


def test_dashboard_alert_api_requires_auth_csrf_and_has_strict_security_headers(
    tmp_path, monkeypatch
):
    app, client, _credential, _database = _fixture(tmp_path)
    assert client.get("/api/dashboard/scores").status_code == 401
    assert client.get("/api/alerts").status_code == 401
    assert client.get("/api/alerts/events").status_code == 401
    login = _login(client)
    assert login.status_code == 200
    cookie = client.cookies.get(COOKIE_NAME)
    assert cookie
    set_cookie = next(
        value for key, value in login.headers.items() if key.casefold() == "set-cookie"
    )
    assert "samesite=strict" in set_cookie.casefold()
    response = client.get("/api/dashboard/scores")
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    assert "unsafe-eval" not in csp
    html = (Path(__file__).parents[2] / "frontend" / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html, flags=re.IGNORECASE)

    alert = app.state.dashboard_alerts.create_once(
        {
            "fingerprint": "new_critical_finding:api-1",
            "rule_id": "new_critical_finding",
            "title": "New critical finding",
            "description": "Critical finding.",
            "severity": "critical",
            "module": "Code Assessment",
        }
    )
    compare_digest = secrets.compare_digest
    comparisons = []

    def track_compare(left, right):
        comparisons.append((left, right))
        return compare_digest(left, right)

    monkeypatch.setattr(secrets, "compare_digest", track_compare)
    bad = client.post(
        f"/api/alerts/{alert['alert_id']}/acknowledge",
        headers={"Origin": str(client.base_url).rstrip("/"), "X-CSRF-Token": "wrong"},
    )
    assert bad.status_code == 403
    assert comparisons and comparisons[-1] == (login.json()["csrf_token"], "wrong")
    good = client.post(
        f"/api/alerts/{alert['alert_id']}/acknowledge",
        headers={
            "Origin": str(client.base_url).rstrip("/"),
            "X-CSRF-Token": login.json()["csrf_token"],
        },
    )
    assert good.status_code == 200
    assert good.json()["state"] == "acknowledged"
    assert (
        client.get(f"/api/alerts/{alert['alert_id']}/audit").json()[-1]["action"] == "acknowledged"
    )


def test_security_dashboard_capability_is_not_assessed_only_after_feature_coverage(tmp_path):
    modules = {item["name"]: item for item in module_capabilities()}
    dashboard = modules["Security Dashboard"]
    assert dashboard["status"] == "partial"
    assert "Alerts panel" not in dashboard["not_assessed"]
    assert "Per-module scores" not in dashboard["not_assessed"]
    app, client, *_ = _fixture(tmp_path)
    _login(client)
    scores = client.get("/api/dashboard/scores").json()
    assert len(scores) == len(modules)
    assert all(
        "why_this_score" in score
        and "checks_completed" in score
        and "inputs" in score
        for score in scores
    )
