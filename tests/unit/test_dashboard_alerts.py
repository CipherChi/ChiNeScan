from datetime import UTC, datetime, timedelta

import pytest

from chinescan.core.dashboard_alerts import AlertStateError, DashboardAlerts
from chinescan.core.dashboard_intelligence import DashboardIntelligence
from chinescan.core.storage.sqlite import SQLiteRepository


def _service(tmp_path):
    repository = SQLiteRepository(tmp_path / "alerts.sqlite3")
    return repository, DashboardAlerts(repository)


def _item():
    return {
        "fingerprint": "new_critical_finding:f-1",
        "rule_id": "new_critical_finding",
        "title": "New critical finding",
        "description": "A critical item was recorded.",
        "severity": "critical",
        "module": "Code Assessment",
    }


def test_alert_dedup_state_transitions_and_append_only_audit(tmp_path):
    repository, alerts = _service(tmp_path)
    first = alerts.create_once(_item())
    second = alerts.create_once(_item())
    assert first["alert_id"] == second["alert_id"]
    assert second["occurrence_count"] == 2
    assert [entry["action"] for entry in alerts.audit(first["alert_id"])] == [
        "created",
        "deduplicated",
    ]

    snooze_until = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    snoozed = alerts.transition(first["alert_id"], "snooze", "analyst", snoozed_until=snooze_until)
    assert snoozed["state"] == "snoozed"
    assert alerts.transition(first["alert_id"], "acknowledge", "analyst")["state"] == "acknowledged"
    assert alerts.transition(first["alert_id"], "resolve", "analyst")["state"] == "resolved"
    assert [entry["action"] for entry in alerts.audit(first["alert_id"])] == [
        "created",
        "deduplicated",
        "snoozed",
        "acknowledged",
        "resolved",
    ]
    with repository.engine.connect() as connection:
        with pytest.raises(Exception, match="append-only"):
            connection.exec_driver_sql("DELETE FROM dashboard_alert_audit")
        with pytest.raises(Exception, match="append-only"):
            connection.exec_driver_sql("UPDATE dashboard_alert_audit SET details='{}'")
    repository.close()


def test_invalid_alert_transition_is_rejected(tmp_path):
    _repository, alerts = _service(tmp_path)
    alert = alerts.create_once(_item())
    alerts.transition(alert["alert_id"], "resolve", "analyst")
    with pytest.raises(AlertStateError, match="Cannot acknowledge"):
        alerts.transition(alert["alert_id"], "acknowledge", "analyst")


def test_malware_triage_is_scored_and_persisted_alert_refresh_is_idempotent(tmp_path):
    repository, alerts = _service(tmp_path)
    repository.save(
        "malware_analysis",
        "triage-1",
        {
            "analysis_id": "triage-1",
            "status": "complete",
            "created_at": datetime.now(UTC).isoformat(),
            "result": {
                "verdict": "likely-malicious",
                "indicator_count": 2,
                "warnings": [],
            },
        },
    )
    intelligence = DashboardIntelligence(repository, alerts)
    score = next(
        item for item in intelligence.score_modules() if item["module"] == "Malware Triage"
    )
    assert score["score"] is not None
    assert score["checks_completed"] == 1
    assert score["findings"][0]["severity"] == "critical"

    intelligence.refresh_alerts()
    intelligence.refresh_alerts()
    alert = alerts.list_alerts()[0]
    assert alert["rule_id"] == "malware_triage_hit"
    assert alert["occurrence_count"] == 1
    assert len(alerts.audit(alert["alert_id"])) == 1
    repository.close()


def test_unavailable_scoring_engine_still_returns_inputs_and_a_breakdown():
    result = DashboardIntelligence._unavailable_score(
        {
            "module": "Code Assessment",
            "checks_completed": 1,
            "checks_total": 3,
            "findings": [{"severity": "critical", "confidence": 0.8, "age_days": 60}],
        }
    )
    assert result["score"] is None
    assert result["checks_not_assessed"] == 2
    assert result["findings"][0]["penalty"] == 16.0
    assert result["inputs"]["findings"][0]["severity"] == "critical"
    assert "Based on 1 checks, 2 not assessed" in result["why_this_score"]
