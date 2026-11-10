"""Persistent local dashboard alert state and append-only audit log."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from chinescan.core.storage.sqlite import SQLiteRepository


def timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class AlertStateError(ValueError):
    pass


class DashboardAlerts:
    def __init__(self, repository: SQLiteRepository) -> None:
        self.repository = repository

    def create_once(
        self,
        item: dict[str, Any],
        *,
        now: str | None = None,
        count_duplicate: bool = True,
    ) -> dict[str, Any]:
        at = now or timestamp()
        alert_id = str(uuid4())
        with self.repository.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                connection.exec_driver_sql(
                    "INSERT OR IGNORE INTO dashboard_alerts "
                    "(alert_id,fingerprint,rule_id,title,description,severity,module,state,"
                    "created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,'open',?,?)",
                    (
                        alert_id,
                        item["fingerprint"],
                        item["rule_id"],
                        item["title"],
                        item["description"],
                        item["severity"],
                        item["module"],
                        at,
                        at,
                    ),
                )
                row = (
                    connection.exec_driver_sql(
                        "SELECT * FROM dashboard_alerts WHERE fingerprint=?", (item["fingerprint"],)
                    )
                    .mappings()
                    .one()
                )
                if row["alert_id"] == alert_id:
                    connection.exec_driver_sql(
                        "INSERT INTO dashboard_alert_audit(alert_id,action,previous_state,"
                        "new_state,actor_id,occurred_at,details) "
                        "VALUES(?,'created',NULL,'open','system',?,'{}')",
                        (alert_id, at),
                    )
                elif count_duplicate:
                    connection.exec_driver_sql(
                        "UPDATE dashboard_alerts SET occurrence_count=occurrence_count+1, "
                        "updated_at=? WHERE alert_id=?",
                        (at, row["alert_id"]),
                    )
                    connection.exec_driver_sql(
                        "INSERT INTO dashboard_alert_audit(alert_id,action,previous_state,"
                        "new_state,actor_id,occurred_at,details) "
                        "VALUES(?,'deduplicated',?,?, 'system',?,?)",
                        (
                            row["alert_id"],
                            row["state"],
                            row["state"],
                            at,
                            json.dumps({"fingerprint": item["fingerprint"]}),
                        ),
                    )
                    row = (
                        connection.exec_driver_sql(
                            "SELECT * FROM dashboard_alerts WHERE alert_id=?", (row["alert_id"],)
                        )
                        .mappings()
                        .one()
                    )
                else:
                    row = (
                        connection.exec_driver_sql(
                            "SELECT * FROM dashboard_alerts WHERE alert_id=?", (row["alert_id"],)
                        )
                        .mappings()
                        .one()
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return dict(row)

    def list_alerts(
        self, *, limit: int = 100, include_resolved: bool = False
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 200:
            raise ValueError("Alert limit is out of bounds.")
        where = "" if include_resolved else "WHERE state <> 'resolved'"
        with self.repository.engine.connect() as connection:
            rows = (
                connection.exec_driver_sql(
                    f"SELECT * FROM dashboard_alerts {where} "
                    "ORDER BY created_at DESC, alert_id LIMIT ?",
                    (limit,),
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows]

    def get(self, alert_id: str) -> dict[str, Any] | None:
        with self.repository.engine.connect() as connection:
            row = (
                connection.exec_driver_sql(
                    "SELECT * FROM dashboard_alerts WHERE alert_id=?", (alert_id,)
                )
                .mappings()
                .first()
            )
        return dict(row) if row else None

    def transition(
        self,
        alert_id: str,
        action: str,
        actor: str,
        *,
        snoozed_until: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        if action not in {"acknowledge", "snooze", "resolve"}:
            raise AlertStateError("Alert action is not supported.")
        at = now or timestamp()
        with self.repository.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                row = (
                    connection.exec_driver_sql(
                        "SELECT * FROM dashboard_alerts WHERE alert_id=?", (alert_id,)
                    )
                    .mappings()
                    .first()
                )
                if row is None:
                    raise KeyError(alert_id)
                previous = str(row["state"])
                transitions = {
                    "acknowledge": {"open", "snoozed"},
                    "snooze": {"open", "acknowledged"},
                    "resolve": {"open", "acknowledged", "snoozed"},
                }
                if previous not in transitions[action]:
                    raise AlertStateError(f"Cannot {action} an alert in state {previous}.")
                new_state = {
                    "acknowledge": "acknowledged",
                    "snooze": "snoozed",
                    "resolve": "resolved",
                }[action]
                if action == "snooze":
                    if snoozed_until is None:
                        raise AlertStateError("Snooze requires an expiry time.")
                    try:
                        until = datetime.fromisoformat(snoozed_until.replace("Z", "+00:00"))
                        current = datetime.fromisoformat(at.replace("Z", "+00:00"))
                    except ValueError as exc:
                        raise AlertStateError("Snooze expiry is invalid.") from exc
                    if (
                        until.tzinfo is None
                        or current.tzinfo is None
                        or not current + timedelta(minutes=1)
                        <= until
                        <= current + timedelta(days=30)
                    ):
                        raise AlertStateError(
                            "Snooze expiry must be 1 minute to 30 days in the future."
                        )
                connection.exec_driver_sql(
                    "UPDATE dashboard_alerts SET state=?,updated_at=?, "
                    "acknowledged_at=CASE WHEN ?='acknowledged' THEN ? ELSE acknowledged_at END, "
                    "snoozed_until=CASE WHEN ?='snoozed' THEN ? ELSE NULL END, "
                    "resolved_at=CASE WHEN ?='resolved' THEN ? ELSE resolved_at END "
                    "WHERE alert_id=?",
                    (
                        new_state,
                        at,
                        new_state,
                        at,
                        new_state,
                        snoozed_until,
                        new_state,
                        at,
                        alert_id,
                    ),
                )
                connection.exec_driver_sql(
                    "INSERT INTO dashboard_alert_audit(alert_id,action,previous_state,new_state,"
                    "actor_id,occurred_at,details) VALUES(?,?,?,?,?,?,?)",
                    (
                        alert_id,
                        action + "d" if action != "snooze" else "snoozed",
                        previous,
                        new_state,
                        actor[:128],
                        at,
                        json.dumps(
                            {"snoozed_until": snoozed_until} if snoozed_until else {},
                            separators=(",", ":"),
                        ),
                    ),
                )
                updated = (
                    connection.exec_driver_sql(
                        "SELECT * FROM dashboard_alerts WHERE alert_id=?", (alert_id,)
                    )
                    .mappings()
                    .one()
                )
                connection.commit()
                return dict(updated)
            except Exception:
                connection.rollback()
                raise

    def audit(self, alert_id: str) -> list[dict[str, Any]]:
        with self.repository.engine.connect() as connection:
            rows = (
                connection.exec_driver_sql(
                    "SELECT audit_id,alert_id,action,previous_state,new_state,actor_id,occurred_at,"
                    "details FROM dashboard_alert_audit WHERE alert_id=? ORDER BY audit_id",
                    (alert_id,),
                )
                .mappings()
                .all()
            )
        return [{**dict(row), "details": json.loads(row["details"])} for row in rows]

    def events_after(self, audit_id: int, limit: int = 100) -> list[dict[str, Any]]:
        with self.repository.engine.connect() as connection:
            rows = (
                connection.exec_driver_sql(
                    "SELECT audit_id,alert_id,action,new_state,occurred_at "
                    "FROM dashboard_alert_audit "
                    "WHERE audit_id>? ORDER BY audit_id LIMIT ?",
                    (max(0, audit_id), min(max(1, limit), 100)),
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows]
