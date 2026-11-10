"""Persist deduplicated local alerts and append-only alert activity."""

from alembic import op

revision = "0004_dashboard_alerts"
down_revision = "0003_malware_backend"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE dashboard_alerts (
            alert_id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL UNIQUE,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
            module TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('open','acknowledged','snoozed','resolved')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            acknowledged_at TEXT,
            snoozed_until TEXT,
            resolved_at TEXT,
            occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count >= 1)
        )
    """)
    op.execute(
        "CREATE INDEX ix_dashboard_alerts_state_created "
        "ON dashboard_alerts(state, created_at DESC)"
    )
    op.execute("""
        CREATE TABLE dashboard_alert_audit (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL REFERENCES dashboard_alerts(alert_id),
            action TEXT NOT NULL CHECK (
                action IN ('created','acknowledged','snoozed','resolved','deduplicated')
            ),
            previous_state TEXT,
            new_state TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '{}'
        )
    """)
    op.execute(
        "CREATE INDEX ix_dashboard_alert_audit_alert_id "
        "ON dashboard_alert_audit(alert_id, audit_id)"
    )
    op.execute("""
        CREATE TRIGGER dashboard_alert_audit_no_update
        BEFORE UPDATE ON dashboard_alert_audit
        BEGIN SELECT RAISE(ABORT, 'alert audit is append-only'); END
    """)
    op.execute("""
        CREATE TRIGGER dashboard_alert_audit_no_delete
        BEFORE DELETE ON dashboard_alert_audit
        BEGIN SELECT RAISE(ABORT, 'alert audit is append-only'); END
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS dashboard_alert_audit_no_delete")
    op.execute("DROP TRIGGER IF EXISTS dashboard_alert_audit_no_update")
    op.drop_index("ix_dashboard_alert_audit_alert_id", table_name="dashboard_alert_audit")
    op.drop_table("dashboard_alert_audit")
    op.drop_index("ix_dashboard_alerts_state_created", table_name="dashboard_alerts")
    op.drop_table("dashboard_alerts")
