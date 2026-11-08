"""SQLAlchemy-backed SQLite repository."""

import hmac
import json
from pathlib import Path
from typing import Any, cast, overload

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import (
    JSON,
    Column,
    MetaData,
    String,
    Table,
    case,
    create_engine,
    func,
    inspect,
    select,
)
from sqlalchemy.engine import Engine
from sqlalchemy.engine.reflection import Inspector

from chinescan.core.errors import StorageError
from chinescan.core.storage.repository import Repository

metadata = MetaData()
records = Table(
    "records",
    metadata,
    Column("record_type", String(80), primary_key=True),
    Column("record_id", String(255), primary_key=True),
    Column("payload", JSON, nullable=False),
)


class SQLiteRepository(Repository):
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{self.path.as_posix()}"
        self._migrate(url)
        self.engine: Engine = create_engine(url)

    def _migrate(self, url: str) -> None:
        """Upgrade fresh/known legacy stores; reject unknown schemas without altering them."""
        engine = create_engine(url)
        try:
            inspector = inspect(engine)
            tables = set(inspector.get_table_names()) - {"alembic_version"}
            with engine.connect() as connection:
                revision = MigrationContext.configure(connection).get_current_revision()
            if revision is None and tables:
                if tables != {"records"} or not self._is_initial_records_schema(inspector):
                    raise StorageError(
                        "SQLite schema is not a recognized ChiNeScan revision; "
                        "database left unchanged."
                    )
                config = self._alembic_config(url)
                command.stamp(config, "0001_initial")
                command.upgrade(config, "head")
            else:
                config = self._alembic_config(url)
                command.upgrade(config, "head")
        except StorageError:
            raise
        except Exception as exc:
            raise StorageError(
                "SQLite migration failed; database contents were not recreated."
            ) from exc
        finally:
            engine.dispose()

    @staticmethod
    def _is_initial_records_schema(inspector: Inspector) -> bool:
        columns = inspector.get_columns("records")
        primary_key = inspector.get_pk_constraint("records").get("constrained_columns", [])
        return [
            (column["name"], column["type"].__class__.__name__, column["nullable"])
            for column in columns
        ] == [
            ("record_type", "VARCHAR", False),
            ("record_id", "VARCHAR", False),
            ("payload", "JSON", False),
        ] and primary_key == ["record_type", "record_id"]

    @staticmethod
    def _alembic_config(url: str) -> Config:
        project_root = Path(__file__).resolve().parents[3]
        config = Config(str(project_root / "alembic.ini"))
        config.set_main_option("script_location", str(project_root / "migrations"))
        config.set_main_option("sqlalchemy.url", url)
        return config

    def save(self, record_type: str, record_id: str, payload: dict[str, Any]) -> None:
        with self.engine.begin() as connection:
            existing = connection.execute(
                select(records.c.record_id).where(
                    records.c.record_type == record_type, records.c.record_id == record_id
                )
            ).first()
            if existing:
                connection.execute(
                    records.update()
                    .where(records.c.record_type == record_type, records.c.record_id == record_id)
                    .values(payload=json.loads(json.dumps(payload)))
                )
            else:
                connection.execute(
                    records.insert().values(
                        record_type=record_type,
                        record_id=record_id,
                        payload=json.loads(json.dumps(payload)),
                    )
                )

    def consume_malware_acknowledgement(
        self, token_hash: str, project_id: str, session_id: str, now: str
    ) -> str:
        """Atomically verify and consume one project/session acknowledgement."""
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    select(records.c.record_id, records.c.payload).where(
                        records.c.record_type == "malware_ack",
                        records.c.record_id == token_hash,
                    )
                ).first()
                if row is None:
                    connection.commit()
                    return "missing_or_invalid"
                payload = cast(dict[str, Any], row.payload)
                if not hmac.compare_digest(str(payload.get("token_hash", "")), token_hash):
                    connection.commit()
                    return "missing_or_invalid"
                reason = (
                    "wrong_session"
                    if payload.get("session_id") != session_id
                    else "wrong_project"
                    if payload.get("project_id") != project_id
                    else "replayed"
                    if payload.get("consumed")
                    else "expired"
                    if str(payload.get("expires_at", "")) <= now
                    else ""
                )
                if not reason:
                    payload["consumed"] = True
                    connection.execute(
                        records.update()
                        .where(
                            records.c.record_type == "malware_ack",
                            records.c.record_id == token_hash,
                        )
                        .values(payload=payload)
                    )
                connection.commit()
                return reason or "consumed"
            except Exception:
                connection.rollback()
                raise

    def delete(self, record_type: str, record_id: str) -> None:
        """Delete one explicitly named record without touching related records."""
        with self.engine.begin() as connection:
            connection.execute(
                records.delete().where(
                    records.c.record_type == record_type,
                    records.c.record_id == record_id,
                )
            )

    def save_many(self, items: list[tuple[str, str, dict[str, Any]]]) -> None:
        """Atomically upsert a bounded set of metadata records in one SQLite transaction."""
        if not 1 <= len(items) <= 100:
            raise ValueError("record transaction must contain between 1 and 100 records")
        with self.engine.begin() as connection:
            for record_type, record_id, payload in items:
                safe_payload = json.loads(json.dumps(payload))
                existing = connection.execute(
                    select(records.c.record_id).where(
                        records.c.record_type == record_type, records.c.record_id == record_id
                    )
                ).first()
                if existing:
                    connection.execute(
                        records.update()
                        .where(
                            records.c.record_type == record_type,
                            records.c.record_id == record_id,
                        )
                        .values(payload=safe_payload)
                    )
                else:
                    connection.execute(
                        records.insert().values(
                            record_type=record_type,
                            record_id=record_id,
                            payload=safe_payload,
                        )
                    )

    def save_malware_intake(
        self,
        sample_id: str,
        sample: dict[str, Any],
        job_id: str,
        job: dict[str, Any],
        audit_id: str,
        audit: dict[str, Any],
        *,
        active_limit: int = 5,
    ) -> None:
        """Atomically reserve one of five malware slots and persist intake metadata."""
        if not 1 <= active_limit <= 5:
            raise ValueError("malware active/queue limit is invalid")
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                active = connection.execute(
                    select(func.count())
                    .select_from(records)
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.payload["status"].as_string().in_(("queued", "running")),
                    )
                ).scalar_one()
                if int(active) >= active_limit:
                    raise OverflowError("Malware queue is full.")
                for record_type, record_id, payload in (
                    ("malware_sample", sample_id, sample),
                    ("malware_job", job_id, job),
                    ("malware_audit", audit_id, audit),
                ):
                    connection.execute(
                        records.insert().values(
                            record_type=record_type,
                            record_id=record_id,
                            payload=json.loads(json.dumps(payload)),
                        )
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def enqueue_malware_analysis(
        self,
        job_id: str,
        job: dict[str, Any],
        audit_id: str,
        audit: dict[str, Any],
        *,
        active_limit: int = 5,
    ) -> None:
        """Atomically reserve an analysis slot for an already managed sample."""
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                active = connection.execute(
                    select(func.count())
                    .select_from(records)
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.payload["status"].as_string().in_(("queued", "running")),
                    )
                ).scalar_one()
                if int(active) >= active_limit:
                    raise OverflowError("Malware queue is full.")
                duplicate = connection.execute(
                    select(func.count())
                    .select_from(records)
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.payload["sample_id"].as_string() == job.get("sample_id"),
                        records.c.payload["status"].as_string().in_(("queued", "running")),
                    )
                ).scalar_one()
                if int(duplicate):
                    raise RuntimeError("An analysis for this managed sample is already active.")
                connection.execute(
                    records.insert().values(
                        record_type="malware_job",
                        record_id=job_id,
                        payload=json.loads(json.dumps(job)),
                    )
                )
                connection.execute(
                    records.insert().values(
                        record_type="malware_audit",
                        record_id=audit_id,
                        payload=json.loads(json.dumps(audit)),
                    )
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def claim_next_malware_job(self, started_at: str) -> dict[str, Any] | None:
        """Claim the oldest queued job only when no other manager has a running job."""
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                running = connection.execute(
                    select(records.c.record_id)
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.payload["status"].as_string() == "running",
                    )
                    .limit(1)
                ).first()
                if running:
                    connection.commit()
                    return None
                row = connection.execute(
                    select(records.c.record_id, records.c.payload)
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.payload["status"].as_string() == "queued",
                    )
                    .order_by(records.c.payload["created_at"].as_string().asc())
                    .limit(1)
                ).first()
                if row is None:
                    connection.commit()
                    return None
                job = dict(row.payload)
                job["status"] = "running"
                job["started_at"] = started_at
                result = connection.execute(
                    records.update()
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.record_id == row.record_id,
                        records.c.payload["status"].as_string() == "queued",
                    )
                    .values(payload=json.loads(json.dumps(job)))
                )
                if result.rowcount != 1:
                    connection.rollback()
                    return None
                connection.commit()
                return job
            except Exception:
                connection.rollback()
                raise

    def get(self, record_type: str, record_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(records.c.payload).where(
                    records.c.record_type == record_type, records.c.record_id == record_id
                )
            ).first()
        return dict(row[0]) if row else None

    def get_many(self, record_type: str, record_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Fetch a bounded ID set in SQLite-safe chunks without per-record queries."""
        if len(record_ids) > 100_000:
            raise ValueError("record ID batch exceeds the supported limit")
        result: dict[str, dict[str, Any]] = {}
        with self.engine.connect() as connection:
            for start in range(0, len(record_ids), 500):
                batch = record_ids[start : start + 500]
                rows = connection.execute(
                    select(records.c.record_id, records.c.payload).where(
                        records.c.record_type == record_type,
                        records.c.record_id.in_(batch),
                    )
                )
                result.update({str(row[0]): dict(row[1]) for row in rows})
        return result

    def list_records(self, record_type: str) -> list[dict[str, Any]]:
        """Return payloads for one record type from the local SQLite store."""
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(records.c.payload).where(records.c.record_type == record_type)
            ).all()
        return [dict(row[0]) for row in rows]

    def page_records(
        self,
        record_type: str,
        *,
        limit: int,
        offset: int,
        sort_by: str,
        descending: bool,
        filters: dict[str, str] | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Fetch a bounded JSON-record page using a caller-allowlisted field set."""
        if not 1 <= limit <= 100 or not 0 <= offset <= 100_000:
            raise ValueError("page bounds are invalid")
        allowed = {
            "scan": {"started_at", "status", "scanner"},
            "finding": {"severity", "title", "scanner", "category"},
            "case": {"created_at", "updated_at", "status", "severity", "title"},
            "log_job": {"created_at", "status", "source_id"},
            "malware_job": {"created_at", "status", "sample_id"},
        }
        if sort_by not in allowed.get(record_type, set()):
            raise ValueError("record sort field is not allowed")
        conditions = [records.c.record_type == record_type]
        for field, value in (filters or {}).items():
            if field not in allowed.get(record_type, set()):
                raise ValueError("record filter field is not allowed")
            json_value = records.c.payload[field].as_string()
            conditions.append(func.lower(json_value) == value.lower())
        sort_value = records.c.payload[sort_by].as_string()
        if record_type == "finding" and sort_by == "severity":
            sort_value = case(
                (func.lower(sort_value) == "critical", 5),
                (func.lower(sort_value) == "high", 4),
                (func.lower(sort_value) == "medium", 3),
                (func.lower(sort_value) == "low", 2),
                (func.lower(sort_value) == "info", 1),
                else_=0,
            )
        ordering = sort_value.desc() if descending else sort_value.asc()
        with self.engine.connect() as connection:
            total = int(
                connection.execute(
                    select(func.count()).select_from(records).where(*conditions)
                ).scalar_one()
            )
            rows = connection.execute(
                select(records.c.payload)
                .where(*conditions)
                .order_by(ordering, records.c.record_id.asc())
                .limit(limit)
                .offset(offset)
            ).all()
        return [dict(row[0]) for row in rows], total

    @overload
    def count_records(self, record_type: str, *, group_by: None = None) -> int: ...

    @overload
    def count_records(self, record_type: str, *, group_by: str) -> dict[str, int]: ...

    def count_records(
        self, record_type: str, *, group_by: str | None = None
    ) -> int | dict[str, int]:
        """Count records or group by an explicitly supported summary field."""
        allowed_groups = {"finding": {"severity"}, "scan": set()}
        if group_by is None:
            with self.engine.connect() as connection:
                return int(
                    connection.execute(
                        select(func.count())
                        .select_from(records)
                        .where(records.c.record_type == record_type)
                    ).scalar_one()
                )
        if group_by not in allowed_groups.get(record_type, set()):
            raise ValueError("record summary field is not allowed")
        field = func.json_extract(records.c.payload, f"$.{group_by}")
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(field, func.count())
                .where(records.c.record_type == record_type)
                .group_by(field)
            ).all()
        return {str(key): int(cast(Any, count)) for key, count in rows if key is not None}

    def close(self) -> None:
        self.engine.dispose()
