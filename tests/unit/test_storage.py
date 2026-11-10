import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from chinescan.core.errors import StorageError
from chinescan.core.storage.sqlite import SQLiteRepository


def test_repository_round_trip(repository) -> None:
    repository.save("finding", "one", {"title": "example", "schema_version": "1.0"})
    assert repository.get("finding", "one") == {"title": "example", "schema_version": "1.0"}


def test_repository_updates_existing_record(repository) -> None:
    repository.save("finding", "one", {"title": "old"})
    repository.save("finding", "one", {"title": "new"})
    assert repository.get("finding", "one") == {"title": "new"}


def test_fresh_repository_uses_versioned_schema_from_another_working_directory(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "fresh.sqlite3"
    monkeypatch.chdir(tmp_path)
    repository = SQLiteRepository(path)
    try:
        assert {"records", "alembic_version"} <= set(inspect(repository.engine).get_table_names())
    finally:
        repository.close()


def test_legacy_initial_schema_is_stamped_without_losing_records(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE records (record_type VARCHAR(80) NOT NULL, "
                "record_id VARCHAR(255) NOT NULL, payload JSON NOT NULL, "
                "PRIMARY KEY (record_type, record_id))"
            )
        )
        connection.execute(
            text("INSERT INTO records VALUES ('finding', 'one', :payload)"),
            {"payload": json.dumps({"title": "preserve me"})},
        )
    engine.dispose()

    repository = SQLiteRepository(path)
    try:
        assert repository.get("finding", "one") == {"title": "preserve me"}
        with repository.engine.connect() as connection:
            from alembic.runtime.migration import MigrationContext

            assert (
                MigrationContext.configure(connection).get_current_revision()
                == "0004_dashboard_alerts"
            )
    finally:
        repository.close()


def test_incompatible_existing_schema_is_rejected_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "incompatible.sqlite3"
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE records (unexpected TEXT)"))
        connection.execute(text("INSERT INTO records VALUES ('keep')"))
    engine.dispose()

    with pytest.raises(StorageError, match="not a recognized"):
        SQLiteRepository(path)
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT unexpected FROM records")).scalar_one() == "keep"
            assert "alembic_version" not in inspect(engine).get_table_names()
    finally:
        engine.dispose()
