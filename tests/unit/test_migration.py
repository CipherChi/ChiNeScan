from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from chinescan.core.storage.sqlite import SQLiteRepository


def test_initial_migration_creates_records_table(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        assert "records" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_malware_backend_revision_upgrades_existing_records_without_rewrite(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "0001_initial")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO records VALUES ('case', 'legacy', '{\"title\":\"Keep\"}')")
        )
    engine.dispose()

    repository = SQLiteRepository(database)
    try:
        assert repository.get("case", "legacy") == {"title": "Keep"}
        with repository.engine.connect() as connection:
            from alembic.runtime.migration import MigrationContext

            assert (
                MigrationContext.configure(connection).get_current_revision()
                == "0004_dashboard_alerts"
            )
    finally:
        repository.close()
