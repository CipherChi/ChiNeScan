from pathlib import Path

import pytest

from chinescan.core.storage.sqlite import SQLiteRepository


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("real scanner integration")
    group.addoption(
        "--run-real-scanners",
        action="store_true",
        default=False,
        help="run opt-in tests against installed real scanner binaries",
    )
    group.addoption(
        "--require-real-scanners",
        action="store_true",
        default=False,
        help="run real scanner tests and fail when required tools/assets are missing",
    )


def pytest_configure(config: pytest.Config) -> None:
    basetemp = config.option.basetemp
    if basetemp is not None:
        repository_root = Path(__file__).resolve().parents[1]
        resolved_basetemp = Path(basetemp).resolve()
        if resolved_basetemp == repository_root or repository_root in resolved_basetemp.parents:
            raise pytest.UsageError(
                "--basetemp must resolve outside the repository; use the OS temp directory"
            )
    config.addinivalue_line(
        "markers", "real_scanner: opt-in integration tests that execute real scanner binaries"
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-real-scanners") or config.getoption("--require-real-scanners"):
        return
    deselected = [item for item in items if "real_scanner" in item.keywords]
    items[:] = [item for item in items if "real_scanner" not in item.keywords]
    config.hook.pytest_deselected(items=deselected)


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    return tmp_path / "config.toml"


@pytest.fixture
def repository(tmp_path: Path) -> SQLiteRepository:
    repo = SQLiteRepository(tmp_path / "records.sqlite3")
    yield repo
    repo.close()


@pytest.fixture(autouse=True)
def isolated_reports_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHINESCAN_REPORTS_DIR", str(tmp_path / "auto-reports"))
