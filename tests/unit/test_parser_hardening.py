from pathlib import Path

import pytest

from chinescan.chain_trace.providers.offline import MAX_IMPORT_BYTES, OfflineProvider
from chinescan.core.config.io import load_config
from chinescan.core.errors import ConfigurationError
from chinescan.log_analysis.ioc_matching import load_iocs
from chinescan.log_analysis.ingest import ingest_path


def test_ioc_json_deep_nesting_returns_bounded_error(tmp_path: Path) -> None:
    path = tmp_path / "deep.json"
    path.write_text("[" * 10_000 + "0" + "]" * 10_000, encoding="utf-8")
    indicators, errors = load_iocs(path)
    assert indicators == []
    assert errors and len(errors[0]) < 200


def test_chain_json_deep_nesting_returns_bounded_error() -> None:
    payload = "[" * 10_000 + "0" + "]" * 10_000
    with pytest.raises(ValueError, match="invalid|limit|import"):
        OfflineProvider(payload, "ethereum", "json")


def test_indicator_and_chain_oversized_inputs_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    indicator = tmp_path / "large.json"
    indicator.write_text("{}", encoding="utf-8")
    monkeypatch.setattr("chinescan.log_analysis.ioc_matching.MAX_IOC_FILE_BYTES", 1)
    _, errors = load_iocs(indicator)
    assert errors and len(errors[0]) < 200

    with pytest.raises(ValueError, match="2 MB"):
        OfflineProvider("x" * (MAX_IMPORT_BYTES + 1), "ethereum")


def test_log_oversized_input_returns_bounded_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_file = tmp_path / "large.log"
    log_file.write_text("x" * 17, encoding="utf-8")
    monkeypatch.setattr("chinescan.log_analysis.ingest.MAX_FILE_BYTES", 16)
    result = ingest_path(log_file)
    assert result.events == []
    assert result.errors and len(result.errors[0]) < 200


def test_python_yaml_tag_is_rejected_as_data() -> None:
    yaml = pytest.importorskip("yaml")
    with pytest.raises(yaml.YAMLError):
        list(yaml.safe_load_all("!!python/object/apply:os.system ['echo unsafe']"))


def test_config_deep_nesting_fails_with_bounded_error(tmp_path: Path) -> None:
    config = tmp_path / "deep.toml"
    config.write_text("x = " + "[" * 10_000 + "0" + "]" * 10_000, encoding="utf-8")
    with pytest.raises(ConfigurationError) as error:
        load_config(config)
    assert len(str(error.value)) < 200


def test_config_oversized_file_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "large.toml"
    config.write_text("x = '" + "a" * 128 + "'", encoding="utf-8")
    monkeypatch.setattr("chinescan.core.config.io.MAX_CONFIG_BYTES", 64)
    with pytest.raises(ConfigurationError, match="Unable to load configuration"):
        load_config(config)
