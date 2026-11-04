"""TOML configuration utilities."""

import os
import re
import tomllib
from pathlib import Path

import tomli_w

from chinescan.core.config.settings import Settings, default_config_path
from chinescan.core.errors import ConfigurationError

MAX_CONFIG_BYTES = 1_048_576


def init_config(path: Path | None = None) -> Path:
    target = path or default_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise ConfigurationError(f"Configuration already exists: {target}")
    defaults = {
        "database_path": str(Settings().database_path),
        "reports_dir": str(Settings().reports_dir),
        "log_level": "INFO",
    }
    try:
        with target.open("x", encoding="utf-8") as stream:
            stream.write(tomli_w.dumps(defaults))
    except FileExistsError as exc:
        raise ConfigurationError(f"Configuration already exists: {target}") from exc
    return target


def load_config(path: Path) -> Settings:
    """Load file settings with environment values overriding the file."""
    return load_settings(path)


def load_settings(
    config_path: Path | None = None, *, cli_overrides: dict[str, object] | None = None
) -> Settings:
    """Resolve defaults < TOML file < environment < explicit CLI values."""
    configured_path = os.environ.get("CHINESCAN_CONFIG_PATH")
    target = config_path or Path(configured_path or default_config_path())
    try:
        if (config_path is not None or configured_path is not None) and not target.is_file():
            raise OSError("selected config file does not exist")
        if target.exists() and target.stat().st_size > MAX_CONFIG_BYTES:
            raise OSError("configuration exceeds size limit")
        data = tomllib.loads(target.read_text(encoding="utf-8")) if target.exists() else {}
        for key in Settings.model_fields:
            env_name = f"CHINESCAN_{key.upper()}"
            if env_name in os.environ:
                data[key] = os.environ[env_name]
        data.update(cli_overrides or {})
        return Settings(_env_file=None, **data)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        detail = "check the file and setting values."
        if isinstance(exc, RecursionError):
            detail = "configuration nesting exceeds the supported depth."
        if isinstance(exc, tomllib.TOMLDecodeError):
            location = re.search(r"\(at line (\d+), column (\d+)\)$", str(exc))
            if location is not None:
                detail = (
                    f"check TOML syntax near line {location.group(1)}, column {location.group(2)}."
                )
            else:
                detail = "check TOML syntax."
        raise ConfigurationError(
            f"Unable to load configuration ({type(exc).__name__}); {detail}"
        ) from exc


def validate_config(path: Path) -> Settings:
    if not path.is_file():
        raise ConfigurationError(f"Configuration does not exist: {path}")
    return load_config(path)
