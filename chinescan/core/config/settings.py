"""Typed application settings and CHINESCAN_ environment overrides."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, cast

from pydantic import Field, PrivateAttr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def default_config_path() -> Path:
    return Path.home() / ".config" / "chinescan" / "config.toml"


def default_data_path() -> Path:
    return Path.home() / ".local" / "share" / "chinescan" / "chinescan.sqlite3"


def default_reports_path() -> Path:
    return Path.home() / ".local" / "share" / "chinescan" / "reports"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CHINESCAN_", extra="ignore")
    database_path: Path = Field(default_factory=default_data_path)
    reports_dir: Path = Field(default_factory=default_reports_path)
    malware_managed_directory: Path | None = None
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    api_token: str | None = Field(default=None, repr=False)
    session_idle_ttl_seconds: int = Field(default=900, ge=60, le=86_400)
    auth_rate_limit: int = Field(default=60, ge=1, le=10_000)
    job_start_rate_limit: int = Field(default=120, ge=1, le=10_000)
    export_rate_limit: int = Field(default=240, ge=1, le=10_000)
    read_rate_limit: int = Field(default=1000, ge=1, le=100_000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600)
    trusted_proxy: bool = False
    allowed_roots: list[Path] = Field(default_factory=list)
    extra_denied_paths: list[Path] = Field(default_factory=list)
    allow_soft_denied: bool = False
    github_import_enabled: bool = False
    chain_network_enabled: bool = False
    chain_labels_path: Path | None = None
    chain_trace_deadline_seconds: int = Field(default=120, ge=1, le=600)
    chain_trace_max_requests: int = Field(default=100, ge=1, le=10_000)
    chain_trace_max_addresses: int = Field(default=500, ge=1, le=5000)
    github_import_timeout_seconds: int = Field(default=120, ge=1, le=600)
    github_import_max_bytes: int = Field(default=524_288_000, ge=1, le=10_737_418_240)
    github_import_max_files: int = Field(default=50_000, ge=1, le=1_000_000)
    github_import_max_projects: int = Field(default=20, ge=1, le=10_000)
    max_files: int = 50_000
    max_total_bytes: int = 1_073_741_824
    max_file_bytes: int = 16_777_216
    max_depth: int = 32
    per_file_seconds: float = 2.0
    job_deadline_seconds: int = 300
    code_excluded_paths: list[str] = Field(default_factory=list)
    malware_max_files: int = 50_000
    malware_max_total_bytes: int = 1_073_741_824
    malware_max_file_bytes: int = 16_777_216
    malware_max_depth: int = 32
    malware_per_file_seconds: float = 2.0
    malware_job_deadline_seconds: int = 300
    malware_known_bad_hashes: Path | None = None
    malware_rules_directory: Path | None = None
    data_source: Literal["real", "simulation"] = "real"
    _allowed_root_validation: list[object] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def validate_configured_roots(self) -> Settings:
        from chinescan.core.fs_policy import (
            policy_paths,
            storage_paths,
            validate_allowed_roots,
        )

        hard, soft = policy_paths(self)
        roots, statuses = validate_allowed_roots(
            list(self.allowed_roots),
            hard_denied=hard,
            soft_denied=soft,
            allow_soft_denied=self.allow_soft_denied,
            storage_paths=storage_paths(self),
        )
        self.allowed_roots = roots
        self._allowed_root_validation = cast(list[object], statuses)
        return self

    @property
    def allowed_root_validation(self) -> list[object]:
        """Path-free validation statuses for roots supplied at configuration load."""
        return list(self._allowed_root_validation)
