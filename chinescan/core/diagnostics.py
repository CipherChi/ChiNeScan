"""Path-free local environment and service diagnostics."""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from re import fullmatch
from typing import Any, Literal
from uuid import UUID

from chinescan import __version__
from chinescan.chain_trace.registry import CHAINS
from chinescan.core.accounts import operator_status
from chinescan.core.config.io import load_settings
from chinescan.core.config.settings import Settings, default_config_path
from chinescan.core.fs_policy import (
    RootValidation,
    policy_paths,
    storage_paths,
    validate_allowed_roots,
)
from chinescan.core.github_import import import_path_at_risk

State = Literal["PASS", "WARN", "FAIL"]
_SAFE_RECORD_STATES = frozenset(
    {
        "active",
        "archived",
        "closed",
        "failed",
        "interrupted",
        "open",
        "partial",
        "queued",
        "resolved",
        "running",
        "succeeded",
        "unknown",
    }
)
_FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


def _check(check_id: str, label: str, state: State, detail: str, hint: str = "") -> dict[str, str]:
    return {"id": check_id, "label": label, "state": state, "detail": detail, "action_hint": hint}


def build_report(
    *,
    settings: Settings | None = None,
    database_path: Path | str | None = None,
    reports_dir: Path | str | None = None,
    credential_path: Path | str | None = None,
    config_path: Path | str | None = None,
    frontend_dist: Path | None = None,
    started_at: float = 0.0,
    errors: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Create diagnostics with logical labels only; never include configured paths."""
    checks: list[dict[str, str]] = []
    loaded = settings
    config_file = (
        Path(config_path)
        if config_path
        else Path(os.environ.get("CHINESCAN_CONFIG_PATH", default_config_path()))
    )
    try:
        if loaded is None:
            overrides: dict[str, object] = {}
            if database_path is not None:
                overrides["database_path"] = Path(database_path)
            if reports_dir is not None:
                overrides["reports_dir"] = Path(reports_dir)
            loaded = load_settings(config_file, cli_overrides=overrides)
        checks.append(
            _check("config", "Configuration", "PASS", "Configuration loaded and validated.")
        )
    except Exception:
        checks.append(
            _check(
                "config",
                "Configuration",
                "FAIL",
                "Configuration could not be loaded.",
                "Review the local configuration and run chinescan config validate.",
            )
        )
        loaded = loaded or Settings.model_validate({})
        config_error = True
    else:
        config_error = False
    db_path = Path(database_path) if database_path else loaded.database_path
    credential = Path(credential_path) if credential_path else config_file.parent / "operator.json"
    credential_state = operator_status(credential)
    credential_schema: str | int | None = None
    try:
        if credential.is_file():
            data = (
                tomllib.loads(credential.read_text(encoding="utf-8"))
                if credential.suffix == ".toml"
                else json.loads(credential.read_text(encoding="utf-8"))
            )
            raw_schema = data.get("schema_version") if isinstance(data, dict) else None
            credential_schema = (
                raw_schema if type(raw_schema) is int and 0 <= raw_schema <= 1000 else None
            )
            credential_check_state: State = (
                "PASS"
                if credential_state == "active"
                else "WARN"
                if credential_state in {"none", "legacy"}
                else "FAIL"
            )
            checks.append(
                _check(
                    "credentials",
                    "Credential store",
                    credential_check_state,
                    "Credential store is present and schema-valid."
                    if credential_check_state == "PASS"
                    else "Credential store requires local setup or migration.",
                    "Create or migrate the local operator credential store."
                    if credential_check_state != "PASS"
                    else "",
                )
            )
        else:
            checks.append(
                _check(
                    "credentials",
                    "Credential store",
                    "WARN",
                    "No local operator credential store is configured.",
                    "Create or recover the local operator account.",
                )
            )
    except (OSError, ValueError, TypeError):
        credential_state = "needs-migration"
        checks.append(
            _check(
                "credentials",
                "Credential store",
                "FAIL",
                "Credential store is unreadable or invalid.",
                "Use the local operator recovery flow.",
            )
        )
    root_valid, root_ignored = 0, 0
    root_reasons: dict[str, int] = {}
    invalid_denied = sum(not path.is_absolute() for path in loaded.extra_denied_paths)
    try:
        hard, soft = policy_paths(loaded)
        validations = loaded.allowed_root_validation
        if not validations:
            _, recalculated_validations = validate_allowed_roots(
                list(loaded.allowed_roots),
                hard_denied=hard,
                soft_denied=soft,
                allow_soft_denied=loaded.allow_soft_denied,
                storage_paths=storage_paths(loaded),
            )
            validations.extend(recalculated_validations)
        for item in validations:
            if isinstance(item, RootValidation):
                if item.valid:
                    root_valid += 1
                else:
                    root_ignored += 1
                    root_reasons[item.reason_code] = root_reasons.get(item.reason_code, 0) + 1
        checks.append(
            _check(
                "filesystem-policy",
                "Filesystem policy",
                "PASS" if root_ignored == 0 and not invalid_denied else "WARN",
                "Allowed roots: "
                + str(root_valid)
                + " valid, "
                + str(root_ignored)
                + " ignored; soft-denied override is "
                + ("enabled" if loaded.allow_soft_denied else "disabled")
                + "; extra deny entries: "
                + str(len(loaded.extra_denied_paths) - invalid_denied)
                + " valid, "
                + str(invalid_denied)
                + " invalid.",
                "Review ignored allowed-root entries and invalid extra deny entries."
                if root_ignored or invalid_denied
                else "",
            )
        )
    except Exception:
        checks.append(
            _check(
                "filesystem-policy",
                "Filesystem policy",
                "FAIL",
                "Filesystem policy validation failed.",
                "Review allowed roots and deny-list configuration.",
            )
        )
    directories = {
        "database directory": db_path.parent,
        "reports directory": loaded.reports_dir,
    }
    dirs_present = all(p.is_dir() for p in directories.values())
    checks.append(
        _check(
            "directories",
            "Required local directories",
            "PASS" if dirs_present else "FAIL",
            "Required directories are present."
            if dirs_present
            else "One or more required local directories are missing.",
            "Create the configured local data directories." if not dirs_present else "",
        )
    )
    db_ok = False
    try:
        if not db_path.is_file():
            raise OSError("database is not present")
        if not os.access(db_path, os.W_OK) or not os.access(db_path.parent, os.W_OK):
            raise PermissionError("database write access is unavailable")
        with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True) as connection:
            connection.execute("BEGIN")
            connection.execute("SELECT 1").fetchone()
            connection.execute("CREATE TEMP TABLE chinescan_diagnostics_probe (value INTEGER)")
            connection.execute("INSERT INTO chinescan_diagnostics_probe VALUES (1)")
            connection.execute("DELETE FROM chinescan_diagnostics_probe")
            counts: dict[str, Any] = {}
            for kind in ("project", "project_log_location", "code_job", "log_job", "malware_job"):
                grouped: dict[str, int] = {}
                rows = connection.execute(
                    "SELECT payload FROM records WHERE record_type = ?", (kind,)
                ).fetchall()
                for row in rows:
                    record = json.loads(str(row[0]))
                    stored_state = str(record.get("status", "unknown"))
                    state = stored_state if stored_state in _SAFE_RECORD_STATES else "other"
                    grouped[state] = grouped.get(state, 0) + 1
                counts[kind] = grouped
            connection.rollback()
        db_ok = True
    except Exception:
        counts = {
            kind: {}
            for kind in ("project", "project_log_location", "code_job", "log_job", "malware_job")
        }
    checks.append(
        _check(
            "database",
            "Local database",
            "PASS" if db_ok else "FAIL",
            "Database read and transactional write probe succeeded."
            if db_ok
            else "Database access or schema validation failed.",
            "Check local database availability and permissions." if not db_ok else "",
        )
    )
    dist = frontend_dist or _FRONTEND_DIST
    checks.append(
        _check(
            "frontend",
            "Frontend build",
            "PASS" if dist.is_dir() else "FAIL",
            "Frontend build is present." if dist.is_dir() else "Frontend build is unavailable.",
            "Build the frontend with npm run build." if not dist.is_dir() else "",
        )
    )
    managed = (
        loaded.malware_managed_directory is not None and loaded.malware_managed_directory.is_dir()
    )
    checks.append(
        _check(
            "managed-malware",
            "Managed malware storage",
            "PASS" if managed else "WARN",
            "Managed malware storage is configured."
            if managed
            else "Managed malware storage is not configured; project scans remain available.",
            "Configure managed malware storage only if local sample triage is needed."
            if not managed
            else "",
        )
    )
    try:
        database_size = db_path.stat().st_size
    except OSError:
        database_size = 0
    size_bucket = (
        "empty"
        if database_size == 0
        else "under_10_mb"
        if database_size < 10_000_000
        else "10_to_100_mb"
        if database_size < 100_000_000
        else "over_100_mb"
    )
    checks.append(
        _check(
            "offline",
            "Offline readiness",
            "PASS",
            "Core local workflows require no network access; "
            "optional audits and domain checks are opt-in.",
        )
    )
    uv_version = _tool_version("uv", "--version")
    checks.append(
        _check(
            "uv",
            "uv",
            "PASS" if uv_version else "WARN",
            "uv is available: " + uv_version if uv_version else "uv is unavailable.",
            "Install uv to run project commands." if not uv_version else "",
        )
    )
    node_version = _tool_version("node", "--version")
    npm_version = _tool_version("npm", "--version")
    checks.append(
        _check(
            "node-npm",
            "Node.js and npm",
            "PASS" if node_version and npm_version else "WARN",
            "Node "
            + (node_version or "unavailable")
            + "; npm "
            + (npm_version or "unavailable")
            + ".",
            "Install Node.js and npm to build the dashboard."
            if not node_version or not npm_version
            else "",
        )
    )
    frontend_root = Path(__file__).resolve().parents[2] / "frontend"
    node_modules = frontend_root / "node_modules"
    dependency_issues = _npm_dependency_issues(frontend_root / "package-lock.json", node_modules)
    dependencies_ready = dependency_issues == []
    checks.append(
        _check(
            "frontend-dependencies",
            "Frontend dependencies",
            "PASS" if dependencies_ready else "WARN",
            "Local frontend dependency installation is present."
            if dependencies_ready
            else _frontend_dependency_detail(dependency_issues),
            "Run npm ci in the frontend directory when preparing a local build."
            if not dependencies_ready
            else "",
        )
    )
    for port in (5173, 8765):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                port_state = "listening"
        except OSError:
            port_state = "free"
        checks.append(
            _check(
                f"port-{port}",
                f"Loopback port {port}",
                "WARN" if port_state == "listening" else "PASS",
                f"Port is {port_state}"
                + (" (potential conflict)" if port_state == "listening" else "")
                + "; no process was changed.",
                "Review the existing local listener if it conflicts with your intended service."
                if port_state == "listening"
                else "",
            )
        )
    venv_environment = os.environ.get("UV_PROJECT_ENVIRONMENT")
    current_venv = Path(sys.prefix)
    repository_root = Path(__file__).resolve().parents[2]
    uv_environment_path = Path(venv_environment).resolve() if venv_environment else None
    broken_venv = (
        current_venv != Path(sys.base_prefix) and not (current_venv / "pyvenv.cfg").is_file()
    ) or bool(
        uv_environment_path
        and (
            not uv_environment_path.is_relative_to(repository_root)
            or not (uv_environment_path / "pyvenv.cfg").is_file()
        )
    )
    checks.append(
        _check(
            "python-environment",
            "Python environment",
            "FAIL" if broken_venv else "PASS",
            "Python environment looks usable."
            if not broken_venv
            else "Python environment configuration points outside the repository "
            "or lacks pyvenv.cfg.",
            "Unset UV_PROJECT_ENVIRONMENT or point it at the repository environment, "
            "then recreate it."
            if broken_venv
            else "",
        )
    )
    deny_counts = {
        "hard": len(policy_paths(loaded)[0]),
        "soft": len(policy_paths(loaded)[1]),
        "extra": len(loaded.extra_denied_paths),
    }
    git_available = shutil.which("git") is not None
    github_import_root = db_path.expanduser().resolve(strict=False).parent / "gh"
    github_path_at_risk = import_path_at_risk(github_import_root)
    github_import_warn = loaded.github_import_enabled and (not git_available or github_path_at_risk)
    checks.append(
        _check(
            "github-import",
            "GitHub import",
            "WARN" if github_import_warn else "PASS",
            "Import is enabled and Git is available."
            if loaded.github_import_enabled and git_available and not github_path_at_risk
            else "Import is enabled but Git is unavailable."
            if loaded.github_import_enabled and not git_available
            else (
                "Import is enabled, but the managed import path is at risk of exceeding the "
                "Windows path limit."
            )
            if loaded.github_import_enabled and github_path_at_risk
            else "Import is disabled; Git availability is informational only.",
            "Install Git to use public repository imports."
            if loaded.github_import_enabled and not git_available
            else (
                "Use a shorter data directory so managed repository paths stay below the "
                "Windows path limit."
            )
            if loaded.github_import_enabled and github_path_at_risk
            else "",
        )
    )
    chain_key_env = next(
        (chain.api_key_env for chain in CHAINS.values() if chain.family == "evm"), ""
    )
    chain_key_configured = bool(chain_key_env and os.getenv(chain_key_env))
    chain_warn = loaded.chain_network_enabled and not chain_key_configured
    checks.append(
        _check(
            "chain-trace",
            "On-chain tracing",
            "WARN" if chain_warn else "PASS",
            "enabled="
            + str(loaded.chain_network_enabled).lower()
            + "; provider_key_configured="
            + str(chain_key_configured).lower(),
            "Set the configured provider key environment variable to enable network traces."
            if chain_warn
            else "",
        )
    )
    report: dict[str, Any] = {
        "status": "ok",
        "app_name": "ChiNeScan",
        "version": __version__,
        "python_version": platform.python_version(),
        "platform": platform.system(),
        "config_status": "invalid" if config_error else "valid",
        "storage_status": "available" if db_ok else "unavailable",
        "operator_state": credential_state,
        "credential_schema_version": credential_schema,
        "allowed_roots": {
            "valid": root_valid,
            "ignored": root_ignored,
            "reason_codes": root_reasons,
        },
        "deny_list_tiers": deny_counts,
        "storage_size_bucket": size_bucket,
        "github_import_enabled": loaded.github_import_enabled,
        "chain_network_enabled": loaded.chain_network_enabled,
        "chain_provider_key_configured": chain_key_configured,
        "github_import_git_available": git_available,
        "github_import_path_budget": "at-risk" if github_path_at_risk else "ok",
        "scan_bounds": {
            "max_files": loaded.max_files,
            "max_total_bytes": loaded.max_total_bytes,
            "max_file_bytes": loaded.max_file_bytes,
            "max_depth": loaded.max_depth,
            "job_deadline_seconds": loaded.job_deadline_seconds,
        },
        "counts": counts,
        "recent_errors": _safe_error_summaries(errors or []),
        "checks": checks,
        "optional_network_features": [
            "pip-audit",
            "npm audit",
            "domain posture checks",
            "on-chain tracing",
        ],
    }
    states = {item["state"] for item in checks}
    report["status"] = "failed" if "FAIL" in states else "degraded" if "WARN" in states else "ok"
    return report


def _tool_version(command: str, argument: str) -> str:
    executable = shutil.which(command)
    if executable is None:
        return ""
    try:
        result = subprocess.run(
            [executable, argument], capture_output=True, text=True, timeout=3, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip()[:80] if result.returncode == 0 else ""


def _safe_error_summaries(errors: list[dict[str, str]]) -> list[dict[str, str]]:
    summaries: list[dict[str, str]] = []
    for item in errors[-50:]:
        code = item.get("error_code", "")
        error_code = code if fullmatch(r"http_[1-5][0-9]{2}", code) else "http_error"
        raw_route = item.get("route", "unmatched")
        route = (
            raw_route[:120]
            if raw_route.startswith("/api/")
            and ".." not in raw_route
            and fullmatch(r"[A-Za-z0-9_/{}/.\-]+", raw_route)
            else "unmatched"
        )
        try:
            request_id = str(UUID(item.get("request_id", "")))
        except ValueError:
            request_id = "unknown"
        try:
            timestamp = (
                datetime.fromisoformat(item.get("timestamp", "")).astimezone(UTC).isoformat()
            )
        except ValueError:
            timestamp = datetime.now(UTC).isoformat()
        message = (
            "Request could not be completed."
            if error_code.startswith("http_5")
            else "Request was rejected."
        )
        summaries.append(
            {
                "error_code": error_code,
                "route": route,
                "request_id": request_id,
                "timestamp": timestamp,
                "message": message,
            }
        )
    return summaries


def _npm_dependency_issues(package_lock: Path, node_modules: Path) -> list[str] | None:
    """Return mismatched top-level package names, or None when inputs are absent/invalid."""
    if not node_modules.is_dir() or not package_lock.is_file():
        return None
    try:
        expected = json.loads(package_lock.read_text(encoding="utf-8"))
        expected_packages = expected.get("packages", {})
        if not isinstance(expected_packages, dict):
            return None
        dependency_paths = [
            name
            for name in expected_packages
            if isinstance(name, str)
            and _is_top_level_node_module(name)
            and _npm_package_applies(expected_packages[name])
        ][:2000]
        issues: list[str] = []
        for package_path in dependency_paths:
            package = expected_packages[package_path]
            package_name = package_path.removeprefix("node_modules/")
            if not isinstance(package, dict) or not isinstance(package.get("version"), str):
                issues.append(package_name)
                continue
            installed_path = node_modules.joinpath(*package_path.split("/")[1:])
            try:
                installed_package = json.loads(
                    (installed_path / "package.json").read_text(encoding="utf-8")
                )
                if (
                    not isinstance(installed_package, dict)
                    or installed_package.get("version") != package["version"]
                ):
                    issues.append(package_name)
            except (OSError, TypeError, ValueError):
                issues.append(package_name)
        if len(expected_packages) > len(dependency_paths) and len(dependency_paths) == 2000:
            issues.append("additional packages beyond check limit")
        return issues
    except (OSError, TypeError, ValueError):
        return None


def _is_top_level_node_module(package_path: str) -> bool:
    parts = package_path.split("/")
    if len(parts) < 2 or parts[0] != "node_modules":
        return False
    package_parts = parts[1:]
    if any(part in {"", ".", ".."} or "\\" in part for part in package_parts):
        return False
    return len(package_parts) == (2 if package_parts[0].startswith("@") else 1)


def _npm_package_applies(package: object) -> bool:
    """Skip optional packages that npm excludes for the current OS or CPU."""
    if not isinstance(package, dict) or not package.get("optional"):
        return True
    system_names = {"Windows": "win32", "Darwin": "darwin", "Linux": "linux"}
    system = system_names.get(platform.system(), platform.system().lower())
    machine_names = {
        "AMD64": "x64",
        "x86_64": "x64",
        "aarch64": "arm64",
        "i386": "ia32",
    }
    machine = machine_names.get(platform.machine(), platform.machine().lower())
    for field, current in (("os", system), ("cpu", machine)):
        constraints = package.get(field)
        if not isinstance(constraints, list):
            continue
        positive = [
            item for item in constraints if isinstance(item, str) and not item.startswith("!")
        ]
        negative = [
            item[1:] for item in constraints if isinstance(item, str) and item.startswith("!")
        ]
        if positive and current not in positive or current in negative:
            return False
    return True


def _frontend_dependency_detail(issues: list[str] | None) -> str:
    if issues is None:
        return "Frontend dependencies or package lock are unavailable; no network check was run."
    if not issues:
        return "Local frontend dependency installation is present."
    return (
        f"Frontend dependencies have {len(issues)} missing or mismatched packages; "
        "no network check was run."
    )


def health_report(*, started_at: float, bind_address: str = "127.0.0.1") -> dict[str, Any]:
    import time

    return {
        "status": "ok",
        "app_name": "ChiNeScan",
        "version": __version__,
        "uptime_seconds": max(0, int(time.monotonic() - started_at)),
        "bind_address": bind_address,
        "timestamp": datetime.now(UTC).isoformat(),
    }
