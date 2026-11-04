"""Project records, legacy project configuration and project-scoped operations."""

from __future__ import annotations

import builtins
import os
import shutil
import stat
import tomllib
import unicodedata
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chinescan.core.fs_policy import (
    FilesystemBrowserService,
    PathDecision,
    decide_path,
    folder_approval_decision,
    folder_approval_error,
)
from chinescan.core.storage.sqlite import SQLiteRepository


class ProjectError(ValueError):
    """Safe project operation error with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _name_key(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().casefold()


def _canonical_directory(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ProjectError("invalid_root", "Choose an absolute local directory.")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProjectError(
            "root_unavailable", "The selected project folder is unavailable."
        ) from exc
    if not resolved.is_dir():
        raise ProjectError("not_a_directory", "The selected project must be a folder.")
    return resolved


class ProjectFileRegistry:
    """Read-only adapter for legacy projects.toml entries."""

    def __init__(self, config_path: Path | str | None, protected: list[Path]) -> None:
        self.config_path = Path(config_path).expanduser() if config_path else None
        self.protected = [path.resolve(strict=False) for path in protected]

    def list(self) -> list[dict[str, str]]:
        if (
            self.config_path is None
            or not self.config_path.is_file()
            or _has_link_component(self.config_path)
        ):
            return []
        try:
            raw = tomllib.loads(self.config_path.read_text(encoding="utf-8"))
            if set(raw) - {"projects", "protected_paths"}:
                return []
            protected = [*self.protected, *_configured_protected(raw)]
            entries = raw.get("projects", [])
            if not isinstance(entries, list):
                return []
            result = []
            seen: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {"id", "name", "root"}:
                    continue
                project_id, name = entry["id"], entry["name"]
                if (
                    not isinstance(project_id, str)
                    or not project_id
                    or len(project_id) > 80
                    or project_id in seen
                    or not isinstance(name, str)
                    or not 1 <= len(name) <= 120
                ):
                    continue
                seen.add(project_id)
                try:
                    root = _canonical_directory(entry["root"])
                    self._check_protected(root, protected)
                except (TypeError, ProjectError):
                    continue
                result.append(
                    {
                        "project_id": project_id,
                        "name": name,
                        "display_name": name,
                        "root": str(root),
                    }
                )
            return result
        except (OSError, ValueError, TypeError):
            return []

    def resolve(self, project_id: str) -> tuple[str, Path]:
        item = next((row for row in self.list() if row["project_id"] == project_id), None)
        if item is None:
            raise ProjectError("project_unavailable", "The configured project is unavailable.")
        return item["name"], Path(item["root"])

    def _check_protected(self, root: Path, protected: Sequence[Path]) -> None:
        for item in protected:
            if root == item or root in item.parents or item in root.parents:
                raise ProjectError(
                    "protected_root", "The project overlaps protected application data."
                )


def _has_link_component(path: Path) -> bool:
    try:
        current = Path(path.absolute().anchor)
        for part in path.absolute().parts[1:]:
            current /= part
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                break
            if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
                return True
            if os.name == "nt" and getattr(metadata, "st_file_attributes", 0) & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            ):
                return True
        return False
    except (OSError, RuntimeError, ValueError):
        return True


def safe_project_tree(root: Path) -> bool:
    """Reject links and reparse entries anywhere in the selected code tree."""
    try:
        canonical = _canonical_directory(root)
        for directory, dirs, files in os.walk(canonical, followlinks=False):
            current = Path(directory)
            for name in [*dirs, *files]:
                child = current / name
                if _has_link_component(child):
                    return False
                if child.resolve(strict=True).parent != current.resolve(strict=True):
                    return False
        return True
    except (OSError, RuntimeError, ProjectError):
        return False


def _configured_protected(raw: dict[str, Any]) -> list[Path]:
    value = raw.get("protected_paths", [])
    if not isinstance(value, list):
        raise ValueError
    result = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError
        path = Path(item).expanduser()
        if not path.is_absolute() or _has_link_component(path):
            raise ValueError
        result.append(path.resolve(strict=False))
    return result


class ProjectService:
    """SQLite-backed projects and safe bridges to folder selections and code jobs."""

    def __init__(
        self,
        repository: SQLiteRepository,
        browser: FilesystemBrowserService,
        legacy: ProjectFileRegistry,
        *,
        allowed_roots: list[Path],
        hard_denied: list[Path],
        soft_denied: list[Path],
        allow_soft_denied: bool,
        managed_import_directory: Path | None = None,
    ) -> None:
        self.repository = repository
        self.browser = browser
        self.legacy = legacy
        self.allowed_roots = list(allowed_roots)
        self.hard_denied = list(hard_denied)
        self.soft_denied = list(soft_denied)
        self.allow_soft_denied = allow_soft_denied
        self.managed_import_directory = (
            managed_import_directory.expanduser().absolute()
            if managed_import_directory is not None
            else None
        )

    def decision(self, path: str | Path) -> PathDecision:
        github_item = self._github_item_for_path(path)
        if github_item is not None:
            return self._github_decision(path, github_item)
        return decide_path(
            path,
            allowed_roots=self.allowed_roots or [Path(path)],
            hard_denied=self.hard_denied,
            soft_denied=self.soft_denied,
            allow_soft_denied=self.allow_soft_denied or not self.allowed_roots,
            require_allowed_root=True,
        )

    def github_project_count(self) -> int:
        return sum(item.get("kind") == "github" for item in self.repository.list_records("project"))

    def _github_item_for_path(self, path: str | Path) -> dict[str, Any] | None:
        try:
            candidate = Path(path).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            return None
        for item in self.repository.list_records("project"):
            if item.get("kind") != "github":
                continue
            try:
                root = Path(str(item["root"])).resolve(strict=False)
                candidate.relative_to(root)
                return item
            except (KeyError, OSError, RuntimeError, ValueError):
                continue
        return None

    def _github_decision(self, path: str | Path, item: dict[str, Any]) -> PathDecision:
        try:
            target = Path(path).expanduser().resolve(strict=True)
            managed = _canonical_directory(self.managed_import_directory or Path())
            root = Path(str(item["root"])).resolve(strict=True)
            target.relative_to(root)
            root.relative_to(managed)
            if _has_link_component(target) or not safe_project_tree(root):
                raise ValueError
            return PathDecision(True, "managed-github", "allowed", target)
        except (OSError, RuntimeError, ValueError, ProjectError, KeyError):
            return PathDecision(False, "denied", "managed_import_invalid")

    def _verified_github_candidate(self, root: Path, job_id: str) -> Path:
        if not job_id or self.managed_import_directory is None:
            raise ProjectError("clone_delete_refused", "The verified import is unavailable.")
        try:
            managed = _canonical_directory(self.managed_import_directory)
            candidate = _canonical_directory(root)
            candidate.relative_to(managed)
            if (
                candidate.parent != managed
                or not candidate.is_dir()
                or not safe_project_tree(candidate)
            ):
                raise ValueError
            return candidate
        except (OSError, RuntimeError, ValueError, ProjectError) as exc:
            raise ProjectError(
                "clone_delete_refused", "The managed import is unavailable."
            ) from exc

    def _delete_verified_github_clone(self, root: Path) -> None:
        verified = self._verified_github_candidate(root, "managed")
        shutil.rmtree(verified)

    def register_github_import(
        self,
        *,
        name: str,
        root: Path,
        origin_url: str,
        commit_sha: str,
        fetched_at: str,
        import_job_id: str,
        max_projects: int,
        replace_project_id: str | None = None,
        replace_confirmation: str | None = None,
    ) -> str:
        normalized = unicodedata.normalize("NFKC", name).strip()
        if not 1 <= len(normalized) <= 120 or any(ord(char) < 32 for char in normalized):
            raise ProjectError("invalid_name", "Project name must be 1 to 120 characters.")
        verified_root = self._verified_github_candidate(root, import_job_id)
        existing = self._stored(replace_project_id) if replace_project_id else None
        if replace_project_id:
            if (
                existing is None
                or existing.get("kind") != "github"
                or existing.get("origin_url") != origin_url
            ):
                raise ProjectError(
                    "replace_unavailable", "Choose the matching GitHub project to replace."
                )
            if replace_confirmation != existing.get("name"):
                raise ProjectError(
                    "confirmation_mismatch", "Type the project name exactly to confirm replacement."
                )
            old_root = self._verified_github_candidate(
                Path(str(existing["root"])), str(existing.get("import_job_id", ""))
            )
            updated = {
                **existing,
                "root": str(verified_root),
                "origin_url": origin_url,
                "commit_sha": commit_sha,
                "fetched_at": fetched_at,
                "import_job_id": import_job_id,
            }
            self.repository.save("project", str(existing["project_id"]), updated)
            try:
                self._delete_verified_github_clone(old_root)
            except (OSError, ValueError) as exc:
                self.repository.save("project", str(existing["project_id"]), existing)
                raise ProjectError(
                    "clone_delete_refused",
                    "The previous managed import could not be removed safely.",
                ) from exc
            return str(existing["project_id"])
        if self.github_project_count() >= max_projects:
            raise ProjectError("project_limit", "The configured GitHub project limit was reached.")
        if any(
            _name_key(str(item.get("name", ""))) == _name_key(normalized)
            for item in self._all_internal_and_file()
        ):
            raise ProjectError("duplicate_name", "A project with that name already exists.")
        project_id = str(uuid.uuid4())
        item = {
            "project_id": project_id,
            "name": normalized,
            "kind": "github",
            "root": str(verified_root),
            "origin_url": origin_url,
            "commit_sha": commit_sha,
            "fetched_at": fetched_at,
            "import_job_id": import_job_id,
            "configured_by": "ui",
            "created_at": _now(),
            "last_scan_refs": [],
        }
        self.repository.save("project", project_id, item)
        return project_id

    def create_from_selection(self, name: str, session: str, directory_id: str) -> dict[str, Any]:
        root = self.browser.resolve_selection(session, "project_directory", directory_id)
        return self.create(name, root)

    def create_from_folder_approval(
        self, session: str, directory_id: str, name: str | None = None
    ) -> dict[str, Any]:
        root = self.browser.resolve_folder_approval(session, directory_id)
        return self.create(name or root.name, root)

    def create(self, name: str, root: str | Path) -> dict[str, Any]:
        normalized = unicodedata.normalize("NFKC", name).strip()
        if not 1 <= len(normalized) <= 120 or any(ord(char) < 32 for char in normalized):
            raise ProjectError("invalid_name", "Project name must be 1 to 120 characters.")
        decision = folder_approval_decision(
            root,
            allowed_roots=self.allowed_roots,
            hard_denied=self.hard_denied,
            soft_denied=self.soft_denied,
            allow_soft_denied=self.allow_soft_denied,
        )
        if not decision.allowed or decision.path is None or not decision.path.is_dir():
            raise ProjectError(decision.reason_code, folder_approval_error(decision.reason_code))
        if any(
            _name_key(item["name"]) == _name_key(normalized)
            for item in self._all_internal_and_file()
        ):
            raise ProjectError("duplicate_name", "A project with that name already exists.")
        project_id = str(uuid.uuid4())
        item: dict[str, Any] = {
            "project_id": project_id,
            "name": normalized,
            "kind": "local",
            "root": str(decision.path),
            "configured_by": "dashboard",
            "created_at": _now(),
            "last_scan_refs": [],
        }
        self.repository.save("project", project_id, item)
        return self._public(item)

    def list(self) -> list[dict[str, Any]]:
        stored = self.repository.list_records("project")
        file_items = self.legacy.list()
        by_id = {item["project_id"]: item for item in stored}
        for item in file_items:
            if item["project_id"] not in by_id:
                by_id[item["project_id"]] = {
                    "project_id": item["project_id"],
                    "name": item["name"],
                    "kind": "local",
                    "root": item["root"],
                    "configured_by": "file",
                    "created_at": "",
                    "last_scan_refs": [],
                }
        scans = self.repository.list_records("scan")
        summaries = []
        for item in sorted(by_id.values(), key=lambda p: _name_key(p["name"])):
            refs = sorted(
                (row for row in scans if row.get("project_id") == item["project_id"]),
                key=lambda row: str(row.get("started_at", "")),
                reverse=True,
            )
            summary = self._summary(item)
            summary["last_scan_refs"] = [str(row["scan_id"]) for row in refs[:10]]
            summary["last_scan"] = (
                summary["last_scan_refs"][0] if summary["last_scan_refs"] else None
            )
            summaries.append(summary)
        return summaries

    def get(self, project_id: str) -> dict[str, Any]:
        item = self._stored(project_id)
        if item is None:
            legacy = next(
                (row for row in self.legacy.list() if row["project_id"] == project_id), None
            )
            if legacy is None:
                raise ProjectError("project_not_found", "Project not found.")
            item = {
                "project_id": project_id,
                "name": legacy["name"],
                "kind": "local",
                "root": legacy["root"],
                "configured_by": "file",
                "created_at": "",
                "last_scan_refs": [],
            }
        scans = [
            row
            for row in self.repository.list_records("scan")
            if row.get("project_id") == project_id
        ]
        scans.sort(key=lambda row: str(row.get("started_at", "")), reverse=True)
        scan_ids = {str(row.get("scan_id")) for row in scans}
        from chinescan.core.models.investigation import Alert, Event, TimelineEntry

        alert_ids = [identifier for scan in scans for identifier in scan.get("alert_ids", [])]
        event_ids = [identifier for scan in scans for identifier in scan.get("event_ids", [])]
        timeline_ids = [
            identifier for scan in scans for identifier in scan.get("timeline_entry_ids", [])
        ]
        alerts = self.repository.get_many("alert", alert_ids)
        events = self.repository.get_many("event", event_ids)
        timeline_entries = self.repository.get_many("timeline_entry", timeline_ids)
        findings = [
            row
            for row in self.repository.list_records("finding")
            if row.get("project_id") == project_id
        ]
        cases = [
            row
            for row in self.repository.list_records("case")
            if scan_ids.intersection(str(scan_id) for scan_id in row.get("scan_ids", []))
        ]
        jobs = [
            row
            for row in self.repository.list_records("code_job")
            if row.get("project_id") == project_id
        ]
        jobs.sort(key=lambda row: str(row.get("created_at", "")), reverse=True)
        malware_jobs = [
            row
            for row in self.repository.list_records("project_malware_job")
            if row.get("project_id") == project_id
        ]
        malware_jobs.sort(key=lambda row: str(row.get("created_at", "")), reverse=True)
        return {
            **self._summary(item),
            "origin_label": "This device" if item.get("kind") == "local" else "GitHub",
            "last_scan_refs": [row["scan_id"] for row in scans[:10]],
            "recent_scans": [self._safe_scan(row) for row in scans[:10]],
            "recent_jobs": [self._safe_job(row) for row in jobs[:10]],
            "malware_jobs": [
                {
                    key: row.get(key)
                    for key in (
                        "job_id",
                        "project_id",
                        "status",
                        "profile",
                        "created_at",
                        "started_at",
                        "finished_at",
                        "scan_id",
                        "finding_count",
                        "files_seen",
                        "skipped_counts",
                        "coverage_notes",
                        "error_code",
                        "error",
                    )
                }
                for row in malware_jobs[:10]
            ],
            "findings_count": len(findings),
            "findings": [self._safe_finding(row) for row in findings[:100]],
            "linked_cases": [self._safe_case(row) for row in cases[:50]],
            "log_locations": [
                {
                    key: location[key]
                    for key in ("location_id", "project_id", "name", "scope", "created_at")
                }
                for location in item.get("log_locations", [])
            ],
            "log_alerts": [
                Alert.model_validate(alerts[item]).model_dump(mode="json")
                for item in alert_ids
                if item in alerts
            ][:100],
            "log_events": [
                Event.model_validate(events[item]).model_dump(mode="json", exclude={"raw_ref"})
                for item in event_ids
                if item in events
            ][:100],
            "log_timeline": [
                TimelineEntry.model_validate(timeline_entries[item]).model_dump(mode="json")
                for item in timeline_ids
                if item in timeline_entries
            ][:100],
        }

    def remove(self, project_id: str, confirmation: str) -> None:
        item = self._stored(project_id)
        if item is None:
            raise ProjectError("project_not_found", "Project not found.")
        if item.get("configured_by") not in {"ui", "dashboard"}:
            raise ProjectError("file_configured", "Projects configured by file are read-only.")
        if confirmation != item.get("name"):
            raise ProjectError(
                "confirmation_mismatch", "Type the project name exactly to confirm removal."
            )
        if item.get("kind") == "github":
            root = self._verified_github_candidate(
                Path(str(item.get("root", ""))), str(item.get("import_job_id", ""))
            )
            try:
                self._delete_verified_github_clone(root)
            except OSError as exc:
                raise ProjectError(
                    "clone_delete_refused", "The managed import could not be removed safely."
                ) from exc
        scans = [
            row
            for row in self.repository.list_records("scan")
            if row.get("project_id") == project_id
        ]
        scan_ids = {str(row.get("scan_id")) for row in scans}
        self.repository.delete("project", project_id)
        for record_type in ("scan", "finding", "code_job"):
            for row in self.repository.list_records(record_type):
                if row.get("project_id") == project_id:
                    row["project_removed"] = True
                    self.repository.save(record_type, self._record_id(record_type, row), row)
        for row in self.repository.list_records("case"):
            if scan_ids.intersection(str(scan_id) for scan_id in row.get("scan_ids", [])):
                row["project_removed"] = True
                self.repository.save("case", str(row.get("case_id")), row)

    def resolve(self, project_id: str) -> tuple[str, Path]:
        item = self._stored(project_id)
        configured_by = "ui"
        if item is None:
            name, root = self.legacy.resolve(project_id)
            configured_by = "file"
        else:
            name, root = str(item["name"]), Path(str(item["root"]))
        if item is not None and item.get("kind") == "github":
            decision = self._github_decision(root, item)
        else:
            decision = folder_approval_decision(
                root,
                allowed_roots=(self.allowed_roots or [root])
                if configured_by == "dashboard"
                else self.allowed_roots
                if configured_by == "ui"
                else [root],
                hard_denied=self.hard_denied,
                soft_denied=self.soft_denied,
                allow_soft_denied=self.allow_soft_denied,
            )
        if not decision.allowed or decision.path is None or not decision.path.is_dir():
            if item is not None and item.get("kind") == "github":
                raise ProjectError(
                    "root_denied",
                    f"Project folder is no longer approved or available ({decision.reason_code}).",
                )
            raise ProjectError(
                decision.reason_code or "root_denied",
                folder_approval_error(decision.reason_code),
            )
        return name, decision.path

    def resolve_path(self, path: str | Path) -> Path:
        decision = self.decision(path)
        if not decision.allowed or decision.path is None or not decision.path.is_dir():
            raise ProjectError("root_denied", "Project folder is not approved.")
        return decision.path

    def code_projects(self) -> builtins.list[dict[str, str]]:
        """Legacy response shape retained for the existing Code assessments page."""
        return [
            {"project_id": str(item["project_id"]), "display_name": str(item["name"])}
            for item in self.list()
        ]

    def _stored(self, project_id: str) -> dict[str, Any] | None:
        return next(
            (
                row
                for row in self.repository.list_records("project")
                if row.get("project_id") == project_id
            ),
            None,
        )

    def _all_internal_and_file(self) -> builtins.list[dict[str, Any]]:
        stored = self.repository.list_records("project")
        names = {_name_key(str(row.get("name", ""))) for row in stored}
        return [
            *stored,
            *[row for row in self.legacy.list() if _name_key(row["name"]) not in names],
        ]

    @staticmethod
    def _record_id(record_type: str, item: dict[str, Any]) -> str:
        key = {"scan": "scan_id", "finding": "finding_id", "code_job": "job_id"}[record_type]
        return str(item[key])

    @staticmethod
    def _summary(item: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "project_id": str(item["project_id"]),
            "name": str(item["name"]),
            "kind": str(item.get("kind", "local")),
            "configured_by": str(item.get("configured_by", "file")),
            "origin_label": "This device" if item.get("kind") == "local" else "GitHub",
            "created_at": str(item.get("created_at", "")),
            "last_scan_refs": list(item.get("last_scan_refs", [])),
            "last_scan": item.get("last_scan_refs", [None])[0]
            if item.get("last_scan_refs")
            else None,
        }
        if item.get("kind") == "github":
            summary.update(
                {
                    "origin_url": str(item.get("origin_url", "")),
                    "commit_sha": str(item.get("commit_sha", "")),
                    "fetched_at": str(item.get("fetched_at", "")),
                }
            )
        return summary

    @staticmethod
    def _public(item: dict[str, Any]) -> dict[str, Any]:
        return ProjectService._summary(item)

    @staticmethod
    def _safe_job(item: dict[str, Any]) -> dict[str, Any]:
        return {
            key: item.get(key)
            for key in (
                "job_id",
                "status",
                "created_at",
                "started_at",
                "finished_at",
                "scan_id",
                "error",
                "warning",
            )
        }

    @staticmethod
    def _safe_finding(item: dict[str, Any]) -> dict[str, Any]:
        return {
            key: item.get(key)
            for key in (
                "finding_id",
                "title",
                "severity",
                "category",
                "rule_id",
                "location",
                "description",
                "tags",
            )
        }

    @staticmethod
    def _safe_case(item: dict[str, Any]) -> dict[str, Any]:
        return {
            key: item.get(key) for key in ("case_id", "title", "status", "severity", "updated_at")
        }

    @staticmethod
    def _safe_scan(item: dict[str, Any]) -> dict[str, Any]:
        gaps = (item.get("coverage") or {}).get("gaps", [])
        skipped = {
            str(gap.get("code", "").removeprefix("bound_")): int(gap.get("count", 0))
            for gap in gaps
            if isinstance(gap, dict) and str(gap.get("code", "")).startswith("bound_")
        }
        return {
            "scan_id": item.get("scan_id"),
            "status": item.get("status", "complete"),
            "finding_count": len(item.get("finding_ids", [])),
            "skipped_counts": skipped,
        }
