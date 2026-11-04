"""Project-owned, policy checked log location associations and suggestions."""

from __future__ import annotations

import os
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chinescan.core.fs_policy import decide_path
from chinescan.core.projects import ProjectError, ProjectService
from chinescan.core.storage.sqlite import SQLiteRepository

IGNORED = frozenset({".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__"})
EXTENSIONS = frozenset({".log", ".jsonl", ".ndjson", ".json", ".csv", ".evtx"})


class LogLocationService:
    """Store associations on project records; never return or mutate their roots."""

    def __init__(self, repository: SQLiteRepository, projects: ProjectService) -> None:
        self.repository, self.projects = repository, projects
        self._suggestions: dict[str, tuple[str, str, Path, str]] = {}

    def _project(self, project_id: str) -> tuple[dict[str, Any], Path]:
        record = self.projects._stored(project_id)
        if record is None or record.get("configured_by") not in {"ui", "dashboard"}:
            raise ProjectError("project_not_found", "Project not found.")
        _, root = self.projects.resolve(project_id)
        return record, root

    @staticmethod
    def _public(item: dict[str, Any]) -> dict[str, Any]:
        return {k: item[k] for k in ("location_id", "project_id", "name", "scope", "created_at")}

    def list(self, project_id: str) -> list[dict[str, Any]]:
        record, _ = self._project(project_id)
        return [self._public(x) for x in record.get("log_locations", [])]

    def add(self, project_id: str, name: str, selected: Path, scope: str) -> dict[str, Any]:
        record, project_root = self._project(project_id)
        clean = name.strip()
        if not 1 <= len(clean) <= 120:
            raise ProjectError("invalid_name", "Location name must be 1 to 120 characters.")
        rows = list(record.get("log_locations", []))
        if len(rows) >= 20:
            raise ProjectError("location_limit", "A project can have at most 20 log locations.")
        if scope == "project":
            if selected == project_root:
                raise ProjectError("invalid_location", "Choose a subfolder inside the project.")
        elif scope == "external":
            pass
        else:
            raise ProjectError("invalid_scope", "Unsupported log location scope.")
        if scope == "project" and record.get("kind") == "github":
            decision = self.projects.decision(selected)
        else:
            approved = (
                [project_root]
                if scope == "project"
                else self.projects.allowed_roots or [Path(selected)]
            )
            decision = decide_path(
                selected,
                allowed_roots=approved,
                hard_denied=self.projects.hard_denied,
                soft_denied=self.projects.soft_denied,
                allow_soft_denied=self.projects.allow_soft_denied
                or (scope == "external" and not self.projects.allowed_roots),
            )
        if not decision.allowed or decision.path is None or not decision.path.is_dir():
            raise ProjectError("location_denied", "The selected log folder is no longer approved.")
        if scope == "project" and not _under(decision.path, project_root):
            raise ProjectError("location_denied", "Choose a folder inside the project.")
        item = {
            "location_id": str(uuid.uuid4()),
            "project_id": project_id,
            "name": clean,
            "scope": scope,
            "root": str(decision.path),
            "created_at": datetime.now(UTC).isoformat(),
        }
        rows.append(item)
        record["log_locations"] = rows
        self.repository.save("project", project_id, record)
        return self._public(item)

    def add_project_selection(self, project_id: str, name: str, selected: Path) -> dict[str, Any]:
        _, root = self._project(project_id)
        return self.add(
            project_id, name, selected, "project" if _under(selected, root) else "external"
        )

    def add_approved_root(self, project_id: str) -> dict[str, Any]:
        """Make a deliberately approved folder directly available for log analysis."""
        record, root = self._project(project_id)
        rows = list(record.get("log_locations", []))
        if len(rows) >= 20:
            raise ProjectError("location_limit", "A project can have at most 20 log locations.")
        item = {
            "location_id": str(uuid.uuid4()),
            "project_id": project_id,
            "name": "Selected folder",
            "scope": "project",
            "root": str(root),
            "created_at": datetime.now(UTC).isoformat(),
        }
        rows.append(item)
        record["log_locations"] = rows
        self.repository.save("project", project_id, record)
        return self._public(item)

    def remove(self, project_id: str, location_id: str) -> None:
        record, _ = self._project(project_id)
        rows = list(record.get("log_locations", []))
        filtered = [x for x in rows if x.get("location_id") != location_id]
        if len(filtered) == len(rows):
            raise ProjectError("location_not_found", "Log location not found.")
        record["log_locations"] = filtered
        self.repository.save("project", project_id, record)

    def suggestions(self, project_id: str, session: str = "cli") -> dict[str, Any]:
        _, root = self._project(project_id)
        found: list[tuple[Path, str]] = []
        visited, partial = 0, False
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            directory, depth = stack.pop()
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if visited >= 5000:
                            partial = True
                            stack.clear()
                            break
                        visited += 1
                        if entry.name in IGNORED:
                            continue
                        child = Path(entry.path)
                        try:
                            metadata = entry.stat(follow_symlinks=False)
                            if stat.S_ISLNK(metadata.st_mode) or (
                                os.name == "nt"
                                and getattr(metadata, "st_file_attributes", 0)
                                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                            ):
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                if entry.name.casefold() in {"log", "logs", "var-log"}:
                                    found.append((child, "directory"))
                                if depth < 8:
                                    stack.append((child, depth + 1))
                                else:
                                    partial = True
                            elif child.suffix.casefold() in EXTENSIONS:
                                found.append((child, "file"))
                        except OSError:
                            continue
            except OSError:
                continue
        if len(found) > 500:
            partial = True
        suggestions = []
        for path, kind in found[:500]:
            suggestion_id = uuid.uuid4().hex
            self._suggestions[suggestion_id] = (session, project_id, path, kind)
            try:
                label = path.relative_to(root).as_posix()
            except ValueError:
                continue
            suggestions.append(
                {
                    "suggestion_id": suggestion_id,
                    "label": label,
                    "unsupported": path.suffix.casefold() == ".evtx",
                }
            )
        return {"items": suggestions, "visited": visited, "partial": partial}

    def confirm(
        self, project_id: str, suggestion_id: str, name: str, session: str = "cli"
    ) -> dict[str, Any]:
        value = self._suggestions.get(suggestion_id)
        if value is None or value[0] != session or value[1] != project_id:
            raise ProjectError("suggestion_unavailable", "Suggestion is no longer available.")
        _, _, path, kind = value
        if path.suffix.casefold() == ".evtx":
            raise ProjectError("unsupported_format", "EVTX parsing is not supported yet.")
        if kind != "directory":
            path = path.parent
        _, root = self._project(project_id)
        return self.add(project_id, name, path, "project")

    def resolve_location(self, project_id: str, location_id: str) -> Path:
        record, project_root = self._project(project_id)
        item = next(
            (
                row
                for row in record.get("log_locations", [])
                if row.get("location_id") == location_id
            ),
            None,
        )
        if item is None:
            raise ProjectError(
                "location_missing", "A selected log location is no longer available."
            )
        root = Path(str(item.get("root", "")))
        allowed = [project_root] if item.get("scope") == "project" else self.projects.allowed_roots
        decision = decide_path(
            root,
            allowed_roots=allowed,
            hard_denied=self.projects.hard_denied,
            soft_denied=self.projects.soft_denied,
            allow_soft_denied=self.projects.allow_soft_denied,
        )
        if not decision.allowed or decision.path is None or not decision.path.is_dir():
            raise ProjectError(
                "location_denied", "A selected log location is no longer approved or available."
            )
        if item.get("scope") == "project" and not _under(decision.path, project_root):
            raise ProjectError(
                "location_denied", "A selected log location is no longer inside the project."
            )
        return decision.path


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except (OSError, RuntimeError, ValueError):
        return False
