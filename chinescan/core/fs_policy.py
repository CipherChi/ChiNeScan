"""Filesystem path policy and capability-scoped, read-only browsing service."""

from __future__ import annotations

import ctypes
import ntpath
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import unquote

if TYPE_CHECKING:
    from chinescan.core.config.settings import Settings

Capability = Literal["project_directory", "log_location", "folder_approval"]
CAPABILITIES = frozenset({"project_directory", "log_location", "folder_approval"})
MAX_PAGE_SIZE = 500
MAX_DIRECTORY_ENTRIES = 50_000
ID_TTL_SECONDS = 300
MAX_ID_RECORDS = 20_000
MAX_CURSOR_RECORDS = 2_000

_DEVICE = re.compile(
    r"^(?:CON|CONIN\$|CONOUT\$|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?$", re.I
)
_SHORT_COMPONENT = re.compile(r"(?i)(?:^|\\)[^\\.]{1,6}~[0-9](?:\.[^\\]*)?(?:\\|$)")
_REMOTE_NT_DEVICE = re.compile(r"(?i)\\(?:device\\mup|device\\lanmanredirector|\?\?\\unc)(?:\\|$)")


@dataclass(frozen=True)
class PathDecision:
    allowed: bool
    tier: str
    reason_code: str
    path: Path | None = None


@dataclass(frozen=True)
class RootValidation:
    index: int
    valid: bool
    reason_code: str


@dataclass(frozen=True)
class _Selection:
    session_key: str
    capability: Capability
    path: Path
    boundary: Path
    label: str
    selectable: bool
    expires_at: float


@dataclass(frozen=True)
class _Cursor:
    session_key: str
    capability: Capability
    directory_id: str
    names: tuple[str, ...]
    truncated: bool
    next_index: int
    expires_at: float


def _key(path: Path | str) -> str:
    value = unicodedata.normalize("NFKC", os.path.normcase(str(path))).casefold()
    return value.rstrip("\\/")


def _under(path: Path, parent: Path) -> bool:
    candidate, base = _key(path), _key(parent)
    separator = "\\" if "\\" in base else os.sep
    return candidate == base or candidate.startswith(base + separator)


def _overlaps(left: Path, right: Path) -> bool:
    return _under(left, right) or _under(right, left)


def _decode_for_validation(value: str) -> str | None:
    current = value
    try:
        for _ in range(3):
            decoded = unquote(current, errors="strict")
            normalized = decoded.replace("/", "\\")
            if decoded != current and ".." in normalized.split("\\"):
                return None
            if decoded == current:
                break
            current = decoded
    except UnicodeError:
        return None
    if re.search(r"(?i)%2e|%2f|%5c", current):
        return None
    return current


def _parts_valid(value: str) -> str | None:
    decoded = _decode_for_validation(value)
    if decoded is None:
        return "encoded_traversal"
    normalized = decoded.replace("/", "\\")
    if normalized.startswith(("\\\\", "\\?\\", "\\.\\")):
        return "network_path"
    if re.match(r"^[A-Za-z]:(?!\\)", normalized):
        return "drive_relative"
    if re.match(r"^[A-Za-z]:.*:[^\\/]+$", normalized):
        return "alternate_data_stream"
    for raw_component in normalized.split("\\"):
        component = unicodedata.normalize("NFKC", raw_component)
        if component in {".", ".."}:
            return "traversal"
        if component.endswith((".", " ")):
            return "trailing_dot_or_space"
        if _DEVICE.fullmatch(component):
            return "reserved_device_name"
    return None


def _expand_8dot3(path: Path) -> Path:
    """Expand Windows short names before any containment or deny-list comparison."""
    if os.name != "nt":
        return path
    raw = str(path)
    if not _SHORT_COMPONENT.search(raw):
        return path
    kernel32 = cast(Any, ctypes).windll.kernel32
    get_long_path = kernel32.GetLongPathNameW
    get_long_path.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
    get_long_path.restype = ctypes.c_uint32
    capacity = 32_768
    buffer = ctypes.create_unicode_buffer(capacity)
    result = get_long_path(raw, buffer, capacity)
    if not result or result >= capacity:
        raise OSError("short path expansion failed")
    return Path(buffer.value)


def _windows_drive_remote(path: Path) -> bool:
    if os.name != "nt":
        return False
    drive = path.drive
    if not drive:
        return False
    kernel32 = cast(Any, ctypes).windll.kernel32
    drive_type = int(kernel32.GetDriveTypeW(drive + "\\"))
    if drive_type == 4:  # DRIVE_REMOTE
        return True
    query = kernel32.QueryDosDeviceW
    query.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
    query.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32_768)
    if not query(drive.rstrip(":"), buffer, len(buffer)):
        return False
    targets = (ctypes.cast(buffer, ctypes.c_wchar_p).value or "").split("\0")
    return any(_REMOTE_NT_DEVICE.match(item) for item in targets if item)


def _is_remote(path: Path) -> bool:
    if str(path).startswith(("\\\\", "\\?\\UNC\\")):
        return True
    try:
        return _windows_drive_remote(path)
    except (AttributeError, OSError, ValueError):
        # If Windows cannot determine the mapping, do not authorize it.
        return os.name == "nt"


def _local_filesystem_roots() -> list[Path]:
    if os.name != "nt":
        return [Path(Path.cwd().anchor or "/")]
    try:
        mask = int(cast(Any, ctypes).windll.kernel32.GetLogicalDrives())
    except (AttributeError, OSError, ValueError):
        return []
    roots = [Path(f"{chr(65 + index)}:\\") for index in range(26) if mask & (1 << index)]
    return [root for root in roots if not _is_remote(root)]


def _reparse(path: Path) -> bool:
    """Return true if any existing path component is a link or reparse point."""
    try:
        absolute = path.absolute()
        current = Path(absolute.anchor)
        for component in absolute.parts[1:]:
            current /= component
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                break
            if stat.S_ISLNK(metadata.st_mode) or getattr(current, "is_junction", lambda: False)():
                return True
            if os.name == "nt":
                attributes = getattr(metadata, "st_file_attributes", 0)
                if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                    return True
        return False
    except (OSError, RuntimeError, ValueError):
        return True


def decide_path(
    value: str | Path,
    *,
    allowed_roots: tuple[Path, ...] | list[Path] = (),
    hard_denied: tuple[Path, ...] | list[Path] = (),
    soft_denied: tuple[Path, ...] | list[Path] = (),
    allow_soft_denied: bool = False,
    must_exist: bool = True,
    require_allowed_root: bool = True,
) -> PathDecision:
    """Return one path authorization decision; hard denials always win."""
    raw = str(value)
    if len(raw) > 32_760:
        return PathDecision(False, "hard", "path_too_long")
    invalid = _parts_valid(raw)
    if invalid:
        return PathDecision(False, "hard", invalid)
    try:
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            return PathDecision(False, "hard", "absolute_path_required")
        candidate = _expand_8dot3(candidate)
        if _is_remote(candidate):
            return PathDecision(False, "hard", "network_drive")
        if _reparse(candidate):
            return PathDecision(False, "hard", "reparse_point")
        resolved = candidate.resolve(strict=must_exist)
    except (OSError, RuntimeError, ValueError):
        return PathDecision(False, "hard", "unavailable")
    if len(str(resolved)) > 32_760:
        return PathDecision(False, "hard", "path_too_long")

    denied: list[Path] = []
    for raw_denied in hard_denied:
        try:
            denied.append(Path(raw_denied).expanduser().resolve(strict=False))
        except (OSError, RuntimeError, ValueError):
            return PathDecision(False, "hard", "deny_rule_invalid")
    if any(_under(resolved, item) for item in denied):
        return PathDecision(False, "hard", "hard_denied", resolved)

    roots: list[Path] = []
    for root in allowed_roots:
        try:
            root_path = Path(root).expanduser()
            if _reparse(root_path) or _is_remote(root_path):
                continue
            roots.append(root_path.resolve(strict=True))
        except (OSError, RuntimeError, ValueError):
            continue
    matching_roots = [root for root in roots if _under(resolved, root)]
    if require_allowed_root and not matching_roots:
        return PathDecision(False, "none", "outside_allowed_roots", resolved)
    soft_paths: list[Path] = []
    for raw_soft in soft_denied:
        try:
            soft_paths.append(Path(raw_soft).expanduser().resolve(strict=False))
        except (OSError, RuntimeError, ValueError):
            continue
    matched_soft = [item for item in soft_paths if _under(resolved, item)]
    if matched_soft and not allow_soft_denied:
        # A narrower approved root is an explicit override; the whole denied path
        # requires allow_soft_denied=true.
        if not any(
            _key(root) != _key(soft) and _under(root, soft) and _under(resolved, root)
            for root in matching_roots
            for soft in matched_soft
        ):
            return PathDecision(False, "soft", "soft_denied", resolved)

    # Recheck after resolution so an alias or path swap cannot widen containment.
    if _reparse(candidate):
        return PathDecision(False, "hard", "reparse_point", resolved)
    try:
        final = candidate.resolve(strict=must_exist)
    except (OSError, RuntimeError, ValueError):
        return PathDecision(False, "hard", "unavailable")
    if _key(final) != _key(resolved) or (
        require_allowed_root and not any(_under(final, root) for root in roots)
    ):
        return PathDecision(False, "hard", "containment_changed")
    if any(_under(final, item) for item in denied):
        return PathDecision(False, "hard", "hard_denied", final)
    return PathDecision(True, "allowed", "allowed", final)


def folder_approval_decision(
    value: str | Path,
    *,
    allowed_roots: list[Path],
    hard_denied: list[Path],
    soft_denied: list[Path],
    allow_soft_denied: bool,
) -> PathDecision:
    """Validate a user-selected directory before it can become an approved project."""
    candidate = Path(value).expanduser()
    raw_candidate = str(value)
    drive, tail = ntpath.splitdrive(raw_candidate)
    if drive and tail and not tail.startswith(("\\", "/")):
        return PathDecision(False, "hard", "drive_relative")
    if raw_candidate.startswith(("\\\\", "//")):
        return PathDecision(False, "hard", "network_path")
    if not candidate.is_absolute():
        return PathDecision(False, "hard", "absolute_path_required")
    decision = decide_path(
        candidate,
        allowed_roots=allowed_roots,
        hard_denied=hard_denied,
        soft_denied=soft_denied,
        allow_soft_denied=allow_soft_denied or not allowed_roots,
        require_allowed_root=bool(allowed_roots),
    )
    if not decision.allowed or decision.path is None:
        return decision
    resolved = decision.path
    if resolved == Path(resolved.anchor):
        return PathDecision(False, "hard", "filesystem_root", resolved)
    try:
        if resolved == Path.home().resolve(strict=False):
            return PathDecision(False, "hard", "user_profile_root", resolved)
    except (OSError, RuntimeError, ValueError):
        return PathDecision(False, "hard", "unavailable")
    system_paths = (
        [
            Path(os.environ.get("WINDIR", r"C:\Windows")),
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
            Path(os.environ.get("ProgramW6432", r"C:\Program Files")),
        ]
        if os.name == "nt"
        else []
    )
    for system_path in system_paths:
        try:
            system_root = system_path.resolve(strict=False)
            if _under(resolved, system_root):
                return PathDecision(False, "hard", "system_directory", resolved)
        except (OSError, RuntimeError, ValueError):
            return PathDecision(False, "hard", "invalid_system_directory_rule")
    if not resolved.is_dir():
        return PathDecision(False, "hard", "not_a_directory", resolved)
    try:
        with os.scandir(resolved):
            pass
    except OSError:
        return PathDecision(False, "hard", "unreadable_directory", resolved)
    return decision


def folder_approval_error(code: str) -> str:
    messages = {
        "absolute_path_required": "Choose an absolute local folder.",
        "filesystem_root": "A drive root cannot be approved. Choose a subfolder.",
        "user_profile_root": "The user profile root cannot be approved. Choose a subfolder.",
        "system_directory": "Windows and Program Files system folders cannot be approved.",
        "network_path": "Network locations cannot be approved.",
        "network_drive": "Network drives cannot be approved.",
        "reparse_point": "Shortcuts, symlinks, and junctions cannot be approved.",
        "unreadable_directory": "This folder cannot be read. Choose a readable folder.",
        "not_a_directory": "Choose a folder, not a file.",
        "unavailable": "The selected folder is no longer available.",
        "outside_allowed_roots": "The selected folder is outside the configured allowed roots.",
        "hard_denied": "This protected system or application folder cannot be approved.",
    }
    return messages.get(code, "The selected folder is not available for approval.")


def validate_allowed_roots(
    roots: list[Path],
    *,
    hard_denied: list[Path],
    soft_denied: list[Path],
    allow_soft_denied: bool,
    storage_paths: list[Path] | None = None,
) -> tuple[list[Path], list[RootValidation]]:
    """Keep only safe directory roots and return path-free per-entry statuses."""
    accepted: list[Path] = []
    statuses: list[RootValidation] = []
    stores = [Path(item).expanduser() for item in (storage_paths or [])]
    for index, raw in enumerate(roots):
        try:
            root = Path(raw).expanduser()
            if not root.is_absolute():
                raise ValueError("absolute_path_required")
            decision = decide_path(
                root,
                allowed_roots=[root],
                hard_denied=hard_denied,
                soft_denied=soft_denied,
                allow_soft_denied=allow_soft_denied,
                must_exist=True,
            )
            if not decision.allowed or decision.path is None:
                statuses.append(RootValidation(index, False, decision.reason_code))
                continue
            if not decision.path.is_dir():
                statuses.append(RootValidation(index, False, "not_a_directory"))
                continue
            if any(_overlaps(decision.path, store.resolve(strict=False)) for store in stores):
                statuses.append(RootValidation(index, False, "overlaps_chinescan_storage"))
                continue
            if any(_key(decision.path) == _key(existing) for existing in accepted):
                statuses.append(RootValidation(index, False, "duplicate_root"))
                continue
            accepted.append(decision.path)
            statuses.append(RootValidation(index, True, "allowed"))
        except (OSError, RuntimeError, ValueError):
            statuses.append(RootValidation(index, False, "invalid_root"))
    return accepted, statuses


def storage_paths(settings: Settings) -> list[Path]:
    """Return storage boundaries that approved roots must not overlap."""
    from chinescan.core.config.settings import (
        default_config_path,
        default_data_path,
        default_reports_path,
    )

    config = Path(os.environ.get("CHINESCAN_CONFIG_PATH", str(default_config_path())))
    config_dir = config.parent
    paths = [
        default_config_path(),
        default_config_path().parent,
        default_data_path(),
        default_data_path().parent,
        default_reports_path(),
        config,
        config_dir,
        settings.database_path,
        settings.reports_dir,
    ]
    if settings.malware_managed_directory:
        paths.append(settings.malware_managed_directory)
        paths.extend(
            [
                settings.malware_managed_directory / "imports",
                settings.malware_managed_directory / "import",
            ]
        )
    return paths


def policy_paths(settings: Settings) -> tuple[list[Path], list[Path]]:
    """Build hard and soft deny tiers without exposing paths to callers."""
    home = Path.home()
    hard = [
        *settings.extra_denied_paths,
        *storage_paths(settings),
        Path(__file__).resolve().parents[2] / ".git",
        home / ".ssh",
        home / ".gnupg",
        home / ".aws",
        home / ".azure",
        home / ".password-store",
        home / ".keepass",
        home / ".config/1Password",
        home / ".config/Bitwarden",
        home / ".local/share/bitwarden",
        home / ".local/share/keyrings",
        home / ".bitcoin/wallets",
        home / ".electrum/wallets",
        home / "AppData/Roaming/Microsoft/Credentials",
        home / "AppData/Roaming/Microsoft/Vault",
        home / "AppData/Roaming/Microsoft/Protect",
        home / "AppData/Local/Google/Chrome/User Data",
        home / "AppData/Local/Microsoft/Edge/User Data",
        home / "AppData/Local/BraveSoftware/Brave-Browser/User Data",
        home / "AppData/Local/Chromium/User Data",
        home / "AppData/Local/Opera Software/Opera Stable",
        home / "AppData/Local/Vivaldi/User Data",
        home / "AppData/Local/Yandex/YandexBrowser/User Data",
        home / "AppData/Roaming/Mozilla/Firefox/Profiles",
        home / "AppData/Roaming/1Password",
        home / "AppData/Local/1Password",
        home / "AppData/Roaming/Dashlane",
        home / "AppData/Local/Dashlane",
        home / "AppData/Roaming/Proton Pass",
        home / "AppData/Local/Proton Pass",
        home / "AppData/Roaming/Bitwarden",
        home / "AppData/Local/Bitwarden",
        home / "AppData/Roaming/KeePass",
        home / "AppData/Roaming/Electrum/wallets",
        home / "AppData/Roaming/Exodus",
    ]
    if os.name == "nt":
        hard.extend(
            Path(item)
            for item in (
                os.environ.get("WINDIR", r"C:\Windows"),
                os.environ.get("ProgramFiles", r"C:\Program Files"),
                os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                os.environ.get("ProgramW6432", r"C:\Program Files"),
            )
        )
    soft = [
        Path(item)
        for key in ("PROGRAMDATA", "APPDATA", "LOCALAPPDATA")
        if (item := os.environ.get(key))
    ]
    soft.append(home)
    return hard, soft


class FilesystemBrowserService:
    """In-memory session/capability-bound directory selections and stable cursors."""

    def __init__(
        self,
        roots: list[Path],
        hard_denied: list[Path],
        soft_denied: list[Path],
        allow_soft_denied: bool,
    ) -> None:
        self.roots = list(roots)
        self.hard_denied = list(hard_denied)
        self.soft_denied = list(soft_denied)
        self.allow_soft_denied = allow_soft_denied
        self._lock = threading.RLock()
        self._selections: dict[str, _Selection] = {}
        self._cursors: dict[str, _Cursor] = {}

    def _purge(self) -> None:
        now = time.monotonic()
        with self._lock:
            self._selections = {
                key: value for key, value in self._selections.items() if value.expires_at > now
            }
            self._cursors = {
                key: value for key, value in self._cursors.items() if value.expires_at > now
            }

    def _decision(
        self, path: Path, boundary: Path, *, allow_soft_override: bool = False
    ) -> PathDecision:
        return decide_path(
            path,
            allowed_roots=[boundary],
            hard_denied=self.hard_denied,
            soft_denied=self.soft_denied,
            allow_soft_denied=self.allow_soft_denied or allow_soft_override,
            must_exist=True,
        )

    def picker_roots_view(self, session: str) -> dict[str, object]:
        """Return policy roots or local drive anchors for the approval picker."""
        roots = self.roots or _local_filesystem_roots()
        items: list[dict[str, object]] = []
        for root in roots:
            decision = self._decision(root, root, allow_soft_override=True)
            if not decision.allowed or decision.path is None or not decision.path.is_dir():
                continue
            selectable = folder_approval_decision(
                decision.path,
                allowed_roots=self.roots,
                hard_denied=self.hard_denied,
                soft_denied=self.soft_denied,
                allow_soft_denied=True,
            ).allowed
            identifier = self._issue(
                session,
                "folder_approval",
                decision.path,
                decision.path,
                str(root),
                selectable=selectable,
            )
            items.append({"directory_id": identifier, "name": str(root), "selectable": selectable})
        return {"items": items}

    def preview_folder_approval(self, session: str, directory_id: str) -> dict[str, str]:
        path = self.resolve_folder_approval(session, directory_id)
        return {"directory_id": directory_id, "name": path.name, "resolved_path": str(path)}

    def resolve_folder_approval(self, session: str, directory_id: str) -> Path:
        selection = self._lookup(session, "folder_approval", directory_id)
        if not selection.selectable:
            raise ValueError("folder_not_selectable")
        decision = folder_approval_decision(
            selection.path,
            allowed_roots=self.roots,
            hard_denied=self.hard_denied,
            soft_denied=self.soft_denied,
            allow_soft_denied=True,
        )
        if (
            not decision.allowed
            or decision.path is None
            or _key(decision.path) != _key(selection.path)
            or not _under(decision.path, selection.boundary)
        ):
            raise ValueError(decision.reason_code or "directory_unavailable")
        return decision.path

    def _issue(
        self,
        session: str,
        capability: Capability,
        path: Path,
        boundary: Path,
        label: str,
        *,
        selectable: bool = True,
    ) -> str:
        self._purge()
        with self._lock:
            if len(self._selections) >= MAX_ID_RECORDS:
                oldest = min(self._selections, key=lambda item: self._selections[item].expires_at)
                del self._selections[oldest]
            identifier = secrets.token_urlsafe(32)
            self._selections[identifier] = _Selection(
                session,
                capability,
                path,
                boundary,
                label,
                selectable,
                time.monotonic() + ID_TTL_SECONDS,
            )
            return identifier

    def _lookup(self, session: str, capability: Capability, identifier: str) -> _Selection:
        self._purge()
        with self._lock:
            item = self._selections.get(identifier)
        if item is None or item.session_key != session or item.capability != capability:
            raise ValueError("directory_unavailable")
        return item

    def roots_view(self, session: str, capability: Capability) -> dict[str, object]:
        if capability not in CAPABILITIES:
            raise ValueError("unsupported_capability")
        items: list[dict[str, object]] = []
        for index, root in enumerate(self.roots):
            decision = self._decision(root, root)
            if not decision.allowed or decision.path is None or not decision.path.is_dir():
                continue
            label = f"Approved folder {index + 1}"
            identifier = self._issue(session, capability, decision.path, decision.path, label)
            items.append({"directory_id": identifier, "name": label, "selectable": True})
        return {"items": items}

    def project_root_view(self, session: str, root: Path) -> dict[str, str]:
        """Issue a project scoped picker root without exposing the internal path."""
        decision = self._decision(root, root)
        if not decision.allowed or decision.path is None or not decision.path.is_dir():
            raise ValueError("directory_unavailable")
        return {
            "directory_id": self._issue(
                session, "project_directory", decision.path, decision.path, "Project folder"
            ),
            "name": "Project folder",
        }

    def list_view(
        self,
        session: str,
        capability: Capability,
        directory_id: str,
        *,
        cursor: str | None = None,
        limit: int = 100,
    ) -> dict[str, object]:
        if capability not in CAPABILITIES:
            raise ValueError("unsupported_capability")
        if not 1 <= limit <= MAX_PAGE_SIZE:
            raise ValueError("invalid_page_size")
        page: _Cursor | None = None
        if cursor is not None:
            self._purge()
            with self._lock:
                page = self._cursors.get(cursor)
            if (
                page is None
                or page.session_key != session
                or page.capability != capability
                or page.directory_id != directory_id
            ):
                raise ValueError("cursor_unavailable")
        selection = self._lookup(session, capability, directory_id)
        checked = self._decision(
            selection.path,
            selection.boundary,
            allow_soft_override=capability == "folder_approval",
        )
        if not checked.allowed or checked.path is None or not checked.path.is_dir():
            raise ValueError("directory_unavailable")
        if _key(checked.path) != _key(selection.path) or not _under(
            checked.path, selection.boundary
        ):
            raise ValueError("directory_unavailable")

        if cursor is None:
            names, truncated = self._snapshot_children(
                checked.path, selection.boundary, capability=capability
            )
            start = 0
        else:
            assert page is not None
            names, truncated, start = page.names, page.truncated, page.next_index

        page_names = names[start : start + limit]
        items: list[dict[str, object]] = []
        for name in page_names:
            child = checked.path / name
            child_decision = self._decision(
                child,
                selection.boundary,
                allow_soft_override=capability == "folder_approval",
            )
            if not child_decision.allowed or child_decision.path is None:
                continue
            if child_decision.path.name != name or not child_decision.path.is_dir():
                continue
            selectable = True
            if capability == "folder_approval":
                selectable = folder_approval_decision(
                    child_decision.path,
                    allowed_roots=self.roots,
                    hard_denied=self.hard_denied,
                    soft_denied=self.soft_denied,
                    allow_soft_denied=True,
                ).allowed
            child_id = self._issue(
                session,
                capability,
                child_decision.path,
                selection.boundary,
                name,
                selectable=selectable,
            )
            items.append({"directory_id": child_id, "name": name, "selectable": selectable})

        next_cursor = None
        next_index = start + len(page_names)
        if next_index < len(names):
            self._purge()
            with self._lock:
                cursor_id = secrets.token_urlsafe(32)
                if len(self._cursors) >= MAX_CURSOR_RECORDS:
                    oldest = min(self._cursors, key=lambda item: self._cursors[item].expires_at)
                    del self._cursors[oldest]
                self._cursors[cursor_id] = _Cursor(
                    session,
                    capability,
                    directory_id,
                    names,
                    truncated,
                    next_index,
                    time.monotonic() + ID_TTL_SECONDS,
                )
                next_cursor = cursor_id

        relative_parts = checked.path.relative_to(selection.boundary).parts
        breadcrumbs: list[dict[str, str]] = [
            {
                "name": selection.label,
                "directory_id": self._issue(
                    session, capability, selection.boundary, selection.boundary, selection.label
                ),
            }
        ]
        current = selection.boundary
        for part in relative_parts:
            current /= part
            if _key(current) == _key(checked.path):
                current_id = directory_id
            else:
                current_id = self._issue(
                    session,
                    capability,
                    current,
                    selection.boundary,
                    part,
                    selectable=selection.selectable,
                )
            breadcrumbs.append({"name": part, "directory_id": current_id})
        return {
            "directory_id": directory_id,
            "name": selection.label if not relative_parts else relative_parts[-1],
            "selectable": selection.selectable,
            "breadcrumbs": breadcrumbs,
            "items": items,
            "next_cursor": next_cursor,
            "truncated": truncated,
        }

    def resolve_selection(self, session: str, capability: Capability, directory_id: str) -> Path:
        """Resolve an opaque picker selection and repeat its full path policy check."""
        selection = self._lookup(session, capability, directory_id)
        decision = self._decision(selection.path, selection.boundary)
        if (
            not decision.allowed
            or decision.path is None
            or not decision.path.is_dir()
            or _key(decision.path) != _key(selection.path)
            or not _under(decision.path, selection.boundary)
        ):
            raise ValueError("directory_unavailable")
        return decision.path

    def _snapshot_children(
        self,
        directory: Path,
        boundary: Path,
        *,
        capability: Capability,
    ) -> tuple[tuple[str, ...], bool]:
        decision = self._decision(
            directory,
            boundary,
            allow_soft_override=capability == "folder_approval",
        )
        if not decision.allowed or decision.path is None:
            raise ValueError("directory_unavailable")
        names: list[str] = []
        truncated = False
        examined = 0
        try:
            with os.scandir(decision.path) as entries:
                for entry in entries:
                    if examined >= MAX_DIRECTORY_ENTRIES:
                        truncated = True
                        break
                    examined += 1
                    try:
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                        metadata = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(metadata.st_mode):
                            continue
                        if os.name == "nt" and getattr(metadata, "st_file_attributes", 0) & getattr(
                            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
                        ):
                            continue
                        names.append(entry.name)
                    except OSError:
                        continue
        except OSError as exc:
            raise ValueError("directory_unavailable") from exc
        after = self._decision(
            decision.path,
            boundary,
            allow_soft_override=capability == "folder_approval",
        )
        if not after.allowed or after.path is None or _key(after.path) != _key(decision.path):
            raise ValueError("directory_unavailable")
        return (
            tuple(
                sorted(
                    names, key=lambda item: (unicodedata.normalize("NFKC", item).casefold(), item)
                )
            ),
            truncated,
        )
