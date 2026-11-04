from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import chinescan.core.fs_policy as policy
from chinescan.core.fs_policy import (
    MAX_PAGE_SIZE,
    FilesystemBrowserService,
    decide_path,
    folder_approval_decision,
    folder_approval_error,
    validate_allowed_roots,
)


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("C:\\safe\\..\\secret", "traversal"),
        ("C:\\safe\\%2e%2e\\secret", "encoded_traversal"),
        ("C:\\safe\\%252e%252e\\secret", "encoded_traversal"),
        ("C:\\safe\\file.txt:stream", "alternate_data_stream"),
        ("C:\\safe\\CON.txt", "reserved_device_name"),
        ("C:\\safe\\CONOUT$", "reserved_device_name"),
        ("C:\\safe\\com¹.log", "reserved_device_name"),
        ("\\\\server\\share", "network_path"),
        ("\\\\?\\UNC\\server\\share", "network_path"),
        ("\\\\?\\C:\\safe", "network_path"),
        ("C:relative\\path", "drive_relative"),
        ("C:\\safe\\folder. ", "trailing_dot_or_space"),
    ],
)
def test_rejects_unsafe_path_forms_without_disclosing_them(value: str, reason: str) -> None:
    decision = decide_path(value, allowed_roots=[Path("C:/safe")])
    assert not decision.allowed
    assert decision.reason_code == reason
    assert str(decision.path or "") == ""


def test_rejects_mixed_separator_traversal() -> None:
    decision = decide_path(r"C:\safe/../private", allowed_roots=[Path("C:/safe")])
    assert decision.reason_code == "traversal"


def test_path_length_is_bounded_before_filesystem_resolution(tmp_path: Path) -> None:
    value = str(tmp_path) + "\\" + "x" * 32_800
    decision = decide_path(value, allowed_roots=[tmp_path])
    assert not decision.allowed
    assert decision.reason_code == "path_too_long"


def test_folder_approval_rejects_filesystem_and_profile_roots() -> None:
    filesystem_root = Path(Path.cwd().anchor or "/")
    root = folder_approval_decision(
        filesystem_root, allowed_roots=[], hard_denied=[], soft_denied=[], allow_soft_denied=False
    )
    profile = folder_approval_decision(
        Path.home(), allowed_roots=[], hard_denied=[], soft_denied=[], allow_soft_denied=False
    )
    assert root.reason_code == "filesystem_root"
    assert profile.reason_code == "user_profile_root"
    assert "subfolder" in folder_approval_error(root.reason_code)


def test_folder_approval_allows_readable_local_folder_with_spaces(tmp_path: Path) -> None:
    folder = tmp_path / "approved project folder"
    folder.mkdir()
    decision = folder_approval_decision(
        folder, allowed_roots=[], hard_denied=[], soft_denied=[], allow_soft_denied=False
    )
    assert decision.allowed
    assert decision.path == folder.resolve()


def test_folder_approval_keeps_nonempty_allowed_roots_as_a_restriction(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    decision = folder_approval_decision(
        outside,
        allowed_roots=[allowed],
        hard_denied=[],
        soft_denied=[],
        allow_soft_denied=False,
    )
    assert not decision.allowed
    assert decision.reason_code == "outside_allowed_roots"


def test_folder_approval_rejects_network_and_drive_relative_paths() -> None:
    for path, expected in [
        (r"\\server\share", "network_path"),
        (r"C:relative\folder", "drive_relative"),
    ]:
        decision = folder_approval_decision(
            path, allowed_roots=[], hard_denied=[], soft_denied=[], allow_soft_denied=False
        )
        assert not decision.allowed
        assert decision.reason_code == expected


def test_folder_approval_rejects_unreadable_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "unreadable"
    folder.mkdir()
    original_scandir = os.scandir

    def guarded_scandir(path):
        if Path(path) == folder:
            raise PermissionError("denied")
        return original_scandir(path)

    monkeypatch.setattr(policy.os, "scandir", guarded_scandir)
    decision = folder_approval_decision(
        folder, allowed_roots=[], hard_denied=[], soft_denied=[], allow_soft_denied=False
    )
    assert not decision.allowed
    assert decision.reason_code == "unreadable_directory"


def test_folder_approval_rejects_reparse_points_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlinks are not available for this account.")
    decision = folder_approval_decision(
        alias, allowed_roots=[], hard_denied=[], soft_denied=[], allow_soft_denied=False
    )
    assert not decision.allowed
    assert decision.reason_code == "reparse_point"


@pytest.mark.skipif(os.name != "nt", reason="Windows system folders only")
def test_folder_approval_rejects_system_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system = tmp_path / "Windows"
    candidate = system / "app"
    candidate.mkdir(parents=True)
    monkeypatch.setenv("WINDIR", str(system))
    decision = folder_approval_decision(
        candidate, allowed_roots=[], hard_denied=[], soft_denied=[], allow_soft_denied=False
    )
    assert not decision.allowed
    assert decision.reason_code == "system_directory"


def test_allowed_root_itself_is_selectable_and_descendants_are_contained(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    child = root / "code"
    child.mkdir(parents=True)
    root_decision = decide_path(root, allowed_roots=[root])
    child_decision = decide_path(child, allowed_roots=[root])
    assert root_decision.allowed and root_decision.path == root.resolve()
    assert child_decision.allowed and child_decision.path == child.resolve()


def test_hard_deny_wins_over_nested_allowed_root(tmp_path: Path) -> None:
    hard = tmp_path / "protected"
    nested = hard / "approved-child"
    nested.mkdir(parents=True)
    decision = decide_path(nested, allowed_roots=[nested], hard_denied=[hard])
    assert not decision.allowed
    assert decision.tier == "hard"
    assert decision.reason_code == "hard_denied"


def test_soft_deny_allows_narrower_approved_root_but_not_the_whole_area(tmp_path: Path) -> None:
    soft = tmp_path / "ProgramData"
    root = soft / "approved"
    child = root / "data"
    child.mkdir(parents=True)
    nested = decide_path(child, allowed_roots=[root], soft_denied=[soft])
    whole = decide_path(soft, allowed_roots=[soft], soft_denied=[soft])
    explicit_whole = decide_path(
        soft, allowed_roots=[soft], soft_denied=[soft], allow_soft_denied=True
    )
    assert nested.allowed
    assert not whole.allowed and whole.tier == "soft" and whole.reason_code == "soft_denied"
    assert explicit_whole.allowed


def test_roots_overlapping_storage_are_ignored_and_report_path_free_reasons(tmp_path: Path) -> None:
    roots = [tmp_path / "valid", tmp_path]
    roots[0].mkdir()
    stores = [tmp_path / "chinescan.sqlite3"]
    accepted, statuses = validate_allowed_roots(
        roots,
        hard_denied=[],
        soft_denied=[],
        allow_soft_denied=False,
        storage_paths=stores,
    )
    assert accepted == [roots[0].resolve()]
    assert [item.valid for item in statuses] == [True, False]
    assert statuses[1].reason_code == "overlaps_chinescan_storage"
    assert str(tmp_path) not in repr(statuses)


def test_case_insensitive_and_unicode_normalized_comparison() -> None:
    left = Path("C:/Users/Analyst/Caf\u00e9")
    right = Path("c:/users/analyst/Cafe\u0301")
    assert policy._key(left) == policy._key(right)


def test_windows_short_name_is_expanded_before_deny_check(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name != "nt":
        pytest.skip("Windows 8.3 short names are provided by NTFS only.")
    protected = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    monkeypatch.setattr(policy, "_expand_8dot3", lambda _path: protected)
    candidate = Path(str(protected.parent) + r"\PROGRA~1")
    decision = decide_path(
        candidate,
        allowed_roots=[protected.parent],
        hard_denied=[protected],
        must_exist=False,
    )
    assert not decision.allowed and decision.reason_code == "hard_denied"


def test_remote_drive_check_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(policy, "_windows_drive_remote", lambda _path: True)
    decision = decide_path(tmp_path, allowed_roots=[tmp_path])
    assert not decision.allowed
    assert decision.reason_code == "network_drive"


def test_windows_drive_type_remote_is_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name != "nt":
        pytest.skip("GetDriveTypeW is available only on Windows.")

    class _Kernel32:
        @staticmethod
        def GetDriveTypeW(root: str) -> int:
            assert root == "Z:\\"
            return 4  # DRIVE_REMOTE

    monkeypatch.setattr(policy.ctypes, "windll", type("_Windll", (), {"kernel32": _Kernel32})())
    assert policy._windows_drive_remote(Path("Z:\\approved")) is True


def _make_junction(link: Path, target: Path) -> None:
    if os.name != "nt":
        pytest.skip("NTFS directory junctions can only be created on Windows.")
    safe_link = str(link).replace("'", "''")
    safe_target = str(target).replace("'", "''")
    command = f"New-Item -ItemType Junction -Path '{safe_link}' -Target '{safe_target}' | Out-Null"
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
    )


def test_rejects_symlink_or_junction_component(tmp_path: Path) -> None:
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "link"
    if os.name == "nt":
        _make_junction(link, outside)
    else:
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"Could not create a temporary symlink: {type(exc).__name__}.")
    decision = decide_path(link, allowed_roots=[root])
    assert not decision.allowed
    assert decision.reason_code == "reparse_point"


def test_directory_swap_to_junction_between_selection_and_use_is_rejected(tmp_path: Path) -> None:
    root, outside = tmp_path / "root", tmp_path / "outside"
    replaceable, secret_child = root / "replaceable", outside / "secret-child"
    replaceable.mkdir(parents=True)
    secret_child.mkdir(parents=True)
    browser = FilesystemBrowserService([root], [], [], False)
    root_entry = browser.roots_view("session-a", "project_directory")["items"][0]
    selected = browser.list_view("session-a", "project_directory", str(root_entry["directory_id"]))[
        "items"
    ][0]
    import shutil

    shutil.rmtree(replaceable)
    if os.name == "nt":
        _make_junction(replaceable, outside)
    else:
        try:
            replaceable.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"Could not create a temporary symlink: {type(exc).__name__}.")
    with pytest.raises(ValueError, match="directory_unavailable"):
        browser.list_view("session-a", "project_directory", str(selected["directory_id"]))


def test_browser_capability_session_and_expiry_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    browser = FilesystemBrowserService([root], [], [], False)
    roots = browser.roots_view("session-a", "project_directory")
    directory_id = str(roots["items"][0]["directory_id"])
    with pytest.raises(ValueError, match="directory_unavailable"):
        browser.list_view("session-b", "project_directory", directory_id)
    with pytest.raises(ValueError, match="directory_unavailable"):
        browser.list_view("session-a", "log_location", directory_id)

    now = [100.0]
    monkeypatch.setattr(policy.time, "monotonic", lambda: now[0])
    token = browser.roots_view("session-a", "project_directory")["items"][0]["directory_id"]
    now[0] += policy.ID_TTL_SECONDS + 1
    with pytest.raises(ValueError, match="directory_unavailable"):
        browser.list_view("session-a", "project_directory", str(token))


def test_pagination_is_capped_stable_and_cursor_bound(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "alpha").mkdir()
    (root / "bravo").mkdir()
    browser = FilesystemBrowserService([root], [], [], False)
    root_id = str(browser.roots_view("s", "project_directory")["items"][0]["directory_id"])
    first = browser.list_view("s", "project_directory", root_id, limit=1)
    assert first["selectable"] is True
    assert first["items"][0]["name"] == "alpha"
    assert first["breadcrumbs"][0]["name"] == "Approved folder 1"
    (root / "aardvark").mkdir()
    second = browser.list_view(
        "s", "project_directory", root_id, cursor=str(first["next_cursor"]), limit=1
    )
    assert second["items"][0]["name"] == "bravo"
    with pytest.raises(ValueError, match="invalid_page_size"):
        browser.list_view("s", "project_directory", root_id, limit=MAX_PAGE_SIZE + 1)
    with pytest.raises(ValueError, match="cursor_unavailable"):
        browser.list_view(
            "other", "project_directory", root_id, cursor=str(first["next_cursor"]), limit=1
        )


def test_directory_entry_limit_is_reported_as_truncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    for name in ("a", "b", "c"):
        (root / name).mkdir()
    monkeypatch.setattr(policy, "MAX_DIRECTORY_ENTRIES", 2)
    browser = FilesystemBrowserService([root], [], [], False)
    root_id = str(browser.roots_view("s", "project_directory")["items"][0]["directory_id"])
    page = browser.list_view("s", "project_directory", root_id, limit=1)
    assert page["truncated"] is True
    assert page["next_cursor"] is not None


def test_directory_scan_cap_counts_files_even_though_they_are_not_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()

    class _FileEntry:
        def __init__(self, name: str) -> None:
            self.name = name

        @staticmethod
        def is_dir(*, follow_symlinks: bool) -> bool:
            return False

    class _Entries:
        def __enter__(self):
            return iter([_FileEntry("a"), _FileEntry("b"), _FileEntry("c")])

        @staticmethod
        def __exit__(*args) -> None:
            return None

    monkeypatch.setattr(policy, "MAX_DIRECTORY_ENTRIES", 2)
    monkeypatch.setattr(policy.os, "scandir", lambda _directory: _Entries())
    browser = FilesystemBrowserService([root], [], [], False)
    root_id = str(browser.roots_view("s", "project_directory")["items"][0]["directory_id"])

    page = browser.list_view("s", "project_directory", root_id)

    assert page["items"] == []
    assert page["truncated"] is True
