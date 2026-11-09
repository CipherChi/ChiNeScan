"""Bounded local log file, directory, gzip, ZIP, and tar ingestion."""

from __future__ import annotations

import gzip
import os
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Protocol

from chinescan.core.models.investigation import Event
from chinescan.log_analysis.parsers import parse_log_data

MAX_LOG_FILES = 10_000
MAX_FILE_BYTES = 25_000_000
MAX_TOTAL_BYTES = 250_000_000
MAX_ARCHIVE_MEMBERS = 1_000
MAX_ARCHIVE_BYTES = 100_000_000
MAX_EVENTS = 100_000
_IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist"}
_FORMATS = {".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".cef", ".leef", ".auth"}
_ARCHIVES = {".zip", ".gz", ".tar", ".tgz"}


@dataclass
class IngestResult:
    """Normalized events and non-fatal ingestion diagnostics."""

    events: list[Event] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source_count: int = 0
    bytes_processed: int = 0


class LogIngestionError(ValueError):
    """Input could not be accessed or exceeded ingestion safety limits."""


class _ExpansionLimitReached(ValueError):
    """The aggregate expanded-byte budget was exhausted while streaming a member."""


class BinaryReader(Protocol):
    """Minimal byte-stream protocol shared by normal and archive readers."""

    def read(self, size: int = -1) -> bytes: ...


def ingest_path(path: Path) -> IngestResult:
    """Read one local log file or directory; archives are streamed and never extracted."""
    try:
        root = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise LogIngestionError("Input path does not exist or is inaccessible.") from exc
    if path.is_symlink():
        raise LogIngestionError("Symbolic-link log inputs are not accepted.")
    if not root.is_file() and not root.is_dir():
        raise LogIngestionError("Input must be a regular file or directory.")
    candidates = _files(root) if root.is_dir() else [root]
    result = IngestResult()
    total_bytes = 0
    for candidate in candidates[:MAX_LOG_FILES]:
        if candidate.is_symlink() or not _supported(candidate.name):
            if root.is_file():
                result.errors.append(f"{candidate}: unsupported log format")
            continue
        try:
            size = candidate.stat().st_size
        except OSError:
            result.errors.append(f"{candidate}: could not read file metadata")
            continue
        is_archive = candidate.suffix.lower() in _ARCHIVES or candidate.name.lower().endswith(
            (".tar.gz", ".tar.bz2", ".tar.xz")
        )
        total_bytes += size if is_archive else min(size, MAX_FILE_BYTES)
        if total_bytes > MAX_TOTAL_BYTES:
            raise LogIngestionError("Input exceeds the total ingestion size limit.")
        result.source_count += 1
        _ingest_file(candidate, result)
        if any("total expanded-byte limit reached" in error for error in result.errors):
            break
        if len(result.events) >= MAX_EVENTS:
            result.errors.append("Input reached the event count limit.")
            result.events = result.events[:MAX_EVENTS]
            break
    if len(candidates) > MAX_LOG_FILES:
        result.errors.append("Input reached the file count limit.")
    return result


def _files(root: Path) -> list[Path]:
    found: list[Path] = []

    def on_error(_: OSError) -> None:
        raise LogIngestionError("A log directory could not be read.")

    for directory, dirnames, filenames in os.walk(root, followlinks=False, onerror=on_error):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in _IGNORED_DIRS and not (Path(directory) / name).is_symlink()
        )
        for filename in sorted(filenames):
            candidate = Path(directory) / filename
            if not candidate.is_symlink() and _supported(filename):
                found.append(candidate)
                if len(found) > MAX_LOG_FILES:
                    return found
    return found


def _supported(name: str) -> bool:
    lower = name.lower()
    if lower.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        return True
    suffix = Path(lower).suffix
    return suffix in _FORMATS | _ARCHIVES


def _ingest_file(path: Path, result: IngestResult) -> None:
    lower = path.name.lower()
    try:
        if lower.endswith(".zip"):
            _ingest_zip(path, result)
        elif lower.endswith((".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz")):
            _ingest_tar(path, result)
        elif lower.endswith(".gz"):
            _ingest_gzip(path, result)
        else:
            data, truncated = _read_log_prefix(path, _remaining_member_budget(result))
            read_size = len(data)
            if truncated:
                data = _complete_lines_prefix(data)
            _parse_member(data, path.name, str(path), result)
            result.bytes_processed += read_size - len(data)
            if truncated:
                result.errors.append(
                    f"{path}: truncated at the per-file limit after reading {read_size} bytes; "
                    "remaining log data was not analyzed."
                )
    except _ExpansionLimitReached:
        result.errors.append(f"{path}: total expanded-byte limit reached")
    except Exception as exc:  # isolate malformed/untrusted input with an explicit diagnostic
        result.errors.append(f"{path}: archive or file read failed ({type(exc).__name__})")


def _ingest_gzip(path: Path, result: IngestResult) -> None:
    with gzip.open(path, "rb") as stream:
        total_remaining = MAX_TOTAL_BYTES - result.bytes_processed
        if total_remaining < MAX_FILE_BYTES:
            data = _read_stream(stream, max(1, total_remaining))
            truncated = False
        else:
            data, truncated = _read_log_stream_prefix(stream, min(MAX_FILE_BYTES, total_remaining))
    member_name = path.name[:-3]
    read_size = len(data)
    if truncated:
        data = _complete_lines_prefix(data)
    _parse_member(data, member_name, f"{path}::{member_name}", result)
    result.bytes_processed += read_size - len(data)
    if truncated:
        result.errors.append(
            f"{path}: decompressed log truncated at the per-file limit after reading "
            f"{read_size} bytes; remaining log data was not analyzed."
        )


def _read_log_prefix(path: Path, limit: int) -> tuple[bytes, bool]:
    with path.open("rb") as stream:
        return _read_log_stream_prefix(stream, limit)


def _read_log_stream_prefix(stream: BinaryReader, limit: int) -> tuple[bytes, bool]:
    """Read one bounded log prefix and distinguish true truncation from an exact-size file."""
    output = bytearray()
    while len(output) < limit:
        chunk = stream.read(min(64 * 1024, limit - len(output)))
        if not chunk:
            return bytes(output), False
        output.extend(chunk)
    return bytes(output), bool(stream.read(1))


def _complete_lines_prefix(data: bytes) -> bytes:
    """Drop only the incomplete trailing record from a prefix known to be truncated."""
    boundary = data.rfind(b"\n")
    return data[: boundary + 1] if boundary >= 0 else b""


def _ingest_zip(path: Path, result: IngestResult) -> None:
    total = 0
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            result.errors.append(f"{path}: archive member count limit reached")
        for info in infos[:MAX_ARCHIVE_MEMBERS]:
            mode = info.external_attr >> 16
            if info.is_dir() or stat.S_ISLNK(mode) or not _supported(info.filename):
                continue
            if info.file_size > MAX_FILE_BYTES or info.file_size > MAX_ARCHIVE_BYTES - total:
                result.errors.append(f"{path}::{info.filename}: archive member exceeds size limit")
                continue
            with archive.open(info) as stream:
                try:
                    data = _read_stream(stream, _remaining_member_budget(result, total))
                except _ExpansionLimitReached:
                    result.errors.append(f"{path}: total expanded-byte limit reached")
                    return
            total += len(data)
            _parse_member(data, info.filename, f"{path}::{info.filename}", result)


def _ingest_tar(path: Path, result: IngestResult) -> None:
    total = 0
    with tarfile.open(path, mode="r:*") as archive:
        for index, member in enumerate(archive):
            if index >= MAX_ARCHIVE_MEMBERS:
                result.errors.append(f"{path}: archive member count limit reached")
                break
            if not member.isfile() or not _supported(member.name):
                continue
            if member.size > MAX_FILE_BYTES or member.size > MAX_ARCHIVE_BYTES - total:
                result.errors.append(f"{path}::{member.name}: archive member exceeds size limit")
                continue
            stream = archive.extractfile(member)
            if stream is None:
                result.errors.append(f"{path}::{member.name}: archive member could not be read")
                continue
            with stream:
                try:
                    data = _read_stream(stream, _remaining_member_budget(result, total))
                except _ExpansionLimitReached:
                    result.errors.append(f"{path}: total expanded-byte limit reached")
                    return
            total += len(data)
            _parse_member(data, member.name, f"{path}::{member.name}", result)


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        return _read_stream(stream, limit)


def _remaining_member_budget(result: IngestResult, archive_bytes: int = 0) -> int:
    remaining = min(
        MAX_FILE_BYTES, MAX_ARCHIVE_BYTES - archive_bytes, MAX_TOTAL_BYTES - result.bytes_processed
    )
    if remaining <= 0:
        raise _ExpansionLimitReached("total expanded-byte limit reached")
    return remaining


def _read_stream(stream: BinaryReader, limit: int) -> bytes:
    output = bytearray()
    while len(output) < limit:
        chunk = stream.read(min(64 * 1024, limit - len(output)))
        if not chunk:
            break
        output.extend(chunk)
    if len(output) == limit:
        raise _ExpansionLimitReached("total expanded-byte limit reached")
    return bytes(output)


def _parse_member(data: bytes, name: str, source_ref: str, result: IngestResult) -> None:
    result.bytes_processed += len(data)
    batch = parse_log_data(data, PurePosixPath(name).name, source_ref)
    remaining = max(0, MAX_EVENTS - len(result.events))
    result.events.extend(batch.events[:remaining])
    if len(batch.events) > remaining:
        result.errors.append("Input reached the event count limit.")
    result.errors.extend(batch.errors)
