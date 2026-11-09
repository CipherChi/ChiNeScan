"""Single, defensive redaction implementation for logs and user-facing errors."""

from __future__ import annotations

import importlib
import logging
import os
import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"
REDACTION_LIMIT_MARKER = "[REDACTED: safe processing limit exceeded]"
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:password|passwd|pwd|hash|token|secret|api[_-]?key|apikey|authorization|"
    r"cookie|session|csrf|credential)"
)
_ASSIGNMENT_VALUE = re.compile(
    r'"(?:\\.|[^"\\\r\n])*"|\'(?:\\.|[^\'\\\r\n])*\'|<[^>]*>|[^\s,;}\]]+'
)
_ASSIGNMENT_DELIMITER = re.compile(r"[:=]")
_ARGON = re.compile(r"\$argon2(?:id|i|d)\$[^\s\"';}]+", re.IGNORECASE)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_TOKEN_RUN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])")
_QUOTED_WINDOWS = re.compile(r"(?i)(?P<quote>[\"'])(?P<path>(?:[A-Z]:\\|\\\\)[^\"']+)\1")
_WINDOWS_PATH = re.compile(r"(?i)(?<![\w])(?:[A-Z]:\\|\\\\)[^\s\"'<>`,;)}\]]+")
_POSIX_PATH = re.compile(
    r"(?<![\w:/])/(?:Users|home|root|tmp|var/tmp|private/tmp|var/folders|etc|opt|mnt)/"
    r"[^\s\"'<>`,;)}\]]+"
)

# Bounds apply to one top-level redaction operation. Exceeding any bound fails
# closed with an actionable marker; callers never receive a partial value.
MAX_REDACT_STRING_CHARS = 1_000_000
MAX_REDACT_TOTAL_CHARS = 8_000_000
MAX_REDACT_DEPTH = 32
MAX_REDACT_NODES = 100_000
MAX_SENSITIVE_KEY_CHARS = 256
_SOURCE_EXTENSIONS = (
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".rs",
    ".go",
    ".java",
    ".cs",
    ".rb",
    ".php",
    ".sh",
    ".ps1",
)

_ENGINE_REQUESTED = os.environ.get("CHINESCAN_ENGINE", "auto").strip().lower() or "auto"
if _ENGINE_REQUESTED not in {"auto", "python", "rust"}:
    raise ValueError("CHINESCAN_ENGINE must be one of: auto, python, rust")
_rust_engine: Any
if _ENGINE_REQUESTED == "python":
    _rust_engine = None
else:
    try:
        _rust_engine = importlib.import_module("chinescan_engine")
    except ImportError:
        _rust_engine = None
if _ENGINE_REQUESTED == "rust" and _rust_engine is None:
    raise RuntimeError("CHINESCAN_ENGINE=rust requires the chinescan_engine extension") from None
_ENGINE_IN_USE = (
    "rust"
    if _ENGINE_REQUESTED == "rust" or (_ENGINE_REQUESTED == "auto" and _rust_engine is not None)
    else "python"
)
_RUST_FAILURE_WARNED = False
_LOGGING_RUST_FAILURE = False
_LOGGER = logging.getLogger(__name__)


class _RedactionLimitExceeded(Exception):
    pass


class _RustRedactionFailure(Exception):
    def __init__(self, native_error: Exception) -> None:
        super().__init__("Rust redaction failed")
        self.native_error = native_error


def engine_in_use() -> str:
    """Return the redaction implementation selected when this module loaded."""
    return _ENGINE_IN_USE


def _redact_string(value: str) -> str:
    global _RUST_FAILURE_WARNED, _LOGGING_RUST_FAILURE
    if _ENGINE_IN_USE != "rust" or _LOGGING_RUST_FAILURE:
        return _redact_string_python(value)
    try:
        result: str = _rust_engine.redact_text(value)
        return result
    except Exception as error:
        if _ENGINE_REQUESTED == "rust":
            raise _RustRedactionFailure(error) from error
        if not _RUST_FAILURE_WARNED:
            _RUST_FAILURE_WARNED = True
            _LOGGING_RUST_FAILURE = True
            try:
                _LOGGER.warning("Rust redaction failed; using the Python redactor")
            finally:
                _LOGGING_RUST_FAILURE = False
        return _redact_string_python(value)


def _redact_text_python(value: str) -> str:
    """Run the Python string path directly, for parity checks and fallback."""
    if len(value) > MAX_REDACT_STRING_CHARS:
        return REDACTION_LIMIT_MARKER
    return _redact_string_python(value)


def _redact_string_python(value: str) -> str:
    try:
        value = _redact_assignments(value)
        value = _ARGON.sub(REDACTED, value)
        value = _BEARER.sub("Bearer " + REDACTED, value)
        for env_name in (
            "USERPROFILE",
            "HOME",
            "TEMP",
            "TMP",
            "APPDATA",
            "LOCALAPPDATA",
            "CHINESCAN_CONFIG_PATH",
            "CHINESCAN_DATABASE_PATH",
            "CHINESCAN_REPORTS_DIR",
        ):
            root = os.environ.get(env_name)
            if root:
                value = re.sub(re.escape(root), "[PATH]", value, flags=re.IGNORECASE)
        value = _QUOTED_WINDOWS.sub(
            lambda match: match.group("quote") + "[PATH]" + match.group("quote"), value
        )
        value = _WINDOWS_PATH.sub("[PATH]", value)
        value = _POSIX_PATH.sub("[PATH]", value)

        def token_replacement(match: re.Match[str]) -> str:
            candidate = match.group(0)
            if _UUID.fullmatch(candidate) or re.fullmatch(r"(?i)[a-f0-9]{32,}", candidate):
                return candidate
            # Separators are common in source symbols and project paths. They
            # do not add entropy by themselves; require mixed case or digits.
            has_letters = bool(re.search(r"[A-Za-z]", candidate))
            high_entropy_shape = has_letters and (
                bool(re.search(r"[0-9]", candidate))
                or (bool(re.search(r"[a-z]", candidate)) and bool(re.search(r"[A-Z]", candidate)))
            )
            return REDACTED if high_entropy_shape else candidate

        value = _TOKEN_RUN.sub(token_replacement, value)
        return value
    except Exception:
        return REDACTED


def _redact_assignments(value: str) -> str:
    """Redact sensitive key assignments with a forward delimiter scan.

    Walking backward only across the key immediately before each delimiter
    avoids regex retries from every character in long untrusted strings while
    retaining support for key names of any length.
    """
    output: list[str] = []
    cursor = 0
    search_from = 0
    value_length = len(value)
    whitespace_checked_to = 0
    token_start = 0
    while search_from < value_length:
        match = _ASSIGNMENT_DELIMITER.search(value, search_from)
        if match is None:
            break
        delimiter = match.start()

        for position in range(whitespace_checked_to, delimiter):
            if value[position].isspace():
                token_start = position + 1
        whitespace_checked_to = delimiter

        key_end = delimiter
        while key_end > search_from and value[key_end - 1].isspace():
            key_end -= 1
        closing_quote = value[key_end - 1] if key_end > search_from else ""
        if closing_quote in {"'", '"'}:
            key_end -= 1
        key_start = key_end
        while key_start > search_from and (
            value[key_start - 1].isalnum() or value[key_start - 1] in "_.-"
        ):
            key_start -= 1
        key = value[key_start:key_end]
        valid_start = bool(key) and (key[0].isalpha() or key[0] == "_")
        if value[delimiter] == ":":
            path_value_start = delimiter + 1
            while path_value_start < value_length and value[path_value_start].isspace():
                path_value_start += 1
            number_end = path_value_start
            while number_end < value_length and value[number_end].isdigit():
                number_end += 1
            numeric_value = number_end > path_value_start and (
                number_end == value_length
                or value[number_end].isspace()
                or value[number_end] in ",;}]"
            )
            if numeric_value:
                preceding = value[token_start:delimiter].casefold()
                if (
                    "/" in preceding
                    or "\\" in preceding
                    or preceding.endswith(_SOURCE_EXTENSIONS)
                ):
                    search_from = delimiter + 1
                    continue
        if valid_start and _sensitive_key_match(key):
            value_start = delimiter + 1
            while value_start < value_length and value[value_start].isspace():
                value_start += 1
            match = _ASSIGNMENT_VALUE.match(value, value_start)
            if match:
                raw = match.group(0)
                if raw[:1] in {"'", '"'} and raw[-1:] == raw[:1]:
                    marker = f"{raw[0]}{REDACTED}{raw[0]}"
                elif raw.startswith("<") and raw.endswith(">"):
                    marker = f"<{REDACTED}>"
                else:
                    marker = REDACTED
                output.extend((value[cursor:value_start], marker))
                cursor = match.end()
                search_from = cursor
                continue
        search_from = delimiter + 1
    if not output:
        return value
    output.append(value[cursor:])
    return "".join(output)


def _sensitive_key_match(key: str) -> bool:
    """Match long keys in bounded overlapping windows without missing a suffix."""
    # OAuth response variables commonly contain both ``token`` and ``Response``;
    # they are identifiers, not secret-bearing keys (and often precede ``await``).
    if re.fullmatch(r"(?i)tokenResponse", key):
        return False
    overlap = 32
    step = MAX_SENSITIVE_KEY_CHARS - overlap
    return any(
        _SENSITIVE_KEY.search(key[start : start + MAX_SENSITIVE_KEY_CHARS])
        for start in range(0, len(key), step)
    )


def redact(value: Any) -> Any:
    """Redact recursively within explicit resource bounds; fail closed on overflow."""
    budget = [0, 0]
    try:
        return _redact(value, budget, 0)
    except _RedactionLimitExceeded:
        return REDACTION_LIMIT_MARKER
    except _RustRedactionFailure as failure:
        raise failure.native_error from None
    except Exception:
        return REDACTED


def _redact(value: Any, budget: list[int], depth: int) -> Any:
    if depth > MAX_REDACT_DEPTH:
        raise _RedactionLimitExceeded
    budget[0] += 1
    if budget[0] > MAX_REDACT_NODES:
        raise _RedactionLimitExceeded
    if isinstance(value, str) and len(value) > MAX_REDACT_STRING_CHARS:
        raise _RedactionLimitExceeded
    if isinstance(value, bytes) and len(value) > MAX_REDACT_STRING_CHARS:
        raise _RedactionLimitExceeded
    if isinstance(value, (str, bytes)):
        budget[1] += len(value)
        if budget[1] > MAX_REDACT_TOTAL_CHARS:
            raise _RedactionLimitExceeded
    try:
        if isinstance(value, Mapping):
            output: dict[Any, Any] = {}
            for key, item in value.items():
                budget[0] += 1
                if budget[0] > MAX_REDACT_NODES:
                    raise _RedactionLimitExceeded
                if isinstance(key, str) and len(key) > MAX_REDACT_STRING_CHARS:
                    raise _RedactionLimitExceeded
                if isinstance(key, str):
                    budget[1] += len(key)
                    if budget[1] > MAX_REDACT_TOTAL_CHARS:
                        raise _RedactionLimitExceeded
                safe_key = _redact_string(key) if isinstance(key, str) else key
                output[safe_key] = (
                    REDACTED
                    if _SENSITIVE_KEY.search(str(key))
                    else _redact(item, budget, depth + 1)
                )
            return output
        if isinstance(value, list):
            return [_redact(item, budget, depth + 1) for item in value]
        if isinstance(value, tuple):
            return tuple(_redact(item, budget, depth + 1) for item in value)
        if isinstance(value, set):
            return {_redact(item, budget, depth + 1) for item in value}
        if isinstance(value, str):
            return _redact_string(value)
        if isinstance(value, bytes):
            try:
                return _redact_string(value.decode("utf-8", errors="replace"))
            except Exception:
                return REDACTED
        return value
    except Exception:
        raise
