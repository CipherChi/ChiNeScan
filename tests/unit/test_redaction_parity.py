import json
import os
import secrets
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from chinescan.core.logging import redaction

_CORPUS = Path(__file__).parents[1] / "fixtures" / "redaction_corpus.json"
_REQUESTED_MODE = os.environ.get("CHINESCAN_ENGINE", "auto").strip().lower() or "auto"


def _native_or_skip():
    try:
        import chinescan_engine
    except ImportError:
        if _REQUESTED_MODE == "rust":
            pytest.fail("CHINESCAN_ENGINE=rust requires the chinescan_engine extension")
        pytest.skip("chinescan_engine is not installed")
    return chinescan_engine


def _all_parity_inputs(tmp_path: Path) -> list[str]:
    values = json.loads(_CORPUS.read_text(encoding="utf-8"))
    token = secrets.token_urlsafe(32)
    argon = "$argon2id$v=19$m=65536,t=3,p=4$salt$encodedhash"
    digest_values = ["a" * 32, "b" * 40, "c" * 64]
    windows_path = str(tmp_path / "profile" / "private.txt")
    secret = "SyntheticCanaryValue-1234567890"
    values.extend(
        [
            "prefix " + ("x" * 1_000) + "_secret=" + "synthetic-long-key-canary",
            *["unlabelled=" + value for value in (argon, token)],
            " ".join([*digest_values, token, argon]),
            "digests " + " ".join(digest_values) + " token " + token + " hash " + argon,
            f"digests {digest_values} token {token} hash {argon}",
            "x" * 2_000 + " password=" + secret + " " + "y" * 2_000,
            "ordinary-text-" * 2_000,
            "password=synthetic-canary " * 2_000,
            "password=" + token + "; path=" + windows_path,
            "untrusted third-party message: " + argon + " path=" + windows_path,
            "C:" + windows_path,
        ]
    )
    return values


def test_engine_selection_matches_requested_mode() -> None:
    native = None
    try:
        import chinescan_engine as native
    except ImportError:
        pass
    if _REQUESTED_MODE == "rust":
        assert native is not None
        assert redaction.engine_in_use() == "rust"
    elif _REQUESTED_MODE == "python":
        assert redaction.engine_in_use() == "python"
    else:
        assert _REQUESTED_MODE == "auto"
        assert redaction.engine_in_use() == ("rust" if native is not None else "python")


def test_auto_mode_falls_back_and_logs_one_sanitized_warning(monkeypatch, caplog) -> None:
    secret = "SyntheticCanarySecret-1234567890"

    def broken_native(_value: str) -> str:
        raise RuntimeError(secret)

    monkeypatch.setattr(redaction, "_ENGINE_REQUESTED", "auto")
    monkeypatch.setattr(redaction, "_ENGINE_IN_USE", "rust")
    monkeypatch.setattr(redaction, "_rust_engine", SimpleNamespace(redact_text=broken_native))
    monkeypatch.setattr(redaction, "_RUST_FAILURE_WARNED", False)
    monkeypatch.setattr(redaction, "_LOGGING_RUST_FAILURE", False)
    assert redaction._redact_string(f"password={secret}") == "password=[REDACTED]"
    assert redaction._redact_string(f"password={secret}") == "password=[REDACTED]"
    assert caplog.text.count("Rust redaction failed; using the Python redactor") == 1
    assert secret not in caplog.text


def test_rust_mode_reraises_native_failure(monkeypatch) -> None:
    def broken_native(_value: str) -> str:
        raise RuntimeError("synthetic native failure")

    monkeypatch.setattr(redaction, "_ENGINE_REQUESTED", "rust")
    monkeypatch.setattr(redaction, "_ENGINE_IN_USE", "rust")
    monkeypatch.setattr(redaction, "_rust_engine", SimpleNamespace(redact_text=broken_native))
    with pytest.raises(RuntimeError, match="synthetic native failure"):
        redaction.redact("safe")


def test_python_and_rust_outputs_match_the_full_corpus(tmp_path: Path) -> None:
    native = _native_or_skip()
    for value in _all_parity_inputs(tmp_path):
        expected = redaction._redact_text_python(value)
        assert native.redact_text(value) == expected, repr(value[:160])


def test_python_and_rust_preserve_source_names_and_locations() -> None:
    native = _native_or_skip()
    values = [
        "def get_api_key_status(self):",
        "scripts/secret_rotation_audit.py:101",
        "api_key = SyntheticCanaryValue-1234567890",
    ]
    for value in values:
        assert native.redact_text(value) == redaction._redact_text_python(value)
    assert native.redact_text(values[0]) == values[0]
    assert native.redact_text(values[1]) == values[1]
    assert "[REDACTED]" in native.redact_text(values[2])


def test_migration_location_and_token_response_are_preserved() -> None:
    native = _native_or_skip()
    values = [
        "supabase/migrations/20250101_x.sql:7",
        "const tokenResponse = await fetch(googleTokenUrl, {",
    ]
    for value in values:
        assert redaction._redact_text_python(value) == value
        assert native.redact_text(value) == value


def test_engine_info_reports_build_versions() -> None:
    native = _native_or_skip()
    info = native.engine_info()
    assert set(info) == {"version", "api_version", "regex_crate"}
    assert info["version"] == native.__version__
    assert info["api_version"] == native.ENGINE_API_VERSION == 1
    assert info["regex_crate"] == "1.11.3"


def test_oversize_text_fails_closed_identically() -> None:
    native = _native_or_skip()
    value = "x" * (redaction.MAX_REDACT_STRING_CHARS + 1)
    assert native.redact_text(value) == redaction._redact_text_python(value)
    assert native.redact_text(value) == redaction.REDACTION_LIMIT_MARKER


def test_r1_performance_inputs_complete_on_both_paths() -> None:
    native = _native_or_skip()
    inputs = [
        "x" * 2_000,
        "x" * 4_000,
        "x" * 20_000,
        ("x:" * 10_000) + "password=synthetic-canary",
        ("x" * 20_000) + "_secret=synthetic-canary",
    ]
    # Keep the same per-call ceiling for both implementations and every input.
    time_limit_seconds = 10.0
    for value in inputs:
        started = time.perf_counter()
        python_result = redaction._redact_text_python(value)
        python_elapsed = time.perf_counter() - started
        started = time.perf_counter()
        rust_result = native.redact_text(value)
        rust_elapsed = time.perf_counter() - started
        assert python_result == rust_result
        assert python_elapsed < time_limit_seconds
        assert rust_elapsed < time_limit_seconds
