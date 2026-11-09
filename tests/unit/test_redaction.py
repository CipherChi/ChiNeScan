import logging
import secrets
from pathlib import Path

import pytest

from chinescan.core.logging.redaction import (
    MAX_REDACT_DEPTH,
    MAX_REDACT_STRING_CHARS,
    REDACTED,
    REDACTION_LIMIT_MARKER,
    redact,
)
from chinescan.core.logging.structured import configure_logging


@pytest.mark.parametrize(
    "text",
    [
        "password=value",
        "passwd: value",
        "pwd='value'",
        '"password_hash": "fake-hash"',
        "reset-token=<token-value>",
        "apiKey='value'",
        "sessionId=value",
        "csrf_token: value",
        "credential=value",
        "Cookie: value",
    ],
)
def test_redacts_sensitive_key_forms(text: str) -> None:
    output = redact(text)
    assert REDACTED in output
    assert "value" not in output


def test_redacts_sensitive_assignment_with_long_key_name() -> None:
    secret = "synthetic-long-key-canary"
    output = redact("prefix " + ("x" * 1_000) + "_secret=" + secret)
    assert secret not in output
    assert output.endswith("[REDACTED]")


def test_preserves_code_symbols_and_project_locations_but_redacts_assignments() -> None:
    source = (
        "def get_api_key_status(self):\n"
        "scripts/secret_rotation_audit.py:101\n"
        "api_key = SyntheticCanaryValue-1234567890"
    )
    output = redact(source)
    assert "def get_api_key_status(self):" in output
    assert "scripts/secret_rotation_audit.py:101" in output
    assert "SyntheticCanaryValue-1234567890" not in output
    assert "api_key = [REDACTED]" in output


@pytest.mark.parametrize(
    "secret",
    [
        "$argon2id$v=19$m=65536,t=3,p=4$salt$fakehash",
        "$argon2i$v=19$m=65536,t=3,p=4$salt$fakehash",
        "$argon2d$v=19$m=65536,t=3,p=4$salt$fakehash",
        "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJjYW5hcnkifQ.signature",
        "q4w3e2r1t0y9u8i7o6p5a4s3d2f1g0h9",
    ],
)
def test_redacts_secret_value_shapes(secret: str) -> None:
    output = redact(f"unlabelled={secret}")
    assert secret not in output


def test_redacts_nested_values_and_paths_and_is_idempotent(tmp_path: Path) -> None:
    windows_path = str(tmp_path / "profile" / "private.txt")
    data = {
        "passwordHash": "$argon2id$v=19$m=65536,t=3,p=4$salt$hash",
        "nested": [{"csrfToken": "canary-token-value"}, windows_path, ("plain",)],
    }
    safe = redact(data)
    assert safe["passwordHash"] == REDACTED
    assert safe["nested"][0]["csrfToken"] == REDACTED
    assert str(tmp_path) not in str(safe)
    assert redact(safe) == safe


def test_hashes_survive_but_generated_url_safe_tokens_and_argon_hashes_do_not() -> None:
    hashes = ["a" * 32, "b" * 40, "c" * 64]
    token = secrets.token_urlsafe(32)
    argon = "$argon2id$v=19$m=65536,t=3,p=4$salt$encodedhash"
    message = " ".join([*hashes, token, argon])
    output = redact(message)
    for digest in hashes:
        assert digest in output
    assert token not in output
    assert argon not in output


def test_log_messages_preserve_digests_and_scrub_token_and_argon_values(caplog) -> None:
    configure_logging()
    caplog.set_level(logging.INFO)
    hashes = ["a" * 32, "b" * 40, "c" * 64]
    token = secrets.token_urlsafe(32)
    argon = "$argon2id$v=19$m=65536,t=3,p=4$salt$encodedhash"
    logging.getLogger("chinescan.ioc").info("digests %s token %s hash %s", hashes, token, argon)
    for digest in hashes:
        assert digest in caplog.text
    assert token not in caplog.text
    assert argon not in caplog.text


def test_redactor_never_raises_on_unusual_values() -> None:
    class Broken:
        def __str__(self) -> str:
            raise RuntimeError("cannot stringify")

    class BrokenMapping(dict):
        def items(self):
            raise RuntimeError("cannot enumerate")

    assert redact(Broken()) is not None
    assert redact(BrokenMapping()) == REDACTED


def test_long_benign_and_sensitive_strings_are_processed_without_leaking() -> None:
    benign = "ordinary-text-" * 2_000
    secret = "SyntheticCanaryValue-1234567890"
    output = redact("x" * 2_000 + " password=" + secret + " " + "y" * 2_000)
    assert output.startswith("x" * 2_000)
    assert secret not in output
    assert REDACTED in output
    benign_output = redact(benign)
    assert benign_output != REDACTION_LIMIT_MARKER
    assert len(benign_output) <= len(benign)


def test_redaction_string_limit_is_inclusive_and_fails_closed() -> None:
    below_limit = "x" * (MAX_REDACT_STRING_CHARS - 1)
    at_limit = "x" * MAX_REDACT_STRING_CHARS
    assert len(redact(below_limit)) == len(below_limit)
    assert redact(at_limit) == at_limit
    over_limit = "x" * (MAX_REDACT_STRING_CHARS + 1)
    assert redact(over_limit) == REDACTION_LIMIT_MARKER
    sensitive_over_limit = "password=synthetic-canary " + "x" * (
        MAX_REDACT_STRING_CHARS - len("password=synthetic-canary ") + 1
    )
    output = redact(sensitive_over_limit)
    assert output == REDACTION_LIMIT_MARKER
    assert "synthetic-canary" not in output


def test_redaction_nesting_and_node_limits_fail_closed(monkeypatch) -> None:
    at_depth = "safe"
    for _ in range(MAX_REDACT_DEPTH):
        at_depth = [at_depth]
    assert redact(at_depth) == at_depth

    over_depth = [at_depth]
    assert redact(over_depth) == REDACTION_LIMIT_MARKER

    monkeypatch.setattr("chinescan.core.logging.redaction.MAX_REDACT_NODES", 5)
    assert redact(["safe"] * 2) == ["safe"] * 2
    assert redact(["safe"] * 4) == ["safe"] * 4  # root + four children = five nodes
    assert redact(["safe"] * 5) == REDACTION_LIMIT_MARKER


def test_redaction_total_character_budget_is_inclusive(monkeypatch) -> None:
    monkeypatch.setattr("chinescan.core.logging.redaction.MAX_REDACT_TOTAL_CHARS", 10)
    assert redact(["1234", "56789"]) == ["1234", "56789"]
    assert redact(["12345", "67890"]) == ["12345", "67890"]
    assert redact(["123456", "78901"]) == REDACTION_LIMIT_MARKER


def test_repeated_values_are_redacted_in_large_bounded_collections() -> None:
    values = [{"description": "password=synthetic-canary", "note": "safe"} for _ in range(2_000)]
    output = redact(values)
    assert len(output) == len(values)
    assert all(item["description"] == "password=[REDACTED]" for item in output)
    assert "synthetic-canary" not in repr(output)


def test_record_factory_redacts_uvicorn_and_third_party_logs_and_tracebacks(
    caplog, tmp_path: Path
) -> None:
    configure_logging()
    caplog.set_level(logging.INFO)
    token = "CanaryToken1234567890abcdefghijklmnopqrstuv"
    fake_hash = "$argon2id$v=19$m=65536,t=3,p=4$salt$fakehash"
    secret_path = str(tmp_path / "operator" / "credential.json")
    try:
        raise RuntimeError(f"password={token}; path={secret_path}")
    except RuntimeError:
        logging.getLogger("uvicorn.error").exception(
            "untrusted third-party message: %s", fake_hash, extra={"credential": secret_path}
        )
    captured = caplog.text
    assert token not in captured
    assert fake_hash not in captured
    assert secret_path not in captured
    assert REDACTED in captured
    assert "[PATH]" in captured


def test_logging_factory_does_not_reenter_logging_record_factory(monkeypatch, caplog) -> None:
    configure_logging()

    def unexpected_record_creation(_values):
        raise AssertionError("formatter must not recursively create log records")

    monkeypatch.setattr(logging, "makeLogRecord", unexpected_record_creation)
    caplog.set_level(logging.INFO)
    logging.getLogger("uvicorn.error").info("record factory remains responsive")
    assert "record factory remains responsive" in caplog.text
