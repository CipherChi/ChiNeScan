from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chinescan.core.accounts import create_operator
from chinescan.web.app import create_app
from chinescan.web.auth import (
    confirm_totp_enrollment,
    disable_operator_totp,
    generate_totp_code,
    start_totp_enrollment,
    totp_code_at,
    verify_operator_totp,
)


def test_rfc_6238_sha1_reference_vectors() -> None:
    secret = b"12345678901234567890"
    assert totp_code_at(secret, 59, digits=8) == "94287082"
    assert totp_code_at(secret, 1_111_111_109, digits=8) == "07081804"
    assert totp_code_at(secret, 1_111_111_111, digits=8) == "14050471"


def test_enrollment_expiry_single_use_replay_and_recovery_codes(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "totp@example.test", "Synthetic secure passphrase 71!")
    now = 1_700_000_000
    secret = start_totp_enrollment(credential, now=now)
    code = generate_totp_code(secret, now=now)
    recovery_codes = confirm_totp_enrollment(credential, code, now=now)
    assert len(recovery_codes) >= 8
    assert not confirm_totp_enrollment(credential, code, now=now)
    next_code = generate_totp_code(secret, now=now + 30)
    assert verify_operator_totp(credential, next_code, now=now + 30) is True
    assert verify_operator_totp(credential, next_code, now=now + 30) is False
    assert verify_operator_totp(credential, recovery_codes[0], now=now + 30) is True
    assert verify_operator_totp(credential, recovery_codes[0], now=now + 30) is False
    disable_code = generate_totp_code(secret, now=now + 60)
    assert disable_operator_totp(credential, disable_code, now=now + 60)


def test_expired_enrollment_cannot_be_confirmed(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "totp@example.test", "Synthetic secure passphrase 71!")
    now = 1_700_000_000
    secret = start_totp_enrollment(credential, now=now)
    code = generate_totp_code(secret, now=now + 600)
    assert not confirm_totp_enrollment(credential, code, now=now + 600)


def test_totp_verification_is_rate_limited(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "totp@example.test", "Synthetic secure passphrase 71!")
    now = 1_700_000_000
    secret = start_totp_enrollment(credential, now=now)
    assert confirm_totp_enrollment(
        credential, generate_totp_code(secret, now=now), now=now
    )
    for _ in range(5):
        assert not verify_operator_totp(credential, "000000", now=now)
    valid_next_code = generate_totp_code(secret, now=now + 30)
    assert not verify_operator_totp(credential, valid_next_code, now=now + 30)
    after_rate_window_code = generate_totp_code(secret, now=now + 300)
    assert verify_operator_totp(credential, after_rate_window_code, now=now + 300)


def test_enrollment_does_not_replace_an_enabled_totp_secret(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "totp@example.test", "Synthetic secure passphrase 71!")
    now = 1_700_000_000
    secret = start_totp_enrollment(credential, now=now)
    confirm_totp_enrollment(credential, generate_totp_code(secret, now=now), now=now)
    with pytest.raises(ValueError):
        start_totp_enrollment(credential, now=now)


def test_login_requires_single_use_totp_and_keeps_failures_generic(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "totp@example.test", "Synthetic secure passphrase 71!")
    secret = start_totp_enrollment(credential)
    assert confirm_totp_enrollment(
        credential, generate_totp_code(secret), now=None
    )
    client = TestClient(
        create_app(tmp_path / "db.sqlite3", credential, serve_frontend=False),
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
    )
    headers = {"Origin": "http://127.0.0.1"}
    body = {"email": "totp@example.test", "password": "Synthetic secure passphrase 71!"}
    try:
        no_code = client.post("/api/auth/login", json=body, headers=headers)
        wrong_password = client.post(
            "/api/auth/login",
            json={"email": body["email"], "password": "wrong"},
            headers=headers,
        )
        assert no_code.status_code == wrong_password.status_code == 401
        assert no_code.json() == wrong_password.json()

        future_now = int(__import__("time").time()) + 30
        code = generate_totp_code(secret, now=future_now)
        success = client.post(
            "/api/auth/login", json=body | {"totp_code": code}, headers=headers
        )
        assert success.status_code == 200
        replay = client.post(
            "/api/auth/login", json=body | {"totp_code": code}, headers=headers
        )
        assert replay.status_code == 401
        assert replay.json() == no_code.json()
        assert secret not in success.text
    finally:
        client.close()
