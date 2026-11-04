"""Single-operator email credentials and process-local opaque sessions."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
RESET_TOKEN_TTL_SECONDS = 15 * 60
RESET_RATE_LIMIT_SECONDS = 60
SESSION_ABSOLUTE_TTL_SECONDS = 30 * 60
SESSION_IDLE_TTL_SECONDS = 10 * 60
TOTP_ENROLLMENT_TTL_SECONDS = 10 * 60
TOTP_VERIFICATION_WINDOW_SECONDS = 5 * 60
TOTP_VERIFICATION_MAX_ATTEMPTS = 5
TOTP_RECOVERY_CODE_COUNT = 10
_CREDENTIAL_LOCK = threading.RLock()
_COMMON_PASSWORDS = frozenset(
    line.strip().casefold()
    for line in resources.files("chinescan.core.data")
    .joinpath("common_passwords.txt")
    .read_text(encoding="utf-8")
    .splitlines()
    if line.strip() and not line.lstrip().startswith("#")
)
_DUMMY_HASH = PasswordHasher().hash("Chinescan dummy verification only")


class CredentialError(ValueError):
    """Credential file is missing or invalid."""


def normalize_email(email: str) -> str:
    """Trim and case-fold email for case-insensitive local identity lookup."""
    normalized = unicodedata.normalize("NFKC", email).strip().lower()
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        raise CredentialError("Enter a valid email address.")
    if len(normalized) > 254 or not EMAIL_RE.fullmatch(normalized):
        raise CredentialError("Enter a valid email address.")
    local, domain = normalized.rsplit("@", 1)
    if (
        len(local) > 64
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or len(domain) > 253
        or any(not label or len(label) > 63 for label in domain.split("."))
        or any(label.startswith("-") or label.endswith("-") for label in domain.split("."))
    ):
        raise CredentialError("Enter a valid email address.")
    return normalized


def _read(path: Path) -> dict[str, Any]:
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError
        return data
    except (OSError, ValueError, TypeError) as exc:
        raise CredentialError("Local operator account is unavailable or invalid.") from exc


def _write_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".operator-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(temp_name, 0o600)
        except OSError:
            pass
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


class LoginThrottle:
    """Per-process throttling for local authentication requests."""

    def __init__(self, limit: int = 5, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allowed(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            recent = [
                stamp for stamp in self._failures.get(key, []) if now - stamp < self.window_seconds
            ]
            if len(recent) >= self.limit:
                self._failures[key] = recent
                return False
            recent.append(now)
            self._failures[key] = recent
            return True

    def succeeded(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


class ProgressiveLockout:
    """Process-local escalating lockouts shared by authentication endpoints."""

    def __init__(self) -> None:
        self._failures: dict[str, int] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def retry_after(self, keys: list[str]) -> int:
        now = time.monotonic()
        with self._lock:
            return max(
                (max(0, int(self._locked_until.get(key, 0) - now + 0.999)) for key in keys),
                default=0,
            )

    def fail(self, keys: list[str]) -> int:
        now = time.monotonic()
        with self._lock:
            for key in set(keys):
                count = self._failures.get(key, 0) + 1
                self._failures[key] = count
                if count >= 5:
                    stage = min((count - 5) // 5, 2)
                    self._locked_until[key] = now + (60, 300, 900)[stage]
            return max(
                (max(0, int(self._locked_until.get(key, 0) - now + 0.999)) for key in keys),
                default=0,
            )

    def succeed(self, keys: list[str]) -> None:
        with self._lock:
            for key in set(keys):
                self._failures.pop(key, None)
                self._locked_until.pop(key, None)


def migrate_legacy_operator(path: Path) -> bool:
    """Move a legacy username to email only when it is already a valid email."""
    if not path.exists():
        return False
    data = _read(path)
    if "username" not in data:
        if data.get("schema_version") == 2:
            return False
        timestamped_credential_backup(path)
        data["schema_version"] = 2
        data.setdefault("auth_epoch", secrets.token_hex(16))
        _write_atomic(path, data)
        return True
    try:
        email = normalize_email(str(data["username"]))
    except CredentialError:
        data["legacy_username"] = data["username"]
        data["requires_email_recovery"] = True
    else:
        data["email"] = email
        data.pop("requires_email_recovery", None)
    data.pop("username", None)
    data["schema_version"] = 2
    data.setdefault("auth_epoch", secrets.token_hex(16))
    timestamped_credential_backup(path)
    _write_atomic(path, data)
    return True


def create_operator(path: Path, email: str, password: str) -> None:
    """Create one Argon2id operator record without overwriting an existing account."""
    normalized = normalize_email(email)
    _validate_password(normalized, password)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "schema_version": 2,
            "email": normalized,
            "password_hash": PasswordHasher().hash(password),
            "auth_epoch": secrets.token_hex(16),
        },
        separators=(",", ":"),
    )
    try:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
    except FileExistsError as exc:
        raise CredentialError(
            "An operator account already exists; refusing to replace it."
        ) from exc
    try:
        path.chmod(0o600)
    except OSError:
        pass


def operator_email(path: Path) -> str | None:
    data = _read(path)
    value = data.get("email")
    if not isinstance(value, str):
        return None
    try:
        return normalize_email(value)
    except CredentialError:
        return None


def operator_identity_summary(path: Path) -> tuple[str, bool]:
    """Return only a safe username label and whether an email field is present."""
    data = _read(path)
    username = data.get("username")
    if not isinstance(username, str) or "@" in username:
        username = "local-operator"
    username = " ".join(username.replace("\r", " ").replace("\n", " ").split())[:100]
    return username or "local-operator", "email" in data


def operator_auth_epoch(path: Path) -> str:
    data = _read(path)
    epoch = data.get("auth_epoch")
    if not isinstance(epoch, str) or len(epoch) < 16:
        return "legacy"
    return epoch


def verify_operator(path: Path, email: str, password: str) -> bool:
    try:
        data = _read(path)
    except CredentialError:
        _verify_dummy(password)
        return False
    stored_email = data.get("email")
    password_hash = data.get("password_hash")
    if not isinstance(stored_email, str) or not isinstance(password_hash, str):
        _verify_dummy(password)
        return False
    try:
        normalized = normalize_email(email)
        stored = normalize_email(stored_email)
        email_matches = secrets.compare_digest(stored.encode(), normalized.encode())
        if not email_matches:
            _verify_dummy(password)
            return False
        return PasswordHasher().verify(password_hash, password)
    except CredentialError:
        return False
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _verify_dummy(password: str) -> None:
    try:
        PasswordHasher().verify(_DUMMY_HASH, password[:128])
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        pass


def perform_dummy_verification(password: str = "") -> None:
    """Run an Argon2id verification for enumeration-resistant public responses."""
    _verify_dummy(password)


def _validate_password(email: str, password: str) -> None:
    if len(password) < 12 or len(password) > 128:
        raise CredentialError("Password must be between 12 and 128 characters.")
    if password.casefold() in _COMMON_PASSWORDS:
        raise CredentialError("Choose a less common password.")
    if password.casefold() == email.split("@", 1)[0].casefold():
        raise CredentialError("Password cannot equal the email local part.")


def operator_status(path: Path) -> str:
    if not path.exists():
        return "none"
    try:
        data = _read(path)
    except CredentialError:
        return "needs-migration"
    if data.get("schema_version") != 2:
        return "legacy"
    try:
        normalize_email(str(data.get("email", "")))
        if not isinstance(data.get("password_hash"), str):
            return "needs-migration"
    except CredentialError:
        return "needs-migration"
    return "active"


def issue_reset_token(path: Path, email: str) -> str:
    with _CREDENTIAL_LOCK:
        return _issue_reset_token(path, email)


def _issue_reset_token(path: Path, email: str) -> str:
    """Store a SHA-256 token digest and return the one-time token to the local CLI."""
    normalized = normalize_email(email)
    data = _read(path)
    stored = operator_email(path)
    if stored is None or not secrets.compare_digest(stored.encode(), normalized.encode()):
        raise CredentialError("No matching operator account.")
    now = int(time.time())
    last = data.get("reset_requested_at")
    if isinstance(last, int) and now - last < RESET_RATE_LIMIT_SECONDS:
        raise CredentialError("A reset was requested recently. Wait one minute and try again.")
    token = secrets.token_urlsafe(32)
    data["reset_token_hash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
    data["reset_token_expires_at"] = now + RESET_TOKEN_TTL_SECONDS
    data["reset_requested_at"] = now
    data.pop("reset_token_used_at", None)
    timestamped_credential_backup(path)
    _write_atomic(path, data)
    return token


def migrate_operator_email_for_reset(path: Path, email: str) -> str:
    with _CREDENTIAL_LOCK:
        return _migrate_operator_email_for_reset(path, email)


def _migrate_operator_email_for_reset(path: Path, email: str) -> str:
    """Replace a legacy identity and issue its reset token in one file update."""
    normalized = normalize_email(email)
    data = _read(path)
    now = int(time.time())
    last = data.get("reset_requested_at")
    if isinstance(last, int) and now - last < RESET_RATE_LIMIT_SECONDS:
        raise CredentialError("A reset was requested recently. Wait one minute and try again.")
    token = secrets.token_urlsafe(32)
    data["email"] = normalized
    data.pop("username", None)
    data.pop("legacy_username", None)
    data.pop("requires_email_recovery", None)
    data["auth_epoch"] = secrets.token_hex(16)
    data["reset_token_hash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
    data["reset_token_expires_at"] = now + RESET_TOKEN_TTL_SECONDS
    data["reset_requested_at"] = now
    data.pop("reset_token_used_at", None)
    timestamped_credential_backup(path)
    _write_atomic(path, data)
    return token


def reset_operator_password(path: Path, email: str, token: str, password: str) -> bool:
    with _CREDENTIAL_LOCK:
        return _reset_operator_password(path, email, token, password)


def _reset_operator_password(path: Path, email: str, token: str, password: str) -> bool:
    normalized = normalize_email(email)
    _validate_password(normalized, password)
    try:
        data = _read(path)
        stored_email = data.get("email")
        expected_hash = data.get("reset_token_hash")
        expiry = data.get("reset_token_expires_at")
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        valid = (
            isinstance(stored_email, str)
            and secrets.compare_digest(normalize_email(stored_email).encode(), normalized.encode())
            and isinstance(expected_hash, str)
            and hmac.compare_digest(expected_hash, token_hash)
            and isinstance(expiry, int)
            and int(time.time()) < expiry
        )
    except (CredentialError, TypeError):
        return False
    if not valid:
        return False
    timestamped_credential_backup(path)
    data["password_hash"] = PasswordHasher().hash(password)
    data["auth_epoch"] = secrets.token_hex(16)
    for key in ("reset_token_hash", "reset_token_expires_at"):
        data.pop(key, None)
    data["reset_token_used_at"] = int(time.time())
    _write_atomic(path, data)
    return True


def set_operator_password(path: Path, email: str, password: str) -> None:
    """Set the password through the local CLI and invalidate every prior session."""
    normalized = normalize_email(email)
    _validate_password(normalized, password)
    with _CREDENTIAL_LOCK:
        data = _read(path)
        stored = normalize_email(str(data.get("email", "")))
        if not secrets.compare_digest(stored.encode(), normalized.encode()):
            raise CredentialError("Local operator account is unavailable or invalid.")
        timestamped_credential_backup(path)
        data["schema_version"] = 2
        data["password_hash"] = PasswordHasher().hash(password)
        data["auth_epoch"] = secrets.token_hex(16)
        for key in ("reset_token_hash", "reset_token_expires_at"):
            data.pop(key, None)
        _write_atomic(path, data)


def timestamped_credential_backup(path: Path) -> Path:
    if not path.is_file():
        raise CredentialError("Operator credential file does not exist.")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = path.with_name(f"{path.name}.{stamp}.bak")
    counter = 1
    while backup.exists():
        backup = path.with_name(f"{path.name}.{stamp}.{counter}.bak")
        counter += 1
    descriptor, temporary_name = tempfile.mkstemp(prefix=".operator-backup-", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        data = _read(path)
        email = data.get("email")
        if not isinstance(email, str):
            email = data.get("username", "")
        try:
            normalized = normalize_email(str(email))
            local, _, domain = normalized.partition("@")
            masked_email = f"{local[:1]}***@{domain}"
        except CredentialError:
            masked_email = "unavailable"
        data["_backup_metadata"] = {
            "id": uuid.uuid4().hex,
            "timestamp": datetime.now(UTC).isoformat(),
            "schema_version": data.get("schema_version", "legacy"),
            "email_masked": masked_email,
        }
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(data, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, backup)
    finally:
        temporary.unlink(missing_ok=True)
    try:
        backup.chmod(0o600)
    except OSError:
        pass
    return backup


@dataclass
class Session:
    email: str
    csrf_token: str
    expires_at: float
    auth_epoch: str
    created_at: float = 0.0
    last_seen_at: float = 0.0


class SessionStore:
    """Opaque, process-local sessions; restarting or password reset invalidates sessions."""

    def __init__(
        self,
        ttl_seconds: int = SESSION_ABSOLUTE_TTL_SECONDS,
        idle_ttl_seconds: int = SESSION_IDLE_TTL_SECONDS,
        *,
        clock: Any = time.time,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.idle_ttl_seconds = idle_ttl_seconds
        self._clock = clock
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self, email: str, auth_epoch: str) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        now = self._clock()
        session = Session(
            email,
            secrets.token_urlsafe(32),
            now + self.ttl_seconds,
            auth_epoch,
            created_at=now,
            last_seen_at=now,
        )
        with self._lock:
            expired = [key for key, value in self._sessions.items() if value.expires_at <= now]
            for key in expired:
                del self._sessions[key]
            if len(self._sessions) >= 128:
                oldest = min(self._sessions, key=lambda key: self._sessions[key].expires_at)
                del self._sessions[oldest]
            self._sessions[self._key(token)] = session
        return token, session

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        key = self._key(token)
        with self._lock:
            session = self._sessions.get(key)
            now = self._clock()
            if session and (
                session.expires_at <= now or session.last_seen_at + self.idle_ttl_seconds <= now
            ):
                del self._sessions[key]
                return None
            if session:
                session.last_seen_at = now
            return session

    def revoke(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(self._key(token), None)

    def revoke_all(self) -> None:
        with self._lock:
            self._sessions.clear()


def totp_code_at(secret: bytes, timestamp: int | float, *, step: int = 30, digits: int = 6) -> str:
    """Calculate an RFC 6238 code using HMAC-SHA1 and dynamic truncation."""
    counter = int(timestamp) // step
    digest = hmac.new(secret, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def generate_totp_secret() -> str:
    """Return a new 160-bit Base32 authenticator secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def generate_totp_code(secret: str, *, now: int | float | None = None) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    decoded = base64.b32decode(padded, casefold=True)
    return totp_code_at(decoded, time.time() if now is None else now)


def _matching_totp_counter(
    secret: str, code: str, now: int | float, last_counter: int
) -> int | None:
    try:
        padded = secret + "=" * ((8 - len(secret) % 8) % 8)
        decoded = base64.b32decode(padded, casefold=True)
    except (ValueError, binascii.Error):
        return None
    current = int(now) // 30
    for counter in range(max(0, current - 1), current + 2):
        expected = totp_code_at(decoded, counter * 30)
        if counter > last_counter and hmac.compare_digest(expected, code):
            return counter
    return None


def start_totp_enrollment(path: Path, *, now: int | float | None = None) -> str:
    """Store a temporary secret for ten minutes; only the local CLI displays it."""
    timestamp = time.time() if now is None else now
    with _CREDENTIAL_LOCK:
        data = _read(path)
        if data.get("totp_enabled"):
            raise CredentialError("Authenticator verification is already enabled.")
        secret = generate_totp_secret()
        data["totp_pending_secret"] = secret
        data["totp_enrollment_expires_at"] = int(timestamp) + TOTP_ENROLLMENT_TTL_SECONDS
        data["totp_last_counter"] = -1
        data["totp_verify_failed_at"] = []
        _write_atomic(path, data)
        return secret


def _totp_rate_limited(data: dict[str, Any], now: int | float) -> tuple[list[int], bool]:
    raw = data.get("totp_verify_failed_at", [])
    failures = (
        [
            int(stamp)
            for stamp in raw
            if isinstance(stamp, (int, float)) and stamp > now - TOTP_VERIFICATION_WINDOW_SECONDS
        ]
        if isinstance(raw, list)
        else []
    )
    return failures, len(failures) >= TOTP_VERIFICATION_MAX_ATTEMPTS


def _verify_totp_in_data(
    data: dict[str, Any], code: str, now: int | float
) -> tuple[bool, int | None]:
    failures, limited = _totp_rate_limited(data, now)
    if limited:
        return False, None
    secret = data.get("totp_secret")
    if not isinstance(secret, str):
        return False, None
    last_counter = int(data.get("totp_last_counter", -1))
    matched = _matching_totp_counter(secret, code.strip(), now, last_counter)
    if matched is not None:
        data["totp_last_counter"] = matched
        data["totp_verify_failed_at"] = []
        return True, matched
    code_digest = hashlib.sha256(code.strip().upper().encode("ascii", errors="ignore")).hexdigest()
    recovery = data.get("totp_recovery_code_hashes", [])
    if isinstance(recovery, list):
        for index, digest in enumerate(recovery):
            if isinstance(digest, str) and hmac.compare_digest(digest, code_digest):
                recovery.pop(index)
                data["totp_recovery_code_hashes"] = recovery
                data["totp_verify_failed_at"] = []
                return True, None
    failures.append(int(now))
    data["totp_verify_failed_at"] = failures
    return False, None


def confirm_totp_enrollment(
    path: Path, code: str, *, now: int | float | None = None
) -> list[str] | None:
    """Enable authenticator verification after a live code and return recovery codes once."""
    timestamp = time.time() if now is None else now
    with _CREDENTIAL_LOCK:
        data = _read(path)
        secret = data.get("totp_pending_secret")
        expires = data.get("totp_enrollment_expires_at")
        if data.get("totp_enabled") or not isinstance(secret, str) or not isinstance(expires, int):
            return None
        if int(timestamp) >= expires:
            data.pop("totp_pending_secret", None)
            data.pop("totp_enrollment_expires_at", None)
            _write_atomic(path, data)
            return None
        failures, limited = _totp_rate_limited(data, timestamp)
        if limited:
            return None
        matched = _matching_totp_counter(secret, code.strip(), timestamp, -1)
        if matched is None:
            failures.append(int(timestamp))
            data["totp_verify_failed_at"] = failures
            _write_atomic(path, data)
            return None
        recovery_codes = [secrets.token_hex(5).upper() for _ in range(TOTP_RECOVERY_CODE_COUNT)]
        data["totp_enabled"] = True
        data["totp_secret"] = secret
        data["totp_last_counter"] = matched
        data["totp_recovery_code_hashes"] = [
            hashlib.sha256(value.encode("ascii")).hexdigest() for value in recovery_codes
        ]
        data["totp_verify_failed_at"] = []
        data.pop("totp_pending_secret", None)
        data.pop("totp_enrollment_expires_at", None)
        _write_atomic(path, data)
        return recovery_codes


def verify_operator_totp(path: Path, code: str, *, now: int | float | None = None) -> bool:
    timestamp = time.time() if now is None else now
    with _CREDENTIAL_LOCK:
        try:
            data = _read(path)
        except CredentialError:
            return False
        if not data.get("totp_enabled"):
            return False
        valid, _counter = _verify_totp_in_data(data, code, timestamp)
        _write_atomic(path, data)
        return valid


def operator_totp_enabled(path: Path) -> bool:
    try:
        return _read(path).get("totp_enabled") is True
    except CredentialError:
        return False


def disable_operator_totp(path: Path, code: str, *, now: int | float | None = None) -> bool:
    timestamp = time.time() if now is None else now
    with _CREDENTIAL_LOCK:
        try:
            data = _read(path)
        except CredentialError:
            return False
        if not data.get("totp_enabled"):
            return False
        valid, _counter = _verify_totp_in_data(data, code, timestamp)
        if not valid:
            _write_atomic(path, data)
            return False
        for key in (
            "totp_enabled",
            "totp_secret",
            "totp_last_counter",
            "totp_recovery_code_hashes",
            "totp_verify_failed_at",
        ):
            data.pop(key, None)
        _write_atomic(path, data)
        return True
