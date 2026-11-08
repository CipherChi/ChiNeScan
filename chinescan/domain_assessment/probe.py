"""Low-impact, injectable DNS/HTTP/TLS posture probes for one public hostname."""

from __future__ import annotations

import ipaddress
import queue
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

MAX_ADDRESSES = 5
CONNECT_TIMEOUT_SECONDS = 3.0
MAX_RESPONSE_HEADER_BYTES = 16_384
SECURITY_HEADERS = {
    "strict-transport-security": ("DAS-HTTPS-001", "HTTPS response omits HSTS", "low"),
    "content-security-policy": (
        "DAS-HTTPS-002",
        "HTTPS response omits Content-Security-Policy",
        "info",
    ),
    "x-content-type-options": (
        "DAS-HTTPS-003",
        "HTTPS response omits X-Content-Type-Options",
        "low",
    ),
}
_REPORTED_HEADERS = set(SECURITY_HEADERS) | {"server", "x-powered-by", "content-type"}


@dataclass(frozen=True)
class ProbeSettings:
    """Operator-adjustable limits for DNS, connections, and sequential requests."""

    timeout_seconds: float = 3.0
    max_addresses: int = MAX_ADDRESSES
    request_interval_seconds: float = 0.0

    def __post_init__(self) -> None:
        if not 0.1 <= self.timeout_seconds <= 10.0:
            raise ValueError("timeout_seconds must be between 0.1 and 10")
        if not 1 <= self.max_addresses <= MAX_ADDRESSES:
            raise ValueError(f"max_addresses must be between 1 and {MAX_ADDRESSES}")
        if not 0.0 <= self.request_interval_seconds <= 5.0:
            raise ValueError("request_interval_seconds must be between 0 and 5")

    def as_dict(self) -> dict[str, str | int | float | bool]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_addresses": self.max_addresses,
            "request_interval_seconds": self.request_interval_seconds,
        }


class DomainProbe(Protocol):
    """Injectable boundary for DNS and bounded HTTP/TLS posture checks."""

    name: str

    def assess(self, hostname: str, profile: str) -> ProbeResult: ...


@dataclass(frozen=True)
class ProbeResult:
    addresses: tuple[str, ...] = ()
    http_status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    certificate: dict[str, str] = field(default_factory=dict)
    findings: tuple[tuple[str, str, str, str], ...] = ()
    errors: tuple[str, ...] = ()

    def summary(self) -> dict[str, object]:
        return {
            "addresses": list(self.addresses),
            "http_status": self.http_status,
            "headers": {
                key: value for key, value in self.headers.items() if key in _REPORTED_HEADERS
            },
            "certificate": self.certificate,
            "findings": [
                {"rule_id": rule, "title": title, "severity": severity, "description": description}
                for rule, title, severity, description in self.findings
            ],
            "errors": list(self.errors),
        }


class NetworkDomainProbe:
    """Resolve a public host and issue at most one HEAD per protocol and address."""

    name = "builtin-domain-posture"

    def __init__(self, settings: ProbeSettings | None = None) -> None:
        self.settings = settings or ProbeSettings()

    def assess(self, hostname: str, profile: str) -> ProbeResult:
        records_queue: queue.Queue[tuple[Any, OSError | None]] = queue.Queue(maxsize=1)

        def resolve() -> None:
            try:
                records_queue.put(
                    (socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM), None)
                )
            except OSError as exc:
                records_queue.put((None, exc))

        threading.Thread(target=resolve, daemon=True, name="chinescan-dns-lookup").start()
        try:
            records, resolution_error = records_queue.get(timeout=self.settings.timeout_seconds)
        except queue.Empty:
            return ProbeResult(errors=("DNS resolution timed out",))
        if resolution_error is not None:
            return ProbeResult(errors=("DNS resolution failed",))
        addresses = sorted(
            {
                str(ipaddress.ip_address(record[4][0]))
                for record in records
                if _is_public_address(str(record[4][0]))
            }
        )[: self.settings.max_addresses]
        if not addresses:
            return ProbeResult(errors=("No public IP addresses were returned",))
        errors: list[str] = []
        headers: dict[str, str] = {}
        status: int | None = None
        certificate: dict[str, str] = {}
        checked_addresses = addresses if profile == "deep" else addresses[:1]
        last_request_at: float | None = None

        def wait_for_request_slot() -> None:
            nonlocal last_request_at
            if last_request_at is not None:
                elapsed = time.monotonic() - last_request_at
                remaining = self.settings.request_interval_seconds - elapsed
                if remaining > 0:
                    time.sleep(remaining)
            last_request_at = time.monotonic()

        for address in checked_addresses:
            try:
                wait_for_request_slot()
                status, response_headers, cert = _head_request(
                    address,
                    hostname,
                    tls=True,
                    timeout_seconds=self.settings.timeout_seconds,
                )
                headers = response_headers
                certificate = cert
                if profile == "light":
                    break
            except (OSError, ssl.SSLError, TimeoutError, ValueError):
                errors.append("HTTPS posture request failed")
        if status is None:
            for address in checked_addresses:
                try:
                    wait_for_request_slot()
                    status, response_headers, _ = _head_request(
                        address,
                        hostname,
                        tls=False,
                        timeout_seconds=self.settings.timeout_seconds,
                    )
                    headers = response_headers
                    break
                except (OSError, TimeoutError, ValueError):
                    errors.append("HTTP posture request failed")
        findings = _header_findings(headers) if status is not None else ()
        return ProbeResult(
            tuple(addresses), status, headers, certificate, findings, tuple(dict.fromkeys(errors))
        )


def _is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not (
        address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
    )


def _head_request(
    address: str,
    hostname: str,
    *,
    tls: bool,
    timeout_seconds: float = CONNECT_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, str], dict[str, str]]:
    port = 443 if tls else 80
    with socket.create_connection((address, port), timeout=timeout_seconds) as raw_socket:
        connection: socket.socket
        certificate: dict[str, str] = {}
        if tls:
            context = _tls_context()
            secured = context.wrap_socket(raw_socket, server_hostname=hostname)
            connection = secured
            cert = secured.getpeercert()
            certificate = _certificate_fields(cert)  # type: ignore[arg-type]
        else:
            connection = raw_socket
        connection.settimeout(timeout_seconds)
        request = (
            f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\n"
            "User-Agent: ChiNeScan/0.1\r\nConnection: close\r\n\r\n"
        )
        connection.sendall(request.encode("ascii"))
        response = bytearray()
        while b"\r\n\r\n" not in response and len(response) <= MAX_RESPONSE_HEADER_BYTES:
            # Read one byte at a time so a recv cannot consume body bytes past the delimiter.
            chunk = connection.recv(1)
            if not chunk:
                break
            response.extend(chunk)
        if len(response) > MAX_RESPONSE_HEADER_BYTES:
            raise ValueError("response headers exceed the configured limit")
    lines = bytes(response).split(b"\r\n")
    status_parts = lines[0].split(maxsplit=2) if lines else []
    if len(status_parts) < 2 or not status_parts[1].isdigit():
        raise ValueError("invalid HTTP status line")
    parsed_headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if separator:
            key = name.decode("ascii", errors="ignore").strip().lower()
            if key in _REPORTED_HEADERS and key not in parsed_headers:
                parsed_headers[key] = value.decode("latin-1", errors="replace").strip()[:500]
    return int(status_parts[1]), parsed_headers, certificate


def _tls_context() -> ssl.SSLContext:
    """Use the system trust store and refuse legacy TLS versions for posture requests."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _certificate_fields(certificate: dict[str, object]) -> dict[str, str]:
    def flatten(name: str) -> str:
        value = certificate.get(name, ())
        if not isinstance(value, tuple):
            return ""
        fields = [str(pair[0][1]) for pair in value if isinstance(pair, tuple) and pair]
        return ", ".join(fields)[:300]

    return {
        "subject": flatten("subject"),
        "issuer": flatten("issuer"),
        "not_before": str(certificate.get("notBefore", ""))[:64],
        "not_after": str(certificate.get("notAfter", ""))[:64],
    }


def _header_findings(headers: dict[str, str]) -> tuple[tuple[str, str, str, str], ...]:
    missing: list[tuple[str, str, str, str]] = []
    for name, details in SECURITY_HEADERS.items():
        if name not in headers:
            rule, title, severity = details
            missing.append((rule, title, severity, f"HTTPS response did not include {name}."))
    return tuple(missing)
