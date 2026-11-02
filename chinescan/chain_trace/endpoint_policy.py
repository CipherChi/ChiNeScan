"""Validation rules for provider URLs used by the live HTTP transport."""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import socket
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import Any
from urllib.parse import SplitResult, urlsplit


class EndpointPolicyError(ValueError):
    """Stable, secret-free endpoint rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


Resolver = Callable[..., Any]
_DNS_SLOTS = threading.BoundedSemaphore(4)
_DNS_SCRIPT = (
    "import json, socket, sys; "
    "print(json.dumps(sorted({str(row[4][0]) for row in "
    "socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), type=socket.SOCK_STREAM)})))"
)


def _resolve_with_timeout(
    resolver: Resolver, host: str, port: int, timeout_seconds: float
) -> list[str]:
    if resolver is socket.getaddrinfo:
        if not _DNS_SLOTS.acquire(timeout=timeout_seconds):
            raise EndpointPolicyError("endpoint_dns_timeout")
        safe_env = {
            key: os.environ[key]
            for key in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP")
            if key in os.environ
        }
        try:
            try:
                result = subprocess.run(
                    [sys.executable, "-c", _DNS_SCRIPT, host, str(port)],
                    capture_output=True,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    env=safe_env,
                    text=True,
                    timeout=timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise EndpointPolicyError("endpoint_dns_timeout") from exc
        finally:
            _DNS_SLOTS.release()
        if result.returncode != 0:
            raise EndpointPolicyError("endpoint_dns_failed")
        try:
            addresses = json.loads(result.stdout)
        except ValueError as exc:
            raise EndpointPolicyError("endpoint_dns_failed") from exc
        if not isinstance(addresses, list) or any(not isinstance(item, str) for item in addresses):
            raise EndpointPolicyError("endpoint_dns_failed")
        return addresses

    if not _DNS_SLOTS.acquire(timeout=timeout_seconds):
        raise EndpointPolicyError("endpoint_dns_timeout")
    result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            result_queue.put((True, resolver(host, port, type=socket.SOCK_STREAM)))
        except BaseException as exc:
            result_queue.put((False, exc))
        finally:
            _DNS_SLOTS.release()

    threading.Thread(target=resolve, daemon=True, name="chinescan-chain-dns").start()
    try:
        succeeded, result = result_queue.get(timeout=timeout_seconds)
    except queue.Empty as exc:
        raise EndpointPolicyError("endpoint_dns_timeout") from exc
    if not succeeded:
        raise result
    try:
        return [str(row[4][0]) for row in result]
    except (IndexError, TypeError) as exc:
        raise EndpointPolicyError("endpoint_dns_failed") from exc


def resolve_endpoint(
    endpoint: str,
    *,
    allowed_hosts: tuple[str, ...] = (),
    allow_nonstandard_port: bool = False,
    expected_host: str | None = None,
    resolver: Resolver = socket.getaddrinfo,
    resolve_timeout_seconds: float = 2.0,
) -> tuple[SplitResult, tuple[str, ...]]:
    """Validate HTTPS, host policy, and every DNS answer before opening a socket."""
    try:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        port = parsed.port or 443
    except ValueError as exc:
        raise EndpointPolicyError("endpoint_invalid") from exc
    if (
        parsed.scheme.lower() != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise EndpointPolicyError("endpoint_invalid")
    host = host.rstrip(".").lower()
    if port != 443 and not allow_nonstandard_port:
        raise EndpointPolicyError("endpoint_invalid")
    if allowed_hosts and host not in {item.lower().rstrip(".") for item in allowed_hosts}:
        raise EndpointPolicyError("endpoint_host_not_allowed")
    if expected_host is not None and host != expected_host.lower().rstrip("."):
        raise EndpointPolicyError("redirect_rejected")
    try:
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            resolved = _resolve_with_timeout(resolver, host, port, resolve_timeout_seconds)
            addresses = [ipaddress.ip_address(item) for item in resolved]
        if not addresses or any(
            not address.is_global
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
            or isinstance(address, ipaddress.IPv6Address)
            and address.ipv4_mapped is not None
            for address in addresses
        ):
            raise EndpointPolicyError("endpoint_non_public_address")
    except EndpointPolicyError:
        raise
    except (OSError, IndexError, TypeError, ValueError) as exc:
        raise EndpointPolicyError("endpoint_dns_failed") from exc
    return parsed, tuple(str(address) for address in addresses)


def validate_endpoint(
    endpoint: str,
    *,
    allowed_hosts: tuple[str, ...] = (),
    allow_nonstandard_port: bool = False,
    expected_host: str | None = None,
    resolver: Resolver = socket.getaddrinfo,
    resolve_timeout_seconds: float = 2.0,
) -> SplitResult:
    return resolve_endpoint(
        endpoint,
        allowed_hosts=allowed_hosts,
        allow_nonstandard_port=allow_nonstandard_port,
        expected_host=expected_host,
        resolver=resolver,
        resolve_timeout_seconds=resolve_timeout_seconds,
    )[0]
