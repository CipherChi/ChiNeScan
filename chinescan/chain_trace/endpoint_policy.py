"""Validation rules for provider URLs used by the live HTTP transport."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import SplitResult, urlsplit


class EndpointPolicyError(ValueError):
    """Stable, secret-free endpoint rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


Resolver = Callable[..., Any]


def resolve_endpoint(
    endpoint: str,
    *,
    allowed_hosts: tuple[str, ...] = (),
    allow_nonstandard_port: bool = False,
    expected_host: str | None = None,
    resolver: Resolver = socket.getaddrinfo,
) -> tuple[SplitResult, tuple[str, ...]]:
    """Validate HTTPS, host policy, and every DNS answer before opening a socket."""
    try:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        port = parsed.port or 443
    except ValueError as exc:
        raise EndpointPolicyError("endpoint_invalid") from exc
    if parsed.scheme.lower() != "https" or not host or parsed.username or parsed.password:
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
            rows = resolver(host, port, type=socket.SOCK_STREAM)
            addresses = [ipaddress.ip_address(str(row[4][0])) for row in rows]
        if not addresses or any(
            not address.is_global
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
) -> SplitResult:
    return resolve_endpoint(
        endpoint,
        allowed_hosts=allowed_hosts,
        allow_nonstandard_port=allow_nonstandard_port,
        expected_host=expected_host,
        resolver=resolver,
    )[0]
