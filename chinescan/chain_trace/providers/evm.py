"""Bounded, redaction-safe Etherscan-family provider."""

import json
import socket
import ssl
import time
from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from http.client import HTTPMessage, HTTPSConnection
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, quote_plus, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from chinescan.chain_trace.endpoint_policy import (
    EndpointPolicyError,
    Resolver,
    resolve_endpoint,
    validate_endpoint,
)
from chinescan.chain_trace.models import Transfer
from chinescan.chain_trace.providers.base import Page

MAX_RESPONSE_BYTES = 2_000_000
REQUEST_TIMEOUT_SECONDS = 15
MAX_REDIRECTS = 2


def _contains_api_key(value: object, api_key: str) -> bool:
    if not api_key:
        return False
    text = str(value)
    return any(
        candidate in text
        for candidate in {api_key, quote(api_key), quote_plus(api_key)}
        if candidate
    )


class ProviderLimitError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _PinnedHTTPSConnection(HTTPSConnection):
    _tunnel_host: str | None
    source_address: tuple[str, int] | None
    _context: ssl.SSLContext | None

    def __init__(self, host: str, *, addresses: tuple[str, ...], **kwargs: Any) -> None:
        super().__init__(host, **kwargs)
        self.addresses = addresses

    def connect(self) -> None:
        if self._tunnel_host:
            raise OSError("provider tunnel is disabled")
        last_error: OSError | None = None
        for address in self.addresses:
            try:
                sock = socket.create_connection(
                    (address, self.port), self.timeout, self.source_address
                )
            except OSError as exc:
                last_error = exc
                continue
            context = self._context or ssl.create_default_context()
            self.sock = context.wrap_socket(sock, server_hostname=self.host)
            return
        raise OSError("provider connection failed") from last_error


class _ValidatedHTTPSHandler(HTTPSHandler):
    def __init__(
        self,
        *,
        allowed_hosts: tuple[str, ...],
        allow_nonstandard_port: bool,
        resolver: Resolver = socket.getaddrinfo,
        resolve_timeout_seconds: float = 2,
    ) -> None:
        super().__init__()
        self.allowed_hosts = allowed_hosts
        self.allow_nonstandard_port = allow_nonstandard_port
        self.resolver = resolver
        self.resolve_timeout_seconds = resolve_timeout_seconds

    def https_open(self, req: Request) -> Any:
        _parsed, addresses = resolve_endpoint(
            req.full_url,
            allowed_hosts=self.allowed_hosts,
            allow_nonstandard_port=self.allow_nonstandard_port,
            resolver=self.resolver,
            resolve_timeout_seconds=self.resolve_timeout_seconds,
        )

        def connection(host: str, **kwargs: Any) -> HTTPSConnection:
            return _PinnedHTTPSConnection(host, addresses=addresses, **kwargs)

        return self.do_open(connection, req)


class _SameHostHTTPSRedirectHandler(HTTPRedirectHandler):
    def __init__(
        self,
        endpoint: str,
        *,
        allow_nonstandard_port: bool,
        resolver: Resolver = socket.getaddrinfo,
        resolve_timeout_seconds: float = 2,
    ) -> None:
        super().__init__()
        parsed = urlsplit(endpoint)
        self.host = (parsed.hostname or "").lower().rstrip(".")
        self.port = parsed.port or 443
        self.allow_nonstandard_port = allow_nonstandard_port
        self.redirect_count = 0
        self.resolver = resolver
        self.resolve_timeout_seconds = resolve_timeout_seconds

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        if self.redirect_count >= MAX_REDIRECTS:
            raise EndpointPolicyError("redirect_limit")
        parsed = validate_endpoint(
            newurl,
            allow_nonstandard_port=self.allow_nonstandard_port,
            expected_host=self.host,
            resolver=self.resolver,
            resolve_timeout_seconds=self.resolve_timeout_seconds,
        )
        if (parsed.port or 443) != self.port:
            raise EndpointPolicyError("redirect_rejected")
        self.redirect_count += 1
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _JsonResponse:
    def __init__(self, payload: bytes, status_code: int = 200, content_type: str = "") -> None:
        self.payload = payload
        self.status_code = status_code
        self.content_type = content_type

    def json(self) -> dict[str, Any]:
        value: object = json.loads(self.payload)
        return value if isinstance(value, dict) else {}


def stdlib_http_get(
    url: str,
    *,
    params: dict[str, object],
    api_key: str = "",
    allowed_hosts: tuple[str, ...] = (),
    allow_nonstandard_port: bool = False,
    timeout_seconds: float = REQUEST_TIMEOUT_SECONDS,
    resolver: Resolver = socket.getaddrinfo,
) -> _JsonResponse:
    """Minimal live HTTP adapter; called only after explicit network authorization."""
    parsed = validate_endpoint(
        url,
        allowed_hosts=allowed_hosts,
        allow_nonstandard_port=allow_nonstandard_port,
        resolver=resolver,
        resolve_timeout_seconds=min(2, timeout_seconds),
    )
    if not allowed_hosts:
        raise EndpointPolicyError("endpoint_host_not_allowed")
    request_params = dict(params)
    if api_key:
        request_params["apikey"] = api_key
    query = "&".join(part for part in (parsed.query, urlencode(request_params)) if part)
    request_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
    redirect_handler = _SameHostHTTPSRedirectHandler(
        request_url,
        allow_nonstandard_port=allow_nonstandard_port,
        resolver=resolver,
        resolve_timeout_seconds=min(2, timeout_seconds),
    )
    request = Request(request_url, headers={"Accept": "application/json"})
    opener = build_opener(
        ProxyHandler({}),
        _ValidatedHTTPSHandler(
            allowed_hosts=allowed_hosts,
            allow_nonstandard_port=allow_nonstandard_port,
            resolver=resolver,
            resolve_timeout_seconds=min(2, timeout_seconds),
        ),
        redirect_handler,
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            deadline = time.monotonic() + timeout_seconds
            payload = bytearray()
            while len(payload) <= MAX_RESPONSE_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProviderLimitError("trace_deadline")
                raw_socket = getattr(getattr(response, "fp", None), "raw", None)
                raw_socket = getattr(raw_socket, "_sock", None)
                if raw_socket is not None:
                    raw_socket.settimeout(remaining)
                chunk_reader = getattr(response, "read1", response.read)
                chunk = chunk_reader(min(65_536, MAX_RESPONSE_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > MAX_RESPONSE_BYTES:
                raise ProviderLimitError("response_too_large")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip()
            if content_type != "application/json" and not content_type.endswith("+json"):
                raise ProviderLimitError("unexpected_content_type")
            return _JsonResponse(bytes(payload), response.status, content_type)
    except EndpointPolicyError:
        raise


class EvmProvider:
    """Provider with all transport exceptions mapped to fixed, secret-free coverage gaps."""

    name = "etherscan-family"

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        http_get: Callable[..., Any],
        chain: str = "ethereum",
        *,
        retries: int = 2,
        throttle_seconds: float = 0.2,
        sleep: Callable[[float], None] = time.sleep,
        allowed_hosts: tuple[str, ...] = (),
        allow_nonstandard_port: bool = False,
        deadline_seconds: float = 120,
        max_requests: int = 100,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.http_get = http_get
        self.chain = chain
        self.retries = max(0, min(5, retries))
        self.throttle_seconds = max(0.0, throttle_seconds)
        self.sleep = sleep
        self.allowed_hosts = allowed_hosts
        self.allow_nonstandard_port = allow_nonstandard_port
        self.deadline_seconds = max(0.0, deadline_seconds)
        self.max_requests = max(1, max_requests)
        self.clock = clock
        self.started_at = clock()
        self.requests_made = 0

    def _request(
        self, address: str, action: str, limit: int, page: int
    ) -> tuple[dict[str, Any] | None, str | None]:
        params: dict[str, object] = {
            "module": "account",
            "action": action,
            "address": address,
            "page": page,
            "offset": limit,
        }
        for attempt in range(self.retries + 1):
            elapsed = self.clock() - self.started_at
            remaining = self.deadline_seconds - elapsed
            if remaining <= 0:
                return None, "trace_deadline"
            if self.requests_made >= self.max_requests:
                return None, "request_limit"
            try:
                self.requests_made += 1
                response = self.http_get(
                    self.endpoint,
                    params=params,
                    api_key=self.api_key,
                    allowed_hosts=self.allowed_hosts,
                    allow_nonstandard_port=self.allow_nonstandard_port,
                    timeout_seconds=min(REQUEST_TIMEOUT_SECONDS, remaining),
                )
                status = int(getattr(response, "status_code", 200))
                if status == 429:
                    if attempt < self.retries:
                        self.sleep(0.25 * (attempt + 1))
                        continue
                    return None, "rate_limited"
                if status >= 500:
                    if attempt < self.retries:
                        self.sleep(0.25 * (attempt + 1))
                        continue
                    return None, "provider_unavailable"
                content_type = str(getattr(response, "content_type", "")).casefold()
                if (
                    content_type
                    and content_type != "application/json"
                    and not content_type.endswith("+json")
                ):
                    return None, "unexpected_content_type"
                try:
                    body = response.json()
                except Exception:
                    return None, "malformed_response"
                if not isinstance(body, dict):
                    return None, "malformed_response"
                result = body.get("result", [])
                message = str(body.get("message", ""))
                text = str(result).casefold()
                if status == 429 or "rate limit" in text:
                    if attempt < self.retries:
                        self.sleep(0.25 * (attempt + 1))
                        continue
                    return None, "rate_limited"
                if message == "NOTOK" and not isinstance(result, list):
                    return None, "provider_error"
                return body, None
            except TimeoutError:
                if attempt < self.retries:
                    self.sleep(0.25 * (attempt + 1))
                    continue
                return None, "provider_timeout"
            except EndpointPolicyError as exc:
                return None, exc.code
            except ProviderLimitError as exc:
                return None, exc.code
            except HTTPError as exc:
                if exc.code == 429:
                    if attempt < self.retries:
                        self.sleep(0.25 * (attempt + 1))
                        continue
                    return None, "rate_limited"
                if attempt < self.retries:
                    self.sleep(0.25 * (attempt + 1))
                    continue
                return None, "provider_error"
            except Exception:
                if attempt < self.retries:
                    self.sleep(0.25 * (attempt + 1))
                    continue
                return None, "provider_error"
        return None, "provider_error"

    def transfers(self, address: str, *, limit: int, cursor: str | None = None) -> Page:
        page_number = int(cursor or 1)
        collected: list[Transfer] = []
        gaps: list[str] = []
        truncated = False
        for action, kind in (
            ("txlist", "transfer"),
            ("txlistinternal", "internal"),
            ("tokentx", "token"),
        ):
            body, gap = self._request(address, action, limit, page_number)
            if gap:
                gaps.append(gap)
                continue
            assert body is not None
            rows = body.get("result", [])
            if isinstance(rows, str) and "no transactions" in rows.casefold():
                rows = []
            if not isinstance(rows, list):
                gaps.append("malformed_response")
                continue
            if len(rows) >= limit:
                truncated = True
            for row in rows:
                try:
                    if not isinstance(row, dict):
                        raise ValueError("invalid transfer row")
                    if _contains_api_key(json.dumps(row, default=str), self.api_key):
                        raise ValueError("sensitive value in provider response")
                    collected.append(
                        Transfer(
                            chain=self.chain,
                            tx_hash=str(row["hash"]),
                            block_time=int(row["timeStamp"]),
                            sender=str(row["from"]) if row.get("from") else None,
                            receiver=str(row["to"]),
                            asset=str(row.get("tokenSymbol", "ETH")),
                            amount=Decimal(str(row.get("value", "0"))),
                            kind=kind,
                        )
                    )
                except (KeyError, TypeError, ValueError, InvalidOperation):
                    gaps.append("provider_row_invalid")
            if self.throttle_seconds:
                self.sleep(self.throttle_seconds)
        return Page(
            tuple(collected[:limit]),
            truncated,
            str(page_number + 1) if truncated else None,
            tuple(sorted(set(gaps))),
        )
