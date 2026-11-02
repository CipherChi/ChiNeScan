import json
import re
import ssl
from decimal import Decimal
from http.client import HTTPMessage
from io import BytesIO
from socket import AF_INET
from urllib.parse import parse_qs
from urllib.request import Request

import pytest
from fastapi.testclient import TestClient

from chinescan.chain_trace.detectors import Lead, detect
from chinescan.chain_trace.endpoint_policy import EndpointPolicyError, validate_endpoint
from chinescan.chain_trace.models import Label, TraceParams, Transfer
from chinescan.chain_trace.providers.evm import (
    EvmProvider,
    ProviderLimitError,
    _PinnedHTTPSConnection,
    _SameHostHTTPSRedirectHandler,
    stdlib_http_get,
)
from chinescan.chain_trace.providers.offline import OfflineProvider
from chinescan.chain_trace.registry import Chain, load_registry, normalize_address
from chinescan.chain_trace.service import ChainTraceService, finding_for_lead
from chinescan.chain_trace.tracer import trace
from chinescan.core.config.settings import Settings
from chinescan.core.reporting import render_report
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.web.app import create_app
from chinescan.web.auth import create_operator


def _public_resolver(_host, _port, *, type):
    return [(AF_INET, type, 6, "", ("93.184.216.34", 443))]


def _private_resolver(_host, _port, *, type):
    return [(AF_INET, type, 6, "", ("127.0.0.1", 443))]


def _mapped_resolver(_host, _port, *, type):
    return [(AF_INET, type, 6, "", ("::ffff:8.8.8.8", 443))]


def _slow_resolver(_host, _port, *, type):
    import time

    time.sleep(0.1)
    return _public_resolver(_host, _port, type=type)


def test_offline_csv_import_and_bad_row_gap() -> None:
    provider = OfflineProvider(
        "hash,from,to,value\ntx1,0xabc,0xdef,1\ntx2,0xabc,0xghi,NaN", "ethereum"
    )
    assert provider.items[0].tx_hash == "tx1"
    assert "import_row_invalid" in provider.gaps


def test_offline_size_cap() -> None:
    with pytest.raises(ValueError, match="2 MB"):
        OfflineProvider("x" * 2_000_001, "ethereum")


def test_family_address_normalization_and_configurable_evm_registry(tmp_path) -> None:
    assert normalize_address(Chain("ethereum", "evm", "ETH"), "0x" + "A" * 40) == "0x" + "a" * 40
    with pytest.raises(ValueError):
        normalize_address(Chain("ethereum", "evm", "ETH"), "bad")
    path = tmp_path / "chains.json"
    path.write_text(
        '{"chains":{"custom":{"family":"evm","native_asset":"NEW",'
        '"explorer_api":"https://explorer.example/api",'
        '"allow_nonstandard_port":true,"chain_id":999}}}'
    )
    custom = load_registry(path)["custom"]
    assert custom.native_asset == "NEW"
    assert custom.explorer_api == "https://explorer.example/api"
    assert custom.allow_nonstandard_port
    assert custom.chain_id == 999


def test_builtin_etherscan_v2_registry_chain_ids() -> None:
    expected = {
        "ethereum": 1,
        "bsc": 56,
        "polygon": 137,
        "arbitrum": 42161,
        "optimism": 10,
        "base": 8453,
        "avalanche": 43114,
    }
    for name, chain_id in expected.items():
        chain = load_registry()[name]
        assert chain.explorer_api == "https://api.etherscan.io/v2/api"
        assert chain.chain_id == chain_id
        assert chain.api_key_env == "CHINESCAN_ETHERSCAN_KEY"
        assert chain.host_allowlist == ("api.etherscan.io",)


def test_evm_provider_sends_v2_chainid_and_maps_error_payloads() -> None:
    canary = "CHAIN_ID_ERROR_SECRET_CANARY"
    observed: list[tuple[str, dict[str, object]]] = []

    def run(payload):
        def http(url, *, params, **_options):
            observed.append((url, params))
            return FakeResponse(payload)

        provider = EvmProvider(
            "https://api.etherscan.io/v2/api",
            canary,
            http,
            retries=0,
            throttle_seconds=0,
            chain_id=8453,
        )
        return provider.transfers("0x" + "a" * 40, limit=10)

    rate_limited = run({"status": "0", "message": "NOTOK", "result": "Rate limit reached"})
    assert "rate_limited" in rate_limited.gaps
    invalid_key = run({"status": "0", "message": "NOTOK", "result": "Invalid API Key"})
    assert "invalid_api_key" in invalid_key.gaps
    generic = run(
        {
            "status": "0",
            "message": "NOTOK",
            "result": f"Provider rejected request; diagnostic {canary}",
        }
    )
    generic_gaps = [gap for gap in generic.gaps if gap.startswith("provider_error:")]
    assert generic_gaps
    assert all(len(gap.partition(":")[2]) <= 120 for gap in generic_gaps)
    assert canary not in str(generic.gaps)
    for payload in (
        {"status": "0", "message": "OK", "result": []},
        {"message": "NOTOK", "result": []},
        {"status": "1", "message": "OK", "result": "Unexpected provider response"},
    ):
        variant = run(payload)
        assert any(gap.startswith("provider_error:") for gap in variant.gaps)
    empty = run({"status": "0", "message": "NOTOK", "result": "No transactions found"})
    assert not empty.gaps
    assert all(url == "https://api.etherscan.io/v2/api" for url, _params in observed)
    assert all(params["chainid"] == 8453 for _url, params in observed)
    assert all("apikey" not in params for _url, params in observed)


class FakeProvider:
    def __init__(self):
        self.edges = {
            "seed": [
                Transfer(
                    chain="x",
                    tx_hash="a",
                    block_time=1,
                    sender="seed",
                    receiver="child",
                    asset="X",
                    amount=Decimal("1"),
                )
            ],
            "child": [],
        }

    def transfers(self, address, *, limit, cursor=None):
        from chinescan.chain_trace.providers.base import Page

        return Page(tuple(self.edges.get(address, [])))


def test_tracer_collects_outgoing_edges_and_depth_gap() -> None:
    wallets, edges, gaps = trace(FakeProvider(), TraceParams(chain="x", seed="seed", depth=1), {})
    assert set(wallets) == {"seed", "child"} and len(edges) == 1
    assert "depth_limit" in gaps


def test_service_aggregates_repeated_coverage_gaps(repository) -> None:
    from chinescan.chain_trace.providers.base import Page

    class BranchingProvider:
        def transfers(self, address, *, limit, cursor=None):
            if address == "seed":
                return Page(
                    (
                        _edge("tx-1", "seed", "child-1"),
                        _edge("tx-2", "seed", "child-2"),
                    )
                )
            return Page(())

    scan, _findings = ChainTraceService(BranchingProvider(), {}, repository).trace(
        TraceParams(chain="ethereum", seed="seed", depth=1), authorization=True
    )
    repeated = [gap for gap in scan.coverage.gaps if gap.code == "depth_limit"]
    assert len(repeated) == 1
    assert repeated[0].count == 2
    assert repeated[0].example == "chain-trace-depth-limit"


class FakeResponse:
    def __init__(self, body, status_code=200):
        self.body = body
        self.status_code = status_code
        self.content_type = "application/json"

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


def test_evm_provider_success_pagination_and_malformed_rows() -> None:
    calls = []

    def http(_url, *, params, **request_options):
        calls.append((params, request_options))
        if params["action"] == "txlist":
            return FakeResponse(
                {
                    "message": "OK",
                    "result": [
                        {"hash": "tx", "timeStamp": "1", "from": "a", "to": "b", "value": "2"}
                    ],
                }
            )
        if params["action"] == "txlistinternal":
            return FakeResponse({"message": "OK", "result": "No transactions found"})
        return FakeResponse({"message": "OK", "result": [{"bad": "row"}]})

    provider = EvmProvider("https://example.invalid", "sentinel", http, throttle_seconds=0)
    page = provider.transfers("a", limit=1)
    assert page.transfers[0].tx_hash == "tx"
    assert page.truncated and page.next_cursor == "2"
    assert "provider_row_invalid" in page.gaps
    assert all(call[1]["api_key"] == "sentinel" for call in calls)
    assert all("apikey" not in call[0] for call in calls)
    from chinescan.chain_trace.providers.base import Page

    class TruncatedProvider:
        def transfers(self, address, *, limit, cursor=None):
            return Page(
                page.transfers, truncated=True, next_cursor=page.next_cursor, gaps=page.gaps
            )

    _nodes, _edges, gaps = trace(
        TruncatedProvider(), TraceParams(chain="ethereum", seed="a", depth=1), {}
    )
    assert "truncated_history" in gaps


def test_evm_provider_429_timeout_and_json_errors_become_gaps() -> None:
    calls = 0

    def limited(_url, *, params, **_request_options):
        nonlocal calls
        calls += 1
        return FakeResponse({}, status_code=429)

    provider = EvmProvider(
        "url", "secret-key", limited, retries=2, throttle_seconds=0, sleep=lambda _: None
    )
    page = provider.transfers("wallet", limit=5)
    assert calls == 9
    assert "rate_limited" in page.gaps

    def timed_out(_url, *, params, **_request_options):
        raise TimeoutError("sentinel-secret timeout")

    timeout_page = EvmProvider(
        "url", "sentinel-secret", timed_out, retries=1, throttle_seconds=0, sleep=lambda _: None
    ).transfers("wallet", limit=5)
    assert "provider_timeout" in timeout_page.gaps
    assert "sentinel-secret" not in str(timeout_page)

    def malformed(_url, *, params, **_request_options):
        return FakeResponse(ValueError("sentinel-secret invalid JSON"))

    malformed_page = EvmProvider("url", "sentinel-secret", malformed, throttle_seconds=0).transfers(
        "wallet", limit=5
    )
    assert "malformed_response" in malformed_page.gaps
    assert "sentinel-secret" not in str(malformed_page)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://provider.example/api",
        "https://user:pass@provider.example/api",
        "https://provider.example:8443/api",
        "https://127.0.0.1/api",
        "https://169.254.169.254/latest/meta-data",
        "file:///etc/passwd",
        "ftp://provider.example/api",
    ],
)
def test_endpoint_policy_rejects_unsafe_urls(endpoint: str) -> None:
    with pytest.raises(EndpointPolicyError):
        validate_endpoint(endpoint, resolver=_private_resolver)


@pytest.mark.parametrize(
    "literal",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::",
        "::ffff:8.8.8.8",
    ],
)
def test_endpoint_policy_rejects_non_public_literal_addresses(literal: str) -> None:
    with pytest.raises(EndpointPolicyError, match="endpoint_non_public_address"):
        validate_endpoint(
            f"https://[{literal}]/api" if ":" in literal else f"https://{literal}/api"
        )


def test_endpoint_policy_rechecks_public_dns_and_allowlist() -> None:
    with pytest.raises(EndpointPolicyError, match="endpoint_non_public_address"):
        validate_endpoint("https://provider.example/api", resolver=_private_resolver)
    with pytest.raises(EndpointPolicyError, match="endpoint_host_not_allowed"):
        validate_endpoint(
            "https://provider.example/api",
            allowed_hosts=("api.etherscan.io",),
            resolver=_public_resolver,
        )
    with pytest.raises(EndpointPolicyError, match="endpoint_non_public_address"):
        validate_endpoint("https://provider.example/api", resolver=_mapped_resolver)
    assert (
        validate_endpoint(
            "https://api.etherscan.io/api",
            allowed_hosts=("api.etherscan.io",),
            resolver=_public_resolver,
        ).hostname
        == "api.etherscan.io"
    )
    with pytest.raises(EndpointPolicyError, match="endpoint_dns_timeout"):
        validate_endpoint(
            "https://provider.example/api",
            resolver=_slow_resolver,
            resolve_timeout_seconds=0.01,
        )


def test_endpoint_policy_rejects_mixed_dns_answers_and_empty_userinfo() -> None:
    def mixed_resolver(_host, _port, *, type):
        return [
            (AF_INET, type, 6, "", ("93.184.216.34", 443)),
            (AF_INET, type, 6, "", ("10.0.0.8", 443)),
        ]

    with pytest.raises(EndpointPolicyError, match="endpoint_non_public_address"):
        validate_endpoint(
            "https://provider.example/api",
            allowed_hosts=("provider.example",),
            resolver=mixed_resolver,
        )
    with pytest.raises(EndpointPolicyError, match="endpoint_invalid"):
        validate_endpoint("https://@provider.example/api", resolver=_public_resolver)
    with pytest.raises(EndpointPolicyError, match="endpoint_non_public_address"):
        validate_endpoint("https://10.0.0.1/api", resolver=_public_resolver)


def test_system_dns_resolution_uses_killable_sanitized_subprocess(monkeypatch) -> None:
    import subprocess
    import sys
    from types import SimpleNamespace

    import chinescan.chain_trace.endpoint_policy as policy

    observed = {}

    def fake_run(args, **kwargs):
        observed.update(args=args, options=kwargs)
        return SimpleNamespace(returncode=0, stdout='["8.8.8.8"]')

    monkeypatch.setattr(policy.subprocess, "run", fake_run)
    endpoint = validate_endpoint(
        "https://provider.example/api", allowed_hosts=("provider.example",)
    )
    assert endpoint.hostname == "provider.example"
    assert observed["args"][0] == sys.executable
    assert observed["args"][3:5] == ["provider.example", "443"]
    assert observed["options"]["timeout"] == 2.0
    assert set(observed["options"]["env"]) <= {
        "PATH",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
    }

    def timed_out(_args, **_kwargs):
        raise subprocess.TimeoutExpired("resolver", 2.0)

    monkeypatch.setattr(policy.subprocess, "run", timed_out)
    with pytest.raises(EndpointPolicyError, match="endpoint_dns_timeout"):
        validate_endpoint("https://provider.example/api")


def test_endpoint_resolver_timeout_keeps_worker_count_bounded() -> None:
    import threading
    import time

    release = threading.Event()
    entered = 0
    entered_lock = threading.Lock()

    def blocked_resolver(_host, _port, *, type):
        nonlocal entered
        with entered_lock:
            entered += 1
        release.wait(timeout=2)
        return _public_resolver(_host, _port, type=type)

    try:
        for _ in range(4):
            with pytest.raises(EndpointPolicyError, match="endpoint_dns_timeout"):
                validate_endpoint(
                    "https://provider.example/api",
                    resolver=blocked_resolver,
                    resolve_timeout_seconds=0.01,
                )
        workers = [
            thread for thread in threading.enumerate() if thread.name == "chinescan-chain-dns"
        ]
        assert entered == 4
        assert len(workers) <= 4
        with pytest.raises(EndpointPolicyError, match="endpoint_dns_timeout"):
            validate_endpoint(
                "https://provider.example/api",
                resolver=blocked_resolver,
                resolve_timeout_seconds=0.01,
            )
        assert entered == 4
    finally:
        release.set()

    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and any(
        thread.name == "chinescan-chain-dns" for thread in threading.enumerate()
    ):
        time.sleep(0.01)
    assert not any(thread.name == "chinescan-chain-dns" for thread in threading.enumerate())


@pytest.mark.parametrize(
    "status,new_url",
    [
        (301, "https://api.etherscan.io/other"),
        (302, "https://api.etherscan.io/other"),
        (303, "https://api.etherscan.io/other"),
        (307, "https://api.etherscan.io/other"),
        (308, "https://api.etherscan.io/other"),
        (307, "http://api.etherscan.io/api"),
        (307, "https://api.etherscan.io:8443/api"),
        (307, "https://user@api.etherscan.io/api"),
        (307, "https://127.0.0.1/api"),
    ],
)
def test_redirect_policy_refuses_every_destination(status: int, new_url: str) -> None:
    handler = _SameHostHTTPSRedirectHandler(
        "https://api.etherscan.io/api",
        allow_nonstandard_port=False,
        resolver=_public_resolver,
    )
    with pytest.raises(EndpointPolicyError, match="redirect_rejected"):
        handler.redirect_request(
            Request("https://api.etherscan.io/api", data=b"apikey=SENTINEL"),
            None,
            status,
            "Redirect",
            HTTPMessage(),
            new_url,
        )


def test_evm_provider_redirect_policy_and_secrets_stay_inside_request_layer() -> None:
    calls = []
    canary = "KEY_CANARY_DO_NOT_LEAK"

    def http(url, *, params, api_key, **_options):
        calls.append((url, params, api_key))
        raise RuntimeError(f"transport failed for {url}?apikey={api_key}")

    page = EvmProvider("https://api.etherscan.io/api", canary, http, throttle_seconds=0).transfers(
        "wallet", limit=1
    )
    handler = _SameHostHTTPSRedirectHandler(
        "https://api.etherscan.io/api",
        allow_nonstandard_port=False,
        resolver=_public_resolver,
    )
    request = Request("https://api.etherscan.io/api")
    with pytest.raises(EndpointPolicyError, match="redirect_rejected"):
        handler.redirect_request(
            request, None, 302, "Found", HTTPMessage(), "https://api.etherscan.io/v4/api"
        )
    handler = _SameHostHTTPSRedirectHandler(
        "https://api.etherscan.io/api",
        allow_nonstandard_port=False,
        resolver=_public_resolver,
    )
    with pytest.raises(EndpointPolicyError, match="redirect_rejected"):
        handler.redirect_request(
            request, None, 302, "Found", HTTPMessage(), "https://attacker.example/collect"
        )
    assert calls[0][2] == canary
    assert "apikey" not in calls[0][1]
    assert "provider_error" in page.gaps
    assert canary not in str(page)


def test_evm_provider_request_and_deadline_bounds_become_gaps() -> None:
    calls = 0

    def http(_url, *, params, **_options):
        nonlocal calls
        calls += 1
        return FakeResponse({"message": "OK", "result": "No transactions found"})

    page = EvmProvider("url", "", http, throttle_seconds=0, retries=0, max_requests=1).transfers(
        "wallet", limit=1
    )
    assert calls == 1
    assert "request_limit" in page.gaps

    times = iter([0.0, 121.0])

    def elapsed_clock() -> float:
        return next(times, 121.0)

    timed_page = EvmProvider("url", "", http, throttle_seconds=0, clock=elapsed_clock).transfers(
        "wallet", limit=1
    )
    assert "trace_deadline" in timed_page.gaps

    def oversized(_url, *, params, **_options):
        raise ProviderLimitError("response_too_large")

    large_page = EvmProvider("url", "", oversized, throttle_seconds=0, retries=0).transfers(
        "wallet", limit=1
    )
    assert "response_too_large" in large_page.gaps


def test_evm_provider_retry_backoff_throttle_and_request_bounds() -> None:
    calls = 0
    delays: list[float] = []

    def rate_limited(_url, *, params, **_options):
        nonlocal calls
        calls += 1
        return FakeResponse({"message": "NOTOK", "result": "rate limit"}, status_code=429)

    provider = EvmProvider(
        "https://example.invalid/api",
        "",
        rate_limited,
        retries=100,
        throttle_seconds=1_000_000,
        sleep=delays.append,
        max_requests=1_000_000,
    )
    page = provider.transfers("wallet", limit=1)
    assert calls == 18  # three actions, six total attempts per action
    assert provider.retries == 5
    assert provider.throttle_seconds == 5
    assert provider.max_requests == 10_000
    assert all(0 <= delay <= 5 for delay in delays)
    assert page.gaps == ("rate_limited",)


def test_evm_provider_rejects_wrong_content_type() -> None:
    def html(_url, *, params, **_options):
        response = FakeResponse({"message": "OK", "result": []})
        response.content_type = "text/html"
        return response

    page = EvmProvider("url", "", html, retries=0, throttle_seconds=0).transfers("wallet", limit=1)
    assert "unexpected_content_type" in page.gaps


def test_evm_provider_rejects_missing_content_type() -> None:
    response = FakeResponse({"message": "OK", "result": []})
    response.content_type = ""
    page = EvmProvider(
        "https://example.invalid/api",
        "",
        lambda _url, **_options: response,
        retries=0,
        throttle_seconds=0,
    ).transfers("wallet", limit=1)
    assert page.gaps == ("unexpected_content_type",)


def test_live_adapter_rejects_invalid_endpoint_before_any_request() -> None:
    provider = EvmProvider("http://127.0.0.1/api", "", stdlib_http_get, retries=0)
    page = provider.transfers("wallet", limit=1)
    assert "endpoint_invalid" in page.gaps
    with pytest.raises(EndpointPolicyError, match="endpoint_host_not_allowed"):
        stdlib_http_get(
            "https://api.etherscan.io/api",
            params={},
            api_key="SENTINEL",
            allowed_hosts=(),
            resolver=_public_resolver,
        )


def test_api_key_url_encoded_form_in_provider_data_becomes_gap() -> None:
    key = "secret/key + value"

    def response_for(value: str):
        def http(_url, *, params, **_options):
            return FakeResponse(
                {
                    "message": "OK",
                    "result": [
                        {"hash": value, "timeStamp": "1", "from": "a", "to": "b", "value": "1"}
                    ],
                }
            )

        return http

    from urllib.parse import quote, quote_plus

    encodings = (key, quote(key), quote_plus(key), quote(quote(key)), quote_plus(quote_plus(key)))
    for encoded in encodings:
        page = EvmProvider(
            "url", key, response_for(encoded), retries=0, throttle_seconds=0
        ).transfers("wallet", limit=1)
        assert not page.transfers
        assert "provider_row_invalid" in page.gaps
        assert key not in str(page)


def test_stdlib_adapter_caps_body_and_rejects_non_json(monkeypatch) -> None:
    import chinescan.chain_trace.providers.evm as evm_module

    class Headers(dict):
        def get_content_type(self):
            return self.get("Content-Type", "").split(";", 1)[0]

    class Response:
        status = 200

        def __init__(self, content_type: str, payload: bytes):
            self.headers = Headers({"Content-Type": content_type})
            self.payload = payload
            self.fp = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read1(self, size: int) -> bytes:
            chunk, self.payload = self.payload[:size], self.payload[size:]
            return chunk

        read = read1

    class Opener:
        def __init__(self, response):
            self.response = response

        def open(self, request, timeout):
            return self.response

    monkeypatch.setattr(
        evm_module,
        "build_opener",
        lambda *_handlers: Opener(Response("text/html", b"{}")),
    )
    with pytest.raises(ProviderLimitError, match="unexpected_content_type"):
        evm_module.stdlib_http_get(
            "https://provider.example/api",
            params={},
            allowed_hosts=("provider.example",),
            resolver=_public_resolver,
        )
    monkeypatch.setattr(
        evm_module,
        "build_opener",
        lambda *_handlers: Opener(Response("application/json", b"x" * (2_000_001))),
    )
    with pytest.raises(ProviderLimitError, match="response_too_large"):
        evm_module.stdlib_http_get(
            "https://provider.example/api",
            params={},
            allowed_hosts=("provider.example",),
            resolver=_public_resolver,
        )


def test_stdlib_adapter_keeps_api_key_out_of_request_url(monkeypatch) -> None:
    import chinescan.chain_trace.providers.evm as evm_module

    class Headers(dict):
        def get_content_type(self):
            return self.get("Content-Type", "").split(";", 1)[0]

    class Response:
        status = 200
        headers = Headers({"Content-Type": "application/json"})
        fp = None

        def __init__(self) -> None:
            self.consumed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read1(self, _size: int) -> bytes:
            if self.consumed:
                return b""
            self.consumed = True
            return b"{}"

        read = read1

    class Opener:
        def open(self, request, timeout):
            assert timeout > 0
            assert request.get_method() == "POST"
            assert "SECRET_CANARY" not in request.full_url
            assert request.full_url == "https://provider.example/api"
            body = parse_qs(request.data.decode("ascii"))
            assert body["apikey"] == ["SECRET_CANARY"]
            assert body["module"] == ["account"]
            return Response()

    monkeypatch.setattr(evm_module, "build_opener", lambda *_handlers: Opener())
    response = evm_module.stdlib_http_get(
        "https://provider.example/api",
        params={"module": "account", "action": "txlist"},
        api_key="SECRET_CANARY",
        allowed_hosts=("provider.example",),
        resolver=_public_resolver,
    )

    assert response.json() == {}


def _stub_https_responses(monkeypatch, responses: list[bytes]):
    import chinescan.chain_trace.providers.evm as evm_module

    requests: list[bytes] = []
    connections: list[object] = []

    class FakeSocket:
        def __init__(self, response: bytes) -> None:
            self.response = response

        def sendall(self, data: bytes) -> None:
            requests.append(data)

        def makefile(self, *_args, **_kwargs):
            return BytesIO(self.response)

        def settimeout(self, _timeout: float) -> None:
            return None

        def close(self) -> None:
            return None

    def connect(connection) -> None:
        index = len(connections)
        connections.append(object())
        connection.sock = FakeSocket(responses[index])

    monkeypatch.setattr(evm_module._PinnedHTTPSConnection, "connect", connect)
    return requests, connections


def test_stdlib_adapter_refuses_cross_host_redirect_without_key_leak(monkeypatch) -> None:
    import chinescan.chain_trace.providers.evm as evm_module

    requests, connections = _stub_https_responses(
        monkeypatch,
        [
            b"HTTP/1.1 307 Temporary Redirect\r\n"
            b"Location: https://attacker.example/collect\r\n"
            b"Content-Length: 0\r\nConnection: close\r\n\r\n"
        ],
    )
    canary = "REDIRECT_SECRET_CANARY"
    with pytest.raises(EndpointPolicyError) as exc_info:
        evm_module.stdlib_http_get(
            "https://api.etherscan.io/api",
            params={"module": "account"},
            api_key=canary,
            allowed_hosts=("api.etherscan.io",),
            resolver=_public_resolver,
        )

    assert exc_info.value.code == "redirect_rejected"
    assert canary not in str(exc_info.value)
    assert canary not in repr(exc_info.value)
    assert len(connections) == 1
    request_lines = [
        request.split(b"\r\n", 1)[0]
        for request in requests
        if request.startswith((b"POST ", b"GET "))
    ]
    assert len(request_lines) == 1  # no connection was made for the redirect host
    assert b"attacker.example" not in b"\r\n".join(request_lines)
    assert all(canary.encode() not in line for line in request_lines)


def test_stdlib_adapter_refuses_same_host_307_before_forwarding_post_body(monkeypatch) -> None:
    import chinescan.chain_trace.providers.evm as evm_module

    requests, connections = _stub_https_responses(
        monkeypatch,
        [
            b"HTTP/1.1 307 Temporary Redirect\r\n"
            b"Location: https://api.etherscan.io/v2/api\r\n"
            b"Content-Length: 0\r\nConnection: close\r\n\r\n",
        ],
    )
    canary = "SAME_HOST_SECRET_CANARY"
    with pytest.raises(EndpointPolicyError) as exc_info:
        evm_module.stdlib_http_get(
            "https://api.etherscan.io/api",
            params={"module": "account"},
            api_key=canary,
            allowed_hosts=("api.etherscan.io",),
            resolver=_public_resolver,
        )

    assert exc_info.value.code == "redirect_rejected"
    assert canary not in str(exc_info.value)
    assert canary not in repr(exc_info.value)
    assert len(connections) == 1
    request_lines = [
        request.split(b"\r\n", 1)[0]
        for request in requests
        if request.startswith((b"POST ", b"GET "))
    ]
    assert len(request_lines) == 1  # no same-host redirect request receives the POST body
    assert all(canary.encode() not in line for line in request_lines)


def test_tracer_non_evm_provider_gap() -> None:
    class Unsupported:
        def transfers(self, address, *, limit, cursor=None):
            from chinescan.chain_trace.providers.base import UnsupportedFamily

            raise UnsupportedFamily("not supported")

    _nodes, _edges, gaps = trace(Unsupported(), TraceParams(chain="bitcoin", seed="wallet"), {})
    assert "unsupported_chain_family" in gaps


def _edge(
    tx: str, sender: str, receiver: str, at: int = 1, amount: str = "1", kind: str = "transfer"
) -> Transfer:
    return Transfer(
        chain="ethereum",
        tx_hash=tx,
        block_time=at,
        sender=sender,
        receiver=receiver,
        asset="ETH",
        amount=Decimal(amount),
        kind=kind,
    )


@pytest.mark.parametrize(
    "rule,edges,labels",
    [
        ("fan_out", [_edge(str(i), "s", str(i)) for i in range(3)], {}),
        ("fan_in", [_edge(str(i), str(i), "r") for i in range(3)], {}),
        ("peel_chain", [_edge("a", "s", "w", 1), _edge("b", "w", "r", 2)], {}),
        ("rapid_pass_through", [_edge("a", "s", "w", 1), _edge("b", "w", "r", 2)], {}),
        ("first_funder", [_edge("a", "f", "w1"), _edge("b", "f", "w2")], {}),
        (
            "cash_out",
            [_edge("a", "s", "exchange")],
            {
                ("ethereum", "exchange"): Label(
                    address="exchange",
                    chain="ethereum",
                    category="exchange",
                    name="Desk",
                    source="local",
                    date="2026-01-01",
                )
            },
        ),
        (
            "mixer_exposure",
            [_edge("a", "s", "mixer")],
            {
                ("ethereum", "mixer"): Label(
                    address="mixer",
                    chain="ethereum",
                    category="mixer",
                    name="Mix",
                    source="local",
                    date="2026-01-01",
                )
            },
        ),
        (
            "sanctioned_exposure",
            [_edge("a", "s", "sanction")],
            {
                ("ethereum", "sanction"): Label(
                    address="sanction",
                    chain="ethereum",
                    category="sanctioned",
                    name="Listed",
                    source="local",
                    date="2026-01-01",
                )
            },
        ),
        (
            "drainer_pattern",
            [_edge("a", "owner", "spender", kind="approval"), _edge("b", "owner", "sweep", 2)],
            {},
        ),
        (
            "address_poisoning",
            [_edge("dust", "0x12345678aaaa", "0x12345678bbbb", amount="0.000000001")],
            {},
        ),
    ],
)
def test_detector_positive_and_negative(rule, edges, labels) -> None:
    matching = [lead for lead in detect(edges, labels) if lead.rule_id == rule]
    assert matching
    finding = finding_for_lead(TraceParams(chain="ethereum", seed="seed"), matching[0])
    assert rule in finding.title and rule in finding.description
    assert "false positives" in finding.description.casefold() and "CoinJoin" in finding.description
    assert "Supporting transaction hashes" in finding.description
    if finding.evidence.value == "pattern_match":
        assert "threshold" in finding.description.casefold() or "window" in (
            finding.description.casefold()
        )
    assert all(tx in finding.description for tx in matching[0].transactions[:10])
    expected_evidence = {
        "cash_out": "reference_only",
        "mixer_exposure": "reference_only",
        "sanctioned_exposure": "confirmed_artifact",
    }.get(rule, "pattern_match")
    assert finding.evidence.value == expected_evidence
    assert finding.confidence.value in {"LIKELY", "POSSIBLE", "INFORMATIONAL"}
    expected_severity = (
        "low"
        if rule in {"fan_out", "fan_in", "first_funder", "peel_chain", "rapid_pass_through"}
        else "high"
        if rule == "sanctioned_exposure"
        else "medium"
    )
    assert finding.severity.value == expected_severity
    assert rule not in {lead.rule_id for lead in detect([_edge("negative", "alpha", "beta")], {})}


def test_labeled_counterparty_downgrades_fan_out_and_notes_why() -> None:
    edges = [_edge(f"tx-{i}", "source", f"wallet-{i}") for i in range(3)]
    unlabeled_lead = next(lead for lead in detect(edges, {}) if lead.rule_id == "fan_out")
    label = Label(
        address="wallet-0",
        chain="ethereum",
        category="exchange",
        name="local-service-label",
        source="operator fixture",
        date="2026-01-01",
    )
    labeled_lead = next(
        lead
        for lead in detect(edges, {("ethereum", "wallet-0"): label})
        if lead.rule_id == "fan_out"
    )
    params = TraceParams(chain="ethereum", seed="source")
    unlabeled_finding = finding_for_lead(params, unlabeled_lead)
    labeled_finding = finding_for_lead(params, labeled_lead)

    assert unlabeled_finding.confidence.value == "LIKELY"
    assert labeled_finding.confidence.value == "POSSIBLE"
    assert "Labeled counterparty context" not in unlabeled_finding.description
    assert "local-service-label" in labeled_finding.description
    assert "reduced weight" in labeled_finding.description


def test_first_funder_skips_traced_seed_but_keeps_distinct_funder() -> None:
    seed_fanout = [_edge("seed-1", "seed", "wallet-1"), _edge("seed-2", "seed", "wallet-2")]
    assert "first_funder" not in {lead.rule_id for lead in detect(seed_fanout, {}, seed="seed")}

    external_funding = [
        _edge("external-1", "upstream", "wallet-1"),
        _edge("external-2", "upstream", "wallet-2"),
    ]
    assert "first_funder" in {lead.rule_id for lead in detect(external_funding, {}, seed="seed")}


def test_finding_locations_use_wallet_for_heuristics_and_exact_hash_for_tx_leads() -> None:
    seed = "0x" + "a" * 40
    edges = [_edge(f"tx-{index}", seed, f"wallet-{index}") for index in range(3)]
    fan_out = next(lead for lead in detect(edges, {}, seed=seed) if lead.rule_id == "fan_out")
    params = TraceParams(chain="ethereum", seed=seed)
    wallet_finding = finding_for_lead(params, fan_out)
    assert wallet_finding.location == f"chain:ethereum:{seed}"
    assert len(wallet_finding.location.rsplit(":", 1)[1]) == 42

    empty_wallet_lead = Lead("fan_out", "", ("0x" + "b" * 64,), "fan-out threshold >= 3")
    assert finding_for_lead(params, empty_wallet_lead).location == f"chain:ethereum:{seed}"

    tx_hash = "0x" + "c" * 64
    tx_finding = finding_for_lead(
        params, Lead("transaction_level", "", (tx_hash,), "Transaction-level reference")
    )
    assert tx_finding.location == tx_hash
    assert len(tx_finding.location) == 66


def test_offline_csv_service_persists_fanout_wallet_location(repository) -> None:
    seed = "0x" + "a" * 40
    rows = ["hash,timeStamp,from,to,value"]
    tx_hashes = set()
    for index in range(16):
        tx_hash = "0x" + f"{index + 1000:064x}"
        recipient = "0x" + f"{index + 1:040x}"
        tx_hashes.add(tx_hash)
        rows.append(f"{tx_hash},{index + 1},{seed},{recipient},1")
    provider = OfflineProvider("\n".join(rows), "ethereum", "csv")

    scan, findings = ChainTraceService(provider, {}, repository).trace(
        TraceParams(chain="ethereum", seed=seed, depth=1), authorization=False
    )

    fan_out = next(finding for finding in findings if finding.rule_id == "fan_out")
    persisted = repository.get("finding", fan_out.finding_id)
    assert persisted is not None
    location = persisted["location"]
    assert isinstance(location, str)
    assert re.fullmatch(r"chain:[a-z0-9_-]+:0x[0-9a-fA-F]{40}", location)
    assert location == f"chain:ethereum:{seed}"
    assert all(tx_hash not in location for tx_hash in tx_hashes)
    markdown = render_report(scan, findings, "markdown")
    location_lines = [line for line in markdown.splitlines() if line.startswith("- Location:")]
    assert len(location_lines) == 1
    assert location in location_lines[0]


def test_heuristic_description_caps_supporting_hashes_at_ten() -> None:
    transactions = tuple(f"tx-{index}" for index in range(12))
    finding = finding_for_lead(
        TraceParams(chain="ethereum", seed="wallet"),
        Lead("fan_out", "wallet", transactions, "12 counterparties (threshold >= 3)"),
    )
    supported = sorted(set(transactions))[:10]
    omitted = sorted(set(transactions))[10:]
    assert all(tx in finding.description for tx in supported)
    assert all(tx not in finding.description for tx in omitted)


def test_chain_share_summary_truncates_addresses_and_omits_tx_hashes() -> None:
    from datetime import UTC, datetime

    from chinescan.core.models.investigation import Scan

    address = "0x" + "a" * 40
    tx_hash = "0x" + "b" * 64
    finding = finding_for_lead(
        TraceParams(chain="ethereum", seed=address),
        Lead("fan_out", "", (tx_hash,), f"3 counterparties from {address} (threshold >= 3)"),
    )
    finding = finding.model_copy(update={"location": tx_hash})
    scan = Scan(
        scan_id="chain-summary-test",
        target_id="chain-summary-target",
        scanner="chain_trace",
        started_at=datetime.now(UTC),
        project_types=["chain", "ethereum"],
    )

    summary = render_report(scan, [finding], "share-summary")
    assert address not in summary
    assert "0xaaaa...aaaa" in summary
    assert tx_hash not in summary
    assert "transaction reference omitted" in summary


def test_full_chain_reports_keep_identifiers_but_redact_sentinel_key() -> None:
    from datetime import UTC, datetime

    from chinescan.core.models.investigation import Scan

    address = "0x" + "a" * 40
    tx_hash = "0x" + "b" * 64
    sentinel = "REPORT_SECRET_SENTINEL"
    finding = finding_for_lead(
        TraceParams(chain="ethereum", seed=address),
        Lead("fan_out", address, (tx_hash,), f"3 counterparties from {address} (threshold >= 3)"),
    )
    finding = finding.model_copy(
        update={"description": finding.description + f" Diagnostic api_key={sentinel}."}
    )
    scan = Scan(
        scan_id="chain-full-report-test",
        target_id="chain-full-report-target",
        scanner="chain_trace",
        started_at=datetime.now(UTC),
        project_types=["chain", "ethereum"],
    )

    for output_format in ("json", "markdown", "html", "csv"):
        report = render_report(scan, [finding], output_format)
        assert address in report
        assert tx_hash in report
        assert sentinel not in report

    summary = render_report(scan, [finding], "share-summary")
    assert address not in summary
    assert tx_hash not in summary
    assert sentinel not in summary
    assert "0xaaaa...aaaa" in summary


def test_chain_report_restores_twenty_five_identifiers_without_placeholder_collisions() -> None:
    from datetime import UTC, datetime

    from chinescan.core.models.investigation import Scan

    address = "0x" + "a" * 40
    hashes = ["0x" + f"{index:064x}" for index in range(1, 26)]
    marker_like = "CHAINHEXPLACEHOLDER00000000END"
    sentinel = "REPORT_HEX_SECRET_SENTINEL"
    finding = finding_for_lead(
        TraceParams(chain="ethereum", seed=address),
        Lead("fan_out", address, tuple(hashes), "Synthetic fixture"),
    ).model_copy(
        update={
            "title": " ".join([marker_like, address, *hashes]),
            "description": f"api_key={sentinel} identifiers: " + " ".join(hashes),
        }
    )
    scan = Scan(
        scan_id="chain-placeholder-test",
        target_id="chain-placeholder-target",
        scanner="chain_trace",
        started_at=datetime.now(UTC),
        project_types=["chain", "ethereum"],
    )

    for output_format in ("json", "markdown", "html", "csv"):
        report = render_report(scan, [finding], output_format)
        assert marker_like in report
        assert address in report
        assert all(tx_hash in report for tx_hash in hashes)
        assert sentinel not in report


def test_service_persists_audit_and_running_scan_before_provider_call(repository, caplog) -> None:
    order = []

    class SpyRepository:
        def save(self, record_type, record_id, payload):
            order.append((record_type, payload.get("status")))
            repository.save(record_type, record_id, payload)

        def get(self, record_type, record_id):
            return repository.get(record_type, record_id)

        def delete(self, record_type, record_id):
            repository.delete(record_type, record_id)

    sentinel = "CHAIN_API_SECRET_SENTINEL"

    def http(_url, *, params, **_request_options):
        assert ("authorization_record", None) in order
        assert ("scan", "running") in order
        return FakeResponse({"message": "OK", "result": "No transactions found"})

    provider = EvmProvider("https://example.invalid", sentinel, http, throttle_seconds=0)
    scan, findings = ChainTraceService(provider, {}, SpyRepository()).trace(
        TraceParams(chain="ethereum", seed="0x" + "a" * 40), authorization=True
    )
    records = [repository.get(kind, scan.scan_id) for kind in ("scan", "chain_graph")]
    records += repository.list_records("authorization_record")
    records += repository.list_records("target")
    records += repository.list_records("finding")
    rendered = render_report(scan, findings, "markdown")
    assert sentinel not in json.dumps(records)
    assert sentinel not in rendered
    assert sentinel not in caplog.text
    assert scan.status == "complete"


def test_provider_exception_url_and_error_body_never_escape(repository, caplog) -> None:
    sentinel = "PROVIDER_KEY_CANARY"
    error_url = f"https://api.etherscan.io/api?apikey={sentinel}"

    def failed_http(_url, *, params, **_options):
        raise RuntimeError(f"request failed: {error_url}; body contains {sentinel}")

    provider = EvmProvider(
        "https://api.etherscan.io/api",
        sentinel,
        failed_http,
        retries=0,
        throttle_seconds=0,
    )
    scan, findings = ChainTraceService(provider, {}, repository).trace(
        TraceParams(chain="ethereum", seed="0x" + "a" * 40), authorization=True
    )
    records = [repository.get(kind, scan.scan_id) for kind in ("scan", "chain_graph")]
    records += repository.list_records("authorization_record")
    records += repository.list_records("target")
    report = render_report(scan, findings, "markdown")
    assert scan.status == "partial"
    assert "provider_error" in {gap.code for gap in scan.coverage.gaps}
    assert sentinel not in json.dumps(records)
    assert sentinel not in report
    assert sentinel not in caplog.text
    assert sentinel not in str(scan.coverage.gaps)


def test_etherscan_error_reason_is_redacted_before_persistence(repository) -> None:
    sentinel = "ETHERSCAN_ERROR_REASON_SECRET_CANARY"

    def rejected(_url, *, params, api_key, **_options):
        assert params["chainid"] == 1
        assert api_key == sentinel
        return FakeResponse(
            {
                "status": "0",
                "message": "NOTOK",
                "result": f"Provider diagnostic: {sentinel}",
            }
        )

    provider = EvmProvider(
        "https://api.etherscan.io/v2/api",
        sentinel,
        rejected,
        retries=0,
        throttle_seconds=0,
        chain_id=1,
    )
    scan, findings = ChainTraceService(provider, {}, repository).trace(
        TraceParams(chain="ethereum", seed="0x" + "a" * 40), authorization=True
    )
    records = [repository.get(kind, scan.scan_id) for kind in ("scan", "chain_graph")]
    records += repository.list_records("authorization_record")
    records += repository.list_records("target")
    report = render_report(scan, findings, "markdown")

    assert scan.status == "partial"
    assert all(gap.code == "provider_error" for gap in scan.coverage.gaps)
    assert all(sentinel not in gap.reason for gap in scan.coverage.gaps)
    assert all("[REDACTED]" in gap.reason for gap in scan.coverage.gaps)
    assert sentinel not in json.dumps(records)
    assert sentinel not in report


def test_address_poisoning_requires_lookalike_dust_transfer() -> None:
    lookalike = _edge("dust", "0x12345678aaaa", "0x12345678bbbb", amount="0.000000001")
    ordinary = _edge("normal", "0x11111111aaaa", "0xeeeeeeeeeeee", amount="1")
    assert "address_poisoning" in {lead.rule_id for lead in detect([lookalike], {})}
    assert "address_poisoning" not in {lead.rule_id for lead in detect([ordinary], {})}


def test_pinned_https_connection_requires_tls_12_or_newer(monkeypatch) -> None:
    class Context:
        minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

        def wrap_socket(self, sock, *, server_hostname):
            assert server_hostname == "api.example.test"
            return sock

    monkeypatch.setattr(
        "chinescan.chain_trace.providers.evm.socket.create_connection", lambda *_args: object()
    )
    connection = _PinnedHTTPSConnection("api.example.test", addresses=("203.0.113.10",))
    context = Context()
    connection._context = context

    connection.connect()

    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_chain_web_auth_csrf_validation_and_network_gate(tmp_path) -> None:
    database = tmp_path / "db.sqlite3"
    credential = tmp_path / "operator.json"
    create_operator(credential, "chain@example.test", "safe chain password")
    settings = Settings(_env_file=None, database_path=database, reports_dir=tmp_path / "reports")
    app = create_app(database, credential, settings=settings, serve_frontend=False)
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 54321)) as client:
        assert client.get("/api/chain/chains").status_code == 401
        login = client.post(
            "/api/auth/login",
            json={"email": "chain@example.test", "password": "safe chain password"},
            headers={"Origin": "http://127.0.0.1"},
        )
        headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]}
        body = {"address": "0x" + "a" * 40, "chain": "ethereum", "depth": 2, "allow_network": True}
        no_csrf = client.post("/api/chain/jobs", json=body, headers={"Origin": "http://127.0.0.1"})
        assert no_csrf.status_code == 403
        disabled = client.post("/api/chain/jobs", json=body, headers=headers)
        assert disabled.status_code == 403
        assert disabled.json()["detail"]["code"] == "chain_network_disabled"
        assert (
            client.post(
                "/api/chain/jobs",
                json={
                    **body,
                    "address": "bad",
                    "allow_network": False,
                    "import_text": "hash,from,to,value",
                },
                headers=headers,
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/chain/jobs",
                json={
                    **body,
                    "depth": 7,
                    "allow_network": False,
                    "import_text": "hash,from,to,value",
                },
                headers=headers,
            ).status_code
            == 422
        )
        oversized = {**body, "allow_network": False, "import_text": "x" * 2_000_001}
        assert client.post("/api/chain/jobs", json=oversized, headers=headers).status_code in {
            413,
            422,
        }
        assert client.get("/api/chain/traces/not-a-scan/graph").status_code == 404
        assert client.get("/api/chain/traces/not-a-scan/export/graph-json").status_code == 404
        assert client.get("/api/chain/traces/not-a-scan/export/unknown").status_code == 404
        non_chain_repo = SQLiteRepository(database)
        non_chain_repo.save(
            "scan", "ordinary-scan", {"scan_id": "ordinary-scan", "scanner": "builtin"}
        )
        non_chain_repo.close()
        assert client.get("/api/chain/traces/ordinary-scan/graph").status_code == 404


def test_chain_cli_is_offline_without_explicit_network_opt_in(tmp_path) -> None:
    from typer.testing import CliRunner

    from chinescan.cli.app import app as cli_app

    result = CliRunner().invoke(
        cli_app,
        [
            "--config",
            str(tmp_path / "missing-config.toml"),
            "--database",
            str(tmp_path / "records.sqlite3"),
            "chain",
            "trace",
            "0x" + "a" * 40,
            "--chain",
            "ethereum",
        ],
    )
    assert result.exit_code == 2
    assert "explicitly opt in" in result.output


def test_chain_cli_label_file_loads_provenance_and_downgrades_only_labeled_lead(tmp_path) -> None:
    from typer.testing import CliRunner

    from chinescan.chain_trace.labels import load_labels
    from chinescan.cli.app import app as cli_app

    seed = "0x" + "a" * 40
    exchange = "0x" + "b" * 40
    other_one = "0x" + "c" * 40
    other_two = "0x" + "d" * 40
    transactions = "\n".join(
        [
            "hash,from,to,value,timeStamp",
            f"0x{'1' * 64},{seed},{exchange},1,1",
            f"0x{'2' * 64},{seed},{other_one},1,2",
            f"0x{'3' * 64},{seed},{other_two},1,3",
        ]
    )
    import_file = tmp_path / "transfers.csv"
    import_file.write_text(transactions, encoding="utf-8")
    label_file = tmp_path / "labels.json"
    label_file.write_text(
        json.dumps(
            {
                "labels": [
                    {
                        "address": exchange,
                        "chain": "ethereum",
                        "category": "exchange",
                        "name": "synthetic exchange fixture",
                        "source": "unit-test fixture",
                        "date": "2026-01-15",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    def run(name: str, label_path=None):
        database = tmp_path / f"{name}.sqlite3"
        config = tmp_path / f"{name}.toml"
        config.write_text("", encoding="utf-8")
        args = [
            "--config",
            str(config),
            "--database",
            str(database),
            "chain",
            "trace",
            seed,
            "--chain",
            "ethereum",
            "--import",
            str(import_file),
            "--depth",
            "1",
            "--no-save-report",
        ]
        if label_path is not None:
            args.extend(["--label-file", str(label_path)])
        result = CliRunner().invoke(cli_app, args)
        assert result.exit_code == 0, result.output
        output = json.loads(result.output)
        repository = SQLiteRepository(database)
        try:
            scan = repository.get("scan", output["scan_id"])
            findings = [repository.get("finding", key) for key in scan["finding_ids"]]
        finally:
            repository.close()
        return scan, [item for item in findings if item is not None]

    labeled_scan, labeled_findings = run("labeled", label_file)
    unlabeled_scan, unlabeled_findings = run("unlabeled")
    assert labeled_scan["coverage"]["examined"]["labels_loaded"] == 1
    labeled_lead = next(item for item in labeled_findings if item["rule_id"] == "fan_out")
    unlabeled_lead = next(item for item in unlabeled_findings if item["rule_id"] == "fan_out")
    assert labeled_lead["confidence"] == "POSSIBLE"
    assert "Labeled counterparty context" in labeled_lead["description"]
    assert "reduced weight" in labeled_lead["description"]
    assert unlabeled_lead["confidence"] == "LIKELY"
    assert "Labeled counterparty context" not in unlabeled_lead["description"]

    invalid_file = tmp_path / "invalid-labels.json"
    invalid_file.write_text(
        json.dumps(
            {
                "labels": [
                    {
                        "address": exchange,
                        "chain": "ethereum",
                        "category": "exchange",
                        "name": "fixture missing source",
                        "date": "2026-01-15",
                    },
                    {
                        "address": other_one,
                        "chain": "ethereum",
                        "category": "exchange",
                        "name": "fixture missing date",
                        "source": "unit-test fixture",
                    },
                    {
                        "address": other_two,
                        "chain": "ethereum",
                        "category": "exchange",
                        "name": "fixture empty provenance",
                        "source": " ",
                        "date": " ",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    invalid_labels, label_gaps = load_labels([invalid_file])
    assert invalid_labels == {}
    assert label_gaps == ["label_row_invalid"] * 3
    invalid_scan, _ = run("invalid-labels", invalid_file)
    assert invalid_scan["status"] == "partial"
    assert any(gap["code"] == "label_row_invalid" for gap in invalid_scan["coverage"]["gaps"])


def test_chain_web_fake_provider_job_graph_and_exports(tmp_path, monkeypatch) -> None:
    import threading

    import chinescan.web.chain_trace_jobs as jobs_module
    from chinescan.chain_trace.providers.base import Page

    started = threading.Event()
    release = threading.Event()
    provider_configuration = []

    class FakeNetworkProvider:
        def __init__(self, *_args, **_kwargs):
            provider_configuration.append((_args, _kwargs))

        def transfers(self, address, *, limit, cursor=None):
            started.set()
            release.wait(timeout=5)
            return Page(())

    monkeypatch.setenv("CHINESCAN_ETHERSCAN_KEY", "WEB_API_SECRET_SENTINEL")
    monkeypatch.setattr(jobs_module, "EvmProvider", FakeNetworkProvider)
    database = tmp_path / "db.sqlite3"
    credential = tmp_path / "operator.json"
    create_operator(credential, "chain@example.test", "safe chain password")
    settings = Settings(
        _env_file=None,
        database_path=database,
        reports_dir=tmp_path / "reports",
        chain_network_enabled=True,
    )
    app = create_app(database, credential, settings=settings, serve_frontend=False)
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 54322)) as client:
        login = client.post(
            "/api/auth/login",
            json={"email": "chain@example.test", "password": "safe chain password"},
            headers={"Origin": "http://127.0.0.1"},
        )
        headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]}
        submitted = client.post(
            "/api/chain/jobs",
            json={
                "address": "0x" + "a" * 40,
                "chain": "ethereum",
                "depth": 1,
                "allow_network": True,
                "endpoint": "https://attacker.example/collect",
                "host": "attacker.example",
                "url": "https://attacker.example/collect",
            },
            headers=headers,
        )
        assert submitted.status_code == 202
        assert submitted.json()["status"] == "queued"
        job_id = submitted.json()["job_id"]
        import time

        assert started.wait(timeout=5)
        assert provider_configuration[0][0][0] == "https://api.etherscan.io/v2/api"
        assert provider_configuration[0][1]["allowed_hosts"] == ("api.etherscan.io",)
        assert client.get(f"/api/chain/jobs/{job_id}").json()["status"] == "running"
        release.set()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            job = client.get(f"/api/chain/jobs/{job_id}").json()
            if job["status"] == "succeeded":
                break
            time.sleep(0.02)
        assert job["status"] == "succeeded"
        scan_id = job["scan_id"]
        assert client.get(f"/api/chain/traces/{scan_id}/graph").status_code == 200
        assert "WEB_API_SECRET_SENTINEL" not in client.get("/api/chain/chains").text
        for fmt in ("graph-json", "graphml", "transfers-csv", "indicators"):
            assert client.get(f"/api/chain/traces/{scan_id}/export/{fmt}").status_code == 200

        class BrokenProvider:
            def __init__(self, *_args, **_kwargs):
                pass

            def transfers(self, address, *, limit, cursor=None):
                raise TimeoutError("secret key must not escape: WEB_API_SECRET_SENTINEL")

        monkeypatch.setattr(jobs_module, "EvmProvider", BrokenProvider)
        failed_request = client.post(
            "/api/chain/jobs",
            json={
                "address": "0x" + "b" * 40,
                "chain": "ethereum",
                "depth": 1,
                "allow_network": True,
            },
            headers=headers,
        )
        failed_id = failed_request.json()["job_id"]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            failed = client.get(f"/api/chain/jobs/{failed_id}").json()
            if failed["status"] in {"failed", "succeeded"}:
                break
            time.sleep(0.02)
        assert failed["status"] == "failed"
        assert "secret key" not in str(failed)
        assert "WEB_API_SECRET_SENTINEL" not in json.dumps(failed)
        persisted = SQLiteRepository(database)
        all_records = []
        for record_type in (
            "chain_job",
            "scan",
            "chain_graph",
            "finding",
            "authorization_record",
        ):
            all_records.extend(persisted.list_records(record_type))
        persisted.close()
        assert "WEB_API_SECRET_SENTINEL" not in json.dumps(all_records)


def test_chain_job_restart_reconciles_queued_job(repository, tmp_path) -> None:
    from chinescan.web.chain_trace_jobs import ChainTraceJobManager

    manager = ChainTraceJobManager(repository, Settings(_env_file=None, chain_labels_path=None))
    queued = manager.submit(
        {
            "address": "wallet",
            "chain": "bitcoin",
            "depth": 1,
            "min_amount": "0",
            "allow_network": False,
        }
    )
    repository.save(
        "chain_job", "running-id", {**queued, "job_id": "running-id", "status": "running"}
    )
    manager.start()
    manager.stop()
    assert manager.get(queued["job_id"])["status"] == "interrupted"
    assert manager.get("running-id")["status"] == "interrupted"
