import json
from decimal import Decimal
from http.client import HTTPMessage
from socket import AF_INET
from urllib.request import Request

import pytest
from fastapi.testclient import TestClient

from chinescan.chain_trace.detectors import detect
from chinescan.chain_trace.endpoint_policy import EndpointPolicyError, validate_endpoint
from chinescan.chain_trace.models import Label, TraceParams, Transfer
from chinescan.chain_trace.providers.evm import (
    EvmProvider,
    ProviderLimitError,
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
        '"allow_nonstandard_port":true}}}'
    )
    custom = load_registry(path)["custom"]
    assert custom.native_asset == "NEW"
    assert custom.explorer_api == "https://explorer.example/api"
    assert custom.allow_nonstandard_port


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


class FakeResponse:
    def __init__(self, body, status_code=200):
        self.body = body
        self.status_code = status_code

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
    assert (
        handler.redirect_request(
            request, None, 302, "Found", HTTPMessage(), "https://api.etherscan.io/v2/api"
        )
        is not None
    )
    assert (
        handler.redirect_request(
            request, None, 302, "Found", HTTPMessage(), "https://api.etherscan.io/v3/api"
        )
        is not None
    )
    with pytest.raises(EndpointPolicyError, match="redirect_limit"):
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


def test_evm_provider_rejects_wrong_content_type() -> None:
    def html(_url, *, params, **_options):
        response = FakeResponse({"message": "OK", "result": []})
        response.content_type = "text/html"
        return response

    page = EvmProvider("url", "", html, retries=0, throttle_seconds=0).transfers("wallet", limit=1)
    assert "unexpected_content_type" in page.gaps


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

    for encoded in (key, quote(key), quote_plus(key)):
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
    expected_evidence = {
        "cash_out": "reference_only",
        "mixer_exposure": "reference_only",
        "sanctioned_exposure": "confirmed_artifact",
    }.get(rule, "pattern_match")
    assert finding.evidence.value == expected_evidence
    assert finding.confidence.value in {"LIKELY", "POSSIBLE", "INFORMATIONAL"}
    assert rule not in {lead.rule_id for lead in detect([_edge("negative", "alpha", "beta")], {})}


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


def test_address_poisoning_requires_lookalike_dust_transfer() -> None:
    lookalike = _edge("dust", "0x12345678aaaa", "0x12345678bbbb", amount="0.000000001")
    ordinary = _edge("normal", "0x11111111aaaa", "0xeeeeeeeeeeee", amount="1")
    assert "address_poisoning" in {lead.rule_id for lead in detect([lookalike], {})}
    assert "address_poisoning" not in {lead.rule_id for lead in detect([ordinary], {})}


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


def test_chain_web_fake_provider_job_graph_and_exports(tmp_path, monkeypatch) -> None:
    import threading

    import chinescan.web.chain_trace_jobs as jobs_module
    from chinescan.chain_trace.providers.base import Page

    started = threading.Event()
    release = threading.Event()

    class FakeNetworkProvider:
        def __init__(self, *_args, **_kwargs):
            pass

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
            },
            headers=headers,
        )
        assert submitted.status_code == 202
        assert submitted.json()["status"] == "queued"
        job_id = submitted.json()["job_id"]
        import time

        assert started.wait(timeout=5)
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
