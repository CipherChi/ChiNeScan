from decimal import Decimal

import pytest

from chinescan.chain_trace.models import TraceParams, Transfer
from chinescan.chain_trace.providers.offline import OfflineProvider
from chinescan.chain_trace.registry import Chain, load_registry, normalize_address
from chinescan.chain_trace.tracer import trace


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
    path.write_text('{"chains":{"custom":{"family":"evm","native_asset":"NEW"}}}')
    assert load_registry(path)["custom"].native_asset == "NEW"


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
