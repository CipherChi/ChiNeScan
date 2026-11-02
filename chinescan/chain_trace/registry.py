"""Data-driven chain registry and address normalization."""

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Chain:
    name: str
    family: str
    native_asset: str
    explorer_api: str = ""
    api_key_env: str = ""
    host_allowlist: tuple[str, ...] = ()
    allow_nonstandard_port: bool = False
    chain_id: int | None = None


CHAINS: dict[str, Chain] = {
    name: Chain(
        name,
        "evm",
        asset,
        "https://api.etherscan.io/v2/api",
        "CHINESCAN_ETHERSCAN_KEY",
        ("api.etherscan.io",),
        chain_id=chain_id,
    )
    for name, (asset, chain_id) in {
        "ethereum": ("ETH", 1),
        "bsc": ("BNB", 56),
        "polygon": ("POL", 137),
        "arbitrum": ("ETH", 42161),
        "optimism": ("ETH", 10),
        "base": ("ETH", 8453),
        "avalanche": ("AVAX", 43114),
    }.items()
}
CHAINS.update(
    {
        name: Chain(name, family, asset)
        for name, family, asset in (
            ("bitcoin", "utxo", "BTC"),
            ("tron", "tron", "TRX"),
            ("solana", "solana", "SOL"),
        )
    }
)


def load_registry(path: Path | None = None) -> dict[str, Chain]:
    chains = dict(CHAINS)
    if path:
        if path.suffix.lower() == ".toml":
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        else:
            raw = json.loads(path.read_text(encoding="utf-8"))
        entries = raw.get("chains", raw)
        for name, values in entries.items():
            chains[name.lower()] = Chain(
                name.lower(),
                values["family"],
                values["native_asset"],
                values.get("explorer_api", ""),
                values.get("api_key_env", ""),
                tuple(values.get("host_allowlist", ())),
                bool(values.get("allow_nonstandard_port", False)),
                int(values["chain_id"]) if values.get("chain_id") is not None else None,
            )
    return chains


def normalize_address(chain: Chain, address: str) -> str:
    value = address.strip()
    if chain.family == "evm":
        if not re.fullmatch(r"0x[a-fA-F0-9]{40}", value):
            raise ValueError("invalid EVM address")
        return value.lower()
    if chain.name == "bitcoin":
        if not re.fullmatch(
            r"(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})", value
        ):
            raise ValueError("invalid Bitcoin address")
        return value
    if chain.name == "tron":
        if not re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", value):
            raise ValueError("invalid Tron address")
        return value
    if chain.name == "solana":
        if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", value):
            raise ValueError("invalid Solana address")
        return value
    raise ValueError("address validation is not configured for this family")
