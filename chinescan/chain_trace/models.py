"""Typed, immutable chain trace records."""

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", json_encoders={Decimal: str})


class Transfer(FrozenModel):
    chain: str
    tx_hash: str
    block_time: int
    sender: str | None = None
    receiver: str
    asset: str
    amount: Decimal
    kind: Literal["transfer", "internal", "token", "bridge", "approval"] = "transfer"
    inputs: tuple[str, ...] = ()
    meta: dict[str, object] = Field(default_factory=dict)


class Label(FrozenModel):
    address: str
    chain: str
    category: Literal["exchange", "mixer", "bridge", "router", "sanctioned", "scam", "other"]
    name: str
    source: str = Field(min_length=1)
    date: str = Field(min_length=1)


class TraceParams(FrozenModel):
    chain: str
    seed: str
    depth: int = Field(default=3, ge=1, le=6)
    min_amount: Decimal = Decimal("0")
    per_wallet_limit: int = Field(default=100, ge=1, le=5000)
    node_limit: int = Field(default=500, ge=1, le=5000)
