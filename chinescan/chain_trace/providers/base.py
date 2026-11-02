"""Provider protocol shared by live and imported transaction history."""

from dataclasses import dataclass
from typing import Protocol

from chinescan.chain_trace.models import Transfer


@dataclass(frozen=True)
class Page:
    transfers: tuple[Transfer, ...]
    truncated: bool = False
    next_cursor: str | None = None
    gaps: tuple[str, ...] = ()


class ChainProvider(Protocol):
    def transfers(self, address: str, *, limit: int, cursor: str | None = None) -> Page: ...


class UnsupportedFamily(RuntimeError):
    """No online provider exists for this address family."""
