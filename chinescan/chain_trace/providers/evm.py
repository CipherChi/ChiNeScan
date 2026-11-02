"""Etherscan-family provider using an injected HTTP callable."""

import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode
from urllib.request import urlopen

from chinescan.chain_trace.providers.base import Page


class _JsonResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def json(self) -> dict[str, Any]:
        value = json.loads(self.payload)
        return value if isinstance(value, dict) else {}


def stdlib_http_get(url: str, *, params: dict[str, object]) -> _JsonResponse:
    """Minimal live HTTP adapter; callers must obtain explicit network consent first."""
    with urlopen(f"{url}?{urlencode(params)}", timeout=15) as response:  # noqa: S310
        return _JsonResponse(response.read(2_000_001))


class EvmProvider:
    name = "etherscan-family"

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        http_get: Callable[..., Any],
        chain: str = "ethereum",
    ) -> None:
        self.endpoint, self.api_key, self.http_get, self.chain = endpoint, api_key, http_get, chain

    def transfers(self, address: str, *, limit: int, cursor: str | None = None) -> Page:
        import time

        from chinescan.chain_trace.models import Transfer

        result = []
        for action in ("txlist", "txlistinternal", "tokentx"):
            response = self.http_get(
                self.endpoint,
                params={
                    "module": "account",
                    "action": action,
                    "address": address,
                    "page": int(cursor or 1),
                    "offset": limit,
                    "apikey": self.api_key,
                },
            )
            body = response.json()
            if (
                body.get("message") == "NOTOK"
                or "rate limit" in str(body.get("result", "")).lower()
            ):
                raise RuntimeError("rate_limited")
            for row in body.get("result", []):
                try:
                    result.append(
                        Transfer(
                            chain=self.chain,
                            tx_hash=row["hash"],
                            block_time=int(row["timeStamp"]),
                            sender=row.get("from"),
                            receiver=row.get("to", ""),
                            asset=row.get("tokenSymbol", "ETH"),
                            amount=__import__("decimal").Decimal(row.get("value", "0")),
                            kind="token"
                            if action == "tokentx"
                            else "internal"
                            if action == "txlistinternal"
                            else "transfer",
                        )
                    )
                except (KeyError, ValueError):
                    continue
            time.sleep(0.2)
        return Page(tuple(result[:limit]), len(result) >= limit)
