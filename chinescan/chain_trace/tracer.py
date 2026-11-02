"""Breadth-first outgoing transaction collector with explicit coverage gaps."""

from collections import deque

from chinescan.chain_trace.models import Label, TraceParams, Transfer
from chinescan.chain_trace.providers.base import ChainProvider, UnsupportedFamily


def trace(
    provider: ChainProvider, params: TraceParams, labels: dict[tuple[str, str], Label]
) -> tuple[list[str], list[Transfer], list[str]]:
    queue = deque([(params.seed, 0)])
    visited: set[str] = set()
    edges: list[Transfer] = []
    gaps: list[str] = list(getattr(provider, "gaps", []))
    while queue:
        address, depth = queue.popleft()
        if address in visited:
            continue
        if len(visited) >= params.node_limit:
            gaps.append("node_limit")
            break
        visited.add(address)
        label = labels.get((params.chain, address.lower()))
        if depth and label and label.category in {"exchange", "bridge"}:
            gaps.append("skipped_high_volume")
            if label.category == "bridge":
                gaps.append("unresolved_bridge")
            continue
        if depth >= params.depth:
            gaps.append("depth_limit")
            continue
        try:
            page = provider.transfers(address, limit=params.per_wallet_limit)
        except UnsupportedFamily:
            gaps.append("unsupported_chain_family")
            continue
        except RuntimeError as exc:
            if str(exc) == "rate_limited":
                gaps.append("rate_limited")
                continue
            raise
        if page.truncated:
            gaps.append("truncated_history")
        selected = [
            e for e in page.transfers if e.sender == address and e.amount >= params.min_amount
        ]
        if len(selected) >= params.per_wallet_limit:
            gaps.append("per_wallet_limit")
        edges.extend(selected)
        for edge in selected:
            if edge.receiver not in visited:
                queue.append((edge.receiver, depth + 1))
    return list(visited), edges, gaps
