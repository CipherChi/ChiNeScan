"""Explainable wallet behavior leads; every rule is heuristic."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from decimal import Decimal

from chinescan.chain_trace.models import Label, Transfer


@dataclass(frozen=True)
class Lead:
    rule_id: str
    address: str
    transactions: tuple[str, ...]
    detail: str


def detect(edges: list[Transfer], labels: dict[tuple[str, str], Label]) -> list[Lead]:
    leads: list[Lead] = []
    outgoing = Counter(e.sender for e in edges if e.sender)
    incoming = Counter(e.receiver for e in edges)
    if any(n >= 3 for n in outgoing.values()):
        leads.append(Lead("fan_out", "", tuple(e.tx_hash for e in edges), "Fan-out heuristic"))
    if any(n >= 3 for n in incoming.values()):
        leads.append(Lead("fan_in", "", tuple(e.tx_hash for e in edges), "Fan-in heuristic"))
    for edge in edges:
        label = labels.get((edge.chain, edge.receiver.lower()))
        if label and label.category == "exchange":
            leads.append(
                Lead(
                    "cash_out",
                    edge.receiver,
                    (edge.tx_hash,),
                    f"Transfer to locally labeled exchange {label.name} "
                    f"from {label.source} dated {label.date}",
                )
            )
        if label and label.category == "mixer":
            leads.append(
                Lead(
                    "mixer_exposure",
                    edge.receiver,
                    (edge.tx_hash,),
                    f"Transfer to locally labeled mixer {label.name} "
                    f"from {label.source} dated {label.date}",
                )
            )
        if label and label.category == "sanctioned":
            leads.append(
                Lead(
                    "sanctioned_exposure",
                    edge.receiver,
                    (edge.tx_hash,),
                    f"Transfer to locally listed sanctioned address {label.name} "
                    f"from {label.source} dated {label.date}",
                )
            )
    funder_wallets: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        if edge.sender:
            funder_wallets[edge.sender].add(edge.receiver)
    for funder, wallets in funder_wallets.items():
        if len(wallets) >= 2:
            leads.append(
                Lead(
                    "first_funder",
                    funder,
                    tuple(e.tx_hash for e in edges if e.sender == funder),
                    "Shared first-funder heuristic",
                )
            )
    by_sender: dict[str, list[Transfer]] = defaultdict(list)
    by_receiver: dict[str, list[Transfer]] = defaultdict(list)
    for edge in edges:
        if edge.sender:
            by_sender[edge.sender].append(edge)
        by_receiver[edge.receiver].append(edge)
    for wallet, deposits in by_receiver.items():
        outgoing_edges = by_sender.get(wallet, [])
        if len(deposits) == 1 and len(outgoing_edges) == 1:
            inbound, outbound = deposits[0], outgoing_edges[0]
            elapsed = outbound.block_time - inbound.block_time
            if 0 <= elapsed <= 3600:
                leads.append(
                    Lead(
                        "rapid_pass_through",
                        wallet,
                        (inbound.tx_hash, outbound.tx_hash),
                        "Rapid pass-through heuristic",
                    )
                )
            if elapsed > 0 and outbound.receiver.lower() != (inbound.sender or "").lower():
                leads.append(
                    Lead(
                        "peel_chain",
                        wallet,
                        (inbound.tx_hash, outbound.tx_hash),
                        "Peel-chain heuristic",
                    )
                )
    for approval in (edge for edge in edges if edge.kind == "approval" and edge.sender):
        sweeps = [
            edge
            for edge in edges
            if edge.sender == approval.sender
            and edge.kind != "approval"
            and edge.block_time > approval.block_time
        ]
        if sweeps:
            sweep = min(sweeps, key=lambda edge: edge.block_time)
            leads.append(
                Lead(
                    "drainer_pattern",
                    approval.sender or "",
                    (approval.tx_hash, sweep.tx_hash),
                    "Approval to a spender followed by a sweep heuristic",
                )
            )
    for edge in edges:
        source = edge.sender or ""
        target = edge.receiver
        if edge.amount <= Decimal("0.00000001") and len(source) >= 8 and len(target) >= 8:
            if (
                source[:4].lower() == target[:4].lower()
                or source[-4:].lower() == target[-4:].lower()
            ):
                leads.append(
                    Lead(
                        "address_poisoning",
                        target,
                        (edge.tx_hash,),
                        "Dust transfer to a lookalike address heuristic",
                    )
                )
    return leads
