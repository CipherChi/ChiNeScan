"""Explainable wallet behavior leads; every rule is heuristic."""

from collections import Counter, defaultdict
from dataclasses import dataclass

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
                    "Transfer to a locally labeled exchange",
                )
            )
        if label and label.category == "mixer":
            leads.append(
                Lead(
                    "mixer_exposure",
                    edge.receiver,
                    (edge.tx_hash,),
                    "Transfer to a locally labeled mixer",
                )
            )
        if label and label.category == "sanctioned":
            leads.append(
                Lead(
                    "sanctioned_exposure",
                    edge.receiver,
                    (edge.tx_hash,),
                    "Transfer to a locally listed sanctioned address",
                )
            )
    parents: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        if edge.sender:
            parents[edge.receiver].append(edge.sender)
    for wallet, funders in parents.items():
        if len(set(funders)) > 1:
            leads.append(
                Lead(
                    "first_funder",
                    wallet,
                    tuple(e.tx_hash for e in edges if e.receiver == wallet),
                    "Shared-funder heuristic",
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
        if any(edge.kind == "approval" for edge in deposits) and outgoing_edges:
            leads.append(
                Lead(
                    "drainer_pattern",
                    wallet,
                    (deposits[0].tx_hash, outgoing_edges[0].tx_hash),
                    "Approval followed by sweep heuristic",
                )
            )
    shared_funder_wallets = {
        wallet for wallet, funders in parents.items() if len(set(funders)) >= 2
    }
    if shared_funder_wallets:
        leads.append(
            Lead(
                "first_funder",
                next(iter(shared_funder_wallets)),
                tuple(e.tx_hash for e in edges if e.receiver in shared_funder_wallets),
                "Shared first-funder heuristic",
            )
        )
    return leads
