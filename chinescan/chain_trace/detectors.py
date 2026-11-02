"""Explainable wallet behavior leads; every rule is heuristic."""

from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal

from chinescan.chain_trace.models import Label, Transfer


@dataclass(frozen=True)
class Lead:
    rule_id: str
    address: str
    transactions: tuple[str, ...]
    detail: str
    context: str = ""


def _context(labels: dict[tuple[str, str], Label], chain: str, addresses: list[str]) -> str:
    notes = []
    for address in dict.fromkeys(addresses):
        label = labels.get((chain, address.lower()))
        if label and (
            label.category in {"exchange", "bridge", "router"}
            or "router" in label.name.casefold()
        ):
            notes.append(
                f"{label.category} label '{label.name}' from {label.source} dated {label.date}"
            )
    if not notes:
        return ""
    return (
        " Labeled counterparty context: "
        + "; ".join(notes[:5])
        + ". Exchange, bridge, or router service activity can produce this pattern, so interpret "
        "the heuristic with reduced weight."
    )


def _lead(
    rule_id: str,
    address: str,
    transactions: tuple[str, ...],
    detail: str,
    labels: dict[tuple[str, str], Label],
    chain: str,
    counterparties: list[str],
) -> Lead:
    return Lead(rule_id, address, transactions, detail, _context(labels, chain, counterparties))


def detect(
    edges: list[Transfer], labels: dict[tuple[str, str], Label], *, seed: str | None = None
) -> list[Lead]:
    leads: list[Lead] = []
    outgoing: dict[str, list[Transfer]] = defaultdict(list)
    incoming: dict[str, list[Transfer]] = defaultdict(list)
    for edge in edges:
        if edge.sender:
            outgoing[edge.sender].append(edge)
        incoming[edge.receiver].append(edge)

    for sender, transfers in outgoing.items():
        counterparties = list(dict.fromkeys(edge.receiver for edge in transfers))
        if len(counterparties) >= 3:
            leads.append(
                _lead(
                    "fan_out",
                    sender,
                    tuple(edge.tx_hash for edge in transfers),
                    f"{len(counterparties)} distinct outgoing counterparties (threshold >= 3)",
                    labels,
                    transfers[0].chain,
                    counterparties,
                )
            )

    for receiver, transfers in incoming.items():
        counterparties = list(dict.fromkeys(edge.sender for edge in transfers if edge.sender))
        if len(counterparties) >= 3:
            leads.append(
                _lead(
                    "fan_in",
                    receiver,
                    tuple(edge.tx_hash for edge in transfers),
                    f"{len(counterparties)} distinct incoming counterparties (threshold >= 3)",
                    labels,
                    transfers[0].chain,
                    counterparties,
                )
            )

    for edge in edges:
        label = labels.get((edge.chain, edge.receiver.lower()))
        if label and label.category in {"exchange", "mixer", "sanctioned"}:
            rule = {
                "exchange": "cash_out",
                "mixer": "mixer_exposure",
                "sanctioned": "sanctioned_exposure",
            }[label.category]
            leads.append(
                Lead(
                    rule,
                    edge.receiver,
                    (edge.tx_hash,),
                    f"Transfer to locally listed {label.category} label {label.name} "
                    f"from {label.source} dated {label.date}",
                )
            )

    funder_wallets: dict[str, list[Transfer]] = defaultdict(list)
    for edge in edges:
        if edge.sender:
            funder_wallets[edge.sender].append(edge)
    for funder, transfers in funder_wallets.items():
        wallets = list(dict.fromkeys(edge.receiver for edge in transfers))
        if len(wallets) >= 2 and funder.lower() != (seed or "").lower():
            leads.append(
                _lead(
                    "first_funder",
                    funder,
                    tuple(edge.tx_hash for edge in transfers),
                    f"Shared first-funder pattern across {len(wallets)} recipient wallets "
                    "(threshold >= 2)",
                    labels,
                    transfers[0].chain,
                    wallets,
                )
            )

    for wallet, deposits in incoming.items():
        outgoing_edges = outgoing.get(wallet, [])
        if len(deposits) != 1 or len(outgoing_edges) != 1:
            continue
        inbound, outbound = deposits[0], outgoing_edges[0]
        elapsed = outbound.block_time - inbound.block_time
        counterparties = [inbound.sender or "", outbound.receiver]
        if 0 <= elapsed <= 3600:
            leads.append(
                _lead(
                    "rapid_pass_through",
                    wallet,
                    (inbound.tx_hash, outbound.tx_hash),
                    f"Exactly 1 inbound and 1 outbound transfer; elapsed {elapsed} seconds "
                    "(window <= 3600 seconds)",
                    labels,
                    inbound.chain,
                    counterparties,
                )
            )
        if elapsed > 0 and outbound.receiver.lower() != (inbound.sender or "").lower():
            leads.append(
                _lead(
                    "peel_chain",
                    wallet,
                    (inbound.tx_hash, outbound.tx_hash),
                    f"Exactly 1 inbound and 1 outbound transfer; elapsed {elapsed} seconds "
                    "(threshold > 0 seconds) with a different destination",
                    labels,
                    inbound.chain,
                    counterparties,
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
            elapsed = sweep.block_time - approval.block_time
            leads.append(
                _lead(
                    "drainer_pattern",
                    approval.sender or "",
                    (approval.tx_hash, sweep.tx_hash),
                    f"Approval followed by a sweep after {elapsed} seconds (threshold > 0 seconds)",
                    labels,
                    approval.chain,
                    [approval.receiver, sweep.receiver],
                )
            )

    for edge in edges:
        source = edge.sender or ""
        target = edge.receiver
        if edge.amount <= Decimal("0.00000001") and len(source) >= 8 and len(target) >= 8:
            prefix_match = source[:4].lower() == target[:4].lower()
            suffix_match = source[-4:].lower() == target[-4:].lower()
            if prefix_match or suffix_match:
                shared = "first" if prefix_match else "last"
                leads.append(
                    _lead(
                        "address_poisoning",
                        target,
                        (edge.tx_hash,),
                        f"Dust amount {edge.amount} <= 0.00000001 threshold with matching "
                        f"{shared} 4 address characters",
                        labels,
                        edge.chain,
                        [source, target],
                    )
                )
    return leads
