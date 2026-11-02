"""Portable chain graph and indicator exports."""

import csv
import json
from io import StringIO
from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring


def export_graph(graph: dict[str, Any], fmt: str) -> str:
    if fmt == "graph-json":
        return json.dumps(graph, indent=2, default=str)
    if fmt == "indicators":
        return json.dumps(
            {
                "indicators": [
                    {"kind": "wallet_address", "value": node["address"]}
                    for node in graph.get("nodes", [])
                ]
            },
            indent=2,
        )
    if fmt == "transfers-csv":
        out = StringIO()
        fields = ["chain", "tx_hash", "block_time", "sender", "receiver", "asset", "amount", "kind"]
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        writer.writerows({k: edge.get(k, "") for k in fields} for edge in graph.get("edges", []))
        return out.getvalue()
    root = Element("graphml")
    graph_el = SubElement(root, "graph", edgedefault="directed")
    for node in graph.get("nodes", []):
        SubElement(graph_el, "node", id=node["address"])
    for index, edge in enumerate(graph.get("edges", [])):
        SubElement(
            graph_el,
            "edge",
            id=str(index),
            source=edge.get("sender") or "unknown",
            target=edge["receiver"],
        )
    return tostring(root, encoding="unicode")
