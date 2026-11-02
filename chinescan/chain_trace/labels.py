"""Local, provenance-bearing address labels."""

import csv
import json
from pathlib import Path

from chinescan.chain_trace.models import Label


def load_labels(paths: list[Path]) -> tuple[dict[tuple[str, str], Label], list[str]]:
    labels: dict[tuple[str, str], Label] = {}
    gaps: list[str] = []
    for path in paths:
        try:
            rows = (
                csv.DictReader(path.open(encoding="utf-8", newline=""))
                if path.suffix.lower() == ".csv"
                else json.loads(path.read_text(encoding="utf-8"))
            )
            if isinstance(rows, dict):
                rows = rows.get("labels", [])
            for row in rows:
                try:
                    label = Label(**row)
                    labels[(label.chain, label.address.lower())] = label
                except Exception:
                    gaps.append("label_row_invalid")
        except (OSError, ValueError):
            gaps.append("label_file_invalid")
    return labels, gaps
