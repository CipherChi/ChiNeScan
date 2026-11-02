"""Audited chain trace orchestration and persistence."""

import hashlib
import uuid
from collections import defaultdict
from datetime import UTC, datetime

from chinescan.chain_trace.detectors import Lead, detect
from chinescan.chain_trace.models import Label, TraceParams
from chinescan.chain_trace.providers.base import ChainProvider
from chinescan.chain_trace.tracer import trace
from chinescan.core.models.common import Confidence, EvidenceKind, FindingCategory, Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import (
    AuthorizationRecord,
    CoverageGap,
    CoverageReport,
    Scan,
    Target,
)
from chinescan.core.storage.repository import Repository
from chinescan.core.verdict import compute_verdict

_WALLET_LEVEL_RULES = {
    "fan_out",
    "fan_in",
    "first_funder",
    "peel_chain",
    "rapid_pass_through",
    "address_poisoning",
    "drainer_pattern",
}


class ChainTraceService:
    def __init__(
        self, provider: ChainProvider, labels: dict[tuple[str, str], Label], repository: Repository
    ) -> None:
        self.provider, self.labels, self.repository = provider, labels, repository

    def trace(self, params: TraceParams, authorization: bool) -> tuple[Scan, list[Finding]]:
        is_offline = bool(getattr(self.provider, "offline", False))
        if not authorization and not is_offline:
            raise ValueError("explicit network authorization is required")
        started = datetime.now(UTC)
        scan_id = str(uuid.uuid4())
        target_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"chain:{params.chain}:{params.seed}"))
        target = Target(value=params.seed, kind="wallet")
        audit = AuthorizationRecord(
            target=params.seed,
            method="local_explorer_import" if is_offline else "explicit_chain_network_opt_in",
            operator="local operator",
            authorized_at=started,
            scan_profile="chain_trace",
            scan_id=scan_id,
        )
        scan = Scan(
            scan_id=scan_id,
            target_id=target_id,
            scanner="chain_trace",
            started_at=started,
            status="running",
            project_types=["chain", params.chain],
            scan_options={"chain": params.chain, "depth": params.depth, "network": not is_offline},
        )
        self.repository.save("target", target_id, target.model_dump(mode="json"))
        self.repository.save(
            "authorization_record", audit.authorization_id, audit.model_dump(mode="json")
        )
        self.repository.save("scan", scan_id, scan.model_dump(mode="json"))
        try:
            nodes, edges, gap_codes = trace(self.provider, params, self.labels)
        except Exception:
            nodes, edges, gap_codes = [params.seed], [], ["provider_failure"]
        findings = []
        findings = [
            finding_for_lead(params, lead)
            for lead in detect(edges, self.labels, seed=params.seed)
        ]
        gap_reasons: dict[str, list[str]] = defaultdict(list)
        for gap in gap_codes:
            code, separator, detail = gap.partition(":")
            reason = detail if code == "provider_error" and separator else code.replace("_", " ")
            gap_reasons[code].append(reason)
        gaps = [
            CoverageGap(
                code=code,
                reason=reasons[0],
                count=len(reasons),
                source="chain_trace",
                example=f"chain-trace-{code.replace('_', '-')}",
            )
            for code, reasons in gap_reasons.items()
        ]
        report = CoverageReport(
            examined={
                "wallets": len(nodes),
                "transfers": len(edges),
                "labels_loaded": len(self.labels),
            },
            gaps=gaps,
        )
        if len(edges) > 5000:
            edges = edges[:5000]
            report.gaps.append(CoverageGap(code="edge_cap", reason="Graph limited to 5000 edges"))
        final = Scan(
            scan_id=scan_id,
            target_id=target_id,
            scanner="chain_trace",
            started_at=started,
            finished_at=datetime.now(UTC),
            status="partial" if gap_codes else "complete",
            project_types=["chain", params.chain],
            finding_ids=[f.finding_id for f in findings],
            scan_options=scan.scan_options,
            coverage=report,
        )
        final.verdict = compute_verdict(final, findings)
        self.repository.save("scan", scan_id, final.model_dump(mode="json"))
        for finding in findings:
            self.repository.save("finding", finding.finding_id, finding.model_dump(mode="json"))
        depths = {params.seed: 0}
        for _ in range(params.depth):
            for edge in edges:
                if edge.sender in depths:
                    depths.setdefault(edge.receiver, depths[edge.sender] + 1)
        graph_nodes = []
        for address in nodes:
            item: dict[str, object] = {
                "address": address,
                "depth": depths.get(address, params.depth),
            }
            label = self.labels.get((params.chain, address.lower()))
            if label:
                item["label"] = label.model_dump(mode="json")
            graph_nodes.append(item)
        self.repository.save(
            "chain_graph",
            scan_id,
            {
                "scan_id": scan_id,
                "chain": params.chain,
                "nodes": graph_nodes,
                "edges": [e.model_dump(mode="json") for e in edges],
                "findings": [
                    {
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "rule_id": f.rule_id,
                        "location": f.location,
                        "evidence": f.evidence.value if f.evidence else None,
                        "confidence": f.confidence.value,
                    }
                    for f in findings
                ],
            },
        )
        return final, findings


def finding_for_lead(params: TraceParams, lead: Lead) -> Finding:
    txs = sorted(set(lead.transactions))
    fingerprint = hashlib.sha256(
        f"{lead.rule_id}|{params.chain}|{'|'.join(txs)}".encode()
    ).hexdigest()
    supporting = ", ".join(txs[:10]) or "none recorded"
    if lead.rule_id in {"cash_out", "mixer_exposure", "sanctioned_exposure"}:
        description = (
            f"Label reference lead ({lead.rule_id}); {lead.detail}. "
            f"Supporting transaction hashes (up to 10): {supporting}. "
            "Labels may be stale or incorrect. False positives include exchange and "
            "custodian labeling mistakes or CoinJoin context. This is not proof of attribution."
        )
    else:
        description = (
            f"Heuristic lead ({lead.rule_id}); trigger: {lead.detail}. "
            f"Supporting transaction hashes (up to 10): {supporting}. {lead.context} "
            "False positives may include exchanges, "
            "custodians, and CoinJoin activity. This is not proof of attribution."
        )
    severity = (
        Severity.LOW
        if lead.rule_id
        in {"fan_out", "fan_in", "first_funder", "peel_chain", "rapid_pass_through"}
        else Severity.HIGH
        if lead.rule_id == "sanctioned_exposure"
        else Severity.MEDIUM
    )
    if lead.context and severity == Severity.MEDIUM:
        severity = Severity.LOW
    confidence = Confidence.POSSIBLE if lead.context else Confidence.LIKELY
    return Finding(
        title=f"{lead.rule_id}: {lead.detail}",
        description=description,
        severity=severity,
        fingerprint=fingerprint,
        category=FindingCategory.THREAT_INTEL,
        confidence=confidence,
        evidence=(
            EvidenceKind.CONFIRMED_ARTIFACT
            if lead.rule_id == "sanctioned_exposure"
            else EvidenceKind.REFERENCE_ONLY
            if lead.rule_id in {"cash_out", "mixer_exposure"}
            else EvidenceKind.PATTERN_MATCH
        ),
        scanner="chain_trace",
        rule_id=lead.rule_id,
        location=(
            f"chain:{params.chain}:{lead.address or params.seed}"
            if lead.rule_id in _WALLET_LEVEL_RULES
            else f"chain:{params.chain}:{lead.address}"
            if lead.address
            else (txs[0] if txs else None)
        ),
        tags=["heuristic", "chain_trace"],
    )
