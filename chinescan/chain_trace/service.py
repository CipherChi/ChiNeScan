"""Audited chain trace orchestration and persistence."""

import hashlib
import uuid
from datetime import UTC, datetime

from chinescan.chain_trace.detectors import detect
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
        for lead in detect(edges, self.labels):
            txs = sorted(lead.transactions)
            fp = hashlib.sha256(
                f"{lead.rule_id}|{params.chain}|{'|'.join(txs)}".encode()
            ).hexdigest()
            findings.append(
                Finding(
                    title=f"{lead.rule_id}: {lead.detail}",
                    description=(
                        f"Heuristic lead ({lead.rule_id}); false positives may include exchanges, "
                        "custodians, and CoinJoin activity. This is not proof of attribution."
                    ),
                    severity=Severity.MEDIUM,
                    fingerprint=fp,
                    category=FindingCategory.THREAT_INTEL,
                    confidence=Confidence.LIKELY,
                    evidence=EvidenceKind.PATTERN_MATCH,
                    scanner="chain_trace",
                    rule_id=lead.rule_id,
                    location=f"chain:{params.chain}:{lead.address}"
                    if lead.address
                    else (txs[0] if txs else None),
                    tags=["heuristic", "chain_trace"],
                )
            )
        gaps = [
            CoverageGap(code=code, reason=code.replace("_", " "), source="chain_trace")
            for code in gap_codes
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
            status="complete",
            project_types=["chain", params.chain],
            finding_ids=[f.finding_id for f in findings],
            scan_options=scan.scan_options,
            coverage=report,
        )
        final.verdict = compute_verdict(final, findings)
        self.repository.save("scan", scan_id, final.model_dump(mode="json"))
        for finding in findings:
            self.repository.save("finding", finding.finding_id, finding.model_dump(mode="json"))
        self.repository.save(
            "chain_graph",
            scan_id,
            {
                "scan_id": scan_id,
                "chain": params.chain,
                "nodes": [{"address": n, "depth": 0} for n in nodes],
                "edges": [e.model_dump(mode="json") for e in edges],
            },
        )
        return final, findings
