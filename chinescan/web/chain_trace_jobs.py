"""Small persistent worker queue for chain trace jobs."""

import os
import threading
import uuid
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chinescan.chain_trace.labels import load_labels
from chinescan.chain_trace.models import TraceParams
from chinescan.chain_trace.providers.base import ChainProvider, Page, UnsupportedFamily
from chinescan.chain_trace.providers.evm import EvmProvider, stdlib_http_get
from chinescan.chain_trace.providers.offline import OfflineProvider
from chinescan.chain_trace.registry import load_registry, normalize_address
from chinescan.chain_trace.service import ChainTraceService
from chinescan.core.storage.sqlite import SQLiteRepository


class ChainTraceJobManager:
    def __init__(self, repository: SQLiteRepository, settings: Any) -> None:
        self.repository, self.settings = repository, settings
        self.lock = threading.RLock()
        self.condition = threading.Condition(self.lock)
        self.queue: deque[str] = deque()
        self.thread: threading.Thread | None = None
        self.stop_requested = False

    def start(self) -> None:
        for row in self.repository.list_records("chain_job"):
            if row.get("status") in {"queued", "running"}:
                row.update(status="interrupted", error="Server restarted.")
                self.repository.save("chain_job", row["job_id"], row)
        self.thread = threading.Thread(target=self.run, daemon=True, name="chinescan-chain-jobs")
        self.thread.start()

    def stop(self) -> None:
        with self.condition:
            self.stop_requested = True
            self.condition.notify_all()
        if self.thread:
            self.thread.join()

    def submit(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self.condition:
            if len(self.queue) >= 4:
                raise OverflowError
            item = {
                "job_id": str(uuid.uuid4()),
                "status": "queued",
                "created_at": datetime.now(UTC).isoformat(),
                "scan_id": None,
                "error": None,
                **payload,
            }
            self.repository.save("chain_job", item["job_id"], item)
            self.queue.append(item["job_id"])
            self.condition.notify()
            return item

    def get(self, job_id: str) -> dict[str, Any] | None:
        return self.repository.get("chain_job", job_id)

    def list(self, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        rows = sorted(
            self.repository.list_records("chain_job"), key=lambda x: x["created_at"], reverse=True
        )
        return rows[offset : offset + limit], len(rows)

    def run(self) -> None:
        while True:
            with self.condition:
                while not self.queue and not self.stop_requested:
                    self.condition.wait()
                if self.stop_requested:
                    return
                job_id = self.queue.popleft()
            job = self.get(job_id)
            if job is None or job.get("status") != "queued":
                continue
            try:
                job["status"] = "running"
                self.repository.save("chain_job", job_id, job)
                chain = load_registry()[job["chain"]]
                address = normalize_address(chain, job["address"])
                provider: ChainProvider
                if job.get("import_text"):
                    provider = OfflineProvider(job["import_text"], chain.name, job["import_format"])
                elif chain.family == "evm":
                    provider = EvmProvider(
                        chain.explorer_api,
                        os.getenv(chain.api_key_env, ""),
                        stdlib_http_get,
                        chain.name,
                        allowed_hosts=chain.host_allowlist,
                        allow_nonstandard_port=chain.allow_nonstandard_port,
                        chain_id=chain.chain_id,
                        deadline_seconds=self.settings.chain_trace_deadline_seconds,
                        max_requests=self.settings.chain_trace_max_requests,
                    )
                else:
                    provider = _UnsupportedProvider()
                label_paths = (
                    [Path(self.settings.chain_labels_path)]
                    if self.settings.chain_labels_path
                    else []
                )
                labels, label_gaps = load_labels(label_paths)
                scan, _findings = ChainTraceService(
                    provider, labels, self.repository, label_gaps
                ).trace(
                    TraceParams(
                        chain=chain.name,
                        seed=address,
                        depth=job["depth"],
                        min_amount=job["min_amount"],
                        node_limit=self.settings.chain_trace_max_addresses,
                    ),
                    authorization=job["allow_network"],
                )
                provider_failed = bool(
                    scan.coverage
                    and any(gap.code == "provider_failure" for gap in scan.coverage.gaps)
                )
                job.update(
                    status="failed" if provider_failed else "succeeded",
                    scan_id=scan.scan_id,
                    error="The chain provider failed; see scan coverage."
                    if provider_failed
                    else None,
                )
            except Exception:
                job.update(
                    status="failed",
                    error="Chain tracing failed; inspect the local scan coverage records.",
                )
            self.repository.save("chain_job", job_id, job)


class _OfflineEmptyProvider:
    def transfers(self, address: str, *, limit: int, cursor: str | None = None) -> Page:
        return Page(())


class _UnsupportedProvider:
    def transfers(self, address: str, *, limit: int, cursor: str | None = None) -> Page:
        raise UnsupportedFamily("online provider is not implemented for this chain family")
