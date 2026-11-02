"""CLI commands for offline-first chain tracing."""

import json
import os
from pathlib import Path

import typer

from chinescan.chain_trace.export import export_graph
from chinescan.chain_trace.models import TraceParams
from chinescan.chain_trace.providers.base import UnsupportedFamily
from chinescan.chain_trace.providers.evm import EvmProvider, stdlib_http_get
from chinescan.chain_trace.providers.offline import OfflineProvider
from chinescan.chain_trace.registry import load_registry, normalize_address
from chinescan.chain_trace.service import ChainTraceService
from chinescan.core.config.settings import Settings
from chinescan.core.report_store import ReportStoreError, save_scan_reports
from chinescan.core.storage.sqlite import SQLiteRepository

app = typer.Typer(help="Offline-first on-chain wallet tracing.")


@app.command("trace")
def trace_command(
    address: str,
    chain: str = typer.Option(..., "--chain"),
    import_paths: list[Path] = typer.Option([], "--import"),  # noqa: B008
    label_paths: list[Path] = typer.Option([], "--label-file"),  # noqa: B008
    depth: int = typer.Option(3, min=1, max=6),
    min_amount: str = "0",
    allow_network_chain: bool = typer.Option(False, "--allow-network-chain"),
    no_save_report: bool = False,
    fail_on_gaps: bool = False,
) -> None:
    registry = load_registry()
    selected = registry.get(chain.lower())
    if selected is None:
        raise typer.BadParameter(f"unknown chain: {chain}")
    try:
        address = normalize_address(selected, address)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if not import_paths and not allow_network_chain:
        raise typer.BadParameter("provide --import or explicitly opt in with --allow-network-chain")
    provider = (
        OfflineProvider(
            import_paths[0].read_text(encoding="utf-8"),
            selected.name,
            import_paths[0].suffix.lstrip(".") or "csv",
        )
        if import_paths
        else EvmProvider(
            selected.explorer_api,
            os.getenv(selected.api_key_env, ""),
            stdlib_http_get,
            selected.name,
        )
    )
    from chinescan.chain_trace.labels import load_labels

    labels, label_gaps = load_labels(label_paths)
    settings = Settings(_env_file=None)
    repository = SQLiteRepository(settings.database_path)
    try:
        try:
            scan, findings = ChainTraceService(provider, labels, repository).trace(
                TraceParams(chain=selected.name, seed=address, depth=depth, min_amount=min_amount),
                authorization=allow_network_chain,
            )
        except (ValueError, UnsupportedFamily) as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(1) from exc
        if label_gaps:
            saved = repository.get("scan", scan.scan_id) or {}
            saved["status"] = "partial"
            repository.save("scan", scan.scan_id, saved)
        typer.echo(
            json.dumps(
                {"scan_id": scan.scan_id, "verdict": scan.verdict, "findings": len(findings)},
                default=str,
            )
        )
        if not no_save_report:
            try:
                save_scan_reports(repository, scan.scan_id, settings.reports_dir)
            except ReportStoreError as exc:
                typer.echo(f"Report warning: {exc}", err=True)
        if fail_on_gaps and scan.coverage and scan.coverage.gaps:
            raise typer.Exit(1)
    finally:
        repository.close()


@app.command("chains")
def chains_command() -> None:
    for name, item in load_registry().items():
        credential_state = (
            "configured" if item.api_key_env and os.getenv(item.api_key_env) else "offline"
        )
        typer.echo(f"{name}\t{item.family}\t{item.native_asset}\t{credential_state}")


@app.command("export")
def export_command(
    scan_id: str,
    format: str = typer.Option(..., "--format"),
    output: Path = typer.Option(..., "--output"),  # noqa: B008
) -> None:
    repository = SQLiteRepository(Settings(_env_file=None).database_path)
    try:
        graph = repository.get("chain_graph", scan_id)
        if graph is None:
            raise typer.BadParameter("chain scan was not found")
        output.write_text(export_graph(graph, format), encoding="utf-8")
    finally:
        repository.close()
