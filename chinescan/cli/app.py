"""Typer application entry point."""

from pathlib import Path

import typer

from chinescan.cli import commands
from chinescan.cli.chain_commands import app as chain_app

app = typer.Typer(help="Authorization-first security investigation platform.")


@app.callback()
def configure(
    config: Path | None = typer.Option(  # noqa: B008
        None, "--config", help="Local TOML configuration file."
    ),
    database: Path | None = typer.Option(  # noqa: B008
        None, "--database", help="Local SQLite database path."
    ),
    reports_dir: Path | None = typer.Option(  # noqa: B008
        None, "--reports-dir", help="Local report directory."
    ),
) -> None:
    """Choose local configuration inputs; explicit options override environment and file."""
    commands.configure_settings(config, database, reports_dir)


app.command("version")(commands.version)
app.command("doctor")(commands.doctor)
app.command("status")(commands.status)
app.add_typer(commands.config_app, name="config")
app.command("code")(commands.code_scan)
app.command("logs")(commands.logs_ingest)


@app.command("scan")
def scan_stub() -> None:
    """Run a scan (Phase 3)."""
    commands.not_implemented(3, "scan")


app.command("report")(commands.report)
app.command("compare")(commands.compare_scans)
app.command("trends")(commands.scan_trends)
app.add_typer(commands.case_app, name="case")
app.add_typer(commands.db_app, name="db")

malware_app = typer.Typer(help="Non-executing local malware static triage.")
malware_app.command("analyze")(commands.malware_analyze)


@malware_app.command("memory")
def malware_memory_stub(
    image: str = typer.Argument(..., help="Local memory image path (analysis is not implemented)."),
) -> None:
    """Run optional memory-image triage (not implemented)."""
    del image
    commands.not_implemented(5, "malware memory")


@malware_app.command("detonate")
def malware_detonate_stub(
    sample: str = typer.Argument(..., help="Sample path (sandbox detonation is not implemented)."),
) -> None:
    """Run dynamic analysis in a configured isolated sandbox (not implemented)."""
    del sample
    commands.not_implemented(5, "malware detonate")


app.add_typer(malware_app, name="malware")

app.command("domain")(commands.domain_assess)
app.add_typer(chain_app, name="chain")
app.add_typer(commands.web_app, name="web")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
app.add_typer(commands.fs_app, name="fs")
app.add_typer(commands.projects_app, name="projects")

github_app = typer.Typer(help="Public GitHub import (disabled unless configured).")
github_app.command("preview")(commands.github_preview)
github_app.command("import")(commands.github_import)
github_app.command("status")(commands.github_status)
github_app.command("cancel")(commands.github_cancel)
app.add_typer(github_app, name="github")
