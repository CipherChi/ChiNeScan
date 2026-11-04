"""Tests for persisted report rendering and case workflows."""

import csv
import html
import io
import json

from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.models.common import Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Scan
from chinescan.core.reporting import render_report

runner = CliRunner()


def sample_scan() -> tuple[Scan, list[Finding]]:
    scan = Scan(
        scan_id="scan-1",
        target_id="target-1",
        scanner="builtin",
        started_at="2026-01-01T00:00:00Z",
        finding_ids=["finding-1"],
    )
    finding = Finding(
        finding_id="finding-1",
        title="<script>alert(1)</script>",
        description="token=topsecret",
        severity=Severity.HIGH,
        fingerprint="abc123",
        rule_id="TEST-RULE",
        location="src/app.py:7",
    )
    return scan, [finding]


def test_render_all_formats_redacts_and_escapes() -> None:
    scan, findings = sample_scan()
    assert "[REDACTED]" in render_report(scan, findings, "json")
    markdown = render_report(scan, findings, "markdown")
    assert "REDACTED" in markdown
    assert "topsecret" not in markdown
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markdown
    html_report = render_report(scan, findings, "html")
    assert html.escape("<script>alert(1)</script>") in html_report
    assert "<script>" not in html_report
    rows = list(csv.DictReader(io.StringIO(render_report(scan, findings, "csv"))))
    assert rows[0]["rule_id"] == "TEST-RULE"
    sarif = json.loads(render_report(scan, findings, "sarif"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "TEST-RULE"
    assert "[REDACTED]" in sarif["runs"][0]["results"][0]["message"]["text"]


def test_csv_neutralizes_spreadsheet_formulas() -> None:
    scan, findings = sample_scan()
    finding = findings[0].model_copy(
        update={"title": "=1+1", "description": '\t=HYPERLINK("https://example.invalid")'}
    )
    rows = list(csv.DictReader(io.StringIO(render_report(scan, [finding], "csv"))))
    assert rows[0]["title"] == "'=1+1"
    assert rows[0]["description"].startswith("'\t=")


def test_case_create_show_update_and_compare(tmp_path, monkeypatch) -> None:
    database = tmp_path / "cases.sqlite3"
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(database))
    scan, findings = sample_scan()
    from chinescan.core.storage.sqlite import SQLiteRepository

    repository = SQLiteRepository(database)
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    repository.save("finding", findings[0].finding_id, findings[0].model_dump(mode="json"))
    later = scan.model_copy(update={"scan_id": "scan-2"})
    repository.save("scan", later.scan_id, later.model_dump(mode="json"))
    repository.close()

    created = runner.invoke(app, ["case", "create", "--from-scan", "scan-1"])
    assert created.exit_code == 0, created.output
    case_id = created.stdout.split()[2]
    shown = runner.invoke(app, ["case", "show", case_id])
    assert shown.exit_code == 0
    assert json.loads(shown.stdout)["finding_ids"] == ["finding-1"]
    updated = runner.invoke(app, ["case", "update", case_id, "--status", "in_progress"])
    assert updated.exit_code == 0, updated.output
    compared = runner.invoke(app, ["compare", "scan-1", "scan-2"])
    assert compared.exit_code == 0, compared.output
    assert json.loads(compared.stdout)["unchanged"] == ["abc123"]
