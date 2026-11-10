"""Tests for persisted report rendering and case workflows."""

import csv
import html
import io
import json

import pytest
from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.models.common import Confidence, FindingVerdict, Severity
from chinescan.core.models.finding import Finding, FindingExplanation
from chinescan.core.models.investigation import (
    CodeAssessmentSummary,
    CoverageReport,
    Scan,
    ScoreContribution,
    VibeCodingRisk,
)
from chinescan.core.reporting import ReportingError, iter_scan_findings_jsonl, render_report
from chinescan.core.storage.sqlite import SQLiteRepository

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
        verdict=FindingVerdict.LIKELY,
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


def test_reporter_uses_native_worker_when_available_and_falls_back(monkeypatch) -> None:
    import chinescan.core.reporting as reporting

    scan, findings = sample_scan()
    observed: dict[str, object] = {}

    def native(request: dict[str, object]) -> str:
        observed.update(request)
        return "native report"

    monkeypatch.setattr(reporting, "render_native_report", native)
    assert reporting.render_report(scan, findings, "markdown") == "native report"
    assert observed["format"] == "markdown"
    metadata = observed["metadata"]
    assert isinstance(metadata, dict)
    assert (
        "Complete language coverage and comprehensive vulnerability analysis"
        in metadata["not_assessed"]
    )

    monkeypatch.setattr(reporting, "render_native_report", lambda _request: None)
    assert "# ChiNeScan report" in reporting.render_report(scan, findings, "markdown")


def test_detached_report_signing_and_key_permission_checks(tmp_path, monkeypatch) -> None:
    import importlib.util
    import os
    import subprocess

    from chinescan.core.native_reporting import (
        ReportSigningError,
        report_public_key,
        sign_report_detached,
        verify_report_detached,
    )

    key_file = tmp_path / "report-signing.seed"
    key_file.write_bytes(bytes(range(32)))
    if os.name != "nt":
        key_file.chmod(0o600)
    else:
        identity = (
            subprocess.run(
                ["whoami.exe", "/user", "/fo", "csv", "/nh"],
                capture_output=True,
                text=True,
                check=True,
            )
            .stdout.strip()
            .strip('"')
            .split('","')[-1]
        )
        subprocess.run(
            [
                "icacls.exe",
                str(key_file),
                "/inheritance:r",
                "/grant:r",
                f"*{identity}:(F)",
                "*S-1-5-18:(F)",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    if importlib.util.find_spec("chinescan_engine") is None:
        pytest.skip("native reporter extension is unavailable")
    report = '{"scan":"local"}'
    signature = sign_report_detached(report, key_file)
    public_key = report_public_key(key_file)
    assert verify_report_detached(report, signature, public_key)
    assert not verify_report_detached(report + "!", signature, public_key)
    wrong_key = report_public_key_for_seed(bytes(reversed(range(32))))
    assert not verify_report_detached(report, signature, wrong_key)

    if os.name != "nt":
        key_file.chmod(0o644)
        with pytest.raises(ReportSigningError, match="too permissive"):
            sign_report_detached(report, key_file)
    else:
        subprocess.run(
            ["icacls.exe", str(key_file), "/grant", "*S-1-1-0:(R)"],
            capture_output=True,
            text=True,
            check=True,
        )
        with pytest.raises(ReportSigningError, match="too permissive"):
            sign_report_detached(report, key_file)
    with pytest.raises(ReportSigningError, match="missing"):
        sign_report_detached(report, tmp_path / "missing.seed")


def report_public_key_for_seed(seed: bytes) -> str:
    import chinescan_engine

    return chinescan_engine.report_public_key(seed).hex()


def test_full_json_export_is_complete_and_records_provenance() -> None:
    scan, findings = sample_scan()
    payload = json.loads(render_report(scan, findings, "full-json"))
    assert payload["summary"]["total_findings"] == 1
    assert payload["summary"]["returned_findings"] == 1
    assert payload["summary"]["omitted_findings"] == 0
    assert payload["summary"]["report_truncated"] is False
    assert payload["provenance"]["product_version"]
    assert payload["findings"][0]["finding_id"] == findings[0].finding_id


def test_code_preview_labels_counts_and_no_omissions() -> None:
    scan, findings = sample_scan()
    scan = scan.model_copy(update={"code_assessment": CodeAssessmentSummary()})
    payload = json.loads(render_report(scan, findings, "json"))
    assert payload["summary"]["total_stored_findings"] == 1
    assert payload["summary"]["available_finding_records"] == 1
    assert payload["summary"]["grouped_issue_total"] == payload["summary"]["grouped_findings"]
    assert payload["summary"]["returned_grouped_findings"] == 1
    assert payload["summary"]["processing_failure_count"] == 0
    assert payload["report_truncated"] is False
    assert payload["report_omissions"]["omitted_preview_groups"] == 0
    assert payload["report_omissions"]["omitted_preview_occurrences"] == 0


def test_code_preview_counts_grouped_occurrences() -> None:
    scan, findings = sample_scan()
    scan = scan.model_copy(update={"code_assessment": CodeAssessmentSummary()})
    first = findings[0].model_copy(
        update={"finding_id": "first", "rule_id": "SAME", "location": "src/app.py:4"}
    )
    second = findings[0].model_copy(
        update={"finding_id": "second", "rule_id": "SAME", "location": "src/app.py:9"}
    )
    payload = json.loads(render_report(scan, [first, second], "json"))
    groups = payload["likely_real_issues"] + payload["leads"] + payload["manual_review"]
    same_rule_groups = [item for item in groups if item["rule_id"] == "SAME"]
    assert len(same_rule_groups) == 1
    assert same_rule_groups[0]["occurrence_count"] == 2


def test_code_report_separates_leads_and_excludes_them_from_issue_counts() -> None:
    scan, findings = sample_scan()
    scan = scan.model_copy(update={"code_assessment": CodeAssessmentSummary()})
    lead = findings[0].model_copy(update={"verdict": FindingVerdict.LEAD})
    payload = json.loads(render_report(scan, [lead], "json"))
    assert payload["summary"]["issue_count"] == 0
    assert payload["summary"]["lead_count"] == 1
    assert payload["summary"]["counts_by_verdict"] == {
        "confirmed": 0,
        "likely": 0,
        "lead": 1,
    }
    assert payload["likely_real_issues"] == []
    assert len(payload["leads"]) == 1
    assert payload["fix_first"] == []


def test_generic_language_coverage_gap_is_near_the_report_top() -> None:
    scan, findings = sample_scan()
    scan = scan.model_copy(
        update={
            "code_assessment": CodeAssessmentSummary(),
            "coverage": CoverageReport(
                language_analyzer_status={
                    "Dart": "Dart checks; generic first-pass only for other risks"
                }
            ),
        }
    )
    report = render_report(scan, findings, "detail")
    assert "## Coverage gaps at a glance" in report
    assert "Dart: Dart checks; generic first-pass only for other risks" in report
    assert report.index("## Coverage gaps at a glance") < report.index("## Fix first")


def test_jsonl_iterator_retrieves_more_than_legacy_cap_exactly_once(tmp_path) -> None:
    total = 10_005
    repository = SQLiteRepository(tmp_path / "large.sqlite3")
    scan = Scan(
        scan_id="large-scan",
        target_id="local",
        scanner="builtin",
        started_at="2026-01-01T00:00:00Z",
        finding_ids=[f"f-{index:05d}" for index in range(total)],
    )
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    for start in range(0, total, 100):
        batch = []
        for index in range(start, min(start + 100, total)):
            finding = Finding(
                finding_id=f"f-{index:05d}",
                title=f"Synthetic {index}",
                severity=Severity.LOW,
                fingerprint=f"fp-{index}",
            )
            batch.append(("finding", finding.finding_id, finding.model_dump(mode="json")))
        repository.save_many(batch)
    lines = iter_scan_findings_jsonl(repository, scan.scan_id)
    manifest = json.loads(next(lines))
    assert manifest["total_findings"] == total
    import hashlib

    digest = hashlib.sha256()
    ids = []
    for line in lines:
        row = json.loads(line)
        if row["type"] == "complete":
            assert row["returned_findings"] == total
            assert row["sha256"] == digest.hexdigest()
            break
        assert row["type"] == "finding"
        digest.update(line.encode("utf-8"))
        ids.append(row["finding"]["finding_id"])
    else:
        pytest.fail("JSONL stream lacked its completion record")
    assert ids == scan.finding_ids
    assert len(ids) == len(set(ids)) == total
    repository.close()


def test_jsonl_iterator_streams_beyond_legacy_byte_cap_with_bounded_records(tmp_path) -> None:
    import hashlib

    total = 23
    repository = SQLiteRepository(tmp_path / "large-bytes.sqlite3")
    scan = Scan(
        scan_id="large-bytes-scan",
        target_id="local",
        scanner="builtin",
        started_at="2026-01-01T00:00:00Z",
        finding_ids=[f"byte-f-{index:02d}" for index in range(total)],
    )
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    large_text = "x" * 999_000
    repository.save_many(
        [
            (
                "finding",
                finding_id,
                Finding(
                    finding_id=f"byte-f-{index:02d}",
                    title=f"Synthetic {index}",
                    description=large_text,
                    severity=Severity.LOW,
                    fingerprint=f"byte-fp-{index}",
                ).model_dump(mode="json"),
            )
            for index, finding_id in enumerate(scan.finding_ids)
        ]
    )

    lines = iter_scan_findings_jsonl(repository, scan.scan_id)
    manifest = json.loads(next(lines))
    assert manifest["total_findings"] == total
    digest = hashlib.sha256()
    ids = []
    emitted_bytes = 0
    for line in lines:
        row = json.loads(line)
        if row["type"] == "complete":
            assert row["returned_findings"] == total
            assert row["sha256"] == digest.hexdigest()
            break
        assert row["type"] == "finding"
        digest.update(line.encode("utf-8"))
        emitted_bytes += len(line.encode("utf-8"))
        ids.append(row["finding"]["finding_id"])
    else:
        pytest.fail("JSONL stream lacked a completion record")
    assert emitted_bytes > 20 * 1024 * 1024
    assert ids == scan.finding_ids
    assert len(ids) == len(set(ids)) == total
    repository.close()


def test_cli_jsonl_is_machine_readable_and_has_completion_marker(tmp_path) -> None:
    scan, findings = sample_scan()
    database = tmp_path / "cli-jsonl.sqlite3"
    repository = SQLiteRepository(database)
    repository.save("scan", scan.scan_id, scan.model_dump(mode="json"))
    repository.save("finding", findings[0].finding_id, findings[0].model_dump(mode="json"))
    repository.close()
    result = runner.invoke(
        app,
        ["--database", str(database), "report", scan.scan_id, "--format", "jsonl"],
    )
    assert result.exit_code == 0, result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert [row["type"] for row in rows] == ["manifest", "finding", "complete"]
    assert rows[1]["finding"]["finding_id"] == findings[0].finding_id
    assert rows[-1]["returned_findings"] == 1


def test_jsonl_stops_without_completion_for_missing_or_unsafe_records(tmp_path) -> None:
    repository = SQLiteRepository(tmp_path / "incomplete.sqlite3")
    scan, findings = sample_scan()
    missing_scan = scan.model_copy(update={"finding_ids": ["missing-id"]})
    repository.save("scan", missing_scan.scan_id, missing_scan.model_dump(mode="json"))
    lines = iter_scan_findings_jsonl(repository, scan.scan_id)
    next(lines)
    with pytest.raises(ReportingError, match="unavailable"):
        next(lines)

    repository.save("finding", findings[0].finding_id, findings[0].model_dump(mode="json"))
    unsafe_scan = scan.model_copy(update={"scan_id": "unsafe-scan"})
    unsafe_finding = findings[0].model_copy(
        update={
            "finding_id": "finding-1",
            "description": "password=synthetic-canary " + "x" * 1_000_001,
        }
    )
    repository.save("scan", unsafe_scan.scan_id, unsafe_scan.model_dump(mode="json"))
    repository.save("finding", unsafe_finding.finding_id, unsafe_finding.model_dump(mode="json"))
    unsafe_lines = iter_scan_findings_jsonl(repository, unsafe_scan.scan_id)
    assert json.loads(next(unsafe_lines))["type"] == "manifest"
    with pytest.raises(ReportingError) as error:
        next(unsafe_lines)
    assert "synthetic-canary" not in str(error.value)
    repository.close()


def test_report_fails_without_partial_output_when_finding_exceeds_redaction_bound() -> None:
    from chinescan.core.logging.redaction import MAX_REDACT_STRING_CHARS

    scan, findings = sample_scan()
    over_limit = findings[0].model_copy(
        update={"description": "password=synthetic-canary " + "x" * MAX_REDACT_STRING_CHARS}
    )
    with pytest.raises(ReportingError, match="safe redaction limits") as error:
        render_report(scan, [over_limit], "full-json")
    assert "synthetic-canary" not in str(error.value)


def test_detail_report_includes_finding_explanation_score_ledger_and_coverage() -> None:
    scan, findings = sample_scan()
    explanation = FindingExplanation(
        observed="db.query(unsafe_sql)",
        match_reason="A database query pattern was observed.",
        severity_rationale="High is potential impact only.",
        confidence_rationale="Possible because data flow is unresolved.",
        limitations=["No inter-file analysis."],
    )
    findings[0] = findings[0].model_copy(update={"explanation": explanation})
    risk = VibeCodingRisk(
        score=28,
        confidence=Confidence.POSSIBLE,
        algorithm_version="signal-score-v2",
        contributions=[
            ScoreContribution(
                signal_id="tutorial_default",
                description="Tutorial-style default",
                raw_count=2,
                effective_count=2,
                weight=14,
                adjustment="Per-file count.",
                contribution=28,
            )
        ],
    )
    scan = scan.model_copy(
        update={
            "coverage": CoverageReport(examined={"python": 1}, excluded={"generated": 2}),
            "code_assessment": CodeAssessmentSummary(
                files_scanned=1, files_excluded=2, vibe_coding_risk=risk
            ),
        }
    )
    detail = render_report(scan, findings, "detail")
    assert "ChiNeScan code assessment report" in detail
    assert "Why it matched" in detail
    assert "High is potential impact only" in detail
    assert "signal-score-v2" in detail
    assert "28" in detail
    assert "Coverage gaps" in detail


def test_report_help_discloses_human_readable_detail_format() -> None:
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0
    assert "detail" in result.stdout
    assert "full-json" in result.stdout


def test_full_json_is_complete_at_configured_count_and_byte_limits(monkeypatch) -> None:
    import chinescan.core.reporting as reporting

    scan, findings = sample_scan()
    monkeypatch.setattr(reporting, "MAX_COMPLETE_FINDINGS", 1)
    body = render_report(scan, findings, "full-json")
    byte_count = len(body.encode("utf-8"))
    monkeypatch.setattr(reporting, "MAX_COMPLETE_JSON_BYTES", byte_count)
    assert len(render_report(scan, findings, "full-json").encode("utf-8")) == byte_count
    monkeypatch.setattr(reporting, "MAX_COMPLETE_JSON_BYTES", byte_count - 1)
    with pytest.raises(ReportingError, match="20 MB export limit"):
        render_report(scan, findings, "full-json")
    monkeypatch.setattr(reporting, "MAX_COMPLETE_JSON_BYTES", byte_count)
    monkeypatch.setattr(reporting, "MAX_COMPLETE_FINDINGS", 0)
    with pytest.raises(ReportingError, match="0 finding limit"):
        render_report(scan, findings, "full-json")


def test_preview_truncation_declares_omissions_and_complete_retrieval(monkeypatch) -> None:
    import chinescan.core.reporting as reporting

    scan, _ = sample_scan()
    scan = scan.model_copy(update={"code_assessment": CodeAssessmentSummary()})
    findings = [
        Finding(
            finding_id=f"finding-{index}",
            title=f"Synthetic finding {index}",
            severity=Severity.MEDIUM,
            confidence=Confidence.LIKELY,
            fingerprint=f"fingerprint-{index}",
            rule_id="SYNTHETIC-RULE",
            location=f"src/{index}.py:1",
        )
        for index in range(25)
    ]
    monkeypatch.setattr(reporting, "MAX_CODE_REPORT_BYTES", 1_200)
    payload = json.loads(render_report(scan, findings, "json"))
    assert payload["report_truncated"] is True
    assert payload["report_omissions"]["omitted_grouped_findings"] > 0
    assert (
        payload["report_omissions"]["omitted_preview_groups"]
        == payload["report_omissions"]["omitted_grouped_findings"]
    )
    assert payload["summary"]["grouped_issue_total"] == payload["summary"]["grouped_findings"]
    assert payload["report_omissions"]["omitted_by_group_cap"] > 0
    assert payload["report_omissions"]["omitted_by_byte_cap"] > 0
    assert "50 KiB JSON preview byte cap" in payload["report_omissions"]["reason"]
    assert "full-json" in payload["report_omissions"]["retrieval"]


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
