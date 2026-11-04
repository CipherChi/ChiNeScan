from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from chinescan.core.external_reports import (
    MAX_EXTERNAL_REPORT_BYTES,
    ExternalReportError,
    parse_scanity_export,
)
from chinescan.core.models.investigation import Scan
from chinescan.core.orchestration.code_rules import RULES, analyze_source
from chinescan.core.orchestration.code_scan import BuiltinRuleScanner, ScanBounds, detect_project
from chinescan.core.reporting import render_report


def test_rule_inventory_has_unique_ids_and_remediation() -> None:
    assert len({rule.rule_id for rule in RULES}) == len(RULES)
    assert all(rule.pattern.pattern and rule.cwe.startswith("CWE-") for rule in RULES)
    assert all(rule.remediation for rule in RULES)


def test_code_scan_excludes_generated_gitignored_and_long_lines(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / ".next" / "static").mkdir(parents=True)
    (root / "src").mkdir()
    (root / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
    (root / "src" / "app.py").write_text("password = 'production-secret-value'\n", encoding="utf-8")
    (root / ".next" / "static" / "bundle.js").write_text("eval(code)\n", encoding="utf-8")
    (root / "ignored.py").write_text("password = 'ignore-me'\n", encoding="utf-8")
    (root / "huge.js").write_text("x" * 10_001 + "\n", encoding="utf-8")

    profile = detect_project(root, ScanBounds())
    scanner = BuiltinRuleScanner(ScanBounds())
    findings = scanner.scan_profile(profile)

    assert {path.name for path in profile.source_files} == {"app.py"}
    assert all("bundle.js" not in str(item.location) for item in findings)
    assert all("ignored.py" not in str(item.location) for item in findings)
    assert profile.excluded_counts["generated"] >= 1
    assert profile.excluded_counts["gitignore"] == 1
    assert profile.excluded_counts["generated (line over 10,000 characters)"] == 1
    credential = next(item for item in findings if item.rule_id == "HARDCODED-CREDENTIAL")
    assert "production-secret-value" not in (credential.code_excerpt or "")


def test_nextjs_fixture_exclusions_and_test_secret_severity(tmp_path: Path) -> None:
    source_root = Path(__file__).parents[1] / "fixtures" / "code-assessment-nextjs"
    root = Path(shutil.copytree(source_root, tmp_path / "project"))
    (root / ".next" / "static" / "chunks").mkdir(parents=True, exist_ok=True)
    (root / ".next" / "static" / "chunks" / "main.js").write_text(
        "eval(devPayload)\n", encoding="utf-8"
    )
    (root / "node_modules" / "vendor").mkdir(parents=True, exist_ok=True)
    (root / "node_modules" / "vendor" / "index.js").write_text(
        "eval(vendorPayload)\n", encoding="utf-8"
    )
    (root / "ignored-source.ts").write_text("eval(request.query.code)\n", encoding="utf-8")
    bounds = ScanBounds()
    profile = detect_project(root, bounds)
    findings = BuiltinRuleScanner(bounds).scan_profile(profile)
    paths = {path.relative_to(root).as_posix() for path in profile.source_files}
    assert not any(path.startswith(".next/") for path in paths)
    assert not any(path.startswith("node_modules/") for path in paths)
    assert "ignored-source.ts" not in paths
    test_key = next(item for item in findings if item.rule_id == "HARDCODED-CREDENTIAL")
    assert test_key.severity.value == "medium"
    assert "verify the value is fake" in test_key.description
    assert {"XSS-DANGEROUS-HTML", "SSRF-USER-URL"} <= {item.rule_id for item in findings}


def test_test_credentials_are_medium_and_clean_project_has_no_high_findings(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "tests").mkdir(parents=True)
    source = root / "tests" / "test_auth.py"
    source.write_text("password = 'fake-test-value'\n", encoding="utf-8")
    test_findings = analyze_source(root, source, source.read_text(), is_test=True)
    assert test_findings[0].severity.value == "medium"
    assert "verify the value is fake" in test_findings[0].description

    clean = root / "clean.ts"
    clean.write_text("export const answer = 42;\n", encoding="utf-8")
    clean_findings = analyze_source(root, clean, clean.read_text(), is_test=False)
    assert not [item for item in clean_findings if item.severity.value in {"high", "critical"}]


def test_manifest_and_environment_file_detectors_have_positive_and_negative_cases(
    tmp_path: Path,
) -> None:
    from chinescan.core.orchestration.code_rules import dependency_findings

    (tmp_path / "package.json").write_text('{"dependencies":{"loose":"*"}}', encoding="utf-8")
    assert [item.rule_id for item in dependency_findings(tmp_path)] == ["UNPINNED-DEPENDENCY"]
    (tmp_path / "package.json").write_text('{"dependencies":{"pinned":"1.2.3"}}', encoding="utf-8")
    assert dependency_findings(tmp_path) == []

    (tmp_path / ".env").write_text("API_KEY=must-not-be-read-or-printed\n", encoding="utf-8")
    profile = detect_project(tmp_path, ScanBounds())
    findings = BuiltinRuleScanner(ScanBounds()).scan_profile(profile)
    env_finding = next(item for item in findings if item.rule_id == "ENV-FILE-PRESENT")
    assert "must-not-be-read-or-printed" not in env_finding.description
    (tmp_path / ".env").unlink()
    clean_profile = detect_project(tmp_path, ScanBounds())
    assert all(
        item.rule_id != "ENV-FILE-PRESENT"
        for item in BuiltinRuleScanner(ScanBounds()).scan_profile(clean_profile)
    )


def test_external_report_import_is_redacted_and_labeled(tmp_path: Path) -> None:
    payload = {
        "findings": [
            {
                "rule_id": "EXT-1",
                "title": "<img src=x onerror=alert(1)>",
                "description": "password='external-secret-value'",
                "path": "src/app.ts",
                "line": 7,
                "severity": "high",
                "cwe": "CWE-79",
            }
        ]
    }
    finding = parse_scanity_export(json.dumps(payload).encode(), target=tmp_path)[0]
    assert finding.source == "scanity"
    assert finding.location == "src/app.ts:7"
    assert "external-secret-value" not in finding.description
    assert "<img" not in finding.description


def test_external_import_rejects_oversized_and_traversal_paths(tmp_path: Path) -> None:
    with pytest.raises(ExternalReportError, match="2 MB"):
        parse_scanity_export(b" " * (MAX_EXTERNAL_REPORT_BYTES + 1), target=tmp_path)
    payload = {"findings": [{"title": "bad", "path": "../../outside.py"}]}
    finding = parse_scanity_export(json.dumps(payload).encode(), target=tmp_path)[0]
    assert finding.location == "external-path-omitted"


def test_code_report_groups_and_separates_external_findings(tmp_path: Path) -> None:
    from chinescan.core.orchestration.code_rules import analyze_source

    source = tmp_path / "app.py"
    text = "password = 'not-a-real-secret'\npassword = 'also-fake-secret'\n"
    source.write_text(text, encoding="utf-8")
    findings = analyze_source(tmp_path, source, text, is_test=False)
    imported = parse_scanity_export(
        b'{"findings":[{"title":"external","path":"app.py","line":2}]}',
        target=tmp_path,
    )
    scan = Scan(
        scan_id="scan",
        target_id="target",
        scanner="builtin",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        project_types=["python"],
        code_assessment={"files_scanned": 1},
    )
    markdown = render_report(scan, [*findings, *imported], "markdown")
    assert "External scanner results" in markdown
    assert "Likely real issues" in markdown
    assert "not-a-real-secret" not in markdown
