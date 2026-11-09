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
from chinescan.core.models.common import Confidence, FindingVerdict, Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Scan
from chinescan.core.orchestration.code_rules import RULES, analyze_source
from chinescan.core.orchestration.code_scan import BuiltinRuleScanner, ScanBounds, detect_project
from chinescan.core.reporting import _fix_first, _markdown, render_report


def test_rule_inventory_has_unique_ids_and_remediation() -> None:
    assert len({rule.rule_id for rule in RULES}) == len(RULES)
    assert all(rule.pattern.pattern and rule.cwe.startswith("CWE-") for rule in RULES)
    assert all(rule.remediation for rule in RULES)
    assert all(rule.title and rule.example_before and rule.example_after for rule in RULES)


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
    assert test_key.severity.value == "info"
    assert test_key.verdict == FindingVerdict.LEAD
    assert "verify the value is fake" in test_key.description
    assert {"XSS-DANGEROUS-HTML", "SSRF-USER-URL"} <= {item.rule_id for item in findings}


def test_test_credentials_are_medium_and_clean_project_has_no_high_findings(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "tests").mkdir(parents=True)
    source = root / "tests" / "test_auth.py"
    source.write_text("password = 'fake-test-value'\n", encoding="utf-8")
    test_findings = analyze_source(root, source, source.read_text(), is_test=True)
    assert test_findings[0].severity.value == "info"
    assert test_findings[0].verdict == FindingVerdict.LEAD
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


def test_offline_advisories_cover_npm_pub_and_cargo_with_reachability_and_fixed_misses(
    tmp_path: Path,
) -> None:
    from chinescan.core.orchestration.code_rules import dependency_findings

    npm = tmp_path / "npm"
    (npm / "src").mkdir(parents=True)
    (npm / "package.json").write_text('{"dependencies":{"lodash":"^4.17.0"}}', encoding="utf-8")
    (npm / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"^4.17.0"}},'
        '"node_modules/lodash":{"version":"4.17.20"}}}',
        encoding="utf-8",
    )
    (npm / "src" / "template.js").write_text("_.template(untrustedInput);\n", encoding="utf-8")
    npm_finding = next(
        item for item in dependency_findings(npm) if item.rule_id.endswith("GHSA-35jh-r3h4-6jhm")
    )
    assert npm_finding.verdict.value == "likely"
    assert "lodash 4.17.20" in npm_finding.code_excerpt
    assert "4.17.21" in npm_finding.description
    assert "Likely reachable" in npm_finding.description
    assert npm_finding.verification_step

    (npm / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}',
        encoding="utf-8",
    )
    assert not [
        item for item in dependency_findings(npm) if item.rule_id.endswith("GHSA-35jh-r3h4-6jhm")
    ]
    (npm / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21-beta.1"}}}',
        encoding="utf-8",
    )
    prerelease_finding = next(
        item for item in dependency_findings(npm) if item.rule_id.endswith("GHSA-35jh-r3h4-6jhm")
    )
    assert prerelease_finding.verdict.value == "likely"
    (npm / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}',
        encoding="utf-8",
    )
    (npm / "src" / "template.js").write_text(
        '// _.template(untrustedInput);\nconst apiName = "_.template";\n', encoding="utf-8"
    )
    (npm / "tests").mkdir()
    (npm / "tests" / "template.test.js").write_text(
        "_.template(untrustedInput);\n", encoding="utf-8"
    )
    npm_lead = next(
        item for item in dependency_findings(npm) if item.rule_id.endswith("GHSA-35jh-r3h4-6jhm")
    )
    assert npm_lead.verdict.value == "lead"
    assert npm_lead.severity.value == "info"

    dart = tmp_path / "dart"
    (dart / "lib").mkdir(parents=True)
    (dart / "pubspec.yaml").write_text("dependencies:\n  jose: ^0.3.0\n", encoding="utf-8")
    (dart / "pubspec.lock").write_text(
        "packages:\n  jose:\n    dependency: 'direct main'\n    version: 0.3.5\n",
        encoding="utf-8",
    )
    (dart / "lib" / "auth.dart").write_text(
        "import 'package:jose/jose.dart';\n"
        "final jwt = await JsonWebToken.decodeAndVerify(encoded, keyStore);\n",
        encoding="utf-8",
    )
    dart_finding = next(
        item for item in dependency_findings(dart) if item.rule_id.endswith("GHSA-vm9r-h74p-hg97")
    )
    assert dart_finding.verdict.value == "likely"
    assert "0.3.5+1" in dart_finding.description

    rust = tmp_path / "rust"
    (rust / "src").mkdir(parents=True)
    (rust / "Cargo.toml").write_text('[dependencies]\ntokio = "1.44"\n', encoding="utf-8")
    (rust / "Cargo.lock").write_text(
        '[[package]]\nname = "tokio"\nversion = "1.44.1"\n', encoding="utf-8"
    )
    (rust / "src" / "main.rs").write_text(
        "use tokio::sync::broadcast;\nlet (_tx, _rx) = broadcast::channel(16);\n",
        encoding="utf-8",
    )
    rust_finding = next(
        item for item in dependency_findings(rust) if item.rule_id.endswith("RUSTSEC-2025-0023")
    )
    assert rust_finding.verdict.value == "likely"
    assert "fixed version 1.44.2" in rust_finding.description

    (rust / "Cargo.lock").write_text(
        '[[package]]\nname = "tokio"\nversion = "1.44.2"\n', encoding="utf-8"
    )
    assert not [
        item for item in dependency_findings(rust) if item.rule_id.endswith("RUSTSEC-2025-0023")
    ]


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


def test_external_import_redacts_retained_prefix_before_discarding_long_tail(
    tmp_path: Path,
) -> None:
    payload = {
        "findings": [
            {
                "title": "synthetic",
                "description": "password=synthetic-canary " + "ordinary " * 20_000,
            }
        ]
    }
    finding = parse_scanity_export(json.dumps(payload).encode(), target=tmp_path)[0]
    assert "synthetic-canary" not in finding.description
    assert "[REDACTED]" in finding.description
    assert len(finding.description) <= 2_000


def test_external_import_rejects_excessive_json_nesting_without_echoing_input(
    tmp_path: Path,
) -> None:
    nested = '{"findings":[' + "[" * 20_000 + '"synthetic-canary"' + "]" * 20_000 + "]}"
    with pytest.raises(ExternalReportError, match="valid UTF-8 JSON") as error:
        parse_scanity_export(nested.encode(), target=tmp_path)
    assert "synthetic-canary" not in str(error.value)


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
    assert "## Leads (not counted as vulnerabilities)" in markdown
    assert "**Confirmed and likely issues:** 0" in markdown
    assert "not-a-real-secret" not in markdown


def test_markdown_leaves_plain_punctuation_and_escapes_untrusted_markup() -> None:
    assert _markdown(".next folder (coverage)") == ".next folder (coverage)"
    unsafe = _markdown("<script>[open](https://invalid.example)</script>", untrusted=True)
    assert "<script>" not in unsafe
    assert "[open](https://invalid.example)" not in unsafe


def test_fix_first_breaks_ties_by_exposure_then_path() -> None:
    findings = [
        Finding(
            finding_id="z-server",
            title="Server",
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            fingerprint="z-server-fingerprint",
            location="z/server.py:1",
            exposure="server",
            verdict=FindingVerdict.LIKELY,
        ),
        Finding(
            finding_id="b-client",
            title="Client",
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            fingerprint="b-client-fingerprint",
            location="b/client.ts:1",
            exposure="client",
            verdict=FindingVerdict.LIKELY,
        ),
        Finding(
            finding_id="a-client",
            title="Earlier client path",
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            fingerprint="a-client-fingerprint",
            location="a/client.ts:1",
            exposure="client",
            verdict=FindingVerdict.LIKELY,
        ),
    ]
    safe = {item.finding_id: item.model_dump(mode="json") for item in findings}
    assert [item["finding_id"] for item in _fix_first(findings, safe)] == [
        "a-client",
        "b-client",
        "z-server",
    ]
