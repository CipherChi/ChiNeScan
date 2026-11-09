import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from chinescan.cli.app import app
from chinescan.core.models.common import Confidence, FindingVerdict, Severity
from chinescan.core.orchestration import code_scan as code_scan_module
from chinescan.core.orchestration.code_scan import (
    BuiltinRuleScanner,
    CodeScanService,
    ScannerError,
    detect_project,
    make_finding,
)
from chinescan.core.storage.sqlite import SQLiteRepository

FIXTURES = Path(__file__).parents[2] / "fixtures"


def test_detects_python_and_node_projects() -> None:
    python_project = detect_project(FIXTURES / "sample-python-project")
    node_project = detect_project(FIXTURES / "sample-node-project")
    assert python_project.kinds == ("python",)
    assert node_project.kinds == ("node",)
    assert any(path.name == "app.py" for path in python_project.source_files)


def test_builtin_scanner_reuses_project_discovery_profile(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "main.py").write_text("def run(): return 1\n", encoding="utf-8")
    original = code_scan_module.detect_project
    calls = 0

    def counted_detect_project(target, bounds=None):
        nonlocal calls
        calls += 1
        return original(target, bounds)

    monkeypatch.setattr(code_scan_module, "detect_project", counted_detect_project)
    result = CodeScanService([BuiltinRuleScanner()]).scan(tmp_path)
    assert result.coverage is not None
    assert result.coverage.examined["files_scanned"] == 1
    assert calls == 1


def test_code_scan_checks_reparse_entries_without_following_them(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    (project / "main.py").write_text("def run(): return 1\n", encoding="utf-8")
    (outside / "linked.py").write_text("eval(user_input)\n", encoding="utf-8")
    try:
        (project / "linked.py").symlink_to(outside / "linked.py")
        (project / "linked-dir").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"Host cannot create symlinks for this regression: {type(exc).__name__}")

    result = CodeScanService([BuiltinRuleScanner()]).scan(project)
    assert result.coverage is not None
    assert result.coverage.examined["files_scanned"] == 1
    assert all("linked" not in (finding.location or "") for finding in result.findings)


def test_coverage_reports_detected_and_unanalyzed_language_counts(tmp_path: Path) -> None:
    project = tmp_path / "mixed"
    project.mkdir()
    (project / "main.py").write_text("print('synthetic')", encoding="utf-8")
    (project / "Main.java").write_text("class Main {}", encoding="utf-8")
    (project / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    result = CodeScanService([BuiltinRuleScanner()]).scan(project)
    assert result.coverage is not None
    assert result.coverage.languages_detected == {
        "Python": 1,
        "Java": 1,
        "XML config": 1,
    }
    assert result.coverage.files_scanned_by_language == {
        "Python": 1,
        "Java": 1,
        "XML config": 1,
    }
    assert result.coverage.language_analyzer_status["Java"] == (
        "generic first-pass only; no analyzer for this language"
    )
    assert result.coverage.language_analyzer_status["XML config"].startswith(
        "Android XML checks: manifest exported components"
    )
    assert any("Supabase RLS" in item for item in result.coverage.not_assessed)


def test_synthetic_flutter_supabase_382_file_regression(tmp_path: Path) -> None:
    project = tmp_path / "flutter-supabase"
    migrations = project / "supabase" / "migrations"
    functions = project / "supabase" / "functions"
    lib = project / "lib"
    android = project / "android" / "app" / "src" / "main"
    migrations.mkdir(parents=True)
    functions.mkdir(parents=True)
    lib.mkdir(parents=True)
    android.mkdir(parents=True)
    (project / "pubspec.yaml").write_text("name: synthetic_fixture\n", encoding="utf-8")
    (migrations / "20250101_create.sql").write_text(
        "CREATE TABLE public.device_pairings (id uuid primary key);\n"
        "CREATE TABLE public.child_devices (id uuid primary key);",
        encoding="utf-8",
    )
    (migrations / "20250102_enable_rls.sql").write_text(
        "ALTER TABLE public.device_pairings ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.child_devices ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY device_pairings_service ON public.device_pairings "
        "FOR ALL TO service_role USING (true);",
        encoding="utf-8",
    )
    for index in range(68):
        (migrations / f"202501{index + 3:02}_noop.sql").write_text(
            "select 1;\n", encoding="utf-8"
        )
    handler = functions / "index.ts"
    handler.write_text(
        "Deno.serve(async (req) => {\n"
        "  const body = await req.json();\n"
        "  const key = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');\n"
        "  await supabase.from('device_pairings').insert(body);\n"
        "  return new Response(JSON.stringify({ error: 'Unable to process request' }));\n"
        "});\n",
        encoding="utf-8",
    )
    for index in range(9):
        (functions / f"worker-{index}.ts").write_text("export {};\n", encoding="utf-8")
    api_key = "AIza" + "A" * 35
    (lib / "main.dart").write_text(
        "final prefs = await SharedPreferences.getInstance();\n"
        "await prefs.setString('access_token', token);\n"
        "client.badCertificateCallback = (_, __, ___) => true;\n"
        "debugPrint(accessToken);\n"
        f"const apiKey = '{api_key}';\n",
        encoding="utf-8",
    )
    for index in range(299):
        (lib / f"screen-{index}.dart").write_text("void screen() {}\n", encoding="utf-8")
    (android / "AndroidManifest.xml").write_text(
        '<manifest><application android:allowBackup="true"/></manifest>\n',
        encoding="utf-8",
    )
    result = CodeScanService([BuiltinRuleScanner()]).scan(project)

    assert result.coverage is not None
    assert result.coverage.examined["files_scanned"] == 382
    coverage = result.coverage.language_analyzer_status
    assert "Deno edge-handler request/auth/service-role checks" in coverage["TypeScript"]
    assert "Dart/Flutter checks" in coverage["Dart"]
    assert "Supabase migration checks" in coverage["SQL"]
    assert "Android XML checks" in coverage["XML config"]
    assert "generic first-pass only" in coverage["Dart"]
    findings = {item.rule_id: item for item in result.findings}
    assert "SUPABASE-MIGRATION-RLS" not in findings
    assert findings["SUPABASE-POLICY-SERVICE-ROLE-INFO"].severity.value == "info"
    assert "REQUEST-NO-SCHEMA" in findings
    request = findings["REQUEST-NO-SCHEMA"]
    assert request.source_location is not None and request.sink_location is not None
    assert request.verdict is FindingVerdict.LIKELY
    assert request.line_numbers == [2, 4]
    service_role = findings["DENO-SERVICE-ROLE-NO-AUTH"]
    assert service_role.verdict is FindingVerdict.CONFIRMED
    assert service_role.source_location is not None and service_role.sink_location is not None
    assert "VERBOSE-ERROR-EXPOSURE" not in findings
    firebase_key = findings["FIREBASE-API-KEY-INFO"]
    assert firebase_key.severity.value == "info"
    assert "does not authenticate a user" in firebase_key.explanation.confidence_rationale
    assert {
        "DART-INSECURE-TOKEN-STORAGE",
        "DART-CERTIFICATE-CHECK-DISABLED",
        "DART-SENSITIVE-LOGGING",
        "ANDROID-ALLOW-BACKUP",
    } <= set(findings)


def test_oversized_source_is_reported_as_scan_failure(tmp_path: Path) -> None:
    project = tmp_path / "large-project"
    project.mkdir()
    (project / "large.py").write_bytes(b"x" * 1_000_001)
    try:
        detect_project(project)
    except ScannerError as exc:
        assert "above the configured 1 MB limit" in str(exc)
    else:
        raise AssertionError("Oversized source was silently omitted from the scan.")


def test_oversized_scan_persists_failed_verdict_and_coverage_gap(tmp_path: Path) -> None:
    project = tmp_path / "large-project"
    project.mkdir()
    (project / "large.py").write_bytes(b"x" * 1_000_001)
    repository = SQLiteRepository(tmp_path / "failed-scan.sqlite3")
    try:
        try:
            CodeScanService([BuiltinRuleScanner()], repository).scan(project)
        except ScannerError:
            pass
        else:
            raise AssertionError("Oversized source did not preserve the existing abort behavior.")
        records = repository.list_records("scan")
        assert len(records) == 1
        assert records[0]["status"] == "failed"
        assert records[0]["verdict"] == "scan_failed"
        assert records[0]["coverage"]["gaps"][0]["code"] == "file_size_limit"
    finally:
        repository.close()


def test_builtin_scanner_does_not_return_secret_value() -> None:
    findings = BuiltinRuleScanner().scan(FIXTURES / "sample-python-project")
    assert {finding.rule_id for finding in findings} == {
        "DYNAMIC-EVAL",
        "PY-SHELL",
        "HARDCODED-CREDENTIAL",
    }
    serialized = json.dumps([finding.model_dump(mode="json") for finding in findings])
    assert "example-fixture-password" not in serialized
    assert all(finding.fingerprint for finding in findings)
    assert all(finding.location for finding in findings)


def test_orchestration_deduplicates_isolates_and_persists(tmp_path: Path) -> None:
    target = FIXTURES / "sample-python-project"

    class DuplicateScanner:
        name = "duplicate"

        def scan(self, scan_target: Path):
            return [
                finding.model_copy(
                    update={
                        "scanner": self.name,
                        "severity": Severity.CRITICAL,
                        "confidence": Confidence.CONFIRMED,
                    }
                )
                for finding in BuiltinRuleScanner().scan(scan_target)
            ]

    class BrokenScanner:
        name = "broken"

        def scan(self, scan_target: Path):
            del scan_target
            raise ScannerError("test failure")

    repository = SQLiteRepository(tmp_path / "scan.sqlite3")
    try:
        result = CodeScanService(
            [BuiltinRuleScanner(), DuplicateScanner(), BrokenScanner()], repository
        ).scan(target)
        assert len(result.findings) == 3
        assert all(finding.scanner == "builtin,duplicate" for finding in result.findings)
        assert all(finding.severity == Severity.CRITICAL for finding in result.findings)
        assert all(finding.confidence == Confidence.CONFIRMED for finding in result.findings)
        assert result.failures == {"broken": "test failure"}
        scan_record = repository.get("scan", result.scan_id)
        assert scan_record is not None
        assert scan_record["status"] == "partial"
        assert repository.get("target", scan_record["target_id"]) is not None
        assert repository.get("finding", result.findings[0].finding_id) is not None
    finally:
        repository.close()


def test_fingerprint_is_stable_and_severity_independent(tmp_path: Path) -> None:
    low = make_finding(
        target=tmp_path,
        scanner="one",
        rule_id="RULE-1",
        title="Candidate",
        severity=Severity.LOW,
        location="app.py:4",
    )
    high = make_finding(
        target=tmp_path,
        scanner="two",
        rule_id="rule-1",
        title="Different prose",
        severity=Severity.HIGH,
        location="app.py:4",
    )
    assert low.fingerprint == high.fingerprint


def test_code_cli_json_summary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(tmp_path / "cli.sqlite3"))
    result = CliRunner().invoke(
        app,
        [
            "--reports-dir",
            str(tmp_path / "custom-reports"),
            "code",
            str(FIXTURES / "sample-node-project"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["project_types"] == ["node"]
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["rule_id"] == "DYNAMIC-EVAL"
    assert len(list((tmp_path / "custom-reports").glob("*"))) == 2


def test_code_cli_no_save_report_and_fail_on_gaps(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(tmp_path / "no-save.sqlite3"))
    reports = tmp_path / "auto-reports"
    disabled = CliRunner().invoke(
        app,
        ["code", str(FIXTURES / "sample-node-project"), "--no-save-report", "--format", "json"],
    )
    assert disabled.exit_code == 0, disabled.output
    assert not reports.exists()

    target = tmp_path / "long-line-project"
    target.mkdir()
    (target / "main.py").write_text("x" * 10_001, encoding="utf-8")
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(tmp_path / "gaps.sqlite3"))
    failed = CliRunner().invoke(app, ["code", str(target), "--fail-on-gaps", "--no-save-report"])
    assert failed.exit_code == 1
    assert "--fail-on-gaps" in failed.stderr


def test_code_cli_report_store_warning_keeps_exit_code(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(tmp_path / "warning.sqlite3"))
    blocker = tmp_path / "reports-file"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("CHINESCAN_REPORTS_DIR", str(blocker / "child"))
    result = CliRunner().invoke(
        app, ["code", str(FIXTURES / "sample-node-project"), "--format", "json"]
    )
    assert result.exit_code == 0
    json.loads(result.stdout)
    assert "Warning:" in result.stderr


def test_code_cli_severity_threshold_is_configurable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CHINESCAN_DATABASE_PATH", str(tmp_path / "threshold.sqlite3"))
    target = str(FIXTURES / "sample-python-project")
    high = CliRunner().invoke(app, ["code", target, "--fail-on", "high", "--format", "json"])
    assert high.exit_code == 1
    assert "Failing threshold high" in high.stderr
    assert json.loads(high.stdout)["finding_count"] >= 1

    critical = CliRunner().invoke(app, ["code", target, "--fail-on", "critical"])
    assert critical.exit_code == 0

    invalid = CliRunner().invoke(app, ["code", target, "--fail-on", "blocker"])
    assert invalid.exit_code == 2


def test_dependency_cli_requires_explicit_network_consent() -> None:
    result = CliRunner().invoke(
        app,
        ["code", str(FIXTURES / "sample-python-project"), "--scanner", "pip-audit"],
    )
    assert result.exit_code == 2
    assert "require explicit --allow-network-audits consent" in result.stderr
