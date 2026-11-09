from __future__ import annotations

from pathlib import Path

import pytest

from chinescan.core.orchestration.code_rules import RULES, analyze_source

# Each detector has a minimal vulnerable sample and a nearby safe sample. Route
# paths are specified where a detector intentionally applies only to handlers.
CASES: dict[str, tuple[str, str, str]] = {
    "DYNAMIC-EVAL": ("eval(input_value)", "const value = input_value", "src/app.js"),
    "NODE-EXEC-INTERPOLATION": (
        "exec(`echo ${request.query.name}`)",
        "execFile('echo', [validatedName])",
        "src/app.js",
    ),
    "PY-SHELL": (
        "subprocess.run(command, shell=True)",
        "subprocess.run([binary, argument], shell=False)",
        "src/app.py",
    ),
    "SQL-INJECTION": (
        "const rows = await db.query('SELECT * FROM users WHERE id=' + request.id)",
        "db.query('SELECT * FROM users WHERE id = ?', [request.id])",
        "src/app.js",
    ),
    "NOSQL-OPERATOR-INJECTION": (
        "const query = { $ne: req.body.value }",
        "const query = { active: true }",
        "src/app.js",
    ),
    "PATH-TRAVERSAL": (
        "readFile(req.query.path)",
        "readFile(resolve(ALLOWED_ROOT, safeName))",
        "src/app.js",
    ),
    "XSS-DANGEROUS-HTML": (
        "element.innerHTML = userInput",
        "element.textContent = userInput",
        "src/app.js",
    ),
    "API-AUTH-MISSING": (
        "export async function POST(request) { return Response.json({}); }",
        "export async function POST(request) { await requireUser(); return Response.json({}); }",
        "src/api/route.ts",
    ),
    "IDOR-RESOURCE-ID": (
        "const item = await findById(req.params.id)",
        "const item = await findById(req.params.id); if (owner) return item",
        "src/data.js",
    ),
    "JWT-ALG-NONE": (
        "verify(token, key, { algorithm: 'none' })",
        "verify(token, key, { algorithms: ['HS256'] })",
        "src/auth.js",
    ),
    "JWT-NO-EXPIRY": (
        "jwt.sign({ sub: user.id }, key)",
        "jwt.sign({ sub: user.id }, key, { expiresIn: '10m' })",
        "src/auth.js",
    ),
    "COOKIE-FLAGS": (
        "res.cookie('session', token)",
        "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' })",
        "src/auth.js",
    ),
    "CSRF-DISABLED": (
        "csrfProtection = false",
        "csrfProtection = true",
        "src/auth.js",
    ),
    "HARDCODED-CREDENTIAL": (
        "password = 'long-hardcoded-password'",
        "password = process.env.APP_PASSWORD",
        "src/auth.py",
    ),
    "NEXT-PUBLIC-SECRET": (
        "process.env.NEXT_PUBLIC_API_KEY",
        "process.env.NEXT_PUBLIC_ANALYTICS_ID",
        "src/app.js",
    ),
    "CORS-WILDCARD-CREDENTIALS": (
        "origin: '*', credentials: true",
        "origin: 'https://trusted.example', credentials: true",
        "src/server.js",
    ),
    "MISSING-SECURITY-HEADERS": (
        "module.exports = { headers: async () => [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }] }] }",  # noqa: E501
        "module.exports = { headers: async () => [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: \"default-src 'self'\" }, { key: 'X-Frame-Options', value: 'DENY' }, { key: 'X-Content-Type-Options', value: 'nosniff' }, { key: 'Referrer-Policy', value: 'no-referrer' }] }] }",  # noqa: E501
        "next.config.js",
    ),
    "TLS-VERIFY-DISABLED": (
        "fetch(url, { rejectUnauthorized: false })",
        "fetch(url, { rejectUnauthorized: true })",
        "src/client.js",
    ),
    "VERBOSE-ERROR-EXPOSURE": (
        "res.json(error.message)",
        "res.json({ error: 'Request failed' })",
        "src/api.js",
    ),
    "OPEN-REDIRECT": (
        "redirect(request.query.next)",
        "redirect('/dashboard')",
        "src/api.js",
    ),
    "SSRF-USER-URL": (
        "fetch(request.query.url)",
        "fetch('https://trusted.example/status')",
        "src/api.js",
    ),
    "REQUEST-NO-SCHEMA": (
        "const body = req.body; await db.insert(body)",
        "const body = schema.parse(req.body); await db.insert(body)",
        "src/api.js",
    ),
    "LOGIN-NO-RATE-LIMIT": (
        "async function login(request) { return authenticate(request); }",
        "login() { rateLimiter.check(); return auth(); }",
        "src/api/login.js",
    ),
    "UPLOAD-NO-CHECKS": (
        "const upload = multer(); upload.single('file')",
        "const upload = multer({ limits: { fileSize: 1000 }, fileFilter })",
        "src/upload.js",
    ),
    "EMPTY-CATCH": (
        "try { run(); } catch (error) {}",
        "try { run(); } catch (error) { reportSafeError(error); }",
        "src/app.js",
    ),
    "SWALLOWED-PROMISE": (
        "task.catch(() => {})",
        "task.catch((error) => reportSafeError(error))",
        "src/app.js",
    ),
    "ASYNC-ROUTE-ERROR": (
        "export async function GET() { return Response.json({ ok: true }); }",
        "export function GET() { return Response.json({ ok: true }); }",
        "src/api/route.ts",
    ),
    "SENSITIVE-CONSOLE-LOG": (
        "console.log('token', token)",
        "console.log('request completed')",
        "src/app.js",
    ),
    "SECURITY-TODO": (
        "// TODO add auth check before release",
        "// TODO update the button label",
        "src/app.js",
    ),
    "CLIENT-COMPONENT-SECRET": (
        "'use client'; const secret = process.env.APP_SECRET",
        "'use client'; const analytics = process.env.NEXT_PUBLIC_ANALYTICS_ID",
        "src/client.tsx",
    ),
}


@pytest.mark.parametrize("rule_id", [rule.rule_id for rule in RULES])
def test_rule_has_positive_and_negative_behavioral_fixture(tmp_path: Path, rule_id: str) -> None:
    positive, negative, relative = CASES[rule_id]
    root = tmp_path / "project"
    root.mkdir()
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    assert rule_id in {
        finding.rule_id for finding in analyze_source(root, path, positive, is_test=False)
    }, f"positive fixture did not trigger {rule_id}"
    assert rule_id not in {
        finding.rule_id for finding in analyze_source(root, path, negative, is_test=False)
    }, f"negative fixture unexpectedly triggered {rule_id}"


def test_upload_rule_ignores_file_existence_suffix_and_reads(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    path = root / "src" / "files.ts"
    path.parent.mkdir()
    text = "if (path.is_file() && path.endsWith('.zip')) { await readFile(path); }"
    path.write_text(text, encoding="utf-8")
    assert "UPLOAD-NO-CHECKS" not in {
        item.rule_id for item in analyze_source(root, path, text, is_test=False)
    }


def test_upload_with_controls_reports_them_without_an_absence_finding(tmp_path: Path) -> None:
    root = tmp_path / "project"
    path = root / "src" / "upload.ts"
    path.parent.mkdir(parents=True)
    text = "const handler = multer({ limits: { fileSize: 1000 }, fileFilter });"
    findings = analyze_source(root, path, text, is_test=False)
    assert "UPLOAD-NO-CHECKS" not in {item.rule_id for item in findings}
    observed = next(item for item in findings if item.rule_id == "UPLOAD-CONTROLS-OBSERVED")
    assert "File size limits: found" in observed.explanation.controls_considered


def test_request_schema_evidence_uses_unvalidated_sink_line(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    path = root / "route.ts"
    text = "const body = await request.json();\nawait db.insert(body);"
    path.write_text(text, encoding="utf-8")
    findings = analyze_source(root, path, text, is_test=False)
    finding = next(item for item in findings if item.rule_id == "REQUEST-NO-SCHEMA")
    assert finding.line_numbers == [2]
    assert finding.code_excerpt == "await db.insert(body);"
    assert finding.explanation is not None
    assert finding.explanation.observed == finding.code_excerpt


def test_empty_catch_includes_body_and_known_fallback_is_info(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    path = root / "src" / "fallback.js"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "try { JSON.parse(value); } catch (error) { /* ignored */ }"
    path.write_text(text, encoding="utf-8")
    findings = analyze_source(root, path, text, is_test=False)
    finding = next(item for item in findings if item.rule_id == "EMPTY-CATCH")
    assert "catch (error) { /* ignored */ }" in finding.code_excerpt
    assert finding.severity.value == "info"


def test_empty_catch_around_auth_failure_is_elevated(tmp_path: Path) -> None:
    root = tmp_path / "project"
    path = root / "src" / "auth.js"
    path.parent.mkdir(parents=True)
    text = "try { await authService.login(); } catch (error) {}"
    findings = analyze_source(root, path, text, is_test=False)
    finding = next(item for item in findings if item.rule_id == "EMPTY-CATCH")
    assert finding.severity.value == "high"


def test_verbose_error_through_fixed_mapper_is_downgraded(tmp_path: Path) -> None:
    path = tmp_path / "src" / "api.js"
    path.parent.mkdir(parents=True)
    text = "res.json({ message: errorMap(error.code, error.message) });"
    findings = analyze_source(tmp_path, path, text, is_test=False)
    finding = next(item for item in findings if item.rule_id == "VERBOSE-ERROR-EXPOSURE")
    assert finding.severity.value == "info"
    assert "Fixed/mapped error handler: found" in finding.explanation.controls_considered


@pytest.mark.parametrize(
    ("relative", "positive", "negative", "rule_id"),
    [
        (
            "lib/config.dart",
            'const api = "ghp_' + "A" * 36 + '";',
            'const api = "example";',
            "HARDCODED-SECRET-SHAPE",
        ),
        (
            "android/AndroidManifest.xml",
            '<application usesCleartextTraffic="true"/>',
            '<application usesCleartextTraffic="false"/>',
            "ANDROID-CLEARTEXT-TRAFFIC",
        ),
        (
            "supabase/migrations/001.sql",
            "CREATE TABLE users (id int);",
            "CREATE TABLE users (id int);\nALTER TABLE users ENABLE ROW LEVEL SECURITY;",
            "SUPABASE-MIGRATION-RLS",
        ),
    ],
)
def test_cross_language_first_pass_rules_have_true_and_false_fixtures(
    tmp_path: Path, relative: str, positive: str, negative: str, rule_id: str
) -> None:
    root = tmp_path / "repo"
    path = root / relative
    path.parent.mkdir(parents=True)
    path.write_text(positive, encoding="utf-8")
    assert rule_id in {item.rule_id for item in analyze_source(root, path, positive, is_test=False)}
    assert rule_id not in {
        item.rule_id for item in analyze_source(root, path, negative, is_test=False)
    }


def test_service_role_usage_is_limited_to_client_mobile_source(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    mobile = root / "mobile" / "main.dart"
    mobile.parent.mkdir(parents=True)
    text = "final key = SUPABASE_SERVICE_ROLE_KEY;"
    mobile.write_text(text, encoding="utf-8")
    assert "SUPABASE-SERVICE-ROLE-CLIENT" in {
        item.rule_id for item in analyze_source(root, mobile, text, is_test=False)
    }
    server = root / "server.py"
    server.write_text(text, encoding="utf-8")
    assert "SUPABASE-SERVICE-ROLE-CLIENT" not in {
        item.rule_id for item in analyze_source(root, server, text, is_test=False)
    }


def test_behavior_fixture_table_covers_every_rule() -> None:
    assert set(CASES) == {rule.rule_id for rule in RULES}


def test_direct_flows_are_likely_with_full_redacted_source_line(tmp_path: Path) -> None:
    path = tmp_path / "src" / "Preview.tsx"
    path.parent.mkdir()
    source = (
        "return <div dangerouslySetInnerHTML={{ __html: request.body.html }} />; "
        '// password="example-realistic-secret"'
    )
    findings = analyze_source(tmp_path, path, source, is_test=False)
    finding = next(item for item in findings if item.rule_id == "XSS-DANGEROUS-HTML")
    assert finding.confidence.value == "LIKELY"
    assert finding.title == "Cross-site scripting (XSS)"
    assert finding.code_excerpt is not None
    assert "return <div" in finding.code_excerpt
    assert len(finding.code_excerpt) <= 160
    assert "example-realistic-secret" not in finding.code_excerpt
    assert "Before: " in (finding.remediation or "")
    assert "After: " in (finding.remediation or "")


def test_context_dependent_match_stays_possible(tmp_path: Path) -> None:
    path = tmp_path / "src" / "api" / "route.ts"
    path.parent.mkdir(parents=True)
    findings = analyze_source(
        tmp_path,
        path,
        "export async function GET(request) { return Response.json({}); }",
        is_test=False,
    )
    finding = next(item for item in findings if item.rule_id == "API-AUTH-MISSING")
    assert finding.confidence.value == "POSSIBLE"


def test_jwt_none_keyword_possible_confidence_caps_at_medium(tmp_path: Path) -> None:
    path = tmp_path / "src" / "auth.js"
    path.parent.mkdir(parents=True)
    findings = analyze_source(
        tmp_path,
        path,
        "verify(token, key, { algorithm: 'none' })",
        is_test=False,
    )
    finding = next(item for item in findings if item.rule_id == "JWT-ALG-NONE")
    assert finding.severity.value == "medium"
    assert finding.confidence.value == "POSSIBLE"
    assert finding.explanation is not None
    assert finding.explanation.classification_policy_version == "signal-quality-v2"
    assert "verifier use is unknown" in (finding.explanation.severity_rationale or "")
    assert not any(rule.severity.value == "critical" for rule in RULES)


@pytest.mark.parametrize(
    ("relative", "source", "expected"),
    [
        ("src/client.ts", 'const node = document.querySelector(`[data-id="${id}"]`);', False),
        ("src/server.ts", 'createHash("sha256").update(`${scope}:${value}`);', False),
        ("src/server.ts", "// db.query(`SELECT * FROM t WHERE id=${request.id}`)", False),
        (
            "src/server.ts",
            'const example = "db.query(`SELECT * FROM t WHERE id=${request.id}`)";',
            False,
        ),
        (
            "src/api.ts",
            "const rows = await db.query(`SELECT * FROM users WHERE id=${request.params.id}`);",
            True,
        ),
        ("src/api.ts", 'cursor.execute("SELECT * FROM users WHERE id=%s", (request.id,))', False),
        (
            "src/api.py",
            'cursor.execute("SELECT * FROM users WHERE id=" + request.args["id"])',
            True,
        ),
        ("src/api.ts", "await prisma.$queryRaw`SELECT * FROM users WHERE id=${request.id}`", True),
    ],
)
def test_sql_detection_requires_database_sink_and_unsafe_query(
    tmp_path: Path, relative: str, source: str, expected: bool
) -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    findings = analyze_source(tmp_path, path, source, is_test=False)
    sql_findings = [finding for finding in findings if finding.rule_id == "SQL-INJECTION"]
    assert bool(sql_findings) is expected
    if sql_findings:
        assert sql_findings[0].confidence.value == "POSSIBLE"
        assert sql_findings[0].explanation is not None
        assert "no AST" in " ".join(sql_findings[0].explanation.limitations)


def test_display_text_and_project_pages_do_not_become_absence_findings(tmp_path: Path) -> None:
    samples = {
        "src/app/(public)/contact/page.tsx": 'export default function Page(){ return <a href="/contact">Contact</a> }',  # noqa: E501
        "src/app/(public)/page.tsx": 'export default function Page(){ return <a href="/admin/login">Login</a> }',  # noqa: E501
        "eslint.config.mjs": "export default config;",
        "playwright.config.ts": "export default defineConfig({});",
    }
    for relative, source in samples.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        rules = {
            finding.rule_id for finding in analyze_source(tmp_path, path, source, is_test=False)
        }
        assert "LOGIN-NO-RATE-LIMIT" not in rules
        assert "MISSING-SECURITY-HEADERS" not in rules


def test_cookie_simple_options_variable_is_resolved(tmp_path: Path) -> None:
    path = tmp_path / "src" / "auth.js"
    path.parent.mkdir()
    source = "const options = { httpOnly: true, secure: true, sameSite: 'lax' };\nres.cookie('session', token, options);"  # noqa: E501
    rules = {finding.rule_id for finding in analyze_source(tmp_path, path, source, is_test=False)}
    assert "COOKIE-FLAGS" not in rules


def test_code_pattern_risk_ledger_reconciles_caps_and_bonuses(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from chinescan.core.orchestration.code_rules import vibe_risk

    files = []
    for index in range(4):
        path = tmp_path / f"src/{index}.tsx"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "'use client'; validate(form); const key = 'service_role';", encoding="utf-8"
        )
        files.append(path)
    route = tmp_path / "src/route.ts"
    route.write_text(
        "export function GET() {}\nexport function POST() {}\nexport function PUT() {}\nexport function DELETE() {}",  # noqa: E501
        encoding="utf-8",
    )
    files.append(route)
    risk = vibe_risk(SimpleNamespace(source_files=tuple(files), root=tmp_path))
    assert risk.algorithm_version == "legacy-pattern-v1"
    assert risk.score == sum(item.contribution for item in risk.contributions)
    by_signal = {item.signal_id: item for item in risk.contributions}
    assert by_signal["tutorial_default"].raw_count == 4
    assert by_signal["tutorial_default"].effective_count == 3
    assert by_signal["tutorial_default"].contribution == 54
    assert by_signal["client_validation"].contribution == 0
    assert by_signal["client_validation"].raw_count == 0
    assert by_signal["route_handlers_without_controls"].contribution == 12
    assert risk.score == 66


def test_legacy_score_has_explicit_versioned_ledger(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from chinescan.core.orchestration.code_rules import vibe_risk

    risk = vibe_risk(SimpleNamespace(source_files=(), root=tmp_path))
    assert risk.score is None
    assert risk.contributions
    assert all(item.raw_count == 0 and item.contribution == 0 for item in risk.contributions)
