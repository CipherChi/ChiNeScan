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
        "const sql = 'SELECT * FROM users WHERE id=' + request.id",
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
        "app = express()",
        "app = express(); app.use(helmet())",
        "src/server.js",
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
        "const body = req.body",
        "const body = zod.parse(req.body)",
        "src/api.js",
    ),
    "LOGIN-NO-RATE-LIMIT": (
        "async function login(request) { return authenticate(request); }",
        "login() { rateLimiter.check(); return auth(); }",
        "src/api/login.js",
    ),
    "UPLOAD-NO-CHECKS": (
        "const upload = multer()",
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
