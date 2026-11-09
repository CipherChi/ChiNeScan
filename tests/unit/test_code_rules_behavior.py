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


def test_request_schema_evidence_shows_source_then_unvalidated_sink(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    path = root / "route.ts"
    text = "const body = await request.json();\nawait db.insert(body);"
    path.write_text(text, encoding="utf-8")
    findings = analyze_source(root, path, text, is_test=False)
    finding = next(item for item in findings if item.rule_id == "REQUEST-NO-SCHEMA")
    assert finding.line_numbers == [1, 2]
    assert finding.code_excerpt == "const body = await request.json(); | await db.insert(body);"
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
                'const token = "ghp_' + "a1B2c3D4e5F6" * 3 + '";',
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
    if rule_id == "SUPABASE-MIGRATION-RLS":
        from chinescan.core.orchestration.code_rules import migration_rls_findings

        assert rule_id in {item.rule_id for item in migration_rls_findings(root)}
        later_migration = root / "supabase" / "migrations" / "002_rls.sql"
        later_migration.write_text(
            "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;", encoding="utf-8"
        )
        assert rule_id not in {item.rule_id for item in migration_rls_findings(root)}
    else:
        assert rule_id in {
            item.rule_id for item in analyze_source(root, path, positive, is_test=False)
        }
        assert rule_id not in {
            item.rule_id for item in analyze_source(root, path, negative, is_test=False)
        }


def test_rls_state_resolves_benchmark_tables_across_ordered_migrations(tmp_path: Path) -> None:
    from chinescan.core.orchestration.code_rules import migration_rls_findings

    migrations = tmp_path / "supabase" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "20250101_create.sql").write_text(
        "CREATE TABLE public.device_pairings (id int);\n"
        "CREATE TABLE public.child_devices (id int);",
        encoding="utf-8",
    )
    (migrations / "20250102_security.sql").write_text(
        "ALTER TABLE public.device_pairings ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.child_devices ENABLE ROW LEVEL SECURITY;",
        encoding="utf-8",
    )
    findings = migration_rls_findings(tmp_path)
    assert not [item for item in findings if item.rule_id == "SUPABASE-MIGRATION-RLS"]


def test_rls_policy_text_flags_permissive_and_accepts_scoped_policy(tmp_path: Path) -> None:
    from chinescan.core.orchestration.code_rules import migration_rls_findings

    migrations = tmp_path / "supabase" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "001_public_policy.sql").write_text(
        "CREATE TABLE public.notes (id int, user_id uuid);\n"
        "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY notes_public ON public.notes FOR SELECT TO anon USING (true);",
        encoding="utf-8",
    )
    findings = migration_rls_findings(tmp_path)
    policy = next(item for item in findings if item.rule_id == "SUPABASE-POLICY-PERMISSIVE")
    assert policy.verdict.value == "likely"
    assert "USING (true)" in policy.code_excerpt

    (migrations / "001_public_policy.sql").write_text(
        "CREATE TABLE public.notes (id int, user_id uuid);\n"
        "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY notes_owner ON public.notes FOR SELECT TO authenticated "
        "USING (auth.uid() = user_id);",
        encoding="utf-8",
    )
    assert not migration_rls_findings(tmp_path)

    (migrations / "001_public_policy.sql").write_text(
        "CREATE TABLE public.notes (id int, user_id uuid);\n"
        "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY notes_service ON public.notes FOR ALL TO service_role USING (true);",
        encoding="utf-8",
    )
    informational = migration_rls_findings(tmp_path)
    assert len(informational) == 1
    service_policy = informational[0]
    assert service_policy.rule_id == "SUPABASE-POLICY-SERVICE-ROLE-INFO"
    assert service_policy.severity.value == "info"
    assert service_policy.verdict.value == "confirmed"
    assert "informational" in service_policy.description
    assert "anon and authenticated roles" in service_policy.verification_step


def test_rls_state_tracks_grants_revokes_and_dropped_recreated_tables(
    tmp_path: Path,
) -> None:
    from chinescan.core.orchestration.code_rules import migration_rls_findings

    migrations = tmp_path / "supabase" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "001_initial.sql").write_text(
        "CREATE TABLE public.device_pairings (id int);\n"
        "ALTER TABLE public.device_pairings ENABLE ROW LEVEL SECURITY;\n"
        "GRANT ALL ON TABLE public.device_pairings TO anon;\n",
        encoding="utf-8",
    )
    (migrations / "002_recreate.sql").write_text(
        "DROP TABLE public.device_pairings;\n"
        "CREATE TABLE public.device_pairings (id int);\n"
        "GRANT ALL ON TABLE public.device_pairings TO service_role;\n",
        encoding="utf-8",
    )

    findings = migration_rls_findings(tmp_path)
    assert len(findings) == 1
    service_info = findings[0]
    assert service_info.rule_id == "SUPABASE-TABLE-SERVICE-ROLE-INFO"
    assert service_info.severity.value == "info"
    assert service_info.verdict.value == "confirmed"
    assert "service_role" in service_info.description

    (migrations / "003_client_grant.sql").write_text(
        "GRANT SELECT ON TABLE public.device_pairings TO authenticated;\n",
        encoding="utf-8",
    )
    findings = migration_rls_findings(tmp_path)
    assert [item.rule_id for item in findings] == ["SUPABASE-MIGRATION-RLS"]

    (migrations / "004_revoke_client.sql").write_text(
        "REVOKE SELECT ON TABLE public.device_pairings FROM authenticated;\n",
        encoding="utf-8",
    )
    findings = migration_rls_findings(tmp_path)
    assert [item.rule_id for item in findings] == ["SUPABASE-TABLE-SERVICE-ROLE-INFO"]


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


def test_dart_secret_storage_tls_logging_and_firebase_classification(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    path = root / "lib" / "main.dart"
    path.parent.mkdir(parents=True)
    firebase = "const apiKey = 'AIza" + "A" * 35 + "';"
    text = (
        "final prefs = await SharedPreferences.getInstance();\n"
        "await prefs.setString('access_token', token);\n"
        "client.badCertificateCallback = (_, __, ___) => true;\n"
        "debugPrint(accessToken);\n"
        + firebase
    )
    findings = analyze_source(root, path, text, is_test=False)
    by_id = {item.rule_id: item for item in findings}
    assert {
        "DART-INSECURE-TOKEN-STORAGE",
        "DART-CERTIFICATE-CHECK-DISABLED",
        "DART-SENSITIVE-LOGGING",
        "FIREBASE-API-KEY-INFO",
    } <= set(by_id)
    assert by_id["FIREBASE-API-KEY-INFO"].severity.value == "info"
    assert "HARDCODED-SECRET-SHAPE" not in by_id
    assert "not, by itself, an authentication secret" in (
        by_id["FIREBASE-API-KEY-INFO"].project_impact
    )

    mitigated = (
        "final secure = FlutterSecureStorage();\n"
        "await secure.write(key: 'access_token', value: token);\n"
        "client.badCertificateCallback = (_, __, ___) => false;\n"
        "debugPrint('Authentication completed');"
    )
    assert not {
        "DART-INSECURE-TOKEN-STORAGE",
        "DART-CERTIFICATE-CHECK-DISABLED",
        "DART-SENSITIVE-LOGGING",
    } & {item.rule_id for item in analyze_source(root, path, mitigated, is_test=False)}


def test_android_export_backup_and_network_config_controls(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    manifest = root / "app" / "src" / "main" / "AndroidManifest.xml"
    manifest.parent.mkdir(parents=True)
    exposed = (
        '<manifest><application android:allowBackup="true">'
        '<activity android:name=".MainActivity" android:exported="true"/>'
        "</application></manifest>"
    )
    findings = analyze_source(root, manifest, exposed, is_test=False)
    by_id = {item.rule_id: item for item in findings}
    assert "ANDROID-ALLOW-BACKUP" in by_id
    assert "ANDROID-EXPORTED-NO-PERMISSION" in by_id
    assert by_id["ANDROID-ALLOW-BACKUP"].verdict.value == "confirmed"

    broad = (
        '<manifest><application><activity android:name=".LinkActivity" android:exported="true">'
        "<intent-filter><action android:name=\"android.intent.action.VIEW\"/>"
        "<category android:name=\"android.intent.category.BROWSABLE\"/>"
        '<data android:scheme="https"/></intent-filter></activity></application></manifest>'
    )
    broad_findings = analyze_source(root, manifest, broad, is_test=False)
    broad_finding = next(
        item for item in broad_findings if item.rule_id == "ANDROID-BROAD-INTENT-FILTER"
    )
    assert broad_finding.line_numbers == [1]
    assert broad_finding.remediation_before
    assert broad_finding.remediation_after
    assert broad_finding.verification_step

    restricted = broad.replace(
        '<data android:scheme="https"/>',
        '<data android:scheme="https" android:host="links.example.invalid"/>',
    )
    assert "ANDROID-BROAD-INTENT-FILTER" not in {
        item.rule_id for item in analyze_source(root, manifest, restricted, is_test=False)
    }
    wildcard_host = broad.replace(
        '<data android:scheme="https"/>',
        '<data android:scheme="https" android:host="*.example.invalid"/>',
    )
    assert "ANDROID-BROAD-INTENT-FILTER" in {
        item.rule_id for item in analyze_source(root, manifest, wildcard_host, is_test=False)
    }

    secure = (
        '<manifest><application android:allowBackup="false">'
        '<activity android:name=".MainActivity" android:exported="true" '
        'android:permission="com.example.SIGNATURE"/>'
        "</application></manifest>"
    )
    assert not {
        "ANDROID-ALLOW-BACKUP",
        "ANDROID-EXPORTED-NO-PERMISSION",
    } & {item.rule_id for item in analyze_source(root, manifest, secure, is_test=False)}

    inherited_permission = (
        '<manifest><application android:permission="com.example.APP">'
        '<activity android:name=".MainActivity" android:exported="true"/>'
        "</application></manifest>"
    )
    assert "ANDROID-EXPORTED-NO-PERMISSION" not in {
        item.rule_id
        for item in analyze_source(root, manifest, inherited_permission, is_test=False)
    }

    commented = (
        '<manifest><!-- <application android:allowBackup="true"/> -->'
        '<application android:allowBackup="false"/></manifest>'
    )
    assert "ANDROID-ALLOW-BACKUP" not in {
        item.rule_id for item in analyze_source(root, manifest, commented, is_test=False)
    }

    dtd_config = (
        '<!DOCTYPE manifest [<!ENTITY enabled "true">]>'
        '<manifest><application android:allowBackup="&enabled;"/></manifest>'
    )
    assert "ANDROID-ALLOW-BACKUP" not in {
        item.rule_id for item in analyze_source(root, manifest, dtd_config, is_test=False)
    }

    config = root / "app" / "src" / "main" / "res" / "xml" / "network_security_config.xml"
    config.parent.mkdir(parents=True)
    insecure = (
        '<network-security-config><base-config cleartextTrafficPermitted="true"/>'
        "</network-security-config>"
    )
    assert "ANDROID-CLEARTEXT-TRAFFIC" in {
        item.rule_id for item in analyze_source(root, config, insecure, is_test=False)
    }
    safe = (
        '<network-security-config><base-config cleartextTrafficPermitted="false"/>'
        "</network-security-config>"
    )
    assert "ANDROID-CLEARTEXT-TRAFFIC" not in {
        item.rule_id for item in analyze_source(root, config, safe, is_test=False)
    }


def test_edge_service_role_requires_auth_and_maps_both_ends(tmp_path: Path) -> None:
    from chinescan.core.orchestration.code_rules import edge_function_findings

    directory = tmp_path / "supabase" / "functions" / "pair-device"
    directory.mkdir(parents=True)
    path = directory / "index.ts"
    unguarded = (
        "Deno.serve(async (req) => {\n"
        "  const body = await req.json();\n"
        "  const key = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;\n"
        "  const admin = createClient(url, key);\n"
        "  await admin.from('pairings').insert(body);\n"
        "  return Response.json({ ok: true });\n"
        "});"
    )
    path.write_text(unguarded, encoding="utf-8")
    findings = edge_function_findings(tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DENO-SERVICE-ROLE-NO-AUTH"
    assert finding.verdict.value == "confirmed"
    assert finding.source_location.file == "supabase/functions/pair-device/index.ts"
    assert finding.source_location.line == 3
    assert finding.sink_location.line == 5
    assert finding.line_numbers == [3, 5]

    secured = unguarded.replace(
        "  const body = await req.json();",
        "  const { data: { user } } = await supabase.auth.getUser(token);\n"
        "  if (!user) return new Response('unauthorized', { status: 401 });\n"
        "  const body = await req.json();",
    )
    path.write_text(secured, encoding="utf-8")
    assert not edge_function_findings(tmp_path)

    no_database_sink = unguarded.replace("admin.from('pairings').insert(body)", "fetch('https://example.test')")
    path.write_text(no_database_sink, encoding="utf-8")
    assert not edge_function_findings(tmp_path)


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
        path.write_text("const corsPolicy = cors('*');", encoding="utf-8")
        files.append(path)
    route = tmp_path / "src/route.ts"
    route.write_text(
        "export function GET() {}\nexport function POST() {}\nexport function PUT() {}\nexport function DELETE() {}",  # noqa: E501
        encoding="utf-8",
    )
    files.append(route)
    risk = vibe_risk(SimpleNamespace(source_files=tuple(files), root=tmp_path))
    assert risk.algorithm_version == "signal-score-v2"
    assert risk.score == sum(item.contribution for item in risk.contributions)
    by_signal = {item.signal_id: item for item in risk.contributions}
    assert by_signal["tutorial_default"].raw_count == 4
    assert by_signal["tutorial_default"].effective_count == 3
    assert by_signal["tutorial_default"].contribution == 54
    assert by_signal["client_validation"].contribution == 0
    assert by_signal["client_validation"].raw_count == 0
    assert by_signal["route_handlers_without_controls"].contribution == 12
    assert risk.score == 66


def test_risk_ignores_env_reads_tests_and_prose_comments(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from chinescan.core.orchestration.code_rules import vibe_risk

    prod = tmp_path / "src" / "main.ts"
    prod.parent.mkdir(parents=True)
    prod.write_text(
        'const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");\n'
        "// in production you should validate security\n"
        "// const this is ordinary prose, not code\n",
        encoding="utf-8",
    )
    test_file = tmp_path / "tests" / "sample.ts"
    test_file.parent.mkdir()
    test_file.write_text("const admin = 'admin/admin';", encoding="utf-8")
    risk = vibe_risk(SimpleNamespace(source_files=(prod, test_file), root=tmp_path))
    assert risk.score is None
    assert risk.algorithm_version == "signal-score-v2"
    assert all(item.raw_count == 0 for item in risk.contributions)


def test_legacy_score_has_explicit_versioned_ledger(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from chinescan.core.orchestration.code_rules import vibe_risk

    risk = vibe_risk(SimpleNamespace(source_files=(), root=tmp_path))
    assert risk.score is None
    assert risk.contributions
    assert all(item.raw_count == 0 and item.contribution == 0 for item in risk.contributions)
