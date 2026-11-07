"""Built-in heuristic rules for local Python and JS/TS code assessment."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from chinescan.core.logging.redaction import redact
from chinescan.core.models.common import Confidence, EvidenceKind, Severity
from chinescan.core.models.finding import Finding, FindingExplanation, Reference
from chinescan.core.models.investigation import ScoreContribution, ScoreEvidence, VibeCodingRisk
from chinescan.core.orchestration.code_scan import make_finding

RULE_COPY: dict[str, tuple[str, str, str]] = {
    "DYNAMIC-EVAL": ("Dynamic code evaluation", "eval(request.code)", "parseData(request.code)"),
    "NODE-EXEC-INTERPOLATION": (
        "Command injection",
        "exec(`tool ${request.input}`)",
        "spawn('tool', [validatedInput])",
    ),
    "PY-SHELL": (
        "Shell command execution",
        "subprocess.run(cmd, shell=True)",
        "subprocess.run([tool, arg], shell=False)",
    ),
    "SQL-INJECTION": (
        "Unsafe SQL construction candidate",
        "query('... ' + request.id)",
        "query('... WHERE id = ?', [request.id])",
    ),
    "NOSQL-OPERATOR-INJECTION": (
        "NoSQL operator injection",
        "find({ $where: request.body })",
        "find({ active: true })",
    ),
    "PATH-TRAVERSAL": (
        "Path traversal",
        "readFile(request.query.path)",
        "readFile(resolve(SAFE_ROOT, validatedName))",
    ),
    "XSS-DANGEROUS-HTML": (
        "Cross-site scripting (XSS)",
        "element.innerHTML = userInput",
        "element.textContent = userInput",
    ),
    "API-AUTH-MISSING": (
        "API route missing authentication",
        "export async function GET() { return data; }",
        "export async function GET() { await requireUser(); return data; }",
    ),
    "IDOR-RESOURCE-ID": (
        "Resource authorization (IDOR)",
        "findById(request.params.id)",
        "findOwnedById(user.id, request.params.id)",
    ),
    "JWT-ALG-NONE": (
        "JWT accepts an unsecured algorithm",
        "verify(token, key, { algorithm: 'none' })",
        "verify(token, key, { algorithms: ['HS256'] })",
    ),
    "JWT-NO-EXPIRY": (
        "JWT without an expiry",
        "jwt.sign(payload, key)",
        "jwt.sign(payload, key, { expiresIn: '10m' })",
    ),
    "COOKIE-FLAGS": (
        "Cookie security flags",
        "res.cookie('session', token)",
        "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' })",
    ),
    "CSRF-DISABLED": (
        "CSRF protection disabled",
        "csrfProtection = false",
        "csrfProtection = true",
    ),
    "HARDCODED-CREDENTIAL": (
        "Hardcoded credential",
        "setting = literal_value",
        "setting = read_secret_store()",
    ),
    "NEXT-PUBLIC-SECRET": (
        "Public-prefixed sensitive-name reference",
        "NEXT_PUBLIC_API_KEY",
        "Verify key privilege and actual client use",
    ),
    "CORS-WILDCARD-CREDENTIALS": (
        "Credentialed wildcard CORS",
        "origin: '*', credentials: true",
        "origin: TRUSTED_ORIGINS, credentials: true",
    ),
    "MISSING-SECURITY-HEADERS": (
        "Missing web security headers",
        "app = express()",
        "app.use(helmet())",
    ),
    "TLS-VERIFY-DISABLED": (
        "TLS certificate verification disabled",
        "rejectUnauthorized: false",
        "rejectUnauthorized: true",
    ),
    "VERBOSE-ERROR-EXPOSURE": (
        "Internal error details exposed",
        "res.json(error.stack)",
        "res.json({ error: 'Request failed' })",
    ),
    "OPEN-REDIRECT": (
        "Unvalidated redirect",
        "redirect(request.query.next)",
        "redirect(allowlistedPath(request.query.next))",
    ),
    "SSRF-USER-URL": (
        "Server-side request forgery (SSRF)",
        "fetch(request.query.url)",
        "fetch(allowlistedUrl(request.query.url))",
    ),
    "REQUEST-NO-SCHEMA": (
        "Request input without schema validation",
        "const body = request.body",
        "const body = schema.parse(request.body)",
    ),
    "LOGIN-NO-RATE-LIMIT": (
        "Login or contact route without rate limiting",
        "async function login(req) { ... }",
        "async function login(req) { await limiter.check(req); ... }",
    ),
    "UPLOAD-NO-CHECKS": (
        "File upload without type or size checks",
        "multer()",
        "multer({ limits: { fileSize: MAX }, fileFilter })",
    ),
    "EMPTY-CATCH": (
        "Exception silently discarded",
        "try { work(); } catch (error) {}",
        "try { work(); } catch (error) { reportSafe(error); }",
    ),
    "SWALLOWED-PROMISE": (
        "Promise rejection silently discarded",
        "task.catch(() => {})",
        "task.catch((error) => reportSafe(error))",
    ),
    "ASYNC-ROUTE-ERROR": (
        "Async route needs error handling",
        "export async function GET() { return work(); }",
        "export async function GET() { try { return work(); } catch { return safeError(); } }",
    ),
    "SENSITIVE-CONSOLE-LOG": (
        "Sensitive value written to console",
        "console.log(token)",
        "console.log('request completed')",
    ),
    "SECURITY-TODO": (
        "Unresolved security TODO",
        "// TODO add auth check",
        "// Authentication enforced by requireUser()",
    ),
    "CLIENT-COMPONENT-SECRET": (
        "Secret used in a client component",
        "'use client'; process.env.APP_SECRET",
        "// Read APP_SECRET in a server-only module",
    ),
}

RULE_TITLES = {rule_id: copy[0] for rule_id, copy in RULE_COPY.items()}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: Confidence
    cwe: str
    description: str
    remediation: str
    example_before: str
    example_after: str
    exposure: str = "server"
    review: bool = False


def _rule(
    rule_id: str,
    pattern: str,
    severity: Severity,
    cwe: str,
    description: str,
    remediation: str,
    *,
    confidence: Confidence = Confidence.LIKELY,
    exposure: str = "server",
    flags: int = re.IGNORECASE,
    review: bool = False,
) -> Rule:
    title, before, after = RULE_COPY[rule_id]
    return Rule(
        rule_id=rule_id,
        title=title,
        pattern=re.compile(pattern, flags),
        severity=severity,
        confidence=confidence,
        cwe=cwe,
        description=description,
        remediation=remediation,
        example_before=before,
        example_after=after,
        exposure=exposure,
        review=review,
    )


RULES: tuple[Rule, ...] = (
    _rule(
        "DYNAMIC-EVAL",
        r"\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*(?:req|request|input|user|code|script|source)\w*",  # noqa: E501
        Severity.HIGH,
        "CWE-95",
        "A non-literal value is evaluated as code and may cross a code-injection boundary.",
        "Remove dynamic evaluation. Use a fixed dispatch table or parse data with a safe parser.",
        exposure="client/server",
    ),
    _rule(
        "NODE-EXEC-INTERPOLATION",
        r"\b(?:exec|execSync|execFile|spawn)\s*\([^\n]*(?:\$\{|\+\s*(?:req|request|input|user))",
        Severity.HIGH,
        "CWE-78",
        "A process command appears to include dynamically constructed input.",
        "Use an argument array with a fixed executable and validate each argument; avoid shell parsing.",  # noqa: E501
    ),
    _rule(
        "PY-SHELL",
        r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^\n]*\bshell\s*=\s*True",
        Severity.HIGH,
        "CWE-78",
        "A subprocess is invoked through a shell, which can interpret attacker-controlled metacharacters.",  # noqa: E501
        "Pass an argument list with shell=False and validate arguments against an allowlist.",
    ),
    _rule(
        "SQL-INJECTION",
        r"(?:query|execute|raw|\$queryRawUnsafe)\s*\(",
        Severity.HIGH,
        "CWE-89",
        "A database query call appears to build SQL text with dynamic data; verify the query API and input source.",  # noqa: E501
        "Use the database API's bound parameters. Review the exact query and its input source before changing code.",  # noqa: E501
        confidence=Confidence.POSSIBLE,
        exposure="unknown",
        review=True,
    ),
    _rule(
        "NOSQL-OPERATOR-INJECTION",
        r"(?:\$where|\$ne|\$gt|\$regex)\s*[:=].{0,100}(?:req\.|request\.|body|query|params)",
        Severity.HIGH,
        "CWE-943",
        "A database operator may be controlled by request data.",
        "Validate input against a typed schema and construct query operators server-side.",
    ),
    _rule(
        "PATH-TRAVERSAL",
        r"\b(?:readFile|readFileSync|createReadStream|open|sendFile)\s*\([^\n]*(?:req\.(?:query|params|body)|request\.(?:args|form|json)|\buser_input)",  # noqa: E501
        Severity.HIGH,
        "CWE-22",
        "A filesystem path appears to include request-controlled input.",
        "Resolve against a fixed allowed directory and reject paths that escape it.",
    ),
    _rule(
        "XSS-DANGEROUS-HTML",
        r"dangerouslySetInnerHTML\s*=|\.innerHTML\s*=\s*(?:req|request|user|input|data|response)\w*|document\.write\s*\(\s*(?:req|request|user|input|data|response)\w*",  # noqa: E501
        Severity.HIGH,
        "CWE-79",
        "HTML is inserted into a browser sink without evidence of context-safe encoding.",
        "Render text normally or sanitize HTML with a maintained allowlist sanitizer.",
        exposure="client",
        review=True,
    ),
    _rule(
        "API-AUTH-MISSING",
        r"(?:export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)|app\.(?:get|post|put|patch|delete)\s*\(|@(?:app|router)\.(?:get|post|put|patch|delete))",  # noqa: E501
        Severity.HIGH,
        "CWE-862",
        "A route handler has no recognizable authentication guard in this file; verify the shared middleware.",  # noqa: E501
        "Require authentication and authorization before reading or changing protected resources.",
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "IDOR-RESOURCE-ID",
        r"(?:find(?:Unique|First|One|ById)|get|load)\w*\s*\([^\n]*(?:req\.(?:params|query)|request\.(?:params|query)|params\.)",  # noqa: E501
        Severity.HIGH,
        "CWE-639",
        "A resource lookup uses a request-supplied identifier; ownership checks need manual verification.",  # noqa: E501
        "Scope the lookup to the authenticated principal or check ownership before returning the record.",  # noqa: E501
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "JWT-ALG-NONE",
        r"(?:algorithm|algorithms)\s*[:=]\s*['\"]none['\"]",
        Severity.HIGH,
        "CWE-347",
        "A JWT algorithm option names `none`; verify whether this configures token verification or only signing, test code, or documentation.",  # noqa: E501
        "Pin an approved verification algorithm if this option controls JWT verification.",
        confidence=Confidence.POSSIBLE,
        exposure="unknown",
        review=True,
    ),
    _rule(
        "JWT-NO-EXPIRY",
        r"jwt\.sign\s*\([^\n]*\)",
        Severity.MEDIUM,
        "CWE-613",
        "A JWT signing call has no visible expiry option on this line; confirm token lifetime configuration.",  # noqa: E501
        "Set a short `expiresIn` and rotate or revoke tokens when credentials change.",
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "COOKIE-FLAGS",
        r"(?:setCookie|cookies?\.set|res\.cookie)\s*\([^\n]*",
        Severity.MEDIUM,
        "CWE-614",
        "Cookie options may omit one or more of HttpOnly, Secure, or SameSite.",
        "Set httpOnly, secure, and sameSite explicitly; verify options passed on adjacent lines.",
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "CSRF-DISABLED",
        r"(?:csrf|xsrf)[^\n]{0,80}(?:false|disabled|ignore)",
        Severity.HIGH,
        "CWE-352",
        "CSRF protection appears disabled or bypassed.",
        "Enable CSRF protection for cookie-authenticated state-changing requests.",
    ),
    _rule(
        "HARDCODED-CREDENTIAL",
        r"(?i)\b(?:password|passwd|api[_-]?key|secret|access[_-]?token|private[_-]?key)\b\s*[:=]\s*(['\"])(?!\s*(?:\$\{|process\.env|os\.environ))[^'\"]{4,}\1",  # noqa: E501
        Severity.HIGH,
        "CWE-798",
        "A credential-like literal is present; its value is redacted in this report.",
        "Move the value to a secret store or environment variable and rotate it if it was committed.",  # noqa: E501
    ),
    _rule(
        "NEXT-PUBLIC-SECRET",
        r"NEXT_PUBLIC_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)",
        Severity.MEDIUM,
        "CWE-540",
        "A public-prefixed variable has a sensitive-sounding name. The name does not establish that its value is privileged or unsafe to expose.",  # noqa: E501
        "Verify credential type, runtime use, and access policy before changing the variable or its placement.",  # noqa: E501
        confidence=Confidence.POSSIBLE,
        exposure="client",
        review=True,
    ),
    _rule(
        "CORS-WILDCARD-CREDENTIALS",
        r"(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*['\"]\*['\"][^\n]*(?:credentials|allowCredentials)\s*[:=]\s*true|(?:credentials|allowCredentials)\s*[:=]\s*true[^\n]*(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*['\"]\*['\"]",  # noqa: E501
        Severity.HIGH,
        "CWE-942",
        "CORS appears to combine wildcard origins with credentials.",
        "Use an explicit origin allowlist and enable credentials only for trusted origins.",
    ),
    _rule(
        "MISSING-SECURITY-HEADERS",
        r"(?:headers\s*(?:\(|:|=)|headers\.set\s*\(|securityHeaders)",
        Severity.MEDIUM,
        "CWE-693",
        "A relevant project header configuration was found; some expected policy values were not recognizable in that configuration.",  # noqa: E501
        "Review effective response headers in the deployment environment and complete the project-level policy where appropriate.",  # noqa: E501
        confidence=Confidence.POSSIBLE,
        exposure="unknown",
        review=True,
    ),
    _rule(
        "TLS-VERIFY-DISABLED",
        r"(?:verify|rejectUnauthorized)\s*[:=]\s*False|rejectUnauthorized\s*:\s*false",
        Severity.HIGH,
        "CWE-295",
        "TLS certificate verification is disabled.",
        "Restore certificate verification and fix the trust configuration instead.",
    ),
    _rule(
        "VERBOSE-ERROR-EXPOSURE",
        r"(?:json|send|Response\.json)\s*\([^\n]*(?:err|error)\.(?:message|stack)",
        Severity.MEDIUM,
        "CWE-209",
        "An error object may be returned to a client and disclose internal details.",
        "Return a generic client error and keep redacted diagnostics in server logs.",
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "OPEN-REDIRECT",
        r"(?:redirect|location)\s*\([^\n]*(?:req\.|request\.|searchParams|query\.)",
        Severity.MEDIUM,
        "CWE-601",
        "A redirect target appears to come from request data.",
        "Allow only relative paths or destinations from a strict hostname allowlist.",
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "SSRF-USER-URL",
        r"\bfetch\s*\([^\n]*(?:req\.|request\.|body\.|query\.|params\.)",
        Severity.HIGH,
        "CWE-918",
        "A server-side fetch target appears to use request-supplied data.",
        "Validate scheme and host against an allowlist and block private or link-local destinations.",  # noqa: E501
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "REQUEST-NO-SCHEMA",
        r"(?:request\.json\(|req\.body|request\.body)",
        Severity.MEDIUM,
        "CWE-20",
        "Request data is read in a route without a recognizable Zod or Yup schema in this file.",
        "Validate request data with a server-side schema before using it.",
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "LOGIN-NO-RATE-LIMIT",
        r"(?:function\s+(?:login|signIn|contact|forgotPassword|resetPassword)|(?:const|let)\s+(?:login|signIn|contact|forgotPassword|resetPassword)\s*=|export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE))",  # noqa: E501
        Severity.MEDIUM,
        "CWE-307",
        "A request-handler candidate was found without a recognizable same-file rate-limit call. Shared controls may not be visible here.",  # noqa: E501
        "Verify the effective server-side rate limit for this handler and its deployment before changing it.",  # noqa: E501
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "UPLOAD-NO-CHECKS",
        r"(?:File\(|multer\(|upload\.single|request\.formData\(|multipart/form-data)",
        Severity.MEDIUM,
        "CWE-434",
        "An upload path is present; type and size enforcement need verification.",
        "Enforce size limits and inspect content type and file signatures before storage.",
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "EMPTY-CATCH",
        r"catch\s*(?:\([^)]*\))?\s*\{\s*\}|except\s*(?:[^:]+)?\s*:\s*(?:pass\s*)?$",
        Severity.LOW,
        "CWE-390",
        "An exception is caught and discarded.",
        "Handle the expected failure explicitly or record a safe, useful diagnostic.",
        confidence=Confidence.LIKELY,
    ),
    _rule(
        "SWALLOWED-PROMISE",
        r"\.catch\s*\(\s*(?:\(\s*\)\s*=>\s*\{\s*\}|\(\s*\w+\s*\)\s*=>\s*(?:null|undefined|void\s+0))",  # noqa: E501
        Severity.MEDIUM,
        "CWE-755",
        "A rejected promise appears to be silently discarded.",
        "Handle the rejection or surface a safe failure state to the caller.",
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "ASYNC-ROUTE-ERROR",
        r"export\s+async\s+function\s+(?:GET|POST|PUT|PATCH|DELETE)",
        Severity.LOW,
        "CWE-703",
        "An asynchronous route handler needs an explicit error boundary or framework guarantee.",
        "Catch expected failures and return a bounded client response; verify framework error handling.",  # noqa: E501
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "SENSITIVE-CONSOLE-LOG",
        r"console\.log\s*\([^\n]*(?:password|token|secret|authorization|cookie)",
        Severity.MEDIUM,
        "CWE-532",
        "A console log appears to include sensitive data.",
        "Remove the log or redact sensitive fields before writing diagnostics.",
    ),
    _rule(
        "SECURITY-TODO",
        r"(?:TODO|FIXME|HACK).{0,100}(?:auth|security|sanitize|validate|csrf|secret|permission|production)",  # noqa: E501
        Severity.LOW,
        "CWE-710",
        "A comment leaves a security-related task unresolved.",
        "Resolve the security note and add a regression test before release.",
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "CLIENT-COMPONENT-SECRET",
        r"process\.env\.[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD)",
        Severity.HIGH,
        "CWE-200",
        "A client-component source line references a secret-like environment variable. Runtime inclusion and value privilege are not established.",  # noqa: E501
        "Verify whether the value is privileged and included in a production client bundle before changing its use.",  # noqa: E501
        confidence=Confidence.POSSIBLE,
        exposure="client",
        review=True,
    ),
)


def _excerpt(line: str) -> str:
    cleaned = str(redact(line.strip()))
    return cleaned[:160]


def _source_line(text: str, number: int) -> str:
    lines = text.splitlines()
    return _excerpt(lines[number - 1]) if 1 <= number <= len(lines) else ""


def _match_confidence(rule: Rule, snippets: list[str], *, is_test: bool) -> Confidence:
    if is_test and rule.rule_id == "HARDCODED-CREDENTIAL":
        return Confidence.POSSIBLE
    if rule.rule_id == "HARDCODED-CREDENTIAL":
        return Confidence.LIKELY
    combined = "\n".join(snippets)
    if rule.rule_id == "DYNAMIC-EVAL":
        if re.search(r"eval\s*\(\s*(?:request|req|user|input|body|query|params)\b", combined, re.I):
            return Confidence.LIKELY
        return Confidence.POSSIBLE
    if rule.rule_id == "XSS-DANGEROUS-HTML":
        if re.search(
            r"\.innerHTML\s*=\s*(?:req|request|user|input|data|response)\w*", combined, re.I
        ):
            return Confidence.LIKELY
        if re.search(r"__html\s*:\s*(?!['\"`])[A-Za-z_$][\w$]*", combined):
            return Confidence.LIKELY
        return Confidence.POSSIBLE
    direct_flow_rules = {
        "NODE-EXEC-INTERPOLATION",
        "XSS-DANGEROUS-HTML",
        "OPEN-REDIRECT",
        "SSRF-USER-URL",
    }
    if rule.rule_id in direct_flow_rules and re.search(
        r"(?:request|req|user|input|body|query|params|searchParams)", combined, re.I
    ):
        return Confidence.LIKELY
    return Confidence.POSSIBLE if rule.review else rule.confidence


_SQL_SINK = re.compile(
    r"\b(?:db|database|conn|connection|cursor|pool|client|sequelize|knex|prisma|sql|transaction)"
    r"\s*\.\s*(?:query|execute|raw|\$queryRawUnsafe)\s*\(",
    re.I,
)
_SQL_VERB = re.compile(
    r"^\s*(?:[rubf]{0,2}\s*)?['\"`]\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b", re.I
)
_SQL_UNSAFE = re.compile(r"(?:\$\{|\bf['\"]|\s\+\s*[A-Za-z_$]|\.format\s*\(|%\s*[A-Za-z_(])", re.I)


def _mask_comments(text: str, suffix: str) -> str:
    """Blank ordinary comments while preserving offsets and literal contents."""
    chars = list(text)
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in "'\"`":
            quote = char
            index += 1
            continue
        comment_end = None
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            comment_end = len(text) if end < 0 else end + 2
        elif text.startswith("//", index) and suffix.lower() not in {".py", ".pyi"}:
            end = text.find("\n", index + 2)
            comment_end = len(text) if end < 0 else end
        elif char == "#" and suffix.lower() in {".py", ".pyi"}:
            end = text.find("\n", index + 1)
            comment_end = len(text) if end < 0 else end
        if comment_end is not None:
            for position in range(index, comment_end):
                if chars[position] != "\n":
                    chars[position] = " "
            index = comment_end
            continue
        index += 1
    return "".join(chars)


def _mask_literals(text: str) -> str:
    """Blank quoted literal bodies so code-shaped text in strings is not a call site."""
    chars = list(text)
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if char not in "\r\n":
                chars[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "'\"`":
            quote = char
            chars[index] = " "
    return "".join(chars)


def _call_end(text: str, open_paren: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(open_paren, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return len(text)


def _sql_unsafe_calls(text: str, suffix: str) -> list[tuple[int, str, bool]]:
    """Find direct unsafe SQL construction at a small set of recognizable DB sinks."""
    uncommented = _mask_comments(text, suffix)
    syntax = _mask_literals(uncommented)
    found: list[tuple[int, str, bool]] = []
    for sink in _SQL_SINK.finditer(syntax):
        open_paren = sink.end() - 1
        close_paren = _call_end(uncommented, open_paren)
        arguments = uncommented[open_paren + 1 : close_paren]
        first_argument = arguments.split(",", 1)[0]
        if not _SQL_VERB.search(first_argument):
            continue
        # Bound placeholders without SQL string interpolation are an explicit safe control.
        has_bound_marker = bool(re.search(r"\?|\$\d+|:\w+|%s\b|%\(\w+\)s", first_argument))
        has_bound_values = "," in arguments
        has_direct_interpolation = bool(
            re.search(r"\$\{|\bf['\"]|\s\+\s*[A-Za-z_$]|\.format\s*\(", first_argument, re.I)
        )
        if has_bound_marker and has_bound_values and not has_direct_interpolation:
            continue
        if not _SQL_UNSAFE.search(first_argument):
            continue
        input_known = bool(
            re.search(r"\b(?:req|request|user|body|params|searchParams)\b", arguments, re.I)
        )
        found.append((sink.start(), sink.group(0).strip(), input_known))
    if suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        prisma_tag = re.compile(r"\bprisma\s*\.\s*\$queryRaw\b", re.I)
        for sink in prisma_tag.finditer(syntax):
            backtick = sink.end()
            while backtick < len(uncommented) and uncommented[backtick].isspace():
                backtick += 1
            if backtick >= len(uncommented) or uncommented[backtick] != "`":
                continue
            end = uncommented.find("`", backtick + 1)
            if end < 0:
                continue
            template = uncommented[backtick : end + 1]
            if not _SQL_VERB.search(template) or not re.search(r"\$\{", template):
                continue
            input_known = bool(
                re.search(r"\b(?:req|request|user|body|params|searchParams)\b", template, re.I)
            )
            found.append((sink.start(), "prisma.$queryRaw template", input_known))
    return found


def _header_config_candidate(relative: str) -> bool:
    name = Path(relative).name.casefold()
    return name.startswith("next.config.") or name in {
        "middleware.ts",
        "middleware.js",
        "middleware.mjs",
    }


def _cookie_call_has_flags(text: str, call: str) -> bool:
    invocation = re.search(r"(?:setCookie|cookies?\.set|res\.cookie)\s*\(", call, re.I)
    if not invocation:
        return False
    open_paren = invocation.end() - 1
    close_paren = _call_end(call, open_paren)
    arguments = call[open_paren + 1 : close_paren]
    option_text = ""
    object_match = re.search(r"\{([^{}]{0,1000})\}", arguments, re.S)
    if object_match:
        option_text = object_match.group(1)
    else:
        pieces = arguments.split(",")
        if len(pieces) >= 3:
            name_match = re.search(r"\b([A-Za-z_$][\w$]*)\s*$", pieces[-1])
            if name_match:
                variable = re.escape(name_match.group(1))
                definition = re.search(
                    rf"\b(?:const|let|var)\s+{variable}\s*=\s*\{{([^{{}}]{{0,1000}})\}}",
                    text,
                    re.S,
                )
                option_text = definition.group(1) if definition else ""
    secure = bool(re.search(r"\bsecure\s*:\s*true\b", option_text, re.I))
    http_only = bool(re.search(r"\bhttpOnly\s*:\s*true\b", option_text, re.I))
    same_site = bool(
        re.search(r"\bsameSite\s*:\s*['\"](?:strict|lax|none)['\"]", option_text, re.I)
    )
    return secure and http_only and same_site


def _specific_explanation(
    rule: Rule,
    relative: str,
    text: str,
    line_numbers: list[int],
    *,
    severity: Severity,
    confidence: Confidence,
    sql_input_known: bool = False,
) -> FindingExplanation | None:
    snippets = [_source_line(text, number) for number in line_numbers]
    excerpt = " | ".join(dict.fromkeys(snippets))[:360]
    if rule.rule_id == "SQL-INJECTION":
        return FindingExplanation(
            observed=excerpt,
            match_reason="A recognized database query call contains SQL text and direct dynamic construction.",  # noqa: E501
            established=["A database-like query method and SQL statement text appear together."]
            + (
                ["A request-like identifier appears in the query arguments."]
                if sql_input_known
                else []
            ),
            inferred=["The dynamic value may alter the SQL statement."]
            + ([] if sql_input_known else ["Input provenance is unknown."]),
            severity_rationale="High describes potential impact if unsafe SQL reaches a database with attacker-controlled data; exploitability was not tested.",  # noqa: E501
            confidence_rationale="Possible: static matching found an SQL sink and interpolation/concatenation, but did not prove taint or runtime execution.",  # noqa: E501
            exposure_rationale="The source uses a database-like API; deployment exposure is not established.",  # noqa: E501
            attack_prerequisites=[
                "The value must be influenced by an attacker and reach this query without safe parameter binding."  # noqa: E501
            ],
            conditional_impact="If those conditions hold, query integrity or confidentiality could be affected.",  # noqa: E501
            false_positive_considerations=[
                "Custom query wrappers, safe query builders, or trusted constant values may not be resolved."  # noqa: E501
            ],
            verification_steps=[
                "Inspect the database API documentation and the complete call.",
                "Trace the value source and confirm whether the API binds parameters.",
            ],
            remediation_rationale="Parameter binding is appropriate only if this call is confirmed to execute dynamic SQL.",  # noqa: E501
            limitations=[
                "Heuristic only; no AST, inter-file taint analysis, database execution, or exploit verification."  # noqa: E501
            ],
            ruleset_version="builtin-2",
            classification_policy_version="static-impact-v1",
        )
    if rule.rule_id == "JWT-ALG-NONE":
        return FindingExplanation(
            observed=excerpt,
            match_reason="A JWT algorithm option contains the literal `none`.",
            established=["The inspected source includes a JWT-related algorithm option."],
            inferred=["The option may permit unsigned-token verification if used in a verifier."],
            severity_rationale="High is the potential impact if the option controls verification of security-sensitive tokens; a keyword match alone does not establish that behavior.",  # noqa: E501
            confidence_rationale="Possible: this is a local text match without API-role, runtime, or token-validation analysis.",  # noqa: E501
            exposure_rationale="Runtime reachability and token audience are not established within the inspected scope.",  # noqa: E501
            attack_prerequisites=[
                "The option must be used for verification, and an attacker must be able to submit a token accepted by a protected operation."  # noqa: E501
            ],
            conditional_impact="If an unsigned token is accepted for a protected identity, an attacker could impersonate a principal.",  # noqa: E501
            false_positive_considerations=[
                "The text may configure signing, be test/documentation content, or not affect the active verifier."  # noqa: E501
            ],
            verification_steps=[
                "Trace the option to the JWT verification call.",
                "Use a local test to confirm whether an unsigned token is rejected.",
            ],
            remediation_rationale="Pin an approved algorithm only after confirming that this option affects verification.",  # noqa: E501
            limitations=[
                "No AST, framework call graph, runtime token test, or exploit verification is performed."  # noqa: E501
            ],
            ruleset_version="builtin-2",
            classification_policy_version="static-impact-v1",
        )
    if rule.rule_id == "NEXT-PUBLIC-SECRET":
        return FindingExplanation(
            observed=excerpt,
            match_reason="A NEXT_PUBLIC-prefixed variable name ends in a credential-like suffix.",
            established=[
                "The source contains a public-prefixed name with a key/token/secret-like suffix."
            ],
            inferred=[
                "The name may refer to a sensitive value; its privileges and actual client use are unknown."  # noqa: E501
            ],
            severity_rationale="Medium is a review priority for a credential-like public configuration name, not a claim that a privileged secret is exposed.",  # noqa: E501
            confidence_rationale="Possible: classification is based on the variable name, not on the value or an observed production bundle.",  # noqa: E501
            exposure_rationale="The framework prefix suggests public client configuration; actual inclusion was not verified.",  # noqa: E501
            conditional_impact="If the value grants privileged access and reaches an untrusted client, that access could be misused. Public/anonymous identifiers may be intentionally client-visible.",  # noqa: E501
            false_positive_considerations=[
                "Public or anonymous provider keys can be designed for client use; a variable name alone does not establish privilege."  # noqa: E501
            ],
            verification_steps=[
                "Identify the credential class without copying its value into logs.",
                "Review provider permissions and access policies.",
                "Check production build references locally.",
            ],
            remediation_rationale="Do not move an intentionally public key without evidence that it has privileged permissions.",  # noqa: E501
            limitations=[
                "Access policies, credential privileges, and deployment bundles were not inspected."
            ],
            ruleset_version="builtin-2",
            classification_policy_version="static-impact-v1",
        )
    if rule.rule_id == "CLIENT-COMPONENT-SECRET":
        return FindingExplanation(
            observed=excerpt,
            match_reason="The file contains a client-component directive and a secret-like environment variable reference.",  # noqa: E501
            established=[
                "A secret-like environment variable name appears in a file containing a client directive."  # noqa: E501
            ],
            inferred=[
                "The value could be exposed if included in a client bundle; inclusion and privilege are unresolved."  # noqa: E501
            ],
            severity_rationale="High reflects potential impact for a privileged value shipped to a client; no such value was verified.",  # noqa: E501
            confidence_rationale="Possible: source naming and client directive were matched, without build-output or privilege analysis.",  # noqa: E501
            exposure_rationale="Client-component source context is present; actual bundle exposure is not established.",  # noqa: E501
            conditional_impact="If a privileged value is bundled, users could retrieve and misuse it.",  # noqa: E501
            false_positive_considerations=[
                "Public identifiers and unreachable/test-only code may match the pattern."
            ],
            verification_steps=[
                "Check whether the variable is public by design and inspect a local production build for its use.",  # noqa: E501
                "Verify provider privileges without disclosing the value.",
            ],
            limitations=["No framework compilation or secret privilege analysis is performed."],
            ruleset_version="builtin-2",
            classification_policy_version="static-impact-v1",
        )
    if rule.rule_id == "MISSING-SECURITY-HEADERS":
        return FindingExplanation(
            observed=excerpt,
            match_reason="A recognized header configuration point was found in a Next.js config or middleware file.",  # noqa: E501
            established=["Some security-header configuration is present in the inspected file."],
            inferred=["One or more expected header names were not recognized in this file."],
            severity_rationale="Medium indicates a configuration review lead; effective response headers were not observed.",  # noqa: E501
            confidence_rationale="Possible: local configuration text was inspected, not the deployed response.",  # noqa: E501
            exposure_rationale="Project configuration scope only; the deployment layer may add headers.",  # noqa: E501
            false_positive_considerations=[
                "A hosting proxy or platform may set headers outside this repository."
            ],
            verification_steps=[
                "Inspect the framework configuration and locally authorized deployment header policy."  # noqa: E501
            ],
            limitations=["No live requests or deployment-layer inspection was performed."],
            ruleset_version="builtin-2",
            classification_policy_version="static-impact-v1",
        )
    if rule.rule_id == "LOGIN-NO-RATE-LIMIT":
        return FindingExplanation(
            observed=excerpt,
            match_reason="A handler-shaped declaration with an authentication/contact name or a route method was found.",  # noqa: E501
            established=[
                "The file contains a handler candidate and no recognizable same-file limiter token."
            ],
            inferred=[
                "The handler may lack abuse controls; shared middleware and imported helpers were not resolved."  # noqa: E501
            ],
            severity_rationale="Medium is a potential abuse-impact review level; request reachability and controls are unknown.",  # noqa: E501
            confidence_rationale="Possible: route/handler shape is heuristic and cross-file control flow is unresolved.",  # noqa: E501
            attack_prerequisites=[
                "An attacker must be able to repeatedly reach a sensitive operation without an effective shared limit."  # noqa: E501
            ],
            conditional_impact="If reachable and unprotected, repeated requests could enable guessing or resource abuse.",  # noqa: E501
            false_positive_considerations=[
                "Imported middleware or platform-level throttling may provide the control."
            ],
            verification_steps=[
                "Trace the handler's route and imported middleware; verify limits in the effective runtime."  # noqa: E501
            ],
            limitations=["No inter-file call graph or deployment policy analysis."],
            ruleset_version="builtin-2",
            classification_policy_version="static-impact-v1",
        )
    if rule.rule_id == "COOKIE-FLAGS":
        return FindingExplanation(
            observed=excerpt,
            match_reason="A cookie-setting call was observed; the call's inline or simple object options were inspected.",  # noqa: E501
            established=["The source sets or forwards a cookie."],
            inferred=[
                "Security attributes may be missing or may be supplied through an unresolved helper."  # noqa: E501
            ],
            severity_rationale="Medium is a configuration review priority; cookie purpose and runtime defaults matter.",  # noqa: E501
            confidence_rationale="Possible: the scanner resolves only nearby literal option objects and simple variables.",  # noqa: E501
            exposure_rationale="Cookie behavior is server/framework dependent and was not exercised.",  # noqa: E501
            false_positive_considerations=[
                "Framework authentication helpers may supply safe defaults or require different attributes."  # noqa: E501
            ],
            verification_steps=[
                "Resolve the options object and verify effective Set-Cookie attributes in a local test response."  # noqa: E501
            ],
            limitations=["Imported helpers and runtime framework defaults are not traced."],
            ruleset_version="builtin-2",
            classification_policy_version="static-impact-v1",
        )
    rationale = (
        "The rule is configured as a manual-review heuristic; no vulnerability verification or probability calibration is performed."  # noqa: E501
        if rule.review
        else "This is the rule's configured static severity; contextual exploitability was not evaluated."  # noqa: E501
    )
    confidence_rationale = (
        "Possible: this finding is marked for manual review by the rule configuration."
        if confidence == Confidence.POSSIBLE
        else "Confidence follows the rule's configured heuristic category; it is not a calibrated probability or proof of exploitability."  # noqa: E501
    )
    return FindingExplanation(
        observed=excerpt,
        match_reason=rule.description,
        established=[f"The {rule.rule_id} source pattern matched in this file."],
        inferred=[
            "The security condition described by the rule may be present; runtime behavior and surrounding controls were not verified."  # noqa: E501
        ],
        severity_rationale=f"{severity.value.capitalize()} is the rule's configured potential-impact label. {rationale}",  # noqa: E501
        confidence_rationale=confidence_rationale,
        exposure_rationale=f"Exposure is the rule's configured value ({rule.exposure}); it was not derived from deployment evidence.",  # noqa: E501
        conditional_impact="Impact depends on the condition described by the rule being reachable and exploitable.",  # noqa: E501
        false_positive_considerations=[
            "The match may be a non-executable example, a safe wrapper, or protected by context not analyzed by this rule."  # noqa: E501
        ],
        verification_steps=[
            "Inspect the complete code path and the controls used by the application before treating this as a vulnerability."  # noqa: E501
        ],
        remediation_rationale="The rule provides generic remediation guidance; verify applicability to this framework and code path first.",  # noqa: E501
        limitations=[
            "Static heuristic only; no execution, comprehensive AST analysis, inter-file data-flow analysis, or exploit verification."  # noqa: E501
        ],
        ruleset_version="builtin-2",
        classification_policy_version="static-impact-v1",
    )


def analyze_source(root: Path, path: Path, text: str, *, is_test: bool) -> list[Finding]:
    """Run rules and return one grouped finding per rule and file."""
    relative = path.relative_to(root).as_posix()
    lines = text.splitlines()
    matched: dict[str, tuple[Rule, list[int], list[str]]] = {}
    analysis_text = _mask_comments(text, path.suffix)
    lowered = analysis_text.lower()
    sql_input_known = False
    for rule in RULES:
        if rule.rule_id == "SQL-INJECTION":
            sql_hits = _sql_unsafe_calls(text, path.suffix)
            if not sql_hits:
                continue
            sql_input_known = any(item[2] for item in sql_hits)
            hits = [(_line_number(text, start), excerpt) for start, excerpt, _ in sql_hits]
        elif rule.rule_id == "MISSING-SECURITY-HEADERS":
            if not _header_config_candidate(relative):
                continue
            matches = list(rule.pattern.finditer(analysis_text))
            if not matches:
                continue
            required_headers = (
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
            )
            if all(header in analysis_text.casefold() for header in required_headers):
                continue
            hits = [(_line_number(text, match.start()), match.group(0)) for match in matches[:4]]
        elif rule.rule_id == "API-AUTH-MISSING":
            if not ("/api/" in relative.lower() or relative.lower().endswith("route.ts")):
                continue
            if not rule.pattern.search(analysis_text) or re.search(
                r"\b(auth|session|requireUser|currentUser|verifyToken|middleware)\b",
                analysis_text,
                re.I,
            ):
                continue
            hits = [(1, lines[0] if lines else "route handler")]
        elif rule.rule_id == "SECURITY-TODO":
            hits = [
                (_line_number(text, match.start()), match.group(0))
                for match in rule.pattern.finditer(text)
            ]
        elif rule.rule_id == "IDOR-RESOURCE-ID":
            if re.search(
                r"\b(owner|userId|user_id|authorize|authorization)\b", analysis_text, re.I
            ):
                continue
            hits = [(m.start(), m.group(0)) for m in rule.pattern.finditer(analysis_text)]
            hits = [(_line_number(text, start), code) for start, code in hits]
        elif rule.rule_id == "JWT-NO-EXPIRY":
            hits = []
            for match in rule.pattern.finditer(analysis_text):
                call = match.group(0)
                if not re.search(r"expiresIn|expires_in|exp\s*:", call, re.I):
                    hits.append((_line_number(text, match.start()), call))
        elif rule.rule_id in {
            "MISSING-SECURITY-HEADERS",
            "REQUEST-NO-SCHEMA",
            "LOGIN-NO-RATE-LIMIT",
            "UPLOAD-NO-CHECKS",
            "COOKIE-FLAGS",
        }:
            matches = list(rule.pattern.finditer(analysis_text))
            if not matches:
                continue
            if rule.rule_id == "REQUEST-NO-SCHEMA" and re.search(
                r"\b(?:zod|z\.|yup)\b", analysis_text, re.I
            ):
                continue
            if rule.rule_id == "LOGIN-NO-RATE-LIMIT":
                is_route = bool(re.search(r"(?:^|/)route\.[jt]sx?$|(?:^|/)api/", relative, re.I))
                is_named_handler = bool(
                    re.search(
                        r"(?:^|/)\w*(?:login|auth|contact|action)\w*\.[jt]sx?$", relative, re.I
                    )
                )
                if not (
                    (
                        is_route
                        and re.search(r"(?:contact|login|auth|session|account)", relative, re.I)
                    )
                    or is_named_handler
                ):
                    continue
                if (
                    not re.search(
                        r"\b(?:login|signin|contact|forgotpassword|resetpassword)\b",
                        analysis_text,
                        re.I,
                    )
                    and not is_route
                ):
                    continue
                if re.search(r"rate.?limit|throttle|limiter", analysis_text, re.I):
                    continue
            if rule.rule_id == "UPLOAD-NO-CHECKS" and re.search(
                r"(?:maxSize|fileSize|sizeLimit|contentType|mimetype|fileFilter)",
                analysis_text,
                re.I,
            ):
                continue
            if rule.rule_id == "COOKIE-FLAGS":
                matches = [
                    match for match in matches if not _cookie_call_has_flags(text, match.group(0))
                ]
                if not matches:
                    continue
            hits = [(_line_number(text, m.start()), m.group(0)) for m in matches[:4]]
        else:
            hits = [
                (_line_number(text, m.start()), m.group(0))
                for m in rule.pattern.finditer(analysis_text)
            ]
        if hits:
            matched[rule.rule_id] = (rule, [n for n, _ in hits], [code for _, code in hits])

    if "use client" in lowered:
        client_rule = next(rule for rule in RULES if rule.rule_id == "CLIENT-COMPONENT-SECRET")
        client_hits = list(client_rule.pattern.finditer(analysis_text))
        if client_hits:
            matched[client_rule.rule_id] = (
                client_rule,
                [_line_number(text, item.start()) for item in client_hits],
                [item.group(0) for item in client_hits],
            )
        else:
            matched.pop(client_rule.rule_id, None)
    else:
        matched.pop("CLIENT-COMPONENT-SECRET", None)

    findings: list[Finding] = []
    for rule, line_numbers, _matched_tokens in matched.values():
        line_numbers = sorted(set(line_numbers))
        snippets = [_source_line(text, number) for number in line_numbers]
        confidence = _match_confidence(rule, snippets, is_test=is_test)
        excerpt = " | ".join(dict.fromkeys(_excerpt(item) for item in snippets))[:360]
        if is_test and rule.rule_id == "HARDCODED-CREDENTIAL":
            description = (
                "Test file credential-like literal; verify the value is fake and not reused."
            )
        else:
            description = rule.description
        if rule.rule_id == "SQL-INJECTION" and not sql_input_known:
            description += " Input provenance is unknown."
        effective_severity = (
            Severity.MEDIUM if is_test and rule.rule_id == "HARDCODED-CREDENTIAL" else rule.severity
        )
        explanation = _specific_explanation(
            rule,
            relative,
            text,
            line_numbers,
            severity=effective_severity,
            confidence=confidence,
            sql_input_known=sql_input_known,
        )
        finding = make_finding(
            target=root,
            scanner="builtin",
            rule_id=rule.rule_id,
            title=rule.title,
            severity=effective_severity,
            category="SAST",
            confidence=confidence.value,
            location=f"{relative}:{line_numbers[0]}",
            description=description,
            evidence=EvidenceKind.PATTERN_MATCH,
            tags=["heuristic", "local"]
            + (["manual-review"] if confidence == Confidence.POSSIBLE else []),
        ).model_copy(
            update={
                "source": "builtin",
                "line_numbers": sorted(set(line_numbers)),
                "code_excerpt": excerpt,
                "remediation": (
                    f"{rule.remediation}\nBefore: {rule.example_before}\n"
                    f"After: {rule.example_after}"
                ),
                "cwe_ids": [rule.cwe],
                "exposure": rule.exposure,
                "explanation": explanation,
                "references": [
                    Reference(
                        title=rule.cwe,
                        url=f"https://cwe.mitre.org/data/definitions/{rule.cwe.removeprefix('CWE-')}.html",  # noqa: E501
                    )
                ],
            }
        )
        findings.append(finding)
    public_finding = next((item for item in findings if item.rule_id == "NEXT-PUBLIC-SECRET"), None)
    component_finding = next(
        (item for item in findings if item.rule_id == "CLIENT-COMPONENT-SECRET"), None
    )
    if public_finding and component_finding:
        public_names = set(re.findall(r"NEXT_PUBLIC_[A-Z0-9_]+", public_finding.code_excerpt or ""))
        component_names = set(
            re.findall(r"process\.env\.([A-Z0-9_]+)", component_finding.code_excerpt or "")
        )
        shared_lines = set(public_finding.line_numbers) & set(component_finding.line_numbers)
        if public_names & component_names and shared_lines:
            merged = public_finding.model_copy(
                update={
                    "contributing_rule_ids": ["NEXT-PUBLIC-SECRET", "CLIENT-COMPONENT-SECRET"],
                    "line_numbers": sorted(shared_lines),
                    "code_excerpt": _excerpt(_source_line(text, min(shared_lines))),
                }
            )
            findings = [
                item
                for item in findings
                if item is not public_finding and item is not component_finding
            ]
            findings.append(merged)
    return findings


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def dependency_findings(root: Path, *, is_test: bool = False) -> list[Finding]:
    """Report obviously floating package.json dependencies without network access."""
    manifest = root / "package.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    entries: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        values = data.get(section, {}) if isinstance(data, dict) else {}
        if isinstance(values, dict):
            entries.extend((str(name), str(version)) for name, version in values.items())
    floating = [name for name, version in entries if version in {"*", "latest"}]
    if not floating:
        return []
    finding = make_finding(
        target=root,
        scanner="builtin",
        rule_id="UNPINNED-DEPENDENCY",
        title="Unpinned dependencies",
        severity=Severity.LOW,
        confidence=Confidence.LIKELY.value,
        location="package.json:1",
        description=(
            "One or more dependencies use `*` or `latest`; no network or advisory lookup was performed."  # noqa: E501
        ),
        tags=["heuristic", "offline"],
    ).model_copy(
        update={
            "source": "builtin",
            "line_numbers": [1],
            "code_excerpt": "Dependencies: " + ", ".join(floating[:12]),
            "remediation": (
                "Pin reviewed versions and commit a lockfile.\n"
                'Before: "package": "*"\n'
                'After: "package": "1.2.3" with a committed lockfile'
            ),
            "cwe_ids": ["CWE-1104"],
            "exposure": "build",
            "references": [
                Reference(
                    title="CWE-1104: Use of Unmaintained Third Party Components",
                    url="https://cwe.mitre.org/data/definitions/1104.html",
                )
            ],
        }
    )
    return [finding]


def vibe_risk(profile: object) -> VibeCodingRisk:
    """Return the preserved legacy arithmetic with a fully inspectable contribution ledger."""
    source_files = tuple(getattr(profile, "source_files", ()))
    root = getattr(profile, "root", None)
    signals: list[str] = []
    all_text: list[str] = []
    contribution_specs = (
        (
            "placeholder_credentials",
            "placeholder credentials",
            20,
            r"(?:your-api-key|changeme|secret123|sk-[A-Za-z0-9_-]{8,})",
        ),
        (
            "leftover_guidance",
            "leftover TODO or production guidance",
            8,
            r"in production you should|TODO.{0,60}(?:auth|security|validate)",
        ),
        (
            "tutorial_default",
            "tutorial-style insecure default",
            18,
            r"(?:admin\s*/\s*admin|allow_origins\s*=\s*\[?['\"]\*|cors\([^\n]*\*|service_role)",
        ),
        (
            "mock_data",
            "mock or dummy data in source",
            8,
            r"(?:mock|dummy|fake)[_-]?(?:user|auth|credential|token)|admin@example\.com",
        ),
        (
            "raw_error",
            "raw error returned to client",
            12,
            r"return\s+(?:Response\.json|jsonify|res\.json)\s*\([^\n]*error\.message",
        ),
        (
            "commented_code",
            "commented-out code",
            5,
            r"^\s*//\s*(?:const|let|function|return|if\s*\()",
        ),
        (
            "client_validation",
            "client-side validation pattern observed (server-side validation not established)",
            8,
            r"(?i)validate|isValid|password",
        ),
    )
    evidence_by_signal: dict[str, list[ScoreEvidence]] = {key: [] for key, *_ in contribution_specs}
    counts = {key: 0 for key, *_ in contribution_specs}
    patterns = {
        key: re.compile(pattern, re.I | (re.M if key == "commented_code" else 0))
        for key, _, _, pattern in contribution_specs
    }
    texts_by_path: list[tuple[Path, str]] = []
    for path in source_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        all_text.append(text)
        texts_by_path.append((path, text))
        try:
            relative = path.relative_to(root).as_posix() if root else path.name
        except ValueError:
            relative = path.name
        for key, _, _, _ in contribution_specs:
            matched = patterns[key].search(text)
            if key == "client_validation":
                has_client_validation = bool(
                    "use client" in text
                    and patterns[key].search(text)
                    and not re.search(r"use server|server action", text, re.I)
                )
                matched = patterns[key].search(text) if has_client_validation else None
            if not matched:
                continue
            counts[key] += 1
            if len(evidence_by_signal[key]) < 3:
                line = text.count("\n", 0, matched.start()) + 1
                excerpt = (
                    _excerpt(text.splitlines()[line - 1])
                    if line <= len(text.splitlines())
                    else None
                )
                evidence_by_signal[key].append(
                    ScoreEvidence(file=relative, line_numbers=[line], code_excerpt=excerpt)
                )

    combined = "\n".join(all_text)
    contributions: list[ScoreContribution] = []
    signal_count = 0
    subtotal = 0
    for key, label, weight, _pattern in contribution_specs:
        raw_count = counts[key]
        effective = min(raw_count, 3)
        contribution = effective * weight
        if raw_count:
            signals.append(f"{label} observed in {raw_count} source file(s)")
            signal_count += 1
        adjustment = (
            "per-file count; effective count capped at 3"
            if raw_count > 3
            else "per-file count; no cap applied"
        )
        if key == "client_validation" and raw_count:
            adjustment += "; no inter-file form-to-handler validation trace"
        contributions.append(
            ScoreContribution(
                signal_id=key,
                description=label,
                raw_count=raw_count,
                effective_count=effective,
                weight=weight,
                adjustment=adjustment,
                contribution=contribution,
                evidence=evidence_by_signal[key],
            )
        )
        subtotal += contribution

    route_hits: list[ScoreEvidence] = []
    route_count = 0
    route_re = re.compile(r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)")
    for path, text in texts_by_path:
        try:
            relative = path.relative_to(root).as_posix() if root else path.name
        except ValueError:
            relative = path.name
        for match in route_re.finditer(text):
            route_count += 1
            if len(route_hits) < 50:
                line = text.count("\n", 0, match.start()) + 1
                route_hits.append(
                    ScoreEvidence(
                        file=relative,
                        line_numbers=[line],
                        code_excerpt=_excerpt(text.splitlines()[line - 1]),
                    )
                )
    route_blocker = bool(
        re.search(r"\b(auth|requireUser|zod|yup|rateLimit|throttle)\b", combined, re.I)
    )
    route_bonus = 12 if route_count >= 4 and not route_blocker and signal_count > 0 else 0
    if route_count >= 4:
        if route_bonus:
            signals.append(
                f"{route_count} route handlers without recognizable auth, validation, or rate-limit patterns"  # noqa: E501
            )
        contributions.append(
            ScoreContribution(
                signal_id="route_handlers_without_controls",
                description="Route-handler heuristic bonus",
                raw_count=route_count,
                effective_count=1 if route_bonus else 0,
                weight=12,
                adjustment="one-time bonus only when at least 4 route handlers exist, a base signal exists, and no checked auth/schema/limiter term exists",  # noqa: E501
                contribution=route_bonus,
                evidence=route_hits,
            )
        )

    request_patterns = (r"\bfetch\s*\(", r"axios\.", r"apiRequest\s*\(")
    request_evidence: list[ScoreEvidence] = []
    request_styles = 0
    for pattern in request_patterns:
        style_evidence: ScoreEvidence | None = None
        for path, text in texts_by_path:
            request_match = re.search(pattern, text)
            if not request_match:
                continue
            try:
                relative = path.relative_to(root).as_posix() if root else path.name
            except ValueError:
                relative = path.name
            line = text.count("\n", 0, request_match.start()) + 1
            style_evidence = ScoreEvidence(
                file=relative,
                line_numbers=[line],
                code_excerpt=_excerpt(text.splitlines()[line - 1]),
            )
            break
        if style_evidence is not None:
            request_styles += 1
            request_evidence.append(style_evidence)
    request_bonus = 6 if request_styles >= 3 else 0
    if request_bonus:
        signals.append("multiple HTTP request styles appear in the scanned source")
    if request_styles:
        contributions.append(
            ScoreContribution(
                signal_id="multiple_http_styles",
                description="Multiple HTTP request styles bonus",
                raw_count=request_styles,
                effective_count=1 if request_bonus else 0,
                weight=6,
                adjustment="one-time bonus at 3 distinct styles: fetch, axios, and apiRequest",
                contribution=request_bonus,
                evidence=request_evidence,
            )
        )
    subtotal += route_bonus + request_bonus
    score = min(100, subtotal)
    if subtotal > 100:
        contributions.append(
            ScoreContribution(
                signal_id="score_cap",
                description="Maximum score cap",
                raw_count=subtotal,
                effective_count=100,
                weight=0,
                adjustment="sum capped at 100",
                contribution=score - subtotal,
            )
        )
    confidence = (
        Confidence.INFORMATIONAL
        if not signals
        else Confidence.POSSIBLE
        if len(signals) < 3
        else Confidence.LIKELY
    )
    confidence_rationale = (
        "No configured signals were observed."
        if not signals
        else f"{len(signals)} signal categories were emitted; POSSIBLE applies below 3 and LIKELY at 3 or more. This is a heuristic threshold, not a probability."  # noqa: E501
    )
    return VibeCodingRisk(
        score=score,
        confidence=confidence,
        signals=signals,
        name="Code pattern risk",
        direction="Higher scores indicate more configured code patterns in the scanned source.",
        interpretation="Deterministic heuristic indicator; not proof of authorship, a vulnerability verdict, or scan completeness.",  # noqa: E501
        algorithm_version="legacy-pattern-v1",
        contributions=contributions,
        coverage_limitations=[
            f"Based on {len(texts_by_path)} readable supported source files only.",
            "Excluded files and unresolved cross-file/framework behavior do not contribute.",
            "Evidence snippets are redacted; matching is heuristic and does not prove exploitability or authorship.",  # noqa: E501
        ],
        confidence_rationale=confidence_rationale,
    )
