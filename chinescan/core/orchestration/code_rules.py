"""Built-in heuristic rules for local Python and JS/TS code assessment."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from chinescan.core.logging.redaction import redact
from chinescan.core.models.common import Confidence, Severity
from chinescan.core.models.finding import Finding, Reference
from chinescan.core.orchestration.code_scan import make_finding


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: Confidence
    cwe: str
    description: str
    remediation: str
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
    return Rule(
        rule_id,
        re.compile(pattern, flags),
        severity,
        confidence,
        cwe,
        description,
        remediation,
        exposure,
        review,
    )


RULES: tuple[Rule, ...] = (
    _rule(
        "DYNAMIC-EVAL",
        r"\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*(?:req|request|input|user|code|script|source)\w*",
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
        r"(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^\n]{0,240}(?:\$\{|\bf['\"][^\n]*\{|\s\+\s*(?:req|request|user|input))",
        Severity.HIGH,
        "CWE-89",
        "SQL text appears to combine a query with dynamic input.",
        "Use parameterized queries or the database library's bound parameters.",
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
        r"\b(?:readFile|readFileSync|createReadStream|open|sendFile)\s*\([^\n]*(?:req\.(?:query|params|body)|request\.(?:args|form|json)|\buser_input)",
        Severity.HIGH,
        "CWE-22",
        "A filesystem path appears to include request-controlled input.",
        "Resolve against a fixed allowed directory and reject paths that escape it.",
    ),
    _rule(
        "XSS-DANGEROUS-HTML",
        r"dangerouslySetInnerHTML\s*=|\.innerHTML\s*=\s*(?:req|request|user|input|data|response)\w*|document\.write\s*\(\s*(?:req|request|user|input|data|response)\w*",
        Severity.HIGH,
        "CWE-79",
        "HTML is inserted into a browser sink without evidence of context-safe encoding.",
        "Render text normally or sanitize HTML with a maintained allowlist sanitizer.",
        exposure="client",
        review=True,
    ),
    _rule(
        "API-AUTH-MISSING",
        r"(?:export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)|app\.(?:get|post|put|patch|delete)\s*\(|@(?:app|router)\.(?:get|post|put|patch|delete))",
        Severity.HIGH,
        "CWE-862",
        "A route handler has no recognizable authentication guard in this file; verify the shared middleware.",  # noqa: E501
        "Require authentication and authorization before reading or changing protected resources.",
        confidence=Confidence.POSSIBLE,
        review=True,
    ),
    _rule(
        "IDOR-RESOURCE-ID",
        r"(?:find(?:Unique|First|One|ById)|get|load)\w*\s*\([^\n]*(?:req\.(?:params|query)|request\.(?:params|query)|params\.)",
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
        Severity.CRITICAL,
        "CWE-347",
        "JWT verification appears to accept the unsecured `none` algorithm.",
        "Reject `none` and pin an approved signing algorithm during verification.",
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
        r"(?i)\b(?:password|passwd|api[_-]?key|secret|access[_-]?token|private[_-]?key)\b\s*[:=]\s*(['\"])(?!\s*(?:\$\{|process\.env|os\.environ))[^'\"]{4,}\1",
        Severity.HIGH,
        "CWE-798",
        "A credential-like literal is present; its value is redacted in this report.",
        "Move the value to a secret store or environment variable and rotate it if it was committed.",  # noqa: E501
    ),
    _rule(
        "NEXT-PUBLIC-SECRET",
        r"NEXT_PUBLIC_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)",
        Severity.HIGH,
        "CWE-540",
        "A secret-like environment variable uses the public Next.js prefix and can reach client bundles.",  # noqa: E501
        "Remove the public prefix and access the secret only in server-side code.",
        exposure="client",
    ),
    _rule(
        "CORS-WILDCARD-CREDENTIALS",
        r"(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*['\"]\*['\"][^\n]*(?:credentials|allowCredentials)\s*[:=]\s*true|(?:credentials|allowCredentials)\s*[:=]\s*true[^\n]*(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*['\"]\*['\"]",
        Severity.HIGH,
        "CWE-942",
        "CORS appears to combine wildcard origins with credentials.",
        "Use an explicit origin allowlist and enable credentials only for trusted origins.",
    ),
    _rule(
        "MISSING-SECURITY-HEADERS",
        r"(?:export\s+default|module\.exports|express\(|FastAPI\(|Flask\(|http\.createServer|app\s*=)",
        Severity.MEDIUM,
        "CWE-693",
        "This file configures a web server but no complete security-header policy was detected.",
        "Configure CSP, frame restrictions, MIME sniffing protection, and a restrictive referrer policy.",  # noqa: E501
        confidence=Confidence.POSSIBLE,
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
        r"(?:login|signIn|contact|forgotPassword|resetPassword)",
        Severity.MEDIUM,
        "CWE-307",
        "An authentication or contact handler has no recognizable rate limiter in this file.",
        "Apply server-side limits, abuse monitoring, and appropriate account lockout controls.",
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
        r"\.catch\s*\(\s*(?:\(\s*\)\s*=>\s*\{\s*\}|\(\s*\w+\s*\)\s*=>\s*(?:null|undefined|void\s+0))",
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
        r"(?:TODO|FIXME|HACK).{0,100}(?:auth|security|sanitize|validate|csrf|secret|permission|production)",
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
        "A client component references a secret-like environment variable.",
        "Move secret access to a server-only module and expose only a narrow server action.",
        exposure="client",
    ),
)


def _excerpt(line: str) -> str:
    cleaned = str(redact(line.strip()))
    return cleaned[:240]


def analyze_source(root: Path, path: Path, text: str, *, is_test: bool) -> list[Finding]:
    """Run rules and return one grouped finding per rule and file."""
    relative = path.relative_to(root).as_posix()
    lines = text.splitlines()
    matched: dict[str, tuple[Rule, list[int], list[str]]] = {}
    lowered = text.lower()
    for rule in RULES:
        if rule.rule_id == "API-AUTH-MISSING":
            if not ("/api/" in relative.lower() or relative.lower().endswith("route.ts")):
                continue
            if not rule.pattern.search(text) or re.search(
                r"\b(auth|session|requireUser|currentUser|verifyToken|middleware)\b", text, re.I
            ):
                continue
            hits = [(1, lines[0] if lines else "route handler")]
        elif rule.rule_id == "IDOR-RESOURCE-ID":
            if re.search(r"\b(owner|userId|user_id|authorize|authorization)\b", text, re.I):
                continue
            hits = [(m.start(), m.group(0)) for m in rule.pattern.finditer(text)]
            hits = [(_line_number(text, start), code) for start, code in hits]
        elif rule.rule_id == "JWT-NO-EXPIRY":
            hits = []
            for match in rule.pattern.finditer(text):
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
            matches = list(rule.pattern.finditer(text))
            if not matches:
                continue
            if rule.rule_id == "MISSING-SECURITY-HEADERS" and re.search(
                r"(?:helmet\(|securityHeaders|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options)",
                text,
                re.I,
            ):
                continue
            if rule.rule_id == "REQUEST-NO-SCHEMA" and re.search(
                r"\b(?:zod|z\.|yup)\b", text, re.I
            ):
                continue
            if rule.rule_id == "LOGIN-NO-RATE-LIMIT" and not re.search(
                r"(?:login|signin|contact|forgotpassword|resetpassword)", relative + text, re.I
            ):
                continue
            if rule.rule_id == "LOGIN-NO-RATE-LIMIT" and re.search(
                r"rate.?limit|throttle|limiter", text, re.I
            ):
                continue
            if rule.rule_id == "UPLOAD-NO-CHECKS" and re.search(
                r"(?:maxSize|fileSize|sizeLimit|contentType|mimetype|fileFilter)", text, re.I
            ):
                continue
            if rule.rule_id == "COOKIE-FLAGS" and all(
                re.search(flag, text, re.I) for flag in (r"httpOnly", r"secure", r"sameSite")
            ):
                continue
            hits = [(_line_number(text, m.start()), m.group(0)) for m in matches[:4]]
        else:
            hits = [
                (_line_number(text, m.start()), m.group(0)) for m in rule.pattern.finditer(text)
            ]
        if hits:
            matched[rule.rule_id] = (rule, [n for n, _ in hits], [code for _, code in hits])

    if "use client" in lowered:
        client_rule = next(rule for rule in RULES if rule.rule_id == "CLIENT-COMPONENT-SECRET")
        client_hits = list(client_rule.pattern.finditer(text))
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
    for rule, line_numbers, snippets in matched.values():
        severity = (
            Severity.MEDIUM if is_test and rule.rule_id == "HARDCODED-CREDENTIAL" else rule.severity
        )
        confidence = (
            Confidence.POSSIBLE
            if rule.review or (is_test and rule.rule_id == "HARDCODED-CREDENTIAL")
            else rule.confidence
        )
        excerpt = " | ".join(dict.fromkeys(_excerpt(item) for item in snippets))[:360]
        if is_test and rule.rule_id == "HARDCODED-CREDENTIAL":
            description = (
                "Test file credential-like literal; verify the value is fake and not reused."
            )
        else:
            description = rule.description
        finding = make_finding(
            target=root,
            scanner="builtin",
            rule_id=rule.rule_id,
            title=rule.rule_id.replace("-", " ").title(),
            severity=severity,
            category="SAST",
            confidence=confidence.value,
            location=f"{relative}:{line_numbers[0]}",
            description=description,
            tags=["heuristic", "local"]
            + (
                ["manual-review"]
                if rule.review or is_test and rule.rule_id == "HARDCODED-CREDENTIAL"
                else []
            ),
        ).model_copy(
            update={
                "source": "builtin",
                "line_numbers": sorted(set(line_numbers)),
                "code_excerpt": excerpt,
                "remediation": rule.remediation,
                "cwe_ids": [rule.cwe],
                "exposure": rule.exposure,
                "references": [
                    Reference(
                        title=rule.cwe,
                        url=f"https://cwe.mitre.org/data/definitions/{rule.cwe.removeprefix('CWE-')}.html",
                    )
                ],
            }
        )
        findings.append(finding)
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
            "remediation": "Pin reviewed versions and commit a lockfile.",
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


def vibe_risk(profile: object) -> tuple[int, Confidence, list[str]]:
    """Return a bounded heuristic score and named signals, never an authorship claim."""
    source_files = getattr(profile, "source_files", ())
    signals: list[str] = []
    counts: dict[str, int] = {}
    all_text: list[str] = []
    for path in source_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        all_text.append(text)
        if re.search(r"(?:your-api-key|changeme|secret123|sk-[A-Za-z0-9_-]{8,})", text, re.I):
            counts["placeholder credentials"] = counts.get("placeholder credentials", 0) + 1
        if re.search(r"in production you should|TODO.{0,60}(?:auth|security|validate)", text, re.I):
            counts["leftover TODO or production guidance"] = (
                counts.get("leftover TODO or production guidance", 0) + 1
            )
        if re.search(
            r"(?:admin\s*/\s*admin|allow_origins\s*=\s*\[?['\"]\*|cors\([^\n]*\*|service_role)",
            text,
            re.I,
        ):
            counts["tutorial-style insecure default"] = (
                counts.get("tutorial-style insecure default", 0) + 1
            )
        if re.search(
            r"(?:mock|dummy|fake)[_-]?(?:user|auth|credential|token)|admin@example\.com", text, re.I
        ):
            counts["mock or dummy data in source"] = (
                counts.get("mock or dummy data in source", 0) + 1
            )
        if re.search(
            r"return\s+(?:Response\.json|jsonify|res\.json)\s*\([^\n]*error\.message", text, re.I
        ):
            counts["raw error returned to client"] = (
                counts.get("raw error returned to client", 0) + 1
            )
        if re.search(r"^\s*//\s*(?:const|let|function|return|if\s*\()", text, re.M):
            counts["commented-out code"] = counts.get("commented-out code", 0) + 1
        if (
            "use client" in text
            and re.search(r"validate|isValid|password", text, re.I)
            and not re.search(r"use server|server action", text, re.I)
        ):
            counts["client-only validation pattern"] = (
                counts.get("client-only validation pattern", 0) + 1
            )
    for label, count in sorted(counts.items()):
        signals.append(f"{label} observed in {count} source file(s)")
    combined = "\n".join(all_text)
    route_count = len(
        re.findall(r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)", combined)
    )
    if route_count >= 4 and not re.search(
        r"\b(auth|requireUser|zod|yup|rateLimit|throttle)\b", combined, re.I
    ):
        signals.append(
            f"{route_count} route handlers without recognizable auth, validation, or rate-limit patterns"  # noqa: E501
        )
    fetch_styles = sum(
        bool(re.search(pattern, combined))
        for pattern in (r"\bfetch\s*\(", r"axios\.", r"apiRequest\s*\(")
    )
    if fetch_styles >= 3:
        signals.append("multiple HTTP request styles appear in the scanned source")
    weights = {
        "placeholder credentials": 20,
        "leftover TODO or production guidance": 8,
        "tutorial-style insecure default": 18,
        "mock or dummy data in source": 8,
        "raw error returned to client": 12,
        "commented-out code": 5,
        "client-only validation pattern": 8,
    }
    score = min(
        100,
        sum(weights.get(label, 8) * min(count, 3) for label, count in counts.items())
        + (12 if route_count >= 4 and signals else 0)
        + (6 if fetch_styles >= 3 else 0),
    )
    confidence = (
        Confidence.INFORMATIONAL
        if not signals
        else Confidence.POSSIBLE
        if len(signals) < 3
        else Confidence.LIKELY
    )
    return score, confidence, signals
