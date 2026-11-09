"""Backend source of truth for honest, current module capability claims."""

from __future__ import annotations


def module_capabilities() -> list[dict[str, object]]:
    """Describe available and planned modules without implying unbuilt checks."""
    planned_guards = [
        "Explicit target authorization confirmation",
        "Block private, loopback, link-local, and metadata addresses; re-check redirects",
        "Passive GET/HEAD requests and handshake-only checks",
    ]
    return [
        {
            "name": "Network Scanner",
            "status": "planned",
            "does_today": "No network scanner is implemented.",
            "not_assessed": ["Ports, services, and network exposure"],
            "authorization_guards": planned_guards,
        },
        {
            "name": "Website Auditor",
            "status": "planned",
            "does_today": "No website auditor is implemented.",
            "not_assessed": ["Web application behavior and headers"],
            "authorization_guards": planned_guards,
        },
        {
            "name": "SSL Analyzer",
            "status": "planned",
            "does_today": "No remote TLS analyzer is implemented.",
            "not_assessed": ["Certificate chain and negotiated TLS configuration"],
            "authorization_guards": planned_guards,
        },
        {
            "name": "File Analyzer",
            "status": "partial",
            "does_today": (
                "Malware triage computes MD5, SHA-1, SHA-256, magic-byte type, size, byte entropy, "
                "bounded strings, and indicators; samples are never executed."
            ),
            "not_assessed": [
                "Archive listing without extraction",
                "File type/extension mismatch reporting",
            ],
            "authorization_guards": ["Operator-local registered sample only"],
        },
        {
            "name": "Vulnerability Reporter",
            "status": "partial",
            "does_today": "Exports findings and coverage from implemented local assessments.",
            "not_assessed": ["Complete language coverage and comprehensive vulnerability analysis"],
            "authorization_guards": ["Authenticated local operator"],
        },
        {
            "name": "Security Dashboard",
            "status": "partial",
            "does_today": (
                "Authenticated local dashboard for scans, findings, cases, jobs, projects, logs, "
                "malware triage, and on-chain investigations."
            ),
            "not_assessed": ["Alerts panel", "Per-module scores"],
            "authorization_guards": ["Authenticated local operator"],
        },
        {
            "name": "Code Assessment",
            "status": "available",
            "does_today": (
                "Local heuristic code assessment for supported Python and JavaScript/TypeScript "
                "files."
            ),
            "not_assessed": [
                "Cross-file data flow",
                "Git history",
                "Unsupported language analysis",
            ],
            "authorization_guards": ["Operator-approved local project folder"],
        },
        {
            "name": "Log Analysis",
            "status": "available",
            "does_today": "Bounded local parsing and detection for supported log formats.",
            "not_assessed": ["Unrecognized formats and external telemetry"],
            "authorization_guards": ["Operator-approved local log sources"],
        },
        {
            "name": "Malware Triage",
            "status": "available",
            "does_today": (
                "Static metadata inspection and hashing of local samples; never executes or "
                "uploads samples."
            ),
            "not_assessed": ["Dynamic behavior and bounded archive listing"],
            "authorization_guards": ["Operator-local managed sample"],
        },
        {
            "name": "On-chain Tracing",
            "status": "available",
            "does_today": "Local import analysis and optional explicitly enabled provider lookups.",
            "not_assessed": ["Complete chain-wide attribution"],
            "authorization_guards": ["Explicit network option for provider lookups"],
        },
    ]
