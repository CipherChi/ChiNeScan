"""Bounded optional dispatch to the Rust report renderer."""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
from pathlib import Path

from chinescan.malware_analysis.process import WorkerFailure, run_native_parser_worker

MAX_REPORT_REQUEST_BYTES = 16 * 1024 * 1024
MAX_LOCAL_INTEL_BYTES = 2 * 1024 * 1024


def _local_intel() -> dict[str, object]:
    """Read an explicitly configured operator file; never fetch intel remotely."""
    source = os.environ.get("CHINESCAN_REPORTER_LOCAL_DATA")
    if not source:
        return {}
    try:
        path = Path(source)
        if path.stat().st_size > MAX_LOCAL_INTEL_BYTES:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}
    cwe = value.get("cwe", {})
    epss = value.get("epss_by_rule", {})
    kev = value.get("kev_rules", [])
    if not isinstance(cwe, dict) or not isinstance(epss, dict) or not isinstance(kev, list):
        return {}
    cwe_map = {
        key: label
        for key, label in cwe.items()
        if isinstance(key, str) and len(key) <= 32 and isinstance(label, str) and len(label) <= 256
    }
    epss_map = {
        key: score
        for key, score in epss.items()
        if isinstance(key, str)
        and len(key) <= 128
        and isinstance(score, (int, float))
        and 0 <= score <= 1
    }
    kev_rules = [rule for rule in kev if isinstance(rule, str) and len(rule) <= 128]
    return {"cwe_map": cwe_map, "epss_by_rule": epss_map, "kev_rules": kev_rules}


def render_native_report(request: dict[str, object]) -> str | None:
    mode = os.environ.get("CHINESCAN_RUST_REPORTER", "off").strip().casefold()
    if mode in {"off", "false", "0", "disabled"}:
        return None
    try:
        if importlib.util.find_spec("chinescan_engine") is None:
            return None
        chinescan_engine = importlib.import_module("chinescan_engine")

        if not hasattr(chinescan_engine, "render_report_json"):
            return None
    except (ImportError, ValueError):
        return None
    try:
        local_intel = _local_intel()
        request = dict(request)
        request.update(local_intel)
        findings = request.get("findings")
        if isinstance(findings, list):
            epss_map = local_intel.get("epss_by_rule", {})
            kev_rules = local_intel.get("kev_rules", [])
            if isinstance(epss_map, dict) and isinstance(kev_rules, list):
                for finding in findings:
                    if isinstance(finding, dict):
                        rule = finding.get("rule_id")
                        if isinstance(rule, str):
                            if rule in epss_map:
                                finding["epss"] = epss_map[rule]
                            finding["kev"] = rule in kev_rules
        body = json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        encoded = body.encode("utf-8")
        if len(encoded) > MAX_REPORT_REQUEST_BYTES:
            return None
        result = run_native_parser_worker("report", encoded)
    except (WorkerFailure, TypeError, ValueError, UnicodeError):
        return None
    content = result.get("report")
    return (
        content
        if isinstance(content, str) and len(content.encode("utf-8")) <= 3 * 1024 * 1024
        else None
    )


class ReportSigningError(ValueError):
    """The local signing key is unavailable or its permissions are not safe."""


def _load_operator_seed(key_path: Path | None = None) -> bytes:
    import stat
    import subprocess

    configured = key_path or (
        Path(os.environ["CHINESCAN_REPORT_SIGNING_KEY"])
        if os.environ.get("CHINESCAN_REPORT_SIGNING_KEY")
        else None
    )
    if configured is None:
        raise ReportSigningError("Report signing key is not configured.")
    if not configured.exists():
        raise ReportSigningError("Configured report signing key is missing.")
    try:
        info = configured.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ReportSigningError("Report signing key must be a regular local file.")
        if os.name == "nt":
            acl = subprocess.run(
                ["icacls.exe", str(configured)],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if acl.returncode != 0:
                raise ReportSigningError("Unable to verify report signing key ACL.")
            who = subprocess.run(
                ["whoami.exe", "/user", "/fo", "csv", "/nh"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if who.returncode != 0:
                raise ReportSigningError(
                    "Unable to identify the current operator for key ACL validation."
                )
            identity_fields = who.stdout.strip().strip('"').split('","')
            operator_name = identity_fields[0].strip().casefold()
            lines = acl.stdout.splitlines()
            known_principals = {
                operator_name,
                "nt authority\\system",
                "builtin\\administrators",
                "administrators",
            }
            principals: list[str] = []
            for line in lines:
                if ":(" not in line:
                    continue
                ace_subject = line.split(":(", 1)[0].strip().casefold()
                matched = next(
                    (name for name in known_principals if ace_subject.endswith(name)), None
                )
                principals.append(matched or ace_subject.rsplit(None, 1)[-1])
            operator_aces = [
                principal
                for principal in principals
                if principal == operator_name or principal.endswith("\\" + operator_name)
            ]
            allowed = known_principals - {operator_name}
            if not principals or not operator_aces:
                raise ReportSigningError(
                    "Report signing key ACL must grant the current operator access."
                )
            if any(p not in allowed and p not in operator_aces for p in principals):
                raise ReportSigningError("Report signing key ACL is too permissive.")
        elif stat.S_IMODE(info.st_mode) & 0o077:
            raise ReportSigningError(
                "Report signing key permissions are too permissive; restrict access to the owner."
            )
        seed = configured.read_bytes()
    except ReportSigningError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReportSigningError("Unable to read or verify the local report signing key.") from exc
    if len(seed) != 32:
        raise ReportSigningError("Report signing key must contain exactly 32 raw seed bytes.")
    return seed


def sign_report_detached(content: str, key_path: Path | None = None) -> str:
    """Sign report bytes with a local raw Ed25519 seed; never logs or returns the seed."""
    if len(content.encode("utf-8")) > 3 * 1024 * 1024:
        raise ReportSigningError("Report exceeds the detached-signature input limit.")
    seed = _load_operator_seed(key_path)
    payload = json.dumps(
        {"content": content, "private_seed_hex": seed.hex()},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    try:
        result = run_native_parser_worker("report-sign", payload)
    except WorkerFailure as exc:
        raise ReportSigningError("Isolated report signing worker failed.") from exc
    signature = result.get("signature")
    if not isinstance(signature, str) or len(signature) != 128:
        raise ReportSigningError("Isolated report signing worker returned an invalid signature.")
    return signature


def verify_report_detached(content: str, signature_hex: str, public_key_hex: str) -> bool:
    """Verify detached signature using a supplied public key; no private key is read."""
    if len(content.encode("utf-8")) > 3 * 1024 * 1024:
        return False
    try:
        payload = json.dumps(
            {"content": content, "signature_hex": signature_hex, "public_key_hex": public_key_hex},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        result = run_native_parser_worker("report-verify", payload)
    except (WorkerFailure, ValueError, TypeError):
        return False
    return result.get("valid") is True


def report_public_key(key_path: Path | None = None) -> str:
    """Return the hex-encoded public key corresponding to the configured local key."""
    seed = _load_operator_seed(key_path)
    try:
        result = run_native_parser_worker("report-public-key", seed.hex().encode("ascii"))
    except WorkerFailure as exc:
        raise ReportSigningError("Isolated report key worker failed.") from exc
    key = result.get("public_key")
    if not isinstance(key, str) or len(key) != 64:
        raise ReportSigningError("Isolated report key worker returned an invalid public key.")
    return key
