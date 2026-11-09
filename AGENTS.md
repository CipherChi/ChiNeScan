# ChiNeScan repository conventions

- The project root is `C:\src\Chinescan`, a standalone Git repository nested in another checkout. Keep all changes and Git operations scoped to this repository.
- Require Python 3.12 or newer. Use `py -3.12` for acceptance checks; do not rely on the default interpreter.
- Do not scan or modify sibling projects or the parent checkout.
- Do not commit or push unless the user explicitly asks.
- Implemented scope includes local CLI code assessment, log analysis, static malware triage, authorized domain posture checks, investigations, reporting, backup, and recovery. Optional or unimplemented commands must be clearly marked as such and return usage exit code 2.
- Configuration initialization must never write secret values. Redact secrets from logs.
- SQLite uses a local configurable data path. The authenticated local web dashboard may
  start a backend listener only through an explicit startup command and must bind to
  loopback by default. Do not add public exposure or remote deployment configuration
  in this stage. No unauthenticated access is allowed to scans, cases, evidence, reports,
  or job controls. Preserve domain authorization, secret redaction, local processing,
  and restrictions on malware execution and external uploads.
- Domain posture checks require explicit authorization for the target. Keep local-only defaults; do not add network activity without the user's explicit authorization.
- Malware analysis is static triage only: never execute samples or upload them. Stage B1 adds an operator-local managed-copy backend; this is not an OS sandbox, authenticated chain of custody, web upload path, or sample download feature.
- Do not claim Windows POSIX mode bits enforce ACL protections.
- Run the acceptance commands documented in `docs/plans/phase-1.md` and capture exact results in `docs/reports/phase-1-report.md`.
