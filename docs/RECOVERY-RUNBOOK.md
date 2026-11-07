# Local recovery and database selection runbook

This runbook describes a manually controlled recovery using a verified backup and a new database
path. It does not replace or merge the active database.

## Preflight

1. Stop scheduled ChiNeScan jobs and every other process that can write to the original database.
   An application lock cannot prove that no unrelated process has it open.
2. Record the original database path and choose a different, nonexistent restored path. Check that
   both refer to the intended local files and preserve the original.
3. Create a backup, then verify it before restore:

   ```powershell
   chinescan --database D:/data/original.sqlite3 db backup --output D:/backups/recovery-001
   chinescan db verify-backup D:/backups/recovery-001 --format json
   chinescan --database D:/data/original.sqlite3 db restore D:/backups/recovery-001 --output D:/recovery/restored.sqlite3
   ```

   Verification checks bundle integrity, supported schema and application record consistency.
   It is read-only; a supported migration runs only on the staged restored copy. Preserve the
   original database and backup bundle. Do not proceed when verification fails.

## Cutover

1. Keep scheduled jobs and other writers stopped. Every command below selects the restored path
   explicitly, so no configuration file is rewritten:

   ```powershell
   chinescan --database D:/recovery/restored.sqlite3 case show <case-id>
   chinescan --database D:/recovery/restored.sqlite3 case note list <case-id>
   chinescan --database D:/recovery/restored.sqlite3 case timeline <case-id>
   chinescan --database D:/recovery/restored.sqlite3 case export <case-id> --format json --output D:/recovery/case.json
   ```

2. Review the recovered case, notes, linked records, timeline, and report output while still in a
   read-only smoke-check phase. Confirm the selected path on every command before permitting writes.
3. When operational policy authorizes writes, continue selecting the restored path explicitly or
   update the local configuration through the approved operator process while no writer is open.

## Rollback

1. Stop all jobs and writers again, then select the original path explicitly and re-check the
   original case and records.
2. Preserve both database files and the backup for investigation. Do not overwrite either copy.
3. Rollback changes database selection only. Writes made after cutover remain in the restored
   database and are not merged into the original. Reconciliation requires a separate reviewed
   process; this release does not merge divergent databases.

## Limits and handling

- Bundles and reports are not encrypted, and the manifest hash does not authenticate a backup.
- Windows mode-bit requests do not establish ACL protections; review and set ACLs with approved
  host controls.
- Case-record links are checked at verification time but have no SQL foreign-key enforcement.
- Current case-report publication uses a same-directory hard link and fails closed when unsupported.
- Backup retention is preview-only and never deletes files.
- Verify that no process holds the selected database before an operational path change. Do not
  rename an open database or remove WAL/SHM sidecars as generic cleanup.

## Offline acceptance drill

Run the synthetic recovery drill in a temporary directory with Python 3.12 and the existing local
environment:

```powershell
$RepoRoot = (Resolve-Path .).Path
$env:PYTHONPATH = "$RepoRoot;$RepoRoot\.venv\Lib\site-packages"
py -3.12 scripts/recovery_acceptance.py
```

It creates fixture log records and a case, backs up and verifies the original, restores to a new
path, invokes case CLI commands with explicit database paths, renders JSON/Markdown/HTML exports,
and adds a uniquely marked note only to the restored copy. Temporary databases and exports are
removed when the process exits. This exercises application behavior; it cannot establish that no
unrelated operating-system process has a database open.
