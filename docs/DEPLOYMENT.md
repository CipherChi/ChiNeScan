# Operations and deployment status

ChiNeScan has no configured production or staging host, image registry, release credentials, or
health-check endpoint. The CI container job builds locally for verification and does not publish
the image. Public/remote deployment is disabled. The authenticated dashboard is available only
through the explicit `chinescan web serve` command, which binds one worker to `127.0.0.1`.
Docker Compose remains a local one-shot CLI runner; its default `--help` command exits and never
starts the dashboard.

## Local container image

The local container uses the digest-pinned Python 3.12.16 slim Trixie image
which provides apt and libapt-pkg7.0 3.0.4, and installs the Trixie security
revision of `zlib1g` (`1:1.3.dfsg+really1.3.1-1+deb13u1`). The image also carries the Alembic
configuration and migrations required to initialize its SQLite database.
The supported container use remains local; the explicit web command binds
to loopback, and the image is not a remote or multi-user deployment
configuration. Rebuild and scan the image with current advisory data when
maintaining it; a package pin and a successful scan are time-specific
evidence, not a guarantee that the image is vulnerability-free.

### Reverse proxy example for an explicitly approved remote deployment

The default bind remains `127.0.0.1`. Do not expose the dashboard publicly without a TLS
terminating reverse proxy, proxy-side rate limits, and an explicitly reviewed deployment
configuration. Keep the application bound to loopback and proxy to it locally. Example Traefik
dynamic configuration (replace the hostname and certificate resolver for the deployment):

```yaml
http:
  middlewares:
    chinescan-rate-limit:
      rateLimit:
        average: 30
        burst: 10
        period: 1m
  routers:
    chinescan:
      rule: Host(`chinescan.example.invalid`)
      entryPoints: [websecure]
      middlewares: [chinescan-rate-limit]
      tls:
        certResolver: letsencrypt
      service: chinescan
  services:
    chinescan:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:8765
```

The proxy must preserve the request host and scheme, route the full path to the application,
and must not set a client IP header that the application is configured to trust without
restricting access to that proxy. Configure the listener and firewall so the application port
is not reachable outside the host. Proxy rate limits complement the application's controls;
they do not authorize remote exposure by themselves.

## Local database backup and restore

The application offers an explicit local backup bundle containing `database.sqlite3` and a
versioned `manifest.json`. It takes a consistent SQLite online backup, so committed WAL data is
included; it never copies only a live database's main file. It opens the source read-only and does
not migrate it. The bundle is staged, checked, and published at a new path only after SQLite
integrity, schema, relationship, size, and checksum checks. The manifest contains no source path or
record content. Its SHA-256 detects disagreement with that manifest; it is not a signature or proof
of authenticity if someone can replace both files.

Use a dedicated backup directory outside the checkout. The parent must already exist, and the
bundle destination must not exist:

```powershell
chinescan db backup --output D:/restricted-backups/chinescan-2026-10-26
chinescan db verify-backup D:/restricted-backups/chinescan-2026-10-26
chinescan db restore D:/restricted-backups/chinescan-2026-10-26 --output D:/recovery/chinescan-restored.sqlite3
```

Verification is read-only and never migrates or repairs a backup. It reports structural/integrity
failures, unsupported schema revisions, and application consistency findings separately. Case
links have no SQL foreign keys, so the verifier checks typed links, linked payload validity, embedded
note ownership, activity references, and persisted scan/event/indicator/authorization relationships.
Older supported schema revisions are checked with the same read-only model defaults. A restore is
allowed only for a fully verified backup and always targets a new database path. It stages and
validates the restored copy before publication; if needed, Alembic upgrades only that copy. The
manifest and backup remain unchanged. Existing destinations, the active database, and paths with
SQLite WAL/SHM sidecars are rejected.

The bundle includes original sensitive records. It is not encrypted. On POSIX systems the tool
requests restrictive mode bits; on Windows those bits do not establish a restrictive ACL. Check and
set Windows ACLs using the host's approved controls. File permissions are not encryption. Keep
backups on encrypted storage according to local policy, and periodically perform a restore drill.

`chinescan db retention-plan --directory <managed-directory>` is preview-only. Defaults retain
verified bundles among the newest five and no older than 90 days; `--keep-last` and
`--max-age-days` can change those preview rules. A newest successfully verified bundle remains
retained even if it is older than the age limit. Manifests and database contents are verified before
an entry is considered managed. Invalid bundles, symlinks, arbitrary files, and unmanaged folders
are listed as skipped. Entries marked `remove` are proposals only; this stage never deletes backups
or prunes database records, and it creates no scheduled cleanup.

A future active-database cutover remains operator-controlled: stop every ChiNeScan process using the
database, make and verify a separate backup, restore to a new path, check the recovered records and
reports, then update the configured database path while no writer is running. Preserve the original
until the new path is confirmed. This release does not replace the active database automatically.

## Upgrades and rollback

Before upgrading, record the current package/image version and take and verify a database backup.
Build and test the new image locally against a copy of that database first. Keep the prior image
and database backup until the new version has been checked. If the upgrade fails, stop all writers
and restore the pre-upgrade database together with the prior image.

SQLite initialization runs Alembic to head before opening the repository. Fresh databases use
`0001_initial` and `0002_case_workflow`. The latter records a backward-compatible JSON payload
evolution and makes no physical table changes or payload rewrites. An unversioned database is
stamped as `0001_initial` only if its `records` table exactly matches the recognized initial
schema, then upgraded to head. Unknown schemas fail without recreation or rewriting. Case payloads
from before workflow fields remain readable through model defaults. Migration rollback does not
remove or downgrade stored case data; restore a verified pre-upgrade backup to a new path if rollback
is needed. Back up the database before upgrading and test against a copy first.

## Retention and incident handling

Retention is preview-only and does not delete backups or evidence. Define retention with the data
owner before operational use. Case report redaction is enabled by default but is not anonymization:
reports can still contain hostnames, usernames, analyst notes, and investigation context. Export
retention and deletion are operator responsibilities. `chinescan trends` summarizes records; it does
not delete or anonymize them. Avoid placing databases, backups, or reports in the checkout or CI artifacts.

If a host or database may be compromised, stop scans and preserve the database and relevant host
logs as evidence. Limit access to those copies, record who handled them, and follow the
organization's incident process for containment and notification. Rotate any credentials that
could have been exposed through the control plane that issued them; do not paste secrets or raw
investigation records into issues or chat. ChiNeScan has no built-in incident-response workflow.

## Requirements before production deployment

Before adding a deployment workflow, the maintainer must specify the hosting platform, target
environment(s), registry and access policy (if needed), deployment identity, health check, rollback
procedure, and database backup/migration expectations. Prefer short-lived OIDC credentials where
the selected platform supports them. Configure production approval through a protected GitHub
environment when available. Do not put credentials in repository files or CI artifacts.

The eventual workflow should promote the exact image digest built and checked by CI, serialize
deployments, run a post-deployment health check, and provide a tested rollback path. No deployment
or automated rollback is currently implemented.
