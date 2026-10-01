# Upgrade and rollback (v1)

This runbook is grounded in the actual migration machinery
(`internal/controlplane/migrations.go` — 17 ordered, transactional
migrations in `schema_migrations`; `internal/staging/sqlite.go` — version 11
in `staging_schema`, exact frozen predecessor shapes, unknown shapes
rejected).

## What happens at startup

Both binaries migrate at startup, each in its own database:

- **Control plane** (`controlplane.OpenSQLite` → `ApplyMigrations`): applies
  every recorded migration with `Version > current`, each inside its own
  transaction; the migration row is committed **only after** the post-apply
  `foreign_key_check` passes, so a failed migration is fully rolled back and
  never recorded. Current: **v17**.
- **Registry/staging** (`staging.NewService`): opens and migrates the
  dedicated staging database after exact schema verification. The migration
  path accepts exclusively the frozen committed predecessor shapes and a
  fresh empty file — a pre-existing database matching none of them is
  **rejected, never adopted**. Current: **v11**.

Migrations are forward-only by design: SQLite schema migrations do not carry
downgrade paths. Rollback of a *migrated* database means restoring the
pre-upgrade backup (below), not running an older binary against a newer
schema.

## Compatibility window (honest)

- Same-version or older-schema databases migrate forward cleanly at startup.
- A **newer-schema** database: staging **fails closed** (unknown shape is
  rejected — `internal/staging/sqlite.go`). The control plane's migration
  loop skips versions above its latest known, so an older control-plane
  binary will not be rejected by the version table itself — but its SQL
  against newer schema objects is undefined. **Rule: never start an older
  binary against a newer database.** If you must go back, restore the
  pre-upgrade backup.
- Schema version of every backup is recorded in its `manifest.json`
  (`controlplane_schema_version`, `staging_schema_version`) and checked by
  `verify-backup.sh` against the archived databases — a backup taken with a
  newer binary than the one you intend to restore is detected up front.

## Upgrade procedure

1. **Backup gate (mandatory, before touching anything):**
   ```bash
   bash scripts/operations/backup.sh --deploy-dir <deployment> --secrets-dir <deployment>/.secrets
   bash scripts/operations/verify-backup.sh --backup-dir backups/<label> --secrets-dir <deployment>/.secrets
   # record the label; it is your rollback artifact and must include the
   # pre-upgrade schema versions in manifest.json
   ```
   The stack may stay up during the backup: `VACUUM INTO` takes a
   transactional snapshot without disturbing writers
   (`backup-restore.md`). Pause the deployment's write activity if you want
   the spool snapshot to match the DBs exactly; startup reconciliation will
   otherwise heal the (rare) skew.
2. **Migration order** is fixed by startup dependencies: control plane then
   registry (registry `depends_on` the healthy control plane in
   `compose.yaml`). New binaries replace the images:
   ```bash
   docker compose --env-file .env up -d --build
   ```
3. **Rolling restart for best-effort continuity**: `docker compose up -d`
   recreates containers; each new binary runs its migrations on start. A
   migration is a short, single-writer transaction per step; the control
   plane's write transactions retry busy/locked with bounded backoff, so a
   briefly concurrent old-process write is absorbed, and a failed migration
   rolls back atomically.
4. **Smoke tests after upgrade:**
   ```bash
   curl -fsS http://127.0.0.1:8081/readyz          # 200 with all components ready
   curl -fsS http://127.0.0.1:80/readyz            # registry data plane ready
   bash scripts/ci/check.sh                        # build, vet, race suite, secret scan
   bash scripts/e2e/compose-smoke.sh               # reference-stack smoke (feed stage skipped by design)
   # schema versions at rest:
   sqlite3 <deployment>/data/controlplane.db "select max(version) from schema_migrations;"   # 17
   sqlite3 <deployment>/data/staging.db "select max(version) from staging_schema;"          # 11
   # post-upgrade baseline backup (captures the new schema versions):
   bash scripts/operations/backup.sh --deploy-dir <deployment> --secrets-dir <deployment>/.secrets
   ```
5. Take the post-upgrade backup and keep it alongside the pre-upgrade one:
   you can now roll back *to the upgrade* or *to before it*.

## Rollback procedure

Two distinct cases:

### A. Binary-only downgrade attempt (no DB migration happened)

If the new binary never started (config/secret rejection, build error
before DB side effects — the binaries validate everything before opening
SQLite), simply redeploy the previous images. No database was touched.

### B. Database migrated — restored from the pre-upgrade backup

Migrations are forward-only, so a database that already ran vN migrations
cannot be read by pre-upgrade binaries. Rollback = restore:

1. Stop the stack: `docker compose --env-file .env down` (volumes kept).
2. **Restore the PRE-UPGRADE backup into a fresh location, never in place:**
   ```bash
   bash scripts/operations/restore.sh --backup-dir backups/<pre-upgrade-label> \
     --dest <stage-dir> --secrets-dir <deployment>/.secrets
   ```
3. Swap the restored tree into the volume paths (or repoint the compose
   volume), restore the excluded secrets and `.env` (they are not in the
   archive — `backup-restore.md`), and start the **previous** images.
4. Verify `/readyz` on both services, the schema version queries above match
   the pre-upgrade manifest, and run the smoke list from step 4 of the
   upgrade.

### Rollback restrictions (honest)

- No downgrade migrations exist; you cannot "run the old binary on the new
  database" — see the compatibility window above. The pre-upgrade backup is
  the only honest rollback path for a migrated DB.
- A backup from a NEWER binary than the one you are rolling back to is
  rejected by `verify-backup.sh`'s schema-version check before restore — use
  the pre-upgrade backup, not the newest one.
- `restore.sh` refuses to write into a non-empty/live destination without
  explicit `--yes` (operator confirms the stack is stopped) and refuses if a
  process holds a destination database file. These are features, not
  friction: an in-place overwrite of a live deployment is exactly the
  failure mode this gate prevents.
- Postage/Bee state is in the `bee-data` volume, not the SQLite databases:
  rollback of the data plane does not roll back Bee stamps. If the upgrade
  changed the Bee image, restore the Bee volume snapshot taken with the
  pre-upgrade backup (`backup-restore.md`).

## Related

- Backup/restore mechanics: `docs/operations/backup-restore.md`
- Key rotations frequently accompany upgrades: `docs/operations/key-rotation.md`
- What to do when an upgrade or restore surfaces corruption:
  `docs/operations/incidents.md`