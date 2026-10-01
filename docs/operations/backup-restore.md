# Backup and restore (v1)

Backup, verification, and restore are implemented by three scripts in
`scripts/operations/`:

| Script | Purpose |
|--------|---------|
| `backup.sh` | consistent, deterministic backup of both SQLite databases + staging spool + deployment config + key-version metadata |
| `verify-backup.sh` | independent verification: manifest, SHA-256 checksums, SQLite `integrity_check`, schema versions, secret-identifier accounting, deployment config presence |
| `restore.sh` | restore into an ISOLATED destination, checksums first, restrictive permissions, migration/readiness checks, no live-deployment overwrite without `--yes` |

All three run `bash -n`-clean, use only `bash`, `python3` (stdlib), and
machine `tar`/`sqlite3`, and never print secret **values** — only
identifiers and presence.

## What a backup contains

A backup is a directory `backups/<label>/` (label defaults to
`uncloud-registry-backup-<UTC timestamp>`):

```text
manifest.json       index: file list, schema versions, key-version metadata,
                    required-secret accounting, state summary (sorted keys)
SHA256SUMS          sorted SHA-256 checksums of every archived file
controlplane.db     consistent SQLite snapshot (VACUUM INTO — transactional
                    point-in-time copy, online-backup mechanism)
staging.db          consistent SQLite snapshot (same method; WAL included)
spool.tar           deterministic archive of the staging spool directory
                    (sorted path list, owner-only entries)
compose.yaml        the deployment configuration at backup time
key-versions.json   master-key current/loaded versions + registry-JWKS kid
                    set — identifiers only, never key bytes
EXCLUDED.list       identifiers of secrets deliberately NOT in the archive
```

### Deliberately excluded (never inside an unencrypted backup by default)

- `master.json` — the master key. Adding it is an explicit, discouraged
  opt-in: `--include-master-key` (only justified when the archive itself is
  encrypted at rest by your storage/transport layer). Without the flag the
  archive records that it is excluded and verification enforces the
  accounting.
- `internal-secret.txt`, `internal-key.pem`, `registry-jwks.json`,
  `bee-password.txt` — credential files, restored out-of-band.
- `.env` — carries `CONTROLPLANE_TOKEN_SECRET` and
  `CONTROLPLANE_REGISTRY_ED25519_KEY`; never archived.

The operator keeps these in the live secrets directory and/or a secret
manager. `verify-backup.sh --secrets-dir <dir>` confirms the live copies
exist (presence + owner-only mode) so a restore is not blocked on discovery
after the fact.

### Why `VACUUM INTO`

`VACUUM INTO` is the SQLite online-backup API: it produces a transactional
point-in-time copy even while writers are active and never disturbs the
live database or its WAL. The script also issues a PASSIVE WAL checkpoint
first to narrow the snapshot window. The staging spool is archived as a
sorted tar; because staging startup reconciliation is idempotent and
session-keyed (see `internal/staging/service.go`), a (rare) spool/DB skew
from files changing between the two snapshots is healed at first boot after
restore — the DBs themselves are always internally consistent.

### Determinism and idempotency

File names are fixed, the spool path list is sorted, `SHA256SUMS` and
manifest keys are sorted; re-running with the same label requires `--force`
and produces byte-identical output except the manifest's `created_at`. Two
consecutive runs in the drill (`docs/evidence/phase-5-recovery.md`) produced
identical `SHA256SUMS` and manifests (modulo `created_at`) — verified.

## Creating a backup

```bash
# from the deployment root (defaults mirror the Task 24 layout):
bash scripts/operations/backup.sh \
  --deploy-dir <deployment> --secrets-dir <deployment>/.secrets

# or with explicit paths (any layout, e.g. paths extracted from the volumes):
bash scripts/operations/backup.sh \
  --controlplane-db /var/lib/uncloud-registry/controlplane.db \
  --staging-db      /var/lib/uncloud-registry/staging.db \
  --staging-root    /var/lib/uncloud-registry/spool \
  --compose-file    <deployment>/compose.yaml \
  --secrets-dir     <deployment>/.secrets \
  --out             <deployment>/backups
```

The script self-verifies with `verify-backup.sh` before reporting success
and refuses `PASS` on any gap.

> **Bee volume.** The Bee keystore, its private key, and postage stamps live
> in the `bee-data` volume, not in the SQLite databases. Back them up with
> a Docker named-volume snapshot (`docker run --rm -v uncloud-registry_bee-data:/src -v $PWD:/dst alpine tar czf /dst/bee-data-<ts>.tgz -C /src .`),
> alongside `bee-password.txt` from the secrets dir. Without the keystore +
> password + stamp batch, feed publication cannot resume after a full
> reinstall.

## Verifying a backup

```bash
bash scripts/operations/verify-backup.sh \
  --backup-dir backups/<label> --secrets-dir <deployment>/.secrets
```

Checks, in order (exit nonzero on any gap, all gaps reported):

1. `manifest.json` + `SHA256SUMS` present and parseable; manifest schema tag.
2. File completeness: every manifest-listed file exists and has a checksum
   entry, and vice versa.
3. SHA-256 re-hash of every file (tamper detection).
4. Control-plane DB `PRAGMA integrity_check == ok`.
5. Staging DB `PRAGMA integrity_check == ok`.
6. Schema versions: `schema_migrations` (Max 17) and `staging_schema`
   (Max 11) inside the archive match the manifest record.
7. Secret-identifier accounting: every required secret is either in the
   archive or explicitly excluded (values never read) — plus optional live
   `--secrets-dir` presence/mode confirmation.
8. Deployment config `compose.yaml` present and matching its recorded hash.

## Restoring

`restore.sh` restores into an **isolated destination** and never touches the
live deployment paths:

```bash
# stop the stack first, then:
bash scripts/operations/restore.sh \
  --backup-dir backups/<label> \
  --dest /srv/uncloud-registry-restored \
  --secrets-dir <deployment>/.secrets
```

Ordering enforced by the script:

1. **Checksums first** — the archive must pass `verify-backup.sh` before a
   single byte is restored.
2. **Destination policy** — the destination must be empty; a non-empty
   destination is refused unless `--yes` (operator confirms the deployment
   there is stopped and drained). With `--yes`, the script additionally
   refuses when `lsof` shows a process holding a destination database file
   (a live deployment).
3. **Restrictive permissions** — directories `0700`, databases/keys `0600`,
   config `0644`.
4. **Migration/readiness checks** — on the restored tree, before success:
   `integrity_check` on both DBs, `foreign_key_check` on the control-plane
   DB, schema versions vs manifest, permission audit. The binaries run their
   full migration suite at startup; these checks prove the restored DBs are
   loadable and schema-consistent.
5. **Secrets** — place the excluded files back from the live secrets dir /
   secret manager, then start the stack. Startup validation fails closed on
   any missing or malformed secret.

### Full disaster recovery (fresh host)

```bash
# 1. rebuild the deployment (install.md), stop everything
# 2. restore the data tree
bash scripts/operations/restore.sh --backup-dir <backup> --dest <deployment>/data
# 3. restore the excluded secrets (master.json, internal-*, registry-jwks.json,
#    bee-password.txt) and the .env from your secret manager
# 4. restore the Bee volume snapshot + bee-password.txt
# 5. docker compose --env-file .env up -d --build
# 6. verify: curl /readyz on both services; bash verify-backup.sh on the backup
```

## The reference-stack push/pull drill is deferred (honest status)

The full reference-stack drill — push fixtures, back up a running stack,
destroy a disposable test deployment, restore to a fresh location, restart,
pull the same digests — is **blocked by the Bee feed-publication deferral**:
the reference stack pins Bee 2.8.2 as an isolated light node
(`--full-node=false`, no peers), and a light node cannot pushsync chunks, so
feed publication and feed-dependent pulls never become retrievable
(`docs/compatibility.md` §8). The drill therefore cannot honestly assert a
push/pull round-trip in this phase.

In its place, the backup/restore machinery is exercised against **the real
SQLite databases produced by the real store constructors**
(`controlplane.OpenSQLite`, `staging.NewService`): fixture creation →
backup → verify → destroy → restore into a fresh tree → `integrity_check` →
schema/data equivalence → re-open with the real constructors → feed-key
decrypt. Full output is recorded in `docs/evidence/phase-5-recovery.md`.
The end-to-end stack drill is scheduled with the Phase 4 / real-Bee gate.

## Operational notes

- Schedule backups with the same command you ran manually; keep the newest
  verified archive plus at least one previous generation off-host.
- Verify a backup **before** you need it, and after any off-host transfer
  (checksums are in the archive, so re-running `verify-backup.sh` is enough).
- The master key is not in the archive. A backup without the master key is
  unusable for feed-key decryption — treat `master.json`'s out-of-band copy
  as part of the backup, and test a restore with a real decrypt
  (`key-rotation.md` has the verification commands).
- Consent ladder: `backup.sh` never overwrites an existing label without
  `--force`; `restore.sh` never touches a non-empty destination without
  `--yes`.