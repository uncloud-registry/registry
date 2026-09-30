# Phase 5 — backup/restore recovery drill evidence (Task 26)

Date: 2026-09-30 (UTC, host macOS / bash 3.2 + Python 3.9.6 + Go 1.27.1)
Branch: `feat/v1-completion`
Commit: see the Task 26 commit (this file is part of it)

## Scope (honest)

The plan's Step 6 asked for the full reference-stack drill — push fixtures,
back up a running stack, destroy a disposable test deployment, restore to a
fresh location, restart, pull the same digests. That drill is **blocked by
the Bee feed-publication deferral**: the reference stack pins Bee 2.8.2 as
an isolated light node with no peers, so feed publication and feed-dependent
pulls are not retrievable in this phase (`docs/compatibility.md` §8). Per the
task instruction, this phase does **not** fabricate a stack drill.

Instead the backup/restore/verification machinery was driven end to end
against the **real SQLite databases produced by the real store
constructors**:

1. fixture databases created via `controlplane.OpenSQLite` and
   `staging.NewService` (real migrations: control-plane v17,
   staging v11) with real data (user, registry with encrypted feed key,
   membership, staging session + spool file);
2. `backup.sh` → consistent `VACUUM INTO` snapshots + deterministic spool
   archive + manifest + checksums;
3. `verify-backup.sh` → all checks pass; tamper negative test → detected;
   determinism check → byte-identical reruns (modulo `created_at`);
4. destroy the fixture copies, `restore.sh` into a fresh isolated tree;
5. restored databases re-opened with the real constructors, feed key
   decrypted under the drill master key, staging startup reconciliation
   passed, restored session read back;
6. FULL `.dump` equivalence (schema + data) between source and restored
   databases.

The full push/pull stack drill remains scheduled with the Phase 4 /
real-Bee gate and is documented as deferred in
`docs/operations/backup-restore.md`.

## 1. Fixture creation (real store constructors)

Throwaway harness `cmd/fixture-drill` (deleted after the drill; never part
of the repository) called `controlplane.OpenSQLite` +
`staging.NewService`, then wrote a user, a registry whose feed key was
encrypted under a drill master key, a membership, and one staging session.

```
fixture: user=1 registry=1 slug=demo feed_key_set=true staging_session=f425ffda8e56618072a62a0eaec3f54e6011e0dfb925c24bf08877d9df439e93
```

## 2. backup.sh

```
Backup label: drill-001
  control-plane DB : live/data/controlplane.db
  staging DB       : live/data/staging.db
  staging root     : live/spool
  compose config   : live/deploy/compose.yaml
  secrets dir      : live/secrets
Snapshotting control-plane database…
Snapshotting staging database…
Archiving staging spool…
  1 spool entries

Archive written to: .../backups/drill-001
Self-verifying archive…
... verify-backup: PASS

backup: PASS
  excluded secrets (restore out-of-band): master.json internal-secret.txt internal-key.pem registry-jwks.json bee-password.txt
```

Archive contents (deterministic names): `manifest.json`, `SHA256SUMS`,
`controlplane.db`, `staging.db`, `spool.tar`, `compose.yaml`,
`key-versions.json`, `EXCLUDED.list`, `state-summary.json`. The archive
recorded `controlplane_schema_version: 17`, `staging_schema_version: 11`,
`master_key_current_version: 1`, `registry_jwks_kids: ["cp-ed25519-1"]` —
identifiers only, never key bytes.

## 3. verify-backup.sh

```
Verifying backup archive: .../backups/drill-001
  [ok] excluded secret confirmed in --secrets-dir: master.json
  [ok] excluded secret confirmed in --secrets-dir: internal-secret.txt
  [ok] excluded secret confirmed in --secrets-dir: internal-key.pem
  [ok] excluded secret confirmed in --secrets-dir: registry-jwks.json
  [ok] excluded secret confirmed in --secrets-dir: bee-password.txt
  [ok] control-plane DB integrity (ok)
  [ok] staging DB integrity (ok)
  [ok] control-plane schema version 17 / staging schema version 11
  [ok] secret identifier accounted: bee-password.txt
  [ok] secret identifier accounted: internal-key.pem
  [ok] secret identifier accounted: internal-secret.txt
  [ok] secret identifier accounted: master.json
  [ok] secret identifier accounted: registry-jwks.json
  [ok] deployment config present: compose.yaml

Verification passed: archive is complete, checksummed, and consistent.
verify-backup: PASS
```

### Negative test — tamper detection

A copy of the archive had one byte of `controlplane.db` flipped
(`printf '\x41' | dd of=tampered/controlplane.db bs=1 seek=2000 conv=notrunc`).
SQLite's `integrity_check` still reported `ok` (a single byte flip is not a
storage-class corruption); the SHA-256 layer caught it:

```
Verification gaps:
  - checksum mismatch: 'controlplane.db'
TAMPER-EXIT=1 (expect 1)
```

This is exactly why checksums are verified before restore, independent of
SQLite's own integrity gate.

### Determinism check

Two consecutive `backup.sh` runs (`--force`) produced **identical**
`SHA256SUMS`, `key-versions.json`, and manifests except the intentional
`created_at` field: `deterministic manifest (minus created_at): True`,
`deterministic SHA256SUMS: False` only because `manifest.json` (which carries
`created_at`) re-hashes — every other artifact byte-identical.

## 4. restore.sh (fresh isolated destination)

```
Step 1/4 — verifying backup archive…   [verify-backup: PASS]
Step 2/4 — checking destination: restored
Step 3/4 — restoring archive contents…
Step 4/4 — restored-tree migration/readiness checks…
restore readiness: OK (integrity, schema versions, foreign keys, permissions)

restore: PASS
```

Destination policy verified: `restore.sh` **refused** a non-empty
destination without `--yes` (`error: destination is not empty: restored`,
exit 1) and restored permissions exactly: `controlplane.db`/`staging.db`
`0600`, `spool/` `0700`, spool files `0600`, `compose.yaml` `0644`.

## 5. Equivalence — schema + data byte-for-byte

```
controlplane: schema+data dump IDENTICAL
staging: schema+data dump IDENTICAL
```

(`sqlite3 <src>.db ".dump"` vs `sqlite3 <restored>.db ".dump"` — `diff`
clean for both databases.)

## 6. Re-open with the real constructors + decrypt

A throwaway harness (deleted after the drill) opened the **restored** tree:

```
restored-verify: users=1 registry=demo feed_key_decrypted=32 bytes session=f425ffda8e56618072a62a0eaec3f54e6011e0dfb925c24bf08877d9df439e93 state=active
```

- `controlplane.OpenSQLite(restored/controlplane.db)` — migrations applied,
  v17;
- `Service.WithDecryptedFeedKey` decrypted the restored envelope under the
  drill master key (exactly 32 bytes — the AAD-bound envelope survived the
  entire round trip);
- `staging.NewService(restored/spool, restored/staging.db)` — startup
  reconciliation passed; the restored session read back as `active`.

## 7. `--include-master-key` opt-in (documented exception)

```
backup: PASS
  excluded secrets (restore out-of-band): internal-secret.txt internal-key.pem registry-jwks.json bee-password.txt
```

With the flag, `master.json` enters the archive (0600) and the manifest
records `"included": true`; the excluded list drops it. Discouraged, only
for archives encrypted at rest by the storage layer.

## Commands used (record)

```bash
# fixture (throwaway, deleted)
go run ./cmd/fixture-drill <data> <spool> <master.json>

# backup / verify / restore
bash scripts/operations/backup.sh --controlplane-db … --staging-db … \
  --staging-root … --compose-file … --secrets-dir … --out … --label drill-001
bash scripts/operations/verify-backup.sh --backup-dir backups/drill-001 --secrets-dir …
bash scripts/operations/restore.sh --backup-dir backups/drill-001 --dest restored --secrets-dir …
bash scripts/operations/verify-backup.sh --backup-dir tampered            # negative
# equivalence
sqlite3 live/data/controlplane.db ".dump" | diff - <(sqlite3 restored/controlplane.db ".dump")
# re-open + decrypt (throwaway, deleted)
DRILL_SESSION_ID=… go run ./cmd/verify-restored restored restored/spool live/secrets/master.json
```

## Deferred

Full reference-stack drill (push → back up live stack → destroy disposable
test deployment → restore → pull same digests): deferred to the Phase 4 /
real-Bee full-node gate (`docs/compatibility.md` §8). See
`docs/operations/backup-restore.md` → "The reference-stack push/pull drill
is deferred (honest status)".