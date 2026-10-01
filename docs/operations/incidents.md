# Incident runbooks (v1)

Recovery procedures grounded in the actual code. Error codes below are the
fixed Distribution envelope codes from `docs/compatibility.md` §9
(`INTEGRITY_ERROR`, `DEPENDENCY_UNAVAILABLE`, `PUBLICATION_UNVERIFIED`, …);
readiness components are those of `/readyz`
(`internal/controlplane/health.go`, `internal/registry/health.go`). Every
runbook: detect → scope → respond → verify → record.

Cross-cutting rule: **take and verify a backup before any destructive step**,
and again afterwards (`docs/operations/backup-restore.md`). Never print
secret values in incident notes.

---

## 1. Data / integrity incident (INTEGRITY_ERROR 502, checksum failures)

**Signals**

- Pulls return `INTEGRITY_ERROR` (502) — the registry re-verified a stored
  blob/manifest and its SHA-256/size did not match
  (`docs/compatibility.md` §9).
- `verify-backup.sh` reports a checksum mismatch or an `integrity_check`
  failure (drill: flipping one byte in a database produces exactly this
  signal while SQLite still reports `ok` — the SHA-256 layer, not SQLite,
  is the tamper detector).

**Response**

1. Scope: which path — Bee-stored content (pull-time verification) or the
   SQLite trees (backup verification)? Pull-side corruption originates in
   Bee content/retrieval; archive corruption originates in storage or a bad
   transfer.
2. Do **not** serve `INTEGRITY_ERROR` content: the registry already refuses
   it; leave it refused. Do not "repair" published state by rewriting
   manifests — a manifest/bundle whose digest is wrong must be re-pushed by
   the owner, not patched.
3. Determine damage window: `verify-backup.sh --secrets-dir …` over the last
   N archives tells you when checksums stopped matching; the manifest's
   `state_summary` tells you what rows existed at each backup.
4. Restore the affected tree from the newest archive that **passes**
   verification, into an isolated destination first, never in place
   (`restore.sh` refuses to overwrite a live deployment; that refusal is the
   gate you want here):
   ```bash
   bash scripts/operations/restore.sh --backup-dir backups/<good-label> \
     --dest /srv/restore-check --secrets-dir .secrets
   ```
   Confirm the restored DBs open with the real constructors (migrations at
   startup) and the control-plane feed keys decrypt (`key-rotation.md` §5).
5. Apply to the deployment only after the isolated restore passed.
6. Post-incident: find who wrote the bad bytes — transfer path, volume
   health, disk errors (dmesg/`smartctl`), and tighten verification cadence.
   Re-push corrupted published content.

**Verify/close:** clean `verify-backup.sh` on the restored archive, healthy
`/readyz`, a pull of a known-good digest succeeds, incident note records the
backup labels used.

---

## 2. Postage exhaustion / stamp failure

**Signals**

- Bee API rejects stamp operations (HTTP `400`/`402`-class on stamp usage);
  publications fail; `PUBLICATION_UNVERIFIED` (502) or `DEPENDENCY_UNAVAILABLE`
  (503) on push paths; control-plane `/readyz` may report the publication
  component not ready when required publications are outstanding
  (`CheckRequiredBeePublication` drains and checks the outbox).

**Response**

1. Confirm: query the stamp/batch via the Bee debug API (`:1635` loopback)
   and check `bee-data` volume space — stamps are a Bee-side resource.
2. Top up: buy a new postage stamp batch on the Bee node (normal Bee
   procedure against the local/real chain the node uses) or fund the
   existing batch.
3. The registry's stamp-policy documents which batch(es) its role/repo
   policy allows (`policy:stamp` topic, STAMP-001/002 in the design doc);
   after topping up, the existing batch id continues to be selected. If the
   policy references a specific batch id, update the policy document for the
   registry (control-plane API) once the new batch is live.
4. Trigger recovery: the reconciler/outbox continues bounded retries; a
   `/readyz` probe also performs one bounded drain per probe. Confirm
   outstanding publication jobs fall to zero (`/metrics`,
   `registry_publication_jobs` counts; `/readyz` returns 200).

**Verify/close:** `/readyz` 200 on the control plane, push of a fixture
succeeds (Phase 4 full-node gate permitting), Bee reports the batch funded.

---

## 3. Bee outage

**Signals**

- `DEPENDENCY_UNAVAILABLE` 503 on pull/push paths; control-plane
  `/readyz` reports the publication component not ready (its probe runs a
  real bounded drain and reports not-ready on failure);
  `docker compose ps` shows `bee` unhealthy; logs show retryable dependency
  errors from `swarm.BeeObjectStore` / `BeeRegistryFeedUpdater` (bounded
  HTTP client; a stalled node can never block a service forever).

**Response**

1. Check the node: `docker compose ps bee`, its logs, disk and listener
   state (`:1633` API, `:1635` debug).
2. Restart Bee: `docker compose --env-file .env restart bee`. The data
   plane and control plane keep their bounded retries; do not restart them
   reflexively — they recover when Bee does.
3. If Bee will be down long: consider `docker compose stop registry controlplane`
   to fail fast and avoid a retry storm, and resume when Bee is healthy.
4. After recovery: confirm the publication outbox drains (`/readyz`, metrics)
   and a pull works.

**Verify/close:** `/readyz` on 8081 + 80, `bee` healthy, digest pull
succeeds (Phase 4 gate permitting), incident note records Bee's
restart/root-cause.

---

## 4. Signer outage (control-plane internal feed signer)

**Signals**

- Registry internal requests to the control plane's feed-signing listener
  (`:8089`, TLS, `CONTROLPLANE_INTERNAL_SECRET_FILE`) fail; push/finalize
  paths answer `DEPENDENCY_UNAVAILABLE` (503) or `PUBLICATION_UNVERIFIED`
  (502); control-plane `/readyz` shows the signing-key component not ready
  (loaded-master-key check: `CheckSigningKey` fails when the master key is
  unloaded); registry logs show internal-credential rejection or TLS/CA
  failures.

**Response**

1. Scope: listener health (`docker compose ps controlplane`), the
   internal-secret file, and the internal TLS pair (`internal-cert.pem` /
   `internal-key.pem` / `internal-ca.pem`). A credential mismatch between
   the two containers (secret rotated in one place) also surfaces here.
2. `CONTROLPLANE_INTERNAL_SECRET_FILE` is loaded once at startup and the
   master key with it; a rotation means a coordinated restart of both
   services (control plane first, then registry — `key-rotation.md` for the
   master-key procedure; the internal secret rotates the same way as any
   mounted credential).
3. Certificates: the internal listener validates its pair at startup and
   fails closed (`credential.LoadTLSKeyPair`); reissue via install.md §3 if
   expired. `REGISTRY_TOKEN_PUBLIC_KEYS_FILE` / the CA bundle are loaded
   once at registry startup, so a replaced CA requires a registry restart.

**Verify/close:** `/readyz` 200 on both services, internal requests succeed
(a push path exercising finalize), logs clean of credential/TLS rejections.

---

## 5. Staging disk pressure

**Signals**

- Append/finalize paths return quota failures (413-class) or `BLOB_UPLOAD_INVALID`;
  disk fills below the staging watermark; registry logs show
  `REGISTRY_MAX_TOTAL_STAGING_BYTES` / `REGISTRY_MAX_REPOSITORY_BYTES`
  enforcement (durable staging quotas are atomic, enforced inside every
  Begin-Immediate append transaction — `staging.Service.SetLimits`).

**Response**

1. Measure before acting: `df -h` the staging volume and
   `du -sh <spool>`; check `REGISTRY_CLEANUP_INTERVAL`/`BATCH` behavior —
   the reaper traverses expired sessions via the durable cursor
   (`cleanup_cursor`, v11) and unpins Bee refs; confirm it is running.
2. If quotas are the cause, they are config: raise the `.env` limits
   (`REGISTRY_MAX_*`) and restart the registry — quotas are installed at
   service start.
3. If disk, not quotas: abort long-running uploads (they self-heal through
   TTL expiry), optionally force expiry:
   `sqlite3 staging.db "select count(*) from upload_sessions where state in ('active','creating') and expires_at < <now-nanos>;"`
   then let the cleanup loop claim them — do not DELETE rows by hand (the
   schema's triggers and cascade are the only safe mutation paths; hand
   deletes strand quota-charged bytes).
4. Persistent pressure: back up (`backup.sh`), and if the spool is bloated
   beyond TTL, consider a maintenance window with the registry stopped:
   nothing in the spool is needed for pull (published state lives in Bee),
   so a clean spool is recovered by TTL expiry + reconciliation.

**Verify/close:** disk back under watermark, `REGISTRY_MAX_TOTAL_STAGING_BYTES`
counts drop, `/readyz` healthy, incident note records the delta.

Sizing references: `compose.yaml` defaults — `REGISTRY_MAX_UPLOAD_BYTES=2 GiB`,
`REGISTRY_MAX_REPOSITORY_BYTES=25 GiB`,
`REGISTRY_MAX_TOTAL_STAGING_BYTES=50 GiB`, cleanup every 5m, batch 100.

---

## 6. Credential exposure

**Signals**

- A secret value appears where it should not (logs, an external paste, a
  leaked `.env`, a compromised host).

**Immediate (all exposures):**

1. Assume the worst for exactly the exposed material and nothing else.
   Rotate immediately — procedures in `key-rotation.md`:
   - `CONTROLPLANE_TOKEN_SECRET` → §2 (instant, logs everyone out — correct
     for exposure).
   - `CONTROLPLANE_REGISTRY_ED25519_KEY` → §1 (gradual kid overlap; the old
     public key stays in `registry-jwks.json` during the window; a
     compromised signer means you likely want the full window regardless).
   - `master.json` → §3 (add v2, re-encrypt rows, retire v1 only after
     verification; a compromised master key means every stored feed-key
     envelope is at risk until re-encryption completes — do not remove v1
     earlier than §3 step 6 permits).
   - `internal-secret.txt` → rotate the mounted credential, restart
     control plane then registry (coordination, §4).
   - `bee-password.txt` / Bee keystore → rotate the Bee password per Bee
     procedure; the keystore itself is in `bee-data`.
2. Restrict: revoke/replace any published value (`.env` is never in the
   repo nor in backups — check the secret manager's rotation history).
3. Audit: `scripts/security/check-repository-secrets.sh` (the enforced
   git/grep gate), plus the CI secret scan, to confirm nothing is tracked.
4. Post-incident: rotate credentials that were *plausibly* derivable too
   (same host, same keychain), never reuse rotated-out values.

**Verify/close:** all rotations verified per `key-rotation.md` §5, secret
scan clean, fresh backup taken and verified, incident note lists exactly
which material was exposed and which rotations ran.

---

## Post-incident discipline

- Record: date, signals, scope, backup labels used, commands run, verify
  results — in the incidence tracker; update these runbooks when the code
  changes behavior.
- Re-drill: after any rotation that touched `master.json` or the registry
  JWKS, run the backup→restore→decrypt round trip
  (`docs/evidence/phase-5-recovery.md` shows the reference procedure).