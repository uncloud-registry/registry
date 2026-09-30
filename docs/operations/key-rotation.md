# Key rotation (v1)

This runbook covers every key the deployment holds, grounded in the actual
code paths (`internal/auth/`, `internal/controlplane/keycrypto.go`,
`internal/controlplane/service.go`, `internal/auth/jwks.go`). Four distinct
materials rotate on four different schedules:

| Material | Location | Rotation window | Overlap on rotation? |
|----------|----------|-----------------|----------------------|
| Registry-token signing key (Ed25519) | `.env` → control plane; public keys in `registry-jwks.json` → registry | gradual, kid-based | **Yes** — both kids stay in the JWKS during the window |
| Session key (`CONTROLPLANE_TOKEN_SECRET`, HMAC-SHA256) | `.env` → control plane | instant | **No** — single key; rotation invalidates all sessions |
| Master key (feed-key encryption) | `master.json` in `SECRETS_DIR` | gradual, versioned | **Yes** — old versions stay loaded for decryption |
| Feed-owner signing key (per registry, encrypted) | `registries.feed_key_*` columns | **not in place** — see §4 | n/a |

Before any rotation: take and verify a backup
(`docs/operations/backup-restore.md`). Every procedure below ends with
verification and states the rollback path.

## 1. Registry-token signing key rotation (overlap by `kid`)

The control plane issues registry bearer tokens signed with an Ed25519 key
whose ID (`kid`) is `CONTROLPLANE_REGISTRY_KEY_ID`. The registry data plane
verifies tokens against the **strict, immutable JWKS file**
`registry-jwks.json` (`auth.LoadJWKSFromFile`): every unique kid in the
document is resolvable until the file is replaced, so the JWKS is the
overlap mechanism (`internal/auth/jwks.go` — "Key rotation is preserved:
every unique kid in the document is resolvable until the set is replaced").
The file is loaded **once at process start** (`cmd/registry/main.go`), so
the registry must be restarted to observe a JWKS change. Originally-issued
tokens stay verifiable for their whole TTL because their kid remains
present.

**Rotate (gradual):**

1. Generate a new seed and kid:
   ```bash
   NEW_SEED=$(openssl rand -hex 32)          # CONTROLPLANE_REGISTRY_ED25519_KEY value
   NEW_KID=cp-ed25519-2                      # CONTROLPLANE_REGISTRY_KEY_ID value
   ```
2. Derive the new public key and **append** it to `registry-jwks.json`
   (same derivation as install.md §4); both `cp-ed25519-1` and
   `cp-ed25519-2` are now present. Restart the **registry** service — it now
   accepts tokens signed by either kid.
3. Point the control plane at the new key: set
   `CONTROLPLANE_REGISTRY_ED25519_KEY=$NEW_SEED`,
   `CONTROLPLANE_REGISTRY_KEY_ID=$NEW_KID` in `.env`, restart the
   **control plane**. New tokens are signed with `cp-ed25519-2`; tokens
   issued before the switch still verify (old kid remains in the JWKS).
4. After the maximum token TTL (registry tokens are short-lived; default
   window is hours), remove `cp-ed25519-1` from `registry-jwks.json` and
   restart the registry. The old key can then be destroyed.

**Verification:** after step 3, `docker login`/push/pull on a previously
authenticated client still works (old tokens), and a fresh login produces
tokens verifiable by the registry. Confirm with:
`bash scripts/operations/verify-backup.sh` for the pre-rotation backup, and
inspect `key-versions.json` → `registry_jwks_kids` (identifiers only) in the
next backup — it must list both kids during the window and only the new kid
after step 4.

**Rollback (window only):** revert `.env` to the old seed/kid, restart the
control plane and (if you already removed it) restore `cp-ed25519-1` in the
JWKS, restart the registry. Ungraceful after step 4 (old key destroyed): the
control plane is the only signer, so simply issue with the new key — nothing
else breaks.

## 2. Session-key rotation

Sessions are HS256 tokens signed with the single `CONTROLPLANE_TOKEN_SECRET`
(`auth.SessionTokenManager`). There is **no key overlap**: the manager holds
exactly one key, and verification uses that same key. Rotating the secret
therefore invalidates every outstanding session (plus their CSRF values) —
users are signed out and must log in again. Default session TTL is 24h, so
an unrotated key's exposure window is bounded by that.

**Rotate (instant):**

1. Generate a new secret:
   `openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 43` — set
   `CONTROLPLANE_TOKEN_SECRET` in `.env`.
2. Restart the control plane. All sessions are now invalid; existing cookies
   fail verification and users re-authenticate.

**Verification:** any pre-rotation cookie now returns the generic
unauthenticated response; a fresh login issues a working session.

**Rollback:** put the old secret back and restart — sessions signed with the
old value verify again. (Rolling forward is preferred over rolling back when
the rotation was a compromise response.)

## 3. Master-key rotation and feed-key re-encryption

The master key is the v1 feed-key encryption key: a JSON document
`{"current":N,"keys":{"1":"<unpadded base64url, exactly 32 bytes>", ...}}`
read strictly at startup (`controlplane.LoadMasterKeyFile`). Every registry
feed key is stored as an AES-GCM envelope
(`registries.feed_key_ciphertext|nonce|version`) whose **version** picks the
master-key version used to seal it; old versions remain loaded in the cipher
so old envelopes keep decrypting (`keycrypto.go`). The feed-owner address
and registry ID are bound into each envelope as authenticated AAD
(`feedKeyAAD`), so **renaming a registry or changing its owner would break
decryption** — see §4.

Re-encryption of rows to the new version is implemented as
`Service.ReencryptFeedKeys(fromVersion, toVersion)`
(`internal/controlplane/service.go`): per-row decrypt-under-old /
re-seal-under-new inside one write transaction per row, resumable, fail
closed on any row that does not authenticate. **It is a library operation —
v1 ships no HTTP/CLI trigger for it.** The rotation procedure below records
this honestly: the operator performs the pass with a small tool built against
the package (a `go run` harness calling `Service.ReencryptFeedKeys` with the
deployment's `Store` and `FeedKeyCipher`), or defers the pass — rows remain
readable because old versions stay loaded.

**Rotate (gradual):**

1. Backup + verify first (`backup-restore.md`).
2. While the service is down: add version 2 to `master.json` and set
   `current` to 2, keeping version 1:
   `{"current":2,"keys":{"1":"<old>","2":"<openssl rand 32 | base64 | tr -d '=\n' | tr '+/' '-_'>"}}`.
   Mode 0600. (The strict parser requires canonical, unpadded, exactly-32-byte
   values; a malformed document fails startup — that is the signal, not a
   silent fallback.)
3. Start the control plane. `/readyz`'s master-key component confirms the
   new cipher is loaded; existing registries still sign because version 1
   envelopes still decrypt.
4. Run the re-encryption pass
   (`Service.ReencryptFeedKeys(1, 2)` harness — see above). It reports
   reencrypted/skipped counts; a row that fails to authenticate aborts the
   pass unchanged (safety over progress).
5. Verify: the next backup's `key-versions.json` shows
   `master_key_current_version: 2`; confirm envelopes moved by checking the
   distribution of `feed_key_version` in `registries`
   (`sqlite3 data/controlplane.db "select feed_key_version, count(*) from registries group by 1"` —
   all rows 2).
6. Only after every row is version 2 and verified: remove version 1 from
   `master.json`, restart, confirm `current=2` and a healthy `/readyz`.
7. Keep the v1 key in your secret manager until the next successful restore
   drill (a restore from a pre-rotation backup needs v1).

**Rollback:** restore the previous `master.json` (v1 current, v1 only) and
restart — v1 envelopes are untouched. Mid-pass rollback is safe because
`ReencryptFeedKeys` is per-row transactional and resumable; a row is either
entirely v1 or entirely v2. Never restore a pre-rotation backup (whose
envelopes are v1) without v1 loaded (step 7).

## 4. Feed-owner rotation — limitations (honest)

The feed owner address is set at registry creation and **cannot be changed
in place**:

- `Store.UpdateRegistrySettings` only changes `anonymous_pull` and
  `default_stamp_batch_id`; there is no owner-update path
  (`internal/controlplane/store.go`).
- The owner is bound into every feed-key envelope as AES-GCM AAD
  (`feedKeyAAD(registryID, owner)`), so an owner change would make stored
  envelopes undecryptable — there is deliberately no migration that rewrites
  them.
- All deterministic topics (`v1:policy:auth`, `v1:policy:stamp`,
  `v1:repo:<name>`) derive from the owner address, so changing ownership
  changes every feed identity.

**Planned feed-owner rotation therefore means "migrate to a new registry":**

1. Create the new registry under the new owner (control-plane API/dashboard).
2. Re-push all repositories to the new host (clients switch
   `REGISTRY_OWNER_MAP`/`REGISTRY_ID_MAP`/`REGISTRY_TOKEN_AUDIENCE` to the
   new owner/host).
3. Cut clients over; keep the old registry alive through the migration
   window (it continues to serve pulls from its existing Bee-published
   state).
4. Decommission the old registry when nothing references it.

This is a documented product limitation (SEC-008 requires "documented policy
and repository migration behavior"), not a bug: the feed key stays bound to
its owner for the registry's lifetime, and rotation is a registry-level
re-provision, not an in-place owner edit.

## 5. Verification discipline (all rotations)

- Before: `bash scripts/operations/backup.sh` + `verify-backup.sh` — the
  archive records `key-versions.json` (master versions + JWKS kids) so the
  pre-rotation state is auditable.
- After: restart cleanly, watch `/readyz` on 8081 and 80 (master-key /
  signing-key / publication components are covered by the control-plane
  readiness probe), exercise a login, and for token/feed-key rotations run a
  real decrypt path (`controlplane.Service.WithDecryptedFeedKey` resolves and
  decrypts a registry's feed key on demand; a drive-by
  `/api/registries`-backed signing flow exercises it).
- Store rotated-out material in the secret manager, not in the repository,
  and keep the pre-rotation backup until the next restore drill passes.