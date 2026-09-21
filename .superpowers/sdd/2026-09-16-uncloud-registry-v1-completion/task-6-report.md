# Task 6 Report: Encrypt feed-owner keys and support rotation

Base: `f7429c92f4498a330416ccd4b10d97f95a5c2c89` → Commit: `<commit>` `feat: encrypt registry feed keys at rest`

## RED (captured against the base)

New task-6 tests were written FIRST against the pre-change code and captured
failing before any implementation:

```
$ go test ./internal/controlplane -run 'TestFeedKey|TestLoadMasterKey|...' -count=1
# github.com/uncloud-registry/registry/internal/controlplane [build failed]
internal/controlplane/keycrypto_test.go:33:42: undefined: FeedKeyCipher
internal/controlplane/keycrypto_store_test.go:27:3: unknown field FeedKeys in struct literal of type Service
internal/controlplane/keycrypto_store_test.go:94:5: too many arguments in call to store.CreateRegistry
    have (context.Context, Registry, unknown type, string)
    want (context.Context, Registry)
internal/controlplane/keycrypto_store_test.go:98:14: created.FeedKeySet undefined (type Registry has no field or method FeedKeySet)
... (build failed)
```

and:

```
$ go test ./cmd/controlplane -run TestMasterKey -count=1
cmd/controlplane/main_test.go:85:15: undefined: masterKeyFileFromEnv
cmd/controlplane/main_test.go:107:21: undefined: legacyKeyMigrationEnabled
FAIL  github.com/uncloud-registry/registry/cmd/controlplane [build failed]
```

None of the Task 6 surface existed (`FeedKeyCipher`, `EncryptedFeedKey`,
`LoadMasterKeyFile`, `Service.FeedKeys`/`ReencryptFeedKeys`/`MigrateLegacyFeedKeys`,
context-bound `CreateRegistry`). All RED tests are preserved in
`internal/controlplane/keycrypto_test.go`, `keycrypto_store_test.go`,
`masterkey_open_{unix,other,static}_test.go`, and the `cmd/controlplane`
main_test.go additions.

## Design summary

### AES-256-GCM envelope, context-bound (Binding ruling 1)

`internal/controlplane/keycrypto.go`:

- `EncryptedFeedKey{Ciphertext, Nonce []byte; KeyVersion int}` — the only
  at-rest form; persisted as BLOB/BLOB/INTEGER columns.
- `FeedKeyCipher` — immutable versioned key set (`NewFeedKeyCipher(keys,
  current)`); `Encrypt(registryID, owner, plaintext)` /
  `EncryptWith(version, registryID, owner, plaintext)` /
  `Decrypt(registryID, owner, value)`. The brief's context-free sketches are
  NOT implemented: AES-GCM AAD is an unambiguous 8-byte big-endian
  length-prefixed registry ID, a `:` separator, then the LITERAL feed-owner
  address bytes (never normalized/case-folded). Cross-registry, cross-owner,
  and owner-case substitution all fail authentication
  (`TestFeedKeyCipherRejectsAADSubstitution`); empty owner is rejected
  (`errFeedKeyEmptyContext`), so an unbound envelope cannot be created.
- Sentinels: `ErrKeyDecrypt` (wraps every GCM failure — tampering, wrong
  master key, context substitution; never echoes key bytes),
  `ErrFeedKeyVersionUnloaded` (unsupported version),
  `errFeedKeyCipherNotConfigured` (fail-closed when no cipher is wired).
- Fresh 12-byte GCM random nonces per encryption; empty plaintext round-trips.
- `zeroBytes` wipes transient plaintext after decryption (rotation,
  `DecryptFeedKey`) where practical.

### Strict versioned master-key file (Binding ruling 2)

Wire format (strict JSON): `{"current": 1, "keys": {"1": "<unpadded
base64url 32 bytes>"}}`.

- `current`: explicit integer — RawMessage token must start with a digit
  (rejects JSON strings, `null`, booleans, arrays, objects — encoding/json
  would happily unmarshal a string into `json.Number`), all digits (rejects
  `1.0`, `1e0`, `-1`), canonical decimal text, positive, and present in
  `keys` (`parseMasterKeyDocument` + `NewFeedKeyCipher`).
- `keys`: canonical positive decimal version strings (`^[1-9][0-9]*$`, no
  leading zeros/sign/exponent/whitespace, overflow-guarded); values are strict
  unpadded base64url decoding to exactly 32 bytes with canonical round-trip
  (non-zero pad bits rejected) — mirroring Task 5's `x`-coordinate discipline.
- Rejects: duplicate members anywhere (token-level walker, before typed
  decode), unknown top-level members, missing current, empty/oversized
  documents, trailing data.
- `LoadMasterKeyFile`: same trust-store discipline as Task 5's JWKS loader —
  on darwin/linux `syscall.Open(O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK)`
  once, the opened descriptor Fstat-validated (regular file, not symlink, not
  group/world-writable (`perm&022==0`), size ≤ 1 MiB via stat + hard
  post-read `LimitReader(max+1)` bound), TOCTOU closed by construction. On
  every other GOOS `openMasterKeyFile` returns the bare
  `ErrMasterKeyFileLoadingUnsupported` sentinel WITHOUT touching the path
  (declared in keycrypto.go so it compiles everywhere). NO key or path
  material in any error or log (data-free by design; the path is an operator
  secret value).

### Schema transition (migration 2)

`internal/controlplane/migrations.go` adds version 2 (pure DDL):

```sql
alter table registries add column feed_key_ciphertext blob
alter table registries add column feed_key_nonce blob
alter table registries add column feed_key_version integer
```

- The schema migration NEVER reads, touches, or clears the legacy
  `encrypted_feed_private_key` column (pinned by
  `TestLegacyPlaintextNeverMigratedWithoutOptIn`). The legacy column survives
  as an empty vestigial column; dropping it is deliberately deferred because
  the same migration must run on databases whose legacy rows still carry
  plaintext and SQLite `DROP COLUMN` would discard it.
- Existing store queries select ONLY the encrypted columns; `CreateRegistry`
  inserts `''` into the vestigial column and the three new columns; fresh
  schemas never rely on plaintext.
- Runtime opt-in/cipher reach the migration WITHOUT global state: legacy data
  migration is a separate operation (`Service.MigrateLegacyFeedKeys`) that
  main invokes ONLY when `CONTROLPLANE_MIGRATE_LEGACY_KEYS=true` and after the
  cipher is loaded; the migration framework stays config-free.
- `Registry` model: `EncryptedFeedPrivateKey string` is gone; replaced by
  `FeedKey EncryptedFeedKey` + `FeedKeySet bool` — no ambiguous secret field.

### Legacy migration (opt-in gated)

`Store.MigrateLegacyFeedKeys(ctx, cipher)` → per-row transaction:
`ListLegacyFeedKeyRows` (the ONLY reader of the legacy column; reachable only
under opt-in) then for each row with non-empty legacy plaintext and no
existing version: re-read in-tx, `Encrypt` with the row's OWN id/owner AAD,
write ciphertext+nonce+version AND clear the legacy column to `''` in the
same statement/transaction — no intermediate half-migrated state;
encryption failure rolls the row back and aborts with a data-free error
(`TestMigrateLegacyFeedKeysRollsBackOnFailure`); already-encrypted rows are
skipped; idempotent (`TestMigrateLegacyFeedKeysEncryptsAndClearsAtomically`).
Opt-in parsing is strict: only literal `true` enables migration; any other
non-blank value fails startup (`TestLegacyKeyMigrationEnabled`).

### Rotation (`Service.ReencryptFeedKeys(ctx, fromVersion, toVersion)`)

- One registry per transaction; `Store.ReencryptRegistryFeedKey` re-reads the
  row in-tx, skips rows without a stored key or whose stored version !=
  fromVersion (untouched — resumable, no partial runs), decrypts the old
  envelope under the row's OWN fresh owner/ID context (tampering →
  `ErrKeyDecrypt`, row left fully unchanged), re-seals under the EXPLICITLY
  requested loaded `toVersion` (validated up front, not merely `current`)
  preserving the owner, updates atomically, zeroes the transient plaintext.
- Returns `FeedKeyReencryptResult{Reencrypted, Skipped}`; errors carry no key
  or owner material (registry ID + version numbers only).
- Behaviors pinned: happy path with a pre-existing v2 row skipped intact
  (`TestReencryptFeedKeysRotatesRows`), bad arguments (same version, unloaded
  source/target, nil cipher), tampered row fail-closed rollback
  (`TestReencryptFeedKeysTamperedRowFailsAndRollsBack`), no-key rows skipped.

### Publisher boundary (no ciphertext at the signer)

`BeeRegistryFeedUpdater` gains a `FeedKeyDecryptor` (`Service.DecryptFeedKey`
re-reads the row fresh and decrypts with the row's own context; bytes zeroed
before the string conversion). Without a decryptor it refuses outright;
with one, only decrypted key material reaches `swarm.NewBeeSequenceFeedUpdater`
— stored ciphertext is never handed to the signer, and plaintext is never at
rest (`TestBeeRegistryFeedUpdaterBoundary`). Task 9/10 consume this boundary.

### cmd/controlplane/main.go

- `CONTROLPLANE_MASTER_KEY_FILE` REQUIRED (no default; byte-preserving path,
  error names the variable only). `LoadMasterKeyFile` failure fails startup.
- `CONTROLPLANE_MIGRATE_LEGACY_KEYS` strict opt-in runs `MigrateLegacyFeedKeys`
  before serving.
- `Service.FeedKeys` wired; Bee publisher wired with `Keys: service`.
- No command-line secret values.

### Fail-closed service behavior

`Service.CreateRegistry`/`MigrateLegacyFeedKeys`/`ReencryptFeedKeys`/
`DecryptFeedKey` all return `errFeedKeyCipherNotConfigured` when no cipher is
configured; the store refuses cipher-with-empty-plaintext creates. Existing
tests were migrated coherently: test Services construct
`newTestFeedKeyCipher`, direct `CreateRegistry` call sites use the new
signature, and `migrations_test.go` version assertions moved 1 → 2.

## Commands / results

- `go test ./internal/controlplane -run 'TestFeedKey|TestUpgradeCurrentSchema' -count=1 -v`
  → PASS (Step 2 RED captured before implementation; Step 7 PASS after).
- `go test -race -count=1 ./...` → all packages ok (controlplane 41.9s).
- `go vet ./...` → clean. `go mod verify` → all modules verified.
- `git diff --check` → clean. `gofmt -l internal/controlplane cmd/controlplane` → clean
  (gofmt also normalized `invite_flash.go`'s missing trailing newline).
- `bash scripts/security/check-repository-secrets.sh` → "repository secret scan clean".
- Cross-compile of the platform-tagged loader (+ tests) → darwin amd64/arm64,
  linux amd64, freebsd amd64, windows amd64 `go test -c` all OK; the
  unsupported-GOOS fail-closed behavior is validated by those compiles plus
  the source-level pins in `masterkey_open_static_test.go`.

## Files

- New: `internal/controlplane/keycrypto.go`, `keycrypto_test.go`,
  `keycrypto_store_test.go`, `masterkey_open_unix.go`,
  `masterkey_open_other.go`, `masterkey_open_unix_test.go`,
  `masterkey_open_other_test.go`, `masterkey_open_static_test.go`.
- Modified: `internal/controlplane/{store,service,publisher,migrations,dto}.go`
  and their tests; `cmd/controlplane/main.go`, `main_test.go`.

## Commit

`feat: encrypt registry feed keys at rest`

## Concerns

- The vestigial `encrypted_feed_private_key` column remains in the schema
  (empty on every row after migration/creation). Dropping it is deferred to a
  schema/DBA task so the same migration stays safe on plaintext-carrying
  databases; the final branch review should triage a follow-up `DROP
  COLUMN`/rebuild once legacy deployments are known to be migrated.
- `Service.DecryptFeedKey` returns a hex string (Go strings cannot be zeroed);
  the intermediate byte buffer is zeroed, and Task 9/10's constrained signing
  service should consume the key without ever stringifying it where possible.
- `CONTROLPLANE_MIGRATE_LEGACY_KEYS` rejects any non-"true" non-blank value
  (including "false") at startup — intentional fail-closed strictness; if an
  operator prefers an explicit "false", document it in the runbook (Task 26).