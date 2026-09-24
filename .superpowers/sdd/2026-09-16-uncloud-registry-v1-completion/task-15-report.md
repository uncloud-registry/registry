# Task 15 Report — Durable Upload Staging (Filesystem Spool + SQLite Metadata)

Branch: feat/v1-completion · base: 8192a7f51c822806a487701272c9d7235b7a367f
Commit: `feat: persist upload staging to disk and SQLite` (54bcb33)

## Summary

Upload staging is now durable end-to-end: blob bytes live in a fail-closed
`os.Root`-based filesystem spool (0700 dirs, 0600 files, O_NOFOLLOW,
descriptor-relative access so symlink/path escapes are refused), and
session/blob lifecycle state lives in a dedicated SQLite database with a
schema-verified single-version migration. The existing in-memory `Store`
contract used by Tasks 1–14 is untouched: `store.go` only gained shared
type/validator/error additions plus `MemoryStore.ClearStagedBlobsByDigest`.
Task 16 owns production handler wiring, ranges, and quotas.

`Service` implements the plan-approved interface: `Create`, `Status`,
`Append` (streaming bounded append with expected-offset serialization),
`Open` (exact committed prefix), `MarkFinalized`, `ListFinalized`, `Delete`
(tombstone → unlink → delete), and `Expire` (startup reconciliation
included). All errors are typed and data-free (no IDs, repos, actors, paths,
or SQL in messages); validation is Unicode-safe byte grammar.

## RED evidence (captured before implementation)

The three new suites (`service_test.go`, `spool_test.go`, `sqlite_test.go`,
3,247 lines total) were written first, against no production API beyond the
existing Store. The RED run:

```
$ go vet ./internal/staging/
vet: internal/staging/service_test.go:...: undefined: NewService
vet: internal/staging/service_test.go:...: undefined: Session
vet: internal/staging/service_test.go:...: undefined: Service (interface)
vet: internal/staging/spool_test.go:...: undefined: spool / rootedPath
vet: internal/staging/sqlite_test.go:...: undefined: normalizeDSN / openStagingDB
```

Behavioral RED (first full-suite executions of the new code, before fixes):

- `path has group or other access` — the service correctly refuses loose
  (0755) spool/DB parents; tests now chmod their temp roots to 0700
  (`tempPrivate`), which is also the realistic deployment shape.
- `cannot commit - no transaction is active` — a duplicated `end` in the
  `trg_blob_update` trigger body (schedule typo) silently ended the migration
  transaction; fixed to a single `end`. This RED exposed the fatal
  consequence of not running the full adversarially-seeded suite early.
- `offset mismatch` after `set offset='4'` — INTEGER-affinity coerced numeric
  TEXT/REAL into INTEGER before `typeof()` CHECKs could see them. Integer
  fields are now declared WITHOUT a type name (BLOB affinity), so storage
  class is pinned by the CHECK alone: numeric text, REAL, and BLOB values are
  rejected, not coerced.
- `GO valid=true schema accepted=false` in grammar parity — the probe reused
  one session ID while `staged_blobs.upload_id` is a per-session PK; probes
  now seed one session per case. Uniqueness is the schema's 1:1 invariant,
  not a grammar loophole.
- final-offset arithmetic in the cross-instance stress test assumed a fixed
  chunk width ("A10;" is 4 bytes, not 3); expected totals are now computed
  per chunk.
- `staging backend unavailable` instead of `context.Canceled` — `withTx` now
  checks the context before acquiring a pooled connection, and surfaces
  `ctx.Err()` on connect failure.

## GREEN evidence

```
$ go test ./internal/staging/ -count=1
ok  github.com/uncloud-registry/registry/internal/staging   1.7s   (165 tests)

$ go test ./internal/staging/ -count=1 -race
ok  github.com/uncloud-registry/registry/internal/staging   9.4s

$ go test ./... -count=1
ok  ... cmd/controlplane 28.4s, cmd/registry, internal/auth, internal/config,
    internal/controlplane, internal/credential, internal/policy,
    internal/publish, internal/registry, internal/resolve,
    internal/spec, internal/staging 6.6s, internal/swarm

$ go test ./... -count=1 -race
ok  ... (all packages; controlplane 356s — pre-existing suite, untouched)
```

## WAL / foreign-keys evidence (4 distinct pooled connections)

```
conn0 journal_mode=wal foreign_keys=1 synchronous=2
conn1 journal_mode=wal foreign_keys=1 synchronous=2
conn2 journal_mode=wal foreign_keys=1 synchronous=2
conn3 journal_mode=wal foreign_keys=1 synchronous=2
```

Every pooled connection inherits `foreign_keys(1)`, `journal_mode(WAL)`,
`synchronous(FULL)`, and a bounded `busy_timeout(5000)` from the normalized
DSN (conflicting pragmas stripped); `PRAGMA foreign_keys` is never toggled
per-connection. `PRAGMA foreign_key_check` passes on a migrated database, and
deleting a tombstoned session cascades its staged blob.

## Durability & concurrency design (verified by tests)

- **Descriptor-relative spool**: the root is opened via `os.Root` and every
  production open/append/align/remove goes through it with `O_NOFOLLOW`;
  `rootedPath` is diagnostics-only. Symlinked files/spool-root, non-directory
  roots, and path-rewrite escapes (`..`, `.`, `//`, `\`, absolute) are
  rejected fail-closed (incl. ELOOP probes).
- **Streaming bounded append**: `io.CopyBuffer` through an `io.LimitedReader`
  plus a one-byte overflow probe rejects with `ErrTooLarge` before any byte
  is retained (truncate-to-committed-offset on failure, zero partial state).
- **Offset ordering**: `Append` requires the exact expected offset; updates
  run under `BEGIN IMMEDIATE` on a pinned `*sql.Conn` with bounded,
  context-aware whole-transaction retry on busy; fsync (FULL) precedes the
  offset update, and commit-failure truncates the file back to the committed
  offset. Fault injection tests drive fsync failure, DB-write failure, and
  commit failure through the same path and prove no partial bytes survive.
- **Cross-instance serialization**: two independent `Service` instances on the
  same spool/DB serialize appends (single winner at offset 0) and merge 50
  interleaved chunks without byte loss or interleaving.
- **Restart/fault**: startup reconciles spool↔DB (truncates/extends files to
  committed offsets; removes orphan files; finishes crashed deletes).
  `TestServiceRestartTruncatesTailAppend`, `TestServiceRestartRemovesOrphanFiles`,
  and the delete-crash retry test cover kill-between-write-and-commit shapes.
- **Ownership & expiry**: repo+actor checks on every op; created/expires are
  integer nanos, expiry checked with a real clock in the loop; delete is
  idempotent for the owner; expiry is a system op with bounded batching.
- **Byte-identical rejection**: schema decisions are made on a pragma-free
  inspection connection FIRST; foreign/unknown databases are rejected before
  any mutation-capable connection opens (no `journal_mode` header rewrite), and
  the tests assert the seeded bytes are unchanged after rejection.
- **Storage-class strictness**: integer columns are affinity-free; `typeof()`
  CHECKs + transition triggers reject numeric text, REAL, BLOB, overflow
  (REAL-ized > MaxInt64), NULLs, expired-before-created pairs, and every
  illegal state transition (return-to-active, finalize-without-blob,
  metadata-clearing, identity mutation, live-blob deletion) on both INSERT
  and UPDATE, per the sqlite-migration-safety skill.

## Gates

```
go test ./... -count=1           ok
go test ./... -count=1 -race     ok
go vet ./...                     ok
gofmt -l (repo)                  clean
go mod tidy                      no diff
go mod verify                    all modules verified
git diff --check                 clean
scripts/security/check-repository-secrets.sh   clean
controlplane.db / user data      untouched (all tests use private temp dirs)
```

## Files

- `internal/staging/store.go` — shared types (`State`), typed errors
  (`ErrInvalidInput/NotFound/OwnerMismatch/OffsetMismatch/TooLarge/Expired/
  InvalidState/FinalizeConflict/ErrDependency`), byte-grammar validators,
  `typed()` wrapper; Tasks 1–14 `Store`/`MemoryStore` contract unchanged.
- `internal/staging/spool.go` (297 stmts) — `os.Root`-based spool, 0700 roots,
  0600 files, fail-closed path handling.
- `internal/staging/sqlite.go` (656) — DSN normalization, fresh/known/foreign
  decision on an inspection connection, single-version migration in one
  transaction with fault injection, full physical verification, CHECKs +
  8 triggers, WAL/FULL/busy pragmas.
- `internal/staging/service.go` (809) — `NewService`, the durable `Service`
  implementation, `withTx` (BEGIN IMMEDIATE + bounded retry + fault hooks),
  reconcile-on-start, all seven operations.
- Tests: `service_test.go` (1,517), `spool_test.go` (395),
  `sqlite_test.go` (810) — 165 tests, all adversarial-first.

## Concerns

- Spool tail-extension on restart applies to every row at startup; with very
  large session counts this is O(sessions) stat calls. Acceptable for Task 15;
  Task 16's quota/policy layer can bound it.
- `Append` holds the global write lock for the duration of the copy; a slow
  client delays other writers up to the busy timeout (5s) before their
  whole-transaction retry kicks in. Task 16's ranges/quota workstream should
  keep per-request copy time bounded.
- The approved interface is implemented as-is; content integrity is settled
  at `MarkFinalized` (size must equal the committed offset; the caller's
  digest is validated by grammar and schema CHECKs), not at `Open` — readers
  of an in-flight session cannot yet know its digest, which is a property of
  the finalize step, not a Task 15 regression.
---

# Round 1 — Independent-review crash-safety, anchoring, schema, confidentiality fixes

Commit: `fix(task15): make staging lifecycle crash-safe`

## Scope

Round 1 repairs the nine accepted Important findings from the independent
review. Task 16 carryovers (handler wiring, ranges, quotas) are untouched;
the Tasks 1–14 `Store`/`MemoryStore` contract is unchanged; no
controlplane.db or other sidecar is produced. The staging schema was rebuilt
in place (single-version v1: sessions/blobs/timestamps/offset same rows, plus
the new `creating` state) — Task 16 must not rely on the pre-Round-1 DDL
text, only on the verified surface this report describes.

## Findings and fixes

1. **Expire rollback/file loss** — `Expire`/`Delete` no longer unlink inside
   any transaction. `expireOne` commits a durable `deleting` tombstone in Tx 1
   (skipping rows another instance already removed), unlinks + fsyncs the
   spool directory OUTSIDE any transaction, then removes metadata in Tx 2.
   Any failure retains the tombstone and leaves live rows coherent
   (per-writer visible rows never share a tombstone); a positive limit,
   deterministic `order by expires_at, id` ordering, and one
   attempt-per-session-per-call keep batching bounded. Second-unlink
   failures, commit/cancel/fault-at-every-phase, cross-instance and restart
   sequencing are covered by tests
   (`TestServiceExpireFaultAtEveryPhase`, `TestServiceExpireCrossInstance`,
   `TestServiceRestartCleansDeletingRows`, `TestServiceDeleteUnlinkFailureRetainsTombstone`).
2. **Startup cleanup** — `reconcileStartup` now only ever finishes/rolls back
   rows the service provably owns. Creation is durably attributable: a
   `creating` row commits before any file byte exists, then
   create+file-fsync+directory-fsync, then activation. Startup: `creating`
   rows with a durable 0600 regular file are activated; without one they are
   tombstoned + removed; `deleting` rows are unlinked (nonempty-dir/symlink
   unlink failure leaves the tombstone and aborts startup fail-closed with
   ErrDependency under a single documented error identity). The unsafe
   blanket deletion of unknown 64-hex files is gone; enumeration is anchored
   through the spool root descriptor, and unknown canonical files are
   preserved and startup fails closed (`TestServiceRestartFailsClosedOnUnknownSpoolFiles`,
   `TestServiceRestartRollsBackCreatingRowWithoutFile`,
   `TestServiceRestartFinishesCreatingRowWithFile`).
3. **Root/DB anchoring races** — spool and DB paths are split into anchored
   parent (chain `Lstat`→`OpenRoot`→descriptor-relative descend) + basename.
   Every component is rejected if a symlink or non-directory; the anchored
   `*os.Root` is retained for all later spool/DB parent operations; opened
   descriptors are identity-checked with `os.SameFile` against the anchored
   snapshot before and after use (rename/swap probes,
   `TestSpoolAnchoredAcrossRootSwap`, `TestServiceOperationsAnchoredAcrossRootSwap`,
   `TestOpenStagingDBRejectsSwappedDatabase`).
   Database: parent + file are checked non-symlink/non-regular BEFORE the
   mutation-capable connection; mode repair for the DB file happens after
   full schema verification and before the pragma connection
   (`repairDBFileMode`); a post-open same-file check runs before the handle
   is returned. The Lstat→OpenDB check-use on the path itself is eliminated;
   the residual microsecond window between verification and SQLite's own
   path open is bounded by the exact-0700 parent ownership and re-verified
   post-open.
4. **Modes/relative DB** — exact 0700 repaired through opened descriptors for
   root and DB parent (impossible modes rejected); exact 0600 for spool
   files and the DB file; a bare `staging.db` (parent `.`) works without
   mkdir'ing or mode-repairing the CWD; relative paths (incl. relative
   subdir like `data/staging.db`) create 0700 parents; file-URI DSN forms
   pass through. Only the service-owned parent/root boundary is required
   private — ancestors such as /var/lib or $HOME are never touched
   (`TestOpenStagingDBBareRelativeName`, `TestOpenStagingDBRelativeSubdir`,
   `TestSpoolRootModeRepair`, `TestOpenStagingDBParentModeRepair`). A
   no-exec (0600) directory cannot be opened descriptor-relatively on macOS;
   the repair falls back to a path-based chmod that verifies opened-descriptor
   identity (`os.SameFile`) against the pre-open snapshot before touching
   anything (`TestSpoolRootModeRepair/no_exec_0600`).
5. **Filesystem durability** — create fsyncs the file, then the directory,
   then activates (`fsyncHook`/`dirSyncHook` inject failures at both); unlink
   paths fsync the directory before metadata deletion; every sync error
   fails closed (tombstoned) and no row is removed unless its file is
   durably gone. Overlong-tail truncation is preserved (restart aligns to
   committed offsets) and short/missing files fail closed
   (spoolErrShort)/complete-delete counting is exact. Report wording fixed to
   describe truncation as tail-alignment, not repair. Injection tests:
   `TestServiceCreateFaultsLeaveNoResidue`, `TestServiceExpireFaultAtEveryPhase`
   (file-sync/dir-sync faults), `TestSpoolAlign...` orderings.
6. **Exact schema verification** — `verifySchemaFully` compares the COMPLETE
   sqlite_schema object set (type/tbl/body) with SQL-aware normalization
   (`normalizeSQL`) that lowercases only outside quotes, preserves quoted
   identifiers and literals byte-for-byte, collapses whitespace, and rejects
   comments and unterminated quotes; plus exact `table_xinfo`,
   `index_xinfo` (incl. the implicit rowid auxiliary entry), and
   `foreign_key_list` column sets/flags, a version-row exactness check, and
   a no-temp-object assertion. Verification runs on the read-only
   mutation-free inspection connection BEFORE any mutation-capable
   pragma/open; malformed/mutated DBs are never written. When the schema is
   valid the inspection connection is `mode=ro` so a rejected database is
   byte-identical. Independent mutated fixtures per CHECK and each lifecycle
   trigger (13 tables/indexes + 8 triggers + version-shape rows +
   schema-object hunts): `TestSchemaLookalikeObjectsRejected` (22 cases),
   `TestSchemaExactPhysicalShape`, `TestSchemaCreatingStateMachine`
7. **SQL/application grammar parity** — the schema grammar is now
   raw-byte-safe. Because `length()`/`glob()`/`substr()` see a truncated
   C-string when a TEXT value contains NUL (modernc interop), all length
   checks moved to `length(hex(x))` (byte-true), a NUL guard
   (`instr(hex(x), '00') = 0`) rejects embedded NULs exactly (no false
   positives for charset-legal values), digest is exactly
   `'sha256:' + 64 lowercase hex` via hex-length 142 + `substr(digest,1,7)`
   + negated-class tail check (no GLOB `*` suffix loophole), and actor/repo
   charset + segment-start (`('/' || repo) not glob '*[/][._-]*'`) +
   leading/trailing/double-slash + `..` rejections are applied on both
   INSERT on UPDATE; BLOB/NULL/numeric classes are rejected via `typeof`
   on affinity-free (typeless) integer columns. The parity corpus
   (`TestSchemaGrammarParityExtended`) drives raw-byte values (NUL,
   malformed UTF-8, supplementary-plane, `\é`) through the Go validators AND
   direct SQL on both insert and update, including `length(hex())`-driven
   smuggling probes (e.g. `a\0` + 64 valid hex tail, `sha256:` + 64 hex +
   NUL + junk).
8. **Owner confidentiality** — `ErrOwnerMismatch` is removed from the
   exported surface; wrong-owner and missing errors are the same exported
   `ErrNotFound` sentinel with identical `errors.Is`/`As`/`Unwrap`, format
   (`%v/%+v/%#v/%q`), JSON, and reflection shape
   (`TestServiceOwnerMismatchIdentityEqualsNotFound`: Status/Append/Open/
   MarkFinalized/Delete, plus `TestServiceOwnershipIsIndistinguishableFromNotFound`
   on the store-facing surface). Internal
   diagnostics stay unexported. `Delete`'s idempotent no-op for a row that
   never existed is unchanged (documented API), and the wrong-owner delete
   returns the exact sentinel.
9. **Constructor error confidentiality** — `NewService`/`newSpool`/
   openStagingDB errors are the fixed data-free `ErrDependency` sentinel;
   no path, DSN, SQL text, or raw cause escapes through Error()/Unwrap/
   accessors/formatting/JSON/reflection. Private causes survive only behind
   an unexported closure (`causeOf(err)` for package-internal logs). The
   only contextual error is a genuinely canceled context. Injection/
   marker/path failures:
   `TestNewServiceConstructorErrorConfidentiality` (9 cases incl.
   unknown-canonical-file, spool-root-a-file, symlinked/parent-file,
   foreign-schema DB, marker-bearing foreign file), JSON
   (`json.Marshal(err) == "{}"`), reflection, and every format verb.

## RED evidence

Tests were written/extended against the pre-Round-1 code first. Captured RED
before the corresponding production change:

- spool API change (compile-time): `spool_test.go:206:16: assignment
  mismatch: 2 variables but sp.create returns 1 value` — before `sp.create`
  gained `(*os.File, error)` and `removeDurable`→`remove`+`syncDir`.
- Runtime RED on the OLD schema before the Round-1 DDL:
  `TestSchemaGrammarParityExtended: repo-insert-x/y\x00z: Go valid=false
  schema accepted=true`, `actor-insert-user:alice\x00admin: …accepted=true`,
  `media-update-application/\x00json: …accepted=true`, and the id-update/
  digest/ref/media valid-rejected probes (fixture isolation) — both NUL
  acceptance and fixture faults were reproduced before the hex-length/NUL
  guard rewrite and fixture fixes.
- `TestServiceRestartFinishesCreatingRowWithFile: finished creating row not
  active: staging upload expired` — fixed-seed expiry predated the real
  clock (fixture), reproduced before the `time.Now()` seed change.
- `TestServiceExpireFaultAtEveryPhase phase 3: n=1 err=<nil>` — service
  hooks were not wired through `expireOne`'s unlink+sync path; reproduced
  before routing all service unlink sites through `s.spool.remove` +
  `s.syncDir()` (hookable).
- `TestSpoolRootModeRepair/no_exec_0600: staging backend unavailable` —
  macOS cannot open/stat an fd-relative `.` in a no-exec dir; reproduced
  before the identity-verified path-based repair fallback.
- `TestServiceCreateFaultsLeaveNoResidue/dir_sync: faulted create left 1
  rows` — the dir-sync fault correctly retains a durable tombstone by
  design; test expectations updated to assert tombstone-or-clean plus a
  restart-clean guarantee (not a code change).
- A debug probe on the old DDL confirmed modernc's C-string truncation:
  `length('application/\x00json') = 12` while the row stores 17 bytes and
  `hex()` sees all 17 — the root cause of every NUL acceptance.

## Gates (all on the Round-1 commit)

```bash
go test ./internal/staging/ -count=1          # ok (…)
go test ./internal/staging/ -count=3          # ok (repeat, no flakes)
go test ./internal/staging/ -race -count=1    # ok
go test ./... -count=1                        # all packages ok
go test -race ./...                           # all packages ok
go build ./...                                # ok
go vet ./...                                  # ok
gofmt -l internal cmd                          # empty
go mod tidy                                   # no diff (go.mod/go.sum unchanged)
go mod verify                                 # all modules verified
git diff --check                              # clean
bash scripts/security/check-repository-secrets.sh  # repository secret scan clean
find repo -name '*.db*'                        # none (no controlplane.db; tests use temp dirs)
```

## Files changed (Round 1)

- `internal/staging/service.go` — creating-first Create + rollback, crash-safe
  Delete/Expire (tombstone → unlink+dirsync → metadata delete), reconciling
  startup (finish-own/rollback-own, no blanket 64-hex removal), service-level
  sync/commit hooks, ctx-correct expires, creating-invisible reads.
- `internal/staging/spool.go` — descriptor-anchored path chain with
  identity-verified mode repair (+ no-exec fallback), O_EXCL file creation,
  symlink/non-regular rejection at every component, anchored enumeration.
- `internal/staging/sqlite.go` — read-only inspection connection
  (`mode=ro`, mutation pragmas stripped), full-schema verification
  (normalizeSQL + xinfo + fk + version + no-temp), hex-length/NUL-guard
  grammar, `creating` state lifecycle triggers, anchored DB
  parent/file identity + 0600 repair, fresh/empty-adopt/existing flows.
- `internal/staging/store.go` — `StateCreating`, `ErrOwnerMismatch` removed
  (identity folded into `ErrNotFound`).
- Tests: `service_test.go`, `spool_test.go`, `sqlite_test.go`.

## Concerns

- The bare-relative DB name works, but the CWD itself is never privacied; if
  the operator runs the service from a world-readable directory, the DB file
  at `staging.db` is private (0600) while the directory listing is not —
  acceptable per the "only the service-owned boundary must be private" rule.
- `reconcileStartup` performs per-row stat calls for `creating`/`deleting`
  rows only (not all rows), and alignment truncation is unchanged from the
  pre-Round-1 design (Task 16 can bound count).
- The expire pass deletes at most N expired sessions per synchronous call
  (positive limit), so a large backlog requires repeated Expire calls —
  flagged in the interface; Expire remains non-overlapping cross-instance
  via the tombstone protocol, so repeated calls are safe.
- modernc's C-string truncation of NUL-bearing TEXT is a driver behavior,
  not forced by our schema; the schema now rejects such values outright, and
  the Go validators reject them before any SQL. No production code path
  emits NUL-bearing identifiers.
- This round did not touch Task 16 items (production wiring, ranges,
  quotas); Task 16 must treat the schema as verified-frozen per this report
  (do not re-derive DDL expectations from Task 15 pre-Round-1 text).
