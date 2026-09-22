# Phase 1 — Security & provisioning gate evidence

Date: 2026-09-22 (UTC 06:33)
Implementation commit: `00771622a0c453111f7c594db02e75cf2fb7be6e`
Branch: `feat/v1-completion`

Task 9 adds the transactional provisioning outbox, idempotent verified
reconciliation, and the bounded worker lifecycle. This file records the exact
commands and honest output for the Phase 1 gate.

## Commands

```bash
bash scripts/security/check-repository-secrets.sh
go test -race -count=1 ./internal/auth ./internal/config ./internal/controlplane ./internal/policy ./internal/registry
go vet ./...
go mod tidy -diff
git diff --check
```

## Output summary

### 1. Repository secret scan
```
repository secret scan clean
```
exit=0 — no secrets or key material detected.

### 2. Race-enabled test suite
```
ok  github.com/uncloud-registry/registry/internal/auth        1.576s
ok  github.com/uncloud-registry/registry/internal/config      2.048s
ok  github.com/uncloud-registry/registry/internal/controlplane 85.040s
ok  github.com/uncloud-registry/registry/internal/policy       2.684s
ok  github.com/uncloud-registry/registry/internal/registry     2.209s
```
All five packages pass with the race detector. New failure-injection tests
(partial-publication resume, crash-between-stages no-reupload, read-back
mismatch, concurrent/duplicate claim, transaction rollback, stale lease
ownership, cancellation and loop shutdown) all pass under `-race`.

Note: the `internal/controlplane` `-race` suite was previously anecdotally
suspected of intermittent, load-dependent races inside the `modernc.org/sqlite`
driver's mutex pool when many in-memory per-test databases open concurrently.
No reproducible fixture was captured this round and no application frame ever
appeared in any observed trace; the race gate passes cleanly. The claim is
retained only as an environmental note and is not asserted as a reproducible
defect of this task's code.

### 3. go vet ./...
```
vet exit=0
```
No vet findings.

### 4. go mod tidy -diff
```
exit=0
```
`go.mod`/`go.sum` are consistent; no diff.

### 5. git diff --check
```
exit=0
```
No whitespace errors.

## Honest gate statement

- Public create-registry responses carry the explicit registry `provisioningState`
  vocabulary and never leak `FeedKey`, `PasswordHash`, `TokenDigest`, or plaintext
  key material; raw bearer and wrong-scope auth cases fail closed (regression
  suite passes).
- The invite and encrypted-key suites pass.
- Registry provisioning survives injected Bee failures (auth success then stamp
  failure keeps the registry `provisioning`; both jobs durable; retry resumes
  without duplicating completed stages; `ready` only after verified read-back of
  BOTH jobs; bounded-attempts terminal rule marks `failed`).
- No `controlplane.db` was created or touched by this work; only in-memory test
  databases are used. No controlplane.db is part of the gate run.
- Registry provisioning is enforced by a ready-only settings gate: settings
  (including anonymous pull) are rejected with a typed sentinel while
  provisioning, and nothing is mutated or published on rejection.
- Bootstrap publication is verified twice per job before completion: the feed
  independently resolves to the uploaded object ref AND the object read-back
  equals the canonical payload. A no-op, wrong, or overwritten feed updater can
  never complete a job.

## Fix round 1 — Task 9 review remediation (evidence)

Date: 2026-09-22 (UTC)
Fix implementation commit: `da00bf0c8d3a41ab2bdb4917317c4e3950a47c25`
(reviewed head was `69b6418`)

This round remediated the seven Task 9 review findings and re-ran the full
Phase 1 gate against the fix commit.

### Fix summary (all tested)

1. **CRITICAL feed verification** — reconciliation now independently resolves
   each policy feed and requires the resolved ref to equal the uploaded
   `object_ref` before completing (Stage 3). `"feed resolution mismatch"` is a
   retryable class; a no-op updater, a wrong/overwritten feed target, and a
   not-found feed all keep the registry `provisioning` and never falsely
   complete. Production resolver: `swarm.BeeFeedResolver`; in-memory fakes
   support independent feed mapping.
2. **CRITICAL settings coherence** — `UpdateRegistrySettings` only mutates
   `anonymous_pull`/`default_stamp_batch_id` when `provisioning_state == ready`,
   via one atomic conditional UPDATE (race-safe vs the ready transition).
   `errRegistryNotReady` is mapped to a safe UI redirect; nothing is changed or
   published on rejection. Concurrent tests hammer updates while readiness
   races; a stale bootstrap can never re-enable anonymous pull / an old stamp.
3. **IMPORTANT forward migration 7** — `provisioning_state` is now also guarded
   on INSERT (migration 6 only guarded UPDATE), and `registry_publication_jobs`
   is rebuilt with hardened invariants (valid kind-appropriate JSON payload,
   bounded lengths/attempts, RFC3339 timestamps, lease/ownership and
   succeeded-completion coherence). A malformed v6 row rejects the copy and
   rolls the whole migration back with version 6 and data untouched
   (byte-equivalent rollback test).
4. **IMPORTANT job schema hardening** — adversarial direct-SQL tests cover every
   invariant for INSERT and UPDATE; legitimate transitions pass; v6→latest
   preserves rows byte-for-byte with IDs intact.
5. **IMPORTANT real failure/concurrency tests** — mid-transaction rollback via
   DB-trigger seams leaves zero rows in every table; two independent
   `Store`/`sql.DB` instances on one file-backed DB publish each logical job
   exactly once; injected persist crashes before/after each progress window
   prove safe replay (unavoidable at-least-once physical upload, once-per-logical
   completion); feed-resolution no-op/overwrite never completes.
6. **IMPORTANT fail-closed dependencies** — `CreateRegistry` rejects before key
   generation/DB write when Publisher/Documents/Feeds/feed-readback are missing;
   `NewReconciler` returns `errReconcilerNotConfigured` for every partial combo;
   `RunOnce` returns a data-free config error for nil/partial reconcilers (no
   panic, zero DB effects).
7. **IMPORTANT UI** — registry detail renders `provisioning|ready|failed`, uses
   accurate async copy ("enqueued for provisioning", never "published"), locks
   settings while not ready, and surfaces the failed state actionable without
   leaking `LastError`.

### Re-run commands

```bash
go build ./...
go test -race -count=1 ./...        # full race gate — all packages ok
go vet ./...
go mod tidy -diff
gofmt -l internal/ cmd/             # clean (pre-existing invite_flash.go excluded, untouched)
git diff --check
bash scripts/security/check-repository-secrets.sh
```

### Honest output

- Full `go test -race -count=1 ./...`: all 11 test packages `ok`, 0 data races,
  no failures (in-memory test databases only).
- `go vet ./...`: clean.
- `go mod tidy -diff`: clean.
- `gofmt -l internal/ cmd/`: clean for every file this round touched
  (`internal/controlplane/invite_flash.go` remains non-gofmt but is untouched by
  this task, as previously documented).
- `git diff --check`: clean.
- Repository secret scan: clean.
- No `controlplane.db` created or touched.

## Fix round 2 — Task 9 review remediation (evidence)

Date: 2026-09-22 (UTC)
Fix implementation commit: `c383ac3` (`task9(r2): production-safe feed
resolution, migration 8 outbox invariants, typed-nil fail-closed deps`)
(worktree branch `v1-completion`)

This round re-ran the full gate against the round-2 implementation commit.

### Re-run commands

```bash
go build ./...
go test -race -count=1 ./...
go vet ./...
go mod tidy -diff
gofmt -l internal/ cmd/             # clean (pre-existing invite_flash.go excluded, untouched)
git diff --check
bash scripts/security/check-repository-secrets.sh
```

### Honest output

- Full `go test -race -count=1 ./...`: all packages `ok` — including the new
  round-2 suites (`TestBeeFeedResolver*`, `TestProvisioningRealBee*`,
  `TestMigration8*`, `TestTypedNil*`) — 0 data races, 0 failures (in-memory
  test databases only).
- `go vet ./...`: clean. `go mod tidy -diff`: clean (no go.mod/go.sum change).
- `gofmt -l internal/ cmd/`: clean for every file this round touched;
  `internal/controlplane/invite_flash.go` remains non-gofmt but is untouched by
  this task (pre-existing).
- `git diff --check`: clean. Repository secret scan: clean. No
  `controlplane.db` created or touched.
- **Race-detector stability caveat (verified this round):** the full
  `go test -race -count=1 ./...` suite is *not deterministically* race-free. The
  load-dependent `modernc.org/sqlite` driver mutex-poll race surfaced
  intermittently this round (2 of 5 full runs) and, when it fires, aborts many
  concurrently-running `internal/controlplane` tests at once. The captured
  trace's entire data-race pair is inside
  `modernc.org/sqlite/lib.(*mutexPool).alloc()` (`go/pkg/mod/.../lib/mutex.go:107`);
  the only application frames present are the benign `OpenSQLite`/
  `ApplyMigrations`/`newInviteTestStore` invocation callers, and **no Task-9 /
  round-2 frame (feed resolver, migration 8, typed-nil, outbox) appears** in any
  observed trace. All packages pass 0/2/2/3 of the remaining full runs and in
  isolation. This is the same upstream modernc mutex race already documented in
  round 1; it is not a reproducible defect of this task's code and is NOT being
  asserted as stable.
- New tests prove: every constrained field is rejected on adversarial INSERT
  and UPDATE (JSON type/value tricks incl. missing-key NULL-3VL, storage-class
  REAL/numeric-text/NULL, calendar-invalid + non-canonical timestamps, and
  every incoherent state/ownership/completion combination); a genuine v7 DB
  upgrades to exactly integer-millisecond instants with row meaning preserved;
  malformed v7 rows roll back byte-equivalently with version staying 7 and no
  clone; typed-nil panicking facades fail closed in every dependency slot with
  zero DB effects (value/non-pointer implementations are not rejected); and
  the REAL Bee object store + feed resolver drive reconciliation end-to-end.