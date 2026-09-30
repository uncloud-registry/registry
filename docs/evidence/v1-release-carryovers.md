# v1 release — carryover rulings (Task 27 phase A)

This fragment records the release-policy dispositions for every open carryover
remaining at the v1 gate. It is the authoritative carryover record the final
release decision (Task 27) reads; entries are either **fixed** (a code change
landed in this phase) or **accepted** (a reasoned ruling that the item is
non-load-bearing, evidence-only, or out of release scope).

## Fixed

### Task 14 — `BeeObjectStore.ReadBounded` validation (mandatory release carryover)

`ReadBounded` previously accepted a zero/nil store and performed no pre-flight
validation, so a nil receiver panicked, an empty `BaseURL` or nil `HTTPClient`
was dereferenced, a non-canonical ref was passed to the wire, and a bound of
`math.MaxInt64` wrapped `maxBytes+1` negative — disabling the overflow probe.

Fixed fail-closed at the top of `ReadBounded` (internal/swarm/bee.go): reject a
nil receiver, an empty `BaseURL`, a nil `HTTPClient`, a non-canonical ref
(exactly 64 hex characters — the only form the `/bytes` endpoint accepts), a
negative bound, and `maxBytes >= math.MaxInt64`, all with data-free errors
before any I/O. `OpenObject` was checked for the same base/client/ref gaps and
patched identically (its counting stream has no `+1` probe, so it needs no
`MaxInt64` guard). Covered by RED→GREEN tests asserting the hostile oversized
body is never read for the `MaxInt64` case.

## Accepted carryovers

### Task 10 — legacy candidate derivation "fail open" (final-review carryover)

Ruled **non-load-bearing — not a real fail-open**. Inspection shows:

- Candidate-derivation failures (unreadable/oversized/malformed/ambiguous
  document, `>256` tags) all return a nil candidate set, which the caller
  treats as "no adoption" and reserves the current operation identity normally.
  The migration-9 quarantine rows are **never** adopted on a failed derivation;
  they remain quarantined. There is no path by which a derivation failure
  promotes a wrong row — the outcome is fail-closed (stranded quarantine row),
  never fail-open.
- The "1 MiB bound checked only after an unbounded read" concern is inaccurate
  for production: the signer's `Docs` is `swarm.NewBeeDocumentStore`, whose
  `Read` is already bounded to `BeeDocumentReadMaxBody` (8 MiB); the 1 MiB
  legacy cap is an additional tighter check applied after that bounded read, so
  the worst transient buffer is 8 MiB, never unbounded.
- The path is additionally unreachable in any v1 release deployment:
  `deriveLegacyCandidates` runs only when a legacy quarantine row exists
  (`LegacyOperationCount > 0`), and migration 17
  (`validateFeedSignerFenceHistorySafe`) refuses the upgrade atomically whenever
  `feed_signer_operations_legacy` holds so much as one row. A fresh v1 install
  has no such rows; a pre-v1 upgrade is refused. So the legacy derivation never
  executes in production.

Accepted as-is; no code change.

### Task 7 — migration-5 fingerprint items (parked after round-5 breaker)

**Ruling 1 (release policy):** the migration-5 schema fingerprint globally folds
quoted and unquoted identifiers beyond the one SQLite `RENAME` table-name
exception, so a hand-authored/malformed database stamped v4 could be falsely
accepted as v5 despite semantic differences. Release policy is that **arbitrary
hand-authored v4 schemas are unsupported** — v1 supports only project-produced
v0–v5 schemas, all of which match the genuine fingerprint. Runtime invite
security is unaffected. Non-load-bearing for the release.

**Ruling 2 (test completeness):** adversarial migration tests do not
independently mutate the permission `CHECK`, the three "weakened" triggers are
in fact stricter, and the helper asserts row count rather than byte-identical
seed data. This is a test-completeness gap only: exact fingerprint comparison
and genuine project-schema upgrade tests remain active. Non-load-bearing.

Accepted as-is; no code change.

### Task 16 — three evidence-only Minors

Accepted carryovers (test-evidence hardening, no correctness gap):

1. Add a winner-held barrier so the concurrent-finalizer test necessarily
   exercises the mid-claim 409 path.
2. Compare the exact `BeeRef` / media type / size in that test.
3. Add a close-start barrier to the pool close-blocking test.

### Task 18 — cleanup-counter Minor

Accepted carryover: concurrent cleanup counters can count idempotent unpin
attempts and increment `Removed` when `finishDeletion` reports no unique
deletion. Observability/evidence only; no correctness impact.

### Task 24 — podman-login Minor

Accepted carryover (Phase 4): `podman login` cannot resolve the
compose-internal `controlplane` host because it lacks `--add-host`. Requires a
host-reachable realm or an `/etc/hosts` mechanism; the full podman round-trip is
already deferred to the Phase 4 gate.
