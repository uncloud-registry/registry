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

Note: the `internal/controlplane` race suite is subject to an intermittent,
pre-existing, load-dependent race inside the `modernc.org/sqlite` driver's
mutex pool (`lib/mutex.go` `mutexPool.alloc` vs `mutexFromPtr`) when many
in-memory per-test databases open concurrently. Every failure trace contains
only driver frames — no application frame — and the suite passes cleanly when
run (verified on a clean pass). The same flake reproduces on the pre-task base
commit, so it predates Task 9.

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