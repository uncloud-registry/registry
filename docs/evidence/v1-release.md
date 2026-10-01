# v1 release decision record

Date: 2026-09-30 (UTC)
Code SHA (Go source state): `9bc3f22ab5b291979c9e9f3cc7b642c7638c4c03` (branch `feat/v1-completion`)
Release-record SHA (docs/evidence + traceability checker state): `d266277301c5078adc8fd30714b7e4d4738a2875` (branch `feat/v1-completion`)

## Decision (honest)

**This is NOT a fully-green release.** The deterministic gate — build, vet,
format, race suite, conformance matrix, secret scan, module hygiene, and the
PRD traceability checker — is green. The **real-Bee end-to-end and the
operational drills are PARTIALLY deferred to Phase 4** pending a Bee **full
node**: the reference stack pins Bee 2.8.2 as an isolated light node
(`--full-node=false`, no peers), which cannot pushsync chunks, so feed
publication and feed-dependent pulls are not retrievable in this phase
([docs/compatibility.md §8](compatibility.md)). The v1 release is therefore
recorded as **implemented-and-unit-verified, with the Bee-E2E layer deferred**,
not as a signed-off production release.

What **is** verified and green now:

- `go test -race -count=1 ./...` — all packages pass (in-memory test databases).
- `go vet ./...`, `go build ./...`, `gofmt -l cmd internal`, `go mod tidy -diff`,
  `go mod verify` — clean.
- `bash scripts/security/check-repository-secrets.sh` — clean.
- `go test ./internal/registry -run TestDistributionConformanceMatrix` — the
  documented wire contract, driven through the real handler with no mocks.
- Backup/restore/verify machinery exercised end-to-end against the **real
  SQLite databases** produced by the real store constructors
  (`docs/evidence/phase-5-recovery.md`).
- `python3 scripts/ci/check-prd-traceability.py` — exit 0; all 101 PRD IDs
  (75 requirements + 26 audit findings) mapped exactly once.

What is **deferred to Phase 4** (Bee full node):

- Real-Bee feed publication/read-back round trip (Phase 2 gate).
- Real Docker/Podman client push/pull E2E (Phase 4 gate).
- Reference workload (small + ≥1 GiB layer + multi-platform) and p95 latency
  on the running reference environment (Phase 5 PERF evidence).
- The full reference-stack backup/restore and upgrade/rollback drills (the
  SQLite-level drill has run; the push→backup→destroy→restore→pull drill has not).

## Container images

The v1 reference deployment builds its two binaries locally from the code
SHA above; no signed registry digests exist yet (the release workflow that would
pin them is not executed in this phase). Image references are therefore the
Dockerfile + tag, not digests.

| Image | Reference | Digest |
|-------|-----------|--------|
| control plane | `uncloud-registry/controlplane:local` (built from `Dockerfile.controlplane`, base `golang:1.25-alpine` → `alpine:3.21`) | not determinable (locally built) |
| registry | `uncloud-registry/registry:local` (built from `Dockerfile.registry`, base `golang:1.25-alpine` → `alpine:3.21`) | not determinable (locally built) |
| Bee | `ethersphere/bee:2.8.2` (compose.yaml) | not pinned in this phase |
| Bee localchain | `ethersphere/bee-localchain:0.9.4` | not pinned in this phase |
| TLS proxy | `caddy:2.11.4` | not pinned in this phase |
| localchain helper | `python:3.12-alpine` | not pinned in this phase |

Pin digests (`image@sha256:…`) during the Phase 4 release run.

## SBOM / checksum procedure

`scripts/ci/release-artifacts.sh` produces, for already-built binaries,
deterministic sorted SHA-256 `checksums.txt` and per-binary CycloneDX SBOMs via
`syft` (installed by the release workflow). SBOMs are reproducible-content
artifacts (syft embeds a timestamp), not byte-stable; checksums are byte-stable.
`scripts/ci/check.sh` is the local/CI driver that sequences build → vet → race
→ secret scan → govulncheck → go-licenses → (opt-in) E2E.

## Migration versions (verified against the code and the drill)

| Database | Version | Source of truth |
|----------|---------|-----------------|
| control plane | **v17** | `internal/controlplane/migrations.go` (migration 17); `docs/evidence/phase-5-recovery.md` |
| staging | **v11** | `internal/staging/sqlite.go` (`latestSchemaVersion = 11`); `docs/evidence/phase-5-recovery.md` |

Both are forward-only; rollback of a migrated database is restore-from-backup
(`docs/operations/upgrade-rollback.md`).

## Bee version

`ethersphere/bee:2.8.2` (pinned in `compose.yaml`), run as an isolated light
node. Full-node feed publication is the Phase 4 dependency.

## Client matrix

Docker and Podman are the declared clients (`docs/compatibility.md` §4). The
**pinned** client-version E2E matrix has **not** been executed in this phase —
no specific Docker/Podman version is claimed tested. `docker-roundtrip.sh` and
`podman-roundtrip.sh` exist and are blocked at first push pending a full node.
Any client speaking the documented OCI subset is expected to work for pull /
first push / re-tag push / manifest-by-digest / blob-by-digest, enforced at the
wire level by `TestDistributionConformanceMatrix` (no mocks).

## Backup/restore drill result

The backup/verify/restore machinery was driven end-to-end against the real
SQLite databases (control plane v17, staging v11): fixture → `backup.sh`
(`VACUUM INTO` snapshots + deterministic spool archive + manifest + checksums) →
`verify-backup.sh` (all checks pass; tamper negative detected) → destroy →
`restore.sh` into a fresh tree (checksums first, restrictive permissions) →
full `.dump` schema+data equivalence → re-open with the real constructors +
feed-key decrypt. Full output: `docs/evidence/phase-5-recovery.md`. The
reference-stack push/pull drill remains deferred (§8).

## Traceability summary

`docs/evidence/release-index.json` (authoritative, machine-readable) maps all
101 PRD IDs exactly once; `docs/evidence/v1-release-index.md` is the rendered
table (regenerate with `--render`). Status breakdown:

- **95 `implemented`** — merged and verified by deterministic tests that run
  without a real Bee full node.
- **6 `deferred-phase4`** — Bee-E2E-blocked: `AC-006`, `AC-014`, `COMP-006`,
  `PERF-002`, `PERF-003`, `AUD-020`.
- **0 `accepted-carryover`, 0 `deferred`** — no requirement is in those states;
  the recorded carryovers (`docs/evidence/v1-release-carryovers.md`) are
  non-load-bearing code-review rulings, not requirement shortfalls.

## Honest gate statement

The full release gate — clean-clone CI, compose smoke, Docker/Podman round
trips, and the operational drills — is **PARTIALLY deferred**: the parts that
require Bee feed publication or a real Docker/Podman client are blocked on a
Bee full node and will be re-run at Phase 4. The traceability checker passes
against the index above, but it records the six Bee-E2E-blocked IDs as
`deferred-phase4` rather than asserting them green. Do not treat this record as
a fully-green release.
