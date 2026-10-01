# v1 release checklist

Operator and CI checklist for a Uncloud Registry v1 release. The same gates are
enforced by `scripts/ci/check.sh` (local/CI driver) and the GitHub Actions
workflows (`.github/workflows/ci.yml`, `release.yml`); this document is the
human-readable sign-off record that ties them together.

**Honesty rule:** a release is NOT green unless every gate below passes from a
clean clone. The two gates marked **(Phase 4)** are Bee-E2E-dependent and are
**deferred until a Bee full node is available** (`docs/compatibility.md` §8);
they must be re-run and recorded before a production sign-off.

## 0. Clean clone

- [ ] Work from a fresh `git clone` of the exact source commit being released
      (record the SHA in `docs/evidence/v1-release.md`).
- [ ] `git status` clean; no untracked secrets, databases, or `.env` files.

## 1. Build, quality, and test gates

- [ ] `bash scripts/ci/check.sh` — exits 0 (build, vet, format, `go mod tidy
      -diff`, `go mod verify`, `-race` suite, secret scan, govulncheck,
      go-licenses; E2E is opt-in).
- [ ] `go test -race -count=1 ./...` — all packages `ok`, no data races.
- [ ] `go test ./internal/registry -run TestDistributionConformanceMatrix
      -count=1 -v` — the documented wire contract passes with no mocks.

## 2. Secret scan

- [ ] `bash scripts/security/check-repository-secrets.sh` — exit 0, no
      credential-like material, no tracked `controlplane.db` / `.env`.

## 3. PRD traceability

- [ ] `python3 scripts/ci/check-prd-traceability.py` — exit 0; all 101 PRD IDs
      (75 requirements + 26 audit findings) mapped exactly once.
- [ ] Re-run `--render docs/evidence/v1-release-index.md` and commit any change
      so the rendered table matches `docs/evidence/release-index.json`.

## 4. Compatibility / documentation reconciliation

- [ ] `docs/compatibility.md` is current and enforced by the conformance matrix.
- [ ] No machine-local paths in tracked docs: `grep -rn '/Users/' docs README.md`
      returns only the sentinel assertions in the gate scripts/docs (no actual
      links).
- [ ] README, runbooks, and `docs/compatibility.md` agree with the final
      binaries (staging is durable SQLite+spool; feed signing is control-plane
      constrained signer; no in-memory-staging or registry-side-signer claims).

## 5. Reference deployment (Phase 4, deferred for feed E2E)

- [ ] `bash scripts/e2e/compose-smoke.sh` — exit 0; reports the feed stage as an
      explicit SKIP (not asserted green) until a full node is present.
- [ ] **(Phase 4)** `bash scripts/e2e/docker-roundtrip.sh` — real Docker push/pull
      round trip against a Bee full node.
- [ ] **(Phase 4)** `bash scripts/e2e/podman-roundtrip.sh` — real Podman round trip.

## 6. Operational drills

- [ ] `bash scripts/operations/backup.sh` then `verify-backup.sh` — PASS; record
      the backup label and schema versions (control plane v17, staging v11).
- [ ] `bash scripts/operations/restore.sh` into an isolated destination — PASS;
      re-open with the real constructors and decrypt the feed key
      (`docs/evidence/phase-5-recovery.md`).
- [ ] **(Phase 4)** Full push→backup→destroy→restore→pull drill against the live
      reference stack.
- [ ] **(Phase 4)** Live upgrade + rollback drill (`docs/operations/upgrade-rollback.md`).

## 7. Release artifacts

- [ ] `bash scripts/ci/release-artifacts.sh <out-dir> <binary> …` — produces
      `checksums.txt` and per-binary CycloneDX SBOMs.
- [ ] Record container image references (digests once pinned) and SBOM paths in
      `docs/evidence/v1-release.md`.

## 8. Sign-off record

Fill in and commit before declaring the release:

- [ ] Source commit SHA: `________________`
- [ ] Container digests (or Dockerfile/tag if unpinned): `________________`
- [ ] Migration versions: control plane `17`, staging `11`
- [ ] Bee version: `2.8.2` (or the Phase 4 pinned version)
- [ ] Client matrix: Docker / Podman versions actually E2E-tested
- [ ] Backup identifier + restore result: `________________`
- [ ] Rollback result: `________________`
- [ ] Traceability checker exit code: `0`
- [ ] Bee-E2E status: **deferred to Phase 4** (honest), or **green** once a full
      node run is recorded.
