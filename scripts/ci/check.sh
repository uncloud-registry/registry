#!/usr/bin/env bash
# Local CI driver (scripts/ci/check.sh) — Task 25.
#
# Runs every gate the CI and release pipelines enforce, in the same order a
# clean-clone CI runner would. The core gates are unconditional and fail the
# build on any violation. Two gates need an external tool that is NOT
# guaranteed on a developer machine — govulncheck (vulnerability scan) and
# go-licenses (dependency license check) — and behave as follows:
#
#   * locally (CI unset): SKIP with a clear message when the tool is absent,
#     so `bash scripts/ci/check.sh` stays green on a plain dev box;
#   * in CI (CI=true, as GitHub Actions sets): FAIL when the tool is absent,
#     because the workflow is responsible for installing it. A silently
#     missing scanner can therefore never no-op on CI.
#
# E2E (compose-smoke + Docker/Podman round trips) is OPT-IN in ALL
# environments via RUN_E2E=1, including CI: it needs a Docker/Podman engine
# plus the reference Bee stack, and feed-publication verification is deferred
# to the Phase 4 real-Bee full-node gate (docs/compatibility.md §8). The CI
# and release workflows keep the E2E jobs disabled until that gate lands
# (ci.yml workflow_dispatch input enable_phase4_e2e), so a plain
# `bash scripts/ci/check.sh` under CI=true does NOT run E2E; it will once the
# Phase 4 gate wires RUN_E2E=1 into those jobs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

say() { printf '\n== %s ==\n' "$*"; }

# require_tool <binary> <gate-label> <install-hint>
# Returns 0 when the binary is present. When absent: exits 1 in CI (fail
# closed), or prints a SKIP line and returns 1 locally.
require_tool() {
  local bin="$1" label="$2" hint="$3"
  if command -v "$bin" >/dev/null 2>&1; then
    return 0
  fi
  if [ "${CI:-}" = "true" ]; then
    echo "error: $label requires '$bin', which is absent; CI must provide it ($hint)" >&2
    exit 1
  fi
  echo "SKIP: $label — '$bin' not installed locally ($hint); CI installs and enforces it"
  return 1
}

say "gofmt (cmd, internal)"
test -z "$(gofmt -l cmd internal)"

say "trailing whitespace (all tracked files)"
if git grep -nE '[[:blank:]]+$' -- .; then
  echo "error: trailing whitespace found on tracked files (listed above)" >&2
  exit 1
fi

say "go mod tidy -diff"
go mod tidy -diff

say "go mod verify"
go mod verify

say "go build ./..."
go build ./...

say "go vet ./..."
go vet ./...

say "go test -race -count=1 ./..."
go test -race -count=1 ./...

say "repository secret scan"
bash scripts/security/check-repository-secrets.sh

say "govulncheck ./..."
if require_tool govulncheck "govulncheck ./..." "go install golang.org/x/vuln/cmd/govulncheck@latest"; then
  govulncheck ./...
fi

say "dependency license check (go-licenses)"
if require_tool go-licenses "dependency license check" "go install github.com/google/go-licenses@latest"; then
  go-licenses check ./...
fi

say "E2E (compose-smoke / docker-roundtrip / podman-roundtrip)"
if [ "${RUN_E2E:-}" != "" ]; then
  bash scripts/e2e/compose-smoke.sh
  bash scripts/e2e/docker-roundtrip.sh
  bash scripts/e2e/podman-roundtrip.sh
else
  echo "SKIP: E2E — opt-in in ALL environments with RUN_E2E=1 (needs a Docker/Podman"
  echo "      engine plus the reference Bee stack). Feed-publication stages are"
  echo "      deferred to the Phase 4 real-Bee gate, and the CI/release workflows"
  echo "      keep the E2E jobs disabled until then, so CI does not run them yet."
fi

echo
echo "CI DRIVER: PASS (any skipped gates are reported above)"
