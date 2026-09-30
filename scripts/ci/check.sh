#!/usr/bin/env bash
# Local CI driver (scripts/ci/check.sh) — Task 25.
#
# Runs every gate the CI and release pipelines enforce, in the same order a
# clean-clone CI runner would. The core gates are unconditional and fail the
# build on any violation. Three gates need an external tool that is NOT
# guaranteed on a developer machine — govulncheck (vulnerability scan),
# go-licenses (dependency license check), and the Docker/Podman E2E suite —
# and behave as follows:
#
#   * locally (CI unset): SKIP with a clear message when the tool/runner is
#     absent, so `bash scripts/ci/check.sh` stays green on a plain dev box;
#   * in CI (CI=true, as GitHub Actions sets): FAIL when the tool/runner is
#     absent, because the workflow is responsible for installing/provisioning
#     it. A silently missing scanner can therefore never no-op on CI.
#
# E2E is opt-in locally via RUN_E2E=1 (it needs a full Docker/Podman engine
# plus the reference Bee stack and is exercised on dedicated CI runners).
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
  echo "SKIP: E2E — opt-in locally with RUN_E2E=1 (needs a Docker/Podman engine plus"
  echo "      the reference Bee stack); CI runs these on dedicated docker/podman runners."
fi

echo
echo "CI DRIVER: PASS (any skipped gates are reported above)"
