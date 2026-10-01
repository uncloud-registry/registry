#!/usr/bin/env bash
# Task 24 Podman round-trip E2E (scripts/e2e/podman-roundtrip.sh).
#
# Local development machines do not all carry podman; when it is absent this
# script SKIPS with a clear message (exit 0) on a dev box, but FAILS under
# CI=true: a CI job that runs the podman round trip is responsible for
# provisioning podman, so a silent no-op "pass" is impossible. When podman IS
# present it performs the same round trip as docker-roundtrip.sh against the
# reference stack, using podman's --tls-verify=false (podman has no
# insecure-registries config file) and --add-host for the registry host.
#
# Run: bash scripts/e2e/podman-roundtrip.sh   (from the repository root)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

if ! command -v podman >/dev/null 2>&1; then
  if [ "${CI:-}" = "true" ]; then
    echo "error: podman is required for the podman round trip but is not installed." >&2
    echo "      A CI job that runs this script must provision podman (Phase 4 gate);" >&2
    echo "      exiting non-zero instead of silently no-op'ing." >&2
    exit 1
  fi
  echo "SKIP: podman is not installed on this host."
  echo "      Run the podman round trip on a machine that carries podman;"
  echo "      local Docker coverage is provided by scripts/e2e/docker-roundtrip.sh."
  exit 0
fi

cd "$REPO_ROOT"

e2e_info "validating required commands"
e2e_require podman
e2e_require curl
e2e_require openssl
e2e_require go "used once to derive the registry JWKS from the Ed25519 seed"
e2e_require python3 "used for JSON assertions"
e2e_require sed
e2e_require awk
e2e_require grep
docker compose version >/dev/null 2>&1 \
  || { echo "error: docker compose plugin is required (podman round trip reuses the reference compose stack)" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Run parameters (mirrors docker-roundtrip.sh)
# ---------------------------------------------------------------------------
E2E_PROJECT="uncloud-registry-e2e-podman"
E2E_DOMAIN="localhost"
SLUG="pm"
REG_HOST="$SLUG.$E2E_DOMAIN"                    # pm.localhost
CP_ADDR="http://127.0.0.1:8081"
BEE_ADDR="http://127.0.0.1:1633"
EMAIL="podman@uncloud-registry.test"
PASSWORD="$(e2e_gen_session_secret)"

E2E_WAIT_TIMEOUT="${E2E_WAIT_TIMEOUT:-240}"
SECRETS_DIR="$(e2e_make_secrets_dir)"
E2E_ENV_FILE="$SECRETS_DIR/stack.env"
LOG_FILE="$SECRETS_DIR/podman-roundtrip.log"
WORK_DIR="$SECRETS_DIR/work"
mkdir -p "$WORK_DIR" "$WORK_DIR/out"
touch "$E2E_ENV_FILE" "$LOG_FILE"

cleanup() {
  local rc=$?
  set +e
  if [ "$rc" -ne 0 ]; then
    e2e_dump_logs "$LOG_FILE"
  fi
  e2e_compose down -v --remove-orphans >/dev/null 2>&1
  rm -rf "$SECRETS_DIR"
  if [ "$rc" -ne 0 ]; then
    echo
    echo "PODMAN ROUND TRIP FAILED (rc=$rc); compose logs preserved at: $LOG_FILE"
  fi
  exit "$rc"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Secrets + fixture
# ---------------------------------------------------------------------------
e2e_info "generating ephemeral secrets in $SECRETS_DIR"
SESSION_SECRET="$(e2e_gen_session_secret)"
REGISTRY_SEED="$(e2e_gen_registry_seed)"
e2e_write_master_key "$SECRETS_DIR"
e2e_write_internal_secret "$SECRETS_DIR"
e2e_write_jwks "$SECRETS_DIR" "$REGISTRY_SEED" "cp-ed25519-1"
e2e_write_internal_tls "$SECRETS_DIR"
e2e_write_bee_password "$SECRETS_DIR"

mkdir -p "$WORK_DIR/one"
cat > "$WORK_DIR/one/payload.txt" <<'EOF'
uncloud-registry podman e2e deterministic payload
EOF
cat > "$WORK_DIR/one/Dockerfile" <<'EOF'
FROM scratch
COPY payload.txt /payload.txt
LABEL org.uncloud-registry.e2e=podman
EOF

cat > "$E2E_ENV_FILE" <<EOF
SECRETS_DIR=$SECRETS_DIR
CONTROLPLANE_MODE=production
CONTROLPLANE_EXTERNAL_URL=https://controlplane.$E2E_DOMAIN
CONTROLPLANE_REGISTRY_DOMAIN=$E2E_DOMAIN
CONTROLPLANE_TOKEN_SECRET=$SESSION_SECRET
CONTROLPLANE_REGISTRY_ED25519_KEY=$REGISTRY_SEED
CONTROLPLANE_REGISTRY_KEY_ID=cp-ed25519-1
CONTROLPLANE_HOST=controlplane.$E2E_DOMAIN
REGISTRY_HOST_GLOB=*.$E2E_DOMAIN
REGISTRY_AUTH_REALM=http://controlplane:8081/token
REGISTRY_OWNER_MAP=
REGISTRY_ID_MAP=
REGISTRY_TOKEN_AUDIENCE=
EOF

e2e_info "building reference images (Dockerfile.controlplane / Dockerfile.registry)"
e2e_compose build controlplane registry

e2e_info "starting control plane + Bee"
e2e_compose up -d controlplane bee
e2e_wait_http "bee" "$BEE_ADDR/health"
e2e_wait_http "controlplane /readyz" "$CP_ADDR/readyz" "200"

e2e_info "provisioning a postage batch (local dev chain)"
BATCH_ID="$(e2e_provision_stamp_batch "$BEE_ADDR" "${LOCALCHAIN_RPC:-http://127.0.0.1:8546}")"
[ -n "$BATCH_ID" ] || { echo "error: could not mint a postage batch on the local chain" >&2; exit 1; }

e2e_info "registering user $EMAIL and creating registry $REG_HOST"
REG_JSON="$(curl -sS -X POST --max-time 20 -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" "$CP_ADDR/api/users/register")"
SESSION_TOKEN="$(printf '%s' "$REG_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')"
CREATE_AUTH="Authorization: Bearer $SESSION_TOKEN"
CREATE_JSON="$(curl -sS -X POST --max-time 20 -H 'Content-Type: application/json' \
  -H "$CREATE_AUTH" \
  -d "{\"slug\":\"$SLUG\",\"defaultStampBatchID\":\"$BATCH_ID\"}" \
  "$CP_ADDR/api/registries")"
REG_ID="$(printf '%s' "$CREATE_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["registry"]["id"])')"
REG_OWNER="$(printf '%s' "$CREATE_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["bootstrap"]["feedOwnerAddress"])')"

cat >> "$E2E_ENV_FILE" <<EOF
REGISTRY_OWNER_MAP=$REG_HOST=$REG_OWNER
REGISTRY_ID_MAP=$REG_HOST=$REG_ID
REGISTRY_TOKEN_AUDIENCE=$REG_HOST
EOF

e2e_info "starting the full reference stack"
e2e_compose up -d
e2e_compose_ps_healthy controlplane
e2e_compose_ps_healthy registry
e2e_compose_ps_healthy bee
e2e_compose_ps_healthy caddy

# Registry host and token realm must resolve for podman. podman on macOS (the
# common case for this repo's maintainers) runs in a VM; give it the registry
# IP via --add-host for the registry host, map the compose-internal
# controlplane hostname to 127.0.0.1 (the control plane publishes 8081 on the
# host loopback) so the 401 token fetch can resolve, and use
# --tls-verify=false (podman has no insecure-registries file).
REG_IP="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$E2E_PROJECT-registry-1" | awk '{print $1}')"
[ -n "$REG_IP" ] || { echo "error: cannot resolve registry container IP" >&2; exit 1; }
echo "registry IP: $REG_IP"

e2e_info "podman login $REG_HOST"
printf '%s' "$PASSWORD" | podman login --tls-verify=false --username "$EMAIL" \
  --password-stdin "$REG_HOST" >/dev/null \
  || { echo "error: podman login failed" >&2; exit 1; }

e2e_info "podman build + push to brand-new repo pm-one"
ONE_DIGEST="$(podman build --add-host "$REG_HOST:$REG_IP" --add-host "controlplane:127.0.0.1" -t "$REG_HOST/pm-one:latest" \
  "$WORK_DIR/one" >/dev/null 2>&1 && \
  podman push --tls-verify=false --add-host "$REG_HOST:$REG_IP" --add-host "controlplane:127.0.0.1" "$REG_HOST/pm-one:latest" 2>&1 \
  | sed -n 's/^.*digest: \(sha256:[0-9a-f]*\).*/\1/p')"
[ "${#ONE_DIGEST}" = "71" ] \
  || { echo "error: podman push did not report a digest (got: ${ONE_DIGEST:-none})" >&2; exit 1; }
echo "pm-one pushed: $ONE_DIGEST"

e2e_info "podman pull + digest comparison after registry restart"
e2e_compose restart registry
e2e_compose_ps_healthy registry
PULLED="$(podman pull --tls-verify=false --add-host "$REG_HOST:$REG_IP" --add-host "controlplane:127.0.0.1" "$REG_HOST/pm-one:latest" 2>/dev/null \
  | tail -1)"
echo "pull result: $PULLED"
podman image inspect --format '{{index .RepoDigests 0}}' "$REG_HOST/pm-one:latest" \
  | grep -q "$ONE_DIGEST" \
  || { echo "error: podman RepoDigest does not match pushed digest" >&2; exit 1; }

echo
echo "PODMAN ROUND TRIP PASS: login, push, restart, pull, digest comparison green on $(podman --version)."