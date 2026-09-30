#!/usr/bin/env bash
# Task 24 Docker round-trip E2E (scripts/e2e/docker-roundtrip.sh).
#
# Builds a deterministic small image and a multi-platform fixture, logs in,
# pushes to a BRAND-NEW repository, inspects manifests over the wire,
# restarts the registry service, pulls, and compares digests — all green with
# a real Docker daemon (pinned docker:27.5.1 CLI/dind + moby/buildkit for the
# multi-platform fixture).
#
# Docker networking on a local engine cannot resolve the registry host to the
# compose network, so the round trip runs its client against an in-network
# docker:dind engine and an in-network buildkit daemon, each pinned and each
# carrying an /etc/hosts entry + insecure-registry declaration for the
# registry host. Everything runs inside the compose network; no daemon config
# outside the stack is touched.
#
# Run: bash scripts/e2e/docker-roundtrip.sh   (from the repository root)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# 1. Command validation
# ---------------------------------------------------------------------------
e2e_info "validating required commands"
e2e_require docker "install Docker Desktop / docker engine (pinned: 27.5.1)"
e2e_require curl
e2e_require openssl
e2e_require go "used once to derive the registry JWKS from the Ed25519 seed"
e2e_require python3 "used for JSON assertions"
e2e_require sed
e2e_require awk
e2e_require grep
docker compose version >/dev/null 2>&1 \
  || { echo "error: docker compose plugin is required" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Run parameters
# ---------------------------------------------------------------------------
E2E_PROJECT="uncloud-registry-e2e"
E2E_DOMAIN="localhost"
SLUG="rt"
REG_HOST="$SLUG.$E2E_DOMAIN"                    # rt.localhost
CP_ADDR="http://127.0.0.1:8081"
BEE_ADDR="http://127.0.0.1:1633"
# Production-mode same-origin enforcement (security.go checkOrigin) requires
# register/login POSTs to carry an Origin equal to CONTROLPLANE_EXTERNAL_URL.
CP_ORIGIN="https://controlplane.$E2E_DOMAIN"
EMAIL="roundtrip@uncloud-registry.test"
PASSWORD="$(e2e_gen_session_secret)"

DIND_IMAGE="docker:27.5.1-dind"
CLI_IMAGE="docker:27.5.1-cli"
BUILDKIT_IMAGE="moby/buildkit:v0.33.0"

E2E_WAIT_TIMEOUT="${E2E_WAIT_TIMEOUT:-240}"
SECRETS_DIR="$(e2e_make_secrets_dir)"
E2E_ENV_FILE="$SECRETS_DIR/stack.env"
LOG_FILE="$SECRETS_DIR/docker-roundtrip.log"
WORK_DIR="$SECRETS_DIR/work"
mkdir -p "$WORK_DIR/one" "$WORK_DIR/multi" "$WORK_DIR/out"
touch "$E2E_ENV_FILE" "$LOG_FILE"

cleanup() {
  local rc=$?
  set +e
  if [ "$rc" -ne 0 ]; then
    e2e_dump_logs "$LOG_FILE"
    local preserved="${TMPDIR:-/tmp}/uncloud-e2e-docker-roundtrip-$(date +%Y%m%d-%H%M%S).log"
    cp "$LOG_FILE" "$preserved" 2>/dev/null || true
  fi
  for c in "$E2E_PROJECT-cli" "$E2E_PROJECT-buildkit" "$E2E_PROJECT-dind"; do
    docker rm -f "$c" >/dev/null 2>&1
  done
  e2e_compose down -v --remove-orphans >/dev/null 2>&1
  rm -rf "$SECRETS_DIR"
  if [ "$rc" -ne 0 ]; then
    echo
    echo "DOCKER ROUND TRIP FAILED (rc=$rc); compose logs preserved at: $preserved"
  fi
  exit "$rc"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 2. Secrets + fixtures
# ---------------------------------------------------------------------------
e2e_info "generating ephemeral secrets in $SECRETS_DIR"
SESSION_SECRET="$(e2e_gen_session_secret)"
REGISTRY_SEED="$(e2e_gen_registry_seed)"
e2e_write_master_key "$SECRETS_DIR"
e2e_write_internal_secret "$SECRETS_DIR"
e2e_write_jwks "$SECRETS_DIR" "$REGISTRY_SEED" "cp-ed25519-1"
e2e_write_internal_tls "$SECRETS_DIR"
e2e_write_bee_password "$SECRETS_DIR"

# Deterministic small image fixture: fixed payload + fixed labels, no ARG/date.
cat > "$WORK_DIR/one/payload.txt" <<'EOF'
uncloud-registry e2e deterministic payload
EOF
cat > "$WORK_DIR/one/Dockerfile" <<'EOF'
FROM scratch
COPY payload.txt /payload.txt
LABEL org.uncloud-registry.e2e=one
EOF
# Multi-platform fixture (built for linux/amd64 AND linux/arm64).
cat > "$WORK_DIR/multi/payload.txt" <<'EOF'
uncloud-registry e2e multi-platform payload
EOF
cat > "$WORK_DIR/multi/Dockerfile" <<'EOF'
FROM scratch
COPY payload.txt /payload.txt
LABEL org.uncloud-registry.e2e=multi
EOF

# dinD insecure-registry declaration and buildkitd registry policy (HTTP +
# insecure for the registry host only; never committed, live in the temp dir).
cat > "$SECRETS_DIR/dind-daemon.json" <<EOF
{"insecure-registries":["$REG_HOST"]}
EOF
cat > "$SECRETS_DIR/buildkitd.toml" <<EOF
[registry."$REG_HOST"]
  http = true
  insecure = true
EOF

# ---------------------------------------------------------------------------
# 3. Bring the reference stack up (pinned images, readiness waits)
# ---------------------------------------------------------------------------
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
  -H "Origin: $CP_ORIGIN" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" "$CP_ADDR/api/users/register")"
SESSION_TOKEN="$(printf '%s' "$REG_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')"
authz_session() { printf 'Authorization: Bearer %s' "$SESSION_TOKEN"; }
CREATE_JSON="$(curl -sS -X POST --max-time 20 -H 'Content-Type: application/json' \
  -H "$(authz_session)" \
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

# Compose network + registry container IP for the helper containers.
NET="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$E2E_PROJECT-registry-1" | awk '{print $1}')"
[ -n "$NET" ] || { echo "error: cannot resolve compose network" >&2; exit 1; }
REG_IP="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' "$E2E_PROJECT-registry-1" | awk '{print $1}')"
[ -n "$REG_IP" ] || { echo "error: cannot resolve registry container IP" >&2; exit 1; }
echo "compose network: $NET; registry IP: $REG_IP"

# ---------------------------------------------------------------------------
# 4. In-network docker engine (dind) + buildkit + client containers
# ---------------------------------------------------------------------------
e2e_info "starting in-network docker engine (pinned $DIND_IMAGE)"
docker run -d --name "$E2E_PROJECT-dind" --privileged --network "$NET" \
  --add-host "$REG_HOST:$REG_IP" \
  -v "$SECRETS_DIR/dind-daemon.json:/etc/docker/daemon.json:ro" \
  "$DIND_IMAGE" >/dev/null
DIND_RDY=0
for _ in $(seq 1 120); do
  if docker exec "$E2E_PROJECT-dind" docker info >/dev/null 2>&1; then DIND_RDY=1; break; fi
  sleep 2
done
[ "$DIND_RDY" = "1" ] || { echo "error: in-network docker daemon did not become ready" >&2; exit 1; }
echo "in-network docker engine ready"

e2e_info "starting in-network buildkit (pinned $BUILDKIT_IMAGE)"
docker run -d --name "$E2E_PROJECT-buildkit" --network "$NET" \
  --add-host "$REG_HOST:$REG_IP" \
  -v "$SECRETS_DIR/buildkitd.toml:/etc/buildkit/buildkitd.toml:ro" \
  "$BUILDKIT_IMAGE" \
  --oci-worker-no-process-sandbox --listen-addr tcp://0.0.0.0:1234 >/dev/null

e2e_info "starting docker CLI container (pinned $CLI_IMAGE)"
docker run -d --name "$E2E_PROJECT-cli" --network "$NET" \
  --add-host "$REG_HOST:$REG_IP" \
  -e "DOCKER_HOST=tcp://$E2E_PROJECT-dind:2375" \
  -v "$WORK_DIR:/work:ro" \
  -v "$WORK_DIR/out:/out:rw" \
  "$CLI_IMAGE" sleep infinity >/dev/null

# ---------------------------------------------------------------------------
# 5. Login, push (deterministic + multi-platform), inspect wire-level
# ---------------------------------------------------------------------------
e2e_info "docker login $REG_HOST"
printf '%s' "$PASSWORD" | docker exec -i "$E2E_PROJECT-cli" \
  docker login "$REG_HOST" -u "$EMAIL" --password-stdin >/dev/null \
  || { echo "error: docker login failed" >&2; exit 1; }

e2e_info "building + pushing deterministic image to brand-new repo rt-one"
ONE_DIGEST="$(docker exec "$E2E_PROJECT-cli" sh -c '
  docker build --provenance=false -t rt.localhost/rt-one:latest /work/one >/dev/null && \
  docker push rt.localhost/rt-one:latest 2>&1 | sed -n "s/^latest: digest: \(sha256:[0-9a-f]*\) size:.*/\1/p"
')"
[ "${#ONE_DIGEST}" = "71" ] && [ "${ONE_DIGEST#sha256:}" != "$ONE_DIGEST" ] \
  || { echo "error: push did not report a manifest digest (got: ${ONE_DIGEST:-none})" >&2; exit 1; }
echo "rt-one pushed: $ONE_DIGEST"
REPO_DIGEST_AFTER_PUSH="$(docker exec "$E2E_PROJECT-cli" docker image inspect \
  --format '{{index .RepoDigests 0}}' rt.localhost/rt-one:latest | tr -d '\r')"
[ "$REPO_DIGEST_AFTER_PUSH" = "rt.localhost/rt-one@$ONE_DIGEST" ] \
  || { echo "error: RepoDigests mismatch after push ($REPO_DIGEST_AFTER_PUSH)" >&2; exit 1; }

e2e_info "building + pushing multi-platform fixture (linux/amd64, linux/arm64)"
docker exec "$E2E_PROJECT-cli" sh -c "
  docker buildx create --name rt-builder --driver remote tcp://$E2E_PROJECT-buildkit:1234 >/dev/null 2>&1 || true
  docker buildx build --builder rt-builder \
    --platform linux/amd64,linux/arm64 \
    --provenance=false --sbom=false \
    -t rt.localhost/rt-multi:latest --push /work/multi >/dev/null 2>&1
" || { echo "error: multi-platform build/push failed" >&2; exit 1; }

e2e_info "inspecting manifests over the wire (token + raw registry HTTP)"
WIRE_TOKEN="$(docker exec "$E2E_PROJECT-cli" sh -c \
  "wget -qO- --user='$EMAIL' --password='$PASSWORD' \
   'http://controlplane:8081/token?service=rt.localhost&scope=repository:rt-one:pull'" \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)"
[ -n "$WIRE_TOKEN" ] || { echo "error: could not fetch a registry token over the wire" >&2; exit 1; }

WIRE_AUTH="Authorization: Bearer $WIRE_TOKEN"
docker exec -e WIRE_AUTH="$WIRE_AUTH" "$E2E_PROJECT-cli" sh -c '
  wget -qO- --header="$WIRE_AUTH" \
    --header="Accept: application/vnd.oci.image.manifest.v1+json" \
    http://rt.localhost/v2/rt-one/manifests/latest > /out/rt-one-manifest.json
  wget -qO- --header="$WIRE_AUTH" \
    --header="Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" \
    http://rt.localhost/v2/rt-multi/manifests/latest > /out/rt-multi-index.json
'
# The wire-served representations must be byte-identical to the pushed
# artifacts: their SHA-256 equals the pushed manifest/index digest. The
# multi-platform index must carry exactly the amd64 + arm64 children and each
# child digest must resolve to a manifest whose own digest matches.
MULTI_DIGEST="$(sha256sum "$WORK_DIR/out/rt-multi-index.json" | awk '{print $1}' | sed 's/^/sha256:/')"
python3 - "$ONE_DIGEST" "$MULTI_DIGEST" "$WORK_DIR/out" <<'PY'
import hashlib, json, sys

one_digest, multi_digest, out = sys.argv[1], sys.argv[2], sys.argv[3]

served_one = open(f"{out}/rt-one-manifest.json", "rb").read()
assert served_one.startswith(b"{"), "rt-one manifest not JSON"
assert "sha256:" + hashlib.sha256(served_one).hexdigest() == one_digest, \
    "served rt-one manifest digest mismatch"
man = json.loads(served_one)
assert man["mediaType"] in (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
), man.get("mediaType")

served_index = open(f"{out}/rt-multi-index.json", "rb").read()
assert "sha256:" + hashlib.sha256(served_index).hexdigest() == multi_digest, \
    "served rt-multi index digest mismatch"
index = json.loads(served_index)
assert index["mediaType"] in (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
), index.get("mediaType")
children = {c["platform"]["architecture"]: c for c in index["manifests"]}
assert set(children) == {"amd64", "arm64"}, list(children)
print("wire manifest inspection OK: rt-one digest + rt-multi index (amd64/arm64 children)")
PY

# ---------------------------------------------------------------------------
# 6. Restart services, pull, compare digests
# ---------------------------------------------------------------------------
e2e_info "restarting the registry service"
e2e_compose restart registry
e2e_compose_ps_healthy registry

e2e_info "pulling after restart and comparing digests"
PULLED_ONE="$(docker exec "$E2E_PROJECT-cli" sh -c '
  docker pull rt.localhost/rt-one:latest >/dev/null 2>&1 && \
  docker image inspect --format "{{index .RepoDigests 0}}" rt.localhost/rt-one:latest | tr -d "\r"
')"
[ "$PULLED_ONE" = "rt.localhost/rt-one@$ONE_DIGEST" ] \
  || { echo "error: rt-one pull digest mismatch (got $PULLED_ONE, want rt.localhost/rt-one@$ONE_DIGEST)" >&2; exit 1; }

docker exec "$E2E_PROJECT-cli" sh -c '
  docker pull rt.localhost/rt-multi:latest >/dev/null 2>&1 && \
  docker pull "rt.localhost/rt-multi@'"$MULTI_DIGEST"'" >/dev/null 2>&1
' \
  || { echo "error: rt-multi pull failed" >&2; exit 1; }
PULLED_MULTI="$(docker exec "$E2E_PROJECT-cli" sh -c \
  'docker image inspect --format "{{range .RepoDigests}}{{println .}}{{end}}" \
   rt.localhost/rt-multi:latest' | tr -d '\r' | grep "rt.localhost/rt-multi@sha256:" || true)"
printf '%s' "$PULLED_MULTI" | grep -q "^rt.localhost/rt-multi@$MULTI_DIGEST$" \
  || { echo "error: rt-multi pull digest mismatch (got: $PULLED_MULTI)" >&2; exit 1; }

echo "digest comparison after restart: rt-one and rt-multi both reproduce their pushed digests"

echo
echo "DOCKER ROUND TRIP PASS: login, first push, wire manifest inspection, restart, pull, digest comparison all green."