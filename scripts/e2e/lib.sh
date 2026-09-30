#!/usr/bin/env bash
# Shared helpers for the Task 24 reference-deployment E2E scripts.
#
# Sourced, not executed. The caller owns `set -euo pipefail` and its cleanup
# trap. Everything here is deterministic and writes secrets ONLY into the
# caller-provided temporary secrets directory (never into the repository).
#
# Runtime requirements checked by e2e_require: docker, docker compose, curl,
# openssl, go (used once to derive the Ed25519 public key/JWKS), python3 (JSON
# assertions), sed/awk/grep.

# --- command validation ---------------------------------------------------

# e2e_require <command> [hint]: fail loudly when a required tool is missing.
e2e_require() {
  local cmd="$1" hint="${2:-}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: required command not found: $cmd" >&2
    if [ -n "$hint" ]; then
      printf '  %s\n' "$hint" >&2
    fi
    exit 2
  fi
}

# --- compose driver -------------------------------------------------------

# e2e_compose <args...>: run docker compose anchored to this project and env
# file. E2E_PROJECT and E2E_ENV_FILE must be set by the caller.
e2e_compose() {
  docker compose -p "$E2E_PROJECT" --env-file "$E2E_ENV_FILE" "$@"
}

# e2e_compose_ps_healthy <service>: poll `docker compose ps` JSON until the
# service reports healthy (bounded; readiness-wait, not a blind sleep).
e2e_compose_ps_healthy() {
  local service="$1" timeout_s="${2:-180}" waited=0
  while [ "$waited" -lt "$timeout_s" ]; do
    local state
    state="$(e2e_compose ps --format json "$service" 2>/dev/null | python3 -c '
import sys, json
try:
    rows = json.load(sys.stdin)
    rows = rows if isinstance(rows, list) else [rows]
    for r in rows:
        if r.get("Service") == "'"$service"'":
            print(r.get("Health") or "")
except Exception:
    pass
')"
    if [ "$state" = "healthy" ]; then
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  echo "error: service $service did not become healthy within ${timeout_s}s (last health: ${state:-unknown})" >&2
  return 1
}

# e2e_wait_http <label> <url> [expected_code]: probe every 2s until the URL
# answers (any code) or -- expected_code matches; bounded by E2E_WAIT_TIMEOUT.
E2E_WAIT_TIMEOUT="${E2E_WAIT_TIMEOUT:-180}"
e2e_wait_http() {
  local label="$1" url="$2" want="${3:-}" waited=0 code
  while [ "$waited" -lt "$E2E_WAIT_TIMEOUT" ]; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 4 "$url" 2>/dev/null || true)"
    if [ -n "$want" ]; then
      [ "$code" = "$want" ] && { echo "$label: ready (HTTP $code)"; return 0; }
    else
      [ -n "$code" ] && [ "$code" != "000" ] && { echo "$label: up (HTTP $code)"; return 0; }
    fi
    sleep 2
    waited=$((waited + 2))
  done
  echo "error: $label not ready after ${E2E_WAIT_TIMEOUT}s (last HTTP ${code:-none})" >&2
  return 1
}

# e2e_wait_feed <bee_url> <owner> <topic>: wait until Bee resolves the feed
# (200) — the control-plane reconciler publishes asynchronously after registry
# creation, so readiness is polled, never slept through.
e2e_wait_feed() {
  local bee="$1" owner="$2" topic="$3" waited=0 code
  while [ "$waited" -lt "$E2E_WAIT_TIMEOUT" ]; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 4 "$bee/feeds/$owner/$topic" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
      echo "feed $owner/$topic: ready (HTTP 200)"
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  echo "error: feed $owner/$topic not resolvable after ${E2E_WAIT_TIMEOUT}s (last HTTP ${code:-none})" >&2
  return 1
}

# --- JSON helpers (python3) ------------------------------------------------

# e2e_json_get <expression> <file>: evaluate a python expression over the
# parsed JSON document (d = document). Used to extract fields safely.
e2e_json_get() {
  local expr="$1" file="$2"
  python3 - "$file" <<PY
import json, sys
d = json.load(open(sys.argv[1], "rb"))
print(eval("$expr"))
PY
}

# --- secrets: temporary directory, keys, certs -----------------------------

# e2e_make_secrets_dir: create a private temporary secrets directory (0700)
# and print its path.
e2e_make_secrets_dir() {
  local dir
  dir="$(mktemp -d "${TMPDIR:-/tmp}/uncloud-e2e-secrets.XXXXXX")"
  chmod 0700 "$dir"
  echo "$dir"
}

# e2e_write_master_key <dir>: master-key file (wire format: strict JSON,
# unpadded base64url 32-byte key under version "1", mode 0600).
e2e_write_master_key() {
  local dir="$1"
  openssl rand 32 | base64 | tr -d '=\n' | tr '+/' '-_' \
    | { printf '{"current":1,"keys":{"1":"'; cat; printf '"}}\n'; } > "$dir/master.json"
  chmod 0600 "$dir/master.json"
}

# e2e_write_internal_secret <dir>: internal service credential file: one line
# of >=32 random base64 bytes plus a single terminal newline, mode 0600.
# (openssl rand -base64 already emits a trailing newline; strip it with \n.)
e2e_write_internal_secret() {
  local dir="$1"
  openssl rand -base64 32 | tr -d '=+/\n' > "$dir/internal-secret.txt"
  printf '\n' >> "$dir/internal-secret.txt"
  chmod 0600 "$dir/internal-secret.txt"
}

# e2e_gen_session_secret: print a production-acceptable CONTROLPLANE_TOKEN_SECRET
# (>=32 random base64url chars, no repeated blocks).
e2e_gen_session_secret() {
  openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 43
}

# e2e_gen_registry_seed: print a 64-character hex Ed25519 seed.
e2e_gen_registry_seed() {
  openssl rand -hex 32
}

# e2e_write_jwks <dir> <seed-hex> <kid>: derive the Ed25519 PUBLIC key from the
# shared control-plane seed and write the strict registry JWKS document
# (only {"kty":"OKP","crv":"Ed25519","kid","x"} entries are accepted). The
# derivation runs a tiny stdlib-only Go program materialized in the secret dir
# (never committed); GOPROXY=off keeps it offline.
e2e_write_jwks() {
  local dir="$1" seed="$2" kid="$3"
  local src="$dir/jwksgen"
  mkdir -p "$src"
  cat > "$src/main.go" <<'GO'
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type key struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

func main() {
	seed, err := hex.DecodeString(os.Args[1])
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "seed must be 64 hex chars")
		os.Exit(1)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	doc := struct {
		Keys []key `json:"keys"`
	}{Keys: []key{{Kty: "OKP", Crv: "Ed25519", Kid: os.Args[2], X: base64.RawURLEncoding.EncodeToString(pub)}}}
	out, err := json.Marshal(doc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
GO
  ( cd "$src" && go mod init jwksgen >/dev/null 2>&1 && \
    GOPROXY=off go run . "$seed" "$kid" > "$dir/registry-jwks.json" )
  chmod 0644 "$dir/registry-jwks.json"
}

# e2e_write_internal_tls <dir>: internal feed-signing listener TLS. Creates a
# self-signed CA plus a server certificate for the SAN the registry dials
# (DNS:controlplane, DNS:localhost, IP:127.0.0.1). The CA bundle is mounted
# into the registry (CONTROLPLANE_CA_BUNDLE_FILE); cert is 0644, key 0600.
#
# NOTE: keys MUST be generated with `openssl ecparam -name prime256v1 -genkey`
# (named curve). `openssl genpkey -pkeyopt ec_paramgen_curve:P-256` on
# LibreSSL (macOS) embeds EXPLICIT prime-field parameters, which Go's x509
# rejects ("unknown elliptic curve").
e2e_write_internal_tls() {
  local dir="$1"
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/ca.key" 2>/dev/null
  openssl req -new -x509 -key "$dir/ca.key" -out "$dir/internal-ca.pem" \
    -days 3650 -subj "/CN=uncloud-registry e2e internal CA" 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/internal-key.pem" 2>/dev/null
  openssl req -new -key "$dir/internal-key.pem" \
    -out "$dir/internal.csr" -subj "/CN=controlplane" 2>/dev/null
  cat > "$dir/internal-ext.cnf" <<'CNF'
[server]
subjectAltName = DNS:controlplane, DNS:localhost, IP:127.0.0.1
CNF
  openssl x509 -req -in "$dir/internal.csr" -CA "$dir/internal-ca.pem" \
    -CAkey "$dir/ca.key" -CAcreateserial -out "$dir/internal-cert.pem" \
    -days 3650 -extfile "$dir/internal-ext.cnf" -extensions server 2>/dev/null
  chmod 0600 "$dir/internal-key.pem"
  chmod 0644 "$dir/internal-cert.pem" "$dir/internal-ca.pem"
  rm -f "$dir/internal.csr" "$dir/internal-ext.cnf" "$dir/ca.srl"
}

# e2e_write_bee_password <dir>: Bee keystore password file (one line).
e2e_write_bee_password() {
  local dir="$1"
  openssl rand -hex 16 > "$dir/bee-password.txt"
  chmod 0644 "$dir/bee-password.txt"
}

# --- postage batches (local dev chain) -------------------------------

# e2e_rpc <rpc-url> <method> <params-json>: JSON-RPC over HTTP, prints result.
e2e_rpc() {
  local rpc="$1" method="$2" params="$3"
  curl -sS --max-time 15 -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "$rpc"
}

# e2e_fund_address <rpc> <token-address> <to-address> <eth-wei-hex> <bzz-wei-hex>
# Fund <to> with ETH and BZZ on the local dev chain, sending from the first
# account that holds a balance. The pinned bee-localchain image funds custom
# private-key accounts (hardhat.config.ts networks.hardhat.accounts); the
# standard hardhat mnemonic accounts are kept as fallbacks.
e2e_fund_address() {
  local rpc="$1" token="$2" to="$3" eth_hex="$4" bzz_hex="$5"
  # The pinned bee-localchain image funds custom private-key accounts listed
  # in its hardhat.config.ts (networks.hardhat.accounts) - the standard
  # hardhat mnemonic accounts do not exist there. Probe that list first, with
  # the default mnemonic accounts kept as fallbacks for other localchains.
  local accounts=(
    0x62CAb2B3b55F341F10348720ca18063CdB779aD5  # deployer
    0x7E71bA1aB8AF3454a01CFafe358BEbb7691d02f8  # admin
    0xFCA295bC36F47A3Eb53F657b88f3f324374656C6  # stamper
    0xB5963cAcF590909407433024cD3BA0319542E99D  # oracle
    0x9C8EEad79edDC16594489d63E5A9F7530b642079  # redistributor
    0x4e0B2f8C2210e9ea9341a401C4276549Ea9541c7  # pauser
    0xbFC32C0779b9B17D2e2DCd916493528BF4561142  # node_0
    0xB257DaAc87899038871E3FB280da58191eFB5Ca2  # node_4
    0x77CbAdb1059dDC7334227e025fC940469f52FEd8  # node_6
    0x4906632d6693733554EE11eA785EB718d2e2ffdA  # node_7
    0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266  # default hardhat (fallback)
    0x70997970C51812dc3A010C7d01b50e0d17dc79C8  # default hardhat (fallback)
  )
  local from="" bal
  for a in "${accounts[@]}"; do
    bal="$(e2e_rpc "$rpc" eth_getBalance "[\"$a\",\"latest\"]" \
      | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["result"],16))' 2>/dev/null || echo 0)"
    if [ "$bal" != "0" ] && [ -n "$bal" ]; then from="$a"; break; fi
  done
  [ -n "$from" ] || { echo "error: no funded account on the local chain ($rpc)" >&2; return 1; }

  # Send the transaction object as a real JSON object in params[0] (a quoted
  # string is rejected by the node) and FAIL LOUDLY on any error: a silently
  # dropped funding tx leaves the bee node unfunded and the stamp mint fails
  # later with an opaque "out of funds".
  local txres
  txres="$(e2e_rpc "$rpc" eth_sendTransaction \
    "[$(printf '{"from":"%s","to":"%s","value":"%s"}' "$from" "$to" "$eth_hex")]")"
  printf '%s' "$txres" | python3 -c 'import json,sys; json.load(sys.stdin)["result"]' \
    || { echo "error: ETH funding transfer failed: $txres" >&2; return 1; }
  # ERC-20 transfer(address,uint256): a9059cbb + padded to + padded amount.
  local data="0xa9059cbb"
  data="$data$(printf '%064s' "${to#0x}" | tr ' ' 0)"
  data="$data$(python3 -c "print('{:064x}'.format(int('$bzz_hex',16)))")"
  txres="$(e2e_rpc "$rpc" eth_sendTransaction \
    "[$(printf '{"from":"%s","to":"%s","data":"%s"}' "$from" "$token" "$data")]")"
  printf '%s' "$txres" | python3 -c 'import json,sys; json.load(sys.stdin)["result"]' \
    || { echo "error: BZZ funding transfer failed: $txres" >&2; return 1; }
  echo "funded $to on localchain ($eth_hex ETH, $bzz_hex BZZ wei) from $from"
}

# e2e_provision_stamp_batch <bee-url> <localchain-rpc>: ensure the bee node's
# wallet is funded on the local chain, then mint a postage batch (amount
# 1e8 PLUR = 0.1 BZZ, depth 20) and print the batchID. Needs the localchain
# token/postage addresses from the reference stack.
e2e_provision_stamp_batch() {
  local bee="$1" rpc="$2"
  # Progress banners go to stderr: this function's STDOUT is captured as the
  # batchID by callers, and any extra line would corrupt the JSON payloads.
  e2e_wait_http "bee stamps API ($bee)" "$bee/stamps" "200" >&2 || return 1

  local addr_json eth
  addr_json="$(curl -sS --max-time 10 "$bee/addresses")"
  eth="$(printf '%s' "$addr_json" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(d.get("ethereum") or d.get("eth") or "")')"
  [ -n "$eth" ] || { echo "error: bee /addresses did not expose an ethereum address: $addr_json" >&2; return 1; }

  # funder: 0.3 ETH (0x429d069189e0000) + 20 BZZ (0x1158e460913d00000) in wei.
  e2e_fund_address "$rpc" "0x6AAB14FE9cccd64A502d23842d916eB5321c26E7" \
    "$eth" "0x429d069189e0000" "0x1158e460913d00000" >&2 || return 1

  e2e_info "minting postage batch (1e8 PLUR, depth 20) on the local chain" >&2
  local batch_json batch_id
  batch_json="$(curl -sS -X POST --max-time 120 "$bee/stamps/100000000/20")"
  batch_id="$(printf '%s' "$batch_json" | python3 -c '
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.stdout.write(d.get("batchID") or "")')"
  [ -n "$batch_id" ] || { echo "error: could not mint a postage batch (stamps API resp: $batch_json)" >&2; return 1; }

  # The dev chain's hardhat node mines a block only when asked, so a fresh
  # batch stays unusable until the chain has advanced past its maturity depth
  # (~20 blocks). Wait for usable BEFORE returning so callers never create
  # registries against an unusable batch: the reconciler would fail to publish
  # policy feeds and control-plane readiness (/readyz) would flip.
  local waited=0 usable
  while [ "$waited" -lt 300 ]; do
    usable="$(curl -sS --max-time 5 "$bee/stamps/$batch_id" 2>/dev/null \
      | python3 -c 'import json,sys; print(json.load(sys.stdin).get("usable", False))' 2>/dev/null || echo False)"
    [ "$usable" = "True" ] && { e2e_info "postage batch usable after ${waited}s" >&2; break; }
    sleep 5
    waited=$((waited + 5))
  done
  [ "$usable" = "True" ] || { echo "error: postage batch $batch_id not usable after ${waited}s" >&2; return 1; }

  printf '%s' "$batch_id"
}

# --- failure handling ------------------------------------------------------

# e2e_dump_logs <logfile>: snapshot the whole stack's logs for failure review.
e2e_dump_logs() {
  local logfile="$1"
  echo "=== dumping compose logs to $logfile" >&2
  e2e_compose logs --no-color > "$logfile" 2>&1 || true
  echo "=== end compose logs" >&2
}

# e2e_info: standard step banner.
e2e_info() {
  printf '\n[%s] %s\n' "$(basename "$0")" "$*"
}