# Installing the reference deployment (v1)

This procedure installs the Task 24 reference deployment (`compose.yaml`) on
a fresh host, grounds on the actual binaries and config in this repository,
and ends with verified readiness. It is the same flow the e2e scripts drive
automatically (`scripts/e2e/compose-smoke.sh`); follow this document when you
need the steps by hand.

## 1. Requirements

- Docker Engine with Compose v2 (`docker compose version`)
- `openssl`, `go` (used once, to derive the Ed25519 JWKS), `python3`
- Ports free on the host: `8081` (control plane, loopback only),
  `1633`/`1635` (Bee debug/API, loopback only), `80`/`443` (Caddy, public)

Bee runs as an **isolated light node** in this stack (see
`docs/compatibility.md` §8): feed-dependent verification (pull round-trips,
auth-policy feed resolution) is deferred to the Phase 4 / real-Bee gate. The
control plane, registry API, sessions, staging, and backup/restore all work
and are verified in this deployment.

## 2. Project layout

```text
<deployment>/
  compose.yaml            copy of this repository's compose.yaml (Task 24)
  .env                    deployment variables (SECRETS-BEARING — never committed)
  .secrets/               SECRETS_DIR — every credential file, mode 0600 where secret
  data/                   (after first start) controlplane.db, staging.db, spool/
  backups/                created by scripts/operations/backup.sh
```

The two persistent Docker named volumes are `controlplane-data`
(`/var/lib/uncloud-registry` inside the control-plane container, holding
`controlplane.db`) and `staging-data` (same path inside the registry
container, holding `staging.db` and `spool/`). `backup.sh` treats a
conventional `<deployment>/data/` tree as the source of truth — see
`backup-restore.md` for mapping volume paths into the scripts.

## 3. Secrets directory (SECRETS_DIR)

Every credential is mounted read-only from `${SECRETS_DIR}` — never baked
into images, never committed. Required files (names fixed by the binaries):

| File | Used by | Notes |
|------|---------|-------|
| `master.json` | control plane | feed-key master key, JSON `{"current":1,"keys":{"1":"<key>"}}`; mode 0600 |
| `internal-secret.txt` | control plane + registry | one line ≥ 32 random bytes; mode 0600 |
| `internal-ca.pem` | registry | CA that signed the internal listener cert; 0644 |
| `internal-cert.pem` | control plane | TLS cert for the internal feed-signing listener (SAN `controlplane`, `localhost`, `127.0.0.1`); 0644 |
| `internal-key.pem` | control plane | matching private key; mode 0600 |
| `registry-jwks.json` | registry | JWKS with the CONTROLPLANE_REGISTRY_ED25519_KEY public key; 0644 |
| `bee-password.txt` | Bee | Bee keystore password (one line); mode 0600 |

Generate with the same commands the e2e scripts use
(`scripts/e2e/lib.sh`):

```bash
mkdir -p .secrets && chmod 0700 .secrets
cd .secrets

# master key: 32 random bytes, unpadded base64url, version "1"
openssl rand 32 | base64 | tr -d '=\n' | tr '+/' '-_' \
  | { printf '{"current":1,"keys":{"1":"'; cat; printf '"}}\n'; } > master.json
chmod 0600 master.json

# internal service credential
openssl rand -base64 32 | tr -d '=+/\n' > internal-secret.txt
printf '\n' >> internal-secret.txt
chmod 0600 internal-secret.txt

# bee password
printf '%s\n' "$(openssl rand -hex 16)" > bee-password.txt
chmod 0600 bee-password.txt

# internal TLS (CA + server cert) — e2e procedure:
#   NOTE: use `openssl ecparam -name prime256v1 -genkey`; `openssl genpkey`
#   on LibreSSL embeds explicit prime-field params that Go's x509 rejects.
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -out internal-ca.pem -days 3650 \
  -subj "/CN=uncloud-registry internal CA"
openssl ecparam -name prime256v1 -genkey -noout -out internal-key.pem
openssl req -new -key internal-key.pem -out internal.csr -subj "/CN=controlplane"
# sign with SANs: DNS:controlplane, DNS:localhost, IP:127.0.0.1
# (see e2e_write_internal_tls in scripts/e2e/lib.sh for the exact openssl x509 invocation)
openssl x509 -req -in internal.csr -CA internal-ca.pem -CAkey ca.key -CAcreateserial \
  -out internal-cert.pem -days 3650 \
  -extfile <(cat <<'CNF'
subjectAltName=DNS:controlplane,DNS:localhost,IP:127.0.0.1
CNF
) 2>/dev/null
chmod 0600 internal-key.pem && rm -f ca.key internal.csr
```

> The internal listener runs in `trusted-proxy` mode inside the compose
> network, so the certificate only needs to be valid for the registry's
> outbound dial (`DNS:controlplane`); it does not need to be publicly
> trusted.

## 4. Registry token signing key and JWKS

The control plane signs registry bearer tokens with an Ed25519 seed
(`CONTROLPLANE_REGISTRY_ED25519_KEY`, 64 hex chars) under key ID
`CONTROLPLANE_REGISTRY_KEY_ID` (default `cp-ed25519-1`). The registry data
plane verifies with the public keys in `registry-jwks.json` — the file is
loaded **once at startup** and supports multiple kids for rotation overlap
(`key-rotation.md`).

```bash
SEED=$(openssl rand -hex 32)
# derive the public key with the stdlib-only helper (identical to e2e_write_jwks)
mkdir -p /tmp/jwksgen && cat > /tmp/jwksgen/main.go <<'GO'
package main
import (
    "crypto/ed25519"; "encoding/base64"; "encoding/hex"; "encoding/json"; "os"
)
type key struct { Kty, Crv, Kid, X string }
func main() {
    seed, _ := hex.DecodeString(os.Args[1])
    pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
    d, _ := json.Marshal(struct{ Keys []key `json:"keys"` }{Keys: []key{{"OKP", "Ed25519", os.Args[2], base64.RawURLEncoding.EncodeToString(pub)}}})
    os.Stdout.Write(d)
}
GO
(cd /tmp/jwksgen && go mod init jwksgen >/dev/null 2>&1 && GOPROXY=off go run . "$SEED" "cp-ed25519-1" > .secrets/registry-jwks.json)
```

Then put `SEED` into `.env` as `CONTROLPLANE_REGISTRY_ED25519_KEY` and set
`CONTROLPLANE_REGISTRY_KEY_ID=cp-ed25519-1`. The seed is a live signing
secret — treat it like the master key (rotation: `key-rotation.md`).

## 5. `.env`

Copy `.env.example` and fill it. The values the binaries actually read are
those documented in `internal/config/controlplane.go` and
`cmd/registry/main.go`; `compose.yaml` passes them through. Minimum set:

```bash
CONTROLPLANE_MODE=production
CONTROLPLANE_EXTERNAL_URL=https://controlplane.example.test
CONTROLPLANE_REGISTRY_DOMAIN=example.test
CONTROLPLANE_TOKEN_SECRET=<43 random base64url chars, e.g. $(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 43)>
CONTROLPLANE_REGISTRY_ED25519_KEY=<the seed from step 4>
CONTROLPLANE_REGISTRY_KEY_ID=cp-ed25519-1
REGISTRY_OWNER_MAP=          # <host>=<feedOwnerAddress>,... after registries exist
REGISTRY_ID_MAP=             # <host>=<registry id>,...
REGISTRY_TOKEN_AUDIENCE=     # exact comma-separated host allowlist
REGISTRY_HOST_GLOB=*.example.test
CONTROLPLANE_HOST=controlplane.example.test
SECRETS_DIR=./.secrets
```

`.env` is secrets-bearing (`CONTROLPLANE_TOKEN_SECRET`,
`CONTROLPLANE_REGISTRY_ED25519_KEY`). It is deliberately **never** included
in a backup archive by `backup.sh` (`backup-restore.md`).

## 6. Start and verify

```bash
docker compose --env-file .env up -d --build
```

Startup order is enforced by `depends_on` health conditions: localchain →
Bee → control plane → registry → Caddy. Each service stages the read-only
secrets mount, drops privileges, and only then execs the binary; the
binaries run their schema migrations at startup (control-plane
`schema_migrations` → v17, staging `staging_schema` → v11) and fail closed
on any missing/malformed secret or config.

Readiness (bounded, per-service):

```bash
curl -fsS http://127.0.0.1:8081/readyz    # control plane: db + master key + signing key + publication
curl -fsS http://127.0.0.1:80/readyz      # registry data plane
curl -fsS http://127.0.0.1:8081/livez     # liveness, always 200
docker compose --env-file .env ps         # all services "healthy"
```

`/readyz` answers 200 with a fixed JSON component summary and 503 when any
component is not ready; components and errors are data-free by design
(`internal/controlplane/health.go`, `internal/registry/health.go`).

## 7. Post-install checks

```bash
bash scripts/ci/check.sh                 # build, vet, race tests, secret scan
bash scripts/security/check-repository-secrets.sh
# Automated smoke (skips the feed-dependent push stage explicitly, exit 0):
bash scripts/e2e/compose-smoke.sh
```

Registry creation and collaborator workflows go through the control-plane
dashboard/API (`/api/registries`); `REGISTRY_OWNER_MAP` / `REGISTRY_ID_MAP`
are filled from `GET /api/registries` after creating each registry. The
pull/push digest round-trips remain deferred to the Phase 4 real-Bee gate
(`docs/compatibility.md` §8).

## 8. First backup

Immediately after a healthy install, take and verify a baseline backup:

```bash
bash scripts/operations/backup.sh --deploy-dir . --secrets-dir .secrets
bash scripts/operations/verify-backup.sh --backup-dir backups/<label> --secrets-dir .secrets
```

See `backup-restore.md` for what the archive contains and what it
deliberately excludes.