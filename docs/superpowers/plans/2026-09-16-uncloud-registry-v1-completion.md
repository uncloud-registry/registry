# Uncloud Registry v1 Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a production-ready self-hosted Uncloud Registry v1 that securely authenticates Docker clients, publishes correct policy and repository feeds to real Bee, survives restarts and concurrent pushes, and ships with a verified Docker Compose operating model.

**Architecture:** Preserve the two-service architecture. The control plane owns users, role policies, asymmetric registry-token signing, envelope-encrypted feed keys, provisioning reconciliation, and constrained feed publication; the registry verifies tokens and published policies, durably stages uploads, validates OCI content, serializes repository publication, and serves immutable Bee content. V1 runs one active registry writer and uses Docker Compose as its canonical deployment.

**Tech Stack:** Go 1.25+, standard `net/http`, `database/sql`, `modernc.org/sqlite`, `github.com/golang-jwt/jwt/v4`, Go `crypto/ed25519`, Go `crypto/aes`/`cipher`, `log/slog`, Prometheus Go client, Docker Compose, Bee HTTP API, Docker and Podman CLIs, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-16-uncloud-registry-v1-completion-design.md`

## Global Constraints

- Keep the module path `github.com/uncloud-registry/registry`.
- V1 is a production-ready self-hosted product, not a hosted multi-tenant service.
- Support one active registry writer; active-active publication is out of scope.
- Store permanent content and published metadata in Bee; store temporary upload bytes in a filesystem spool and upload metadata in SQLite.
- The registry process must never receive feed private keys.
- Registry tokens are signed asymmetrically by the control plane and verified with public keys by the registry.
- Session tokens and registry tokens use separate keys, issuers, audiences, types, and validators.
- Policy management remains structured and role-based; unrestricted policy JSON editing is out of scope.
- Validate manifests before immutable upload and publish only referenced staged blobs.
- Pass the stamp-policy-selected batch explicitly through every Bee operation requiring postage.
- Every behavior change follows red-green-refactor and runs `go test -race` before commit.
- Every phase ends with executable evidence; code review alone cannot close a phase.
- Do not delete or rewrite the existing local `controlplane.db`; migration and rotation procedures must preserve recoverability.

---

## Planned file map

### Authentication and security

- Create `internal/auth/registry_token.go`: asymmetric registry-token claims, issuer, verifier, and exact scope matching.
- Create `internal/auth/session_token.go`: session-only HMAC claims and validator.
- Create `internal/auth/principal.go`: verified principal and authorization action types.
- Replace `internal/auth/token.go` after callers migrate; retain no raw bearer fallback.
- Create `internal/controlplane/dto.go`: response-only API/UI models.
- Create `internal/controlplane/keycrypto.go`: AES-GCM feed-key encryption and key versions.
- Create `internal/controlplane/invites.go`: one-way invite digest helpers and recipient validation.
- Create `internal/controlplane/security.go`: CSRF, secure-cookie, rate-limit, and internal-service authentication helpers.

### Persistence and publication

- Create `internal/controlplane/migrations.go`: ordered schema migrations and schema version table.
- Create `internal/controlplane/outbox.go`: durable publication jobs and state transitions.
- Create `internal/controlplane/reconciler.go`: idempotent policy-publication worker.
- Create `internal/controlplane/feed_signer.go`: constrained key decrypt/sign/publish service.
- Create `internal/controlplane/internal_http.go`: private feed-publication endpoint.
- Create `internal/publish/commit.go`: registry-side control-plane feed commit client and request types.
- Create `internal/publish/manifest.go`: OCI manifest/index parsing and reference extraction.
- Create `internal/publish/locks.go`: keyed per-owner/repository publication serialization.
- Modify `internal/swarm/bee.go`: explicit batch propagation, binary references, read-back, pin cleanup.

### Durable staging

- Create `internal/staging/sqlite.go`: SQLite upload metadata and migrations.
- Create `internal/staging/spool.go`: safe filesystem paths and streaming file operations.
- Create `internal/staging/service.go`: ownership, offsets, quotas, expiry, finalization, and cleanup.
- Retire `internal/staging/store.go` memory behavior from production wiring; preserve a focused in-memory test adapter if useful.

### HTTP, operations, and deployment

- Create `internal/registry/errors.go`: stable Distribution-style error mapping.
- Create `internal/registry/authn.go`: request authentication boundary.
- Create `internal/registry/manifest.go`: HTTP negotiation and OCI validation integration.
- Create `internal/registry/health.go`: liveness/readiness handlers.
- Create `internal/controlplane/health.go`: liveness/readiness handlers.
- Create `internal/observability/metrics.go`: shared Prometheus metrics.
- Create `internal/server/server.go`: timeout and graceful-shutdown wrapper.
- Create `Dockerfile.registry`, `Dockerfile.controlplane`, `compose.yaml`, and `.env.example`.
- Create `scripts/e2e/compose-smoke.sh`, `scripts/e2e/docker-roundtrip.sh`, and `scripts/e2e/podman-roundtrip.sh`.
- Create `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- Create `docs/compatibility.md` and operator runbooks under `docs/operations/`.

---

## Phase 0 — Containment and baseline

### Task 1: Add secret-scanning and sensitive-response regression gates

**Files:**
- Create: `.gitleaks.toml`
- Create: `scripts/security/check-repository-secrets.sh`
- Create: `internal/controlplane/response_security_test.go`
- Modify: `.github/workflows/ci.yml` only when Task 22 creates the workflow
- Reference: `internal/controlplane/http.go:68-131`
- Reference: `internal/controlplane/store.go:20-38`

**Interfaces:**
- Consumes: current HTTP handlers and persistence models.
- Produces: `TestPublicResponsesDoNotExposeSecrets` and a deterministic repository scan command used by every later phase gate.

- [ ] **Step 1: Write the failing response-redaction test**

```go
func TestPublicResponsesDoNotExposeSecrets(t *testing.T) {
    server, token := newAuthenticatedControlPlaneServer(t)
    bodies := [][]byte{
        doJSON(t, server, http.MethodPost, "/api/users/register", `{"email":"a@example.test","password":"correct-horse-battery-staple"}`, ""),
        doJSON(t, server, http.MethodPost, "/api/registries", `{"slug":"alice","ensName":"alice.registry.eth","defaultStampBatchID":"batch-1"}`, token),
        doJSON(t, server, http.MethodGet, "/api/registries", "", token),
    }
    forbidden := []string{"PasswordHash", "password_hash", "EncryptedFeedPrivateKey", "encrypted_feed_private_key", "TokenHash", "token_hash"}
    for _, body := range bodies {
        for _, key := range forbidden {
            if bytes.Contains(body, []byte(key)) {
                t.Fatalf("response exposed %q: %s", key, body)
            }
        }
    }
}
```

- [ ] **Step 2: Run the test and verify the current API fails**

Run: `go test ./internal/controlplane -run TestPublicResponsesDoNotExposeSecrets -count=1 -v`

Expected: FAIL because current handlers serialize `User` and `Registry` persistence structs directly.

- [ ] **Step 3: Add the repository scan script**

```bash
#!/usr/bin/env bash
set -euo pipefail

git grep -nE '(BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})' -- ':!go.sum' && {
  echo "credential-like material found" >&2
  exit 1
}

for path in controlplane.db .env; do
  if git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
    echo "sensitive runtime file is tracked: $path" >&2
    exit 1
  fi
done
```

- [ ] **Step 4: Add focused gitleaks configuration**

```toml
[extend]
useDefault = true

[allowlist]
description = "Documented sample values and test-only literals"
paths = [
  '''README\.md''',
  '''docs/.*\.md''',
  '''.*_test\.go'''
]
```

- [ ] **Step 5: Run baseline gates**

Run:

```bash
bash scripts/security/check-repository-secrets.sh
go test -race -count=1 ./...
go vet ./...
go mod verify
git diff --check
```

Expected: the repository scan, race tests, vet, module verification, and whitespace check pass; the new response test remains red until Task 3.

- [ ] **Step 6: Commit the baseline**

```bash
git add .gitleaks.toml scripts/security/check-repository-secrets.sh internal/controlplane/response_security_test.go
git commit -m "test: add security containment gates"
```

### Task 2: Introduce versioned SQLite migrations and schema constraints

**Files:**
- Create: `internal/controlplane/migrations.go`
- Create: `internal/controlplane/migrations_test.go`
- Modify: `internal/controlplane/store.go:64-136`
- Test: `internal/controlplane/migrations_test.go`

**Interfaces:**
- Consumes: `*sql.DB` opened by `OpenSQLite`.
- Produces: `func ApplyMigrations(ctx context.Context, db *sql.DB) error` and `func CurrentSchemaVersion(ctx context.Context, db *sql.DB) (int, error)`.

- [ ] **Step 1: Write failing migration tests**

```go
func TestApplyMigrationsCreatesConstrainedSchema(t *testing.T) {
    db := openRawTestDB(t)
    require.NoError(t, ApplyMigrations(context.Background(), db))
    version, err := CurrentSchemaVersion(context.Background(), db)
    require.NoError(t, err)
    require.Equal(t, 1, version)

    _, err = db.Exec(`insert into registry_memberships
        (registry_id,user_id,role,can_pull,can_push,created_at)
        values (999,999,'member',1,0,?)`, time.Now().UTC().Format(time.RFC3339))
    require.Error(t, err)
}

func TestApplyMigrationsIsIdempotent(t *testing.T) {
    db := openRawTestDB(t)
    require.NoError(t, ApplyMigrations(context.Background(), db))
    require.NoError(t, ApplyMigrations(context.Background(), db))
}
```

Use standard-library assertions if the project does not add `testify`; do not add a test framework solely for these examples.

- [ ] **Step 2: Run tests and verify failure**

Run: `go test ./internal/controlplane -run 'TestApplyMigrations' -count=1 -v`

Expected: FAIL because `ApplyMigrations` and schema versioning do not exist.

- [ ] **Step 3: Implement ordered migration application**

```go
type migration struct {
    Version int
    SQL     []string
}

var migrations = []migration{{
    Version: 1,
    SQL: []string{
        `create table if not exists schema_migrations (version integer primary key, applied_at text not null)`,
        `create table if not exists users (id integer primary key autoincrement, email text not null unique, password_hash text not null, created_at text not null)`,
        `create table if not exists registries (id integer primary key autoincrement, slug text not null unique, host text not null unique, ens_name text not null, owner_user_id integer not null references users(id), feed_owner_address text not null, encrypted_feed_private_key text not null, default_stamp_batch_id text not null, anonymous_pull integer not null, created_at text not null)`,
        `create table if not exists registry_memberships (id integer primary key autoincrement, registry_id integer not null references registries(id) on delete cascade, user_id integer not null references users(id) on delete cascade, role text not null, can_pull integer not null, can_push integer not null, created_at text not null, unique(registry_id,user_id))`,
        `create table if not exists registry_invites (id integer primary key autoincrement, registry_id integer not null references registries(id) on delete cascade, email text not null, role text not null, can_pull integer not null, can_push integer not null, token_hash text not null unique, status text not null, expires_at text not null, created_at text not null)`,
    },
}}
```

Apply each version in one transaction, enable `PRAGMA foreign_keys=ON`, and insert the migration row only after every statement succeeds.

- [ ] **Step 4: Wire migrations into `OpenSQLite`**

Replace `store.Migrate(context.Background())` with `ApplyMigrations(context.Background(), db)`. Keep compatibility migration logic only as an explicit migration version; remove error-string matching for duplicate columns after an upgrade test covers the existing schema.

- [ ] **Step 5: Add existing-schema upgrade fixture**

Create a test database with the current schema, insert one user/registry/membership/invite, run `ApplyMigrations`, and assert all rows remain and foreign-key checks report no violations.

Run: `go test ./internal/controlplane -run 'TestApplyMigrations|TestUpgradeCurrentSchema' -count=1 -v`

Expected: PASS.

- [ ] **Step 6: Commit the migration framework**

```bash
git add internal/controlplane/migrations.go internal/controlplane/migrations_test.go internal/controlplane/store.go
git commit -m "feat: add versioned control-plane migrations"
```

### Task 3: Add public DTOs and close response exposure

**Files:**
- Create: `internal/controlplane/dto.go`
- Create: `internal/controlplane/dto_test.go`
- Modify: `internal/controlplane/http.go`
- Modify: `internal/controlplane/ui.go`
- Test: `internal/controlplane/response_security_test.go`

**Interfaces:**
- Consumes: `User`, `Registry`, `Membership`, `Invite` persistence records.
- Produces: `PublicUser`, `PublicRegistry`, `PublicMembership`, `PublicInvite`, and conversion functions.

- [ ] **Step 1: Write failing DTO serialization tests**

```go
func TestPublicRegistryJSONHasNoSecretFields(t *testing.T) {
    raw, err := json.Marshal(NewPublicRegistry(Registry{
        ID: 1, Slug: "alice", Host: "alice.example.test",
        EncryptedFeedPrivateKey: "ciphertext",
    }))
    if err != nil { t.Fatal(err) }
    if bytes.Contains(raw, []byte("ciphertext")) || bytes.Contains(raw, []byte("EncryptedFeedPrivateKey")) {
        t.Fatalf("secret leaked: %s", raw)
    }
}
```

- [ ] **Step 2: Run tests and verify failure**

Run: `go test ./internal/controlplane -run 'TestPublicRegistryJSON|TestPublicResponsesDoNotExposeSecrets' -count=1 -v`

Expected: FAIL because DTO types do not exist and handlers still return persistence structs.

- [ ] **Step 3: Implement explicit DTOs**

```go
type PublicUser struct {
    ID        int64     `json:"id"`
    Email     string    `json:"email"`
    CreatedAt time.Time `json:"createdAt"`
}

type PublicRegistry struct {
    ID                  int64     `json:"id"`
    Slug                string    `json:"slug"`
    Host                string    `json:"host"`
    ENSName             string    `json:"ensName"`
    FeedOwnerAddress    string    `json:"feedOwnerAddress"`
    DefaultStampBatchID string    `json:"defaultStampBatchID"`
    AnonymousPull       bool      `json:"anonymousPull"`
    CreatedAt           time.Time `json:"createdAt"`
}
```

Define equivalent membership and invite DTOs. Invite DTOs exclude `TokenHash`; the one-time raw invite token is returned in a separate creation response only.

- [ ] **Step 4: Convert every API and UI view model at the handler boundary**

Update registration, login, registry create/list/detail, membership, and invite responses. Do not add `json:"-"` as the only protection; persistence structs must not cross the response boundary.

- [ ] **Step 5: Run security and package tests**

Run:

```bash
go test ./internal/controlplane -run 'TestPublic|TestUI' -count=1 -v
go test -race -count=1 ./internal/controlplane
bash scripts/security/check-repository-secrets.sh
```

Expected: PASS, including the red test from Task 1.

- [ ] **Step 6: Commit DTO isolation**

```bash
git add internal/controlplane/dto.go internal/controlplane/dto_test.go internal/controlplane/http.go internal/controlplane/ui.go internal/controlplane/response_security_test.go
git commit -m "fix: prevent control-plane secret exposure"
```

## Phase 1 — Secure trust boundary

### Task 4: Split session and registry token types

**Files:**
- Create: `internal/auth/principal.go`
- Create: `internal/auth/session_token.go`
- Create: `internal/auth/session_token_test.go`
- Create: `internal/auth/registry_token.go`
- Create: `internal/auth/registry_token_test.go`
- Modify: `internal/auth/token.go`
- Modify: `internal/controlplane/service.go`

**Interfaces:**
- Produces: `SessionTokenManager`, `RegistryTokenIssuer`, `RegistryTokenVerifier`, `Principal`, and `Action`.
- `RegistryTokenVerifier.Verify(raw, service, repository string, action Action) (Principal, error)` is consumed by Task 5.

- [ ] **Step 1: Define the verified principal and action types**

```go
type Action string

const (
    ActionPull Action = "pull"
    ActionPush Action = "push"
)

type Principal struct {
    Subject    string
    TokenID    string
    Service    string
    Repository string
    Actions    map[Action]struct{}
}
```

- [ ] **Step 2: Write failing registry-token matrix tests**

Test valid push, expired token, wrong algorithm, wrong key ID, session token, wrong issuer, wrong service, wrong repository, pull-only token used for push, malformed scope, and unknown action.

```go
func TestRegistryTokenVerifierRejectsWrongRepository(t *testing.T) {
    issuer, verifier := newTestRegistryTokenPair(t)
    raw := issueRegistryToken(t, issuer, "role:write", "alice.example.test", "backend/api", ActionPush)
    _, err := verifier.Verify(raw, "alice.example.test", "other/repo", ActionPush)
    if !errors.Is(err, ErrScopeDenied) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 3: Run tests and verify failure**

Run: `go test ./internal/auth -run 'TestRegistryTokenVerifier' -count=1 -v`

Expected: FAIL because asymmetric verifier types do not exist.

- [ ] **Step 4: Implement asymmetric registry token issuance**

Use `ed25519.PrivateKey`, JWT `SigningMethodEdDSA`, explicit issuer, audience/service, `typ=registry`, token ID, and an access array:

```go
type RegistryAccess struct {
    Type    string   `json:"type"`
    Name    string   `json:"name"`
    Actions []Action `json:"actions"`
}

type RegistryClaims struct {
    TokenType string           `json:"typ"`
    Service   string           `json:"service"`
    Access    []RegistryAccess `json:"access"`
    jwt.RegisteredClaims
}
```

Reject every algorithm except EdDSA. Resolve verification keys by `kid` through `type PublicKeySet interface { Key(ctx context.Context, keyID string) (ed25519.PublicKey, error) }`.

- [ ] **Step 5: Implement a separate session manager**

Keep session tokens on a separate HMAC key and require `typ=session`, control-plane issuer, and control-plane audience. Remove generic parsing that can accept both purposes.

- [ ] **Step 6: Update control-plane issuance**

Replace `IssueRegistryToken(subject, service, scope, ttl)` with structured input:

```go
type RegistryTokenRequest struct {
    Subject    string
    Service    string
    Repository string
    Actions    []auth.Action
    TTL        time.Duration
}
```

Parse Docker scope exactly as `repository:<name>:<comma-separated-actions>` and reject extra or missing fields.

- [ ] **Step 7: Run authentication tests**

Run:

```bash
go test -race -count=1 ./internal/auth
go test -count=1 ./internal/controlplane -run 'Test.*RegistryToken' -v
```

Expected: PASS for all positive and negative cases.

- [ ] **Step 8: Commit token separation**

```bash
git add internal/auth internal/controlplane/service.go internal/controlplane/service_test.go
git commit -m "feat: add asymmetric scoped registry tokens"
```

### Task 5: Refactor registry authentication to fail closed

**Files:**
- Create: `internal/registry/authn.go`
- Create: `internal/registry/authn_test.go`
- Modify: `internal/registry/handler.go`
- Modify: `internal/policy/authz.go`
- Modify: `internal/policy/stamps.go`
- Modify: `cmd/registry/main.go`
- Test: `internal/registry/handler_test.go`

**Interfaces:**
- Consumes: `RegistryTokenVerifier.Verify` from Task 4.
- Produces: `Authenticator.Authenticate(ctx, authorization, service, repository string, action auth.Action) (auth.Principal, error)`.

- [ ] **Step 1: Write failing raw-bearer and scope tests**

```go
func TestPushRejectsUnsignedRoleBearer(t *testing.T) {
    h := newSignedTokenTestHandler(t)
    req := httptest.NewRequest(http.MethodPost, "/v2/backend/api/blobs/uploads/", nil)
    req.Host = "alice.example.test"
    req.Header.Set("Authorization", "Bearer role:write")
    rec := httptest.NewRecorder()
    h.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized { t.Fatalf("status=%d", rec.Code) }
}
```

Add wrong-service, wrong-repository, pull-only, expired, and session-token cases.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `go test ./internal/registry -run 'TestPushRejects|TestPullRejects' -count=1 -v`

Expected: FAIL because raw bearer values are accepted.

- [ ] **Step 3: Implement the authentication boundary**

```go
type Authenticator interface {
    Authenticate(ctx context.Context, authorization, service, repository string, action auth.Action) (auth.Principal, error)
}
```

Parse the Bearer scheme once. Return `auth.ErrMissingToken` or `auth.ErrInvalidToken`; never return raw credentials.

- [ ] **Step 4: Pass verified principals into policy authorization**

Change policy interfaces to consume `auth.Principal` instead of authorization headers or free-form actor strings:

```go
type PullAuthorizer interface {
    Authorize(ctx context.Context, registry resolve.RegistryIdentity, repo string, principal auth.Principal) (bool, error)
}

type PushAuthorizer interface {
    Authorize(ctx context.Context, registry resolve.RegistryIdentity, repo string, principal auth.Principal) (batchID string, allowed bool, err error)
}
```

Anonymous pull uses `Principal{Subject:"anonymous"}` only after the auth policy explicitly allows it.

- [ ] **Step 5: Require verification-key configuration**

Replace optional `REGISTRY_TOKEN_SECRET` with registry public-key configuration (`REGISTRY_TOKEN_PUBLIC_KEYS_FILE`, issuer, and audience). Production startup fails when absent. Tests may inject in-memory keys.

- [ ] **Step 6: Replace raw-bearer fixtures with signed tokens**

Update `internal/registry/handler_test.go` so every authenticated request uses a token issued by the test key pair.

- [ ] **Step 7: Run registry and policy tests**

Run:

```bash
go test -race -count=1 ./internal/auth ./internal/policy ./internal/registry
go vet ./internal/auth ./internal/policy ./internal/registry ./cmd/registry
```

Expected: PASS; unsigned bearer regression remains rejected.

- [ ] **Step 8: Commit fail-closed registry auth**

```bash
git add internal/registry internal/policy cmd/registry/main.go
git commit -m "fix: enforce verified registry token scopes"
```

### Task 6: Encrypt feed-owner keys and support rotation

**Files:**
- Create: `internal/controlplane/keycrypto.go`
- Create: `internal/controlplane/keycrypto_test.go`
- Modify: `internal/controlplane/store.go`
- Modify: `internal/controlplane/service.go`
- Modify: `internal/controlplane/migrations.go`
- Modify: `cmd/controlplane/main.go`

**Interfaces:**
- Produces: `FeedKeyCipher.Encrypt`, `FeedKeyCipher.Decrypt`, `EncryptedFeedKey`, and key-version configuration.
- Consumed by Task 9 feed signer.

- [ ] **Step 1: Write failing encryption tests**

Test round trip, random nonce uniqueness, wrong master key, tampered ciphertext, unsupported key version, and absence of plaintext in database rows.

```go
func TestFeedKeyCipherRejectsTampering(t *testing.T) {
    c := newTestFeedKeyCipher(t)
    enc, err := c.Encrypt([]byte("private-key"))
    if err != nil { t.Fatal(err) }
    enc.Ciphertext[0] ^= 0xff
    if _, err := c.Decrypt(enc); !errors.Is(err, ErrKeyDecrypt) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Run tests and verify failure**

Run: `go test ./internal/controlplane -run TestFeedKeyCipher -count=1 -v`

Expected: FAIL because `FeedKeyCipher` does not exist.

- [ ] **Step 3: Implement AES-256-GCM envelope encryption**

```go
type EncryptedFeedKey struct {
    Ciphertext []byte
    Nonce      []byte
    KeyVersion int
}

type FeedKeyCipher struct {
    keys    map[int][]byte
    current int
}

func (c *FeedKeyCipher) Encrypt(plaintext []byte) (EncryptedFeedKey, error)
func (c *FeedKeyCipher) Decrypt(value EncryptedFeedKey) ([]byte, error)
```

Use 32-byte master keys, random GCM nonces, and associated data containing registry ID and feed-owner address. Zero temporary plaintext byte slices after signing where practical.

- [ ] **Step 4: Migrate registry key columns**

Add `feed_key_ciphertext`, `feed_key_nonce`, and `feed_key_version`. Migration reads the legacy plaintext only when the operator explicitly supplies `CONTROLPLANE_MIGRATE_LEGACY_KEYS=true`; after successful encrypted write, clear the legacy value in the same transaction.

- [ ] **Step 5: Require master-key file configuration**

Load versioned keys from a root-readable secret file, not command-line flags or logs. Fail startup if the current key is missing or malformed.

- [ ] **Step 6: Add rotation operation**

Implement `Service.ReencryptFeedKeys(ctx, fromVersion, toVersion int) error` using one registry transaction at a time. It re-encrypts without changing the feed owner.

- [ ] **Step 7: Run migration and encryption tests**

Run: `go test -race -count=1 ./internal/controlplane -run 'TestFeedKey|TestUpgradeCurrentSchema' -v`

Expected: PASS and database scans contain no plaintext test key.

- [ ] **Step 8: Commit key encryption**

```bash
git add internal/controlplane cmd/controlplane/main.go
git commit -m "feat: encrypt registry feed keys at rest"
```

### Task 7: Make invites one-way, recipient-bound, revocable, and single-use

**Files:**
- Create: `internal/controlplane/invites.go`
- Create: `internal/controlplane/invites_test.go`
- Modify: `internal/controlplane/store.go`
- Modify: `internal/controlplane/service.go`
- Modify: `internal/controlplane/ui.go`
- Modify: `internal/controlplane/http.go`

**Interfaces:**
- Produces: `NewInviteToken() (raw string, digest []byte, error)`, `DigestInviteToken(raw string) []byte`, `AcceptInvite(ctx, rawToken string, user User) (Invite, error)`, and `RevokeInvite`.

- [ ] **Step 1: Write failing lifecycle tests**

Cover intended recipient, wrong recipient, expired token, revoked token, second acceptance, malformed token, and inability to reconstruct raw token from stored digest.

- [ ] **Step 2: Run tests and verify failure**

Run: `go test ./internal/controlplane -run 'TestInvite' -count=1 -v`

Expected: FAIL for recipient binding, revocation, and reversible stored token.

- [ ] **Step 3: Implement cryptographic token digests**

```go
func NewInviteToken() (string, []byte, error) {
    raw := make([]byte, 24)
    if _, err := rand.Read(raw); err != nil { return "", nil, err }
    token := base64.RawURLEncoding.EncodeToString(raw)
    sum := sha256.Sum256([]byte(token))
    return token, sum[:], nil
}
```

Store the digest as BLOB or lowercase hex but never decode it into the token.

- [ ] **Step 4: Bind acceptance to normalized email**

Load the accepting `User` in the same transaction. Compare normalized addresses. Update invite status and insert membership atomically. Return the same successful result only to the same user on safe retry.

- [ ] **Step 5: Add revocation and one-time display**

Only the create-invite response and immediate UI success page receive the raw token. Listing pending invites shows recipient, permissions, state, and expiry but no reusable link reconstructed from storage.

- [ ] **Step 6: Run invite and UI tests**

Run: `go test -race -count=1 ./internal/controlplane -run 'TestInvite|TestUIInvite' -v`

Expected: PASS.

- [ ] **Step 7: Commit invite hardening**

```bash
git add internal/controlplane
git commit -m "fix: secure collaborator invite lifecycle"
```

### Task 8: Add browser security, rate limits, and production config validation

**Files:**
- Create: `internal/controlplane/security.go`
- Create: `internal/controlplane/security_test.go`
- Modify: `internal/controlplane/http.go`
- Modify: `internal/controlplane/ui.go`
- Modify: `cmd/controlplane/main.go`
- Create: `internal/config/controlplane.go`
- Create: `internal/config/controlplane_test.go`

**Interfaces:**
- Produces: `ControlPlaneConfig.Validate() error`, CSRF middleware, login/token limiter, and secure cookie builder.

- [ ] **Step 1: Write failing production-config tests**

Test rejection of `dev-secret-change-me`, missing external URL, insecure cookies for HTTPS external URL, missing registry signing key, missing master-key file, and invalid trusted proxy settings.

- [ ] **Step 2: Write failing browser-security tests**

Assert mutation without CSRF token returns 403, secure deployments set `Secure`, login errors do not reveal whether email exists, and repeated login/token requests receive 429.

- [ ] **Step 3: Run tests and verify failure**

Run: `go test ./internal/config ./internal/controlplane -run 'TestControlPlaneConfig|TestCSRF|TestRateLimit|TestSessionCookie' -count=1 -v`

Expected: FAIL because the controls do not exist.

- [ ] **Step 4: Implement config validation and secure cookies**

Use explicit environment mode. In production, reject defaults and require secure external URLs. Build cookies with `HttpOnly`, `Secure`, `SameSite=Lax`, bounded `MaxAge`, and explicit path.

- [ ] **Step 5: Implement CSRF and bounded rate limiting**

Use synchronizer tokens stored in the authenticated session context. Implement a bounded in-memory token bucket keyed by normalized email plus client IP for login and by client IP for token issuance; expose counters for later metrics.

- [ ] **Step 6: Return generic credential failures**

Log correlated internal causes, but return one public login failure message and constant HTTP status.

- [ ] **Step 7: Run security tests**

Run: `go test -race -count=1 ./internal/config ./internal/controlplane`

Expected: PASS.

- [ ] **Step 8: Commit browser and configuration security**

```bash
git add internal/config internal/controlplane cmd/controlplane/main.go
git commit -m "feat: harden control-plane HTTP security"
```

### Task 9: Add transactional provisioning outbox and policy bootstrap

**Files:**
- Create: `internal/controlplane/outbox.go`
- Create: `internal/controlplane/outbox_test.go`
- Create: `internal/controlplane/reconciler.go`
- Create: `internal/controlplane/reconciler_test.go`
- Modify: `internal/controlplane/store.go`
- Modify: `internal/controlplane/service.go`
- Modify: `internal/controlplane/publisher.go`
- Modify: `internal/controlplane/migrations.go`

**Interfaces:**
- Produces: `PublicationJob`, `OutboxStore`, `Reconciler.RunOnce(ctx)`, and registry provisioning states `provisioning|ready|failed`.
- Consumed by Task 10 internal signing and Task 23 Compose readiness.

- [ ] **Step 1: Write failing partial-publication tests**

Simulate auth policy success followed by stamp policy failure. Assert registry remains `provisioning`, both jobs are durable, retry does not duplicate completed work, and registry becomes `ready` only after feed read-back.

- [ ] **Step 2: Run tests and verify failure**

Run: `go test ./internal/controlplane -run 'TestProvisioning|TestReconciler' -count=1 -v`

Expected: FAIL because publication is currently inline and non-atomic.

- [ ] **Step 3: Add outbox schema and store methods**

```go
type PublicationJob struct {
    ID          string
    RegistryID  int64
    Kind        string
    PayloadJSON []byte
    State       string
    Attempts    int
    NextAttempt time.Time
    LastError   string
}
```

Add claim, complete, fail-with-backoff, and list-stale operations using short transactions.

- [ ] **Step 4: Make registry creation transactional locally**

One transaction inserts registry in `provisioning`, owner membership, and auth/stamp bootstrap jobs. Return provisioning state rather than pretending external publication completed synchronously.

- [ ] **Step 5: Implement idempotent reconciliation**

Build policy documents deterministically, upload, update feeds, then read back and validate. Persist completed object/feed references so retry does not create a second logical operation.

- [ ] **Step 6: Wire a bounded worker lifecycle**

The control plane runs a reconciler loop with context cancellation, bounded batch size, exponential backoff, and graceful shutdown. Expose `RunOnce` for deterministic tests.

- [ ] **Step 7: Run failure-injection tests**

Run: `go test -race -count=1 ./internal/controlplane -run 'TestProvisioning|TestReconciler|TestService.*Registry' -v`

Expected: PASS.

- [ ] **Step 8: Commit provisioning consistency**

```bash
git add internal/controlplane
git commit -m "feat: reconcile registry policy provisioning"
```

### Phase 1 gate

- [ ] Run:

```bash
bash scripts/security/check-repository-secrets.sh
go test -race -count=1 ./internal/auth ./internal/config ./internal/controlplane ./internal/policy ./internal/registry
go vet ./...
go mod tidy -diff
git diff --check
```

Expected: all pass; public responses contain no secret fields; raw bearer and wrong-scope cases fail closed; invite and encrypted-key suites pass; registry provisioning survives injected Bee failures.

- [ ] Record the evidence in `docs/evidence/phase-1-security.md` with command, commit SHA, date, and test output summary.

- [ ] Commit the gate evidence:

```bash
git add docs/evidence/phase-1-security.md
git commit -m "docs: record phase 1 security gate"
```

## Phase 2 — Correct Bee publication

### Task 10: Add constrained internal feed-signing service

**Files:**
- Create: `internal/controlplane/feed_signer.go`
- Create: `internal/controlplane/feed_signer_test.go`
- Create: `internal/controlplane/internal_http.go`
- Create: `internal/controlplane/internal_http_test.go`
- Create: `internal/publish/commit.go`
- Create: `internal/publish/commit_test.go`
- Modify: `cmd/controlplane/main.go`
- Modify: `cmd/registry/main.go`

**Interfaces:**
- Consumes: encrypted key cipher from Task 6 and registry records.
- Produces: internal `POST /internal/v1/feed-updates`, `FeedCommitRequest`, `FeedCommitResult`, and `ControlPlaneCommitter.Commit`.

- [ ] **Step 1: Write failing constraint tests**

Test valid repo topic, unknown registry, owner mismatch, non-deterministic topic, auth-policy topic requested by registry data plane, disallowed batch, expected-generation mismatch, invalid reference, duplicate operation ID, and invalid internal service credential.

- [ ] **Step 2: Run tests and verify failure**

Run: `go test ./internal/controlplane ./internal/publish -run 'TestFeedSigner|TestInternalFeed|TestControlPlaneCommitter' -count=1 -v`

Expected: FAIL because signer API and client do not exist.

- [ ] **Step 3: Define request and result types**

```go
type FeedCommitRequest struct {
    OperationID       string `json:"operationID"`
    RegistryID        int64  `json:"registryID"`
    Owner             string `json:"owner"`
    Topic             string `json:"topic"`
    Reference         string `json:"reference"`
    BatchID           string `json:"batchID"`
    ExpectedGeneration int64 `json:"expectedGeneration"`
}

type FeedCommitResult struct {
    OperationID string `json:"operationID"`
    Feed        string `json:"feed"`
    Reference   string `json:"reference"`
}
```

- [ ] **Step 4: Implement constrained signing**

Authenticate the registry service with a dedicated secret mounted from file and compare using `subtle.ConstantTimeCompare`. Resolve registry by ID, compare normalized owner, derive the only allowed repo topic from the supplied repository identity, resolve current stamp policy, verify the batch, decrypt the feed key, call the Bee updater, and zero plaintext bytes.

- [ ] **Step 5: Implement idempotency storage**

Store operation ID, normalized request hash, and result. Repeating an identical operation returns the stored result; reusing an operation ID with different input returns conflict.

- [ ] **Step 6: Implement the registry client**

Use an HTTP client with bounded timeout, context propagation, internal service credential, stable error decoding, and no key material.

- [ ] **Step 7: Run internal signing tests**

Run: `go test -race -count=1 ./internal/controlplane ./internal/publish -run 'TestFeedSigner|TestInternalFeed|TestControlPlaneCommitter' -v`

Expected: PASS.

- [ ] **Step 8: Commit the signing boundary**

```bash
git add internal/controlplane internal/publish cmd/controlplane/main.go cmd/registry/main.go
git commit -m "feat: add constrained control-plane feed signer"
```

### Task 11: Correct Bee postage and feed payload handling

**Files:**
- Modify: `internal/swarm/bee.go`
- Modify: `internal/swarm/bee_test.go`
- Create: `internal/swarm/feed.go`
- Create: `internal/swarm/feed_test.go`

**Interfaces:**
- Produces: `BeeSequenceFeedUpdater.Update(ctx, FeedUpdate) error`, where `FeedUpdate` carries `Feed`, `Reference`, and `BatchID` explicitly.

- [ ] **Step 1: Strengthen the existing fake-Bee test first**

Assert `/chunks` and `/soc` both carry the expected `Swarm-Postage-Batch-Id`, payload contains the binary 32-byte reference rather than ASCII hex, next sequence index is respected, and owner mismatch fails before network calls.

```go
type FeedUpdate struct {
    Feed      string
    Reference string
    BatchID   string
}
```

- [ ] **Step 2: Run the focused test and verify failure**

Run: `go test ./internal/swarm -run TestBeeSequenceFeedUpdater -count=1 -v`

Expected: FAIL because current code passes the content reference as the batch ID.

- [ ] **Step 3: Implement explicit batch propagation**

Decode the immutable reference from hex to bytes before wrapping it. Reject empty or malformed 32-byte references and batch IDs before network calls. Pass `BatchID` unchanged to `/chunks` and `/soc`.

- [ ] **Step 4: Add feed read-back helper**

```go
type FeedValue struct {
    Reference string
    Index     string
}

func (c *BeeClient) ReadFeed(ctx context.Context, feed string) (FeedValue, error)
```

Parse the Bee feed response and required headers, returning a normalized immutable reference.

- [ ] **Step 5: Run Swarm tests**

Run: `go test -race -count=1 ./internal/swarm`

Expected: PASS with exact header and payload assertions.

- [ ] **Step 6: Commit Bee feed correctness**

```bash
git add internal/swarm
git commit -m "fix: publish Bee feeds with explicit postage"
```

### Task 12: Parse OCI manifests and indexes before upload

**Files:**
- Create: `internal/publish/manifest.go`
- Create: `internal/publish/manifest_test.go`
- Modify: `internal/publish/publisher.go`
- Test: `internal/publish/manifest_test.go`

**Interfaces:**
- Produces: `ParseArtifact(mediaType string, body []byte) (Artifact, error)` and `Artifact.References() []Descriptor`.

- [ ] **Step 1: Write table-driven failing tests**

Cover OCI manifest, Docker schema-2 manifest, OCI index, Docker manifest list, malformed JSON, wrong schema version, missing config, invalid digest, negative size, duplicate descriptor digest with conflicting size, unsupported media type, and body digest mismatch.

- [ ] **Step 2: Run tests and verify failure**

Run: `go test ./internal/publish -run TestParseArtifact -count=1 -v`

Expected: FAIL because structured artifact parsing does not exist.

- [ ] **Step 3: Implement strict descriptors**

```go
type Descriptor struct {
    MediaType string            `json:"mediaType"`
    Digest    string            `json:"digest"`
    Size      int64             `json:"size"`
    Platform  *Platform         `json:"platform,omitempty"`
}

type Artifact struct {
    MediaType  string
    Kind       ArtifactKind
    Config     *Descriptor
    Layers     []Descriptor
    Manifests  []Descriptor
}
```

Validate canonical `sha256:<64 lowercase hex>` digests and non-negative sizes. Return typed validation errors.

- [ ] **Step 4: Move validation before `Objects.Put`**

Publisher validates and resolves every required reference before uploading the manifest or state. Invalid input produces zero object or feed writes; assert with a counting fake.

- [ ] **Step 5: Run publisher tests**

Run: `go test -race -count=1 ./internal/publish`

Expected: PASS, including “no writes on invalid manifest.”

- [ ] **Step 6: Commit artifact validation**

```bash
git add internal/publish
git commit -m "feat: validate OCI artifacts before publication"
```

### Task 13: Implement generation-zero first publication and referenced-blob selection

**Files:**
- Modify: `internal/resolve/registry.go`
- Modify: `internal/publish/publisher.go`
- Modify: `internal/registry/handler.go`
- Create: `internal/registry/first_push_test.go`
- Modify: `internal/registry/handler_test.go`

**Interfaces:**
- Consumes: `Artifact.References` from Task 12 and `ControlPlaneCommitter` from Task 10.
- Produces: `ResolveRepoStateOptional` and first-publish behavior.

- [ ] **Step 1: Write a failing unseeded first-push test**

Create registry, auth, and stamp feeds only. Upload referenced blobs and PUT a manifest. Assert 201, generation one, expected tag, exactly referenced blobs, and successful pull.

- [ ] **Step 2: Write a failing unrelated-staged-blob test**

Stage blobs A and B, submit a manifest referencing A, and assert state contains A but not B; B remains staged.

- [ ] **Step 3: Run tests and verify failure**

Run: `go test ./internal/registry -run 'TestFirstPush|TestManifestPublishesOnlyReferencedBlobs' -count=1 -v`

Expected: FAIL because repo state must be pre-seeded and all staged blobs are currently copied.

- [ ] **Step 4: Add optional repo-state resolution**

```go
func (r RegistryResolver) ResolveRepoStateOptional(ctx context.Context, registry RegistryIdentity, repo string) (spec.RepoStateDocument, bool, error)
```

Only a confirmed missing feed returns `(empty,false,nil)`. Bee/network/decode failures remain errors.

- [ ] **Step 5: Build generation zero in the manifest path**

For authorized manifest PUT only, construct:

```go
spec.RepoStateDocument{
    Version: 1, Repo: repo, Generation: 0,
    Tags: map[string]string{},
    Manifests: map[string]spec.ManifestDescriptor{},
    Blobs: map[string]spec.BlobDescriptor{},
}
```

- [ ] **Step 6: Select staged blobs by parsed references**

Create a digest set from `Artifact.References`. Require each reference in current state or the actor’s staged set. Pass only referenced staged descriptors to the builder.

- [ ] **Step 7: Run first-push tests**

Run: `go test -race -count=1 ./internal/resolve ./internal/publish ./internal/registry -run 'TestFirstPush|TestManifestPublishesOnlyReferencedBlobs|TestPushBlobAndPublishManifest' -v`

Expected: PASS.

- [ ] **Step 8: Commit first-repository semantics**

```bash
git add internal/resolve internal/publish internal/registry
git commit -m "feat: publish repositories from generation zero"
```

### Task 14: Add read-after-write verification, stable errors, and operation idempotency

**Files:**
- Create: `internal/registry/errors.go`
- Create: `internal/registry/errors_test.go`
- Modify: `internal/publish/publisher.go`
- Modify: `internal/registry/handler.go`
- Modify: `internal/publish/commit.go`
- Test: `internal/registry/first_push_test.go`

**Interfaces:**
- Produces: typed `ValidationError`, `ConflictError`, `DependencyError`, `IntegrityError`; `VerifyPublishedState`.

- [ ] **Step 1: Write failing read-back tests**

Simulate signer success followed by stale feed read, wrong state reference, wrong generation, wrong repo, wrong tag, and correct state. Assert only correct read-back returns 201.

- [ ] **Step 2: Write failing error-mapping tests**

Assert authentication→401, policy denial→403, digest/manifest/range validation→4xx Distribution code, generation conflict→409, Bee/signing dependency→503, and integrity mismatch→502.

- [ ] **Step 3: Run tests and verify failure**

Run: `go test ./internal/registry -run 'TestPublishReadBack|TestErrorMapping' -count=1 -v`

Expected: FAIL because every publisher error is currently mapped to 400 and no read-back gate exists.

- [ ] **Step 4: Implement typed errors and mapping**

Use `errors.As` in one HTTP error writer. Public messages remain generic for dependency/internal errors; logs retain correlated causes.

- [ ] **Step 5: Implement read-after-write verification**

Resolve the repository feed after commit, load state, and verify owner-derived feed, repo, generation, immutable reference, tag, and manifest digest before returning success.

- [ ] **Step 6: Thread operation IDs**

Generate or accept a stable operation ID at manifest PUT, pass it to the control-plane commit request, and return the prior verified result on safe retry.

- [ ] **Step 7: Run registry tests**

Run: `go test -race -count=1 ./internal/publish ./internal/registry`

Expected: PASS.

- [ ] **Step 8: Commit verified publication**

```bash
git add internal/publish internal/registry
git commit -m "feat: verify and classify repository publication"
```

### Phase 2 gate

- [ ] Start a pinned Bee node in an integration fixture and run:

```bash
go test -tags=integration -count=1 ./internal/swarm ./internal/controlplane ./internal/registry
```

Expected: registry bootstrap publishes readable auth and stamp policies; first push publishes generation one; pull verifies manifest and blob digests; wrong/depleted batch tests fail with dependency errors.

- [ ] Record Bee version, image digest, commands, and results in `docs/evidence/phase-2-bee-publication.md`.

- [ ] Commit the gate evidence:

```bash
git add docs/evidence/phase-2-bee-publication.md
git commit -m "docs: record phase 2 Bee publication gate"
```

## Phase 3 — Durable staging and concurrency

### Task 15: Build filesystem spool and SQLite upload metadata

**Files:**
- Create: `internal/staging/sqlite.go`
- Create: `internal/staging/sqlite_test.go`
- Create: `internal/staging/spool.go`
- Create: `internal/staging/spool_test.go`
- Create: `internal/staging/service.go`
- Create: `internal/staging/service_test.go`
- Modify: `internal/staging/store.go`

**Interfaces:**
- Produces: `staging.Service` with streaming methods and durable `Session` state.

```go
type Service interface {
    Create(ctx context.Context, repo, actor string, ttl time.Duration) (Session, error)
    Status(ctx context.Context, id, repo, actor string) (Session, error)
    Append(ctx context.Context, id, repo, actor string, expectedOffset int64, src io.Reader, maxBytes int64) (Session, error)
    Open(ctx context.Context, id, repo, actor string) (io.ReadCloser, Session, error)
    MarkFinalized(ctx context.Context, id, digest, beeRef, mediaType string, size int64) error
    ListFinalized(ctx context.Context, repo, actor string) ([]spec.StagedBlob, error)
    Delete(ctx context.Context, id, repo, actor string) error
    Expire(ctx context.Context, now time.Time, limit int) (int, error)
}
```

- [ ] **Step 1: Write failing spool path and permission tests**

Assert generated paths stay under the configured root, IDs with separators are rejected, files use `0600`, directories use `0700`, and existing symlinks are not followed.

- [ ] **Step 2: Write failing restart tests**

Create, append, close the service, reopen against the same database/root, verify offset and bytes, then finalize.

- [ ] **Step 3: Run tests and verify failure**

Run: `go test ./internal/staging -run 'TestSpool|TestSQLite|TestRestart' -count=1 -v`

Expected: FAIL because durable staging does not exist.

- [ ] **Step 4: Implement staging migrations and metadata transactions**

Create upload-session and staged-blob tables with ownership, state, expiry, offsets, paths, references, and unique operation constraints. Enable foreign keys and evaluate WAL mode in tests.

- [ ] **Step 5: Implement safe spool operations**

Generate server IDs, open files without path traversal, append by streaming `io.CopyBuffer`, fsync before committing the new offset, and keep database/file state recoverable after interruption.

- [ ] **Step 6: Implement expiration and idempotent deletion**

Expired sessions return `ErrExpired`. Cleanup removes metadata and files safely even when one side is already absent.

- [ ] **Step 7: Run durable staging tests**

Run: `go test -race -count=1 ./internal/staging`

Expected: PASS.

- [ ] **Step 8: Commit durable staging storage**

```bash
git add internal/staging
git commit -m "feat: persist upload staging to disk and SQLite"
```

### Task 16: Stream registry uploads with offsets, ranges, and quotas

**Files:**
- Modify: `internal/registry/handler.go`
- Create: `internal/registry/upload.go`
- Create: `internal/registry/upload_test.go`
- Create: `internal/config/registry.go`
- Create: `internal/config/registry_test.go`
- Modify: `cmd/registry/main.go`

**Interfaces:**
- Consumes: durable `staging.Service` from Task 15.
- Produces: bounded upload HTTP path and `RegistryConfig` quota fields.

- [ ] **Step 1: Write failing range and quota tests**

Test correct append, stale offset, malformed `Content-Range`, oversized chunk, per-upload limit, total-staging limit, expired session, actor mismatch, repo mismatch, and cancellation.

- [ ] **Step 2: Write a bounded-memory test**

Use a generated reader larger than the configured in-memory buffer and assert handler completes without `io.ReadAll`; expose the buffer factory or copy function for deterministic instrumentation.

- [ ] **Step 3: Run tests and verify failure**

Run: `go test ./internal/registry -run 'TestUpload' -count=1 -v`

Expected: FAIL because the handler ignores ranges and uses unrestricted `io.ReadAll`.

- [ ] **Step 4: Implement registry staging configuration**

```go
type RegistryConfig struct {
    StagingRoot          string
    StagingDB            string
    UploadTTL            time.Duration
    MaxUploadBytes       int64
    MaxRepositoryBytes   int64
    MaxTotalStagingBytes int64
    StreamBufferBytes    int
}
```

Validate positive limits, safe paths, and buffer bounds at startup.

- [ ] **Step 5: Replace upload `io.ReadAll` calls**

Pass request bodies directly to `staging.Service.Append`. Validate expected offset before writing and set accurate `Range`, `Location`, and `Docker-Upload-UUID` headers.

- [ ] **Step 6: Stream digest verification and Bee upload**

Open the staged file, hash it with `io.TeeReader` or a separate streaming pass, then stream to an object uploader interface that accepts `io.Reader` and size. Do not load the full blob into memory.

- [ ] **Step 7: Run upload and race tests**

Run: `go test -race -count=1 ./internal/staging ./internal/registry -run 'TestUpload|TestRestart' -v`

Expected: PASS.

- [ ] **Step 8: Commit streaming uploads**

```bash
git add internal/config internal/registry cmd/registry/main.go
git commit -m "feat: stream and bound registry uploads"
```

### Task 17: Serialize repository publication and handle generation conflicts

**Files:**
- Create: `internal/publish/locks.go`
- Create: `internal/publish/locks_test.go`
- Modify: `internal/publish/publisher.go`
- Modify: `internal/registry/handler.go`
- Create: `internal/registry/concurrency_test.go`

**Interfaces:**
- Produces: `RepositoryLocker.WithLock(ctx, owner, repo string, fn func(context.Context) error) error`.

- [ ] **Step 1: Write failing keyed-lock lifecycle tests**

Assert same owner/repo serializes, different repos proceed concurrently, canceled waiters return promptly, and unused key entries are removed.

- [ ] **Step 2: Write failing simultaneous-push test**

Start two manifest PUTs for different tags against one repo. Delay the first commit to force overlap. Assert both successful tags exist and generations are monotonic; no race detector findings.

- [ ] **Step 3: Run tests and verify failure**

Run: `go test -race ./internal/publish ./internal/registry -run 'TestRepositoryLocker|TestConcurrentPushes' -count=1 -v`

Expected: FAIL or final state loses one update.

- [ ] **Step 4: Implement keyed serialization**

Use a mutex-protected map of reference-counted lock entries. Acquire context-aware admission before the per-key mutex; release and remove entries safely.

- [ ] **Step 5: Re-read state inside the lock**

Move repository-state resolution into the locked publication callback. Compare expected generation immediately before commit. On conflict, rebuild once from current state when inputs remain valid; otherwise return `ConflictError`.

- [ ] **Step 6: Add crash-point idempotency tests**

Inject failure after object upload, after signer request dispatch, after feed update but before response, and after verification but before staging cleanup. Retry with the same operation ID and assert one feed advancement.

- [ ] **Step 7: Run concurrency stress tests**

Run:

```bash
go test -race -count=20 ./internal/publish ./internal/registry -run 'TestRepositoryLocker|TestConcurrentPushes|TestPublishRetry'
```

Expected: PASS with both tags preserved.

- [ ] **Step 8: Commit concurrency safety**

```bash
git add internal/publish internal/registry
git commit -m "fix: serialize repository publication safely"
```

### Task 18: Add staging cleanup and eligible Bee unpin behavior

**Files:**
- Create: `internal/staging/cleanup.go`
- Create: `internal/staging/cleanup_test.go`
- Modify: `internal/swarm/bee.go`
- Modify: `internal/swarm/bee_test.go`
- Modify: `cmd/registry/main.go`

**Interfaces:**
- Produces: `Cleanup.RunOnce(ctx, now, limit)` and `BeeObjectStore.Unpin(ctx, ref string) error`.

- [ ] **Step 1: Write failing cleanup tests**

Cover expired active session, expired finalized blob, committed referenced blob, missing file, already-unpinned reference, Bee unpin failure, and bounded cleanup batches.

- [ ] **Step 2: Run tests and verify failure**

Run: `go test ./internal/staging ./internal/swarm -run 'TestCleanup|TestBeeObjectStoreUnpin' -count=1 -v`

Expected: FAIL because cleanup/unpin operations do not exist.

- [ ] **Step 3: Implement explicit cleanup states**

Transition metadata through `expiring` before side effects. Never unpin a blob known to be published. Retry failed file/unpin cleanup without losing metadata.

- [ ] **Step 4: Implement Bee unpin**

Call the pinned-content deletion endpoint supported by the pinned Bee version. Treat not-found as idempotent success and classify other statuses.

- [ ] **Step 5: Wire bounded periodic cleanup**

Run with context cancellation and a configurable interval. Emit counts for examined, expired, removed, unpinned, and failed items.

- [ ] **Step 6: Run cleanup tests**

Run: `go test -race -count=1 ./internal/staging ./internal/swarm -run 'TestCleanup|TestBeeObjectStoreUnpin' -v`

Expected: PASS.

- [ ] **Step 7: Commit cleanup lifecycle**

```bash
git add internal/staging internal/swarm cmd/registry/main.go
git commit -m "feat: clean expired staging safely"
```

### Phase 3 gate

- [ ] Run restart, quota, expiry, concurrency, and crash-recovery suites:

```bash
go test -race -count=10 ./internal/staging ./internal/publish ./internal/registry
```

- [ ] Run an integration process test that pauses a real HTTP upload, stops the registry, restarts with the same volumes, resumes at the reported offset, finalizes, publishes, and pulls.

- [ ] Record commands and results in `docs/evidence/phase-3-durability.md` and commit:

```bash
git add docs/evidence/phase-3-durability.md
git commit -m "docs: record phase 3 durability gate"
```

## Phase 4 — Docker/OCI compatibility contract

### Task 19: Add OCI index publication and strict descriptor validation

**Files:**
- Modify: `internal/publish/manifest.go`
- Modify: `internal/publish/manifest_test.go`
- Modify: `internal/spec/documents.go`
- Modify: `internal/registry/handler.go`
- Create: `internal/registry/index_test.go`

**Interfaces:**
- Extends: `Artifact` from Task 12 to support index references and recursive availability checks.

- [ ] **Step 1: Write failing index tests**

Test valid two-platform OCI index, Docker manifest list, missing child manifest, wrong child size, unsupported nested media type, malformed platform, and index pull by tag/digest.

- [ ] **Step 2: Run tests and verify failure**

Run: `go test ./internal/publish ./internal/registry -run 'Test.*Index|Test.*ManifestList' -count=1 -v`

Expected: FAIL until index references are stored and validated.

- [ ] **Step 3: Extend repository state for artifact descriptors**

Represent both image manifests and indexes in the manifest descriptor map with media type and size. Validate referenced child manifests are in current state or staged artifact set before publishing the index.

- [ ] **Step 4: Add media negotiation**

Parse `Accept` values and return a supported representation or a documented manifest error. Preserve exact stored media type on GET/HEAD.

- [ ] **Step 5: Run index tests**

Run: `go test -race -count=1 ./internal/publish ./internal/spec ./internal/registry -run 'Test.*Index|Test.*ManifestList|TestPullManifest' -v`

Expected: PASS.

- [ ] **Step 6: Commit multi-platform support**

```bash
git add internal/publish internal/spec internal/registry
git commit -m "feat: support OCI image indexes"
```

### Task 20: Enforce pull integrity and normalize registry hosts

**Files:**
- Modify: `internal/registry/handler.go`
- Create: `internal/registry/pull_test.go`
- Modify: `internal/resolve/registry.go`
- Create: `internal/resolve/host.go`
- Create: `internal/resolve/host_test.go`

**Interfaces:**
- Produces: `NormalizeRegistryHost(raw string) (string, error)` and streaming integrity verification.

- [ ] **Step 1: Write failing host table tests**

Cover lowercase hostname, hostname with port, bracketed IPv6 with port, trailing dot, malformed host, and configured static host lookup.

- [ ] **Step 2: Write failing pull-integrity tests**

Return wrong blob bytes, wrong manifest bytes, descriptor size mismatch, and backend read error. Assert no corrupt content is returned as success and integrity failures are classified distinctly.

- [ ] **Step 3: Run tests and verify failure**

Run: `go test ./internal/resolve ./internal/registry -run 'TestNormalizeRegistryHost|TestPullIntegrity' -count=1 -v`

Expected: FAIL because static resolution is exact/raw and pulls trust returned bytes.

- [ ] **Step 4: Normalize once at the request boundary**

Use normalized host for registry resolution and token service comparison. Preserve externally configured service name rules in one function.

- [ ] **Step 5: Verify pulled content**

Stream through SHA-256 and verify descriptor size. Because HTTP status cannot change after bytes are sent, verify small manifests before writing and define blob integrity strategy: either pre-verify from Bee into bounded spool/cache or require Bee reference/content-address guarantees plus descriptor verification before response. Record the chosen strategy in `docs/compatibility.md` and tests.

- [ ] **Step 6: Run pull and host tests**

Run: `go test -race -count=1 ./internal/resolve ./internal/registry -run 'TestNormalizeRegistryHost|TestPullIntegrity|TestManifestAndBlobPull' -v`

Expected: PASS.

- [ ] **Step 7: Commit host and integrity handling**

```bash
git add internal/resolve internal/registry
git commit -m "fix: normalize hosts and verify pull integrity"
```

### Task 21: Publish and enforce the compatibility matrix

**Files:**
- Create: `docs/compatibility.md`
- Create: `internal/registry/conformance_test.go`
- Modify: `README.md`
- Modify: `internal/registry/handler.go`

**Interfaces:**
- Produces: machine-readable conformance table in tests and user-facing compatibility documentation.

- [ ] **Step 1: Write endpoint conformance tests**

Create a table covering every supported route/method, auth requirement, expected success status, unsupported method status, and Distribution error code. Include deferred catalog, delete, and mount routes.

- [ ] **Step 2: Run tests and verify current mismatches**

Run: `go test ./internal/registry -run TestDistributionConformanceMatrix -count=1 -v`

Expected: FAIL for undocumented/ambiguous methods or error codes.

- [ ] **Step 3: Centralize route and method behavior**

Ensure supported methods set correct `Allow`, challenge, digest, location, range, upload UUID, content type, and content length headers. Unsupported operations return explicit documented errors.

- [ ] **Step 4: Write `docs/compatibility.md`**

Include supported endpoints, OCI/Docker media types, Docker/Podman versions, authentication behavior, first-push semantics, known limitations, and deferred operations. Change README wording from broad Registry v2 compatibility to the documented subset.

- [ ] **Step 5: Replace absolute README links**

Convert machine-local `/Users/Alok/...` links to repository-relative links and list all test suites and gate commands.

- [ ] **Step 6: Run documentation and conformance checks**

Run:

```bash
go test -race -count=1 ./internal/registry -run TestDistributionConformanceMatrix -v
python3 - <<'PY'
from pathlib import Path
s=Path('README.md').read_text()
assert '/Users/' not in s
assert 'docs/compatibility.md' in s
PY
```

Expected: PASS.

- [ ] **Step 7: Commit compatibility contract**

```bash
git add README.md docs/compatibility.md internal/registry
git commit -m "docs: define Docker OCI compatibility contract"
```

### Phase 4 gate

- [ ] Run pinned Docker and Podman clients against the real Bee integration stack for anonymous pull, reader pull, writer first push, second tag push, manifest by digest, blob by digest, upload resume, cancellation, and multi-platform index round trip.

- [ ] Record client versions, commands, image digests, and results in `docs/evidence/phase-4-compatibility.md`.

- [ ] Commit evidence:

```bash
git add docs/evidence/phase-4-compatibility.md
git commit -m "docs: record phase 4 compatibility gate"
```

## Phase 5 — Production operations and release

### Task 22: Add bounded server lifecycle and dependency clients

**Files:**
- Create: `internal/server/server.go`
- Create: `internal/server/server_test.go`
- Modify: `cmd/registry/main.go`
- Modify: `cmd/controlplane/main.go`
- Modify: `internal/swarm/bee.go`
- Modify: `internal/resolve/ens.go`

**Interfaces:**
- Produces: `server.Run(ctx, Config, http.Handler) error` and bounded HTTP clients.

- [ ] **Step 1: Write failing lifecycle tests**

Assert configured read-header/read/write/idle timeouts, graceful shutdown on context cancellation, in-flight request grace period, forced close after deadline, and database/worker cleanup callbacks.

- [ ] **Step 2: Write dependency timeout tests**

Use a server that never responds; assert Bee and ENS calls return within configured timeout and preserve `context.DeadlineExceeded` wrapping.

- [ ] **Step 3: Run tests and verify failure**

Run: `go test ./internal/server ./internal/swarm ./internal/resolve -run 'TestServer|Test.*Timeout' -count=1 -v`

Expected: FAIL because binaries use bare `ListenAndServe` and default clients.

- [ ] **Step 4: Implement the server wrapper**

```go
type Config struct {
    Address           string
    ReadHeaderTimeout time.Duration
    ReadTimeout       time.Duration
    WriteTimeout      time.Duration
    IdleTimeout       time.Duration
    ShutdownTimeout   time.Duration
}
```

Run `ListenAndServe` in an errgroup, call `Shutdown` with a fresh timeout context, and return wrapped errors.

- [ ] **Step 5: Construct bounded dependency clients**

Create configured clients once in each command and inject them into Bee/ENS adapters. Do not use `http.DefaultClient` in production wiring.

- [ ] **Step 6: Run lifecycle tests**

Run: `go test -race -count=1 ./internal/server ./internal/swarm ./internal/resolve ./cmd/...`

Expected: PASS.

- [ ] **Step 7: Commit lifecycle hardening**

```bash
git add internal/server internal/swarm internal/resolve cmd
git commit -m "feat: add bounded service lifecycle"
```

### Task 23: Add health, readiness, structured logs, and metrics

**Files:**
- Create: `internal/observability/metrics.go`
- Create: `internal/observability/metrics_test.go`
- Create: `internal/registry/health.go`
- Create: `internal/registry/health_test.go`
- Create: `internal/controlplane/health.go`
- Create: `internal/controlplane/health_test.go`
- Modify: `internal/registry/handler.go`
- Modify: `internal/controlplane/http.go`
- Modify: both command entry points
- Modify: `go.mod`

**Interfaces:**
- Produces: `/livez`, `/readyz`, `/metrics`, component `*slog.Logger`, and shared metric instruments.

- [ ] **Step 1: Write failing health tests**

Registry readiness fails for inaccessible staging root, missing verification keys, or failed Bee probe. Control-plane readiness fails for database, master key, signing key, or required Bee publication failure. Liveness remains independent of external dependencies.

- [ ] **Step 2: Write failing metric tests**

Assert request count/latency/error class, staged bytes/sessions, publication conflicts/retries, dependency failures, outbox depth/age, cleanup results, and integrity failures appear with bounded labels.

- [ ] **Step 3: Run tests and verify failure**

Run: `go test ./internal/observability ./internal/registry ./internal/controlplane -run 'Test.*Health|Test.*Metrics' -count=1 -v`

Expected: FAIL because endpoints and instruments do not exist.

- [ ] **Step 4: Add Prometheus client dependency and metrics**

Use `prometheus/client_golang`. Avoid email, token, digest, upload ID, or unbounded repository labels. Expose registry/operation/result/dependency only where bounded.

- [ ] **Step 5: Add structured request logging**

Use `log/slog` with component, request ID, operation ID, registry, repository, action, duration, status, result class, and dependency. Add tests with a JSON handler buffer and assert secrets are absent.

- [ ] **Step 6: Wire health and metrics routes**

Keep health endpoints outside registry API parsing. Readiness uses short timeouts and returns a structured but non-secret component summary.

- [ ] **Step 7: Run telemetry tests**

Run: `go test -race -count=1 ./internal/observability ./internal/registry ./internal/controlplane`

Expected: PASS.

- [ ] **Step 8: Commit observability**

```bash
git add go.mod go.sum internal/observability internal/registry internal/controlplane cmd
git commit -m "feat: add registry operational telemetry"
```

### Task 24: Build the canonical Docker Compose deployment

**Files:**
- Create: `Dockerfile.registry`
- Create: `Dockerfile.controlplane`
- Create: `compose.yaml`
- Create: `.env.example`
- Create: `deploy/Caddyfile`
- Create: `scripts/e2e/compose-smoke.sh`
- Create: `scripts/e2e/docker-roundtrip.sh`
- Create: `scripts/e2e/podman-roundtrip.sh`
- Create: `scripts/e2e/lib.sh`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: health/readiness endpoints and all production configuration.
- Produces: one reproducible reference stack and executable E2E entry points.

- [ ] **Step 1: Write the smoke script first**

The script must:

1. Validate required commands.
2. Create a temporary secret directory with restrictive permissions.
3. Generate master, session, registry-signing, and internal-service keys.
4. Start Compose with pinned images.
5. Wait on readiness rather than sleep.
6. Register a user and create a registry.
7. Verify auth and stamp feeds are readable.
8. Stop services and preserve logs on failure.

- [ ] **Step 2: Run the script and verify failure**

Run: `bash scripts/e2e/compose-smoke.sh`

Expected: FAIL because Dockerfiles and Compose services do not exist.

- [ ] **Step 3: Add multi-stage Dockerfiles**

Build with the module Go version, run as a non-root numeric user, copy only the binary and required certificates, expose documented ports, and define no baked secrets.

- [ ] **Step 4: Add Compose services and persistent volumes**

Include control plane, registry, Bee, and Caddy/reference TLS routing. Mount control-plane database, staging database/spool, Bee data, and secret files separately. Set `restart: unless-stopped`, health checks, and dependency readiness.

- [ ] **Step 5: Add Docker and Podman round-trip scripts**

Build a deterministic small image and a multi-platform fixture, login, push to a nonexistent repository, inspect manifests, restart services, pull, and compare digests. Podman script skips with a clear message only when Podman is not installed in local development; CI uses a runner that has it.

- [ ] **Step 6: Run the reference stack**

Run:

```bash
bash scripts/e2e/compose-smoke.sh
bash scripts/e2e/docker-roundtrip.sh
bash scripts/e2e/podman-roundtrip.sh
```

Expected: all required tools’ scripts pass; temporary secrets remain outside Git.

- [ ] **Step 7: Commit deployment packaging**

```bash
git add Dockerfile.registry Dockerfile.controlplane compose.yaml .env.example deploy scripts/e2e .gitignore
git commit -m "feat: add production reference deployment"
```

### Task 25: Add CI, vulnerability, license, SBOM, and release workflows

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`
- Create: `.github/dependabot.yml`
- Create: `scripts/ci/check.sh`
- Create: `scripts/ci/release-artifacts.sh`
- Create: `LICENSE`

**Interfaces:**
- Produces: clean-clone CI and traceable release artifacts.

- [ ] **Step 1: Write the local CI driver**

```bash
#!/usr/bin/env bash
set -euo pipefail

test -z "$(gofmt -l cmd internal)"
go mod tidy -diff
go mod verify
go build ./...
go vet ./...
go test -race -count=1 ./...
bash scripts/security/check-repository-secrets.sh
```

Add `govulncheck ./...`, dependency-license checking, and E2E invocations after required tools are installed by CI.

- [ ] **Step 2: Run the driver before workflow creation**

Run: `bash scripts/ci/check.sh`

Expected: PASS locally except explicitly reported missing external scanners; update the script to fail in CI when installation steps did not provide them.

- [ ] **Step 3: Create CI jobs**

Jobs: Go quality/race, secret scan, govulncheck, license check, container build, real Bee integration, Docker compatibility, Podman compatibility, and documentation checks. Cache modules but never cache secrets or runtime databases.

- [ ] **Step 4: Create release workflow**

On signed version tags, rebuild from clean source, run every gate, produce binaries and containers, generate checksums and SBOMs, attach vulnerability/license reports, and record source commit plus image digests.

- [ ] **Step 5: Add license and dependency automation**

Use the operator-approved project license; if no license has been selected, stop this task and request the owner’s choice before creating `LICENSE`. Dependabot covers Go modules, GitHub Actions, and Docker bases.

- [ ] **Step 6: Validate workflow syntax and local driver**

Run:

```bash
bash scripts/ci/check.sh
gh workflow view .github/workflows/ci.yml --yaml >/dev/null
gh workflow view .github/workflows/release.yml --yaml >/dev/null
```

Expected: local driver passes and GitHub accepts workflow YAML after push.

- [ ] **Step 7: Commit CI and release automation**

```bash
git add .github scripts/ci LICENSE
git commit -m "ci: add verified build and release gates"
```

### Task 26: Add backup, restore, key rotation, upgrade, rollback, and incident runbooks

**Files:**
- Create: `docs/operations/install.md`
- Create: `docs/operations/backup-restore.md`
- Create: `docs/operations/key-rotation.md`
- Create: `docs/operations/upgrade-rollback.md`
- Create: `docs/operations/incidents.md`
- Create: `scripts/operations/backup.sh`
- Create: `scripts/operations/restore.sh`
- Create: `scripts/operations/verify-backup.sh`
- Modify: `README.md`

**Interfaces:**
- Produces: executable operator procedures and verification scripts.

- [ ] **Step 1: Write backup verification script first**

It verifies archive manifest, checksums, control-plane database integrity, staging database integrity, required secret identifiers without printing secret values, and deployment configuration presence.

- [ ] **Step 2: Implement consistent backup**

Pause or checkpoint writers, use SQLite online backup or `VACUUM INTO`, archive staging metadata/files consistently, include key-version metadata and Compose configuration, and write SHA-256 checksums. Never copy the master key into an unencrypted backup archive by default.

- [ ] **Step 3: Implement restore into an isolated destination**

Require an empty destination, verify checksums first, restore restrictive permissions, run migration/readiness checks, and avoid overwriting a live deployment without explicit operator confirmation.

- [ ] **Step 4: Write key-rotation runbook**

Cover registry-token signing key overlap by `kid`, session-key rotation, master-key re-encryption, feed-owner rotation limitations, verification, and rollback.

- [ ] **Step 5: Write upgrade/rollback and incident runbooks**

Define migration order, backup gate, compatibility window, rollback restrictions, smoke tests, integrity incident response, postage exhaustion, Bee outage, signer outage, staging disk pressure, and credential exposure.

- [ ] **Step 6: Perform backup/restore drill**

Run the reference stack, push fixtures, back up, destroy only a disposable test deployment, restore to a fresh location, restart, and pull the same digests. Record outputs in `docs/evidence/phase-5-recovery.md`.

- [ ] **Step 7: Commit operator procedures**

```bash
git add docs/operations docs/evidence/phase-5-recovery.md scripts/operations README.md
git commit -m "docs: add production operations runbooks"
```

### Task 27: Final v1 release gate and documentation reconciliation

**Files:**
- Modify: `README.md`
- Modify: `docs/compatibility.md`
- Create: `docs/evidence/v1-release.md`
- Create: `docs/release-checklist.md`
- Modify: PRD status in `docs/superpowers/specs/2026-09-16-uncloud-registry-v1-completion-design.md`

**Interfaces:**
- Consumes: every prior phase artifact and evidence document.
- Produces: final release decision record.

- [ ] **Step 1: Build a requirement-to-evidence checker**

Create `scripts/ci/check-prd-traceability.py` that parses requirement and audit IDs from the PRD, requires a mapping in the release evidence index, rejects duplicates, and exits nonzero on gaps.

- [ ] **Step 2: Run the checker and verify initial gaps**

Run: `python3 scripts/ci/check-prd-traceability.py`

Expected: FAIL until the release evidence index maps all 75 requirements and 26 audit findings.

- [ ] **Step 3: Populate the final evidence index**

For every requirement, record implementing commit, test command, evidence file, and status. Every audit ID must be closed or explicitly deferred only if the PRD marks it post-v1; no P0/P1 audit item may be deferred.

- [ ] **Step 4: Run the full clean-clone release gate**

From a fresh clone:

```bash
bash scripts/ci/check.sh
bash scripts/e2e/compose-smoke.sh
bash scripts/e2e/docker-roundtrip.sh
bash scripts/e2e/podman-roundtrip.sh
python3 scripts/ci/check-prd-traceability.py
```

Expected: all pass.

- [ ] **Step 5: Perform operational drills**

Execute and record clean install, registry bootstrap, first push, restart recovery, concurrent push, backup/restore, token-signing rotation, master-key rotation, version upgrade, and rollback.

- [ ] **Step 6: Reconcile documentation with observed behavior**

Verify README, compatibility matrix, configuration reference, Compose files, and runbooks against the final binaries. Remove unsupported claims and machine-local links.

- [ ] **Step 7: Mark the PRD implemented and write release decision**

Change PRD status only after every gate passes. Record source SHA, container digests, SBOMs, migration version, Bee version, client matrix, backup ID, restore result, and rollback result in `docs/evidence/v1-release.md`.

- [ ] **Step 8: Commit final release evidence**

```bash
git add README.md docs scripts/ci/check-prd-traceability.py
git commit -m "docs: record Uncloud Registry v1 release gate"
```

---

## Requirement-to-task coverage

| PRD requirements | Implementing tasks | Gate evidence |
|---|---|---|
| SEC-001–SEC-005 | Tasks 4–5 | Phase 1 adversarial token and policy tests |
| SEC-006 | Tasks 1 and 3 | Phase 1 response schema/value scan |
| SEC-007–SEC-008 | Tasks 6 and 10 | Phase 1 encryption/rotation tests; Phase 2 signer tests |
| SEC-009 | Task 7 | Phase 1 invite lifecycle suite |
| SEC-010–SEC-011 | Task 8 | Phase 1 browser and production-config tests |
| STAMP-001–STAMP-002 | Tasks 9, 10, and 13 | Phase 2 bootstrap and first-push integration |
| STAMP-003 | Task 11 | Phase 2 exact Bee header/payload assertions |
| STAMP-004–STAMP-005 | Tasks 10–11 | Phase 2 constrained signer and postage-failure tests |
| PUB-001–PUB-004 | Tasks 12–13 | Phase 2 first-push and artifact tests |
| PUB-005–PUB-006 | Task 17 | Phase 3 concurrency stress evidence |
| PUB-007 | Task 10 | Phase 2 internal signer API tests |
| PUB-008 and PUB-010 | Task 14 | Phase 2 read-back and retry tests |
| PUB-009 | Tasks 13 and 18 | Phase 2 referenced-blob test; Phase 3 cleanup tests |
| STAGE-001–STAGE-003 | Task 15 | Phase 3 restart and ownership tests |
| STAGE-004–STAGE-006 | Task 16 | Phase 3 range, digest, and restart E2E tests |
| STAGE-007 | Task 18 | Phase 3 expiration and cleanup tests |
| STAGE-008–STAGE-009 | Tasks 15–16 | Phase 3 quota and filesystem-safety tests |
| COMP-001–COMP-002 | Task 21 | Phase 4 matrix and route conformance evidence |
| COMP-003 | Tasks 12 and 19 | Phase 2/4 descriptor and index validation tests |
| COMP-004 | Task 20 | Phase 4 pull-integrity tests |
| COMP-005–COMP-006 | Tasks 21 and 24 | Phase 4 unsupported-operation and client E2E evidence |
| CP-001 and CP-004 | Task 2 | Phase 1 migration and constraint tests |
| CP-002–CP-003 | Task 9 | Phase 1 outbox/reconciliation failure injection |
| CP-005 | Tasks 4, 8, and 20 | Phase 1 input/scope tests; Phase 4 host tests |
| CP-006 | Task 9 | Phase 1 policy synchronization tests |
| OPS-001 | Task 24 | Phase 5 clean Compose install and smoke evidence |
| OPS-002–OPS-003 | Task 22 | Phase 5 lifecycle and timeout tests |
| OPS-004–OPS-006 | Task 23 | Phase 5 health, log, and metric assertions |
| OPS-007–OPS-008 | Task 26 | Phase 5 backup/restore and rollback drills |
| OPS-009 | Task 25 | Phase 5 release workflow, SBOM, vulnerability, and license artifacts |
| PERF-001 | Tasks 15–16 | Phase 3 streaming and bounded-memory tests |
| PERF-002 | Task 24 | Phase 5 reference workload E2E evidence |
| PERF-003 | Task 23 | Phase 5 metrics-backed latency evidence |
| PERF-004 | Tasks 16, 23, and 24 | Phase 3 quota tests and Phase 5 saturation evidence |
| AC-001–AC-002 | Task 5 | Raw-bearer and wrong-scope registry tests |
| AC-003 | Task 3 | Public response schema/value scan |
| AC-004 | Task 7 | Email-bound invite lifecycle test |
| AC-005 | Task 9 | Partial bootstrap failure and reconciliation test |
| AC-006 | Task 13 | Unseeded first-repository push test |
| AC-007 | Tasks 12 and 14 | Zero-write invalid-manifest test |
| AC-008 | Task 13 | Referenced-staged-blob selection test |
| AC-009 | Task 11 | Exact Bee postage header test |
| AC-010 | Task 10 | Constrained signer rejection matrix |
| AC-011 | Task 17 | Concurrent tag preservation stress test |
| AC-012 | Tasks 15–16 | Process restart and upload resume test |
| AC-013 | Task 20 | Pull integrity failure test |
| AC-014 | Tasks 19 and 24 | Multi-platform real-client round trip |
| AC-015 | Tasks 10 and 23 | Control-plane outage and readiness test |

Every AUD-001–AUD-026 row is already mapped to these requirements in the PRD. Task 27 mechanically verifies that all 75 requirement IDs and all 26 audit IDs have release evidence before the PRD status can change.

## Execution order and review checkpoints

1. Complete Tasks 1–3 and review Phase 0 containment before security implementation.
2. Complete Tasks 4–9, run the Phase 1 gate, and obtain security-focused code review.
3. Complete Tasks 10–14, run the real Bee Phase 2 gate, and review feed protocol evidence.
4. Complete Tasks 15–18, run Phase 3 stress/restart gates, and review durability evidence.
5. Complete Tasks 19–21, run Docker/Podman Phase 4 gates, and approve the compatibility matrix.
6. Complete Tasks 22–27, run recovery and release gates from a clean clone, then decide v1 release.

Do not begin a later phase while an earlier phase gate is red. Within a phase, independent test-writing work may run in parallel, but interface-producing tasks must land before their consumers.
