# Docker / OCI Compatibility Contract

Uncloud Registry implements a **documented subset** of the
[OCI Distribution Spec](https://github.com/opencontainers/distribution-spec)
and the Docker Registry HTTP API v2. It is **not** a drop-in replacement for
Docker Distribution; endpoints, methods, headers, and error codes outside the
tables below are not part of the v1 contract and must not be relied on.

The wire contract in this document is enforced by the machine-readable
conformance matrix in
[`internal/registry/conformance_test.go`](../internal/registry/conformance_test.go)
(`TestDistributionConformanceMatrix`), which drives every row through the real
HTTP handler over `httptest` — no mocks. Any route/method/header change that
violates this document fails that test, and any **new** endpoint MUST be added
to the matrix before it can be called supported.

## 1. Supported endpoints

Every request is scoped to a repository under a registry host resolved from
the request `Host`. Auth scope is `pull` (reads) or `push` (writes); the
policy decides which principals each repository grants.

| Method | Route | Auth | Success | Headers on success |
|--------|-------|------|---------|--------------------|
| GET, HEAD | `/v2`, `/v2/` | none | 200 | `Docker-Distribution-API-Version: registry/2.0` |
| GET, HEAD | `/v2/<name>/manifests/<tag or digest>` | pull | 200 | `Docker-Content-Digest`, `Content-Type`, `Content-Length`, `Vary: Accept` |
| PUT | `/v2/<name>/manifests/<tag>` | push | 201 | `Location`, `Docker-Content-Digest`, `X-Uncloud-Operation-Id` |
| GET, HEAD | `/v2/<name>/blobs/<digest>` | pull | 200 | `Docker-Content-Digest`, `Content-Length`, `Content-Type` (when the descriptor stores one) |
| POST | `/v2/<name>/blobs/uploads/` | push | 202 | `Location`, `Docker-Upload-UUID`, `Range` |
| GET | `/v2/<name>/blobs/uploads/<uuid>` | push | 204 | `Location`, `Docker-Upload-UUID`, `Range` |
| PATCH | `/v2/<name>/blobs/uploads/<uuid>` | push | 202 | `Location`, `Docker-Upload-UUID`, `Range` (current offset) |
| PUT | `/v2/<name>/blobs/uploads/<uuid>?digest=<digest>` | push | 201 | `Location`, `Docker-Content-Digest` |
| DELETE | `/v2/<name>/blobs/uploads/<uuid>` | push | 204 | — |

Anything else is one of:

- an **unsupported method** on a supported route → `405` with
  `Allow` naming the supported methods and error code `UNSUPPORTED`
  (see the Allow contracts below); or
- an unknown path → `404 NAME_UNKNOWN` (fixed, data-free); or
- a **deferred operation** → `405 UNSUPPORTED` (see §2).

Allow contracts (pinned by the matrix):

| Route | Allow |
|-------|-------|
| `/v2`, `/v2/` | `GET, HEAD` |
| `/v2/<name>/manifests/...` | `GET, HEAD, PUT` |
| `/v2/<name>/blobs/<digest>` | `GET, HEAD` |
| `/v2/<name>/blobs/uploads/` (session start) | `POST` |
| `/v2/<name>/blobs/uploads/<uuid>` | `GET, PATCH, PUT, DELETE` |

## 2. Deferred operations

The following Distribution operations are **explicitly deferred** in v1 and
answer a fixed, data-free `405` with error code `UNSUPPORTED`:

| Operation | Request | Response |
|-----------|---------|----------|
| Repository catalog | `GET /v2/_catalog` (and `/v2/_catalog/`) | 405 `UNSUPPORTED`, `Allow: GET, HEAD` |
| Manifest deletion | `DELETE /v2/<name>/manifests/<reference>` | 405 `UNSUPPORTED`, `Allow: GET, HEAD, PUT` |
| Blob deletion | `DELETE /v2/<name>/blobs/<digest>` | 405 `UNSUPPORTED`, `Allow: GET, HEAD` |
| Cross-repository blob mount | `POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<repo>` | 405 `UNSUPPORTED`, `Allow: POST` |

These responses are answered **before identity resolution and
authentication**: they are identical for every repository and host, carry no
request data, and therefore can never act as an existence oracle. A client
that requested a mount should fall back to a plain upload session
(`POST /v2/<name>/blobs/uploads/` without `mount`/`from`), which is fully
supported. Tag listing (`/v2/<name>/tags/list`) is likewise not implemented
and answers `404 NAME_UNKNOWN`.

## 3. Media types

Supported manifest/index media types (exactly four; anything else is
`400 MANIFEST_INVALID` before any write):

| Artifact | Media type |
|----------|------------|
| OCI image manifest | `application/vnd.oci.image.manifest.v1+json` |
| OCI image index | `application/vnd.oci.image.index.v1+json` |
| Docker image manifest (schema 2) | `application/vnd.docker.distribution.manifest.v2+json` |
| Docker manifest list | `application/vnd.docker.distribution.manifest.list.v2+json` |

Index children (descriptor `mediaType`) may only reference
**single-platform** manifests (OCI or Docker schema-2). Nested indexes are not
supported in v1 and are rejected before any publication write. The Docker
schema-1 manifest format is **not** supported.

Descriptor and blob behavior:

- A manifest PUT by **digest** is not supported → `400 MANIFEST_INVALID`
  ("manifest publish by digest is not supported in v1"); publish by **tag**
  only.
- The `Content-Type` of a manifest/index PUT selects the artifact kind and
  must be one of the four types above.
- Blob media types are accepted as uploaded at finalization; an absent
  `Content-Type` is stored as `application/octet-stream`. Descriptor media
  type values must conform to RFC 6838 media-type syntax and are validated
  data-free at publication (invalid values → `400 MANIFEST_INVALID`, never
  echoed).
- Pull serves the **stored** representation only: content negotiation
  follows RFC 9110 (`Vary: Accept` is emitted). OCI↔Docker transcoding and
  index child descent are never performed, so a stored representation that is
  unacceptable to the request's `Accept` answers `404 MANIFEST_UNKNOWN`.

## 4. Docker and Podman client support

Any Docker/Podman/nerdctl client that speaks the OCI Distribution subset
documented above is expected to work for pull, first push, re-tag push,
manifest-by-digest pull, and blob-by-digest pull.

Real-client E2E compatibility verification against **pinned** Docker and
Podman versions is a **planned Phase 4 gate that has NOT been executed yet**
and is owned by a later task. When it runs, it will record the exact tested
client versions, commands, image digests, and results as evidence under
`docs/evidence/`; until then, no specific client version has been verified
against this release and none is claimed as tested here. The wire contract
in §1 is enforced by the conformance matrix (see §10 gate commands), not by
a client E2E run. Untested client versions are not implied to be
unsupported — they simply are not part of any recorded evidence yet.

Docker/Podman features that require a deferred operation (catalog, deletion,
mount) will surface as the documented `405 UNSUPPORTED`; Docker's own upload
logic treats an unsupported mount as a fallback to a plain upload session,
which keeps push working.

## 5. Authentication behavior

- `/v2` base ping is anonymous and requires no token.
- **Pull** may be anonymous **iff** the repository's auth policy lists
  `anonymous`; otherwise a pull without a valid credential answers
  `401` + `WWW-Authenticate` with the `Bearer realm/service/scope` challenge
  (`scope=repository:<name>:pull`).
- **Push** always requires a valid bearer token with `push` scope for the
  repository. A missing/invalid credential answers `401` + challenge
  (`scope=repository:<name>:push`).
- An **authenticated** principal denied by policy answers `403 DENIED`
  (push) or a re-challenge `401` (pull) — never a success and never an
  existence oracle.
- Every `401` carries `WWW-Authenticate: Bearer realm="…",service="<host>",
  scope="repository:<name>:<action>"`.
- Tokens are issued by the control plane: Ed25519 JWTs bound to the exact
  registry host (service + audience) and to repository/action scope. Tokens
  are verified for signature, issuer, host, and scope before any policy or
  storage access.

## 6. First-push semantics

A first push to a brand-new repository works without any pre-creation step:

1. `POST /v2/<name>/blobs/uploads/` → `202`, `Location`, `Docker-Upload-UUID`,
   `Range: 0-0`.
2. `PATCH .../uploads/<uuid>` appends bytes (with or without
   `Content-Range`); each accepted `PATCH` answers `202` with the accurate
   current `Range`. A stale/future offset answers `416
   RANGE_NOT_SATISFIABLE` with the actual current Range.
3. `PUT .../uploads/<uuid>?digest=<digest>` finalizes: the staged bytes are
   stream-hashed and must match `digest` (`DIGEST_INVALID` → `400`, zero
   writes otherwise), then streamed to Swarm; success is `201` with
   `Location` and `Docker-Content-Digest`. Retrying a finalized session with
   the same digest and an empty body answers the same verified `201`
   idempotently with zero external writes.
4. `PUT /v2/<name>/manifests/<tag>` is the **publication commit point**: the
   manifest is parsed and validated, its referenced blobs must already be
   staged or committed (`MANIFEST_INVALID` → `400` otherwise, with zero
   writes), the repository state is advanced, and the **read-after-write
   verification** must pass before the `201` — which carries
   `Docker-Content-Digest`, `Location`, and `X-Uncloud-Operation-Id` for
   restart-safe retries. Re-PUTing the exact same tag→digest with the same
   operation id answers a verified `201` without re-publishing. A reused
   operation id with a different payload is `409 MANIFEST_CONFLICT`.

Staged blobs are consumed only after a **verified** publication; a failed or
conflicted publication retains them for a safe retry.

## 7. Pull-integrity strategy (Task 20)

Pull content is **pre-verified before any success byte leaves the handler**:

- **Blob GET**: content is streamed from the bounded object stream into a
  bounded per-request temp file, hashed with SHA-256 and size-checked against
  the committed repository-state descriptor, and only a fully verified file
  is served. The temp file is removed on success and failure paths.
- **Manifest GET**: the body is read through the bounded artifact-byte reader
  and verified for byte length and SHA-256 against the committed descriptor
  before any response byte is written.
- `HEAD` is descriptor-metadata-only (no content read).
- A digest/size mismatch answers `502 INTEGRITY_ERROR`; an unavailable read
  answers `502` with the fixed unavailability code
  (`MANIFEST_BLOB_UNKNOWN` / `BLOB_UNKNOWN`). The raw cause never crosses the
  HTTP boundary, and corrupt content is never returned as `200`.

## 8. Known limitations

- Catalog, manifest/blob deletion, cross-repository mounting, and tag
  listing are not implemented (see §2).
- Manifest publish by digest is not supported; publish by tag only.
- No GC/retention policy; staged uploads expire by session TTL and cleanup.
- One active writer per repository (in-process serialization plus an
  authoritative control-plane generation fence for cross-process safety);
  no active-active writers.
- Staging is durable (SQLite metadata + filesystem spool) in Bee-backed
  mode; it is in-memory only under `REGISTRY_BACKEND=memory`.
- Secure JWKS keys-file loading is implemented on macOS and Linux only; other
  platforms fail closed at startup.
- ENS ownership resolution follows the subdomain-to-ENS naming convention and
  is not a general external ENS resolver integration.
- In the localchain reference deployment (Task 24), feed **publication**
  requires a Bee **full node** (or peers): the stack pins Bee 2.8.2 as an
  isolated light node (`--full-node=false`, no bootnodes/peers), and a light
  node cannot pushsync chunks, so the control-plane reconciler's feed updates
  never become retrievable and feed-dependent requests answer retryable
  dependency errors. Feed-dependent E2E verification (feed readability via
  Bee, and the registry auth path whose pull-policy decisions resolve the
  auth policy feed) is therefore deferred to the Phase 4 / real-Bee E2E gate;
  the Docker/Podman round-trip scripts (`docker-roundtrip.sh`,
  `podman-roundtrip.sh`) are likewise blocked at their first-push stage until
  a full node is available. `scripts/e2e/compose-smoke.sh` reports this stage
  as an explicit SKIP (exit 0) rather than asserting it green.

## 9. Error codes

| Code | Status | Meaning |
|------|--------|---------|
| `NAME_UNKNOWN` | 404 | Unknown path or unresolved repository |
| `MANIFEST_UNKNOWN` | 404 | Manifest (tag/digest) not in state, or stored representation not acceptable |
| `BLOB_UNKNOWN` | 404 | Blob digest not in state |
| `BLOB_UPLOAD_UNKNOWN` | 404 | Upload session unknown/expired/foreign |
| `MANIFEST_INVALID` | 400 | Manifest body, reference, or referenced blobs invalid (data-free) |
| `DIGEST_INVALID` | 400 | Finalize digest missing/invalid, or staged content mismatch |
| `BLOB_UPLOAD_INVALID` | 400/409/413 | Upload range/offset/state/size violation |
| `RANGE_NOT_SATISFIABLE` | 416 | Non-contiguous upload offset |
| `UNAUTHORIZED` | 401 | Missing/invalid credential or denied pull (with challenge) |
| `DENIED` | 403 | Authenticated principal denied by policy |
| `UNSUPPORTED` | 405 | Unsupported method or deferred operation (with `Allow`) |
| `MANIFEST_CONFLICT` | 409 | Idempotency/generation conflict |
| `DEPENDENCY_UNAVAILABLE` | 503 | Control plane / Bee temporarily unavailable (retryable) |
| `PUBLICATION_UNVERIFIED` | 502 | Read-after-write verification of a committed publication failed |
| `INTEGRITY_ERROR` | 502 | Stored pull content failed SHA-256/size verification |
| `UNKNOWN` | 500 | Unknown internal failure |

All error bodies use the Distribution envelope
`{"errors":[{"code":"…","message":"…"}]}` with `Content-Type:
application/json`. Every message is fixed and data-free: hosts, digests,
repository names, references, and cause text never cross the HTTP boundary.

## 10. Gate commands

```bash
# Conformance matrix (this contract)
go test ./internal/registry -run TestDistributionConformanceMatrix -count=1 -v
go test -race -count=1 ./internal/registry -run TestDistributionConformanceMatrix -v

# Full suite, vet, build, formatting
go test ./...
go vet ./...
go build ./...
gofmt -l .
go mod tidy   # must produce no diff

# Documentation assertions (must hold)
python3 - <<'PY'
from pathlib import Path
s = Path('README.md').read_text()
assert '/Users/' not in s
assert 'docs/compatibility.md' in s
PY
```