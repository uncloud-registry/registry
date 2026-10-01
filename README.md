# Uncloud Registry

`uncloud-registry` is a registry server implementing a **documented subset** of the Docker Registry HTTP API v2 / OCI Distribution API. It stores both image content and published registry metadata in Swarm. The exact wire contract — supported endpoints and methods, headers, error codes, media types, authentication behavior, and deferred operations — is pinned by the conformance matrix in [docs/compatibility.md](docs/compatibility.md) and enforced by `TestDistributionConformanceMatrix`. It is not a drop-in replacement for Docker Distribution; endpoints outside the documented subset are not supported.

The core idea is:

- Docker clients keep talking to a normal registry over HTTPS.
- The registry server resolves a registry feed owner from the request host.
- ENS can be used outside the registry to point a registry name at that owner address.
- Each repository has one mutable `stateFeed`.
- Each `stateFeed` points to one immutable repo state document.
- Auth policy and stamp policy are also feed-backed documents under deterministic topics.
- Repo state contains all tag, manifest, and blob mappings needed for pull.
- Pushes stage blobs temporarily, then atomically publish a new repo state on manifest upload.

This repo currently supports:

- pull from published repo state
- push with staged blob upload and tag-based manifest publish
- in-memory mode for local testing
- Bee-backed mode for real object/document reads and feed publication
- static or ENS-backed registry-owner resolution
- a server-rendered dashboard for registry creation, settings, collaborator invites, and invite acceptance

## Architecture at a glance

Uncloud Registry is split into a registry data plane and a separate control plane.

```text
Docker client
    |
    v
Registry data plane ---- resolves host through static mapping or ENS
    |                    enforces auth and stamp policies
    |                    stages uploads and serves OCI registry requests
    v
Swarm / Bee ------------ stores blobs, manifests, and immutable repo snapshots
    ^                    exposes one mutable feed per repository
    |
Control plane ---------- manages accounts, registries, collaborators, tokens,
                         signer keys, and auth/stamp policy publication
```

For each registry owner, deterministic feed topics locate the auth policy, stamp policy, and every repository state. A repository state is an immutable snapshot containing all tag, manifest, and blob mappings needed for pulls; its mutable feed points to the latest snapshot.

During a push, blobs are uploaded and staged first. Uploading the manifest validates its referenced blobs, writes a new repository-state snapshot, and advances the repository feed. That feed update is the publication commit point. During a pull, the registry resolves the owner from the request host, authorizes the request, resolves the latest repository state, and reads the requested manifest or blob from Swarm.

## Why This Design

This project does not use a classic registry storage driver as the primary abstraction.

The main design choice was to move up to the HTTP layer because the registry needs more context than a storage driver naturally has:

- repository identity
- tag updates
- manifest commit points
- auth policy
- stamp policy
- ENS-based registry ownership discovery

The important protocol decision is that a push is only considered published when the client uploads the manifest. Blob uploads are preparatory. Manifest upload is the commit point.

That leads to this storage model:

- blobs are stored in Swarm as raw bytes
- manifests are stored in Swarm as raw bytes
- repo metadata is stored in Swarm as immutable JSON documents
- each repo has a mutable Swarm feed that points to the latest repo state

This keeps published state in Swarm and avoids a long-term metadata database.

## High-Level Architecture

For an image like:

```text
alice.uncloud-registry.com/backend/api:latest
```

the system interprets it as:

- registry host: `alice.uncloud-registry.com`
- registry subdomain: `alice`
- repo: `backend/api`
- tag: `latest`

The registry server:

1. extracts the subdomain from the request host
2. resolves the registry feed owner for that host
3. derives deterministic topic feeds for:
   - auth policy
   - stamp policy
   - repo state
4. resolves the current repo state document from the repo topic
5. answers manifest and blob requests from that repo state

## Metadata Model

### Topic Layout

All published registry metadata is addressed by deterministic feed topics under one registry owner address.

Logical topics:

- `v1:policy:auth`
- `v1:policy:stamp`
- `v1:repo:<repo-name>`

The concrete feed reference is:

```text
feed://<owner>/<keccak256(topic)>
```

That means the server does not need a root registry manifest in the hot path. If it knows the registry owner address, it can derive every feed it needs.

### Repo State Document

Each repo has one mutable `stateFeed`. The feed is derived from `v1:repo:<repo-name>` and points to the current immutable repo state document.

Example shape:

```json
{
  "version": 1,
  "repo": "backend/api",
  "generation": 42,
  "updatedAt": "2026-04-05T12:00:00Z",
  "tags": {
    "latest": "sha256:1111"
  },
  "manifests": {
    "sha256:1111": {
      "swarmRef": "manifest-ref",
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "size": 702
    }
  },
  "blobs": {
    "sha256:aaaa": {
      "swarmRef": "blob-ref",
      "size": 3456789,
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"
    }
  }
}
```

Responsibilities:

- `tags`: tag -> manifest digest
- `manifests`: manifest digest -> Swarm ref
- `blobs`: blob digest -> Swarm ref

This document is the complete published state for pull.

## Pull Flow

The pull path is manifest-first, matching OCI distribution semantics.

### Manifest pull

For `GET /v2/<repo>/manifests/<tag>`:

1. resolve registry owner from host
2. resolve auth policy topic
3. authorize `pull`
4. resolve repo state topic
5. resolve tag -> manifest digest
6. resolve manifest digest -> manifest descriptor
7. fetch manifest bytes from Swarm
8. return them with `Docker-Content-Digest`

### Blob pull

For `GET /v2/<repo>/blobs/<digest>`:

1. resolve registry owner from host
2. resolve auth policy topic
3. authorize `pull`
4. resolve repo state topic
5. resolve blob digest -> blob descriptor
6. fetch bytes from Swarm
7. stream them back

## Push Flow

The push path has two phases.

### 1. Blob staging

Blob uploads use upload sessions:

- `POST /v2/<repo>/blobs/uploads/`
- `PATCH /v2/<repo>/blobs/uploads/<uuid>`
- `PUT /v2/<repo>/blobs/uploads/<uuid>?digest=...`

On finalize:

- digest is verified
- push authorization is checked
- stamp policy is resolved
- blob bytes are uploaded to Swarm
- the resulting blob descriptor is stored in temporary staging

These staged blobs are not published state yet.

### 2. Manifest publish

Manifest publish uses:

- `PUT /v2/<repo>/manifests/<tag>`

On publish:

- manifest is parsed
- referenced config/layer digests must already exist either:
  - in current repo state, or
  - in the actor’s staged blob set
- manifest bytes are uploaded to Swarm
- a new repo state document is built
- repo `stateFeed` is updated to the new repo state

This feed update is the atomic publish point.

## Auth And Stamps

Both auth policy and stamp policy are public documents.

This is intentional. The trust boundary is not secrecy of policy; it is control over:

- token issuance
- feed update keys
- postage consumption keys

Current policy behavior:

- pull can be anonymous if the repo auth policy includes `anonymous`
- push requires an authenticated actor
- push also requires stamp policy to allow that actor to use the selected batch

## Supported Backends

### 1. Memory backend

`REGISTRY_BACKEND=memory`

This mode is for local testing and unit/integration tests.

It uses:

- in-memory document store
- in-memory object store
- in-memory feed store
- in-memory upload staging

This mode is the easiest way to understand handler behavior and verify registry semantics.

### 2. Bee backend

`REGISTRY_BACKEND=bee`

This mode uses Bee for:

- document reads via `/bzz/...` and `/feeds/...`
- blob/manifest upload via `/bytes`
- feed publication via `/chunks` and `/soc`

Bee mode uses durable upload staging (SQLite metadata + filesystem spool) and Swarm-backed published state and content.

## Feed Update Design

The Bee feed updater is sequence-feed based.

It works by:

1. reading the next sequence index from `GET /feeds/{owner}/{topic}`
2. wrapping the new repo state reference as chunk payload
3. uploading the wrapped chunk to `/chunks`
4. computing the feed identifier from `topic || nextIndex`
5. signing `identifier || wrappedChunkAddress`
6. uploading the SOC to `/soc/{owner}/{identifier}?sig=...`

The feed-owner private key lives in the control plane; the registry data plane requests each feed commit through the constrained control-plane signing service (`CONTROLPLANE_URL`) and never holds or reads a feed private key.

## Current Limitations

The exact compatibility subset — including supported routes, methods, and
error codes — is documented in [docs/compatibility.md](docs/compatibility.md)
and enforced by the `TestDistributionConformanceMatrix` conformance test.
Important current limitations:

- registry **catalog** (`/v2/_catalog`), **manifest/blob deletion**, and
  **cross-repository blob mounting** are deferred and answer explicit
  `405 UNSUPPORTED` (see docs/compatibility.md §2)
- tag listing (`/v2/<name>/tags/list`) is not implemented
- manifest publish by **digest** is not supported; publish by tag only
- concurrent multi-writer publish is handled by per-repository serialization
  plus an authoritative control-plane generation fence — no active-active
  writers
- staging is process-local durable (SQLite metadata + filesystem spool); publication is serialized in-process plus a control-plane generation fence
- secure JWKS key-file loading for registry token verification (kernel `O_NOFOLLOW`/`O_NONBLOCK` single-descriptor open) is implemented on macOS and Linux only; on any other platform the registry fails closed at startup rather than loading keys through a weaker fallback — there is no Windows (or other non-macOS/Linux) keys-file loading support
- ENS resolution is currently subdomain-to-ENS naming convention, not a full external ENS resolver integration
- no GC or retention policy yet
- no Redis-backed distributed staging/locking

## Repository Walkthrough

### Entry point

- [cmd/registry/main.go](/cmd/registry/main.go)

Chooses the backend and wires the HTTP handler.

### Spec layer

- [internal/spec/documents.go](/internal/spec/documents.go)

Typed schema definitions and validation for:

- root registry document
- repo state document
- auth policy
- stamp policy
- upload session
- staged blob

### Resolution layer

- [internal/resolve/registry.go](/internal/resolve/registry.go)

Responsible for:

- resolving root document from host
- resolving repo state from root + repo
- in-memory document and feed stores used for testing

### Policy layer

- [internal/policy/authz.go](/internal/policy/authz.go)
- [internal/policy/stamps.go](/internal/policy/stamps.go)

Responsible for:

- pull authorization
- push authorization
- stamp policy resolution

### Registry HTTP layer

- [internal/registry/handler.go](/internal/registry/handler.go)

Implements the registry API surface documented in [docs/compatibility.md](docs/compatibility.md):

- `GET/HEAD /v2`, `/v2/` (base ping)
- `GET/HEAD /v2/<name>/manifests/<tag|digest>`
- `PUT /v2/<name>/manifests/<tag>`
- `GET/HEAD /v2/<name>/blobs/<digest>`
- `POST/GET/PATCH/PUT/DELETE /v2/<name>/blobs/uploads/...`
- deferred (explicit `405 UNSUPPORTED`): catalog, manifest/blob deletion, cross-repo mount

### Staging layer

- [internal/staging/store.go](/internal/staging/store.go)

Ephemeral upload state:

- upload sessions
- staged blob descriptors

### Publish layer

- [internal/publish/publisher.go](/internal/publish/publisher.go)

Builds the next repo state and publishes it by moving the repo feed.

### Swarm adapter layer

- [internal/swarm/bee.go](/internal/swarm/bee.go)

Bee-backed adapters for:

- document reads
- object reads/writes
- subdomain -> ENS reference mapping
- sequence feed updates

## Tests

The compatibility contract, its gate commands, and the supported test suites
are listed in [docs/compatibility.md](docs/compatibility.md) and enforced by
the conformance matrix.

Run all tests with:

```bash
go test ./...
```

Gate commands (all must pass before a release):

```bash
# Conformance matrix (distribution wire contract, no mocks)
go test ./internal/registry -run TestDistributionConformanceMatrix -count=1 -v
go test -race -count=1 ./internal/registry -run TestDistributionConformanceMatrix -v

# Full suite, vet, build, formatting, module hygiene
go test ./...
go vet ./...
go build ./...
gofmt -l .
go mod tidy   # must produce no diff
```

The most useful test files are:

- [internal/registry/handler_test.go](/internal/registry/handler_test.go)
- [internal/swarm/bee_test.go](/internal/swarm/bee_test.go)
- [internal/staging/store_test.go](/internal/staging/store_test.go)
- [internal/spec/documents_test.go](/internal/spec/documents_test.go)

## How To Run

### Local memory mode

This is the recommended development mode.

```bash
REGISTRY_BACKEND=memory go run ./cmd/registry
```

By default it listens on `:8080`.

You can override the listen address:

```bash
REGISTRY_BACKEND=memory REGISTRY_ADDR=:5000 go run ./cmd/registry
```

Note:

- memory mode does not come with seeded registry documents by default in `main`
- it is mainly intended for tests and local handler development
- if you want a usable standalone memory-mode server, the next improvement would be bootstrapping initial in-memory root/auth/stamp/repo docs from config or fixtures

### Bee mode

```bash
REGISTRY_BACKEND=bee \
REGISTRY_RESOLUTION_MODE=static \
BEE_API_URL=http://localhost:1633 \
REGISTRY_OWNER_MAP=alice.uncloud-registry.com=0xfeedowner \
CONTROLPLANE_URL=http://localhost:8081 \
go run ./cmd/registry
```

Required variables in Bee mode:

- `BEE_API_URL`
- `REGISTRY_RESOLUTION_MODE`
- `CONTROLPLANE_URL` (repository feed commits are signed by the control plane)

Resolution-specific variables:

- when `REGISTRY_RESOLUTION_MODE=static`:
  - `REGISTRY_OWNER_MAP` (host → feed-owner address)
  - `REGISTRY_ID_MAP` (host → registry id)
- when `REGISTRY_RESOLUTION_MODE=ens`:
  - `ETH_RPC_URL`
  - `REGISTRY_ENS_SUFFIX`
  - optional `ENS_REGISTRY_ADDRESS`
- when `REGISTRY_RESOLUTION_MODE=controlplane`:
  - `CONTROLPLANE_URL` (the control plane's internal listener — also required for
    feed commits)
  - `CONTROLPLANE_INTERNAL_SECRET_FILE` (the shared internal credential)

Behavior:

- without `CONTROLPLANE_URL`, Bee mode can read documents and upload objects but cannot publish repo state (repository feed commits are refused)
- with `CONTROLPLANE_URL`, the registry requests each feed commit from the control-plane constrained signer

> **Canonical deployment:** the reference `compose.yaml` stack is the
> supported way to run the two services together (see
> [docs/operations/install.md](docs/operations/install.md) for the secrets
> layout, config, and readiness checks). The standalone `go run` examples
> below are for local development only.

`REGISTRY_OWNER_MAP` is a comma-separated host-to-owner mapping:

```text
alice.uncloud-registry.com=0xabc...,bob.uncloud-registry.com=0xdef...
```

For ENS-backed resolution, run:

```bash
REGISTRY_BACKEND=bee \
REGISTRY_RESOLUTION_MODE=ens \
BEE_API_URL=http://localhost:1633 \
ETH_RPC_URL=https://your-ethereum-rpc \
REGISTRY_ENS_SUFFIX=registry.eth \
CONTROLPLANE_URL=http://localhost:8081 \
go run ./cmd/registry
```

In ENS mode, the registry server:

- derives `<subdomain>.<REGISTRY_ENS_SUFFIX>`
- resolves the ENS resolver on-chain
- reads the ENS `addr` record
- uses that address as the registry feed owner

For control-plane-backed dynamic resolution, run:

```bash
REGISTRY_BACKEND=bee \
REGISTRY_RESOLUTION_MODE=controlplane \
BEE_API_URL=http://localhost:1633 \
CONTROLPLANE_URL=http://127.0.0.1:8089 \
CONTROLPLANE_INTERNAL_SECRET_FILE=/path/to/internal-secret \
go run ./cmd/registry
```

In controlplane mode, the registry server resolves every host to its
feed-owner address and RegistryID by calling the control plane's internal
`/internal/v1/resolve/{host}` endpoint on each request (no cache). This reuses
the same internal credential as feed commits — there is no separate token for
resolution.

Known limitations of controlplane mode:

- resolution is a live call per request, so the data plane depends on the
  control plane being reachable to resolve any host (an availability deviation
  from the static/ENS modes' offline behavior)
- the periodic staging-cleanup loop is not started (its committed-state guard
  needs the full static identity list up front); staged uploads still expire
  via the upload-time checks

### Port override

```bash
REGISTRY_BACKEND=bee \
REGISTRY_ADDR=:5000 \
BEE_API_URL=http://localhost:1633 \
REGISTRY_RESOLUTION_MODE=static \
REGISTRY_OWNER_MAP=alice.uncloud-registry.com=0xfeedowner \
CONTROLPLANE_URL=http://localhost:8081 \
go run ./cmd/registry
```

### Control plane

The control plane is a separate binary. It manages:

- users and login
- registry creation
- collaborator invites
- Docker token issuance
- publication of auth and stamp policy topics
- a server-rendered dashboard at `/ui/...`

Local SQLite mode:

```bash
CONTROLPLANE_DB_PATH='file:controlplane.db?_pragma=foreign_keys(1)' \
CONTROLPLANE_TOKEN_SECRET=dev-secret-change-me \
CONTROLPLANE_REGISTRY_DOMAIN=uncloud-registry.com \
go run ./cmd/controlplane
```

Bee-backed publication mode:

```bash
CONTROLPLANE_DB_PATH='file:controlplane.db?_pragma=foreign_keys(1)' \
CONTROLPLANE_TOKEN_SECRET=dev-secret-change-me \
CONTROLPLANE_REGISTRY_DOMAIN=uncloud-registry.com \
CONTROLPLANE_BEE_API_URL=http://localhost:1633 \
go run ./cmd/controlplane
```

Notes:

- if `CONTROLPLANE_BEE_API_URL` is unset, the control plane still works for auth and persistence but does not publish registry policy topics to Bee
- if `CONTROLPLANE_BEE_API_URL` is set, registry creation publishes:
  - auth policy feed content
  - stamp policy feed content
- returns the generated feed owner address so the UI can guide external ENS address-record setup
- each registry uses its own generated feed signer key stored by the control plane and used for policy-feed updates

### Browser flow

The control plane includes a server-rendered dashboard:

- `/ui/register`
- `/ui/login`
- `/ui/registries`
- `/ui/registries/new`
- `/ui/registries/{id}`
- `/ui/invites/accept?token=...`

The registry detail page is the main settings surface. It includes:

- registry overview and ENS setup instructions
- current auth policy document
- current stamp policy document
- editable default stamp and anonymous-pull settings
- JSON editors for auth and stamp policy publication
- collaborator list
- pending invites with shareable accept links and a copy action

The intended setup flow is:

1. Create a registry in the UI.
2. Review the generated ENS setup instructions on the registry detail page.
3. Update the ENS address record for the chosen ENS name externally.
4. Invite collaborators from the same page and share the accept link.
5. Collaborators open the accept page, create an account, and accept the invite.
6. Run the registry server in `ens` resolution mode.
7. Push and pull using the registry host.

## Operations

Production runbooks for the reference deployment (Task 24 `compose.yaml`),
grounded in the actual binaries:

- [docs/operations/install.md](docs/operations/install.md) — secrets layout,
  key/JWKS generation, `.env`, start and readiness verification.
- [docs/operations/backup-restore.md](docs/operations/backup-restore.md) —
  `scripts/operations/backup.sh`, `verify-backup.sh`, `restore.sh`; archive
  contents, what is deliberately excluded (master key, credential files,
  `.env`), restore safety gates, and the honest status of the deferred
  push/pull stack drill (Phase 4).
- [docs/operations/key-rotation.md](docs/operations/key-rotation.md) —
  registry-token signing key rotation by `kid` overlap, session-key
  rotation, master-key rotation + feed-key re-encryption, feed-owner
  rotation limitations, verification and rollback.
- [docs/operations/upgrade-rollback.md](docs/operations/upgrade-rollback.md) —
  migration order (control plane v17 / staging v11), the backup gate,
  compatibility window, and rollback-by-restore restrictions.
- [docs/operations/incidents.md](docs/operations/incidents.md) — integrity
  incidents, postage exhaustion, Bee outage, signer outage, staging disk
  pressure, credential exposure.
- [docs/evidence/phase-5-recovery.md](docs/evidence/phase-5-recovery.md) —
  the executed backup/restore drill against the real SQLite databases
  (fixture → backup → verify → tamper/determinism checks → restore →
  schema/data equivalence → re-open + decrypt with the real constructors).
- [docs/release-checklist.md](docs/release-checklist.md) — the operator/CI
  release checklist (check.sh, traceability checker, secret scan, E2E,
  operational drills, sign-off record).
- [docs/evidence/v1-release.md](docs/evidence/v1-release.md) — the v1 release
  decision record (source SHA, images, migration/Bee versions, client matrix,
  backup drill result, honest deferral statement).

## Suggested Reading Order

If you are new to the codebase, read in this order:

1. [README.md](/README.md)
2. [internal/spec/documents.go](/internal/spec/documents.go)
3. [internal/registry/handler.go](/internal/registry/handler.go)
4. [internal/publish/publisher.go](/internal/publish/publisher.go)
5. [internal/swarm/bee.go](/internal/swarm/bee.go)
6. [internal/registry/handler_test.go](/internal/registry/handler_test.go)

That sequence goes from the conceptual model to the request flow to the Swarm integration.

## Design Choices Summary

These are the main choices made so far:

- registry logic lives at the HTTP layer, not as a pure storage driver
- manifest upload is the publish commit point
- published metadata is fully Swarm-backed
- each repo has a single mutable feed
- repo state is a self-contained immutable snapshot
- auth policy and stamp policy are public
- staging is ephemeral
- memory adapters are kept as first-class options for testing and development

## Near-Term Next Steps

v1 is feature-complete for its documented scope; the remaining work is the
deferred Phase 4 / real-Bee E2E gate, then the production release sign-off:

- run the real-Bee feed-publication and Docker/Podman round-trip gates
  (deferred pending a Bee full node — see [docs/compatibility.md](docs/compatibility.md) §8)
- pin container image digests and produce release SBOMs/checksums
- execute the full push/backup/restore/pull and live upgrade/rollback drills
- complete the operator release checklist ([docs/release-checklist.md](docs/release-checklist.md))
- record the final release decision in [docs/evidence/v1-release.md](docs/evidence/v1-release.md)
