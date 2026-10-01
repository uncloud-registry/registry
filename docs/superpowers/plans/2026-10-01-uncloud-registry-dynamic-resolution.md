# Plan: Dynamic registry resolution via the control plane (v1-completion redo)

Status: approved (design A–E, cleanup option 2) — re-implemented against
`feat/v1-completion`, which already contains the internal feed-signing service
and its credential mechanism.

## Context

`feat/v1-completion` already ships the v1 control plane + data plane. Three
facts discovered during this redo change the original design and must be
respected:

1. `resolve.RegistryIdentity` now carries `RegistryID int64` — the resolve
   endpoint must return BOTH `owner` and `registryID`, not just owner.
2. An internal-service auth mechanism already exists: a dedicated internal
   listener (`InternalFeedServer`) authenticates with the
   `X-Uncloud-Internal-Auth` header against a secret file
   (`CONTROLPLANE_INTERNAL_SECRET_FILE`), compared in constant time. The data
   plane already reuses this exact mechanism for feed commits and operation
   bindings. The resolve endpoint must reuse it — NOT a new bearer token.
3. `requireRegistryIDs` (cmd/registry/main.go) currently hard-rejects every
   non-static resolver in Bee mode. That gate is exactly what this feature
   relaxes for the controlplane resolver.

## Approved design (A–E)

- **A.** Endpoint lives on the INTERNAL listener: new route
  `GET /internal/v1/resolve/{host}` on `InternalFeedServer`, reusing the
  existing credential header.
- **B.** Response is `{"owner": "...", "registryID": N}`.
- **C.** Data-plane resolver reuses `CONTROLPLANE_URL` +
  `CONTROLPLANE_INTERNAL_SECRET_FILE` (already loaded for signing) — no new
  env vars. It strips the port before lookup (control plane stores host
  WITHOUT port) and sends the credential header.
- **D.** `requireRegistryIDs` accepts the controlplane resolver (IDs are
  authoritative from the control plane). Cleanup under controlplane resolution
  follows option 2: the periodic cleanup loop is NOT started (the
  committed-state guard needs the full static identity list up front).
  `canonicalRegistryHostLabels` already fails closed to the placeholder for
  non-static resolvers — no change needed.
- **E.** No cache (A1). Live control-plane call per resolution. Spec section 4
  availability deviation still holds, scoped to controlplane mode.

## Tasks

Each task ends in its own commit with green tests/vet.

### Task 1 — Control-plane resolve endpoint

- Add `publish.InternalResolvePath = "/internal/v1/resolve/"` and
  `publish.ResolveResponse{Owner, RegistryID}` (shared wire contract).
- Add `Store *Store` to `InternalFeedServer`, populated from `signer.Store` in
  `NewInternalFeedServer` (signer already carries the store).
- Route `GET` on the resolve prefix in `ServeHTTP`; `handleResolve` does
  credential check → `FindRegistryByHost` → 200 `{owner, registryID}` / 404
  (no rows) / 503 (backend) / 400 (empty host).
- Tests: auth rejection (missing/wrong credential), 404 unknown host, 200
  shape, empty host.

### Task 2 — Data-plane controlplane resolver

- New `publish.ControlPlaneRegistryIdentityResolver` (BaseURL, Secret,
  HTTPClient) implementing `resolve.RegistryIdentityResolver`.
- `ResolveRegistry` strips the port, does GET
  `baseURL + InternalResolvePath + escaped(host)` with the credential header,
  strictly decodes the response, validates owner non-empty + registryID > 0,
  returns `resolve.RegistryIdentity{Host, Owner, RegistryID}`.
- Tests: 200 decode, 404 → error, 401 → error, port stripping, malformed body.

### Task 3 — Registry binary wiring

- `buildRegistryIdentityResolver` gains a `controlplane` case. Reorder
  `buildBeeHandler` so `CONTROLPLANE_URL`/secret/cpHTTPClient load BEFORE the
  resolver is built, and pass them in.
- `requireRegistryIDs` accepts `*publish.ControlPlaneRegistryIdentityResolver`.
- Gate the cleanup loop on `registryResolver` being static (option 2).
- Tests: controlplane mode builds; requireRegistryIDs accepts controlplane and
  still rejects ENS/other; cleanup skipped under controlplane.

### Task 4 — README

- Document `REGISTRY_RESOLUTION_MODE=controlplane`, its (already-required)
  `CONTROLPLANE_URL`/`CONTROLPLANE_INTERNAL_SECRET_FILE` inputs, the cleanup
  limitation, and the availability deviation.

## Verification

- `go build ./...`, `go vet ./...`, `go test ./...` green after each task.
- Endpoint reuses `checkCredential` (constant-time, exact-byte) — no new auth.
