# Uncloud Registry — Dynamic Registry Resolution

- Status: Approved
- Date: 2026-10-01
- Product: `github.com/uncloud-registry/registry`
- Depends on: `feat/v1-completion` (the internal feed-signing service and its credential mechanism)
- Supersedes: manual `REGISTRY_OWNER_MAP` / `REGISTRY_ID_MAP` static config

## 1. Purpose

Today, in `static` resolution mode, an operator must edit the
`REGISTRY_OWNER_MAP` AND `REGISTRY_ID_MAP` environment variables and restart
the registry data plane every time a registry is added or its identity changes.
The control plane already knows every registry's host-to-owner mapping and its
unambiguous RegistryID in SQLite (`Store.FindRegistryByHost`), but the data
plane has no way to consult it.

This work adds a third resolution mode — `controlplane` — in which the data
plane resolves host to (feed-owner, RegistryID) by asking the control plane over
HTTP. It closes the manual-config gap while the codebase remains pre-ENS, and is
intended to be superseded by contenthash-based ENS resolution later (see the
future-work document). For that reason the design deliberately adds minimal
machinery: no cache, no new data model, no service-identity system.

## 2. Current behavior

`internal/resolve/registry.go` defines the `RegistryIdentityResolver`
interface:

```go
type RegistryIdentityResolver interface {
    ResolveRegistry(ctx context.Context, host string) (RegistryIdentity, error)
}
```

`RegistryIdentity` carries `Host`, `Owner` (the feed-owner address), and
`RegistryID` (the control-plane registry identifier, 0 when a resolver does not
carry one). In Bee mode the data plane routes every internal feed commit by
`RegistryID`, so a dynamic resolver must return it — not just the owner.

`cmd/registry/main.go` `buildRegistryIdentityResolver()` switches on
`REGISTRY_RESOLUTION_MODE`:

- `static`: `StaticRegistryIdentityResolver` over the env-derived
  `REGISTRY_OWNER_MAP` + `REGISTRY_ID_MAP`.
- `ens`: `ENSRegistryIdentityResolver`, deriving `<subdomain>.<suffix>` and
  reading the on-chain `addr` record.

Nothing about feed-topic derivation changes in this work.

The control plane already exposes a host lookup internally:
`Store.FindRegistryByHost` is used by `IssueRegistryToken`. The data plane has
no client for it.

## 3. Target design

### 3.1 Control-plane endpoint

Add `GET /internal/v1/resolve/{host}` to the INTERNAL feed server
(`InternalFeedServer`), NOT the public router. This is the same listener that
already serves feed signing and operation binding, and it is the right trust
boundary for a host-to-identity directory: it can never inherit the public
browser CSRF/session assumptions, and it already authenticates the data plane.

- Input: the registry host, taken from the request path after the
  `InternalResolvePath` prefix. Hosts are stored WITHOUT a port, and the data
  plane strips any port before calling.
- Auth: the EXISTING internal credential header `X-Uncloud-Internal-Auth`,
  compared in constant time against the same secret file used for feed signing
  (`CONTROLPLANE_INTERNAL_SECRET_FILE`). No new token or env var.
- Success: `200 {"owner":"0x...","registryID":N}` — `owner` is
  `Registry.FeedOwnerAddress`, `registryID` is `Registry.ID`.
- Unknown host: `404`.
- Empty/malformed host: `400`.
- Backend failure: `503`.

The owner address is not secret — it is already shown in the UI and published
in policy — but the endpoint enumerates the host-to-owner directory, so the
credential gate exists to close that enumeration, not to protect key material.

### 3.2 Data-plane resolver

Add `ControlPlaneRegistryIdentityResolver` in `internal/publish` (alongside the
committer and operation binder — the other control-plane clients). It returns
`resolve.RegistryIdentity` and implements `resolve.RegistryIdentityResolver`.

- Fields: `BaseURL`, `Secret []byte`, `HTTPClient`.
- `ResolveRegistry(ctx, host)`:
  1. Strip the port from `host` (the control plane stores `Registry.Host`
     without a port, and Docker clients commonly send `host:port`).
  2. `GET <baseURL>/internal/v1/resolve/<escaped(hostname)>` with the shared
     credential header, using the provided context.
  3. `200` → strictly decode `{owner, registryID}`, reject a blank owner or a
     non-positive RegistryID, and return
     `RegistryIdentity{Host: hostname, Owner: owner, RegistryID: registryID}`.
  4. `401` → authentication error.
  5. `404` → not-found error.
  6. `400/500`, network failure, timeout → dependency error.

All failures are returned as errors so the existing error taxonomy's
Dependency/Not-found classes apply. There is no fallback and no cache.

### 3.3 Wiring

In `buildBeeHandler`, the control-plane origin, the shared internal credential,
and the bounded HTTP client are loaded first (they are already required for feed
commits), then `buildRegistryIdentityResolver()` adds a `controlplane` case:

- Construct `publish.ControlPlaneRegistryIdentityResolver` from the SAME
  `CONTROLPLANE_URL`, `CONTROLPLANE_INTERNAL_SECRET_FILE`, and bounded client
  the committer/binder use — no new env vars.
- `requireRegistryIDs` accepts the dynamic resolver (IDs are authoritative from
  the control plane) while still rejecting the static zero-ID case and every
  other resolver shape.

The data plane now depends on the control plane for resolution (this work) and
already depends on it for feed signing. Token verification remains offline —
the data plane still verifies registry tokens locally, never by calling the
control plane. That boundary is unchanged.

### 3.4 Staging cleanup (option 2)

The periodic staging-cleanup loop's committed-state guard needs the full static
identity list up front (`registryIdentities`), which controlplane resolution
cannot enumerate at startup. Under `controlplane` mode the cleanup loop is NOT
started. Staged uploads still expire via the upload-time checks; only the
periodic reaper is off. This is the smallest correct option and is scoped to
`controlplane` mode only.

## 4. Availability deviation

This is a deliberate, accepted deviation from v1's pull-independence property
(PRD section 7.4, AC-015). Under `controlplane` resolution with no cache, a
control-plane outage makes pulls fail with a dependency error, because
host-to-owner resolution cannot complete.

Rationale: the user intends ENS/contenthash resolution to become the default,
and a caching layer added now for a control-plane resolver would be throwaway
machinery. Reversal path: if pull availability under control-plane outage
matters before ENS lands, add the stale-while-revalidate cache (option A2 in
the design discussion). This deviation is scoped to `controlplane` mode only;
`static` and `ens` are unchanged.

## 5. Non-goals

- No caching, TTLs, or stale-while-revalidate.
- No new service-identity or bearer-token system — the endpoint reuses the
  v1 internal credential (`X-Uncloud-Internal-Auth`).
- No change to feed-topic derivation or the deterministic topic layout.
- No change to `static` or `ens` modes.
- No contenthash resolution (future work, separate PRD).

## 6. Testing

- Endpoint test: internal server returns `200` for a known host (owner +
  RegistryID), `404` for unknown, `401` for missing/wrong credential, `400`
  for an empty host, `405` for a non-GET method.
- Resolver unit test: `httptest` server returns `200`/`404`/`401`/`500`; assert
  owner + RegistryID decoding, port stripping, credential header, and error
  classification for each; malformed bodies (blank owner, non-positive ID,
  unknown field, trailing content) are rejected.
- Wiring test: `buildRegistryIdentityResolver` returns a
  `ControlPlaneRegistryIdentityResolver` for mode `controlplane` carrying the
  shared origin/secret/client; `requireRegistryIDs` accepts it and still
  rejects ENS/unknown shapes.
- Context cancellation and timeout propagation through the HTTP call.

## 7. Acceptance scenarios

### AC-RES-001

Given `REGISTRY_RESOLUTION_MODE=controlplane` and a known registry host, when
the data plane resolves it, then the owner matches `FeedOwnerAddress` and the
RegistryID matches the row ID in the control plane's store.

### AC-RES-002

Given a request host `alice.example.com:5000`, when the resolver strips the
port, then the control plane lookup uses `alice.example.com`.

### AC-RES-003

Given a wrong or missing internal credential, when the data plane resolves,
then the control plane returns `401` and the resolver returns an authentication
error.

### AC-RES-004

Given the control plane is unreachable, when the data plane resolves, then the
resolver returns a dependency error and the pull fails with a dependency class.

### AC-RES-005

Given an unknown host, when the data plane resolves, then the resolver returns
a not-found error.
