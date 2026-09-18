# Uncloud Registry v1 Completion PRD

- Status: Proposed for implementation
- Approved design: 2026-09-18
- Product: `github.com/uncloud-registry/registry`
- Canonical deployment: Docker Compose
- Release target: Production-ready self-hosted v1

## 1. Executive summary

Uncloud Registry v1 is a production-ready, self-hosted Docker/OCI registry whose image content and published registry metadata are stored in Swarm/Bee. A single operator owns the deployment, while the product supports multiple registry namespaces, repositories, users, and collaborators.

The current repository proves the core architecture through an in-memory path and mocked Bee adapters, but it is not releasable. The audit identified release blockers in authentication, secret exposure, first-repository publication, Bee postage handling, durability, concurrency, protocol validation, and operations.

V1 closes those failure classes without attempting complete Docker Distribution API parity. It delivers a documented and executable Docker/OCI compatibility subset, a secure control plane, correct Bee publication, durable staging, one active registry writer, and a reproducible Docker Compose operating model.

## 2. Product vision

An operator should be able to deploy Uncloud Registry, create a registry namespace, configure static or ENS ownership resolution, invite collaborators, authenticate Docker or Podman, and push and pull images whose durable content and published state live in Swarm/Bee.

The system must preserve these design properties:

1. Docker clients use standard Registry HTTP API operations.
2. Registry identity is derived from the request host.
3. Auth, stamp, and repository state live behind deterministic feeds owned by the registry.
4. Blobs, manifests, policies, and repository snapshots are immutable Bee objects.
5. A repository feed update is the publication commit point.
6. The control plane owns users, roles, token issuance, key custody, policy publication, and constrained feed signing.
7. The registry data plane verifies authorization, stages uploads, validates manifests, and serves published content.

## 3. Target users and roles

### 3.1 Operator

Deploys and upgrades the stack, supplies Bee and cryptographic configuration, manages backups, monitors health, rotates keys, and responds to incidents.

### 3.2 Registry owner

Creates and configures a registry namespace, controls anonymous pull, assigns collaborators, and selects the default postage batch.

### 3.3 Registry administrator

Manages registry settings and collaborators but cannot supersede operator-level deployment or key-management controls.

### 3.4 Writer

Can pull and push repositories within a registry according to issued token scope and published policy.

### 3.5 Reader

Can pull repositories according to issued token scope and published policy.

### 3.6 Anonymous client

Can pull only when the current published auth policy permits anonymous pull.

## 4. V1 scope

### 4.1 Included

- Self-hosted deployment for one operator
- Multiple registry namespaces, repositories, users, and collaborators
- Structured owner, administrator, reader, and writer permissions
- Static and ENS registry-owner resolution
- Asymmetrically signed, short-lived Docker registry tokens
- Resumable blob upload with durable local staging
- Implicit repository creation on first authorized manifest publication
- Tag-based manifest publication
- Manifest and blob pull by tag or digest
- OCI image manifests and OCI image indexes for multi-platform images
- Correct Bee object, chunk, SOC, and sequence-feed publication
- One active registry writer with per-owner/repository publication serialization
- Docker Compose reference deployment
- Health, readiness, structured logs, metrics, backup, restore, upgrade, rollback, and key-rotation procedures
- CI security, quality, integration, compatibility, and release gates

### 4.2 Explicitly deferred

- Hosted multi-tenant SaaS operation
- Billing and isolation between unrelated operators
- Active-active registry writers
- Multi-region deployment
- Registry catalog or search APIs
- Manifest and blob deletion APIs
- Cross-repository blob mounting
- Kubernetes as the canonical v1 deployment
- Arbitrary auth or stamp policy JSON editing
- Complete Docker Distribution API parity

## 5. V1 completion outcome

V1 is complete only when a clean Docker Compose deployment can:

1. Provision the control plane, registry, and Bee dependencies.
2. Create a registry with a valid bootstrap postage batch.
3. Publish and read back auth and stamp policy feeds.
4. Configure static or ENS resolution for the registry hostname.
5. Issue a correctly scoped Docker registry token.
6. Push a previously nonexistent multi-platform repository.
7. Publish generation one through a correctly stamped, signed repository feed update.
8. Restart the registry and control-plane services.
9. Pull the same image and verify all digests.
10. Complete backup/restore, signer rotation, upgrade, and rollback drills.

All phase-specific security, failure, concurrency, and compatibility acceptance tests must also pass.

## 6. Approved architecture decisions

| Area | Decision |
|---|---|
| Product | Production-ready self-hosted product |
| Compatibility | Hardened, documented Docker/OCI subset |
| Staging | Filesystem spool with SQLite metadata |
| Concurrency | Single active writer with per-repository serialization |
| Feed-key storage | AES-GCM envelope encryption under an operator-supplied master key |
| Registry tokens | Asymmetric signing by the control plane; public-key verification by registry |
| Repository creation | Implicit on first authorized manifest publication |
| Feed signing | Constrained internal control-plane signing service |
| Deployment | Docker Compose reference stack plus standalone binaries |
| Policy model | Opinionated role-based settings; no raw JSON editor |
| Delivery | Gated, risk-first phases with executable exit evidence |

## 7. Target system architecture

### 7.1 Control plane

The control plane remains responsible for:

- Users, password verification, sessions, registries, memberships, and invites
- Registry provisioning state
- Role-based auth and stamp policy construction
- Registry-token signing
- Envelope-encrypted feed-owner private keys
- Policy-feed publication
- Constrained repository-feed signing and publication
- Publication outbox, retry, and reconciliation state
- Audit events for key use, policy changes, token issuance, and feed updates

The control plane must use explicit public response DTOs. Persistence models containing password hashes, key ciphertext, invite digests, internal state, or audit data must never be serialized directly.

### 7.2 Registry data plane

The registry remains responsible for:

- Docker/OCI HTTP endpoints in the published compatibility matrix
- Registry-owner resolution from the request host
- Registry-token verification
- Auth-policy and stamp-policy resolution
- Durable upload sessions and blob spooling
- Digest, offset, descriptor, and manifest validation
- Repository-state construction
- Per-owner/repository publication serialization
- Constrained requests to the control-plane signing service
- Read-after-write verification
- Published manifest and blob serving

The registry never receives or stores feed private keys.

### 7.3 Swarm/Bee

Bee stores:

- Immutable blob bytes
- Immutable manifest bytes
- Immutable auth and stamp policy documents
- Immutable repository-state snapshots
- Deterministic mutable feeds pointing to current auth, stamp, and repository state

### 7.4 Availability boundary

- Pulls depend on registry availability, owner resolution, and readable published Bee state.
- Pushes additionally depend on durable local staging and the internal control-plane signing service.
- If the control plane is unavailable, pushes fail closed; pulls continue from existing published state.
- V1 supports exactly one active writer registry process. A standby may be started after failure against the same restored staging state.

## 8. Registry bootstrap lifecycle

### 8.1 Inputs

Registry creation requires:

- Unique registry slug and hostname
- ENS name when ENS resolution is used
- Anonymous-pull setting
- Initial owner membership
- Valid Bee bootstrap postage batch

### 8.2 Bootstrap sequence

1. Create a registry record in `provisioning` state.
2. Generate a registry feed-owner key.
3. Encrypt the private key using AES-GCM under the configured master key.
4. Persist only ciphertext, nonce, key version, and public owner address.
5. Build the initial role-based auth policy.
6. Build the initial stamp policy containing the allowed writer roles and default batch.
7. Upload both policy documents to Bee using the bootstrap batch.
8. Use the internal control-plane signer to publish the deterministic auth and stamp feeds.
9. Read both feeds and documents back from Bee.
10. Validate document versions, owner, expected references, and policy contents.
11. Mark the registry `ready` only after both feeds verify.

### 8.3 Bootstrap failures

Registry creation must not report readiness when only part of bootstrap succeeds. A durable outbox records pending policy publication operations. Reconciliation retries idempotently. Operators can inspect provisioning state and the last failure without accessing secrets.

## 9. Authentication and authorization requirements

### SEC-001: Fail-closed bearer handling

Any missing, malformed, unverifiable, expired, or unsupported token must produce an authentication failure. Caller-supplied bearer text must never become an authorization subject.

### SEC-002: Separate token purposes

Session tokens and registry tokens must use separate signing keys, issuers, audiences, token types, and validators.

### SEC-003: Asymmetric registry tokens

The control plane signs registry tokens. Registry processes hold only public verification keys. Tokens carry a key ID to support rotation.

### SEC-004: Exact registry authorization

Registry-token validation must verify:

- Supported signing algorithm
- Key ID and signature
- Issuer and audience/service
- Token type
- Issued-at and expiry
- Exact repository scope
- Requested action (`pull` or `push`)

Substring scope matching is prohibited.

### SEC-005: Published policy enforcement

After token verification, the registry resolves the current auth policy and confirms that the verified role or anonymous client is permitted for the repository and action.

### SEC-006: Safe public DTOs

No API or UI response may expose:

- Password hashes
- Feed private-key plaintext or ciphertext
- Encryption nonces or master-key metadata sufficient for offline use
- Invite digests
- Session or registry signing private keys
- Internal publication credentials

### SEC-007: Feed-key encryption

Feed private keys must be encrypted with authenticated encryption. The master key is supplied through a secret file or secret-management integration and is not stored in SQLite, logs, images, or Git.

### SEC-008: Feed-key rotation

The system must support planned feed-owner rotation with documented policy and repository migration behavior. Key decrypt/sign operations must emit audit events without logging key material.

### SEC-009: Invite safety

Invite tokens must:

- Contain at least 192 bits of cryptographic randomness
- Be stored only as a one-way SHA-256 or keyed HMAC digest
- Be shown only at creation time
- Be single-use and expiry checked
- Be bound to the normalized invited email
- Support revocation before acceptance

### SEC-010: Browser security

Production UI operation requires secure cookies, CSRF protection on mutations, generic authentication errors, and rate limits for login, registration, invite, and token endpoints.

### SEC-011: Production configuration validation

Production startup must reject default or missing cryptographic secrets, insecure cookie configuration, invalid public URLs, and missing trusted-proxy/TLS configuration.

## 10. Stamp policy and postage requirements

### STAMP-001: Published stamp policy

Every ready registry has a readable deterministic stamp-policy feed and a valid current policy document.

### STAMP-002: Batch selection

Before accepting or finalizing a push, the registry resolves the current stamp policy and selects the batch allowed for the verified role and repository.

### STAMP-003: Batch propagation

The selected batch is passed explicitly through:

- Blob upload
- Manifest upload
- Repository-state upload
- Wrapped chunk upload
- SOC upload

A content reference must never be substituted for a postage batch ID.

### STAMP-004: Signing-service revalidation

The internal signing service verifies that:

- The registry service is authenticated
- The owner belongs to the requested registry
- The topic is an allowed deterministic policy or repository topic
- The selected batch is permitted by the current stamp policy
- The immutable reference has the expected format

### STAMP-005: Batch failures

Expired, depleted, missing, or rejected batches produce a dependency error that is distinguishable from authentication, authorization, and manifest-validation failures.

## 11. First-push and publication requirements

### PUB-001: First repository

A missing repository feed is treated as an empty generation-zero state only during an authorized manifest publication. Blob upload alone does not publish or create a repository.

### PUB-002: Validate before immutable upload

The registry parses and validates the manifest and referenced descriptors before uploading manifest bytes or the next repository state.

### PUB-003: Referenced blobs only

Only staged blobs referenced by the submitted manifest are copied into the next repository state. Unrelated staged blobs remain staged until used or expired.

### PUB-004: Generation progression

The first successful publication creates generation one. Every later successful publication increments the current generation by exactly one.

### PUB-005: Publication serialization

Manifest publication is serialized by registry owner and repository. Before feed update, the publisher re-reads current state and verifies the expected generation.

### PUB-006: Conflict behavior

If the generation changed, publication retries by rebuilding from the newest state when safe. Otherwise it returns a stable conflict response. Silent last-write-wins data loss is prohibited.

### PUB-007: Control-plane signed commit

The registry sends an authenticated internal request containing registry identity, feed owner, deterministic repository topic, immutable state reference, selected batch, expected generation, and operation ID.

### PUB-008: Read-after-write verification

A manifest PUT returns success only after the registry resolves the updated feed and verifies owner, repository, generation, state reference, tag, and manifest digest.

### PUB-009: Staging cleanup after commit

Only staging entries referenced by the successfully verified manifest are cleared. Cleanup failure is recorded and retried without reverting a committed publication.

### PUB-010: Idempotency

Publication operations carry stable operation IDs. Repeating a request after an uncertain response must not advance the feed twice or lose repository state.

## 12. Durable staging requirements

### STAGE-001: Streaming spool

Upload bodies are streamed to files under a configured staging root. Entire blobs must not be buffered in process memory or stored as SQLite BLOBs.

### STAGE-002: Metadata

A dedicated SQLite database stores upload ID, registry owner, repository, actor, offset, path, expected digest, state, timestamps, expiry, finalized Bee reference, and operation ID.

### STAGE-003: Ownership

Only the actor and repository that created a session may inspect, append, finalize, or cancel it.

### STAGE-004: Offset and range validation

PATCH and PUT operations validate content range and expected offset. Conflicts return the correct current range without corrupting staged bytes.

### STAGE-005: Digest verification

Finalization streams the staged file through SHA-256 and compares the complete canonical digest before upload to Bee.

### STAGE-006: Restart recovery

After process restart, active sessions and finalized-but-unpublished blob references remain usable until expiry.

### STAGE-007: Expiry and cleanup

Expired sessions are rejected and eventually removed. Cleanup is idempotent and covers metadata, spool files, and eligible orphaned Bee pins.

### STAGE-008: Quotas

Operators configure per-upload, per-repository, and total staging limits. Limit exhaustion fails before disk exhaustion and emits metrics and actionable errors.

### STAGE-009: Filesystem safety

Spool paths are derived from server-generated IDs, cannot escape the staging root, use restrictive permissions, and are never controlled directly by request paths.

## 13. Docker/OCI compatibility contract

### COMP-001: Published matrix

Documentation lists each supported endpoint, method, media type, client, and known limitation. The README must not claim complete Registry v2 compatibility.

### COMP-002: Required v1 workflows

The supported matrix must cover:

- Registry ping
- Token challenge and token acquisition
- Resumable blob upload start, status, append, finalize, and cancel
- Manifest PUT by tag
- Manifest GET and HEAD by tag and digest
- Blob GET and HEAD by digest
- OCI image manifests
- OCI image indexes and referenced platform manifests
- Anonymous pull when policy permits
- Authenticated reader and writer workflows

### COMP-003: Strict descriptors

Digest syntax, size, media type, schema version, config descriptor, layer descriptors, and index descriptors are validated before publication.

### COMP-004: Pull integrity

Returned content length and digest must agree with published descriptors. Corrupt or mismatched Bee content fails closed and emits an integrity alert.

### COMP-005: Unsupported operations

Deferred operations return stable, documented Distribution-style errors or method responses rather than ambiguous internal failures.

### COMP-006: Client matrix

CI pins and tests supported Docker and Podman versions. A client version is not claimed supported without a successful end-to-end push and pull.

## 14. Control-plane consistency requirements

### CP-001: Transactional local state

User, registry, membership, invite, and settings mutations use database transactions where multiple local records form one operation.

### CP-002: External publication outbox

Bee publication is represented as durable outbox work. Database state distinguishes pending, retrying, ready, and failed publication states.

### CP-003: Reconciliation

A reconciler retries idempotently and can repair database/feed drift. Operators can inspect status and retry without exposing credentials.

### CP-004: Schema integrity

SQLite migrations are versioned and tested. Foreign keys and uniqueness constraints enforce user, registry, membership, invite, and publication relationships.

### CP-005: Validation

Email, password, slug, hostname, ENS name, batch ID, registry ID, repository name, and scope inputs are normalized and validated before persistence.

### CP-006: Policy synchronization

Role, anonymous-pull, and batch changes publish new policy documents and do not report success until outbox/reconciliation state is visible. The UI must not claim publication when only local settings changed.

## 15. Error taxonomy

The registry and control plane distinguish:

| Class | Examples | Client behavior |
|---|---|---|
| Authentication | Missing, expired, malformed, wrong-signature token | `401` with appropriate challenge |
| Authorization | Verified identity lacks policy permission | `403` or Distribution-compatible denial |
| Validation | Bad digest, manifest, descriptor, range, scope, or input | Stable `4xx` with specific code |
| Conflict | Offset or repository generation changed | Stable conflict response with recovery data |
| Not found | Unknown registry, repository, tag, digest, upload | Distribution-compatible not-found code |
| Dependency | Bee, ENS RPC, signing service, or postage batch unavailable | Retryable `5xx`; dependency identified internally |
| Integrity | Read-back or digest mismatch | Fail closed; alert and `5xx` |
| Internal | Unexpected database, filesystem, or application failure | Generic client message; correlated structured log |

Secrets, password hashes, raw tokens, private keys, and internal topology must never appear in client error messages or logs.

## 16. Operational requirements

### OPS-001: Docker Compose reference stack

The repository provides a reproducible Compose deployment for registry, control plane, Bee, TLS proxy guidance, persistent volumes, migrations, and health checks.

### OPS-002: Lifecycle

Both binaries use explicit `http.Server` configuration, read/header/write/idle timeouts, context cancellation, SIGTERM/SIGINT handling, graceful shutdown, and database closure.

### OPS-003: Dependency timeouts

Bee and Ethereum RPC clients use bounded timeouts and propagate request cancellation.

### OPS-004: Health and readiness

- Liveness proves the process event loop is responsive.
- Registry readiness checks staging storage, public verification keys, and required Bee reads.
- Control-plane readiness checks SQLite, master-key availability, token signing, and configured Bee publication capability.

### OPS-005: Structured logs

Logs are structured and include component, operation ID, request ID, registry, repository, action, latency, result class, and dependency status. Credentials and key material are redacted.

### OPS-006: Metrics

At minimum expose:

- Request count, latency, and error class
- Active upload sessions and staged bytes
- Upload and publication duration
- Publication conflicts and retries
- Bee/RPC/signing dependency failures
- Outbox depth and age
- Cleanup results
- Read-back integrity failures

### OPS-007: Backup and restore

Document and test coordinated backup/restore of control-plane SQLite, staging SQLite/files, cryptographic configuration, and deployment configuration. Permanent image data remains in Bee.

### OPS-008: Upgrade and rollback

Every release defines migration order, compatibility window, rollback restrictions, and verification steps. Destructive migrations require a backup and explicit operator confirmation.

### OPS-009: Supply chain

Release CI produces container images, checksums, SBOMs, vulnerability results, dependency-license results, and immutable source/release references.

## 17. Performance and resource requirements

### PERF-001: Bounded memory

Blob upload and download memory usage is bounded independently of blob size. Streaming buffers are configurable and have safe defaults.

### PERF-002: Reference workload

The Compose acceptance environment must successfully push and pull:

- A small image under 100 MiB
- An image with at least one 1 GiB layer
- A multi-platform OCI index with at least two platform manifests

### PERF-003: Metadata latency

On the reference environment, local metadata and auth endpoints target p95 latency below 500 ms excluding explicitly reported external dependency latency.

### PERF-004: Backpressure

Disk quota, queue depth, and dependency saturation produce controlled rejection or retry behavior rather than unbounded goroutines, memory, or disk growth.

## 18. Delivery phases and gates

### Phase 0: Containment and baseline

Deliverables:

- Rotate exposed or potentially exposed password, invite, token-signing, and feed-signing material
- Remove production data from source/deployment artifacts
- Establish migration framework and deterministic fixtures
- Add security-regression and secret-scanning baselines

Exit gate:

- Old credentials and signer keys no longer work
- Git history, build context, container images, logs, and API responses contain no runtime secrets
- Build, format, vet, unit, and race baselines pass

### Phase 1: Secure trust boundary

Deliverables:

- SEC-001 through SEC-011
- CP-001 through CP-006
- Internal service authentication design for signing operations

Exit gate:

- Adversarial token suite passes
- Response-redaction suite passes
- Invite recipient, expiry, revocation, and single-use tests pass
- Key encryption and rotation tests pass
- Partial local/external failure tests leave recoverable state

### Phase 2: Correct Bee publication

Deliverables:

- STAMP-001 through STAMP-005
- PUB-001 through PUB-010, excluding later staging cleanup implementation where noted
- Real Bee integration environment

Exit gate:

- Clean registry bootstrap publishes and verifies both policies
- First push into a nonexistent repository succeeds against real Bee
- Subsequent pull verifies manifest and blob digests
- Wrong, expired, or depleted postage batches fail with the expected class
- Publication cannot succeed without read-after-write verification

### Phase 3: Durable staging and concurrency

Deliverables:

- STAGE-001 through STAGE-009
- Per-repository serialization and conflict behavior
- Cleanup and eligible Bee-unpin behavior

Exit gate:

- Upload resumes after registry restart
- Expired uploads are rejected and cleaned
- Quotas prevent disk exhaustion
- Concurrent pushes preserve all successful tags
- Crash points before and after feed update recover idempotently

### Phase 4: Docker/OCI compatibility

Deliverables:

- COMP-001 through COMP-006
- Docker and Podman compatibility matrix
- Multi-platform image support

Exit gate:

- Every supported workflow passes end to end against real Bee
- Unsupported workflows match documented behavior
- README and API documentation contain no broader claims

### Phase 5: Production operations and v1 release

Deliverables:

- OPS-001 through OPS-009
- PERF-001 through PERF-004
- Operator and incident runbooks

Exit gate:

- Clean-machine Compose installation passes
- Restart, backup/restore, key rotation, upgrade, and rollback drills pass
- CI release gates pass from a clean clone
- Release artifacts are traceable to the verified source commit

## 19. Acceptance scenarios

### AC-001: Raw bearer bypass is rejected

Given a policy allowing `role:write`, when a client sends `Bearer role:write` without a valid signature, then the registry returns an authentication failure and no upload session is created.

### AC-002: Wrong scope cannot push

Given a valid pull-only token or a token for another repository/service, when it attempts a push, then authorization fails before staging or Bee upload.

### AC-003: Sensitive fields are absent

Given registration, login, registry creation, listing, and detail responses, then password hashes, key material, invite digests, and encryption metadata are absent by schema and value scan.

### AC-004: Invite is email-bound

Given an invite for one normalized email, when another authenticated user attempts acceptance, then acceptance fails and the invite remains valid for the intended recipient.

### AC-005: Registry bootstrap is atomic to users

Given a Bee failure after one policy is published, when registry creation returns, then the registry is visibly provisioning or failed—not ready—and reconciliation can complete it idempotently.

### AC-006: First repository push

Given a ready registry with no repository feed, when an authorized writer pushes valid blobs and a manifest, then generation one is published and can be pulled.

### AC-007: Invalid manifest creates no publication artifacts

Given a manifest with missing or invalid references, when it is submitted, then no manifest, repository-state, chunk, or SOC upload occurs.

### AC-008: Unrelated staged blobs remain unpublished

Given two staged blobs but a manifest referencing one, when publication succeeds, then only the referenced blob appears in repository state and the other remains staged until expiry or later use.

### AC-009: Correct postage batch

Given a stamp policy selecting batch X, when a push publishes all objects and feed updates, then every Bee upload requiring postage carries X and no content reference is used as a batch ID.

### AC-010: Control-plane signing constraint

Given an authenticated registry service, when it requests a signature for an owner/topic not belonging to the registry or a batch not allowed by policy, then the control plane rejects the operation and emits an audit event.

### AC-011: Concurrent tags are preserved

Given two simultaneous pushes to different tags in one repository, when both report success, then the final state contains both tags and monotonically advanced generations.

### AC-012: Restart recovery

Given an upload paused after several chunks, when the registry restarts, then status reports the correct offset and upload can resume and finalize.

### AC-013: Read integrity failure

Given Bee returns bytes whose digest does not match published state, when a client pulls them, then the registry fails closed and emits an integrity metric and correlated error.

### AC-014: Multi-platform round trip

Given an OCI image index with two platform manifests, when Docker pushes and later pulls it through the reference deployment, then the index and platform content resolve correctly.

### AC-015: Control-plane outage behavior

Given published content and policies exist but the control plane is unavailable, pulls continue according to current policy while new pushes fail closed with a retryable dependency error.

## 20. Audit traceability matrix

| Audit ID | Verified finding | Requirements | Phase | Required evidence |
|---|---|---|---|---|
| AUD-001 | Arbitrary bearer value becomes subject | SEC-001, SEC-004 | 1 | AC-001 and adversarial token tests |
| AUD-002 | Token type, service, repo, and action ignored | SEC-002–SEC-005 | 1 | AC-002 and token matrix |
| AUD-003 | Password hashes and feed keys serialized | SEC-006 | 1 | AC-003 and schema/value scan |
| AUD-004 | Feed key stored as plaintext despite encrypted name | SEC-007, SEC-008 | 1 | Encryption, restart, and rotation tests |
| AUD-005 | Invite digest is reversible and not recipient-bound | SEC-009 | 1 | AC-004 and invite lifecycle suite |
| AUD-006 | Unsafe secret defaults, cookies, and browser mutations | SEC-010, SEC-011 | 1 | Production-config and browser-security tests |
| AUD-007 | Registry/settings publication is non-atomic | CP-001–CP-003, CP-006 | 1 | AC-005 and failure injection |
| AUD-008 | First repository requires pre-seeded state | PUB-001, PUB-004 | 2 | AC-006 |
| AUD-009 | State reference used as Bee postage batch | STAMP-002–STAMP-005 | 2 | AC-009 and real Bee header assertions |
| AUD-010 | Manifest uploaded before validation | PUB-002 | 2 | AC-007 |
| AUD-011 | All actor/repo staged blobs enter state | PUB-003, PUB-009 | 2 | AC-008 |
| AUD-012 | Concurrent publication can lose updates | PUB-005, PUB-006, PUB-010 | 3 | AC-011 and stress test |
| AUD-013 | Staging is ephemeral and expiry unenforced | STAGE-001–STAGE-007 | 3 | AC-012 and expiry tests |
| AUD-014 | Request bodies are read without bounds | STAGE-001, STAGE-008, PERF-001, PERF-004 | 3 | Large-body and quota tests |
| AUD-015 | One global registry signer cannot serve multiple owners | SEC-007, STAMP-004, PUB-007 | 2 | Multi-registry signing tests |
| AUD-016 | Memory server has no bootstrap path | PUB-001, OPS-001 | 2/5 | First-push fixture and Compose E2E |
| AUD-017 | Static host mapping fails with host ports | COMP-001, CP-005 | 4 | Host normalization table tests |
| AUD-018 | No server/client timeouts or graceful shutdown | OPS-002, OPS-003 | 5 | Shutdown and timeout tests |
| AUD-019 | No health, metrics, tracing, or structured request logs | OPS-004–OPS-006 | 5 | Endpoint and telemetry assertions |
| AUD-020 | No real Bee or Docker end-to-end gate | COMP-006, OPS-001 | 2/4/5 | Real Bee Docker/Podman CI jobs |
| AUD-021 | Low coverage and missing policy/publish/cmd tests | All phase gates | 0–5 | Package and risk-based coverage reports |
| AUD-022 | No CI, containers, deployment, SBOM, or release evidence | OPS-001, OPS-009 | 5 | Clean-clone release pipeline |
| AUD-023 | README overstates compatibility and contains stale claims/links | COMP-001, COMP-005 | 4/5 | Documentation verification gate |
| AUD-024 | Local database artifact contained sensitive material | SEC-006–SEC-009, Phase 0 | 0 | Rotation evidence and secret scan |
| AUD-025 | Expired-invite test did not test rejection | SEC-009 | 1 | Negative acceptance test |
| AUD-026 | SQLite schema lacks declared foreign-key relationships | CP-004 | 1 | Migration and constraint tests |

## 21. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Bee feed semantics differ from mocked assumptions | Publication failure or corruption | Real Bee integration begins in Phase 2 and gates later phases |
| Control plane becomes a push dependency | Push outage when unavailable | Explicit fail-closed behavior, readiness, retries, and published pull independence |
| Local spool fills disk | Registry outage | Quotas, backpressure, metrics, expiry, cleanup, dedicated volume guidance |
| SQLite contention under concurrent uploads | Latency or lock errors | Short transactions, WAL mode evaluation, bounded concurrency, stress tests |
| Master key loss | Feed keys become unrecoverable | Backup procedure, startup checks, rotation/versioning, recovery drill |
| Master key compromise | All stored feed keys at risk | Restrictive secret mounting, audit, rotation plan, optional future external KMS provider |
| Single writer limits availability | Push downtime during failover | Documented standby/restore procedure; active-active explicitly deferred |
| Protocol subset surprises clients | Client incompatibility | Published matrix and pinned Docker/Podman E2E tests |
| Immutable orphaned Bee content consumes postage | Resource leakage | Validate before upload, operation tracking, pin cleanup where supported, retention metrics |

## 22. Non-goals for this PRD

This PRD does not define:

- Hosted SaaS commercial features
- Active-active distributed consensus for feed writers
- General-purpose policy language
- Kubernetes production topology
- Complete garbage collection of globally replicated Swarm content
- Registry browsing or artifact-management UI
- Content signing, provenance, or admission policy beyond registry auth and integrity

These may receive separate post-v1 PRDs.

## 23. Definition of done

A requirement is done only when:

1. Its implementation is merged with tests written against the requirement.
2. Unit, race, integration, and relevant end-to-end tests pass.
3. Failure behavior and observability are verified.
4. Documentation reflects actual behavior.
5. The traceability matrix links the requirement to evidence.
6. No open P0 or P1 finding remains for its phase.
7. The phase exit gate passes from a clean environment.

The v1 release is done only when all six phase gates pass and the operator release checklist is signed off with source commit, container digests, SBOM, migration version, backup identifier, and rollback result.

## 24. Implementation planning contract

After this PRD is approved, a separate implementation plan will:

- Decompose work by the six phases above
- Respect phase dependencies and release gates
- Use test-driven development for behavior changes
- Name exact files and interfaces to introduce or modify
- Define tests before implementation steps
- Specify verification commands and expected evidence
- Avoid unrelated refactors
- Keep deferred scope out of v1 tasks

The implementation plan will be stored separately at:

`docs/superpowers/plans/2026-09-16-uncloud-registry-v1-completion.md`
