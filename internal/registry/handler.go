package registry

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/staging"
)

type ObjectStore interface {
	Get(ctx context.Context, ref string) ([]byte, error)
}

type ObjectUploader interface {
	Put(ctx context.Context, data []byte, batchID string) (string, error)
	// PutStream uploads a blob by streaming src with an EXACT size and an
	// explicit postage batch id — the registry blob finalization path. It
	// never buffers the whole payload in memory.
	PutStream(ctx context.Context, src io.Reader, size int64, batchID string) (string, error)
}

// ErrUploaderPreSideEffect marks an object-uploader failure that is
// CONCLUSIVELY PRE-SIDE-EFFECT: the object store never received (and never
// could have received) any of the blob's bytes, so finalization may safely
// RELEASE its durable claim and return the session to active with ZERO risk
// of a duplicate or orphaned external write. It is the ONLY classification
// that authorizes release. Every generic transport/HTTP/parse failure — the
// object store may or may not have stored the bytes and the returned
// reference is lost if the process dies before the receipt is persisted — is
// AMBIGUOUS and must RETAIN the claim fail-closed. The data-free text carries
// no operation token, reference, batch id, or raw cause.
var ErrUploaderPreSideEffect = errors.New("object upload failed before any external write")

type PullAuthorizer interface {
	Authorize(ctx context.Context, registry resolve.RegistryIdentity, repo string, principal auth.Principal) (bool, error)
}

type PushAuthorizer interface {
	Authorize(ctx context.Context, registry resolve.RegistryIdentity, repo string, principal auth.Principal) (batchID string, allowed bool, err error)
}

type Handler struct {
	Resolver       resolve.RegistryResolver
	Objects        ObjectStore
	Uploader       ObjectUploader
	PullAuthorizer PullAuthorizer
	PushAuthorizer PushAuthorizer
	Authenticator  Authenticator
	Staging        staging.RegistryStore
	Publisher      publish.Publisher
	// Preflight durably binds an EXPLICIT caller operation key to exactly one
	// logical payload (registry + owner + repo + tag + manifest digest) in the
	// control-plane operation store BEFORE any immutable object, feed, or
	// staging write. A reused key with a changed payload is a 409 here — with
	// zero object writes — and the durable binding survives process restarts.
	// It is nil in modes without a control plane (in-memory/dev), where the
	// feed read-back retry recognition still governs idempotency but no
	// durable cross-request binding exists.
	Preflight  publish.OperationBinder
	SessionTTL time.Duration
	AuthRealm  string
	// MaxUploadBytes bounds any single upload; when >0 it also bounds the
	// copy boundary the handler passes to streaming Append for requests
	// without an explicit Content-Range. Zero means the handler uses a
	// bounded default copy cap (the durable service still enforces the
	// configured per-upload quota atomically).
	MaxUploadBytes int64
}

func NewHandler(resolver resolve.RegistryResolver, objects ObjectStore, uploader ObjectUploader, pullAuthorizer PullAuthorizer, pushAuthorizer PushAuthorizer, authenticator Authenticator, stageStore staging.RegistryStore, publisher publish.Publisher, preflight publish.OperationBinder, authRealm string) http.Handler {
	return &Handler{
		Resolver:       resolver,
		Objects:        objects,
		Uploader:       uploader,
		PullAuthorizer: pullAuthorizer,
		PushAuthorizer: pushAuthorizer,
		Authenticator:  authenticator,
		Staging:        stageStore,
		Publisher:      publisher,
		Preflight:      preflight,
		SessionTTL:     15 * time.Minute,
		AuthRealm:      authRealm,
	}
}

// ServeHTTP authenticates every repo-scoped request BEFORE any policy
// resolution, storage read, Bee call, or staging side effect. The service
// bound into verification is the canonical host of the resolved registry
// identity; repository and action come from the matched route. Only a missing
// token on pull may degrade to the anonymous principal, and only so the auth
// policy can then explicitly allow or deny it.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v2" || r.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}

	repo, resource, reference, ok := parsePath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "unknown path")
		return
	}

	registryIdentity, err := h.Resolver.ResolveRegistry(r.Context(), r.Host)
	if err != nil {
		// Fixed centralized classification: a raw identity-resolution failure
		// (which can carry the host, repository, document references, decoder
		// or topology detail) must never cross the HTTP boundary.
		status, code, message := classifyRequestBoundaryError(err)
		writeError(w, status, code, message)
		return
	}

	action, ok := routeAction(resource, r.Method)
	if !ok {
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "unknown path")
		return
	}

	principal, err := h.Authenticator.Authenticate(r.Context(), r.Header.Get("Authorization"), registryIdentity.Host, repo, action)
	if err != nil {
		if errors.Is(err, auth.ErrMissingToken) && action == auth.ActionPull {
			principal = auth.Principal{Subject: auth.AnonymousSubject}
		} else {
			w.Header().Set("WWW-Authenticate", bearerChallenge(h.AuthRealm, registryIdentity.Host, repo, string(action)))
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", string(action)+" access denied")
			return
		}
	}

	switch resource {
	case "uploads":
		h.handleUpload(w, r, registryIdentity, repo, reference, principal)
	case "manifests":
		if r.Method == http.MethodPut {
			h.handleManifestPut(w, r, registryIdentity, repo, reference, principal)
			return
		}
		h.handlePullManifest(w, r, registryIdentity, repo, reference, principal)
	case "blobs":
		h.handlePullBlob(w, r, registryIdentity, repo, reference, principal)
	default:
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "unknown path")
	}
}

// routeAction maps a matched route resource to the registry action its
// authorization scope demands. Uploads (all methods) and manifest PUT are
// push; manifest reads and blob reads are pull. The action is derived before
// any handler work so method-specific dispatch inside handlers never runs
// before authentication.
func routeAction(resource string, method string) (auth.Action, bool) {
	switch resource {
	case "uploads":
		return auth.ActionPush, true
	case "manifests":
		if method == http.MethodPut {
			return auth.ActionPush, true
		}
		return auth.ActionPull, true
	case "blobs":
		return auth.ActionPull, true
	default:
		return "", false
	}
}

func (h *Handler) handlePullManifest(w http.ResponseWriter, r *http.Request, registryIdentity resolve.RegistryIdentity, repo string, reference string, principal auth.Principal) {
	authorized, err := h.PullAuthorizer.Authorize(r.Context(), registryIdentity, repo, principal)
	if err != nil {
		status, code, message := classifyRequestBoundaryError(err)
		writeError(w, status, code, message)
		return
	}
	if !authorized {
		w.Header().Set("WWW-Authenticate", bearerChallenge(h.AuthRealm, registryIdentity.Host, repo, "pull"))
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "pull access denied")
		return
	}

	state, err := h.Resolver.ResolveRepoState(r.Context(), registryIdentity, repo)
	if err != nil {
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", messageRepositoryNotFound)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	digest := reference
	if !strings.HasPrefix(reference, "sha256:") {
		var ok bool
		digest, ok = state.Tags[reference]
		if !ok {
			writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "tag not found")
			return
		}
	}

	desc, ok := state.Manifests[digest]
	if !ok {
		writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest not found")
		return
	}

	data, err := h.Objects.Get(r.Context(), desc.SwarmRef)
	if err != nil {
		writeError(w, http.StatusBadGateway, "MANIFEST_BLOB_UNKNOWN", messageManifestUnavailable)
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Type", desc.MediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *Handler) handlePullBlob(w http.ResponseWriter, r *http.Request, registryIdentity resolve.RegistryIdentity, repo string, digest string, principal auth.Principal) {
	authorized, err := h.PullAuthorizer.Authorize(r.Context(), registryIdentity, repo, principal)
	if err != nil {
		status, code, message := classifyRequestBoundaryError(err)
		writeError(w, status, code, message)
		return
	}
	if !authorized {
		w.Header().Set("WWW-Authenticate", bearerChallenge(h.AuthRealm, registryIdentity.Host, repo, "pull"))
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "pull access denied")
		return
	}

	state, err := h.Resolver.ResolveRepoState(r.Context(), registryIdentity, repo)
	if err != nil {
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", messageRepositoryNotFound)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	desc, ok := state.Blobs[digest]
	if !ok {
		writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not found")
		return
	}

	data, err := h.Objects.Get(r.Context(), desc.SwarmRef)
	if err != nil {
		writeError(w, http.StatusBadGateway, "BLOB_UNKNOWN", messageBlobUnavailable)
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if desc.MediaType != "" {
		w.Header().Set("Content-Type", desc.MediaType)
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request, registryIdentity resolve.RegistryIdentity, repo string, uploadID string, principal auth.Principal) {
	h.handleUploadV1(w, r, registryIdentity, repo, uploadID, principal)
}

func (h *Handler) handleManifestPut(w http.ResponseWriter, r *http.Request, registryIdentity resolve.RegistryIdentity, repo string, reference string, principal auth.Principal) {
	if strings.HasPrefix(reference, "sha256:") {
		writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", "manifest publish by digest is not supported in v1")
		return
	}

	actor := principal.Subject

	batchID, authorized, err := h.PushAuthorizer.Authorize(r.Context(), registryIdentity, repo, principal)
	if err != nil {
		status, code, message := classifyRequestBoundaryError(err)
		writeError(w, status, code, message)
		return
	}
	if !authorized {
		// An AUTHENTICATED principal denied by policy is 403 DENIED (not a
		// 401 challenge): re-challenging would loop the client.
		writeError(w, http.StatusForbidden, "DENIED", "push access denied")
		return
	}

	// Caller-supplied idempotency key: exactly one, validated against the
	// Task 10 operation-ID grammar BEFORE any resolve, object, feed, or
	// staging write. An invalid key is 400 with zero writes and the value is
	// never echoed.
	clientOperationID := r.Header.Get(OperationIDHeader)
	if clientOperationID != "" {
		if err := publish.ValidateOperationID(clientOperationID); err != nil {
			writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", "invalid operation ID: "+err.Error())
			return
		}
	}
	if second := r.Header.Values(OperationIDHeader); len(second) > 1 {
		writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", "duplicate operation-ID header")
		return
	}

	// Task 14 (round 2): an explicit operation key is ONLY ever accepted when
	// a durable binder is attached. Without one, a keyed request cannot be
	// durably bound to exactly one logical payload, so accepting the key would
	// allow changed-payload reuse and would echo caller-supplied ids as prior
	// success with no durable backing. Reject the keyed request with a fixed
	// 503 dependency response BEFORE the registry-identity resolver, any
	// object/feed write, or any staging consumption (the staged blobs remain,
	// ready for a no-key or properly-wired retry). No-key identity mode keeps
	// working — its idempotency is governed by the durable feed read-back
	// gate below, never by a fabricated identity.
	if clientOperationID != "" && h.Preflight == nil {
		writeError(w, http.StatusServiceUnavailable, ErrorCodeDependencyUnavailable, messageDependencyUnavailable)
		return
	}

	// Safe first-publication resolution: a CONCLUSIVELY absent repository feed
	// (generation zero, never written) is NOT an error — publication proceeds
	// to create the repository as generation zero. Network, timeout, decode,
	// integrity, and repo-mismatch failures stay typed errors. This optional
	// resolution runs ONLY on the authorized manifest PUT path; pull and list
	// paths keep the strict resolver and never synthesize missing state.
	//
	// Task 13 (round 1): the handler BRANCHES on found — when the feed is
	// conclusively absent it constructs the EXACT generation-zero document
	// (version 1, the canonical REQUEST repo, generation 0, NON-NIL empty
	// Tags/Manifests/Blobs maps) BEFORE handing it to the Publisher/Builder.
	// A found=true state is passed through UNCHANGED. The constructed maps are
	// fresh per request, so concurrent first pushes can never alias each
	// other's state.
	current, found, err := h.Resolver.ResolveRepoStateOptional(r.Context(), registryIdentity, repo)
	if err != nil {
		status, code, message := classifyPublicationError(err)
		writeError(w, status, code, message)
		return
	}
	if !found {
		current = spec.RepoStateDocument{
			Version:    1,
			Repo:       repo,
			Generation: 0,
			Tags:       map[string]string{},
			Manifests:  map[string]spec.ManifestDescriptor{},
			Blobs:      map[string]spec.BlobDescriptor{},
		}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, publish.MaxArtifactBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", "failed to read the manifest body")
		return
	}
	if len(body) > publish.MaxArtifactBodyBytes {
		writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", "manifest body exceeds the size bound")
		return
	}

	// Parse the artifact at the handler boundary with the SAME strict routine
	// the publisher runs (identical inputs → identical outcome), so the exact
	// referenced digest set is known before staging selection and clearing:
	// only referenced staged blobs enter the build input, and only they are
	// consumed after a successful publication. Unrelated staged blobs stay
	// staged.
	artifact, err := publish.ParseArtifact(r.Header.Get("Content-Type"), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", err.Error())
		return
	}
	referencedDigests := make(map[string]struct{}, len(artifact.References()))
	for _, ref := range artifact.References() {
		referencedDigests[ref.Digest] = struct{}{}
	}

	manifestDigest := computeDigest(body)
	stateFeed := spec.RepoStateFeedRef(registryIdentity.Owner, repo)
	input := publish.BuildInput{
		Repo:           repo,
		Tag:            reference,
		ManifestDigest: manifestDigest,
		ManifestJSON:   body,
		Manifest: spec.ManifestDescriptor{
			MediaType: r.Header.Get("Content-Type"),
			Size:      int64(len(body)),
		},
	}

	// Restart-safe retry recognition BEFORE any write: the effective feed is
	// the durable truth — if it already carries this exact tag→digest mapping
	// at generation >= 1, the client may be retrying a lost response. The
	// prior publication's IDENTITY is recovered from the DURABLE per-tag
	// publication provenance recorded in the immutable repo-state document —
	// the exact operation that produced THIS tag's mapping, retained across
	// unrelated publications — never re-inferred from the current generation.
	// The prior publication is re-VERIFIED through the production
	// feed/document path and the verified 201 is returned without touching
	// the feed, the object store, or staging again.
	//
	// An explicit key can fast-path ONLY when it equals the exact recorded
	// operation ID (and its durable binding is validated below, before any
	// answer). A DISTINCT explicit key — including an arbitrary, new, or
	// previously-conflicting one — never fast-paths: it falls through to the
	// preflight where it becomes a genuine new operation or a hard conflict,
	// and is never echoed as a prior success. A document WITHOUT provenance
	// (legacy valid state) falls through to a fresh publication. If the feed
	// advanced incompatibly, the effort falls through to a fresh publication
	// whose generation check at the control plane conflicts rather than
	// overwrites.
	if found && current.Generation >= 1 {
		if mappedDigest, mapped := current.Tags[reference]; mapped && mappedDigest == manifestDigest {
			if pub, hasProvenance := current.TagPublications[reference]; hasProvenance && pub.OperationID != "" && pub.Digest == manifestDigest {
				if clientOperationID == "" || clientOperationID == pub.OperationID {
					if clientOperationID != "" {
						// An explicit key is never echoed as prior success
						// without a VALID durable binding to this exact
						// logical payload: revalidate the binding first.
						if err := h.Preflight.Bind(r.Context(), publish.OperationBindingRequest{
							OperationID:    clientOperationID,
							RegistryID:     registryIdentity.RegistryID,
							Owner:          registryIdentity.Owner,
							Repo:           repo,
							Tag:            reference,
							ManifestDigest: manifestDigest,
						}); err != nil {
							status, code, message := classifyPublicationError(err)
							writeError(w, status, code, message)
							return
						}
					}
					verr := VerifyPublishedRetryState(r.Context(), h.Resolver.Feeds, h.Resolver.Docs, stateFeed, repo, reference, manifestDigest, pub.OperationID, input, artifact)
					if verr == nil {
						writePublishedSuccess(w, repo, reference, manifestDigest, pub.OperationID)
						return
					}
					if errors.Is(verr, ErrTargetNotCurrentState) {
						// Effective feed advanced incompatibly since
						// resolution: not a retry. Fall through to the normal
						// publish path.
					} else {
						status, code, message := classifyPublicationError(verr)
						writeError(w, status, code, message)
						return
					}
				}
				// A distinct explicit key: not a retry of the recorded
				// operation. Fall through to the preflight/publish path.
			}
			// No provenance for this tag (legacy document): the exact prior
			// operation identity is not recoverable and is NEVER fabricated —
			// fall through to a fresh publication.
		}
	}

	// Explicit-key PREFLIGHT binding BEFORE any immutable object write. The
	// control plane durably reserves this operation key for exactly this
	// logical payload (registry + owner + repo + tag + manifest digest), so a
	// reused key with a DIFFERENT payload is a 409 here — before the manifest
	// and draft-state objects are uploaded, before any feed write, and before
	// any staging consumption — and the durable binding survives process
	// restarts, so a reconstructed handler rejects the same conflict with
	// zero writes. The already-published case was answered above, so a
	// genuine retry never pays a binding call; a same-key-same-payload
	// request whose feed has NOT advanced passes the binding (a reservation
	// never blocks its matching commit) and proceeds to the normal publish
	// path. The key grammar was validated at the top of this handler, so an
	// invalid or oversized key never reaches the control plane.
	if clientOperationID != "" && h.Preflight != nil {
		if err := h.Preflight.Bind(r.Context(), publish.OperationBindingRequest{
			OperationID:    clientOperationID,
			RegistryID:     registryIdentity.RegistryID,
			Owner:          registryIdentity.Owner,
			Repo:           repo,
			Tag:            reference,
			ManifestDigest: manifestDigest,
		}); err != nil {
			status, code, message := classifyPublicationError(err)
			writeError(w, status, code, message)
			return
		}
	}

	stagedBlobs, err := h.Staging.ListStagedBlobs(r.Context(), repo, actor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "UNKNOWN", "internal server error")
		return
	}
	blobMap := make(map[string]spec.BlobDescriptor, len(stagedBlobs))
	for _, blob := range stagedBlobs {
		// Referenced-only staging selection: staged blobs this manifest does
		// not reference never enter the build input.
		if _, isRef := referencedDigests[blob.Digest]; !isRef {
			continue
		}
		blobMap[blob.Digest] = spec.BlobDescriptor{
			SwarmRef:  blob.SwarmRef,
			Size:      blob.Size,
			MediaType: blob.MediaType,
		}
	}

	operationID := clientOperationID
	if operationID == "" {
		operationID = publish.ComputeOperationID(registryIdentity.RegistryID, registryIdentity.Owner, repo, reference, manifestDigest, current.Generation)
	}
	input.StagedBlobs = blobMap
	// Byte-stable state rebuilds across retries: the state timestamp is
	// derived deterministically from the operation identity, never the clock.
	input.UpdatedAt = publish.DeterministicUpdatedAt(operationID)

	receipt, err := h.Publisher.PublishCommit(r.Context(), stateFeed, current, input, batchID, registryIdentity.RegistryID, registryIdentity.Owner, operationID)
	if err != nil {
		status, code, message := classifyPublicationError(err)
		writeError(w, status, code, message)
		return
	}

	// Read-after-write verification BEFORE the 201: the exact committed state
	// reference must resolve through the effective feed and decode to exact,
	// coherent repository state (generation, repo, tag→digest, manifest
	// descriptor and object bytes, referenced blob records). A 201 is only
	// ever produced after this verification passes; on failure the referenced
	// staging is RETAINED for a safe retry.
	if err := VerifyPublishedState(r.Context(), h.Resolver.Feeds, h.Resolver.Docs, receipt, input, artifact); err != nil {
		status, code, message := classifyPublicationError(err)
		writeError(w, status, code, message)
		return
	}

	// Consume ONLY the staged digests the published manifest referenced;
	// unrelated staged blobs remain staged for a later manifest.
	consumed := make([]string, 0, len(referencedDigests))
	for digest := range referencedDigests {
		consumed = append(consumed, digest)
	}
	if err := h.Staging.ClearStagedBlobsByDigest(r.Context(), repo, actor, consumed); err != nil {
		writeError(w, http.StatusInternalServerError, "UNKNOWN", "internal server error")
		return
	}

	writePublishedSuccess(w, repo, reference, manifestDigest, operationID)
}

// writePublishedSuccess emits the verified 201 publication response with the
// operation identity header the caller needs for restart-safe retries.
func writePublishedSuccess(w http.ResponseWriter, repo string, tag string, digest string, operationID string) {
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", repo, tag))
	w.Header().Set(OperationIDHeader, operationID)
	w.WriteHeader(http.StatusCreated)
}

func parsePath(path string) (repo string, resource string, reference string, ok bool) {
	trimmed := strings.TrimPrefix(path, "/v2/")
	for _, marker := range []struct {
		resource string
		token    string
	}{
		{resource: "uploads", token: "/blobs/uploads/"},
		{resource: "manifests", token: "/manifests/"},
		{resource: "blobs", token: "/blobs/"},
	} {
		if idx := strings.Index(trimmed, marker.token); idx >= 0 {
			return trimmed[:idx], marker.resource, trimmed[idx+len(marker.token):], true
		}
	}

	return "", "", "", false
}

func bearerChallenge(realm string, service string, repo string, action string) string {
	return fmt.Sprintf(`Bearer realm=%q,service=%q,scope=%q`, realm, service, "repository:"+repo+":"+action)
}

// Close releases any durable staging resource the handler owns (spool root +
// SQLite). Drivers backed by in-memory state close as a no-op. Called by the
// registry process on shutdown so a handle is never leaked.
func (h *Handler) Close() error {
	if c, ok := h.Staging.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func computeDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum[:])
}

// Fixed, data-free messages for the non-publication paths (pull and upload).
// Raw err.Error() text — which can carry repository, digest, swarm-reference,
// document, decoder, or store detail — never crosses the HTTP boundary; each
// path answers with exactly one of these fixed strings and a fixed status/code.
const (
	messageRepositoryNotFound  = "repository not found"
	messageManifestUnavailable = "the manifest content is unavailable"
	messageBlobUnavailable     = "the blob content is unavailable"
	messageUploadBodyRead      = "failed to read the upload body"
	messageBlobUploadFailed    = "blob upload failed"
)

func writeError(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{
			{
				"code":    code,
				"message": message,
			},
		},
	})
}
