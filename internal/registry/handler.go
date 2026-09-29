package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
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

// BoundedBytesReader reads an immutable ARTIFACT-CONTENT object (the Bee
// /bytes object path) with an EXPLICIT upper bound on the returned payload. It
// is the production counterpart of resolve.Reader for artifact BODIES — the
// read-after-write publication verification reads manifest and index-child
// bodies through it, bounded BEFORE allocation, while repo-state documents
// continue to flow through resolve.Reader (the /bzz document path).
// Production: *swarm.BeeObjectStore (ReadBounded) and the in-memory
// MemoryDocumentStore implement it; the verification fails closed if it is
// ever absent when an artifact body read is required (it never silently falls
// back to an unbounded read).
type BoundedBytesReader interface {
	ReadBounded(ctx context.Context, ref string, maxBytes int64) ([]byte, error)
}

type ObjectUploader interface {
	Put(ctx context.Context, data []byte, batchID string) (string, error)
	// PutStream uploads a blob by streaming src with an EXACT size and an
	// explicit postage batch id — the registry blob finalization path. It
	// never buffers the whole payload in memory.
	PutStream(ctx context.Context, src io.Reader, size int64, batchID string) (string, error)
}

// BoundedObjectStreamer streams an immutable object's content (the Bee
// /bytes object path) with an EXPLICIT total byte bound enforced DURING
// streaming: an object larger than maxBytes fails the stream closed, and no
// caller ever receives a truncated payload masquerading as an in-bounds
// object. It is the pull-integrity counterpart of BoundedBytesReader — blob
// content is streamed through it into a bounded verification temp file
// BEFORE HTTP success headers are committed, never buffered whole in memory.
// Production: *swarm.BeeObjectStore (OpenObject); the in-memory
// MemoryDocumentStore implements it for tests. The pull path fails closed if
// it is ever absent when a blob read is required (it never falls back to an
// unbounded in-memory read).
type BoundedObjectStreamer interface {
	OpenObject(ctx context.Context, ref string, maxBytes int64) (io.ReadCloser, error)
}

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
	// BoundedBytes reads immutable ARTIFACT-CONTENT objects (the Bee /bytes
	// path) with an explicit per-read byte bound, used by the post-commit
	// read-after-write verification for manifest and index-child BODIES. It is
	// the /bytes counterpart of Resolver.Docs (/bzz), which continues to serve
	// repo-state documents. NewHandler wires it from the object store when it
	// implements BoundedBytesReader; the verification fails closed (it never
	// falls back to an unbounded read) if it is absent when needed.
	BoundedBytes BoundedBytesReader
	// ObjectStream streams immutable BLOB content with an explicit total byte
	// bound (BoundedObjectStreamer) for pull-integrity PRE-VERIFICATION: blob
	// bytes are streamed through it into a bounded per-request temp file, hashed
	// and size-checked against the committed descriptor BEFORE any HTTP success
	// header is committed, and only the verified file is served. NewHandler
	// wires it from the object store when it implements BoundedObjectStreamer;
	// the blob pull fails closed (502, data-free) if it is absent when needed —
	// it never falls back to an unbounded in-memory read.
	ObjectStream BoundedObjectStreamer
	// Preflight durably binds an EXPLICIT caller operation key to exactly one
	// logical payload (registry + owner + repo + tag + manifest digest) in the
	// control-plane operation store BEFORE any immutable object, feed, or
	// staging write. A reused key with a changed payload is a 409 here — with
	// zero object writes — and the durable binding survives process restarts.
	// It is nil in modes without a control plane (in-memory/dev), where the
	// feed read-back retry recognition still governs idempotency but no
	// durable cross-request binding exists.
	Preflight publish.OperationBinder
	// Locker serializes the read/build/commit/verify decision per canonical
	// owner+repository inside the registry process. It is an in-process
	// corrective boundary only; cross-process correctness is enforced by the
	// authoritative control-plane generation comparison at commit. NewHandler
	// always installs a fresh locker; callers that construct Handler directly
	// must set it before serving manifest PUTs.
	Locker     *publish.RepositoryLocker
	SessionTTL time.Duration
	AuthRealm  string
	// MaxUploadBytes bounds any single upload; when >0 it also bounds the
	// copy boundary the handler passes to streaming Append for requests
	// without an explicit Content-Range. Zero means the handler uses a
	// bounded default copy cap (the durable service still enforces the
	// configured per-upload quota atomically).
	MaxUploadBytes int64
	// blobTempDir overrides the directory for pull pre-verification temp
	// files; empty uses the process temp directory. Test-only override for
	// deterministic cleanup assertions; production always uses the default.
	blobTempDir string
}

func NewHandler(resolver resolve.RegistryResolver, objects ObjectStore, uploader ObjectUploader, pullAuthorizer PullAuthorizer, pushAuthorizer PushAuthorizer, authenticator Authenticator, stageStore staging.RegistryStore, publisher publish.Publisher, preflight publish.OperationBinder, authRealm string) http.Handler {
	h := &Handler{
		Resolver:       resolver,
		Objects:        objects,
		Uploader:       uploader,
		PullAuthorizer: pullAuthorizer,
		PushAuthorizer: pushAuthorizer,
		Authenticator:  authenticator,
		Staging:        stageStore,
		Publisher:      publisher,
		Preflight:      preflight,
		Locker:         publish.NewRepositoryLocker(),
		SessionTTL:     15 * time.Minute,
		AuthRealm:      authRealm,
	}
	// Wire the bounded artifact-byte reader from the object store when it
	// implements it (production BeeObjectStore and the in-memory store both
	// do). When absent the verification fails closed at the first artifact
	// body read — it never silently falls back to an unbounded read.
	if bb, ok := objects.(BoundedBytesReader); ok {
		h.BoundedBytes = bb
	}
	// Wire the bounded blob-content streamer from the object store when it
	// implements it (production BeeObjectStore and the in-memory store both
	// do). When absent the blob pull fails closed before any success header —
	// it never silently falls back to an unbounded in-memory read.
	if os, ok := objects.(BoundedObjectStreamer); ok {
		h.ObjectStream = os
	}
	return h
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

	// Distribution Accept negotiation: serve the stored representation ONLY if
	// it is acceptable for the request (matching concrete type, matching
	// wildcard, or an absent Accept that accepts anything). We never transcode
	// OCI↔Docker and never descend into child manifests for the top-level, so
	// an explicitly unacceptable stored media type is a documented 404
	// MANIFEST_UNKNOWN with a fixed data-free message, and returns WITHOUT
	// touching the object store or any state.
	//
	// The negotiated representation depends on Accept, so `Vary: Accept` is
	// emitted on BOTH the served representation and the negotiation-rejected
	// response so a shared cache never serves one Accept's answer to another.
	w.Header().Add("Vary", "Accept")
	if !acceptAcceptsValues(r.Header.Values("Accept"), desc.MediaType) {
		writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", messageManifestNotAcceptable)
		return
	}

	// HEAD is descriptor-metadata-only: the committed descriptor's size is
	// authoritative and no body is sent, so no content read is required —
	// the body-bearing GET carries the pre-verification.
	if r.Method == http.MethodHead {
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Type", desc.MediaType)
		w.Header().Set("Content-Length", strconv.FormatInt(desc.Size, 10))
		w.WriteHeader(http.StatusOK)
		return
	}

	// GET pre-verifies the manifest BODY against its committed digest AND
	// size BEFORE any response byte is written: HTTP status cannot change
	// after bytes are sent, so a digest/size mismatch is a data-free error
	// with no body leaked, and corrupt content is never returned as 200.
	data, err := h.readVerifiedManifest(r.Context(), desc, digest)
	if err != nil {
		status, code, message := classifyPullContentFailure(pullKindManifest, err)
		writeError(w, status, code, message)
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Type", desc.MediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
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

	// HEAD is descriptor-metadata-only: Content-Length and the digest come
	// from the committed descriptor; no body is sent, so no content read is
	// required — the body-bearing GET carries the pre-verification.
	if r.Method == http.MethodHead {
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Length", strconv.FormatInt(desc.Size, 10))
		if desc.MediaType != "" {
			w.Header().Set("Content-Type", desc.MediaType)
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// GET pre-verifies the blob BODY into a bounded per-request temp file
	// BEFORE HTTP success headers are committed: content is streamed through
	// the bounded object stream, hashed with SHA-256 and size-checked against
	// the committed descriptor; only a fully verified file is served. A
	// digest/size mismatch or read failure is a data-free error BEFORE any
	// success byte — no corrupt bytes ever reach the client — and the temp
	// file is always removed on success and failure paths.
	verified, size, err := h.verifyBlobToTempFile(r.Context(), desc, digest)
	if err != nil {
		status, code, message := classifyPullContentFailure(pullKindBlob, err)
		writeError(w, status, code, message)
		return
	}
	defer func() {
		name := verified.Name()
		_ = verified.Close()
		_ = os.Remove(name)
	}()

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	if desc.MediaType != "" {
		w.Header().Set("Content-Type", desc.MediaType)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, verified)
}

func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request, registryIdentity resolve.RegistryIdentity, repo string, uploadID string, principal auth.Principal) {
	h.handleUploadV1(w, r, registryIdentity, repo, uploadID, principal)
}

// errPullIntegrity is the internal marker for pull content that EXISTS but
// failed SHA-256/size verification against its committed state descriptor.
// classifyPullContentFailure maps it to the DISTINCT 502 INTEGRITY_ERROR
// surface; every other read failure stays in the unavailability class.
var errPullIntegrity = errors.New("pull content integrity failure")

// pullKind distinguishes the manifest and blob pull paths for the error
// classifier (each has its own established unavailability code).
type pullKind int

const (
	pullKindManifest pullKind = iota
	pullKindBlob
)

// readVerifiedManifest reads and PRE-VERIFIES a manifest body against its
// committed descriptor BEFORE any response byte is written: the body read is
// bounded (BoundedBytesReader, never an unbounded fallback), the length must
// equal the committed size, and the SHA-256 digest must equal the committed
// digest. A size or digest mismatch is errPullIntegrity (data-free
// INTEGRITY_ERROR); a transport/read failure or a missing bounded reader is
// an unavailability-class failure. Corrupt manifest content is never
// returned as 200.
func (h *Handler) readVerifiedManifest(ctx context.Context, desc spec.ManifestDescriptor, digest string) ([]byte, error) {
	if h.BoundedBytes == nil {
		return nil, errors.New("manifest pull: bounded artifact byte reader is not configured")
	}
	data, err := h.BoundedBytes.ReadBounded(ctx, desc.SwarmRef, artifactReadBound(desc.Size, 0))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != desc.Size {
		return nil, fmt.Errorf("manifest body length %d does not match the descriptor size %d: %w", len(data), desc.Size, errPullIntegrity)
	}
	if computeDigest(data) != digest {
		return nil, fmt.Errorf("manifest body does not match the committed digest: %w", errPullIntegrity)
	}
	return data, nil
}

// verifyBlobToTempFile streams blob content from the BOUNDED object stream
// (BoundedObjectStreamer — never an unbounded in-memory fallback) into an
// exclusive per-request temp file while hashing it with SHA-256, then
// verifies the byte length AND the digest against the committed descriptor
// BEFORE the file is returned (positioned at offset 0 for serving). The
// per-request temp file makes concurrent pulls of the same blob independent.
// On ANY failure the temp file is removed and a classified error returned;
// on success the caller owns the file and MUST close and remove it (the
// handler's deferred cleanup covers success and error paths).
func (h *Handler) verifyBlobToTempFile(ctx context.Context, desc spec.BlobDescriptor, digest string) (*os.File, int64, error) {
	if h.ObjectStream == nil {
		return nil, 0, errors.New("blob pull: bounded object streamer is not configured")
	}
	tmpDir := h.blobTempDir
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	tmp, err := os.CreateTemp(tmpDir, "uncloud-pull-verify-*")
	if err != nil {
		return nil, 0, fmt.Errorf("create blob verification file: %w", err)
	}
	cleanup := func() {
		name := tmp.Name()
		_ = tmp.Close()
		_ = os.Remove(name)
	}

	src, err := h.ObjectStream.OpenObject(ctx, desc.SwarmRef, desc.Size+1)
	if err != nil {
		cleanup()
		return nil, 0, err
	}
	hasher := sha256.New()
	// The handler's own limit (desc.Size+1) enforces the descriptor bound so
	// an oversized object is detected as a SIZE mismatch (integrity); the
	// streamer's bound is defense-in-depth for any other caller.
	n, copyErr := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(src, desc.Size+1))
	closeErr := src.Close()
	if copyErr != nil {
		cleanup()
		return nil, 0, copyErr
	}
	if closeErr != nil {
		cleanup()
		return nil, 0, closeErr
	}
	if n != desc.Size {
		cleanup()
		return nil, 0, fmt.Errorf("blob body length %d does not match the descriptor size %d: %w", n, desc.Size, errPullIntegrity)
	}
	if "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != digest {
		cleanup()
		return nil, 0, fmt.Errorf("blob body does not match the committed digest: %w", errPullIntegrity)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, 0, fmt.Errorf("rewind verified blob file: %w", err)
	}
	return tmp, n, nil
}

// classifyPullContentFailure maps pull pre-verification failures to the
// fixed data-free surface: integrity mismatches (digest/size) are the
// DISTINCT 502 INTEGRITY_ERROR (content exists but disagrees with its
// committed descriptor), while transport/read/absent-reader failures stay
// the existing 502 unavailability codes (MANIFEST_BLOB_UNKNOWN /
// BLOB_UNKNOWN). The raw cause never crosses the HTTP boundary.
func classifyPullContentFailure(kind pullKind, err error) (int, string, string) {
	if errors.Is(err, errPullIntegrity) {
		return http.StatusBadGateway, ErrorCodeIntegrity, messageContentIntegrity
	}
	if kind == pullKindManifest {
		return http.StatusBadGateway, "MANIFEST_BLOB_UNKNOWN", messageManifestUnavailable
	}
	return http.StatusBadGateway, "BLOB_UNKNOWN", messageBlobUnavailable
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
	referencedBlobDigests := make(map[string]struct{})
	referencedManifestDigests := make(map[string]struct{})
	for _, ref := range artifact.References() {
		// The referenced digest set is split by NAMESPACE: an image index's
		// operands are child MANIFESTS, resolved exclusively in the manifest/
		// artifact namespace (comitted manifests), while an ordinary
		// manifest's operands are BLOBS resolved in the blob/staging
		// namespace. A child-manifest digest is NEVER treated as a blob — it
		// must not be listed, claimed, or consumed as a staged blob even when
		// a staged blob row merely collides with it by digest.
		if artifact.Kind == publish.ArtifactKindIndex {
			referencedManifestDigests[ref.Digest] = struct{}{}
		} else {
			referencedBlobDigests[ref.Digest] = struct{}{}
		}
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

	// The ENTIRE read/build/commit/verify decision for one owner+repository is
	// serialized through the per-repository publication lock, so two concurrent
	// publications to the same owner+repo cannot interleave their state reads,
	// object writes, commits, or staging consumption. Current repository state
	// is RE-RESOLVED inside the lock — a state read taken before waiting may be
	// stale by the time the lock is granted — and every side effect (retry
	// recognition, preflight binding, staging read, object upload, feed commit,
	// read-after-write verification, staging consumption) happens under it. A
	// canceled waiter therefore performs ZERO immutable/feed/staging writes.
	//
	// The lock is an IN-PROCESS corrective boundary only. Cross-process
	// correctness across independent registry instances is enforced by the
	// AUTHORITATIVE control-plane generation comparison at commit (see
	// PublishCommitWithConflictRebuild), never by this lock alone.
	err = h.Locker.WithLock(r.Context(), registryIdentity.Owner, repo, func(ctx context.Context) error {
		// Re-resolve the current state inside the lock. Safe first-publication
		// resolution: a CONCLUSIVELY absent repository feed (generation zero,
		// never written) is NOT an error — publication proceeds to create the
		// repository as generation zero. Network, timeout, decode, integrity,
		// and repo-mismatch failures stay typed errors. When the feed is absent
		// the handler constructs the EXACT generation-zero document (version 1,
		// the canonical REQUEST repo, generation 0, NON-NIL empty Tags/
		// Manifests/Blobs maps); found=true state is passed through UNCHANGED.
		// The constructed maps are fresh per request, so concurrent first pushes
		// can never alias each other's state.
		current, found, err := h.Resolver.ResolveRepoStateOptional(ctx, registryIdentity, repo)
		if err != nil {
			return err
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

		// Restart-safe retry recognition inside the lock, against the freshly
		// resolved state: if the effective feed already carries this exact
		// tag→digest mapping at generation >= 1, the client may be retrying a
		// lost response. The prior publication's IDENTITY is recovered from the
		// DURABLE per-tag publication provenance in the immutable repo-state
		// document — the exact operation that produced THIS tag's mapping,
		// retained across unrelated publications — never re-inferred from the
		// current generation. The prior publication is re-VERIFIED through the
		// production feed/document path and the verified 201 is returned
		// without touching the feed, the object store, or staging again.
		//
		// An explicit key can fast-path ONLY when it equals the exact recorded
		// operation ID (and its durable binding is validated below, before any
		// answer). A DISTINCT explicit key never fast-paths. A document WITHOUT
		// provenance (legacy valid state) falls through to a fresh publication.
		// boundOperationID tracks the identity (if any) the fast-path retry
		// recognition below has ALREADY durably preflight-bound in THIS
		// request, so the universal preflight bind further down never repeats
		// an identical bind call for the same identity/payload it just made.
		boundOperationID := ""

		if found && current.Generation >= 1 {
			if mappedDigest, mapped := current.Tags[reference]; mapped && mappedDigest == manifestDigest {
				if pub, hasProvenance := current.TagPublications[reference]; hasProvenance && pub.OperationID != "" && pub.Digest == manifestDigest {
					if clientOperationID == "" || clientOperationID == pub.OperationID {
						if clientOperationID != "" {
							// An explicit key is never echoed as prior success
							// without a VALID durable binding to this exact
							// logical payload: revalidate the binding first.
							if err := h.Preflight.Bind(ctx, publish.OperationBindingRequest{
								OperationID:    clientOperationID,
								RegistryID:     registryIdentity.RegistryID,
								Owner:          registryIdentity.Owner,
								Repo:           repo,
								Tag:            reference,
								ManifestDigest: manifestDigest,
							}); err != nil {
								return err
							}
							boundOperationID = clientOperationID
						}
						verr := VerifyPublishedRetryState(ctx, h.Resolver.Feeds, h.Resolver.Docs, h.BoundedBytes, stateFeed, repo, reference, manifestDigest, pub.OperationID, input, artifact)
						if verr == nil {
							// The prior attempt for THIS operation committed and was
							// verified. It may have crashed before consuming the
							// staged rows it claimed under pub.OperationID; finish
							// those surviving claims now. Claim cleanup is part of
							// this operation's own state, so a consume failure FAILS
							// CLOSED — the verified 201 is withheld and the fixed
							// error surface returned instead. The client's exact
							// retry then re-enters this fast path, re-verifies,
							// retries the consumption, and only after it succeeds
							// receives the verified 201. Returning 201 while a
							// quota-charged claim survives would strand the charge
							// forever; this never consumes rows owned by a different
							// operation.
							consumed := make([]string, 0, len(referencedBlobDigests))
							for digest := range referencedBlobDigests {
								consumed = append(consumed, digest)
							}
							if pub.OperationID != "" {
								if err := h.Staging.ConsumeStagedForPublish(ctx, repo, actor, pub.OperationID, consumed); err != nil {
									return err
								}
							}
							writePublishedSuccess(w, repo, reference, manifestDigest, pub.OperationID)
							return nil
						}
						if !errors.Is(verr, ErrTargetNotCurrentState) {
							return verr
						}
						// Effective feed advanced incompatibly: not a retry.
						// Fall through to a fresh publication whose generation
						// check at the control plane conflicts rather than
						// overwrites.
					}
					// A distinct explicit key: not a retry. Fall through to the
					// preflight/publish path. No-provenance documents also fall
					// through; the exact prior operation identity is NEVER
					// fabricated.
				}
			}
		}

		// The STABLE logical publication identity is derived from the CURRENT
		// (lock-resolved) generation when the caller supplied no explicit key:
		// two concurrent publications to the same owner+repo get distinct
		// deterministic identities matching their actual resulting
		// generations, while a lost-response retry of one logical publication
		// recomputes the identical identity and timestamp. This identity is
		// what is recorded as durable per-tag provenance, returned to the
		// caller, and durably bound below — it is NEVER the per-attempt
		// FeedSigner identity a conflict rebuild derives internally (see
		// Publisher.PublishCommitWithConflictRebuild), so it stays fixed
		// across a one-time rebuild.
		operationID := clientOperationID
		if operationID == "" {
			operationID = publish.ComputeOperationID(registryIdentity.RegistryID, registryIdentity.Owner, repo, reference, manifestDigest, current.Generation)
		}

		// PREFLIGHT binding BEFORE any immutable object write, for EVERY
		// logical publication identity — generated or explicit. The control
		// plane durably reserves this identity for exactly this logical
		// payload: a reused key with a DIFFERENT payload is a hard 409 here
		// (before any object upload, feed write, or staging consumption), and
		// the durable binding survives process restarts. Binding a GENERATED
		// identity too (not just an explicit client key) is what lets a later
		// one-time conflict rebuild still authenticate at the control plane:
		// the rebuild's recomputed generated-form check no longer matches (it
		// targets a fresh generation), so it depends on THIS binding, reserved
		// before the conflicted first attempt, surviving the conflict. Skipped
		// when the fast-path retry recognition above ALREADY durably bound
		// this EXACT identity for this exact payload moments ago — never a
		// second identical bind call for the same request.
		if h.Preflight != nil && operationID != boundOperationID {
			if err := h.Preflight.Bind(ctx, publish.OperationBindingRequest{
				OperationID:    operationID,
				RegistryID:     registryIdentity.RegistryID,
				Owner:          registryIdentity.Owner,
				Repo:           repo,
				Tag:            reference,
				ManifestDigest: manifestDigest,
			}); err != nil {
				return err
			}
		}

		// Determine the referenced staged candidates from the CURRENT
		// publishable listing (only genuinely finalized, non-expired rows).
		// Then ATOMICALLY claim them under operationID BEFORE any immutable
		// object or feed write: the claim re-reads authoritative row state
		// inside one serialized write transaction, so a candidate row that
		// cleanup won (expiring/removed) or a FOREIGN operation claimed
		// between this listing and the claim FAILS the whole claim closed and
		// this publication makes ZERO immutable-object, feed, or
		// staging-consumption writes. This closes the cross-process
		// publication-versus-unpin race: a manifest is never committed
		// referencing staged content that cleanup concurrently unpinned. The
		// descriptors fed to the build are the FRESH claim-time descriptors
		// returned by the claim — never the stale pre-claim listing. A
		// referenced digest that was claimed by a PRIOR crashed attempt of
		// THIS SAME operation (a surviving claim) is reacquired idempotently.
		stagedBlobs, err := h.Staging.ListStagedBlobs(ctx, repo, actor)
		if err != nil {
			return err
		}
		present := map[string]struct{}{}
		for _, blob := range stagedBlobs {
			if _, isRef := referencedBlobDigests[blob.Digest]; !isRef {
				continue
			}
			present[blob.Digest] = struct{}{}
		}
		// Digests already durably claimed by THIS operation from a prior
		// crashed/retried attempt (rows in the publication-owned claimed
		// state owned by operationID).
		owned, err := h.Staging.ClaimedDigests(ctx, repo, actor, operationID)
		if err != nil {
			return err
		}

		// A referenced digest is genuinely UNRESOLVABLE only when it is
		// neither a staged candidate, nor already committed in repository
		// state, nor a surviving same-operation claim. In that case the
		// publication is impossible and the builder reports the exact missing
		// reference (400) — so claim NOTHING: the staged candidates stay
		// finalized and visible, and the failed publication performs zero
		// immutable/feed/staging-mutation writes. This preserves the contract
		// that a manifest referencing a never-staged, never-committed blob
		// fails typed (400) before any fence or external write.
		unresolvable := false
		for digest := range referencedBlobDigests {
			// Ordinary manifest operands are BLOBS: they resolve through a
			// staged candidate, an already-committed blob record, or a
			// surviving same-operation staging claim.
			if _, isCand := present[digest]; isCand {
				continue
			}
			if _, committed := current.Blobs[digest]; committed {
				continue
			}
			if _, reused := owned[digest]; reused {
				continue
			}
			unresolvable = true
			break
		}
		for digest := range referencedManifestDigests {
			// An index child manifest is a committed MANIFEST — never a staged
			// blob — so it resolves ONLY through the manifests map (the
			// authoritative record a previously-published single-platform
			// manifest left behind). Blob staging is never consulted for a
			// child-manifest digest, and v1 has no staged-manifest transport
			// (a manifest PUT publishes directly).
			if _, committedManifest := current.Manifests[digest]; committedManifest {
				continue
			}
			unresolvable = true
			break
		}
		if unresolvable {
			// Let the builder report the missing reference with the exact
			// typed 400; feed the plain finalized listing as input (no claim,
			// no staging mutation).
			blobMap := make(map[string]spec.BlobDescriptor, len(stagedBlobs))
			for _, blob := range stagedBlobs {
				if _, isRef := referencedBlobDigests[blob.Digest]; !isRef {
					continue
				}
				blobMap[blob.Digest] = spec.BlobDescriptor{
					SwarmRef:  blob.SwarmRef,
					Size:      blob.Size,
					MediaType: blob.MediaType,
				}
			}
			input.StagedBlobs = blobMap
		} else {
			// Claim the union of staged candidates and surviving same-operation
			// claims for every referenced digest. ClaimStagedForPublish claims
			// the finalized candidates, reacquires the already-claimed-by-this-op
			// rows, and fails the WHOLE claim closed if any referenced digest's
			// row became unpinnable (cleanup won / foreign claim / expiry)
			// between the listing and the commit — zero external writes.
			claimSet := make(map[string]struct{}, len(present)+len(owned))
			for d := range present {
				claimSet[d] = struct{}{}
			}
			for d := range owned {
				if _, isRef := referencedBlobDigests[d]; isRef {
					claimSet[d] = struct{}{}
				}
			}
			claimDigests := make([]string, 0, len(claimSet))
			for d := range claimSet {
				claimDigests = append(claimDigests, d)
			}
			sort.Strings(claimDigests)
			if len(claimDigests) == 0 {
				// Nothing to fence: every referenced digest is already
				// committed in repository state (no staged candidate, no
				// surviving same-operation claim). Proceed with an empty
				// staged input.
				input.StagedBlobs = map[string]spec.BlobDescriptor{}
			} else {
				claimedBlobs, err := h.Staging.ClaimStagedForPublish(ctx, repo, actor, operationID, claimDigests)
				if err != nil {
					return err
				}
				blobMap := make(map[string]spec.BlobDescriptor, len(claimedBlobs))
				for _, blob := range claimedBlobs {
					blobMap[blob.Digest] = spec.BlobDescriptor{
						SwarmRef:  blob.SwarmRef,
						Size:      blob.Size,
						MediaType: blob.MediaType,
					}
				}
				input.StagedBlobs = blobMap
			}
		}

		// Byte-stable state rebuilds across retries and conflict rebuilds: the
		// state timestamp is derived deterministically from the STABLE
		// publication identity, never the clock, and never the per-attempt
		// FeedSigner identity.
		input.UpdatedAt = publish.DeterministicUpdatedAt(operationID)

		// Publish through the conflict-safe commit path. On an AUTHORITATIVE
		// generation conflict (feed advanced elsewhere) it re-resolves the
		// newest state and rebuilds ONCE, keeping the same stable publication
		// identity/timestamp but deriving a FRESH per-attempt FeedSigner
		// identity for the rebuilt attempt (see ComputeCommitAttemptID), so
		// concurrent publications and crash-point retries advance the feed at
		// most once per resolved logical publication. Distinct logical
		// publications never inherit another's success.
		receipt, err := h.Publisher.PublishCommitWithConflictRebuild(ctx, stateFeed, current, input, batchID, registryIdentity.RegistryID, registryIdentity.Owner, operationID, func(cctx context.Context) (spec.RepoStateDocument, bool, error) {
			return h.Resolver.ResolveRepoStateOptional(cctx, registryIdentity, repo)
		})
		if err != nil {
			return err
		}

		// Read-after-write verification BEFORE the 201: the exact committed
		// state reference must resolve through the effective feed and decode to
		// exact, coherent repository state. A 201 is only ever produced after
		// this verification passes; on failure the referenced staging is
		// RETAINED for a safe retry (never cleared before verified publication).
		if err := VerifyPublishedState(ctx, h.Resolver.Feeds, h.Resolver.Docs, h.BoundedBytes, receipt, input, artifact); err != nil {
			return err
		}

		// Consume ONLY the staged rows claimed by THIS operation and referenced by
		// the published manifest, WITHOUT unpinning; unrelated staged blobs and
		// rows claimed by a DIFFERENT operation remain staged. This is the
		// publication-owned consume: it never clears another operation's claim.
		consumed := make([]string, 0, len(referencedBlobDigests))
		for digest := range referencedBlobDigests {
			consumed = append(consumed, digest)
		}
		if err := h.Staging.ConsumeStagedForPublish(ctx, repo, actor, operationID, consumed); err != nil {
			return err
		}

		writePublishedSuccess(w, repo, reference, manifestDigest, operationID)
		return nil
	})

	if err != nil {
		status, code, message := classifyPublicationError(err)
		writeError(w, status, code, message)
	}
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
	messageRepositoryNotFound    = "repository not found"
	messageManifestUnavailable   = "the manifest content is unavailable"
	messageBlobUnavailable       = "the blob content is unavailable"
	messageUploadBodyRead        = "failed to read the upload body"
	messageBlobUploadFailed      = "blob upload failed"
	messageManifestNotAcceptable = "the stored manifest representation is not acceptable for the requested media types"
)

// Accept negotiation is implemented in accept.go (RFC 9110 §12.4.2/§12.5.1).

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
