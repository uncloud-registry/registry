package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// The manifest/publication error surface is ENTIRELY centralized here: typed
// error classes, one classifier to public responses, and the read-after-write
// verification that gates every 201. Every public status/message is fixed and
// data-free — no err.Error() text, marker, digest, ref, host, or topology ever
// crosses the HTTP boundary. The three typed classes retain the root cause
// ONLY as a PRIVATE diagnostic (reachable for internal logging via the
// unexported diagnose method); the EXPORTED surface is data-free: Error() is
// the fixed public message, Unwrap() returns ONLY the fixed safe class
// sentinel, and there are no cause/detail accessors — so the entire
// externally traversable unwrap chain carries no raw detail. errors.As still
// classifies the typed value and errors.Is matches the safe sentinel.

// Fixed safe class sentinels: Unwrap() on the typed classes returns exactly
// one of these — never the private diagnostic cause.
var (
	// ErrPublicationUnverified is the fixed safe sentinel of IntegrityError.
	ErrPublicationUnverified = errors.New("published repository state could not be verified")
	// ErrDependencyUnavailable is the fixed safe sentinel of DependencyError.
	ErrDependencyUnavailable = errors.New("a required service is temporarily unavailable")
	// ErrPublicationConflict is the fixed safe sentinel of ConflictError.
	ErrPublicationConflict = errors.New("the repository publication conflicts with an existing operation")
)

// IntegrityError is the fail-closed class for a publication whose committed
// outcome cannot be VERIFIED through the production feed/document path (stale
// feed, missing/malformed state, generation or repo mismatch, tag/digest
// mismatch, missing or forged publication provenance, manifest-object or
// blob-record incoherence).
type IntegrityError struct{ cause error }

func (e *IntegrityError) Error() string { return ErrPublicationUnverified.Error() }
func (e *IntegrityError) Unwrap() error { return ErrPublicationUnverified }

// diagnose exposes the private causal chain for INTERNAL logging only. It is
// never reachable through the exported surface; no caller of the public API
// can obtain the cause.
func (e *IntegrityError) diagnose() error { return e.cause }

// DependencyError is the class for a required service being temporarily
// unavailable (control-plane feed signer, Bee, internal credential,
// identity/policy consultation): retryable.
type DependencyError struct{ cause error }

func (e *DependencyError) Error() string { return ErrDependencyUnavailable.Error() }
func (e *DependencyError) Unwrap() error { return ErrDependencyUnavailable }

func (e *DependencyError) diagnose() error { return e.cause }

// ConflictError is the class for an idempotency/generation conflict: reusing
// one operation identity with different input, or the repository generation
// having advanced elsewhere. The caller must NOT retry the same request body
// blindly; resolve the conflict first.
type ConflictError struct{ cause error }

func (e *ConflictError) Error() string { return ErrPublicationConflict.Error() }
func (e *ConflictError) Unwrap() error { return ErrPublicationConflict }

func (e *ConflictError) diagnose() error { return e.cause }

// newIntegrityError wraps a diagnostic cause into the data-free IntegrityError
// class. Only the class travels outward; the cause is private.
func newIntegrityError(cause error) error { return &IntegrityError{cause: cause} }

// newDependencyError wraps a diagnostic cause into the data-free
// DependencyError class.
func newDependencyError(cause error) error { return &DependencyError{cause: cause} }

// newConflictError wraps a diagnostic cause into the data-free
// ConflictError class.
func newConflictError(cause error) error { return &ConflictError{cause: cause} }

// OperationIDHeader carries the stable caller-visible operation identity on
// every successful (201) publication response and accepts the caller-provided
// idempotency key on the request. The request-side value is validated with the
// exact Task 10 operation-ID grammar before any write.
const OperationIDHeader = "X-Uncloud-Operation-Id"

// Stable public error codes. These are the fixed wire contract; never extend
// without a plan-level decision.
const (
	// ErrorCodeDenied is 403: an authenticated principal is denied by policy.
	ErrorCodeDenied = "DENIED"
	// ErrorCodeManifestInvalid is 400: manifest body/reference validation.
	ErrorCodeManifestInvalid = "MANIFEST_INVALID"
	// ErrorCodeManifestConflict is 409: idempotency or generation conflict.
	ErrorCodeManifestConflict = "MANIFEST_CONFLICT"
	// ErrorCodePublicationUnverified is 502: read-after-write verification of
	// the committed outcome failed; the request is safe to retry (staging is
	// retained).
	ErrorCodePublicationUnverified = "PUBLICATION_UNVERIFIED"
	// ErrorCodeDependencyUnavailable is 503: the control plane / Bee is
	// temporarily unavailable; retryable.
	ErrorCodeDependencyUnavailable = "DEPENDENCY_UNAVAILABLE"
	// ErrorCodeInternal is 500: an unknown internal failure; the caller may
	// retry but the operator should investigate.
	ErrorCodeInternal = "UNKNOWN"
)

// ErrTargetNotCurrentState is returned by VerifyPublishedRetryState when the
// effective repository state does NOT currently carry the request's tag→digest
// target — the feed advanced incompatibly since resolution. The retry gate
// must NOT report success, and must fall through to a fresh publication whose
// generation check at the control plane conflicts rather than overwrites.
var ErrTargetNotCurrentState = errors.New("publication target is not the current repository state")

// fixedPublicMessages holds the fixed, data-free messages for every stable
// class. The validation class carries the validation error's own message
// (itself a fixed contract of the publish package — never body echo).
const (
	messageUnverified            = "the published repository state could not be verified; retain the request and retry"
	messageConflict              = "the request conflicts with an already-recorded publication or with a newer repository generation"
	messageDependencyUnavailable = "a required service is temporarily unavailable; retain the request and retry"
	messageUnknown               = "internal server error"
)

// classifyPublicationError is the SINGLE centralized mapper from publication
// errors to the public HTTP surface. Every branch yields a fixed status, a
// fixed code, and a fixed data-free message. Raw errors (default) collapse to
// 500 UNKNOWN with the fixed generic message — never their text.
func classifyPublicationError(err error) (int, string, string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return http.StatusServiceUnavailable, ErrorCodeDependencyUnavailable, messageDependencyUnavailable
	case errors.As(err, new(*ConflictError)):
		return http.StatusConflict, ErrorCodeManifestConflict, messageConflict
	case errors.Is(err, publish.ErrCommitConflict):
		return http.StatusConflict, ErrorCodeManifestConflict, messageConflict
	case errors.As(err, new(*DependencyError)):
		return http.StatusServiceUnavailable, ErrorCodeDependencyUnavailable, messageDependencyUnavailable
	case errors.Is(err, publish.ErrCommitBackend),
		errors.Is(err, publish.ErrCommitUnauthorized),
		errors.Is(err, publish.ErrCommitUnknownRegistry),
		errors.Is(err, publish.ErrCommitMalformed):
		return http.StatusServiceUnavailable, ErrorCodeDependencyUnavailable, messageDependencyUnavailable
	case errors.As(err, new(*IntegrityError)):
		return http.StatusBadGateway, ErrorCodePublicationUnverified, messageUnverified
	case errors.As(err, new(*publish.ValidationError)):
		// The validation message is itself a fixed contract of the publish
		// package (no body echo, no marker leakage).
		return http.StatusBadRequest, ErrorCodeManifestInvalid, err.Error()
	default:
		return http.StatusInternalServerError, ErrorCodeInternal, messageUnknown
	}
}

// VerifyPublishedState performs the exact read-after-write verification of a
// publication receipt through the PRODUCTION resolver/document path — never an
// in-memory cache. The effective repository feed must resolve to EXACTLY the
// committed state reference; that document must decode to repository state
// whose generation, repo, tag→digest mapping, DURABLE per-tag publication
// provenance (exact operation identity, applied generation, digest), manifest
// descriptor (including the exact committed manifest reference), manifest
// object bytes, and referenced blob records are all exact and coherent. Any
// mismatch is a fail-closed *IntegrityError: the caller must NOT report
// success and MUST retain staging for a safe retry. A read-side timeout
// collapses to the dependency class (retryable), never to success.
func VerifyPublishedState(ctx context.Context, feeds resolve.FeedResolver, docs resolve.Reader, receipt publish.PublicationReceipt, input publish.BuildInput, artifact publish.Artifact) error {
	stateRef, err := feeds.ResolveFeed(ctx, receipt.StateFeed)
	if err != nil {
		return classifyResolverFailure("verify published state: resolve feed", err)
	}
	if publish.CanonicalReference(stateRef) != publish.CanonicalReference(receipt.StateRef) {
		return newIntegrityError(fmt.Errorf("verify published state: effective feed does not resolve to the committed reference"))
	}
	stateBytes, err := docs.Read(ctx, stateRef)
	if err != nil {
		return classifyResolverFailure("verify published state: read state document", err)
	}
	doc, err := spec.DecodeRepoStateDocument(stateBytes)
	if err != nil {
		return newIntegrityError(fmt.Errorf("verify published state: decode state document: %w", err))
	}
	if doc.Generation != receipt.Generation {
		return newIntegrityError(fmt.Errorf("verify published state: generation %d does not match receipt generation %d", doc.Generation, receipt.Generation))
	}
	desc, ok := doc.Manifests[input.ManifestDigest]
	if !ok {
		return newIntegrityError(fmt.Errorf("verify published state: manifest descriptor for the receipt digest missing"))
	}
	if publish.CanonicalReference(desc.SwarmRef) != publish.CanonicalReference(receipt.ManifestRef) {
		return newIntegrityError(fmt.Errorf("verify published state: manifest document reference does not match the receipt reference"))
	}
	if err := verifyPublicationProvenance(doc, receipt); err != nil {
		return err
	}
	if err := verifyPublicationCoherence(ctx, docs, doc, receipt.Repo, receipt.Tag, receipt.ManifestDigest, input.Manifest, artifact); err != nil {
		return err
	}
	return nil
}

// VerifyPublishedRetryState verifies that the CURRENT effective repository
// state (at the given feed) carries the requested tag→digest target as an
// already-published, structurally coherent publication — the restart-safe
// recognition of a lost-response retry. Success means the request's target is
// verifiably already effective AND the durable per-tag publication provenance
// records EXACTLY the expected operation identity (never inferred from the
// current generation — an unrelated publication that advanced the feed must
// not make a different operation answerable as this retry). ErrTargetNotCurrentState
// means the mapping or its recorded provenance does not match: NOT a retry,
// the caller proceeds as a fresh publication (whose generation check at the
// control plane conflicts rather than overwrites). A legacy document WITHOUT
// provenance stays schema-valid but is not a retry — the exact prior operation
// identity is not recoverable and must never be fabricated. Any
// structural/read/integrity problem is *IntegrityError.
func VerifyPublishedRetryState(ctx context.Context, feeds resolve.FeedResolver, docs resolve.Reader, stateFeed string, repo string, tag string, digest string, expectedOperationID string, input publish.BuildInput, artifact publish.Artifact) error {
	stateRef, err := feeds.ResolveFeed(ctx, stateFeed)
	if err != nil {
		return classifyResolverFailure("verify retry state: resolve feed", err)
	}
	stateBytes, err := docs.Read(ctx, stateRef)
	if err != nil {
		return classifyResolverFailure("verify retry state: read state document", err)
	}
	doc, err := spec.DecodeRepoStateDocument(stateBytes)
	if err != nil {
		return newIntegrityError(fmt.Errorf("verify retry state: decode state document: %w", err))
	}
	if doc.Generation < 1 {
		return newIntegrityError(fmt.Errorf("verify retry state: already-published target requires generation >= 1, got %d", doc.Generation))
	}
	if doc.Repo != repo {
		return newIntegrityError(fmt.Errorf("verify retry state: state document repo does not match the request repo"))
	}
	if doc.Tags[tag] != digest {
		// The feed advanced incompatibly: this exact target is no longer the
		// current tag mapping. NOT a retry of the current target.
		return ErrTargetNotCurrentState
	}
	pub, recorded := doc.TagPublications[tag]
	if !recorded || pub.OperationID != expectedOperationID {
		// The current mapping was produced by a DIFFERENT operation (or the
		// document predates provenance): the exact prior operation identity is
		// not recoverable — this request is NOT a retry of the expected
		// operation and its ID must never be fabricated or echoed.
		return ErrTargetNotCurrentState
	}
	if err := verifyPublicationCoherence(ctx, docs, doc, repo, tag, digest, input.Manifest, artifact); err != nil {
		return err
	}
	return nil
}

// verifyPublicationProvenance checks the committed document's durable per-tag
// publication provenance against the receipt: the entry for the receipt's tag
// must exist and record the EXACT operation identity, the applied generation,
// and the digest of the committed publication. Schema validation has already
// bound the entry's digest to the tag mapping, so this is the final
// fail-closed check that the document durably states the operation the 201
// would name.
func verifyPublicationProvenance(doc spec.RepoStateDocument, receipt publish.PublicationReceipt) error {
	pub, ok := doc.TagPublications[receipt.Tag]
	if !ok {
		return newIntegrityError(fmt.Errorf("verify published state: publication provenance for the receipt target missing"))
	}
	if pub.OperationID != receipt.OperationID || pub.Generation != receipt.Generation || pub.Digest != receipt.ManifestDigest {
		return newIntegrityError(fmt.Errorf("verify published state: publication provenance does not match the committed operation"))
	}
	return nil
}

// verifyPublicationCoherence checks the content-level coherence of a decoded
// repository state document against the request target: the tag→digest
// mapping, the manifest descriptor (media type and size), the manifest object
// bytes (sha256 digest), and every referenced blob record's size and media
// type. All failures are *IntegrityError whose diagnostic causes stay private.
func verifyPublicationCoherence(ctx context.Context, docs resolve.Reader, doc spec.RepoStateDocument, repo string, tag string, digest string, manifest spec.ManifestDescriptor, artifact publish.Artifact) error {
	if doc.Repo != repo {
		return newIntegrityError(fmt.Errorf("verify publication: state document repo does not match the target repo"))
	}
	if doc.Tags[tag] != digest {
		return newIntegrityError(fmt.Errorf("verify publication: tag does not map to the target digest in the published state"))
	}
	desc, ok := doc.Manifests[digest]
	if !ok {
		return newIntegrityError(fmt.Errorf("verify publication: manifest descriptor for the target digest missing from published state"))
	}
	if desc.MediaType != manifest.MediaType || desc.Size != manifest.Size {
		return newIntegrityError(fmt.Errorf("verify publication: manifest descriptor media/size disagree with the request target"))
	}
	raw, err := docs.Read(ctx, desc.SwarmRef)
	if err != nil {
		return classifyResolverFailure(fmt.Sprintf("verify publication: read manifest document %q", desc.SwarmRef), err)
	}
	if publish.ComputeDigest(raw) != digest {
		return newIntegrityError(fmt.Errorf("verify publication: manifest document bytes do not match the target digest"))
	}
	for _, ref := range artifact.References() {
		blob, ok := doc.Blobs[ref.Digest]
		if !ok {
			return newIntegrityError(fmt.Errorf("verify publication: a referenced blob is missing from published state"))
		}
		if blob.Size != ref.Size || blob.MediaType != ref.MediaType {
			return newIntegrityError(fmt.Errorf("verify publication: a referenced blob descriptor disagrees with the manifest reference"))
		}
	}
	return nil
}

// classifyResolverFailure translates a resolver/document-layer failure into
// the publication error classes WITHOUT guessing: a CONCLUSIVE not-found
// (never-written feed or definitively-missing object) is an integrity
// violation after a commit was reported; any other failure — transport,
// network, timeout, decode-of-transport — is a retryable dependency. The
// raw cause (which can carry host, document references, decoder/SQL/topology
// detail) is retained ONLY as the private diagnostic of the typed class.
func classifyResolverFailure(context string, err error) error {
	if errors.Is(err, resolve.ErrFeedNotFound) || errors.Is(err, resolve.ErrDocumentNotFound) {
		return newIntegrityError(fmt.Errorf("%s: %w", context, err))
	}
	return newDependencyError(fmt.Errorf("%s: %w", context, err))
}

// classifyRequestBoundaryError is the fixed centralized mapper for failures
// at the REQUEST BOUNDARY — registry-identity resolution and
// authorization-policy consultation — where no typed publication class can be
// produced and the raw resolver/policy error (which can carry host names,
// repository names, digests, document references, decoder or network detail)
// must NEVER cross the HTTP boundary. Unauthenticated (401 challenge) and
// policy-denied (403) outcomes are decided by OTHER code before and after
// this mapper and never reach it; every consultation failure collapses to the
// fixed retryable dependency surface: 503 DEPENDENCY_UNAVAILABLE with the
// fixed generic message. A typed integrity failure is still surfaced as 502
// PUBLICATION_UNVERIFIED and a conflict as 409 MANIFEST_CONFLICT, each with
// its fixed data-free message.
func classifyRequestBoundaryError(err error) (int, string, string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return http.StatusServiceUnavailable, ErrorCodeDependencyUnavailable, messageDependencyUnavailable
	case errors.As(err, new(*ConflictError)):
		return http.StatusConflict, ErrorCodeManifestConflict, messageConflict
	case errors.As(err, new(*IntegrityError)):
		return http.StatusBadGateway, ErrorCodePublicationUnverified, messageUnverified
	default:
		// Every raw identity/policy dependency or unknown failure collapses to
		// the fixed retryable dependency surface — never its error text.
		return http.StatusServiceUnavailable, ErrorCodeDependencyUnavailable, messageDependencyUnavailable
	}
}
