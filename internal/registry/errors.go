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
// crosses the HTTP boundary. All three classes carry the root cause ONLY for
// errors.Is/errors.As inspection and logging; Error() is the fixed public
// message.

// IntegrityError is the fail-closed class for a publication whose committed
// outcome cannot be VERIFIED through the production feed/document path (stale
// feed, missing/malformed state, generation or repo mismatch, tag/digest
// mismatch, manifest-object or blob-record incoherence).
type IntegrityError struct{ Err error }

func (e *IntegrityError) Error() string { return "published repository state could not be verified" }
func (e *IntegrityError) Unwrap() error { return e.Err }

// DependencyError is the class for a required service being temporarily
// unavailable (control-plane feed signer, Bee, internal credential): retryable.
type DependencyError struct{ Err error }

func (e *DependencyError) Error() string { return "a required service is temporarily unavailable" }
func (e *DependencyError) Unwrap() error { return e.Err }

// ConflictError is the class for an idempotency/generation conflict: reusing
// one operation identity with different input, or the repository generation
// having advanced elsewhere. The caller must NOT retry the same request body
// blindly; resolve the conflict first.
type ConflictError struct{ Err error }

func (e *ConflictError) Error() string {
	return "the repository publication conflicts with an existing operation"
}
func (e *ConflictError) Unwrap() error { return e.Err }

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
// whose generation, repo, tag→digest mapping, manifest descriptor (including
// the exact committed manifest reference), manifest object bytes, and
// referenced blob records are all exact and coherent. Any mismatch is a
// fail-closed *IntegrityError: the caller must NOT report success and MUST
// retain staging for a safe retry. A read-side timeout collapses to the
// dependency class (retryable), never to success.
func VerifyPublishedState(ctx context.Context, feeds resolve.FeedResolver, docs resolve.Reader, receipt publish.PublicationReceipt, input publish.BuildInput, artifact publish.Artifact) error {
	stateRef, err := feeds.ResolveFeed(ctx, receipt.StateFeed)
	if err != nil {
		return classifyResolverFailure("verify published state: resolve feed", err)
	}
	if publish.CanonicalReference(stateRef) != publish.CanonicalReference(receipt.StateRef) {
		return &IntegrityError{Err: fmt.Errorf("verify published state: effective feed resolves to %q, committed reference is %q", stateRef, receipt.StateRef)}
	}
	stateBytes, err := docs.Read(ctx, stateRef)
	if err != nil {
		return classifyResolverFailure("verify published state: read state document", err)
	}
	doc, err := spec.DecodeRepoStateDocument(stateBytes)
	if err != nil {
		return &IntegrityError{Err: fmt.Errorf("verify published state: decode state document: %w", err)}
	}
	if doc.Generation != receipt.Generation {
		return &IntegrityError{Err: fmt.Errorf("verify published state: generation %d does not match receipt generation %d", doc.Generation, receipt.Generation)}
	}
	desc, ok := doc.Manifests[input.ManifestDigest]
	if !ok {
		return &IntegrityError{Err: fmt.Errorf("verify published state: manifest descriptor for %s missing", input.ManifestDigest)}
	}
	if publish.CanonicalReference(desc.SwarmRef) != publish.CanonicalReference(receipt.ManifestRef) {
		return &IntegrityError{Err: fmt.Errorf("verify published state: manifest document reference %q does not match receipt reference %q", desc.SwarmRef, receipt.ManifestRef)}
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
// verifiably already effective. ErrTargetNotCurrentState means the feed
// advanced incompatibly: NOT a retry, the caller proceeds as a fresh
// publication (whose generation check at the control plane conflicts rather
// than overwrites). Any structural/read/integrity problem is *IntegrityError.
func VerifyPublishedRetryState(ctx context.Context, feeds resolve.FeedResolver, docs resolve.Reader, stateFeed string, repo string, tag string, digest string, input publish.BuildInput, artifact publish.Artifact) error {
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
		return &IntegrityError{Err: fmt.Errorf("verify retry state: decode state document: %w", err)}
	}
	if doc.Generation < 1 {
		return &IntegrityError{Err: fmt.Errorf("verify retry state: already-published target requires generation >= 1, got %d", doc.Generation)}
	}
	if doc.Repo != repo {
		return &IntegrityError{Err: fmt.Errorf("verify retry state: state document repo %q does not match request repo %q", doc.Repo, repo)}
	}
	if doc.Tags[tag] != digest {
		// The feed advanced incompatibly: this exact target is no longer the
		// current tag mapping. NOT a retry of the current target.
		return ErrTargetNotCurrentState
	}
	if err := verifyPublicationCoherence(ctx, docs, doc, repo, tag, digest, input.Manifest, artifact); err != nil {
		return err
	}
	return nil
}

// verifyPublicationCoherence checks the content-level coherence of a decoded
// repository state document against the request target: the tag→digest
// mapping, the manifest descriptor (media type and size), the manifest object
// bytes (sha256 digest), and every referenced blob record's size and media
// type. All failures are *IntegrityError with no payload data.
func verifyPublicationCoherence(ctx context.Context, docs resolve.Reader, doc spec.RepoStateDocument, repo string, tag string, digest string, manifest spec.ManifestDescriptor, artifact publish.Artifact) error {
	if doc.Repo != repo {
		return &IntegrityError{Err: fmt.Errorf("verify publication: state document repo %q does not match target repo %q", doc.Repo, repo)}
	}
	if doc.Tags[tag] != digest {
		return &IntegrityError{Err: fmt.Errorf("verify publication: tag %q does not map to digest %s in the published state", tag, digest)}
	}
	desc, ok := doc.Manifests[digest]
	if !ok {
		return &IntegrityError{Err: fmt.Errorf("verify publication: manifest descriptor for digest %s missing from published state", digest)}
	}
	if desc.MediaType != manifest.MediaType || desc.Size != manifest.Size {
		return &IntegrityError{Err: fmt.Errorf("verify publication: manifest descriptor media/size disagree with the request target")}
	}
	raw, err := docs.Read(ctx, desc.SwarmRef)
	if err != nil {
		return classifyResolverFailure(fmt.Sprintf("verify publication: read manifest document %q", desc.SwarmRef), err)
	}
	if publish.ComputeDigest(raw) != digest {
		return &IntegrityError{Err: fmt.Errorf("verify publication: manifest document bytes do not match digest %s", digest)}
	}
	for _, ref := range artifact.References() {
		blob, ok := doc.Blobs[ref.Digest]
		if !ok {
			return &IntegrityError{Err: fmt.Errorf("verify publication: referenced blob %s missing from published state", ref.Digest)}
		}
		if blob.Size != ref.Size || blob.MediaType != ref.MediaType {
			return &IntegrityError{Err: fmt.Errorf("verify publication: referenced blob %s descriptor disagrees with the manifest reference", ref.Digest)}
		}
	}
	return nil
}

// classifyResolverFailure translates a resolver/document-layer failure into
// the publication error classes WITHOUT guessing: a CONCLUSIVE not-found
// (never-written feed or definitively-missing object) is an integrity
// violation after a commit was reported; any other failure — transport,
// network, timeout, decode-of-transport — is a retryable dependency.
func classifyResolverFailure(context string, err error) error {
	if errors.Is(err, resolve.ErrFeedNotFound) || errors.Is(err, resolve.ErrDocumentNotFound) {
		return &IntegrityError{Err: fmt.Errorf("%s: %w", context, err)}
	}
	return &DependencyError{Err: fmt.Errorf("%s: %w", context, err)}
}
