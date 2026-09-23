package publish

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"strings"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

type ObjectUploader interface {
	Put(ctx context.Context, data []byte, batchID string) (string, error)
}

type FeedUpdater interface {
	UpdateFeed(ctx context.Context, feed string, ref string) error
}

// RepoCommitter commits an immutable repository-state reference through the
// control-plane internal feed signer. The control plane verifies the topic is
// the deterministic feed for the referenced repository, the generation
// advanced by exactly one, the batch is permitted by the current stamp policy,
// and the operation ID is durable-idempotent. ControlPlaneCommitter satisfies
// it; in-memory modes use Publisher.Feeds directly and leave it nil.
type RepoCommitter interface {
	Commit(ctx context.Context, req FeedCommitRequest) (FeedCommitResult, error)
}

type RepoStateStore interface {
	LoadCurrent(ctx context.Context, repo string) (spec.RepoStateDocument, error)
}

type Builder interface {
	BuildNext(current spec.RepoStateDocument, input BuildInput) (spec.RepoStateDocument, error)
}

type BuildInput struct {
	Repo           string
	Tag            string
	ManifestDigest string
	ManifestJSON   []byte
	Manifest       spec.ManifestDescriptor
	StagedBlobs    map[string]spec.BlobDescriptor
}

type Publisher struct {
	Builder Builder
	Objects ObjectUploader
	Feeds   FeedUpdater
	// Commits, when set, routes the repository-state feed commit through the
	// control-plane internal feed signer instead of the local Feeds updater.
	// Bee-mode registry processes set it; in-memory mode leaves it nil and
	// publishes through Feeds. It is never an in-process signer — the control
	// plane alone holds and uses the feed-owner signing key.
	Commits RepoCommitter
}

type DefaultBuilder struct{}

func (p Publisher) Publish(ctx context.Context, stateFeed string, current spec.RepoStateDocument, input BuildInput, batchID string) (spec.RepoStateDocument, error) {
	return p.publish(ctx, stateFeed, current, input, batchID, false, 0, "", "")
}

// PublishCommit is the publisher path that carries the registry identity,
// owner, expected generation, and a stable deterministic operation ID into the
// repository feed commit. When Publisher.Commits is configured (Bee mode) the
// immutable state reference is committed through the control-plane internal
// feed signer with a FeedCommitRequest built from those fields; otherwise it
// falls back to the local Feeds updater (in-memory mode).
func (p Publisher) PublishCommit(ctx context.Context, stateFeed string, current spec.RepoStateDocument, input BuildInput, batchID string, registryID int64, owner string, operationID string) (spec.RepoStateDocument, error) {
	return p.publish(ctx, stateFeed, current, input, batchID, true, registryID, owner, operationID)
}

func (p Publisher) publish(ctx context.Context, stateFeed string, current spec.RepoStateDocument, input BuildInput, batchID string, useCommits bool, registryID int64, owner string, operationID string) (spec.RepoStateDocument, error) {
	// Strict pre-upload validation: parse the artifact, verify the
	// handler-provided digest/size/media against the actual body, and confirm
	// every referenced descriptor's size and media type agree with its stored
	// blob — ALL before the first object write. Invalid input must produce
	// zero object puts and zero feed updates. validateInputArtifact is the
	// SAME routine DefaultBuilder.BuildNext runs, so both entry points share
	// one validation contract with no parse-twice drift.
	if _, err := validateInputArtifact(current, input); err != nil {
		return spec.RepoStateDocument{}, err
	}

	manifestRef, err := p.Objects.Put(ctx, input.ManifestJSON, batchID)
	if err != nil {
		return spec.RepoStateDocument{}, fmt.Errorf("upload manifest bytes: %w", err)
	}

	input.Manifest.SwarmRef = manifestRef
	next, err := p.Builder.BuildNext(current, input)
	if err != nil {
		return spec.RepoStateDocument{}, err
	}

	stateBytes, err := json.Marshal(next)
	if err != nil {
		return spec.RepoStateDocument{}, fmt.Errorf("marshal repo state: %w", err)
	}

	stateRef, err := p.Objects.Put(ctx, stateBytes, batchID)
	if err != nil {
		return spec.RepoStateDocument{}, fmt.Errorf("upload repo state: %w", err)
	}

	if useCommits && p.Commits != nil {
		// Bee mode: route the immutable state reference through the control
		// plane. The control plane alone holds and uses the feed-owner signing
		// key; the registry process never receives it.
		if _, err := p.Commits.Commit(ctx, FeedCommitRequest{
			OperationID:        operationID,
			RegistryID:         registryID,
			Owner:              owner,
			Topic:              stateFeed,
			Reference:          stateRef,
			BatchID:            batchID,
			ExpectedGeneration: current.Generation,
		}); err != nil {
			return spec.RepoStateDocument{}, fmt.Errorf("commit state feed: %w", err)
		}
	} else if err := p.Feeds.UpdateFeed(ctx, stateFeed, stateRef); err != nil {
		return spec.RepoStateDocument{}, fmt.Errorf("update state feed: %w", err)
	}

	return next, nil
}

func (DefaultBuilder) BuildNext(current spec.RepoStateDocument, input BuildInput) (spec.RepoStateDocument, error) {
	if input.Repo == "" || input.Tag == "" || input.ManifestDigest == "" {
		return spec.RepoStateDocument{}, fmt.Errorf("build input missing repo, tag, or manifest digest")
	}

	// The builder stays self-validating for direct callers: it runs the exact
	// same routine Publish uses — body digest/size/media coherence plus
	// reference availability — so a direct caller with a wrong digest, size,
	// or media type fails typed and leaves input/current unmutated.
	artifact, err := validateInputArtifact(current, input)
	if err != nil {
		return spec.RepoStateDocument{}, err
	}

	next := spec.RepoStateDocument{
		Version:    1,
		Repo:       input.Repo,
		Generation: current.Generation + 1,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
		Tags:       cloneStringMap(current.Tags),
		Manifests:  cloneManifestMap(current.Manifests),
		Blobs:      cloneBlobMap(current.Blobs),
	}

	// Copy staged blobs into the next state REFERENCED-ONLY: a staged blob is
	// included iff the artifact references its digest. Unrelated staged blobs
	// (pushed alongside, never referenced) stay OUT of repository state — they
	// are retained in staging, not published. The same-digest metadata-safety
	// rule still applies: a referenced staged record NEVER overwrites a digest
	// already present in current state, because current is the authoritative,
	// richer record and a generic staged placeholder (empty or
	// application/octet-stream) would otherwise degrade it.
	referenced := make(map[string]struct{}, len(artifact.References()))
	for _, ref := range artifact.References() {
		referenced[ref.Digest] = struct{}{}
	}
	for digest, desc := range input.StagedBlobs {
		if _, exists := current.Blobs[digest]; exists {
			continue
		}
		if _, isRef := referenced[digest]; !isRef {
			continue
		}
		next.Blobs[digest] = desc
	}
	next.Manifests[input.ManifestDigest] = input.Manifest
	next.Tags[input.Tag] = input.ManifestDigest

	return next, next.Validate()
}

func ComputeDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum[:])
}

// validateInputArtifact is the SINGLE shared validation routine for the whole
// publication path. It strictly parses the manifest/index body, enforces the
// caller contract at the earliest layer that holds BOTH the body and the
// handler-provided descriptor (computed body digest must equal
// BuildInput.ManifestDigest, actual body length must equal
// BuildInput.Manifest.Size, and the top-level media type is exactly a
// supported type), and confirms every referenced descriptor's stored blob is
// present with a coherent size and media type. It is invoked by
// Publisher.publish BEFORE the first object write and by
// DefaultBuilder.BuildNext before any state is derived, so both entry points
// share one contract with no parse-twice drift. It returns the validated
// Artifact for callers that need it. All failures are typed *ValidationError
// with no body echo.
func validateInputArtifact(current spec.RepoStateDocument, input BuildInput) (Artifact, error) {
	artifact, err := ParseArtifact(input.Manifest.MediaType, input.ManifestJSON)
	if err != nil {
		return Artifact{}, err
	}
	// Publication gate: ParseArtifact accepts OCI indexes / Docker manifest
	// lists (including empty ones), but their PUBLICATION is not supported
	// until Task 19. Reject index kinds with a stable typed error here — BEFORE
	// reference availability, state derivation, or any object/feed write — so
	// both Publisher.publish and DefaultBuilder.BuildNext refuse index
	// publication with zero writes. Parser support is deliberately separate.
	if artifact.Kind == ArtifactKindIndex {
		return Artifact{}, &ValidationError{
			Kind: ErrKindUnsupportedPublication,
			Err:  errors.New("index publication is not supported in v1 until Task 19"),
		}
	}
	if got := ComputeDigest(input.ManifestJSON); got != input.ManifestDigest {
		return Artifact{}, newValidationError(ErrKindDigestMismatch, "",
			"computed manifest body digest disagrees with the handler-provided digest")
	}
	if int64(len(input.ManifestJSON)) != input.Manifest.Size {
		return Artifact{}, newValidationError(ErrKindSizeMismatch, "",
			"manifest body size disagrees with the handler-provided descriptor")
	}
	if err := validateManifestReferences(current, input, artifact); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

// blobGenericMediaType is the Content-Type the blob-upload transport carries
// when a client provides no meaningful media type. Docker and OCI clients
// push blob bodies with Content-Type application/octet-stream (or none at
// all), which does not carry the blob's real descriptor media type; a stored
// blob with this value or an empty one is therefore the "unspecified"
// placeholder in the reference-coherence contract.
const blobGenericMediaType = "application/octet-stream"

// validateManifestReferences requires every descriptor referenced by the
// artifact to resolve to a stored blob whose SIZE and MEDIA TYPE are coherent
// with the descriptor. For each digest EVERY present source is validated —
// the current repository state record if present AND the caller's staged blob
// set if present — because the builder writes both into the next state; a
// size/media conflict in either source rejects even when the other source
// matches or is the preferred record. current state remains the authoritative
// record for the digest in state derivation (see BuildNext).
//
// Normed media-type contract:
//   - the blob-upload transport does not reliably carry a media type
//     (octet-stream / empty — see blobGenericMediaType), so an unspecified
//     stored type is transparent and never conflicts;
//   - any CONCRETE stored type is normalized via mime.ParseMediaType
//     (case-insensitive, parameter-agnostic) and must equal the canonical
//     descriptor media type — a concrete conflicting type (e.g. text/plain
//     for a gzip layer) or a malformed stored type is a media-type mismatch.
//
// Any size or media-type conflict returns a typed error BEFORE any object
// write, so the failed publication performs zero puts and zero feed updates.
func validateManifestReferences(current spec.RepoStateDocument, input BuildInput, artifact Artifact) error {
	for _, ref := range artifact.References() {
		staged, inStaged := input.StagedBlobs[ref.Digest]
		currentStored, inCurrent := current.Blobs[ref.Digest]
		if !inCurrent && !inStaged {
			return newValidationError(ErrKindMissingReference, "",
				"manifest references a blob that is neither in repository state nor staged")
		}
		if inCurrent {
			if err := checkReferenceMetadata(ref, currentStored); err != nil {
				return err
			}
		}
		if inStaged {
			if err := checkReferenceMetadata(ref, staged); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkReferenceMetadata verifies one descriptor's size and media type against
// one present stored blob record. Errors are data-free: the message never
// echoes the descriptor digest, stored size, or stored media type, and no
// attacker-controlled detail is retained as a cause.
func checkReferenceMetadata(ref Descriptor, stored spec.BlobDescriptor) error {
	if stored.Size != ref.Size {
		return newValidationError(ErrKindSizeMismatch, "",
			"stored blob size disagrees with the manifest descriptor")
	}
	if err := mediaTypesCoherent(ref.MediaType, stored.MediaType); err != nil {
		return err
	}
	return nil
}

// mediaTypesCoherent reports whether a stored blob media type is coherent with
// the canonical descriptor media type under the normalization contract
// documented on validateManifestReferences. Empty and generic octet-stream
// stored types are the upload transport's unspecified placeholder and are
// transparent; any concrete stored type must MIME-normalize equal the
// descriptor's, and a concrete conflicting or malformed type is a mismatch.
// Error messages are data-free: the stored/descriptor media-type values are
// never echoed and never retained.
func mediaTypesCoherent(descriptorMediaType, storedMediaType string) error {
	trimmed := strings.TrimSpace(storedMediaType)
	if trimmed == "" {
		return nil
	}
	norm, err := normalizeMediaType(trimmed)
	if err != nil {
		return newValidationError(ErrKindMediaTypeMismatch, "",
			"stored blob media type is malformed and cannot be reconciled with the descriptor")
	}
	if norm == blobGenericMediaType {
		return nil
	}
	want, err := normalizeMediaType(descriptorMediaType)
	if err != nil {
		return newValidationError(ErrKindMediaTypeMismatch, "",
			"descriptor media type cannot be reconciled with the stored blob type")
	}
	if norm != want {
		return newValidationError(ErrKindMediaTypeMismatch, "",
			"stored blob media type disagrees with the manifest descriptor media type")
	}
	return nil
}

// normalizeMediaType MIME-normalizes a media type so legitimate casing and
// parameter variations compare equal. It returns an error for malformed input.
func normalizeMediaType(s string) (string, error) {
	mt, _, err := mime.ParseMediaType(s)
	if err != nil {
		return "", err
	}
	return mt, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneManifestMap(in map[string]spec.ManifestDescriptor) map[string]spec.ManifestDescriptor {
	out := make(map[string]spec.ManifestDescriptor, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneBlobMap(in map[string]spec.BlobDescriptor) map[string]spec.BlobDescriptor {
	out := make(map[string]spec.BlobDescriptor, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
