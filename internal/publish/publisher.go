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
	// OperationID, when non-empty, is the operation identity the
	// repository-state document records as the DURABLE publication provenance
	// for input.Tag (see spec.TagPublication): the exact operation that
	// produced this tag's mapping, the generation it was applied at, and the
	// digest it points at. PublishCommit always supplies it via the operation
	// identity it commits to the feed; callers of the legacy Publish path
	// leave it empty and their documents carry no provenance — those
	// documents stay valid, and their exact prior operation identity is
	// simply not recoverable by a later retry (never fabricated).
	OperationID string
	// UpdatedAt, when non-empty, is the EXACT repo-state UpdatedAt value the
	// builder must persist verbatim. Callers that need byte-stable,
	// restart-safe idempotent rebuilds (a retry of one logical publication
	// must produce byte-identical repo-state bytes) supply
	// DeterministicUpdatedAt(operationID); an empty value keeps the builder's
	// wall-clock fallback for callers with no retry contract.
	UpdatedAt string
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

// PublicationReceipt is the exact observable outcome of one repository
// publication, captured BEFORE the uncertain commit boundary so the caller can
// VERIFY the committed outcome afterwards through the production
// resolver/document path (exact read-after-write verification) and answer
// lost-response retries restart-safely. The control plane independently
// records the same operation identity; the receipt is the data plane's
// caller-visible statement of what this logical publication intended to
// commit.
type PublicationReceipt struct {
	// OperationID is the stable identity of this logical publication, echoed
	// to the caller in the successful response.
	OperationID string
	// StateFeed is the canonical repository-state feed the commit targeted.
	StateFeed string
	// StateRef is the immutable repository-state document reference committed
	// to the feed. Verification requires the effective feed to resolve to
	// EXACTLY this reference.
	StateRef string
	// ManifestRef is the immutable reference the published manifest body was
	// stored under.
	ManifestRef string
	// Owner and Repo identify the repository namespace the publication
	// targeted.
	Owner string
	Repo  string
	// Tag is the manifest reference (tag) this publication wrote.
	Tag string
	// ManifestDigest is the content digest of the published manifest body.
	ManifestDigest string
	// ExpectedGeneration is the generation the publication was built against,
	// and Generation is the generation it resulted in (Expected + 1).
	ExpectedGeneration int64
	Generation         int64
}

type DefaultBuilder struct{}

func (p Publisher) Publish(ctx context.Context, stateFeed string, current spec.RepoStateDocument, input BuildInput, batchID string) (spec.RepoStateDocument, error) {
	next, _, err := p.publish(ctx, stateFeed, current, input, batchID, false, 0, "", "")
	return next, err
}

// PublishCommit is the publisher path that carries the registry identity,
// owner, expected generation, and a stable deterministic operation ID into the
// repository feed commit. When Publisher.Commits is configured (Bee mode) the
// immutable state reference is committed through the control-plane internal
// feed signer with a FeedCommitRequest built from those fields; otherwise it
// falls back to the local Feeds updater (in-memory mode). It returns the exact
// PublicationReceipt — captured BEFORE the commit boundary — so the caller can
// run the read-after-write verification and answer retries.
func (p Publisher) PublishCommit(ctx context.Context, stateFeed string, current spec.RepoStateDocument, input BuildInput, batchID string, registryID int64, owner string, publicationID string) (PublicationReceipt, error) {
	_, receipt, err := p.publish(ctx, stateFeed, current, input, batchID, true, registryID, owner, publicationID)
	return receipt, err
}

// IsGenerationConflict reports whether err is the AUTHORITATIVE
// control-plane generation-conflict sentinel — the repository-generation
// comparison at the feed signer found the expected generation stale because
// the feed advanced elsewhere. Only this conflict class is safe to recover by
// a rebuild; a permanent operation/binding conflict (ErrCommitConflict — the
// same operation or publication identity reused with a different logical
// payload) is a hard 409 to the caller and must NEVER be retried or rebuilt.
func IsGenerationConflict(err error) bool { return errors.Is(err, ErrCommitGenerationConflict) }

// RebuildResolver re-resolves the current repository state (its generation and
// content) inside the caller's held publication lock. found=false reports a
// conclusively absent (generation-zero, never-written) repository.
type RebuildResolver func(ctx context.Context) (current spec.RepoStateDocument, found bool, err error)

// PublishCommitWithConflictRebuild is the conflict-safe publication entry
// point. It commits the immutable state reference exactly like PublishCommit,
// but when the control plane reports an AUTHORITATIVE generation conflict (the
// repository feed advanced elsewhere) it re-resolves the newest state through
// reResolve and rebuilds ONCE, reusing the exact stable publicationID and its
// deterministic timestamp (input.UpdatedAt derives from publicationID) so a
// lost-response retry of this same logical publication stays byte-stable.
// publicationID is NEVER mutated across the rebuild — it is the identity
// recorded in TagPublications, returned to the caller, and durably bound by
// preflight; only the fresh immutable state bytes/reference (Generation
// advances) and, internally, the derived per-attempt FeedSigner identity
// change (see ComputeCommitAttemptID) — which is exactly what lets the
// rebuilt attempt avoid colliding with the conflicted attempt's permanently
// reserved durable operation row. The rebuild re-runs the strict input
// validation (via PublishCommit) against the fresh state, so it proceeds only
// while the original staged inputs remain valid and coherent — otherwise it
// fails typed with zero feed writes. Retries are bounded to this single
// rebuild: if the fresh state did not actually advance, re-resolving failed,
// or the rebuild itself conflicts again, the ORIGINAL conflict (mapped to 409
// by the caller) is returned. Different logical publications never inherit
// another's success: publicationID is unchanged, and only a feed that never
// recorded it is re-advanced.
func (p Publisher) PublishCommitWithConflictRebuild(ctx context.Context, stateFeed string, current spec.RepoStateDocument, input BuildInput, batchID string, registryID int64, owner string, publicationID string, reResolve RebuildResolver) (PublicationReceipt, error) {
	receipt, err := p.PublishCommit(ctx, stateFeed, current, input, batchID, registryID, owner, publicationID)
	if err == nil || !IsGenerationConflict(err) {
		return receipt, err
	}
	fresh, _, rerr := reResolve(ctx)
	if rerr != nil || fresh.Generation <= current.Generation {
		// Not safely rebuildable: the feed did not durably advance for us, so
		// surrender the original conflict rather than risk an orphaned write
		// becoming authoritative.
		return PublicationReceipt{}, err
	}
	return p.PublishCommit(ctx, stateFeed, fresh, input, batchID, registryID, owner, publicationID)
}

func (p Publisher) publish(ctx context.Context, stateFeed string, current spec.RepoStateDocument, input BuildInput, batchID string, useCommits bool, registryID int64, owner string, publicationID string) (spec.RepoStateDocument, PublicationReceipt, error) {
	// Strict pre-upload validation: parse the artifact, verify the
	// handler-provided digest/size/media against the actual body, and confirm
	// every referenced descriptor's size and media type agree with its stored
	// blob — ALL before the first object write. Invalid input must produce
	// zero object puts and zero feed updates. validateInputArtifact is the
	// SAME routine DefaultBuilder.BuildNext runs, so both entry points share
	// one validation contract with no parse-twice drift.
	if _, err := validateInputArtifact(current, input); err != nil {
		return spec.RepoStateDocument{}, PublicationReceipt{}, err
	}

	manifestRef, err := p.Objects.Put(ctx, input.ManifestJSON, batchID)
	if err != nil {
		return spec.RepoStateDocument{}, PublicationReceipt{}, fmt.Errorf("upload manifest bytes: %w", err)
	}

	input.Manifest.SwarmRef = manifestRef
	// The committed STABLE publication identity IS the durable publication
	// provenance recorded in the repo-state document (spec.TagPublication).
	// The legacy Publish path passes an empty identity and its documents carry
	// no provenance; PublishCommit always records the exact publication it
	// commits. This identity is deliberately NEVER the per-attempt FeedSigner
	// identity (see below) — it stays stable across a one-time conflict
	// rebuild.
	input.OperationID = publicationID
	next, err := p.Builder.BuildNext(current, input)
	if err != nil {
		return spec.RepoStateDocument{}, PublicationReceipt{}, err
	}

	stateBytes, err := json.Marshal(next)
	if err != nil {
		return spec.RepoStateDocument{}, PublicationReceipt{}, fmt.Errorf("marshal repo state: %w", err)
	}

	stateRef, err := p.Objects.Put(ctx, stateBytes, batchID)
	if err != nil {
		return spec.RepoStateDocument{}, PublicationReceipt{}, fmt.Errorf("upload repo state: %w", err)
	}

	// The receipt is fully determined at this point — BEFORE the uncertain
	// commit boundary — so the caller can verify the committed outcome through
	// the production feed/document path without trusting this process's
	// memory.
	receipt := PublicationReceipt{
		OperationID:        publicationID,
		StateFeed:          stateFeed,
		StateRef:           stateRef,
		ManifestRef:        manifestRef,
		Owner:              owner,
		Repo:               input.Repo,
		Tag:                input.Tag,
		ManifestDigest:     input.ManifestDigest,
		ExpectedGeneration: current.Generation,
		Generation:         next.Generation,
	}

	if useCommits && p.Commits != nil {
		// Bee mode: route the immutable state reference through the control
		// plane. The control plane alone holds and uses the feed-owner signing
		// key; the registry process never receives it. The ATTEMPT identity
		// sent as OperationID is deterministically derived from the stable
		// publicationID plus THIS attempt's own expected generation/reference —
		// never reused unchanged across a rebuild — so the durable FeedSigner
		// operation row it reserves can never collide with a different
		// attempt's permanently-fixed request hash (see
		// ComputeCommitAttemptID).
		attemptID := ComputeCommitAttemptID(publicationID, registryID, owner, stateFeed, stateRef, current.Generation)
		if _, err := p.Commits.Commit(ctx, FeedCommitRequest{
			OperationID:        attemptID,
			PublicationID:      publicationID,
			RegistryID:         registryID,
			Owner:              owner,
			Topic:              stateFeed,
			Reference:          stateRef,
			BatchID:            batchID,
			ExpectedGeneration: current.Generation,
		}); err != nil {
			return spec.RepoStateDocument{}, PublicationReceipt{}, fmt.Errorf("commit state feed: %w", err)
		}
	} else if err := p.Feeds.UpdateFeed(ctx, stateFeed, stateRef); err != nil {
		return spec.RepoStateDocument{}, PublicationReceipt{}, fmt.Errorf("update state feed: %w", err)
	}

	return next, receipt, nil
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

	// The state timestamp is part of the persisted document BYTES, so a
	// non-empty deterministic UpdatedAt (see BuildInput.UpdatedAt) must be
	// honored verbatim to keep retried rebuilds byte-identical; a malformed
	// non-empty value is rejected. The wall-clock fallback exists only for
	// callers with no retry contract.
	updatedAt := input.UpdatedAt
	if updatedAt != "" {
		if _, err := time.Parse(time.RFC3339, updatedAt); err != nil {
			return spec.RepoStateDocument{}, newValidationError(ErrKindInvalidShape, "UpdatedAt",
				"a non-empty deterministic UpdatedAt must be RFC3339")
		}
	} else {
		updatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	next := spec.RepoStateDocument{
		Version:    1,
		Repo:       input.Repo,
		Generation: current.Generation + 1,
		UpdatedAt:  updatedAt,
		Tags:       cloneStringMap(current.Tags),
		Manifests:  cloneManifestMap(current.Manifests),
		Blobs:      cloneBlobMap(current.Blobs),
		// The per-tag publication provenance is cloned like every other map
		// (never aliased against the caller's document) and REPLACED for the
		// operated tag when an operation identity is supplied. It is retained
		// verbatim across unrelated tags' publications — the durable record a
		// restart-safe retry reads. A nil current map yields a non-nil empty
		// map, so every PublishCommit-produced document carries the field.
		TagPublications: cloneTagPublications(current.TagPublications),
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
	if input.OperationID != "" {
		// Record the durable per-tag provenance: the EXACT operation identity
		// this publication commits under, the generation it is applied at, and
		// the digest its tag now maps to. The resulting document is validated
		// below (coherence with the tag mapping is checked by
		// RepoStateDocument.Validate), so a malformed identity fails closed.
		next.TagPublications[input.Tag] = spec.TagPublication{
			OperationID: input.OperationID,
			Generation:  next.Generation,
			Digest:      input.ManifestDigest,
		}
	} else {
		// Legacy publication (no operation identity): the operated tag's OLD
		// provenance entry — if any — is REMOVED. Retaining it would leave the
		// stale entry's digest disagreeing with the new tag mapping and fail
		// document validation AFTER the manifest object was uploaded. Unrelated
		// tags' entries are already cloned and never aliased above.
		delete(next.TagPublications, input.Tag)
	}

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

// CheckBlobReferenceCoherence verifies ONE stored blob record against the
// manifest descriptor that references it — exact size plus the documented
// media-type normalization contract — using EXACTLY the same rules the data
// plane applies at upload time (checkReferenceMetadata). The control plane
// reuses it for the operated artifact after the manifest BODY has been
// independently parsed, so the signer's blob-state proof is the same strict
// contract a legitimate publication had to pass. Errors are data-free.
func CheckBlobReferenceCoherence(ref Descriptor, stored spec.BlobDescriptor) error {
	return checkReferenceMetadata(ref, stored)
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

// cloneTagPublications deep-enough clones the per-tag publication provenance
// map (the entry values are value structs). It always returns a NON-NIL map —
// including for a nil input — so every document the built-in builder produces
// carries the provenance field deterministically.
func cloneTagPublications(in map[string]spec.TagPublication) map[string]spec.TagPublication {
	out := make(map[string]spec.TagPublication, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
