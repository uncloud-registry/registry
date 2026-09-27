package publish

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// recordingCommitter is a fake RepoCommitter for
// PublishCommitWithConflictRebuild tests: it fails the first failFirst calls
// with failWith and records every request it receives.
type recordingCommitter struct {
	failFirst int
	failWith  error
	calls     []FeedCommitRequest
}

func (c *recordingCommitter) Commit(_ context.Context, req FeedCommitRequest) (FeedCommitResult, error) {
	c.calls = append(c.calls, req)
	if len(c.calls) <= c.failFirst {
		return FeedCommitResult{}, c.failWith
	}
	return FeedCommitResult{
		OperationID: req.OperationID,
		Feed:        CanonicalTopic(req.Topic),
		Reference:   CanonicalReference(req.Reference),
	}, nil
}

func freshRepoState(repo string, generation int64) spec.RepoStateDocument {
	return spec.RepoStateDocument{
		Version:    1,
		Repo:       repo,
		Generation: generation,
		Tags:       map[string]string{},
		Manifests:  map[string]spec.ManifestDescriptor{},
		Blobs:      map[string]spec.BlobDescriptor{},
	}
}

// TestComputeCommitAttemptIDIndependentVector pins ComputeCommitAttemptID
// against an INDEPENDENT reference implementation of its documented framing
// (domain prefix + length-prefixed fields, never calling the production
// helper's own byte-writing code), then proves every input field affects the
// output (no accidental field-boundary collision) and that Topic/Reference
// are canonicalized before hashing.
func TestComputeCommitAttemptIDIndependentVector(t *testing.T) {
	publicationID := "pub-vector-1"
	registryID := int64(42)
	owner := "0xABCDEF0123456789ABCDEF0123456789ABCDEF01"
	topic := "feed://abcdef0123456789abcdef0123456789abcdef01/" + strings.Repeat("c", 64)
	reference := strings.ToUpper(strings.Repeat("a", 64))
	expectedGeneration := int64(7)

	got := ComputeCommitAttemptID(publicationID, registryID, owner, topic, reference, expectedGeneration)

	h := sha256.New()
	h.Write([]byte("uncloud-registry-feed-commit-attempt:v1\x00"))
	writeField := func(s string) {
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(s)))
		h.Write(lb[:])
		h.Write([]byte(s))
	}
	writeInt := func(v int64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v))
		h.Write(b[:])
	}
	writeField(publicationID)
	writeInt(registryID)
	writeField(spec.NormalizeOwner(owner))
	writeField(CanonicalTopic(topic))
	writeField(CanonicalReference(reference))
	writeInt(expectedGeneration)
	want := hex.EncodeToString(h.Sum(nil))

	if got != want {
		t.Fatalf("ComputeCommitAttemptID drifted from its documented framing: got %q want %q", got, want)
	}

	if ComputeCommitAttemptID(publicationID+"x", registryID, owner, topic, reference, expectedGeneration) == got {
		t.Fatal("publicationID must affect the attempt id")
	}
	if ComputeCommitAttemptID(publicationID, registryID+1, owner, topic, reference, expectedGeneration) == got {
		t.Fatal("registryID must affect the attempt id")
	}
	if ComputeCommitAttemptID(publicationID, registryID, owner, topic, reference, expectedGeneration+1) == got {
		t.Fatal("expectedGeneration must affect the attempt id")
	}
	if ComputeCommitAttemptID(publicationID, registryID, owner, topic, strings.ToLower(reference), expectedGeneration) != got {
		t.Fatal("attempt id must canonicalize the reference before hashing")
	}
}

// TestIsGenerationConflictDistinguishesPermanentConflict proves the two
// control-plane conflict classes carry DISTINCT sentinels: only the
// recoverable generation conflict is recognized by IsGenerationConflict, so a
// permanent operation/binding conflict can never trigger a rebuild.
func TestIsGenerationConflictDistinguishesPermanentConflict(t *testing.T) {
	if !IsGenerationConflict(ErrCommitGenerationConflict) {
		t.Fatal("IsGenerationConflict must recognize the recoverable generation-conflict sentinel")
	}
	if IsGenerationConflict(ErrCommitConflict) {
		t.Fatal("IsGenerationConflict must NOT recognize the permanent operation/binding conflict sentinel")
	}
	if IsGenerationConflict(errors.New("unrelated")) {
		t.Fatal("IsGenerationConflict must not match an unrelated error")
	}
}

// TestPublishCommitWithConflictRebuildKeepsStablePublicationIDAcrossAttempts
// proves the one-time rebuild keeps ONE stable PublicationID — the identity
// recorded in the receipt (and, through it, TagPublications and the public
// response) — IDENTICAL across the conflicted attempt and the rebuild, while
// each attempt's wire-level FeedCommitRequest.OperationID is a FRESH
// per-attempt identity deterministically derived from that stable id plus the
// attempt's own ExpectedGeneration/Reference. This is what lets the durable
// FeedSigner operation row the rebuild reserves avoid colliding with the
// conflicted attempt's permanently-fixed request hash.
func TestPublishCommitWithConflictRebuildKeepsStablePublicationIDAcrossAttempts(t *testing.T) {
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	committer := &recordingCommitter{failFirst: 1, failWith: ErrCommitGenerationConflict}
	p := Publisher{Builder: DefaultBuilder{}, Objects: docs, Feeds: feeds, Commits: committer}

	registryID := int64(7)
	owner := "0xaliceowner"
	current := freshRepoState("backend/api", 5)
	fresh := freshRepoState("backend/api", 6)

	input := validBuildInput(t)
	publicationID := ComputeOperationID(registryID, owner, input.Repo, input.Tag, input.ManifestDigest, current.Generation)
	input.UpdatedAt = DeterministicUpdatedAt(publicationID)

	feed := spec.RepoStateFeedRef(owner, input.Repo)
	resolveCalls := 0
	receipt, err := p.PublishCommitWithConflictRebuild(context.Background(), feed, current, input, "batch-1", registryID, owner, publicationID,
		func(ctx context.Context) (spec.RepoStateDocument, bool, error) {
			resolveCalls++
			return fresh, true, nil
		})
	if err != nil {
		t.Fatalf("rebuild must succeed: %v", err)
	}
	if resolveCalls != 1 {
		t.Fatalf("expected exactly one re-resolution, got %d", resolveCalls)
	}
	if len(committer.calls) != 2 {
		t.Fatalf("expected exactly 2 commit attempts (1 conflict + 1 rebuild), got %d", len(committer.calls))
	}

	first, second := committer.calls[0], committer.calls[1]
	if first.PublicationID != publicationID || second.PublicationID != publicationID {
		t.Fatalf("both attempts must carry the SAME stable publication id, got %q and %q want %q", first.PublicationID, second.PublicationID, publicationID)
	}
	if receipt.OperationID != publicationID {
		t.Fatalf("receipt must expose the stable publication id, got %q want %q", receipt.OperationID, publicationID)
	}

	if first.OperationID == second.OperationID {
		t.Fatal("rebuilt attempt must derive a FRESH attempt id distinct from the conflicted attempt")
	}
	wantFirstAttempt := ComputeCommitAttemptID(publicationID, registryID, owner, first.Topic, first.Reference, first.ExpectedGeneration)
	wantSecondAttempt := ComputeCommitAttemptID(publicationID, registryID, owner, second.Topic, second.Reference, second.ExpectedGeneration)
	if first.OperationID != wantFirstAttempt {
		t.Fatalf("first attempt id must be deterministic in its own request, got %q want %q", first.OperationID, wantFirstAttempt)
	}
	if second.OperationID != wantSecondAttempt {
		t.Fatalf("second attempt id must be deterministic in its own request, got %q want %q", second.OperationID, wantSecondAttempt)
	}
	if second.ExpectedGeneration != fresh.Generation {
		t.Fatalf("rebuilt attempt must target the fresh ExpectedGeneration, got %d", second.ExpectedGeneration)
	}
}

// TestPublishCommitWithConflictRebuildRebasesExplicitPublicationIDToo proves
// an EXPLICIT client-chosen stable publication id ALSO rebuilds exactly once
// after an authoritative generation conflict, deriving two DISTINCT
// per-attempt identities exactly like the generated case — the stable id
// alone no longer prevents a safe rebase, since the durable FeedSigner
// operation row is keyed by the derived per-attempt identity, not the stable
// publication id.
func TestPublishCommitWithConflictRebuildRebasesExplicitPublicationIDToo(t *testing.T) {
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	committer := &recordingCommitter{failFirst: 1, failWith: ErrCommitGenerationConflict}
	p := Publisher{Builder: DefaultBuilder{}, Objects: docs, Feeds: feeds, Commits: committer}

	current := freshRepoState("backend/api", 5)
	fresh := freshRepoState("backend/api", 6)
	input := validBuildInput(t)
	const explicitID = "client-chosen-id-0001"
	input.UpdatedAt = DeterministicUpdatedAt(explicitID)

	feed := spec.RepoStateFeedRef("0xaliceowner", input.Repo)
	resolveCalls := 0
	receipt, err := p.PublishCommitWithConflictRebuild(context.Background(), feed, current, input, "batch-1", 7, "0xaliceowner", explicitID,
		func(ctx context.Context) (spec.RepoStateDocument, bool, error) {
			resolveCalls++
			return fresh, true, nil
		})
	if err != nil {
		t.Fatalf("explicit publication id rebuild must succeed: %v", err)
	}
	if resolveCalls != 1 {
		t.Fatalf("expected exactly one re-resolution, got %d", resolveCalls)
	}
	if len(committer.calls) != 2 {
		t.Fatalf("expected exactly 2 commit attempts, got %d", len(committer.calls))
	}
	if receipt.OperationID != explicitID {
		t.Fatalf("receipt must expose the stable explicit publication id, got %q", receipt.OperationID)
	}
	first, second := committer.calls[0], committer.calls[1]
	if first.PublicationID != explicitID || second.PublicationID != explicitID {
		t.Fatalf("both attempts must carry the client's stable publication id, got %q and %q", first.PublicationID, second.PublicationID)
	}
	if first.OperationID == second.OperationID {
		t.Fatal("rebuilt attempt must derive a FRESH attempt id distinct from the conflicted attempt")
	}
}

// TestPublishCommitWithConflictRebuildPermanentConflictNeverRebuilds proves a
// PERMANENT operation/binding conflict (errFeedSignerConflict at the control
// plane, ErrCommitConflict at this boundary) never triggers re-resolution or a
// second immutable upload/commit attempt — only a generation conflict is
// recoverable.
func TestPublishCommitWithConflictRebuildPermanentConflictNeverRebuilds(t *testing.T) {
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	committer := &recordingCommitter{failFirst: 99, failWith: ErrCommitConflict}
	p := Publisher{Builder: DefaultBuilder{}, Objects: docs, Feeds: feeds, Commits: committer}

	registryID := int64(7)
	owner := "0xaliceowner"
	current := freshRepoState("backend/api", 5)
	input := validBuildInput(t)
	publicationID := ComputeOperationID(registryID, owner, input.Repo, input.Tag, input.ManifestDigest, current.Generation)
	input.UpdatedAt = DeterministicUpdatedAt(publicationID)

	feed := spec.RepoStateFeedRef(owner, input.Repo)
	resolveCalls := 0
	_, err := p.PublishCommitWithConflictRebuild(context.Background(), feed, current, input, "batch-1", registryID, owner, publicationID,
		func(ctx context.Context) (spec.RepoStateDocument, bool, error) {
			resolveCalls++
			return spec.RepoStateDocument{}, false, nil
		})
	if !errors.Is(err, ErrCommitConflict) {
		t.Fatalf("expected the permanent conflict to surface unchanged, got %v", err)
	}
	if resolveCalls != 0 {
		t.Fatalf("a PERMANENT conflict must never trigger re-resolution: expected 0, got %d", resolveCalls)
	}
	if len(committer.calls) != 1 {
		t.Fatalf("a PERMANENT conflict must never retry the commit: expected 1 attempt, got %d", len(committer.calls))
	}
}
