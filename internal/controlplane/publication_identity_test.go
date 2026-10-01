package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
)

// TestNormalizeFeedCommitHashSeparatesPublicationID proves the request hash
// domain-separates on PublicationID: two otherwise-identical requests that
// differ ONLY in their stable publication identity (or one that carries none
// at all) must never collide, so two DISTINCT stable publications sharing an
// attempt's other fields can never be confused as the same durable request.
func TestNormalizeFeedCommitHashSeparatesPublicationID(t *testing.T) {
	base := validCommitReq(1, "batch-1")
	base.Topic = "feed://" + testFeedOwner + "/" + refHex('d')
	base.PublicationID = "pub-a"
	h1 := NormalizeFeedCommitHash(base)

	other := base
	other.PublicationID = "pub-b"
	h2 := NormalizeFeedCommitHash(other)
	if h1 == h2 {
		t.Fatal("two requests differing only in PublicationID must hash differently")
	}

	legacy := base
	legacy.PublicationID = ""
	h3 := NormalizeFeedCommitHash(legacy)
	if h3 == h1 {
		t.Fatal("an empty (legacy) PublicationID must not accidentally collide with a non-empty one")
	}
}

// TestFeedSignerRejectsAttemptIDNotDerivedFromPublicationID proves that when a
// request carries a non-empty PublicationID, its OperationID MUST be exactly
// the deterministic per-attempt identity ComputeCommitAttemptID derives from
// it — a forged, stale, or otherwise arbitrary OperationID is rejected
// malformed BEFORE any request hashing, durable row reservation, or
// registry/document lookup.
func TestFeedSignerRejectsAttemptIDNotDerivedFromPublicationID(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	w := newFileBackedFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	req.PublicationID = "pub-stable-xyz"
	req.OperationID = "not-the-deterministic-attempt-id"

	if _, err := w.signer.Commit(context.Background(), req); !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("mismatched attempt identity must be rejected malformed, got %v", err)
	}
	if _, err := w.store.GetFeedSignerOperation(context.Background(), req.OperationID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("a rejected mismatched attempt identity must never create a durable operation row")
	}
}

// TestFeedSignerAuthenticatesDistinctAttemptAndPublicationIdentities proves
// the two identities live in two entirely separate durable records: the
// per-attempt FeedCommitRequest.OperationID keys the feed_signer_operations
// row (Task 10/14 durable idempotency, unchanged), while the STABLE
// PublicationID keys the SEPARATE publication_bindings row (provenance/
// binding authentication) — never the same row, and the per-attempt identity
// is never itself accepted as a bound publication identity.
func TestFeedSignerAuthenticatesDistinctAttemptAndPublicationIdentities(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFileBackedFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
		targetTags: map[string]string{"latest": "sha256:" + refHex('a')},
		artifact:   &fx,
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	// The fixture seeded the target document's provenance and the durable
	// binding row under req.OperationID ("op-1") — that value now becomes the
	// STABLE PublicationID, and a FRESH deterministic value becomes the
	// per-attempt identity actually sent as OperationID.
	publicationID := req.OperationID
	attemptID := publish.ComputeCommitAttemptID(publicationID, req.RegistryID, req.Owner, req.Topic, req.Reference, req.ExpectedGeneration)
	req.OperationID = attemptID
	req.PublicationID = publicationID

	result, err := w.signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("commit with distinct attempt/publication identities must succeed: %v", err)
	}
	if result.OperationID != attemptID {
		t.Fatalf("result must echo the per-ATTEMPT identity, got %q want %q", result.OperationID, attemptID)
	}

	op, err := w.store.GetFeedSignerOperation(context.Background(), attemptID)
	if err != nil {
		t.Fatalf("attempt row lookup by attempt id: %v", err)
	}
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("attempt row must be succeeded, got %v", op.State)
	}

	binding, err := w.store.GetPublicationBinding(context.Background(), publicationID)
	if err != nil {
		t.Fatalf("publication binding lookup by publication id: %v", err)
	}
	if binding.RegistryID != req.RegistryID {
		t.Fatalf("binding registry mismatch: %+v", binding)
	}
	if _, err := w.store.GetPublicationBinding(context.Background(), attemptID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("the per-attempt identity must NEVER itself be durably bound as a publication identity")
	}
}
