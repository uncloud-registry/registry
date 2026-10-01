package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
)

// Round 3, Finding 1: the FeedSigner.Commit publication-execution gate. A
// stable PublicationID that already reached a terminal success must NEVER
// authorize a DIFFERENT attempt to advance the feed again — the exact defect
// where P succeeds, an unrelated Q later overwrites the same tag, and a
// retried P (recomputing a fresh per-attempt identity against the new
// generation) would otherwise authenticate cleanly and advance the feed a
// second time. These tests exercise the gate directly against the FeedSigner
// (never through HTTP), using a REAL file-backed Store; the full production
// HTTP/registry.Handler P/Q/P proof lives in
// task17_real_conflict_integration_test.go.

// TestFeedSignerGateRejectsDifferentAttemptAfterSuccess proves that once a
// PublicationID's first attempt succeeds, a SECOND, DIFFERENT attempt id for
// the SAME PublicationID is rejected as a PERMANENT conflict before the gate
// ever reads the (arbitrary, never-served) target document its Reference
// names — zero feed advancement, zero new feed_signer_operations row, and the
// durable publication_states row stays succeeded under the ORIGINAL attempt.
func TestFeedSignerGateRejectsDifferentAttemptAfterSuccess(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFileBackedFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
		targetTags: map[string]string{"latest": "sha256:" + refHex('a')},
		artifact:   &fx,
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	publicationID := req.OperationID
	attemptID1 := publish.ComputeCommitAttemptID(publicationID, req.RegistryID, req.Owner, req.Topic, req.Reference, req.ExpectedGeneration)
	req.OperationID = attemptID1
	req.PublicationID = publicationID

	if _, err := w.signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("first attempt must succeed: %v", err)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('a') {
		t.Fatalf("feed must resolve to the first attempt's reference, got %q", got)
	}

	// A DIFFERENT fresh attempt for the SAME PublicationID (as if Q had
	// overwritten the tag and P was retried against the new generation). Its
	// Reference is deliberately never seeded in the document store — the gate
	// must reject BEFORE any document is ever read.
	req2 := req
	req2.ExpectedGeneration = 5
	req2.Reference = refHex('f')
	req2.OperationID = publish.ComputeCommitAttemptID(publicationID, req.RegistryID, req.Owner, req.Topic, req2.Reference, req2.ExpectedGeneration)

	_, err := w.signer.Commit(context.Background(), req2)
	if !errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("a different attempt after terminal success must be a permanent conflict, got %v", err)
	}

	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('a') {
		t.Fatalf("the feed must NEVER advance again, got %q", got)
	}
	if _, err := w.store.GetFeedSignerOperation(context.Background(), req2.OperationID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("a rejected different attempt must never create a durable feed_signer_operations row")
	}
	exec, err := w.store.GetPublicationExecution(context.Background(), publicationID)
	if err != nil {
		t.Fatalf("publication execution lookup: %v", err)
	}
	if exec.State != PublicationExecutionSucceeded || exec.AttemptID != attemptID1 {
		t.Fatalf("the durable publication execution must remain succeeded under the ORIGINAL attempt, got %+v", exec)
	}
}

// TestFeedSignerGateSameAttemptRetryAfterSuccessIsIdempotent proves a
// lost-response retry of the EXACT SAME attempt (same PublicationID, same
// per-attempt OperationID) after a terminal success returns the identical
// stored result and performs ZERO additional feed writes.
func TestFeedSignerGateSameAttemptRetryAfterSuccessIsIdempotent(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	fx := simpleArtifact(t, '4', '5', '6', 100, 100)
	w := newFileBackedFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
		targetTags: map[string]string{"latest": "sha256:" + refHex('a')},
		artifact:   &fx,
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	publicationID := req.OperationID
	attemptID := publish.ComputeCommitAttemptID(publicationID, req.RegistryID, req.Owner, req.Topic, req.Reference, req.ExpectedGeneration)
	req.OperationID = attemptID
	req.PublicationID = publicationID

	first, err := w.signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("first attempt must succeed: %v", err)
	}

	second, err := w.signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("same-attempt retry must be idempotent, got error: %v", err)
	}
	if second != first {
		t.Fatalf("retry must return the IDENTICAL stored result, got %+v want %+v", second, first)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('a') {
		t.Fatalf("retry must not advance the feed, got %q", got)
	}
	exec, err := w.store.GetPublicationExecution(context.Background(), publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionSucceeded || exec.AttemptID != attemptID {
		t.Fatalf("execution must remain succeeded/%s, got %+v", attemptID, exec)
	}
}

// TestFeedSignerGateNonGenerationFailureNeverAuthorizesReplacement proves the
// gate distinguishes failure classes: a definite MALFORMED failure (an
// impermissible batch id, never a generation mismatch) must NOT flip the
// publication's execution row to replaceable, so a DIFFERENT fresh attempt
// for the same PublicationID is blocked (a retryable backend condition, never
// a silent authorization) even though the first attempt never advanced the
// feed.
// alwaysFailingFeedUpdater simulates a dependency/network failure on every
// external feed update: a plain (non-ErrFeedAlreadyExists) error, which
// finishBoundCommit's caller (runSignedCommit) classifies as UNCERTAIN — the
// one non-generation failure class that can still occur strictly AFTER the
// publication execution slot has already been durably reserved active, since
// round 5 moved every OTHER non-generation check (binding/provenance,
// current-transition integrity, batch/stamp authorization) into
// prepareBoundCommit's zero-mutation phase, which runs strictly BEFORE
// authorizePublicationExecution ever reserves anything.
type alwaysFailingFeedUpdater struct{}

func (alwaysFailingFeedUpdater) UpdateRegistryFeed(context.Context, Registry, string, string, string, bool) error {
	return errors.New("simulated backend/network failure")
}

func TestFeedSignerGateNonGenerationFailureNeverAuthorizesReplacement(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	fx := simpleArtifact(t, '7', '8', '9', 100, 100)
	w := newFileBackedFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
		targetTags: map[string]string{"latest": "sha256:" + refHex('a')},
		artifact:   &fx,
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	publicationID := req.OperationID
	attemptID1 := publish.ComputeCommitAttemptID(publicationID, req.RegistryID, req.Owner, req.Topic, req.Reference, req.ExpectedGeneration)
	req.OperationID = attemptID1
	req.PublicationID = publicationID

	// An otherwise fully-authenticated attempt (round 5: every non-generation
	// check already passed in the zero-mutation preparation phase, and the
	// publication execution slot is durably reserved active) whose external
	// update fails UNCERTAINLY. This is a definite NON-generation-conflict
	// condition, so the row must stay active under attempt1 — NEVER released,
	// NEVER marked replaceable.
	w.signer.Feeds = alwaysFailingFeedUpdater{}

	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("an uncertain update failure must surface as a retryable backend condition, got %v", err)
	}
	if errors.Is(err, errFeedSignerGenerationConflict) {
		t.Fatal("an uncertain update failure must never surface as a generation conflict")
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("the feed must be untouched, got %q", got)
	}
	exec, err := w.store.GetPublicationExecution(context.Background(), publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionActive || exec.AttemptID != attemptID1 {
		t.Fatalf("a non-generation (uncertain update) failure must NEVER flip the row to replaceable, got %+v", exec)
	}

	// A DIFFERENT fresh attempt (even a well-formed, otherwise-valid one) for
	// the same PublicationID must be blocked: the recorded attempt has not
	// been proven dead by a generation conflict.
	req2 := req
	req2.BatchID = "batch-1"
	req2.ExpectedGeneration = 5
	req2.Reference = refHex('f')
	req2.OperationID = publish.ComputeCommitAttemptID(publicationID, req.RegistryID, req.Owner, req.Topic, req2.Reference, req2.ExpectedGeneration)

	_, err = w.signer.Commit(context.Background(), req2)
	if err == nil || errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("a different attempt while the recorded one is still active (never proven conflicted) must be a retryable backend condition, not a permanent conflict or a success, got %v", err)
	}
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("expected a retryable backend condition, got %v", err)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("the feed must still be untouched, got %q", got)
	}
	exec, err = w.store.GetPublicationExecution(context.Background(), publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionActive || exec.AttemptID != attemptID1 {
		t.Fatalf("the row must remain active under the ORIGINAL attempt, got %+v", exec)
	}
}

// TestFeedSignerGateGenerationConflictAuthorizesExactlyOneReplacement proves
// the ONLY failure class that ever authorizes a replacement attempt is an
// authoritative generation conflict: the first attempt's stale
// ExpectedGeneration is rejected as a generation conflict, flips the
// publication's row to replaceable, and a fresh SECOND attempt (correct
// generation/reference) then wins the CAS, becomes active, and succeeds —
// advancing the feed exactly once.
func TestFeedSignerGateGenerationConflictAuthorizesExactlyOneReplacement(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	fx := simpleArtifact(t, 'a', 'b', 'c', 100, 100)
	w := newFileBackedFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
		targetTags: map[string]string{"latest": "sha256:" + refHex('a')},
		artifact:   &fx,
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	publicationID := req.OperationID
	// A STALE expected generation: the actual current feed is at generation 0
	// (currentGen), but this attempt claims generation 3 — an authoritative
	// generation conflict, decided before any object write.
	req.ExpectedGeneration = 3
	attemptID1 := publish.ComputeCommitAttemptID(publicationID, req.RegistryID, req.Owner, req.Topic, req.Reference, req.ExpectedGeneration)
	req.OperationID = attemptID1
	req.PublicationID = publicationID

	if _, err := w.signer.Commit(context.Background(), req); !errors.Is(err, errFeedSignerGenerationConflict) {
		t.Fatalf("stale expected generation must be a generation conflict, got %v", err)
	}
	exec, err := w.store.GetPublicationExecution(context.Background(), publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionReplaceable || exec.AttemptID != attemptID1 {
		t.Fatalf("an authoritative generation conflict must flip the row to replaceable, got %+v", exec)
	}

	// The fresh replacement attempt targets the REAL generation 0->1 target
	// document the world seeded (currentGen=0, targetGen=1, targetRef).
	req2 := req
	req2.ExpectedGeneration = 0
	req2.Reference = refHex('a')
	req2.OperationID = publish.ComputeCommitAttemptID(publicationID, req.RegistryID, req.Owner, req.Topic, req2.Reference, req2.ExpectedGeneration)

	if _, err := w.signer.Commit(context.Background(), req2); err != nil {
		t.Fatalf("the replacement attempt must succeed: %v", err)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('a') {
		t.Fatalf("the feed must advance exactly once, to the replacement's reference, got %q", got)
	}
	exec, err = w.store.GetPublicationExecution(context.Background(), publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionSucceeded || exec.AttemptID != req2.OperationID {
		t.Fatalf("the row must terminate succeeded under the REPLACEMENT attempt, got %+v", exec)
	}
}
