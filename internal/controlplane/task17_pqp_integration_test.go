package controlplane

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/registry"
	"github.com/uncloud-registry/registry/internal/spec"
)

// putManifestOp is putManifest plus an explicit caller operation-id header —
// the stable PublicationID a real client supplies for restart-safe retries.
// An empty opID omits the header (the generated-identity path).
func (w *realConflictWorld) putManifestOp(t *testing.T, serverURL, tag, opID string, body []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, serverURL+"/v2/"+integrationRepo+"/manifests/"+tag, bytes.NewReader(body))
	req.Host = integrationServiceHost
	req.Header.Set("Authorization", w.bearer(t))
	req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
	if opID != "" {
		req.Header.Set(registry.OperationIDHeader, opID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("manifest publish request: %v", err)
	}
	return resp
}

// TestRealFeedSignerTerminalPublicationSurvivesLaterOverwrite is the
// MANDATORY round-3 / Finding 1 acceptance proof: P (an explicit stable
// PublicationID) succeeds; Q — an entirely unrelated LATER publication —
// overwrites the SAME tag; a retried P (the identical explicit key and
// payload) must produce ZERO additional feed advancement and must NEVER be
// authorized as a fresh attempt, even though retrying naturally computes a
// FRESH per-attempt identity against the new (post-Q) generation. This runs
// through the REAL file-backed Store, the REAL FeedSigner, the REAL
// InternalFeedServer HTTP boundary, and a REAL registry.Handler — never a
// fake committer — exactly like the round-2 conflict-rebuild proof.
func TestRealFeedSignerTerminalPublicationSurvivesLaterOverwrite(t *testing.T) {
	w := newRealConflictWorld(t)
	const stablePublicationID = "pub-pqp-stable-P"

	// P: the first publication, under an explicit stable PublicationID.
	configP := []byte(`{"publication":"P"}`)
	configPDigest := w.stageBlob(t, w.s1.URL, configP)
	manifestP := integrationManifest(configPDigest, len(configP))
	manifestPDigest := publish.ComputeDigest(manifestP)

	respP := w.putManifestOp(t, w.s1.URL, "img", stablePublicationID, manifestP)
	bodyP, _ := io.ReadAll(respP.Body)
	respP.Body.Close()
	if respP.StatusCode != http.StatusCreated {
		t.Fatalf("P publish status %d: %s", respP.StatusCode, bodyP)
	}
	if got := respP.Header.Get(registry.OperationIDHeader); got != stablePublicationID {
		t.Fatalf("P's response must echo the caller's stable id, got %q want %q", got, stablePublicationID)
	}
	afterP := w.currentRepoState(t)
	if afterP.Generation != 1 {
		t.Fatalf("expected generation 1 after P, got %d", afterP.Generation)
	}
	if afterP.Tags["img"] != manifestPDigest {
		t.Fatalf("tag must map to P's digest after P, got %+v", afterP.Tags)
	}
	pPub, ok := afterP.TagPublications["img"]
	if !ok || pPub.OperationID != stablePublicationID {
		t.Fatalf("provenance must record P's stable id, got %+v", pPub)
	}
	opsAfterP := w.feedSignerOperationCount(t)

	// Compute P's real per-attempt identity (registryID/owner/topic/reference
	// at P's ORIGINAL generation 0) so we can independently confirm the
	// durable publication_states row terminates under it.
	stateFeed := spec.RepoStateFeedRef(integrationOwnerHex, integrationRepo)
	attemptP1 := publish.ComputeCommitAttemptID(stablePublicationID, w.registryRow.ID, integrationOwnerHex, stateFeed, mustFeedRef(t, w, stateFeed), 0)

	execAfterP, err := w.store.GetPublicationExecution(context.Background(), stablePublicationID)
	if err != nil {
		t.Fatalf("publication execution lookup after P: %v", err)
	}
	if execAfterP.State != PublicationExecutionSucceeded || execAfterP.AttemptID != attemptP1 {
		t.Fatalf("execution must be succeeded under P's real attempt id, got %+v want attempt %q", execAfterP, attemptP1)
	}

	// Q: an entirely UNRELATED later publication (generated identity) that
	// overwrites the SAME tag with DIFFERENT content — modeling a legitimate
	// retag that has nothing to do with P.
	configQ := []byte(`{"publication":"Q"}`)
	configQDigest := w.stageBlob(t, w.s2.URL, configQ)
	manifestQ := integrationManifest(configQDigest, len(configQ))
	manifestQDigest := publish.ComputeDigest(manifestQ)

	respQ := w.putManifestOp(t, w.s2.URL, "img", "", manifestQ)
	bodyQ, _ := io.ReadAll(respQ.Body)
	respQ.Body.Close()
	if respQ.StatusCode != http.StatusCreated {
		t.Fatalf("Q publish status %d: %s", respQ.StatusCode, bodyQ)
	}
	afterQ := w.currentRepoState(t)
	if afterQ.Generation != 2 {
		t.Fatalf("expected generation 2 after Q, got %d", afterQ.Generation)
	}
	if afterQ.Tags["img"] != manifestQDigest {
		t.Fatalf("tag must map to Q's digest after Q (P's mapping overwritten), got %+v", afterQ.Tags)
	}
	qPub := afterQ.TagPublications["img"]
	if qPub.OperationID == stablePublicationID {
		t.Fatal("Q's provenance must NOT be P's stable id (Q is unrelated)")
	}
	opsAfterQ := w.feedSignerOperationCount(t)

	// Retry P: the EXACT SAME explicit stable key and the EXACT SAME payload
	// (manifestP, tag "img"). Because the tag no longer maps to P's digest,
	// the handler's fast-path retry recognition does NOT fire, so this falls
	// through to a FRESH publication attempt with a FRESH per-attempt
	// identity computed against the post-Q generation. That fresh attempt
	// must be rejected as a PERMANENT conflict before any feed write.
	retryResp := w.putManifestOp(t, w.s1.URL, "img", stablePublicationID, manifestP)
	retryBody, _ := io.ReadAll(retryResp.Body)
	retryResp.Body.Close()
	if retryResp.StatusCode != http.StatusConflict {
		t.Fatalf("retried P must be rejected as a conflict, got status %d: %s", retryResp.StatusCode, retryBody)
	}

	// Zero additional feed advancement: generation, tags, and provenance are
	// EXACTLY what Q left them.
	final := w.currentRepoState(t)
	if final.Generation != 2 {
		t.Fatalf("retried P must NOT advance the feed again, got generation %d", final.Generation)
	}
	if final.Tags["img"] != manifestQDigest {
		t.Fatalf("retried P must NOT restore P's tag mapping, got %+v", final.Tags)
	}
	if final.TagPublications["img"].OperationID != qPub.OperationID {
		t.Fatalf("retried P must NOT overwrite Q's provenance, got %+v want %+v", final.TagPublications["img"], qPub)
	}

	// No fresh authorized attempt: no new feed_signer_operations row was
	// created for the retry (the gate rejected it before ever reserving one).
	if n := w.feedSignerOperationCount(t); n != opsAfterQ {
		t.Fatalf("retried P must create ZERO new feed_signer_operations rows, count changed from %d to %d", opsAfterQ, n)
	}
	if opsAfterQ <= opsAfterP {
		t.Fatalf("sanity: Q must have created at least one new operation row, got opsAfterP=%d opsAfterQ=%d", opsAfterP, opsAfterQ)
	}

	// The durable terminal state remains EXACTLY what it was after P
	// succeeded: succeeded, under P's ORIGINAL attempt id — never replaced,
	// never re-authorized, never touched by Q or by the rejected retry.
	execFinal, err := w.store.GetPublicationExecution(context.Background(), stablePublicationID)
	if err != nil {
		t.Fatalf("publication execution lookup after retry: %v", err)
	}
	if execFinal.State != PublicationExecutionSucceeded || execFinal.AttemptID != attemptP1 {
		t.Fatalf("durable terminal state must be unchanged, got %+v want succeeded/%q", execFinal, attemptP1)
	}
}

// mustFeedRef resolves the CURRENT immutable reference the given feed
// resolves to.
func mustFeedRef(t *testing.T, w *realConflictWorld, feed string) string {
	t.Helper()
	ref, err := w.feeds.ResolveFeed(context.Background(), feed)
	if err != nil {
		t.Fatalf("resolve feed %q: %v", feed, err)
	}
	return ref
}
