package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// Round 4 / Finding 2, MANDATORY acceptance proof: the durable
// publication_states row for a stable PublicationID must never be reserved
// or CASed for an attempt whose payload has not yet been authenticated
// against the immutable target document. This is the exact "PublicationID
// poisoning" sequence the round-3 ordering (authorizePublicationExecution
// running BEFORE authenticatePublicationBinding) left open: an
// internal-credential caller presenting a WRONG payload could still derive a
// self-consistent attempt id for a real stable PublicationID, seize its
// (as yet unreserved) execution slot, and — provided the wrong payload also
// happened to trip the generation-conflict class — leave the row durably
// "replaceable" under a NEVER-AUTHENTICATED attempt, even though the row's
// legitimate owner (the caller who actually preflight-bound the id) had not
// yet made a single request.
//
// This test drives the FULL production composition — two INDEPENDENT
// controlplane.Store handles over one shared file-backed SQLite database,
// each wrapped by its own real FeedSigner and served over its own real
// InternalFeedServer HTTP boundary — exactly the cross-process topology
// task17_real_conflict_integration_test.go and feed_signer_test.go's
// sharedFeedWorld already established for Task 17's other mandatory proofs.
//
// It must FAIL if run against the pre-fix (round 3) ordering, where
// authorizePublicationExecution ran before authenticatePublicationBinding:
// under that ordering, B's forged/mismatched payload — shaped to ALSO trip
// the historical early (target-document) generation-conflict check — would
// reserve publication_states for P under B's attempt id BEFORE any
// authentication ever ran, then get marked "replaceable" once the generation
// check (reached only because authentication had not yet gated it) failed.
// Both of the following would then diverge from this test's assertions:
//   - the wire status would be 412 (generation conflict), not 400
//     (malformed) — the generation check, not authentication, would be the
//     first thing to reject B;
//   - a publication_states row for P WOULD exist (state replaceable, attempt
//     id = B's forged identity) instead of not existing at all.
func TestFeedSignerPublicationIDPoisoningRequiresAuthenticationBeforeExecutionGate(t *testing.T) {
	ctx := context.Background()
	const publicationID = "pub-poison-P"
	const poisonSecret = "poison-test-internal-secret-0123456789"

	// --- two independent Store handles over ONE shared file-backed database ---
	dbPath := filepath.Join(t.TempDir(), "poison.sqlite")
	store1, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("open store1: %v", err)
	}
	t.Cleanup(func() { store1.DB.Close() })
	store2, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("open store2: %v", err)
	}
	t.Cleanup(func() { store2.DB.Close() })
	if _, err := store1.DB.ExecContext(ctx, `pragma busy_timeout = 10000`); err != nil {
		t.Fatal(err)
	}
	if _, err := store2.DB.ExecContext(ctx, `pragma busy_timeout = 10000`); err != nil {
		t.Fatal(err)
	}

	owner := seedProvisioningOwner(t, store1)
	feedOwner := testFeedOwner
	ownerHex0x := "0x" + feedOwner
	reg, err := store1.CreateProvisionedRegistry(ctx, Registry{
		Slug: "poisonreg", Host: "poisonreg.test", ENSName: "",
		OwnerUserID: owner.ID, FeedOwnerAddress: feedOwner, DefaultStampBatchID: "batch-1",
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create provisioned registry: %v", err)
	}
	if err := store1.MarkRegistryReady(ctx, reg.ID); err != nil {
		t.Fatalf("mark registry ready: %v", err)
	}

	repoTopic := spec.RepoStateFeedRef(feedOwner, testRepo)
	stampFeed := spec.StampPolicyFeedRef(feedOwner)
	currentRef := refHex('0')
	stampRef := refHex('c')

	feedStore := &MemoryRegistryFeedStore{Feeds: map[string]string{
		repoTopic: currentRef,
		stampFeed: stampRef,
	}}
	updater := &countingFeedUpdater{inner: feedStore}
	docs := resolve.NewMemoryDocumentStore()
	docs.Documents = map[string][]byte{
		currentRef: mustRepoDoc(t, testRepo, 0),
		stampRef:   mustStampDoc(t, "batch-1"),
	}
	bytesReader := newMemoryBytesReader()

	signer1 := &FeedSigner{Store: store1, Feeds: updater, ResolveFeeds: feedStore, Docs: docs, Bytes: bytesReader}
	signer2 := &FeedSigner{Store: store2, Feeds: updater, ResolveFeeds: feedStore, Docs: docs, Bytes: bytesReader}

	srv1, err := NewInternalFeedServer(signer1, &PublicationBinder{Store: store1}, []byte(poisonSecret), nil)
	if err != nil {
		t.Fatalf("new internal feed server 1: %v", err)
	}
	srv2, err := NewInternalFeedServer(signer2, &PublicationBinder{Store: store2}, []byte(poisonSecret), nil)
	if err != nil {
		t.Fatalf("new internal feed server 2: %v", err)
	}

	// --- Step 1: preflight-bind the stable PublicationID P to legitimate
	// payload A (repo/tag/digest/document provenance A), through store1 —
	// the exact durable preflight reservation the real data plane performs
	// before its first immutable write for an explicit stable key. ---
	fxA := simpleArtifact(t, '1', '2', '3', 100, 100)
	bytesReader.serve(fxA.manifest.SwarmRef, fxA.body)
	referenceA := refHex('a')
	docs.Documents[referenceA] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": fxA.digest},
		map[string]spec.TagPublication{"latest": {OperationID: publicationID, Generation: 1, Digest: fxA.digest}},
		map[string]spec.ManifestDescriptor{fxA.digest: fxA.manifest},
		fxA.blobDescs)
	hashA := NormalizePublicationBindingHash(reg.ID, ownerHex0x, testRepo, "latest", fxA.digest)
	if _, err := store1.ReservePublicationBinding(ctx, publicationID, reg.ID, hashA); err != nil {
		t.Fatalf("preflight-bind P to legitimate payload A: %v", err)
	}

	// --- Step 2: through signer/handler/store INSTANCE 1, submit P with a
	// DIFFERENT payload B (an unrelated tag/digest, no provenance entry for
	// P at all — mismatching P's binding/provenance) using B's own
	// correctly-derived attempt OperationID. B's target document generation
	// is ALSO deliberately shaped to trip the historical early
	// (target-document) generation-conflict check the pre-fix ordering
	// reached before ever authenticating anything. ---
	referenceB := refHex('f')
	digestOther := digestRef('9')
	const expectedGenerationB = 0
	const docBGeneration = 9 // != expectedGenerationB+1: the historical early generation-conflict shape.
	docs.Documents[referenceB] = transitionDoc(t, testRepo, docBGeneration,
		map[string]string{"other-tag": digestOther},
		map[string]spec.TagPublication{"other-tag": {OperationID: "attacker-unrelated-op", Generation: docBGeneration, Digest: digestOther}},
		manifestsForTags(map[string]string{"other-tag": digestOther}, nil),
		map[string]spec.BlobDescriptor{})

	attemptIDB := publish.ComputeCommitAttemptID(publicationID, reg.ID, ownerHex0x, repoTopic, referenceB, expectedGenerationB)
	reqB := publish.FeedCommitRequest{
		PublicationID:      publicationID,
		OperationID:        attemptIDB,
		RegistryID:         reg.ID,
		Owner:              ownerHex0x,
		Topic:              repoTopic,
		Reference:          referenceB,
		BatchID:            "batch-1",
		ExpectedGeneration: expectedGenerationB,
	}

	// First, drive it directly through the signer to inspect the Go-level
	// sentinel/error text (no wire-body serialization involved yet).
	_, directErr := signer1.Commit(ctx, reqB)
	if directErr == nil {
		t.Fatal("B (forged/mismatched payload with a correctly-derived attempt id) must be rejected")
	}
	if !errors.Is(directErr, errFeedSignerMalformed) {
		t.Fatalf("B must be rejected as malformed (authentication must run BEFORE the generation-conflict class is ever reached), got %v", directErr)
	}
	if errors.Is(directErr, errFeedSignerGenerationConflict) {
		t.Fatalf("B must NOT surface as a generation conflict — that is exactly the pre-fix (round 3) ordering this test guards against: %v", directErr)
	}
	if errors.Is(directErr, errFeedSignerConflict) {
		t.Fatalf("B must not be classified as the permanent operation/binding conflict sentinel either, got %v", directErr)
	}
	directErrText := directErr.Error()
	for _, leak := range []string{publicationID, referenceB, attemptIDB, digestOther, "attacker-unrelated-op", fxA.digest, referenceA} {
		if strings.Contains(directErrText, leak) {
			t.Fatalf("the Go-level error must be data-free but leaked %q: %v", leak, directErr)
		}
	}

	// Now drive the SAME request through the real HTTP wire boundary
	// (instance 1's InternalFeedServer) and inspect the actual serialized
	// response body: a fixed generic string, never internal error text.
	bodyB, err := json.Marshal(reqB)
	if err != nil {
		t.Fatal(err)
	}
	recB := postFeedUpdate(t, srv1, publish.InternalFeedUpdatePathV2, poisonSecret, string(bodyB))
	if recB.Code != http.StatusBadRequest {
		t.Fatalf("B must be rejected 400 malformed over the wire (a 412 would mean the generation check ran before payload authentication), got %d: %s", recB.Code, recB.Body.String())
	}
	wireBody := recB.Body.String()
	if strings.TrimSpace(wireBody) != `{"error":"invalid request"}` {
		t.Fatalf("rejected wire body must be the fixed generic malformed message, got %q", wireBody)
	}
	for _, leak := range []string{publicationID, referenceB, attemptIDB, digestOther, "attacker-unrelated-op", fxA.digest, referenceA} {
		if strings.Contains(wireBody, leak) {
			t.Fatalf("the wire response body must be data-free but leaked %q: %s", leak, wireBody)
		}
	}

	// --- Step 4: zero durable publication_states row for P, zero B row that
	// ever reached 'succeeded', and zero external feed update/advancement.
	// Count each boundary directly. ---
	var pubStateRows int
	if err := store1.DB.QueryRowContext(ctx, `select count(*) from publication_states where operation_id = ?`, publicationID).Scan(&pubStateRows); err != nil {
		t.Fatal(err)
	}
	if pubStateRows != 0 {
		t.Fatalf("a rejected, unauthenticated attempt must NEVER create a publication_states row for P — the pre-fix ordering would leave exactly one (replaceable, under B's forged attempt id); got %d", pubStateRows)
	}
	if _, err := store1.GetPublicationExecution(ctx, publicationID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPublicationExecution must report sql.ErrNoRows for P, got %v", err)
	}
	var bSucceededRows int
	if err := store1.DB.QueryRowContext(ctx, `select count(*) from feed_signer_operations where operation_id = ? and state = 'succeeded'`, attemptIDB).Scan(&bSucceededRows); err != nil {
		t.Fatal(err)
	}
	if bSucceededRows != 0 {
		t.Fatalf("B's forged attempt must never durably succeed as a feed_signer_operations row, got %d succeeded rows", bSucceededRows)
	}
	// The durable idempotency row B's rejected attempt reserved (if any) must
	// be released back to pending — never left claimed/processing — exactly
	// like every other definite pre-update failure class in this package.
	if opB, err := store1.GetFeedSignerOperation(ctx, attemptIDB); err == nil {
		if opB.State != FeedSignerOpPending {
			t.Fatalf("B's attempt row must be released to pending (never left processing/succeeded), got %q", opB.State)
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("rejected B must cause ZERO external feed updates, got %d", n)
	}
	if got := feedStore.Feeds[repoTopic]; got != currentRef {
		t.Fatalf("the feed must be untouched by the rejected attempt, got %q", got)
	}

	// --- Step 5: through INDEPENDENT instance 2 over the SAME file-backed
	// DB, submit legitimate A with its own correctly-derived attempt id.
	// Prove it succeeds exactly once, creates the expected terminal
	// publication state, and exactly one external feed advancement occurs
	// (the rejected B above must not have consumed or blocked it). ---
	attemptIDA := publish.ComputeCommitAttemptID(publicationID, reg.ID, ownerHex0x, repoTopic, referenceA, 0)
	reqA := publish.FeedCommitRequest{
		PublicationID:      publicationID,
		OperationID:        attemptIDA,
		RegistryID:         reg.ID,
		Owner:              ownerHex0x,
		Topic:              repoTopic,
		Reference:          referenceA,
		BatchID:            "batch-1",
		ExpectedGeneration: 0,
	}
	bodyA, err := json.Marshal(reqA)
	if err != nil {
		t.Fatal(err)
	}
	recA := postFeedUpdate(t, srv2, publish.InternalFeedUpdatePathV2, poisonSecret, string(bodyA))
	if recA.Code != http.StatusOK {
		t.Fatalf("legitimate A through the independent second instance must succeed, got %d: %s", recA.Code, recA.Body.String())
	}
	var result publish.FeedCommitResult
	if err := json.Unmarshal(recA.Body.Bytes(), &result); err != nil {
		t.Fatalf("bad result body: %v", err)
	}
	if result.OperationID != attemptIDA || result.Reference != referenceA || result.Feed != repoTopic {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected EXACTLY ONE external feed advancement total, got %d", n)
	}
	if got := feedStore.Feeds[repoTopic]; got != referenceA {
		t.Fatalf("the feed must advance to A's reference, got %q", got)
	}
	exec, err := store2.GetPublicationExecution(ctx, publicationID)
	if err != nil {
		t.Fatalf("publication execution lookup after A: %v", err)
	}
	if exec.State != PublicationExecutionSucceeded || exec.AttemptID != attemptIDA || exec.RegistryID != reg.ID {
		t.Fatalf("the durable publication state must terminate succeeded under A's OWN attempt id, got %+v want attempt %q", exec, attemptIDA)
	}
	opA, err := store2.GetFeedSignerOperation(ctx, attemptIDA)
	if err != nil {
		t.Fatal(err)
	}
	if opA.State != FeedSignerOpSucceeded {
		t.Fatalf("A's attempt row must be succeeded, got %q", opA.State)
	}
}
