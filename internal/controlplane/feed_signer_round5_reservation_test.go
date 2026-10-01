package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// Round 5 (final normal repair round): GPT-5.6-Sol's Important 1 finding
// against round 4's ordering fix. authorizePublicationExecution and the
// feed_signer_operations reservation ran strictly after
// authenticatePublicationBinding (the target-document tag/digest/provenance
// proof) but strictly BEFORE authenticateCurrentTagConsistency (the current-
// transition integrity proof) and verifyBatch (the stamp/batch authorization
// proof). An attempt B that reuses a legitimate publication P's EXACT bound
// tag/digest/provenance — so it clears authenticatePublicationBinding cleanly
// — but carries an unrelated transition mutation or an impermissible batch id
// could still durably REACH one of those two later checks only AFTER already
// having reserved (or, worse, permanently occupied) P's execution slot or
// P/A's shared attempt-id row. Because neither failure class is a generation
// conflict, runSignedCommit never marks the row replaceable, so the
// legitimate owner's own distinct attempt is blocked forever (test A), or —
// because attempt ids deliberately exclude BatchID while the durable request
// hash includes it — a corrected-batch retry under the SAME attempt id
// collides with B's already-reserved hash (test B).
//
// Both tests drive the full production composition (two INDEPENDENT
// controlplane.Store handles over one shared file-backed SQLite database,
// each wrapped by its own real FeedSigner/InternalFeedServer), exactly like
// TestFeedSignerPublicationIDPoisoningRequiresAuthenticationBeforeExecutionGate,
// and must fail against the round-4 ordering (authorizePublicationExecution
// and ReserveFeedSignerOperation running before authenticateCurrentTagConsistency
// / verifyBatch).

// TestFeedSignerSameBoundMalformedTransitionZeroReservation is RED test A.
func TestFeedSignerSameBoundMalformedTransitionZeroReservation(t *testing.T) {
	ctx := context.Background()
	const publicationID = "pub-round5-transition-P"
	const secret = "round5-transition-internal-secret-0123456789"

	dbPath := filepath.Join(t.TempDir(), "round5-transition.sqlite")
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
		Slug: "round5transreg", Host: "round5transreg.test", ENSName: "",
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

	srv1, err := NewInternalFeedServer(signer1, &PublicationBinder{Store: store1}, []byte(secret), nil)
	if err != nil {
		t.Fatalf("new internal feed server 1: %v", err)
	}
	srv2, err := NewInternalFeedServer(signer2, &PublicationBinder{Store: store2}, []byte(secret), nil)
	if err != nil {
		t.Fatalf("new internal feed server 2: %v", err)
	}

	// --- Preflight-bind P to legitimate payload A: tag "latest" -> fxA.digest. ---
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

	// --- B: a DIFFERENT reference whose target document carries P's EXACT
	// bound tag/digest/provenance ("latest" -> fxA.digest, TagPublications
	// {OperationID: P, Generation: 1, Digest: fxA.digest}) — clearing
	// authenticatePublicationBinding cleanly — but ALSO an unrelated second
	// tag mutation ("rogue") that no legitimate publication would ever
	// produce alongside it. Generation is shaped to be UNCONFLICTED (docB
	// generation 1 == expectedGenerationB(0)+1; current doc generation 0 ==
	// expectedGenerationB), so the rejection can ONLY come from the current-
	// transition integrity check (authenticateCurrentTagConsistency), never
	// from either generation-conflict class. ---
	referenceB := refHex('f')
	digestOther := digestRef('9')
	const expectedGenerationB = 0
	const docBGeneration = expectedGenerationB + 1
	docs.Documents[referenceB] = transitionDoc(t, testRepo, docBGeneration,
		map[string]string{"latest": fxA.digest, "rogue": digestOther},
		map[string]spec.TagPublication{
			"latest": {OperationID: publicationID, Generation: docBGeneration, Digest: fxA.digest},
			"rogue":  {OperationID: "attacker-unrelated-op", Generation: docBGeneration, Digest: digestOther},
		},
		manifestsForTags(map[string]string{"latest": fxA.digest, "rogue": digestOther}, map[string]spec.ManifestDescriptor{fxA.digest: fxA.manifest}),
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

	_, directErr := signer1.Commit(ctx, reqB)
	if directErr == nil {
		t.Fatal("B (P's correct bound tag/digest/provenance plus an unrelated tag mutation) must be rejected")
	}
	if !errors.Is(directErr, errFeedSignerMalformed) {
		t.Fatalf("B must be rejected as malformed (current-transition integrity, not a generation-conflict class), got %v", directErr)
	}
	if errors.Is(directErr, errFeedSignerGenerationConflict) {
		t.Fatalf("B must NOT surface as a generation conflict: %v", directErr)
	}

	bodyB, err := json.Marshal(reqB)
	if err != nil {
		t.Fatal(err)
	}
	recB := postFeedUpdate(t, srv1, publish.InternalFeedUpdatePathV2, secret, string(bodyB))
	if recB.Code != http.StatusBadRequest {
		t.Fatalf("B must be rejected 400 malformed over the wire, got %d: %s", recB.Code, recB.Body.String())
	}

	// --- Zero durable reservation of EITHER class for P/B: no
	// publication_states row, no feed_signer_operations row for B's attempt
	// id at all (not merely released to pending), no external update. ---
	var pubStateRows int
	if err := store1.DB.QueryRowContext(ctx, `select count(*) from publication_states where operation_id = ?`, publicationID).Scan(&pubStateRows); err != nil {
		t.Fatal(err)
	}
	if pubStateRows != 0 {
		t.Fatalf("a same-bound but transition-malformed B must NEVER reserve publication_states for P — this permanently blocks legitimate A under the pre-fix ordering; got %d rows", pubStateRows)
	}
	if _, err := store1.GetPublicationExecution(ctx, publicationID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPublicationExecution must report sql.ErrNoRows for P, got %v", err)
	}
	if _, err := store1.GetFeedSignerOperation(ctx, attemptIDB); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("B's attempt must NEVER reserve a feed_signer_operations row at all (zero mutation before full non-generation validation), got err=%v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("rejected B must cause ZERO external feed updates, got %d", n)
	}
	if got := feedStore.Feeds[repoTopic]; got != currentRef {
		t.Fatalf("the feed must be untouched by the rejected attempt, got %q", got)
	}

	// --- Legitimate A, through the INDEPENDENT second instance, must still
	// succeed exactly once: B's rejection must not have consumed or blocked
	// P's execution slot. ---
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
	recA := postFeedUpdate(t, srv2, publish.InternalFeedUpdatePathV2, secret, string(bodyA))
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
}

// TestFeedSignerBadBatchPoisoningZeroReservation is RED test B. B uses P/A's
// SAME reference and thus the SAME deterministic attempt id (attempt ids
// deliberately exclude BatchID) but an impermissible BatchID. This proves
// specifically that the durable request-hash binding (feed_signer_operations,
// keyed by the attempt id, carrying the FULL request hash which DOES include
// BatchID) is never reserved before batch validation: under the pre-fix
// ordering, B's bad-batch attempt would reserve the shared attempt id's row
// under its own (differing) request hash, permanently colliding with a
// later corrected-batch retry under the identical attempt id.
func TestFeedSignerBadBatchPoisoningZeroReservation(t *testing.T) {
	ctx := context.Background()
	const publicationID = "pub-round5-batch-P"
	const secret = "round5-batch-internal-secret-0123456789ab"

	dbPath := filepath.Join(t.TempDir(), "round5-batch.sqlite")
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
		Slug: "round5batchreg", Host: "round5batchreg.test", ENSName: "",
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
		stampRef:   mustStampDoc(t, "batch-1"), // only "batch-1" is permitted by policy.
	}
	bytesReader := newMemoryBytesReader()

	signer1 := &FeedSigner{Store: store1, Feeds: updater, ResolveFeeds: feedStore, Docs: docs, Bytes: bytesReader}
	signer2 := &FeedSigner{Store: store2, Feeds: updater, ResolveFeeds: feedStore, Docs: docs, Bytes: bytesReader}

	srv1, err := NewInternalFeedServer(signer1, &PublicationBinder{Store: store1}, []byte(secret), nil)
	if err != nil {
		t.Fatalf("new internal feed server 1: %v", err)
	}
	srv2, err := NewInternalFeedServer(signer2, &PublicationBinder{Store: store2}, []byte(secret), nil)
	if err != nil {
		t.Fatalf("new internal feed server 2: %v", err)
	}

	// A CLEAN single-tag transition (current has no tags; target adds
	// exactly "latest") so the ONLY possible rejection reason for the
	// bad-batch request is batch/stamp authorization — never current-
	// transition integrity, never a generation-conflict class.
	fxA := simpleArtifact(t, '4', '5', '6', 64, 64)
	bytesReader.serve(fxA.manifest.SwarmRef, fxA.body)
	reference := refHex('a')
	docs.Documents[reference] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": fxA.digest},
		map[string]spec.TagPublication{"latest": {OperationID: publicationID, Generation: 1, Digest: fxA.digest}},
		map[string]spec.ManifestDescriptor{fxA.digest: fxA.manifest},
		fxA.blobDescs)
	hash := NormalizePublicationBindingHash(reg.ID, ownerHex0x, testRepo, "latest", fxA.digest)
	if _, err := store1.ReservePublicationBinding(ctx, publicationID, reg.ID, hash); err != nil {
		t.Fatalf("preflight-bind P: %v", err)
	}

	// attempt id excludes BatchID: the bad-batch request and the later
	// corrected-batch retry share the IDENTICAL attempt id.
	attemptID := publish.ComputeCommitAttemptID(publicationID, reg.ID, ownerHex0x, repoTopic, reference, 0)

	reqBadBatch := publish.FeedCommitRequest{
		PublicationID:      publicationID,
		OperationID:        attemptID,
		RegistryID:         reg.ID,
		Owner:              ownerHex0x,
		Topic:              repoTopic,
		Reference:          reference,
		BatchID:            "not-the-policy-batch",
		ExpectedGeneration: 0,
	}

	_, directErr := signer1.Commit(ctx, reqBadBatch)
	if directErr == nil {
		t.Fatal("the impermissible-batch attempt must be rejected")
	}
	if !errors.Is(directErr, errFeedSignerMalformed) {
		t.Fatalf("the impermissible-batch attempt must be rejected as malformed, got %v", directErr)
	}
	if errors.Is(directErr, errFeedSignerConflict) {
		t.Fatalf("the impermissible-batch attempt must not surface as the permanent operation-conflict sentinel: %v", directErr)
	}

	bodyBad, err := json.Marshal(reqBadBatch)
	if err != nil {
		t.Fatal(err)
	}
	recBad := postFeedUpdate(t, srv1, publish.InternalFeedUpdatePathV2, secret, string(bodyBad))
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("the impermissible-batch attempt must be rejected 400 over the wire, got %d: %s", recBad.Code, recBad.Body.String())
	}

	// --- Zero durable reservation of EITHER class, and specifically zero
	// feed_signer_operations row under the shared attempt id: the bad-batch
	// attempt must never bind the durable request hash before batch
	// validation runs. ---
	var pubStateRows int
	if err := store1.DB.QueryRowContext(ctx, `select count(*) from publication_states where operation_id = ?`, publicationID).Scan(&pubStateRows); err != nil {
		t.Fatal(err)
	}
	if pubStateRows != 0 {
		t.Fatalf("an impermissible-batch attempt must NEVER reserve publication_states for P, got %d rows", pubStateRows)
	}
	if _, err := store1.GetFeedSignerOperation(ctx, attemptID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("the bad-batch attempt must NEVER reserve the shared attempt id's feed_signer_operations row — this is exactly what would collide with a later corrected-batch retry under the pre-fix ordering; got err=%v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("rejected bad-batch attempt must cause ZERO external feed updates, got %d", n)
	}

	// --- A corrected-batch retry under the IDENTICAL attempt id, through the
	// INDEPENDENT second instance, must succeed exactly once: the earlier
	// bad-batch rejection must not have consumed or poisoned the shared
	// attempt id's durable row. ---
	reqCorrected := reqBadBatch
	reqCorrected.BatchID = "batch-1"
	bodyGood, err := json.Marshal(reqCorrected)
	if err != nil {
		t.Fatal(err)
	}
	recGood := postFeedUpdate(t, srv2, publish.InternalFeedUpdatePathV2, secret, string(bodyGood))
	if recGood.Code != http.StatusOK {
		t.Fatalf("the corrected-batch retry under the SAME attempt id must succeed, got %d: %s", recGood.Code, recGood.Body.String())
	}
	var result publish.FeedCommitResult
	if err := json.Unmarshal(recGood.Body.Bytes(), &result); err != nil {
		t.Fatalf("bad result body: %v", err)
	}
	if result.OperationID != attemptID || result.Reference != reference || result.Feed != repoTopic {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected EXACTLY ONE external feed advancement total, got %d", n)
	}
	if got := feedStore.Feeds[repoTopic]; got != reference {
		t.Fatalf("the feed must advance to the corrected reference, got %q", got)
	}
	exec, err := store2.GetPublicationExecution(ctx, publicationID)
	if err != nil {
		t.Fatalf("publication execution lookup after the corrected retry: %v", err)
	}
	if exec.State != PublicationExecutionSucceeded || exec.AttemptID != attemptID || exec.RegistryID != reg.ID {
		t.Fatalf("the durable publication state must terminate succeeded under the shared attempt id, got %+v want attempt %q", exec, attemptID)
	}
}
