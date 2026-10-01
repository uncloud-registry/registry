package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
)

// Task 17 closure review (GPT-5.6-Sol, single final review): a nonterminal
// publication state could bypass the two-ledger replay guard through the
// LATER shared succeeded-operation path. terminalReplayResult (feed_signer.go)
// and authorizePublicationExecution both correctly require publication-terminal
// agreement, but reserveAndRunClaim's FeedSignerOpSucceeded case returned
// storedResult(op, req) UNCONDITIONALLY — with zero requirement that
// publication_states agree the SAME attempt reached the SAME terminal state.
// Sequence: P active under A; A becomes succeeded via SOME path that bypasses
// CompleteFeedSignerOperationAndTerminatePublication (e.g. a standalone
// CompleteFeedSignerOperation call — closed independently below); an exact
// retry declines terminalReplayResult's early replay (publication nonterminal),
// prepares and authorizes the same active A (authorizePublicationExecution
// permits "active, SAME attempt id"), then the shared operation lookup in
// reserveAndRunClaim returns success while P remains active forever.
//
// The fix: FeedSigner.resolveSucceededOperation is now the single call site
// reserveAndRunClaim's succeeded case uses, and it reuses ONE authoritative
// helper (FeedSigner.publicationExecutionAgreement) — the same comparison
// terminalReplayResult itself now delegates to — to decide whether the
// publication genuinely agrees, mismatches (permanent conflict), or is merely
// nonterminal (reconcilable). Store.CompleteFeedSignerOperation additionally
// refuses atomically against a genuinely PublicationID-indirected active/
// replaceable row, closing the standalone-completion vector at its source.

// --- Test A: file-backed current-v2 split fixture ---------------------

// TestFeedSignerSucceededOperationReconcilesActivePublicationOnReplay is RED
// test A. A REAL file-backed publication succeeds normally (both ledgers
// terminate together). publication_states is then reverted directly to
// "active" under the SAME attempt id — simulating the durable shape any
// standalone-completion bug (present or future) could leave behind,
// independent of how it arose. An exact retry, through an INDEPENDENT second
// Store handle over the SAME database file, must NOT silently return success
// while publication_states disagrees: every invariant needed to reconcile is
// independently provable (the operation is genuinely succeeded, the stored
// result is hash/coherence-verified against this exact request, and the
// publication row already agrees on registry+attempt, merely not yet
// terminal), so it atomically reconciles publication_states back to succeeded
// and THEN returns the identical stored result — causing ZERO additional
// external feed update.
func TestFeedSignerSucceededOperationReconcilesActivePublicationOnReplay(t *testing.T) {
	ctx := context.Background()
	w := newRound6AWorld(t, "terminalagreement")
	const publicationID = "pub-round17-split-P"

	fxA := simpleArtifact(t, 'a', 'b', 'c', 64, 64)
	w.bytesReader.serve(fxA.manifest.SwarmRef, fxA.body)
	referenceA := refHex('a')
	w.docs.Documents[referenceA] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": fxA.digest},
		map[string]spec.TagPublication{"latest": {OperationID: publicationID, Generation: 1, Digest: fxA.digest}},
		map[string]spec.ManifestDescriptor{fxA.digest: fxA.manifest},
		fxA.blobDescs)
	hash := NormalizePublicationBindingHash(w.reg.ID, w.ownerHex0x, testRepo, "latest", fxA.digest)
	if _, err := w.store1.ReservePublicationBinding(ctx, publicationID, w.reg.ID, hash); err != nil {
		t.Fatalf("preflight-bind P: %v", err)
	}

	attemptID := publish.ComputeCommitAttemptID(publicationID, w.reg.ID, w.ownerHex0x, w.repoTopic, referenceA, 0)
	req := publish.FeedCommitRequest{
		PublicationID:      publicationID,
		OperationID:        attemptID,
		RegistryID:         w.reg.ID,
		Owner:              w.ownerHex0x,
		Topic:              w.repoTopic,
		Reference:          referenceA,
		BatchID:            "batch-1",
		ExpectedGeneration: 0,
	}

	signer1 := w.signer(w.store1)
	first, err := signer1.Commit(ctx, req)
	if err != nil {
		t.Fatalf("original commit must succeed: %v", err)
	}
	if n := w.updater.count(); n != 1 {
		t.Fatalf("expected exactly one external update after the original commit, got %d", n)
	}
	exec, err := w.store1.GetPublicationExecution(ctx, publicationID)
	if err != nil || exec.State != PublicationExecutionSucceeded || exec.AttemptID != attemptID {
		t.Fatalf("publication must terminate succeeded after the original commit, got %+v err %v", exec, err)
	}

	// Simulate the split directly (file-backed, bypassing every
	// application-level guard): feed_signer_operations is genuinely succeeded
	// and left UNTOUCHED; publication_states alone is reverted to active under
	// the SAME attempt id.
	if _, err := w.store1.DB.ExecContext(ctx, `update publication_states set state = 'active' where operation_id = ?`, publicationID); err != nil {
		t.Fatalf("simulate split state: %v", err)
	}
	reverted, err := w.store1.GetPublicationExecution(ctx, publicationID)
	if err != nil || reverted.State != PublicationExecutionActive || reverted.AttemptID != attemptID {
		t.Fatalf("split-state fixture malformed: %+v err %v", reverted, err)
	}

	// The exact retry, through an INDEPENDENT second Store handle over the
	// SAME database file.
	signer2 := w.signer(w.store2)
	second, err := signer2.Commit(ctx, req)
	if err != nil {
		t.Fatalf("exact retry against a reconcilable split must not fail closed, got error: %v", err)
	}
	if second != first {
		t.Fatalf("retry must return the IDENTICAL stored result, got %+v want %+v", second, first)
	}
	if n := w.updater.count(); n != 1 {
		t.Fatalf("reconciling a split state must cause ZERO additional external updates, got %d total", n)
	}

	final, err := w.store1.GetPublicationExecution(ctx, publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != PublicationExecutionSucceeded || final.AttemptID != attemptID {
		t.Fatalf("publication must be reconciled back to succeeded under the SAME attempt, got %+v", final)
	}
	op, err := w.store1.GetFeedSignerOperation(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("operation must remain succeeded, got %q", op.State)
	}
}

// --- Test D: replaceable publication is never promoted, only active is ----

// TestFeedSignerSucceededOperationNeverReconcilesReplaceablePublicationOnReplay
// is task 17's FINAL closure fix (targeted review). Test A above correctly
// reconciles an ACTIVE-but-nonterminal publication row back to succeeded on
// an exact retry. But "replaceable" is NOT a harmless nonterminal variant of
// "active": it is the authoritative generation-conflict marker — this exact
// attempt already had its external update DEFINITELY refused with zero write
// (see authorizePublicationExecution / MarkPublicationExecutionReplaceable),
// and a DIFFERENT fresh attempt may legitimately CAS it back to active at any
// time. If a succeeded feed_signer_operations row for this SAME attempt ever
// coexists with a replaceable publication row (a split reconciliation must
// never paper over, whatever bug or race produced it), promoting
// "replaceable" to "succeeded" would permanently poison the publication
// against the very replacement its own state exists to authorize — even
// though this attempt's generation-conflict path performed NO external
// write. The fix restricts reconciliation to a coherent "active" row only;
// "replaceable" (or any other non-active, non-succeeded state) under the
// same registry/publication/attempt must fail closed, data-free, and
// retryable, with ZERO mutation to either ledger — while a genuinely fresh
// attempt id must remain free to replace the row exactly as before.
//
// NOTE: through the real Commit path exercised here, this exact retry
// actually fails one layer BEFORE ever reaching resolveSucceededOperation:
// reserveAndRunClaim's insert-or-ignore of the (already-succeeded)
// feed_signer_operations row still fires migration 17's BEFORE INSERT fence
// trigger, which aborts because publication_states is "replaceable", not
// "active", for this attempt. That is a real, independently-load-bearing
// guard, but it means this test alone does not prove
// resolveSucceededOperation/ReconcilePublicationExecutionSucceeded refuse to
// promote a replaceable row — see
// TestResolveSucceededOperationNeverReconcilesReplaceablePublicationDirectly
// below for a direct exercise of that path, bypassing the fence trigger
// entirely via a self-mapped operation row.
func TestFeedSignerSucceededOperationNeverReconcilesReplaceablePublicationOnReplay(t *testing.T) {
	ctx := context.Background()
	w := newRound6AWorld(t, "replaceablesplit")
	const publicationID = "pub-round17-replaceable-P"

	fxA := simpleArtifact(t, 'a', 'b', 'c', 64, 64)
	w.bytesReader.serve(fxA.manifest.SwarmRef, fxA.body)
	referenceA := refHex('a')
	w.docs.Documents[referenceA] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": fxA.digest},
		map[string]spec.TagPublication{"latest": {OperationID: publicationID, Generation: 1, Digest: fxA.digest}},
		map[string]spec.ManifestDescriptor{fxA.digest: fxA.manifest},
		fxA.blobDescs)
	hash := NormalizePublicationBindingHash(w.reg.ID, w.ownerHex0x, testRepo, "latest", fxA.digest)
	if _, err := w.store1.ReservePublicationBinding(ctx, publicationID, w.reg.ID, hash); err != nil {
		t.Fatalf("preflight-bind P: %v", err)
	}

	attemptID := publish.ComputeCommitAttemptID(publicationID, w.reg.ID, w.ownerHex0x, w.repoTopic, referenceA, 0)
	req := publish.FeedCommitRequest{
		PublicationID:      publicationID,
		OperationID:        attemptID,
		RegistryID:         w.reg.ID,
		Owner:              w.ownerHex0x,
		Topic:              w.repoTopic,
		Reference:          referenceA,
		BatchID:            "batch-1",
		ExpectedGeneration: 0,
	}

	signer1 := w.signer(w.store1)
	first, err := signer1.Commit(ctx, req)
	if err != nil {
		t.Fatalf("original commit must succeed: %v", err)
	}
	if n := w.updater.count(); n != 1 {
		t.Fatalf("expected exactly one external update after the original commit, got %d", n)
	}

	// Simulate the split directly (file-backed, bypassing every
	// application-level guard): feed_signer_operations is genuinely succeeded
	// and left UNTOUCHED; publication_states alone is forced to "replaceable"
	// under the SAME attempt id — the authoritative generation-conflict shape,
	// never a harmless nonterminal variant of "active".
	if _, err := w.store1.DB.ExecContext(ctx, `update publication_states set state = 'replaceable' where operation_id = ?`, publicationID); err != nil {
		t.Fatalf("simulate replaceable split state: %v", err)
	}
	before, err := w.store1.GetPublicationExecution(ctx, publicationID)
	if err != nil || before.State != PublicationExecutionReplaceable || before.AttemptID != attemptID {
		t.Fatalf("split-state fixture malformed: %+v err %v", before, err)
	}

	// The exact retry, through an INDEPENDENT second Store handle over the
	// SAME database file, using the real FeedSigner/current-v2 Commit path.
	signer2 := w.signer(w.store2)
	_, err = signer2.Commit(ctx, req)
	if err == nil {
		t.Fatal("exact retry against a replaceable-disagreeing publication must not silently succeed")
	}
	if errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("must not be classified as a permanent conflict (replaceable is retryable, not permanent): %v", err)
	}
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("expected a data-free, fail-closed/retryable backend error, got %v", err)
	}

	after, err := w.store1.GetPublicationExecution(ctx, publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State != before.State || after.AttemptID != before.AttemptID ||
		after.RegistryID != before.RegistryID || after.PublicationID != before.PublicationID ||
		!after.CreatedAt.Equal(before.CreatedAt) || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("publication row must remain byte-for-byte unchanged, before=%+v after=%+v", before, after)
	}
	op, err := w.store1.GetFeedSignerOperation(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("operation must remain succeeded, got %q", op.State)
	}
	if !bytesEqual(op.ResultJSON, publish.CanonicalFeedCommitResultJSON(first)) {
		t.Fatalf("stored operation result must remain unchanged, got %s", op.ResultJSON)
	}
	if n := w.updater.count(); n != 1 {
		t.Fatalf("a fail-closed replay must cause ZERO additional external updates, got %d total", n)
	}

	// A legitimate replacement attempt must still be permitted by the
	// existing state machine: a DIFFERENT fresh attempt id may atomically CAS
	// the still-replaceable row back to active.
	won, replaced, err := w.store1.ReplacePublicationExecutionAttempt(ctx, publicationID, w.reg.ID, attemptID, "attempt-B-legit-replacement")
	if err != nil {
		t.Fatalf("legitimate replacement CAS: %v", err)
	}
	if !won || replaced.State != PublicationExecutionActive || replaced.AttemptID != "attempt-B-legit-replacement" {
		t.Fatalf("a fresh attempt must still be able to replace the replaceable row, got won=%v row=%+v", won, replaced)
	}
}

// TestResolveSucceededOperationNeverReconcilesReplaceablePublicationDirectly
// is the direct exercise TestFeedSignerSucceededOperationNeverReconcilesReplaceablePublicationOnReplay's
// own doc comment above describes: it calls
// FeedSigner.resolveSucceededOperation and
// Store.ReconcilePublicationExecutionSucceeded DIRECTLY against a replaceable
// publication row, bypassing migration 17's insert-fence trigger entirely
// (that test alone only proves the fence trigger refuses the retry one layer
// above; it never reaches resolveSucceededOperation at all). This proves the
// two functions themselves — not just the fence trigger — refuse to promote
// a replaceable row to succeeded.
func TestResolveSucceededOperationNeverReconcilesReplaceablePublicationDirectly(t *testing.T) {
	ctx := context.Background()
	w := newRound6AWorld(t, "replaceabledirect")
	const publicationID = "pub-round17-replaceable-direct-P"

	fxA := simpleArtifact(t, 'a', 'b', 'c', 64, 64)
	w.bytesReader.serve(fxA.manifest.SwarmRef, fxA.body)
	referenceA := refHex('a')
	w.docs.Documents[referenceA] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": fxA.digest},
		map[string]spec.TagPublication{"latest": {OperationID: publicationID, Generation: 1, Digest: fxA.digest}},
		map[string]spec.ManifestDescriptor{fxA.digest: fxA.manifest},
		fxA.blobDescs)
	hash := NormalizePublicationBindingHash(w.reg.ID, w.ownerHex0x, testRepo, "latest", fxA.digest)
	if _, err := w.store1.ReservePublicationBinding(ctx, publicationID, w.reg.ID, hash); err != nil {
		t.Fatalf("preflight-bind P: %v", err)
	}

	attemptID := publish.ComputeCommitAttemptID(publicationID, w.reg.ID, w.ownerHex0x, w.repoTopic, referenceA, 0)
	req := publish.FeedCommitRequest{
		PublicationID:      publicationID,
		OperationID:        attemptID,
		RegistryID:         w.reg.ID,
		Owner:              w.ownerHex0x,
		Topic:              w.repoTopic,
		Reference:          referenceA,
		BatchID:            "batch-1",
		ExpectedGeneration: 0,
	}

	signer := w.signer(w.store1)
	first, err := signer.Commit(ctx, req)
	if err != nil {
		t.Fatalf("original commit must succeed: %v", err)
	}
	if n := w.updater.count(); n != 1 {
		t.Fatalf("expected exactly one external update after the original commit, got %d", n)
	}

	// Simulate the split directly, exactly like Test D: feed_signer_operations
	// stays genuinely succeeded; publication_states alone is forced to
	// "replaceable" under the SAME attempt id.
	if _, err := w.store1.DB.ExecContext(ctx, `update publication_states set state = 'replaceable' where operation_id = ?`, publicationID); err != nil {
		t.Fatalf("simulate replaceable split state: %v", err)
	}
	before, err := w.store1.GetPublicationExecution(ctx, publicationID)
	if err != nil || before.State != PublicationExecutionReplaceable || before.AttemptID != attemptID {
		t.Fatalf("split-state fixture malformed: %+v err %v", before, err)
	}
	op, err := w.store1.GetFeedSignerOperation(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("operation fixture must be succeeded, got %q", op.State)
	}

	// The direct call, bypassing reserveAndRunClaim and the fence trigger
	// entirely.
	result, err := signer.resolveSucceededOperation(ctx, op, req)
	if err == nil {
		t.Fatalf("direct call against a replaceable-disagreeing publication must not silently succeed, got result %+v", result)
	}
	if errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("must not be classified as a permanent conflict (replaceable is retryable, not permanent): %v", err)
	}
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("expected a data-free, fail-closed/retryable backend error, got %v", err)
	}
	if result != (publish.FeedCommitResult{}) {
		t.Fatalf("must return no result, got %+v", result)
	}

	after, err := w.store1.GetPublicationExecution(ctx, publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State != before.State || after.AttemptID != before.AttemptID ||
		after.RegistryID != before.RegistryID || after.PublicationID != before.PublicationID ||
		!after.CreatedAt.Equal(before.CreatedAt) || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("publication row must remain byte-for-byte unchanged, before=%+v after=%+v", before, after)
	}
	opAfter, err := w.store1.GetFeedSignerOperation(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if opAfter.State != FeedSignerOpSucceeded {
		t.Fatalf("operation must remain succeeded, got %q", opAfter.State)
	}
	if !bytesEqual(opAfter.ResultJSON, publish.CanonicalFeedCommitResultJSON(first)) {
		t.Fatalf("stored operation result must remain unchanged, got %s", opAfter.ResultJSON)
	}
	if n := w.updater.count(); n != 1 {
		t.Fatalf("a direct fail-closed call must cause ZERO external updates, got %d total", n)
	}

	// Store.ReconcilePublicationExecutionSucceeded, called directly, must
	// likewise refuse to apply against the replaceable row.
	applied, err := w.store1.ReconcilePublicationExecutionSucceeded(ctx, publicationID, w.reg.ID, attemptID)
	if err != nil {
		t.Fatalf("ReconcilePublicationExecutionSucceeded: %v", err)
	}
	if applied {
		t.Fatalf("must not report applied against a replaceable row")
	}
	finalExec, err := w.store1.GetPublicationExecution(ctx, publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if finalExec.State != before.State || finalExec.AttemptID != before.AttemptID ||
		finalExec.RegistryID != before.RegistryID || finalExec.PublicationID != before.PublicationID ||
		!finalExec.CreatedAt.Equal(before.CreatedAt) || !finalExec.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("publication row must remain byte-for-byte unchanged after ReconcilePublicationExecutionSucceeded, before=%+v after=%+v", before, finalExec)
	}
}

// --- Test B: standalone CompleteFeedSignerOperation must never split ------

// TestCompleteFeedSignerOperationRejectsSplitFromActivePublication is RED
// test B (part 1). A standalone CompleteFeedSignerOperation call against an
// attempt id a GENUINELY PublicationID-indirected publication_states row
// (operation_id != attempt_id — never a round-6B self-mapped row) still
// claims "active" must fail atomically, leaving BOTH the feed_signer_operations
// row (still processing) and the publication_states row (still active)
// completely unchanged. This is the exact standalone-completion vector the
// closure review's evidence sequence describes.
func TestCompleteFeedSignerOperationRejectsSplitFromActivePublication(t *testing.T) {
	store := newFileBackedProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()

	const attemptID = "op-split-guard-A"
	const publicationID = "pub-split-guard-P"
	if _, err := store.ReservePublicationExecution(ctx, publicationID, reg.ID, attemptID); err != nil {
		t.Fatalf("reserve publication execution: %v", err)
	}

	hash := feedSignerTestHash("split-guard")
	if _, err := store.ReserveFeedSignerOperation(ctx, attemptID, reg.ID, topic, hash); err != nil {
		t.Fatalf("reserve operation: %v", err)
	}
	token := testClaimToken(t)
	won, err := store.ClaimFeedSignerOperation(ctx, attemptID, hash, token, time.Now().UTC().Add(time.Minute))
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}

	result := []byte(`{"operationID":"` + attemptID + `","feed":"` + topic + `","reference":"` + refHex('d') + `"}`)
	if err := store.CompleteFeedSignerOperation(ctx, attemptID, hash, token, result); err == nil {
		t.Fatal("standalone completion against an active matching publication must fail")
	}

	op, err := store.GetFeedSignerOperation(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpProcessing || op.ClaimToken == nil || *op.ClaimToken != token {
		t.Fatalf("operation must remain processing, unchanged, got %+v", op)
	}
	exec, err := store.GetPublicationExecution(ctx, publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionActive || exec.AttemptID != attemptID {
		t.Fatalf("publication must remain active, unchanged, got %+v", exec)
	}
}

// TestCompleteFeedSignerOperationSucceedsWithNoPublicationRow is RED test B
// (part 2). The SAME method, against an attempt id with NO publication_states
// row at all (the genuine pre-migration-17-fence legacy shape, built here at
// exactly schema version 16 where the fence does not yet exist), must keep
// succeeding exactly as before.
func TestCompleteFeedSignerOperationSucceedsWithNoPublicationRow(t *testing.T) {
	ctx := context.Background()
	db := openRawFileTestDB(t)
	if err := applyMigrationsThrough(ctx, db, 16); err != nil {
		t.Fatalf("apply through migration 16: %v", err)
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)

	const attemptID = "op-legacy-no-publication-row"
	hash := feedSignerTestHash("legacy-no-pub")
	if _, err := store.ReserveFeedSignerOperation(ctx, attemptID, reg.ID, topic, hash); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	token := testClaimToken(t)
	won, err := store.ClaimFeedSignerOperation(ctx, attemptID, hash, token, time.Now().UTC().Add(time.Minute))
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	result := []byte(`{"operationID":"` + attemptID + `","feed":"` + topic + `","reference":"` + refHex('e') + `"}`)
	if err := store.CompleteFeedSignerOperation(ctx, attemptID, hash, token, result); err != nil {
		t.Fatalf("legacy completion with no publication row must still succeed: %v", err)
	}
	op, err := store.GetFeedSignerOperation(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("expected succeeded, got %q", op.State)
	}
}

// --- Test C: mismatched publication state never reconciles ----------------

// seedFeedSignerRegistryNamed is seedFeedSignerRegistry parameterized by a
// unique name, so a single test can seed MULTIPLE distinct registries (and
// their distinct owners) against ONE store without colliding on the fixed
// slug/host/owner-email seedFeedSignerRegistry itself uses.
func seedFeedSignerRegistryNamed(t *testing.T, store *Store, name string) (Registry, string) {
	t.Helper()
	owner, err := store.CreateUser(context.Background(), name+"-owner@example.com", "hash")
	if err != nil {
		t.Fatalf("create owner %s: %v", name, err)
	}
	reg, err := store.CreateProvisionedRegistry(context.Background(), Registry{
		Slug: name, Host: name + ".test", ENSName: "",
		OwnerUserID: owner.ID, FeedOwnerAddress: testFeedOwner, DefaultStampBatchID: "batch-signer",
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("seed provisioned registry %s: %v", name, err)
	}
	if err := store.MarkRegistryReady(context.Background(), reg.ID); err != nil {
		t.Fatalf("mark registry ready %s: %v", name, err)
	}
	topic := spec.RepoStateFeedRef(spec.NormalizeOwner(reg.FeedOwnerAddress), "myrepo")
	return reg, topic
}

// TestResolveSucceededOperationNeverReconciliesOnMismatch is RED test C. A
// publication_states row that disagrees with the request — a DIFFERENT
// attempt already recorded, a DIFFERENT registry, or a stored result that
// does not coherently match the request — must NEVER be reconciled or
// returned as success; each is a permanent, data-free failure that leaves
// publication_states completely unchanged. A row that genuinely already
// agrees (same registry, same attempt, already succeeded) must keep
// returning success directly, with no reconciliation attempted.
func TestResolveSucceededOperationNeverReconciliesOnMismatch(t *testing.T) {
	ctx := context.Background()
	store := newFileBackedProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	otherReg, _ := seedFeedSignerRegistryNamed(t, store, "mismatch-registry")
	signer := &FeedSigner{Store: store}

	const attemptID = "op-mismatch-A"
	reference := refHex('f')
	req := publish.FeedCommitRequest{
		PublicationID: "pub-mismatch-P", OperationID: attemptID, RegistryID: reg.ID,
		Owner: "0x" + testFeedOwner, Topic: topic, Reference: reference,
		BatchID: "batch-1", ExpectedGeneration: 0,
	}
	hash := NormalizeFeedCommitHash(req)
	resultJSON := publish.CanonicalFeedCommitResultJSON(publish.FeedCommitResult{
		OperationID: attemptID, Feed: publish.CanonicalTopic(topic), Reference: publish.CanonicalReference(reference),
	})

	// Seed a genuinely succeeded feed_signer_operations row for attemptID,
	// fenced by its OWN self-mapped publication row (irrelevant to the
	// mismatch scenarios below, which each reserve a SEPARATE publication id).
	if _, err := store.ReservePublicationExecution(ctx, attemptID, reg.ID, attemptID); err != nil {
		t.Fatalf("self-map fence: %v", err)
	}
	if _, err := store.ReserveFeedSignerOperation(ctx, attemptID, reg.ID, topic, hash); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	token := testClaimToken(t)
	won, err := store.ClaimFeedSignerOperation(ctx, attemptID, hash, token, time.Now().UTC().Add(time.Minute))
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	if err := store.CompleteFeedSignerOperation(ctx, attemptID, hash, token, resultJSON); err != nil {
		t.Fatalf("complete: %v", err)
	}
	op, err := store.GetFeedSignerOperation(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("different attempt already succeeded", func(t *testing.T) {
		if _, err := store.ReservePublicationExecution(ctx, req.PublicationID, reg.ID, "op-other-attempt"); err != nil {
			t.Fatalf("reserve publication: %v", err)
		}
		if _, err := signer.resolveSucceededOperation(ctx, op, req); !errors.Is(err, errFeedSignerConflict) {
			t.Fatalf("expected permanent conflict, got %v", err)
		}
		exec, err := store.GetPublicationExecution(ctx, req.PublicationID)
		if err != nil || exec.State != PublicationExecutionActive || exec.AttemptID != "op-other-attempt" {
			t.Fatalf("publication must remain unchanged, got %+v err %v", exec, err)
		}
	})

	t.Run("different registry", func(t *testing.T) {
		const pubID2 = "pub-mismatch-registry-P"
		if _, err := store.ReservePublicationExecution(ctx, pubID2, otherReg.ID, attemptID); err != nil {
			t.Fatalf("reserve publication: %v", err)
		}
		reqMismatch := req
		reqMismatch.PublicationID = pubID2
		if _, err := signer.resolveSucceededOperation(ctx, op, reqMismatch); !errors.Is(err, errFeedSignerConflict) {
			t.Fatalf("expected permanent conflict, got %v", err)
		}
		exec, err := store.GetPublicationExecution(ctx, pubID2)
		if err != nil || exec.State != PublicationExecutionActive || exec.RegistryID != otherReg.ID {
			t.Fatalf("publication must remain unchanged, got %+v err %v", exec, err)
		}
	})

	t.Run("stored result does not match request", func(t *testing.T) {
		const pubID3 = "pub-mismatch-hash-P"
		if _, err := store.ReservePublicationExecution(ctx, pubID3, reg.ID, attemptID); err != nil {
			t.Fatalf("reserve publication: %v", err)
		}
		reqWrongRef := req
		reqWrongRef.PublicationID = pubID3
		reqWrongRef.Reference = refHex('9')
		if _, err := signer.resolveSucceededOperation(ctx, op, reqWrongRef); !errors.Is(err, errFeedSignerBackend) {
			t.Fatalf("expected data-free backend failure, got %v", err)
		}
		exec, err := store.GetPublicationExecution(ctx, pubID3)
		if err != nil || exec.State != PublicationExecutionActive {
			t.Fatalf("publication must remain unchanged (never reconciled on a malformed result), got %+v err %v", exec, err)
		}
	})

	t.Run("already agreeing succeeded publication returns success directly", func(t *testing.T) {
		const pubID4 = "pub-agree-P"
		if _, err := store.ReservePublicationExecution(ctx, pubID4, reg.ID, attemptID); err != nil {
			t.Fatalf("reserve publication: %v", err)
		}
		if applied, err := store.ReconcilePublicationExecutionSucceeded(ctx, pubID4, reg.ID, attemptID); err != nil || !applied {
			t.Fatalf("seed succeeded: applied=%v err=%v", applied, err)
		}
		reqAgree := req
		reqAgree.PublicationID = pubID4
		result, err := signer.resolveSucceededOperation(ctx, op, reqAgree)
		if err != nil {
			t.Fatalf("an agreeing terminal publication must return success, got %v", err)
		}
		if result.OperationID != attemptID {
			t.Fatalf("unexpected result: %+v", result)
		}
	})
}
