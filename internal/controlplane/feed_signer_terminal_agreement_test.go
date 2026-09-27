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
