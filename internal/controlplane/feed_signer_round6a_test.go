package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// Round 6A (Exceptional Task 17 repair, risk 1 of 2): GPT-5.6-Sol's Important
// 1 finding against the round-5 bound-protocol split (prepareBoundCommit /
// finishBoundCommit). prepareBoundCommit's verifyBatch reads the MUTABLE
// stamp-policy feed during non-mutating preparation, strictly BEFORE any
// durable reservation — including the durable succeeded-result lookup that
// answers a lost-response retry. Three failure classes follow:
//
//   - A (terminal replay): an exact retry of an attempt that already reached
//     durable terminal success must return the stored result without ever
//     re-validating a stamp policy that has since rotated. Before this round,
//     it instead re-entered prepareBoundCommit and failed malformed.
//   - B (pre-claim staleness): the policy can rotate between
//     prepareBoundCommit's unlocked read and the durable claim being won;
//     finishBoundCommit must freshly reconcile it before any external update,
//     performing ZERO external update on a mismatch, and must abandon (not
//     merely release) the stale request-hash reservation so a corrected
//     retry under the SAME deterministic attempt id (BatchID is excluded
//     from publish.ComputeCommitAttemptID) can still succeed — without ever
//     making the publication replaceable to a DIFFERENT attempt.
//   - C (crash recovery): an exact retry of an attempt whose external update
//     already applied (current feed already resolves to the target
//     reference) must reconcile and durably complete via the done-recovery
//     path even when the mutable stamp policy has since rotated — batch
//     validation is meaningless once the batch has already been consumed by
//     the real write, and must not be repeated against a rotated policy.
//
// All three tests drive a REAL file-backed SQLite Store (two independent
// Store handles over one shared database file, exactly like
// feed_signer_round5_reservation_test.go), and B additionally drives a
// deterministic in-process barrier (stampPolicyPauseResolver) to force the
// pause between preparation and the fresh reconciliation.

// round6aWorld assembles the shared fixture plumbing for the round-6A tests:
// two independent *Store handles over ONE shared file-backed SQLite database,
// a shared in-memory feed/document/bytes fixture, and a shared external
// feed-update counter.
type round6aWorld struct {
	store1, store2 *Store
	reg            Registry
	ownerHex0x     string
	repoTopic      string
	stampFeed      string
	feedStore      *MemoryRegistryFeedStore
	docs           *resolve.MemoryDocumentStore
	bytesReader    *memoryBytesReader
	updater        *countingFeedUpdater
}

func newRound6AWorld(t *testing.T, name string) *round6aWorld {
	t.Helper()
	ctx := context.Background()

	dbPath := filepath.Join(t.TempDir(), "round6a-"+name+".sqlite")
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
	for _, s := range []*Store{store1, store2} {
		if _, err := s.DB.ExecContext(ctx, `pragma busy_timeout = 10000`); err != nil {
			t.Fatal(err)
		}
	}

	owner := seedProvisioningOwner(t, store1)
	feedOwner := testFeedOwner
	ownerHex0x := "0x" + feedOwner
	reg, err := store1.CreateProvisionedRegistry(ctx, Registry{
		Slug: "round6a" + name, Host: "round6a" + name + ".test", ENSName: "",
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

	return &round6aWorld{
		store1: store1, store2: store2, reg: reg, ownerHex0x: ownerHex0x,
		repoTopic: repoTopic, stampFeed: stampFeed, feedStore: feedStore,
		docs: docs, bytesReader: bytesReader, updater: updater,
	}
}

func (w *round6aWorld) signer(store *Store) *FeedSigner {
	return &FeedSigner{Store: store, Feeds: w.updater, ResolveFeeds: w.feedStore, Docs: w.docs, Bytes: w.bytesReader}
}

// rotateStampPolicy republishes the stamp-policy feed at a FRESH
// content-addressed reference carrying batch, simulating a legitimate policy
// rotation between two points in a test.
func (w *round6aWorld) rotateStampPolicy(t *testing.T, newRef byte, batch string) {
	t.Helper()
	ref := refHex(newRef)
	w.docs.Documents[ref] = mustStampDoc(t, batch)
	w.feedStore.Feeds[w.stampFeed] = ref
}

// --- Class A: terminal replay must survive a stamp-policy rotation ---------

// TestFeedSignerTerminalReplaySurvivesStampPolicyRotation is RED test A. A
// bound publication succeeds under stamp policy X (batch-1). The policy then
// rotates to Y (batch-2). An EXACT lost-response retry of the SAME request
// (same OperationID/PublicationID, same BatchID X, same request hash) must
// return the stored success — via signer.Commit directly, through an
// INDEPENDENT second Store handle over the SAME database file, and over the
// wire through InternalFeedServer — without ever re-entering mutable
// preparation. Before round 6A, prepareBoundCommit's verifyBatch ran BEFORE
// the durable succeeded-row lookup and rejected the retry malformed.
func TestFeedSignerTerminalReplaySurvivesStampPolicyRotation(t *testing.T) {
	ctx := context.Background()
	w := newRound6AWorld(t, "terminalreplay")
	const publicationID = "pub-round6a-terminal-P"
	const secret = "round6a-terminal-internal-secret-0123456"

	fxA := simpleArtifact(t, '1', '2', '3', 64, 64)
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
	reqA := publish.FeedCommitRequest{
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
	first, err := signer1.Commit(ctx, reqA)
	if err != nil {
		t.Fatalf("original commit must succeed: %v", err)
	}
	if n := w.updater.count(); n != 1 {
		t.Fatalf("expected exactly one external update after the original commit, got %d", n)
	}

	// Rotate the stamp policy AFTER the original success.
	w.rotateStampPolicy(t, 'd', "batch-2")

	// --- Exact retry, direct call, same store instance. ---
	second, err := signer1.Commit(ctx, reqA)
	if err != nil {
		t.Fatalf("exact lost-response retry must survive the stamp-policy rotation, got error: %v", err)
	}
	if second != first {
		t.Fatalf("retry must return the IDENTICAL stored result, got %+v want %+v", second, first)
	}
	if n := w.updater.count(); n != 1 {
		t.Fatalf("exact retry must cause ZERO additional external updates, got %d total", n)
	}

	// --- Exact retry, direct call, INDEPENDENT second Store handle over the
	// SAME database file. ---
	signer2 := w.signer(w.store2)
	third, err := signer2.Commit(ctx, reqA)
	if err != nil {
		t.Fatalf("exact retry through the independent store must survive the rotation, got error: %v", err)
	}
	if third != first {
		t.Fatalf("cross-store retry must return the IDENTICAL stored result, got %+v want %+v", third, first)
	}
	if n := w.updater.count(); n != 1 {
		t.Fatalf("cross-store exact retry must cause ZERO additional external updates, got %d total", n)
	}

	// --- Exact retry over the wire, through InternalFeedServer, driven by the
	// independent second Store handle. ---
	srv2, err := NewInternalFeedServer(signer2, &PublicationBinder{Store: w.store2}, []byte(secret), nil)
	if err != nil {
		t.Fatalf("new internal feed server 2: %v", err)
	}
	body, err := json.Marshal(reqA)
	if err != nil {
		t.Fatal(err)
	}
	rec := postFeedUpdate(t, srv2, publish.InternalFeedUpdatePathV2, secret, string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("exact retry over the wire must succeed 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var wireResult publish.FeedCommitResult
	if err := json.Unmarshal(rec.Body.Bytes(), &wireResult); err != nil {
		t.Fatalf("bad result body: %v", err)
	}
	if wireResult != first {
		t.Fatalf("wire retry must return the IDENTICAL stored result, got %+v want %+v", wireResult, first)
	}
	if n := w.updater.count(); n != 1 {
		t.Fatalf("wire exact retry must cause ZERO additional external updates, got %d total", n)
	}

	// Durable state is untouched by any of the replays.
	op, err := w.store1.GetFeedSignerOperation(ctx, attemptID)
	if err != nil {
		t.Fatalf("load operation: %v", err)
	}
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("operation must remain succeeded, got %q", op.State)
	}
	exec, err := w.store1.GetPublicationExecution(ctx, publicationID)
	if err != nil {
		t.Fatalf("load publication execution: %v", err)
	}
	if exec.State != PublicationExecutionSucceeded || exec.AttemptID != attemptID {
		t.Fatalf("publication execution must remain succeeded under the original attempt, got %+v", exec)
	}
}

// --- Class B: pre-claim staleness must abandon (not poison) the retry ------

// stampPolicyPauseResolver wraps a resolve.FeedResolver and, on the Nth call
// to ResolveFeed for a specific feed reference, signals paused (closing it)
// and then blocks until resume is closed — a deterministic barrier for
// pausing a request strictly between its non-mutating preparation (which
// resolves the stamp-policy feed once) and its later, fresh reconciliation
// under the won claim (which resolves it again). The underlying resolver is
// always queried BEFORE the pause, so the returned reference reflects
// whatever the caller observed at the moment of its OWN call — only the
// delivery back to FeedSigner is delayed, exactly modeling a goroutine that
// read the policy and was then preempted before continuing.
type stampPolicyPauseResolver struct {
	inner       resolve.FeedResolver
	pauseFeed   string
	pauseAtCall int

	mu     sync.Mutex
	calls  int
	paused chan struct{}
	resume chan struct{}
}

func (r *stampPolicyPauseResolver) ResolveFeed(ctx context.Context, feed string) (string, error) {
	ref, err := r.inner.ResolveFeed(ctx, feed)
	if feed == r.pauseFeed {
		r.mu.Lock()
		r.calls++
		n := r.calls
		r.mu.Unlock()
		if n == r.pauseAtCall {
			close(r.paused)
			<-r.resume
		}
	}
	return ref, err
}

// TestFeedSignerPreClaimStalenessAbandonsAndAllowsCorrectedRetry is RED test
// B. An attempt X observes stamp policy X (batch-1) during non-mutating
// preparation, is then paused (a deterministic barrier) strictly before its
// durable reservation/claim, the policy rotates to Y (batch-2), and the
// attempt then continues into reservation, claim, and finishBoundCommit's
// fresh reconciliation. It must:
//   - cause ZERO external feed update;
//   - NOT poison the publication: publication_states must stay "active"
//     under the SAME attempt id (never replaceable, never a different
//     attempt authorized);
//   - abandon (delete, not merely release) its stale feed_signer_operations
//     reservation, so a corrected retry Y (the SAME deterministic attempt id
//     — BatchID is excluded from publish.ComputeCommitAttemptID — with the
//     CORRECTED batch and therefore a DIFFERENT request hash) can still
//     succeed, driven here through an INDEPENDENT second Store handle and
//     over the wire through InternalFeedServer.
func TestFeedSignerPreClaimStalenessAbandonsAndAllowsCorrectedRetry(t *testing.T) {
	ctx := context.Background()
	w := newRound6AWorld(t, "preclaimstale")
	const publicationID = "pub-round6a-preclaim-P"
	const secret = "round6a-preclaim-internal-secret-0123456"

	fxA := simpleArtifact(t, '4', '5', '6', 64, 64)
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
	reqX := publish.FeedCommitRequest{
		PublicationID:      publicationID,
		OperationID:        attemptID,
		RegistryID:         w.reg.ID,
		Owner:              w.ownerHex0x,
		Topic:              w.repoTopic,
		Reference:          referenceA,
		BatchID:            "batch-1",
		ExpectedGeneration: 0,
	}

	pause := &stampPolicyPauseResolver{
		inner: w.feedStore, pauseFeed: w.stampFeed, pauseAtCall: 1,
		paused: make(chan struct{}), resume: make(chan struct{}),
	}
	signer1 := &FeedSigner{Store: w.store1, Feeds: w.updater, ResolveFeeds: pause, Docs: w.docs, Bytes: w.bytesReader}

	errCh := make(chan error, 1)
	go func() {
		_, err := signer1.Commit(context.Background(), reqX)
		errCh <- err
	}()

	select {
	case <-pause.paused:
	case <-time.After(5 * time.Second):
		t.Fatal("attempt X never paused at its non-mutating stamp-policy read")
	}

	// The policy rotates strictly BETWEEN X's preparation-time read and its
	// (not yet executed) durable reservation/claim/fresh reconciliation.
	w.rotateStampPolicy(t, 'd', "batch-2")
	close(pause.resume)

	var err error
	select {
	case err = <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("attempt X's paused commit never returned")
	}
	if err == nil {
		t.Fatal("attempt X must fail once its fresh stamp-policy reconciliation observes the rotation")
	}
	if errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("staleness must not surface as a permanent malformed failure, got %v", err)
	}
	if errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("staleness must not surface as a permanent conflict, got %v", err)
	}
	if errors.Is(err, errFeedSignerGenerationConflict) {
		t.Fatalf("staleness is not a repository-generation conflict, got %v", err)
	}
	if !errors.Is(err, errFeedSignerStampPolicyStale) {
		t.Fatalf("expected the dedicated stamp-policy-stale sentinel, got %v", err)
	}

	if n := w.updater.count(); n != 0 {
		t.Fatalf("a discovered staleness must cause ZERO external feed updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('0') {
		t.Fatalf("the repository feed must be untouched, got %q", got)
	}

	// The stale reservation must be ABANDONED (deleted), not merely released.
	if _, err := w.store1.GetFeedSignerOperation(ctx, attemptID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("the stale attempt's feed_signer_operations row must be deleted so a corrected retry can bind a fresh hash, got err=%v", err)
	}
	// The publication must NOT be poisoned: still active under the SAME
	// attempt id, never replaceable, never a different attempt.
	exec, err := w.store1.GetPublicationExecution(ctx, publicationID)
	if err != nil {
		t.Fatalf("publication execution lookup: %v", err)
	}
	if exec.State != PublicationExecutionActive || exec.AttemptID != attemptID {
		t.Fatalf("publication execution must remain active under the SAME attempt id, got %+v want attempt %q", exec, attemptID)
	}

	// --- The corrected retry, same deterministic attempt id, DIFFERENT
	// request hash (corrected BatchID), through an INDEPENDENT second Store
	// handle, over the wire. ---
	reqY := reqX
	reqY.BatchID = "batch-2"
	signer2 := w.signer(w.store2)
	srv2, err := NewInternalFeedServer(signer2, &PublicationBinder{Store: w.store2}, []byte(secret), nil)
	if err != nil {
		t.Fatalf("new internal feed server 2: %v", err)
	}
	bodyY, err := json.Marshal(reqY)
	if err != nil {
		t.Fatal(err)
	}
	rec := postFeedUpdate(t, srv2, publish.InternalFeedUpdatePathV2, secret, string(bodyY))
	if rec.Code != http.StatusOK {
		t.Fatalf("the corrected retry under the SAME attempt id must succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	var result publish.FeedCommitResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("bad result body: %v", err)
	}
	if result.OperationID != attemptID || result.Reference != referenceA || result.Feed != w.repoTopic {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := w.updater.count(); n != 1 {
		t.Fatalf("expected exactly ONE external update total (the corrected retry), got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != referenceA {
		t.Fatalf("the feed must advance to the corrected reference, got %q", got)
	}
	exec, err = w.store2.GetPublicationExecution(ctx, publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionSucceeded || exec.AttemptID != attemptID {
		t.Fatalf("publication execution must terminate succeeded under the SAME attempt id, got %+v", exec)
	}
	op, err := w.store2.GetFeedSignerOperation(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpSucceeded || op.RequestHash != NormalizeFeedCommitHash(reqY) {
		t.Fatalf("the corrected retry's own request hash must be the one durably stored, got state=%q", op.State)
	}
}

// --- Class C: crash recovery must reconcile despite a stamp-policy rotation

// TestFeedSignerCrashRecoveryReconcilesDespiteStampPolicyRotation is RED test
// C. It simulates the durable aftermath of a crash: the external feed update
// already applied (the current feed already resolves to the target
// reference) but the attempt's own row is left "processing" with an EXPIRED
// lease (as ClaimFeedSignerOperation would leave a crashed owner's row), and
// the logical publication is left "active" under that same attempt — exactly
// the state a process crash between the external write and its own durable
// completion would leave behind. The stamp policy then rotates. An EXACT
// retry of the ORIGINAL request (same BatchID, same request hash) must still
// reach the done-recovery path and durably complete/return success — it must
// NOT re-validate batch/stamp authorization against the rotated policy (the
// batch was already consumed by the real write), and it must cause ZERO
// additional external update.
func TestFeedSignerCrashRecoveryReconcilesDespiteStampPolicyRotation(t *testing.T) {
	ctx := context.Background()
	w := newRound6AWorld(t, "crashrecovery")
	const publicationID = "pub-round6a-crash-P"

	fxA := simpleArtifact(t, '7', '8', '9', 64, 64)
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
	reqX := publish.FeedCommitRequest{
		PublicationID:      publicationID,
		OperationID:        attemptID,
		RegistryID:         w.reg.ID,
		Owner:              w.ownerHex0x,
		Topic:              w.repoTopic,
		Reference:          referenceA,
		BatchID:            "batch-1",
		ExpectedGeneration: 0,
	}
	hashX := NormalizeFeedCommitHash(reqX)

	// --- Simulate the durable aftermath of a crash: the external write
	// already applied (bypassing the counting updater entirely — the
	// "crashed" process's write is not visible to THIS process's counter),
	// but the attempt's own completion never ran. ---
	w.feedStore.Feeds[w.repoTopic] = referenceA
	if _, err := w.store1.ReservePublicationExecution(ctx, publicationID, w.reg.ID, attemptID); err != nil {
		t.Fatalf("simulate pre-crash publication reservation: %v", err)
	}
	if _, err := w.store1.ReserveFeedSignerOperation(ctx, attemptID, w.reg.ID, w.repoTopic, hashX); err != nil {
		t.Fatalf("simulate pre-crash operation reservation: %v", err)
	}
	expiredLease := time.Now().UTC().Add(-time.Minute)
	won, err := w.store1.ClaimFeedSignerOperation(ctx, attemptID, hashX, "crashed-claim-token", expiredLease)
	if err != nil || !won {
		t.Fatalf("simulate the crashed claim: won=%v err=%v", won, err)
	}

	// The stamp policy rotates AFTER the crash.
	w.rotateStampPolicy(t, 'd', "batch-2")

	signer1 := w.signer(w.store1)
	result, err := signer1.Commit(ctx, reqX)
	if err != nil {
		t.Fatalf("the exact retry must reconcile the already-applied update and complete despite the rotated policy, got error: %v", err)
	}
	if result.OperationID != attemptID || result.Reference != referenceA || result.Feed != w.repoTopic {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := w.updater.count(); n != 0 {
		t.Fatalf("recovery must cause ZERO additional external updates (the write already applied), got %d", n)
	}

	op, err := w.store1.GetFeedSignerOperation(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpSucceeded || op.RequestHash != hashX {
		t.Fatalf("the operation must durably complete under the ORIGINAL request hash, got state=%q", op.State)
	}
	exec, err := w.store1.GetPublicationExecution(ctx, publicationID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionSucceeded || exec.AttemptID != attemptID {
		t.Fatalf("the publication must durably terminate succeeded under the ORIGINAL attempt, got %+v", exec)
	}
}
