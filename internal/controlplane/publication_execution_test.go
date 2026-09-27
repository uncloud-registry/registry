package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/publish"
)

// Round 3: the durable logical-publication execution state machine
// (publication_states, migration 16). It closes the finding-1 defect: a
// stable PublicationID that already reached a terminal success must NEVER
// authorize a second, different attempt to advance the feed again — even
// after an unrelated later publication overwrites the same tag. Exactly one
// attempt may be "active" for a PublicationID at a time; a fresh attempt may
// only replace the recorded one after it is durably marked "replaceable" (an
// authoritative generation conflict with zero external write) — never on any
// other failure class, and never while the prior attempt is still active.
//
// Every test in this file uses a FRESH file-backed store per invocation
// (newFileBackedProvisioningStore / openRawFileTestDB), never a shared-cache
// in-memory database keyed by a fixed name or t.Name(): those persist for the
// life of the test BINARY, so a repeated `go test -count=N` invocation of the
// SAME test would silently observe the PRIOR run's rows instead of a clean
// slate (the exact class of bug flagged in round 2).

// openRawFileTestDB opens an ISOLATED file-backed raw SQLite handle under a
// fresh t.TempDir(), so migration fixtures never collide across repeated
// `-count=N` runs of the same test (unlike a fixed shared-memory name).
func openRawFileTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "publication_execution.sqlite")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open raw file-backed sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestReservePublicationExecutionFreshAndRaced proves the FIRST-ever attempt
// for a PublicationID atomically wins the row (insert-or-ignore, like
// ReservePublicationBinding), and a losing concurrent contender reads back
// the SAME winning attempt id rather than creating a second row.
func TestReservePublicationExecutionFreshAndRaced(t *testing.T) {
	store := newFileBackedProvisioningStore(t)
	reg, _ := seedFeedSignerRegistry(t, store)
	ctx := context.Background()

	got, err := store.ReservePublicationExecution(ctx, "pub-exec-fresh", reg.ID, "attempt-1")
	if err != nil {
		t.Fatalf("fresh reserve: %v", err)
	}
	if got.State != PublicationExecutionActive {
		t.Fatalf("fresh reserve must be active, got %q", got.State)
	}
	if got.AttemptID != "attempt-1" {
		t.Fatalf("fresh reserve must record the attempt id, got %q", got.AttemptID)
	}
	if got.RegistryID != reg.ID {
		t.Fatalf("fresh reserve must scope the row to the registry, got %d", got.RegistryID)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatal("fresh reserve must stamp created/updated times")
	}

	// A second reserve call for the SAME publication id with a DIFFERENT
	// attempt id must never overwrite the winner: insert-or-ignore semantics.
	lost, err := store.ReservePublicationExecution(ctx, "pub-exec-fresh", reg.ID, "attempt-2")
	if err != nil {
		t.Fatalf("racing reserve: %v", err)
	}
	if lost.AttemptID != "attempt-1" {
		t.Fatalf("a racing reserve must read back the WINNING attempt id, got %q", lost.AttemptID)
	}

	var rows int
	if err := store.DB.QueryRowContext(ctx, `select count(*) from publication_states`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("exactly one execution row must ever exist per publication id, got %d", rows)
	}
}

// TestReservePublicationExecutionConcurrentSingleWinner drives many
// concurrent distinct-attempt contenders at ONE publication id across TWO
// store handles over ONE file-backed database (one unique t.TempDir() path
// opened twice): exactly one attempt id wins, every contender reads back the
// SAME winner, and only one row is ever created — proving "two distinct
// attempts racing under one PublicationID cannot both pass pending state" at
// the store's atomic primitive.
func TestReservePublicationExecutionConcurrentSingleWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pubexec_concurrent.sqlite")
	storeA, errA := OpenSQLite(path)
	if errA != nil {
		t.Fatal(errA)
	}
	defer storeA.DB.Close()
	storeB, errB := OpenSQLite(path)
	if errB != nil {
		t.Fatal(errB)
	}
	defer storeB.DB.Close()
	reg, _ := seedFeedSignerRegistry(t, storeA)
	ctx := context.Background()

	const pubID = "pub-exec-concurrent"
	const contenders = 12
	var wg sync.WaitGroup
	results := make([]string, contenders)
	errs := make([]error, contenders)
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := storeA
			if i%2 == 1 {
				store = storeB
			}
			attemptID := "attempt-" + string(rune('a'+i))
			row, err := store.ReservePublicationExecution(ctx, pubID, reg.ID, attemptID)
			results[i] = row.AttemptID
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("contender %d: %v", i, errs[i])
		}
	}
	winner := results[0]
	for i := 1; i < contenders; i++ {
		if results[i] != winner {
			t.Fatalf("every contender must read back the SAME winning attempt id; contender %d diverged (%q vs %q)", i, results[i], winner)
		}
	}
	var rows int
	if err := storeA.DB.QueryRowContext(ctx, `select count(*) from publication_states`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("exactly one execution row must win, got %d", rows)
	}
}

// TestMarkPublicationExecutionReplaceableGuardsOnAttemptAndState proves
// MarkPublicationExecutionReplaceable only flips active->replaceable when the
// CALLER's attempt id still matches the recorded active attempt (applied=true
// only then), and is a harmless, OBSERVABLE no-op (applied=false, err=nil)
// against a stale attempt id or a non-active row — the caller can and must
// distinguish "durably confirmed" from "silently skipped".
func TestMarkPublicationExecutionReplaceableGuardsOnAttemptAndState(t *testing.T) {
	store := newFileBackedProvisioningStore(t)
	reg, _ := seedFeedSignerRegistry(t, store)
	ctx := context.Background()

	if _, err := store.ReservePublicationExecution(ctx, "pub-exec-mark", reg.ID, "attempt-1"); err != nil {
		t.Fatal(err)
	}

	// A stale attempt id must never flip the row, and must report applied=false.
	applied, err := store.MarkPublicationExecutionReplaceable(ctx, "pub-exec-mark", "attempt-stale")
	if err != nil {
		t.Fatalf("mark with stale attempt id must not error: %v", err)
	}
	if applied {
		t.Fatal("a stale attempt id must report applied=false")
	}
	row, err := store.GetPublicationExecution(ctx, "pub-exec-mark")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != PublicationExecutionActive {
		t.Fatalf("a stale attempt id must never flip the row, got %q", row.State)
	}

	// The exact current attempt id flips it and reports applied=true.
	applied, err = store.MarkPublicationExecutionReplaceable(ctx, "pub-exec-mark", "attempt-1")
	if err != nil {
		t.Fatalf("mark with the current attempt id: %v", err)
	}
	if !applied {
		t.Fatal("the exact current attempt id must report applied=true")
	}
	row, err = store.GetPublicationExecution(ctx, "pub-exec-mark")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != PublicationExecutionReplaceable {
		t.Fatalf("expected replaceable, got %q", row.State)
	}

	// Once replaceable, marking again with the SAME attempt id is a no-op
	// (already flipped; the guard requires state='active') and reports
	// applied=false — it is NOT durably re-confirmed by this call.
	applied, err = store.MarkPublicationExecutionReplaceable(ctx, "pub-exec-mark", "attempt-1")
	if err != nil {
		t.Fatalf("re-mark must not error: %v", err)
	}
	if applied {
		t.Fatal("re-marking an already-replaceable row must report applied=false")
	}
	row, err = store.GetPublicationExecution(ctx, "pub-exec-mark")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != PublicationExecutionReplaceable {
		t.Fatalf("re-mark must stay replaceable, got %q", row.State)
	}
}

// TestReplacePublicationExecutionAttemptCAS proves the compare-and-swap
// contract: replacement succeeds ONLY when the row is currently replaceable
// with the exact old attempt id, atomically flips to active with the new
// attempt id, and a losing racer against the SAME old attempt id never wins
// once another replacement already succeeded.
func TestReplacePublicationExecutionAttemptCAS(t *testing.T) {
	store := newFileBackedProvisioningStore(t)
	reg, _ := seedFeedSignerRegistry(t, store)
	ctx := context.Background()

	if _, err := store.ReservePublicationExecution(ctx, "pub-exec-cas", reg.ID, "attempt-old"); err != nil {
		t.Fatal(err)
	}

	// Not yet replaceable: the CAS must not win.
	won, row, err := store.ReplacePublicationExecutionAttempt(ctx, "pub-exec-cas", reg.ID, "attempt-old", "attempt-new")
	if err != nil {
		t.Fatal(err)
	}
	if won {
		t.Fatal("a CAS against a still-active row must never win")
	}
	if row.State != PublicationExecutionActive || row.AttemptID != "attempt-old" {
		t.Fatalf("unchanged row expected, got %+v", row)
	}

	if _, err := store.MarkPublicationExecutionReplaceable(ctx, "pub-exec-cas", "attempt-old"); err != nil {
		t.Fatal(err)
	}

	// A CAS against the WRONG old attempt id must never win, even though the
	// row is replaceable.
	won, _, err = store.ReplacePublicationExecutionAttempt(ctx, "pub-exec-cas", reg.ID, "attempt-wrong", "attempt-new")
	if err != nil {
		t.Fatal(err)
	}
	if won {
		t.Fatal("a CAS against the wrong old attempt id must never win")
	}

	// The exact old attempt id wins and flips the row to active/new.
	won, row, err = store.ReplacePublicationExecutionAttempt(ctx, "pub-exec-cas", reg.ID, "attempt-old", "attempt-new")
	if err != nil {
		t.Fatal(err)
	}
	if !won {
		t.Fatal("the exact CAS must win")
	}
	if row.State != PublicationExecutionActive || row.AttemptID != "attempt-new" {
		t.Fatalf("winner row must be active/attempt-new, got %+v", row)
	}

	// A SECOND replacement bid against the now-stale old attempt id must
	// never win a second time (the row is active again, not replaceable).
	won, _, err = store.ReplacePublicationExecutionAttempt(ctx, "pub-exec-cas", reg.ID, "attempt-old", "attempt-third")
	if err != nil {
		t.Fatal(err)
	}
	if won {
		t.Fatal("a stale replaceable CAS must never win twice")
	}
}

// TestReplacePublicationExecutionAttemptConcurrentSingleWinner proves that
// when two distinct fresh attempts race the SAME CAS concurrently, exactly
// one wins and the row lands on exactly one of the two candidate attempt
// ids — never both, never neither, never corrupted.
func TestReplacePublicationExecutionAttemptConcurrentSingleWinner(t *testing.T) {
	store := newFileBackedProvisioningStore(t)
	reg, _ := seedFeedSignerRegistry(t, store)
	ctx := context.Background()

	if _, err := store.ReservePublicationExecution(ctx, "pub-exec-cas-race", reg.ID, "attempt-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkPublicationExecutionReplaceable(ctx, "pub-exec-cas-race", "attempt-old"); err != nil {
		t.Fatal(err)
	}

	const contenders = 10
	var mu sync.Mutex
	var winCount int
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			newID := "attempt-new-" + string(rune('a'+i))
			won, _, err := store.ReplacePublicationExecutionAttempt(ctx, "pub-exec-cas-race", reg.ID, "attempt-old", newID)
			if err != nil {
				t.Errorf("contender %d: %v", i, err)
				return
			}
			if won {
				mu.Lock()
				winCount++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if winCount != 1 {
		t.Fatalf("exactly one racing replacement must win, got %d", winCount)
	}
	row, err := store.GetPublicationExecution(ctx, "pub-exec-cas-race")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != PublicationExecutionActive {
		t.Fatalf("the row must land active after the race, got %q", row.State)
	}
	if row.AttemptID == "attempt-old" {
		t.Fatal("the row must have been replaced by one of the racing attempts")
	}
}

// completeFixture seeds a reserved publication execution row plus a claimed
// feed_signer_operations attempt row ready for
// CompleteFeedSignerOperationAndTerminatePublication, returning everything a
// caller needs to invoke and re-verify it.
type completeFixture struct {
	store     *Store
	reg       Registry
	pubID     string
	attemptID string
	reqHash   [32]byte
	token     string
	result    []byte
}

func newCompleteFixture(t *testing.T, pubID, attemptID string) completeFixture {
	t.Helper()
	store := newFileBackedProvisioningStore(t)
	reg, _ := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	if _, err := store.ReservePublicationExecution(ctx, pubID, reg.ID, attemptID); err != nil {
		t.Fatal(err)
	}
	reqHash := feedSignerTestHash("complete-" + pubID + "-" + attemptID)
	feed := "feed://" + testFeedOwner + "/" + refHex('c')
	if _, err := store.ReserveFeedSignerOperation(ctx, attemptID, reg.ID, feed, reqHash); err != nil {
		t.Fatal(err)
	}
	token := testClaimToken(t)
	won, err := store.ClaimFeedSignerOperation(ctx, attemptID, reqHash, token, time.Now().UTC().Add(time.Minute))
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	result := []byte(`{"operationID":"` + attemptID + `","feed":"` + feed + `","reference":"` + refHex('a') + `"}`)
	return completeFixture{store: store, reg: reg, pubID: pubID, attemptID: attemptID, reqHash: reqHash, token: token, result: result}
}

// TestCompleteFeedSignerOperationAndTerminatePublicationAtomic proves the
// combined completion helper marks BOTH the per-attempt feed_signer_operations
// row succeeded AND the logical publication_states row succeeded/terminal in
// one atomic transaction, guarded on the exact active attempt id and
// registry.
func TestCompleteFeedSignerOperationAndTerminatePublicationAtomic(t *testing.T) {
	fx := newCompleteFixture(t, "pub-exec-complete", "attempt-complete-1")
	ctx := context.Background()

	if err := fx.store.CompleteFeedSignerOperationAndTerminatePublication(ctx, fx.attemptID, fx.reqHash, fx.token, fx.result, fx.pubID, fx.reg.ID, fx.attemptID); err != nil {
		t.Fatalf("combined complete: %v", err)
	}

	op, err := fx.store.GetFeedSignerOperation(ctx, fx.attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("attempt row must be succeeded, got %q", op.State)
	}
	exec, err := fx.store.GetPublicationExecution(ctx, fx.pubID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionSucceeded {
		t.Fatalf("publication execution must be succeeded, got %q", exec.State)
	}
	if exec.AttemptID != fx.attemptID {
		t.Fatalf("succeeded execution must record the succeeding attempt id, got %q", exec.AttemptID)
	}
}

// TestCompleteFeedSignerOperationAndTerminatePublicationIdempotentConcurrent
// proves a second call with the SAME exact attempt id, registry, and
// canonical result — modeling a concurrent identical completer racing the
// first — is a safe idempotent no-op: no error, and both rows stay exactly as
// the first completion left them.
func TestCompleteFeedSignerOperationAndTerminatePublicationIdempotentConcurrent(t *testing.T) {
	fx := newCompleteFixture(t, "pub-exec-complete-idem", "attempt-complete-idem")
	ctx := context.Background()

	if err := fx.store.CompleteFeedSignerOperationAndTerminatePublication(ctx, fx.attemptID, fx.reqHash, fx.token, fx.result, fx.pubID, fx.reg.ID, fx.attemptID); err != nil {
		t.Fatalf("first complete: %v", err)
	}
	// A second call reusing the SAME (now-cleared) claim token cannot re-win
	// the feed_signer_operations UPDATE (state is already 'succeeded', not
	// 'processing'), which is exactly the concurrent-identical-completer shape
	// CompleteFeedSignerOperation itself tolerates.
	if err := fx.store.CompleteFeedSignerOperationAndTerminatePublication(ctx, fx.attemptID, fx.reqHash, fx.token, fx.result, fx.pubID, fx.reg.ID, fx.attemptID); err != nil {
		t.Fatalf("idempotent concurrent complete must not error: %v", err)
	}
	op, err := fx.store.GetFeedSignerOperation(ctx, fx.attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("attempt row must remain succeeded, got %q", op.State)
	}
	exec, err := fx.store.GetPublicationExecution(ctx, fx.pubID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionSucceeded || exec.AttemptID != fx.attemptID {
		t.Fatalf("execution row must remain succeeded/%s, got %+v", fx.attemptID, exec)
	}
}

// TestCompleteFeedSignerOperationAndTerminatePublicationRollsBackOnMissingRow
// proves that when the publication_states row was NEVER reserved for this
// publication id (a bug, or an attempt that never went through the gate), the
// combined completion returns an error and rolls back the
// feed_signer_operations completion it just applied in the SAME transaction —
// the attempt row is left EXACTLY as it was before the call (still
// processing, not succeeded), never split.
func TestCompleteFeedSignerOperationAndTerminatePublicationRollsBackOnMissingRow(t *testing.T) {
	store := newFileBackedProvisioningStore(t)
	reg, _ := seedFeedSignerRegistry(t, store)
	ctx := context.Background()

	const attemptID = "attempt-orphan"
	reqHash := feedSignerTestHash("orphan-attempt")
	feed := "feed://" + testFeedOwner + "/" + refHex('c')
	if _, err := store.ReserveFeedSignerOperation(ctx, attemptID, reg.ID, feed, reqHash); err != nil {
		t.Fatal(err)
	}
	token := testClaimToken(t)
	won, err := store.ClaimFeedSignerOperation(ctx, attemptID, reqHash, token, time.Now().UTC().Add(time.Minute))
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	result := []byte(`{"operationID":"` + attemptID + `","feed":"` + feed + `","reference":"` + refHex('a') + `"}`)

	// No publication_states row was ever reserved for "pub-exec-orphan".
	if err := store.CompleteFeedSignerOperationAndTerminatePublication(ctx, attemptID, reqHash, token, result, "pub-exec-orphan", reg.ID, attemptID); err == nil {
		t.Fatal("a missing publication execution row must fail the combined completion")
	}

	op, err := store.GetFeedSignerOperation(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpProcessing {
		t.Fatalf("the attempt row must be ROLLED BACK to processing (unchanged), got %q", op.State)
	}
	if _, err := store.GetPublicationExecution(ctx, "pub-exec-orphan"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("no publication execution row must have been created, got %v", err)
	}
}

// TestCompleteFeedSignerOperationAndTerminatePublicationRollsBackOnStaleAttempt
// proves that when the publication_states row is active under a DIFFERENT
// attempt id than the one completing (a bug, or a completion racing a
// replacement it does not know about), the combined completion errors and
// rolls back — the attempt row is left processing, never succeeded, and the
// execution row is left exactly as it was (active under the OTHER attempt).
func TestCompleteFeedSignerOperationAndTerminatePublicationRollsBackOnStaleAttempt(t *testing.T) {
	fx := newCompleteFixture(t, "pub-exec-stale", "attempt-stale-mine")
	ctx := context.Background()

	// Force the row into a state owned by a DIFFERENT attempt id, modeling a
	// replacement that happened between this attempt's own commit
	// authorization and its (racing, now-stale) completion.
	if _, err := fx.store.MarkPublicationExecutionReplaceable(ctx, fx.pubID, fx.attemptID); err != nil {
		t.Fatal(err)
	}
	replacedWon, _, err := fx.store.ReplacePublicationExecutionAttempt(ctx, fx.pubID, fx.reg.ID, fx.attemptID, "attempt-other-owner")
	if err != nil {
		t.Fatal(err)
	}
	if !replacedWon {
		t.Fatal("setup: the replacement to a different attempt id must win")
	}

	if err := fx.store.CompleteFeedSignerOperationAndTerminatePublication(ctx, fx.attemptID, fx.reqHash, fx.token, fx.result, fx.pubID, fx.reg.ID, fx.attemptID); err == nil {
		t.Fatal("completing under a stale (replaced) attempt id must fail")
	}

	op, err := fx.store.GetFeedSignerOperation(ctx, fx.attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpProcessing {
		t.Fatalf("the attempt row must be ROLLED BACK to processing, got %q", op.State)
	}
	exec, err := fx.store.GetPublicationExecution(ctx, fx.pubID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionActive || exec.AttemptID != "attempt-other-owner" {
		t.Fatalf("the execution row must remain owned by the OTHER attempt, got %+v", exec)
	}
}

// TestCompleteFeedSignerOperationAndTerminatePublicationRollsBackOnRegistryMismatch
// proves a registryID mismatch (a defensive/impossible-in-practice case,
// since PublicationID hashes bind the registry) still fails closed rather
// than silently terminating a publication scoped to a different registry.
func TestCompleteFeedSignerOperationAndTerminatePublicationRollsBackOnRegistryMismatch(t *testing.T) {
	fx := newCompleteFixture(t, "pub-exec-regmismatch", "attempt-regmismatch")
	ctx := context.Background()

	otherOwner, err := fx.store.CreateUser(ctx, "pubexec-other-owner@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	otherReg, err := fx.store.CreateProvisionedRegistry(ctx, Registry{
		Slug: "signertest-other", Host: "signer-other.registry.test", ENSName: "signer-other.eth",
		OwnerUserID: otherOwner.ID, FeedOwnerAddress: testFeedOwner, DefaultStampBatchID: "batch-signer-other",
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("seed second registry: %v", err)
	}
	if otherReg.ID == fx.reg.ID {
		t.Fatal("setup requires two distinct registries")
	}

	if err := fx.store.CompleteFeedSignerOperationAndTerminatePublication(ctx, fx.attemptID, fx.reqHash, fx.token, fx.result, fx.pubID, otherReg.ID, fx.attemptID); err == nil {
		t.Fatal("a registry-scope mismatch must fail the combined completion")
	}

	op, err := fx.store.GetFeedSignerOperation(ctx, fx.attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != FeedSignerOpProcessing {
		t.Fatalf("the attempt row must be ROLLED BACK to processing, got %q", op.State)
	}
	exec, err := fx.store.GetPublicationExecution(ctx, fx.pubID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.State != PublicationExecutionActive || exec.RegistryID != fx.reg.ID {
		t.Fatalf("the execution row must remain untouched under its original registry, got %+v", exec)
	}
}

// TestPublicationExecutionTableConstraints pins the DB-level guards: the FK
// to registries, the registry_id > 0 check, the state vocabulary, and the
// byte-exact operation-ID grammar applied to BOTH operation_id and
// attempt_id, so a direct-SQL write can never store a malformed row.
func TestPublicationExecutionTableConstraints(t *testing.T) {
	db := openRawFileTestDB(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := &Store{DB: db}
	reg, _ := seedFeedSignerRegistry(t, store)
	now := timeToNanos(time.Now().UTC())

	insert := func(pubID string, registryID int64, state, attemptID string) error {
		_, err := db.ExecContext(ctx, `insert into publication_states
			(operation_id, registry_id, state, attempt_id, created_at, updated_at)
			values (?, ?, ?, ?, ?, ?)`, pubID, registryID, state, attemptID, now, now)
		return err
	}

	if err := insert("pub-exec-ok", reg.ID, "active", "attempt-ok"); err != nil {
		t.Fatalf("valid row must insert: %v", err)
	}

	badCases := []struct {
		name string
		run  func() error
	}{
		{"unknown registry FK", func() error { return insert("pub-exec-badfk", 999999, "active", "attempt-1") }},
		{"non-positive registry id", func() error { return insert("pub-exec-badreg", 0, "active", "attempt-1") }},
		{"bad state vocabulary", func() error { return insert("pub-exec-badstate", reg.ID, "pending", "attempt-1") }},
		{"empty operation id", func() error { return insert("", reg.ID, "active", "attempt-1") }},
		{"oversized operation id", func() error {
			return insert(string(make([]byte, 129)), reg.ID, "active", "attempt-1")
		}},
		{"empty attempt id", func() error { return insert("pub-exec-badattempt", reg.ID, "active", "") }},
		{"double-quote attempt id", func() error { return insert("pub-exec-q", reg.ID, "active", `attempt"x`) }},
		{"invalid utf8 attempt id", func() error { return insert("pub-exec-u8", reg.ID, "active", "attempt-\xff") }},
	}
	for _, tc := range badCases {
		if err := tc.run(); err == nil {
			t.Fatalf("%s must be rejected by the schema", tc.name)
		}
	}
	var rows int
	if err := db.QueryRowContext(ctx, `select count(*) from publication_states`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("only the single valid row may exist, got %d", rows)
	}
}

// TestMigration16FreshUpgradeAndRollback covers startup compatibility and
// atomicity: a fresh database converges to version 16 with the table and its
// identity triggers; a version-15 database upgrades with its existing
// publication_bindings/feed_signer_operations state intact; and a
// migration-16 statement failure (pre-existing wrong-schema table) rolls the
// whole transaction back — version stays 15, no migration row is recorded,
// and the incompatible table is untouched.
func TestMigration16FreshUpgradeAndRollback(t *testing.T) {
	ctx := context.Background()

	fresh := openRawFileTestDB(t)
	if err := ApplyMigrations(ctx, fresh); err != nil {
		t.Fatalf("fresh apply: %v", err)
	}
	if v, _ := CurrentSchemaVersion(ctx, fresh); v != 16 {
		t.Fatalf("fresh db must reach version 16, got %d", v)
	}
	if sqliteObjectCount(t, fresh, "table", "publication_states") != 1 {
		t.Fatal("migration 16 must create publication_states on a fresh database")
	}
	if sqliteObjectCount(t, fresh, "trigger", "publication_state_operation_id_ins") != 1 ||
		sqliteObjectCount(t, fresh, "trigger", "publication_state_operation_id_upd") != 1 {
		t.Fatal("migration 16 must install the publication-state identity triggers")
	}

	upg := openRawFileTestDB(t)
	if err := applyMigrationsThrough(ctx, upg, 15); err != nil {
		t.Fatalf("apply through 15: %v", err)
	}
	upgStore := &Store{DB: upg}
	reg, _ := seedFeedSignerRegistry(t, upgStore)
	hash := NormalizePublicationBindingHash(reg.ID, testFeedOwner, "myrepo", "latest", "sha256:"+string(make([]byte, 64)))
	if _, err := upgStore.ReservePublicationBinding(ctx, "op-before-16", reg.ID, hash); err != nil {
		t.Fatalf("seed pre-16 binding: %v", err)
	}
	if err := ApplyMigrations(ctx, upg); err != nil {
		t.Fatalf("upgrade to 16: %v", err)
	}
	if v, _ := CurrentSchemaVersion(ctx, upg); v != 16 {
		t.Fatalf("upgraded db must reach version 16, got %d", v)
	}
	if sqliteObjectCount(t, upg, "table", "publication_states") != 1 {
		t.Fatal("migration 16 must create publication_states on upgrade")
	}
	var kept string
	if err := upg.QueryRowContext(ctx, `select operation_id from publication_bindings where operation_id = 'op-before-16'`).Scan(&kept); err != nil || kept != "op-before-16" {
		t.Fatalf("pre-16 publication-binding state must be untouched, got %q err %v", kept, err)
	}

	rb := openRawFileTestDB(t)
	if err := applyMigrationsThrough(ctx, rb, 15); err != nil {
		t.Fatalf("apply through 15: %v", err)
	}
	if _, err := rb.ExecContext(ctx, `create table publication_states (operation_id text primary key, unrelated_col integer)`); err != nil {
		t.Fatalf("seed wrong-schema table: %v", err)
	}
	if err := ApplyMigrations(ctx, rb); err == nil {
		t.Fatal("migration 16 must fail against a wrong-schema pre-existing table")
	}
	if v, _ := CurrentSchemaVersion(ctx, rb); v != 15 {
		t.Fatalf("failed migration 16 must leave version at 15, got %d", v)
	}
	var migRows int
	if err := rb.QueryRowContext(ctx, `select count(*) from schema_migrations`).Scan(&migRows); err != nil {
		t.Fatal(err)
	}
	if migRows != 15 {
		t.Fatalf("failed migration 16 must not record a migration row, got %d", migRows)
	}
	cols := tableColumnsOf(t, rb, "publication_states")
	if !cols["operation_id"] || !cols["unrelated_col"] || len(cols) != 2 {
		t.Fatalf("the incompatible table must be untouched by the failed migration, got %v", cols)
	}
}

// TestMigration16RejectsMalformedV15Predecessor proves migration 16 validates
// the exact migration-15 publication-binding schema before installing any new
// object. A stamped-but-weakened predecessor must fail closed and atomically:
// version 15 remains current and publication_states is not created.
func TestMigration16RejectsMalformedV15Predecessor(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *sql.DB)
	}{
		{
			name: "missing binding identity trigger",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`drop trigger publication_binding_operation_id_ins`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "weakened binding table lookalike",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`drop table publication_bindings`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`create table publication_bindings (operation_id text primary key, registry_id integer, binding_hash blob, created_at integer, updated_at integer)`); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := openRawFileTestDB(t)
			if err := applyMigrationsThrough(ctx, db, 15); err != nil {
				t.Fatalf("apply exact predecessor: %v", err)
			}
			tc.mutate(t, db)

			if err := ApplyMigrations(ctx, db); err == nil {
				t.Fatal("migration 16 must reject a malformed version-15 predecessor")
			}
			if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 15 {
				t.Fatalf("failed migration must leave version 15 current, got %d (err %v)", v, err)
			}
			if sqliteObjectCount(t, db, "table", "publication_states") != 0 {
				t.Fatal("failed predecessor validation must not leave publication_states installed")
			}
			if sqliteObjectCount(t, db, "trigger", "publication_state_operation_id_ins") != 0 ||
				sqliteObjectCount(t, db, "trigger", "publication_state_operation_id_upd") != 0 {
				t.Fatal("failed predecessor validation must not leave publication-state triggers installed")
			}
		})
	}
}

// TestGetPublicationExecutionNoRows proves a never-reserved publication id
// reports sql.ErrNoRows, never a fabricated zero-value row.
func TestGetPublicationExecutionNoRows(t *testing.T) {
	store := newFileBackedProvisioningStore(t)
	if _, err := store.GetPublicationExecution(context.Background(), "pub-exec-never"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

// Round 4 / Finding 1: migration 16 must not silently create an empty
// publication_states table over a v15 database that already carries
// unprotectable completed-publication history. These tests build the exact
// predecessor via the SAME migration helpers used everywhere else
// (applyMigrationsThrough executes real migrations 1-15; nothing here is a
// hand-authored lookalike row), then drive a REAL feed_signer_operations row
// through the SAME store methods the pre-round-3 signer used
// (ReserveFeedSignerOperation / ClaimFeedSignerOperation /
// CompleteFeedSignerOperation), so the "succeeded" row is a genuine
// persisted equivalent of a pre-v16 completed publication, not an imagined
// one.

// TestMigration16RefusesPreV16SucceededPublicationHistory is the round-4 /
// Finding 1 acceptance proof. Neither feed_signer_operations (keyed by the
// per-ATTEMPT identity, a one-way hash) nor publication_bindings (which
// carries a bound hash but no success/failure state) can be inverted back to
// "which stable PublicationID, if any, already reached a terminal success" —
// so an empty publication_states table would silently leave a real pre-v16
// success unprotected: exactly the round-3 gap where a retried P
// (recomputing a fresh per-attempt identity against a generation an
// unrelated later Q advanced) authenticates cleanly and advances the feed a
// second time. Migration 16 must instead refuse atomically: version stays
// 15, publication_states is never created, and the pre-existing succeeded
// row is byte-for-byte untouched.
func TestMigration16RefusesPreV16SucceededPublicationHistory(t *testing.T) {
	ctx := context.Background()
	db := openRawFileTestDB(t)
	if err := applyMigrationsThrough(ctx, db, 15); err != nil {
		t.Fatalf("apply exact predecessor: %v", err)
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)

	// P: a real publish attempt driven to a genuine 'succeeded' row through
	// the pre-round-3 store machinery (unaffected by migrations 15/16).
	const opP = "op-p-pre-v16-succeeded"
	reqP := publish.FeedCommitRequest{
		OperationID: opP, RegistryID: reg.ID, Owner: "0x" + testFeedOwner,
		Topic: topic, Reference: refHex('a'), BatchID: "batch-1", ExpectedGeneration: 0,
	}
	hashP := NormalizeFeedCommitHash(reqP)
	if _, err := store.ReserveFeedSignerOperation(ctx, opP, reg.ID, topic, hashP); err != nil {
		t.Fatalf("reserve P: %v", err)
	}
	const tokenP = "claim-token-pre-v16-000000000001"
	won, err := store.ClaimFeedSignerOperation(ctx, opP, hashP, tokenP, time.Now().UTC().Add(time.Minute))
	if err != nil || !won {
		t.Fatalf("claim P: won=%v err=%v", won, err)
	}
	resultP := publish.FeedCommitResult{OperationID: opP, Feed: publish.CanonicalTopic(topic), Reference: publish.CanonicalReference(refHex('a'))}
	if err := store.CompleteFeedSignerOperation(ctx, opP, hashP, tokenP, publish.CanonicalFeedCommitResultJSON(resultP)); err != nil {
		t.Fatalf("complete P: %v", err)
	}
	before, err := store.GetFeedSignerOperation(ctx, opP)
	if err != nil || before.State != FeedSignerOpSucceeded {
		t.Fatalf("P must be a genuine succeeded row before migrating, got %+v err %v", before, err)
	}

	// Q: an unrelated later publication that would overwrite the same tag —
	// modeled here as a second real succeeded row, proving the refusal is not
	// an artifact of there being only one completed operation.
	const opQ = "op-q-pre-v16-succeeded"
	reqQ := publish.FeedCommitRequest{
		OperationID: opQ, RegistryID: reg.ID, Owner: "0x" + testFeedOwner,
		Topic: topic, Reference: refHex('f'), BatchID: "batch-1", ExpectedGeneration: 1,
	}
	hashQ := NormalizeFeedCommitHash(reqQ)
	if _, err := store.ReserveFeedSignerOperation(ctx, opQ, reg.ID, topic, hashQ); err != nil {
		t.Fatalf("reserve Q: %v", err)
	}
	const tokenQ = "claim-token-pre-v16-000000000002"
	won, err = store.ClaimFeedSignerOperation(ctx, opQ, hashQ, tokenQ, time.Now().UTC().Add(time.Minute))
	if err != nil || !won {
		t.Fatalf("claim Q: won=%v err=%v", won, err)
	}
	resultQ := publish.FeedCommitResult{OperationID: opQ, Feed: publish.CanonicalTopic(topic), Reference: publish.CanonicalReference(refHex('f'))}
	if err := store.CompleteFeedSignerOperation(ctx, opQ, hashQ, tokenQ, publish.CanonicalFeedCommitResultJSON(resultQ)); err != nil {
		t.Fatalf("complete Q: %v", err)
	}

	if err := ApplyMigrations(ctx, db); err == nil || !errors.Is(err, errPublicationStateHistoryUnsafe) {
		t.Fatalf("migration 16 must refuse pre-v16 succeeded publication history, got %v", err)
	}
	if v, verr := CurrentSchemaVersion(ctx, db); verr != nil || v != 15 {
		t.Fatalf("refused migration must leave version 15 current, got %d (err %v)", v, verr)
	}
	if sqliteObjectCount(t, db, "table", "publication_states") != 0 {
		t.Fatal("refused migration must not create publication_states")
	}
	var migRows int
	if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations`).Scan(&migRows); err != nil {
		t.Fatal(err)
	}
	if migRows != 15 {
		t.Fatalf("refused migration must not record a migration row, got %d", migRows)
	}
	afterP, err := store.GetFeedSignerOperation(ctx, opP)
	if err != nil || afterP.State != FeedSignerOpSucceeded || !bytesEqual(afterP.ResultJSON, publish.CanonicalFeedCommitResultJSON(resultP)) {
		t.Fatalf("P's pre-existing succeeded row must be byte-for-byte untouched, got %+v err %v", afterP, err)
	}
	afterQ, err := store.GetFeedSignerOperation(ctx, opQ)
	if err != nil || afterQ.State != FeedSignerOpSucceeded {
		t.Fatalf("Q's pre-existing succeeded row must be untouched, got %+v err %v", afterQ, err)
	}
}

// TestMigration16AllowsSafePreV16History proves the fail-closed rule targets
// EXACTLY completed (succeeded) history: a completely empty pre-v16
// database, and a v15 database carrying ONLY non-terminal history (a durable
// preflight binding with no completed write, and a feed_signer_operations
// row still pending) both upgrade to 16 normally.
func TestMigration16AllowsSafePreV16History(t *testing.T) {
	ctx := context.Background()

	t.Run("empty history", func(t *testing.T) {
		db := openRawFileTestDB(t)
		if err := applyMigrationsThrough(ctx, db, 15); err != nil {
			t.Fatalf("apply through 15: %v", err)
		}
		if err := ApplyMigrations(ctx, db); err != nil {
			t.Fatalf("empty-history upgrade must succeed: %v", err)
		}
		if v, _ := CurrentSchemaVersion(ctx, db); v != 16 {
			t.Fatalf("expected version 16, got %d", v)
		}
	})

	t.Run("merely bound and pending history", func(t *testing.T) {
		db := openRawFileTestDB(t)
		if err := applyMigrationsThrough(ctx, db, 15); err != nil {
			t.Fatalf("apply through 15: %v", err)
		}
		store := &Store{DB: db}
		reg, topic := seedFeedSignerRegistry(t, store)

		hash := NormalizePublicationBindingHash(reg.ID, "0x"+testFeedOwner, "myrepo", "latest", "sha256:"+refHex('d'))
		if _, err := store.ReservePublicationBinding(ctx, "op-bound-only", reg.ID, hash); err != nil {
			t.Fatalf("seed binding: %v", err)
		}

		req := publish.FeedCommitRequest{
			OperationID: "op-pending-only", RegistryID: reg.ID, Owner: "0x" + testFeedOwner,
			Topic: topic, Reference: refHex('a'), BatchID: "batch-1", ExpectedGeneration: 0,
		}
		reqHash := NormalizeFeedCommitHash(req)
		if _, err := store.ReserveFeedSignerOperation(ctx, req.OperationID, reg.ID, topic, reqHash); err != nil {
			t.Fatalf("seed pending operation: %v", err)
		}
		pendingRow, err := store.GetFeedSignerOperation(ctx, req.OperationID)
		if err != nil || pendingRow.State != FeedSignerOpPending {
			t.Fatalf("sanity: row must be pending before migrating, got %+v err %v", pendingRow, err)
		}

		if err := ApplyMigrations(ctx, db); err != nil {
			t.Fatalf("merely-bound/pending upgrade must succeed: %v", err)
		}
		if v, _ := CurrentSchemaVersion(ctx, db); v != 16 {
			t.Fatalf("expected version 16, got %d", v)
		}
		if sqliteObjectCount(t, db, "table", "publication_states") != 1 {
			t.Fatal("safe upgrade must still create publication_states")
		}
	})
}

// TestMigration16RepeatedApplyIsIdempotent proves ApplyMigrations run twice
// over the same already-migrated database never re-applies migration 16 (or
// records a duplicate row).
func TestMigration16RepeatedApplyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	db := openRawFileTestDB(t)
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("repeated apply must be a no-op, got: %v", err)
	}
	if v, _ := CurrentSchemaVersion(ctx, db); v != 16 {
		t.Fatalf("expected version 16, got %d", v)
	}
	var rows int
	if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations where version = 16`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("migration 16 must be recorded exactly once, got %d", rows)
	}
}
