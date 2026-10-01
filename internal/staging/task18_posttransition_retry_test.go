package staging

// Task 18 round-2 correction: a publication consume whose filesystem /
// quarantine cleanup fails AFTER the claimed -> deleting transition commits
// must leave a PUBLICATION-OWNED deleting tombstone (operation_id retained),
// never an unowned one, so an exact-operation retry can durably finish it.
// Before this fix the transition cleared operation_id, so the exact retry
// (which selects state='claimed' AND operation_id=?) saw nothing, returned
// success, and the handler emitted 201 while the quota-charged bytes stayed
// stranded until a restart.

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// rawDeletingOwner reads, by DB path, the operation_id bound to a deleting
// tombstone (empty means unowned/NULL). This is the introspection that proves
// the post-transition tombstone retained (or lost) its publication ownership.
func rawDeletingOwner(t *testing.T, dbPath, id string) string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	var op sql.NullString
	if err := db.QueryRow(`select operation_id from upload_sessions where id = ?`, id).Scan(&op); err != nil {
		t.Fatalf("read operation_id: %v", err)
	}
	return op.String
}

// rawOwnedDeletingCount counts publication-owned deleting tombstones
// (state='deleting' AND operation_id non-null) across the DB — the durable
// post-transition residue form an exact retry must be able to finish.
func rawOwnedDeletingCount(t *testing.T, dbPath, repo, actor string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(
		`select count(*) from upload_sessions where repo = ? and actor = ? and state = 'deleting' and operation_id is not null`,
		repo, actor).Scan(&n); err != nil {
		t.Fatalf("count owned deleting: %v", err)
	}
	return n
}

// mustRawDB opens a direct SQLite handle on the shared staging DB path.
func mustRawDB(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// rawRowState reads the state column of one session by id (raw helper).
func rawRowState(t *testing.T, dbPath, id string) string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw state: %v", err)
	}
	defer db.Close()
	var st string
	if err := db.QueryRow(`select state from upload_sessions where id = ?`, id).Scan(&st); err != nil {
		t.Fatalf("read state: %v", err)
	}
	return st
}

// TestConsumePostTransitionFaultRetainsOwnedTombstoneAndRetryRemoves proves
// the core finding: a consume whose production finishDeletion faults AFTER
// the claimed -> deleting transition commits must (a) leave a
// PUBLICATION-OWNED deleting tombstone that keeps charging quota, (b) make a
// DIFFERENT operation's consume a no-op, and (c) let the SAME operation's
// exact retry durably resume and remove it (201-equivalent success, quota
// reusable).
func TestConsumePostTransitionFaultRetainsOwnedTombstoneAndRetryRemoves(t *testing.T) {
	dir := tempPrivate(t)
	svc := openSharedService(t, dir)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)

	repo, actor := seedRepo, seedActor
	digest, _ := claimPubFinalize(t, svc, repo, actor)
	mustClaim(t, svc, repo, actor, "op-retry", []string{digest})

	// Fault the PRODUCTION finishDeletion path (directory sync) so the first
	// consume transitions claimed -> deleting and then FAILS the filesystem
	// cleanup — exactly the post-transition window the finding describes. The
	// caller (handler) would withhold 201 on this error.
	di := firstSessionID(t, mustRawDB(t, dir+"/staging.db"))
	svc.dirSyncHook = func() error { return errors.New("INJECTED_FINISH_FAULT_9f2b") }
	if err := svc.ConsumeStagedForPublish(context.Background(), repo, actor, "op-retry", []string{digest}); err == nil {
		t.Fatal("faulted consume must report an error (handler withholds 201)")
	}
	svc.dirSyncHook = nil

	// The residue is a PUBLICATION-OWNED deleting tombstone: operation_id is
	// retained (never cleared), so an exact retry can select it.
	if st := rawRowState(t, dir+"/staging.db", di); st != string(StateDeleting) {
		t.Fatalf("post-fault residue state = %q, want deleting", st)
	}
	if op := rawDeletingOwner(t, dir+"/staging.db", di); op != "op-retry" {
		t.Fatalf("post-fault deleting tombstone lost operation ownership, got %q, want op-retry", op)
	}
	if n := rawOwnedDeletingCount(t, dir+"/staging.db", repo, actor); n != 1 {
		t.Fatalf("owned deleting tombstone count = %d, want 1 (quota still strands)", n)
	}

	// A DISTINCT operation's consume must NEVER resume/clear the owned
	// tombstone.
	if err := svc.ConsumeStagedForPublish(context.Background(), repo, actor, "op-other", []string{digest}); err != nil {
		t.Fatalf("foreign consume: %v", err)
	}
	if n := rawOwnedDeletingCount(t, dir+"/staging.db", repo, actor); n != 1 {
		t.Fatalf("foreign consume cleared the owned tombstone, want still 1, got %d", n)
	}
	if op := rawDeletingOwner(t, dir+"/staging.db", di); op != "op-retry" {
		t.Fatalf("foreign consume re-owned the tombstone as %q, want op-retry", op)
	}

	// The EXACT operation's retry resumes the owned tombstone and durably
	// removes it (finishDeletion now succeeds): 201-equivalent success, and
	// the quota charge is released.
	if err := svc.ConsumeStagedForPublish(context.Background(), repo, actor, "op-retry", []string{digest}); err != nil {
		t.Fatalf("exact retry consume: %v", err)
	}
	if n := rawOwnedDeletingCount(t, dir+"/staging.db", repo, actor); n != 0 {
		t.Fatalf("exact retry left an owned deleting tombstone, want 0, got %d", n)
	}
	if got := mustListStaged(t, svc, repo, actor); len(got) != 0 {
		t.Fatalf("publishable rows after retry = %+v, want none", got)
	}
}

// TestConsumePostTransitionRestartFinishesOwnedTombstone proves startup
// reconciliation may safely finish a PUBLICATION-OWNED deleting tombstone
// (without unpinning) and never convert it back to publishable state, so the
// stranding is bounded by a restart even if no explicit retry arrives.
func TestConsumePostTransitionRestartFinishesOwnedTombstone(t *testing.T) {
	dir := tempPrivate(t)
	svc1 := openSharedService(t, dir)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc1, now)

	repo, actor := seedRepo, seedActor
	digest, _ := claimPubFinalize(t, svc1, repo, actor)
	mustClaim(t, svc1, repo, actor, "op-crash", []string{digest})

	di := firstSessionID(t, mustRawDB(t, dir+"/staging.db"))
	svc1.dirSyncHook = func() error { return errors.New("INJECTED_FINISH_FAULT_9f2b") }
	if err := svc1.ConsumeStagedForPublish(context.Background(), repo, actor, "op-crash", []string{digest}); err == nil {
		t.Fatal("faulted consume must report an error")
	}
	svc1.dirSyncHook = nil
	if op := rawDeletingOwner(t, dir+"/staging.db", di); op != "op-crash" {
		t.Fatalf("crash residue lost ownership, got %q", op)
	}

	// "Restart": a NEW independent service instance over the same DB runs
	// startup reconciliation. The publication-owned deleting tombstone is a
	// terminal delete; startup finishes it (frees quota) and NEVER converts it
	// back to a publishable/claimable state.
	svc2 := openSharedService(t, dir)
	if n := rawOwnedDeletingCount(t, dir+"/staging.db", repo, actor); n != 0 {
		t.Fatalf("startup left an owned deleting tombstone, want 0, got %d", n)
	}
	if got := mustListStaged(t, svc2, repo, actor); len(got) != 0 {
		t.Fatalf("startup resurrected a publishable row, got %+v", got)
	}
	if _, err := svc2.ClaimStagedForPublish(context.Background(), repo, actor, "op-new", []string{digest}); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("startup must never convert an owned tombstone back to claimable, got %v", err)
	}
}
