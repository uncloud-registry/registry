package staging

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Task 18 round-5 regressions (findings 1 & 2).
//
// Finding 1: bounded fair cleanup traversal. The candidate batch query used to
// reselect the SAME oldest LIMIT rows every pass; when those oldest rows are
// retained (published/ambiguous finalized blobs that keep their state/order),
// they monopolized every batch and eligible later rows were never examined.
// These tests prove repeated RunOnce advances past a full batch of retained
// rows and eventually cleans the eligible work, and that a restart / new
// handle cannot re-introduce permanent starvation.
//
// Finding 2: generic Service.Expire must be STRICTLY contentless-only. It must
// never directly delete a finalized blob (bypassing the authoritative cleanup's
// committed-state eligibility + Bee unpin) and must never steal a cleanup-owned
// `expiring` claim. These tests prove finalized and expiring rows survive a
// generic Expire and that the durable expiring claim's unpin provenance is
// preserved.
// ---------------------------------------------------------------------------

// distinctHexRef builds a distinct lowercase 64-hex ref from a numeric key.
func distinctHexRef(key int) string {
	return fmt.Sprintf("%064x", key)
}

// createExpiredFinalizedBlobAt creates an expired finalized blob whose
// created_at (hence expires_at) is anchored at `at` on svc's fixed clock.
func createExpiredFinalizedBlobAt(t *testing.T, svc *service, repo, actor, data, ref string) Session {
	t.Helper()
	s := mustCreate(t, svc, repo, actor)
	s = mustAppend(t, svc, s, data)
	dg, _, media, size := finalizeArgs(s)
	mustFinalize(t, svc, s, dg, ref, media, size)
	return s
}

// TestCleanupFairTraversalNoStarvation proves bounded fair traversal: a full
// batch of retained (committed) expired blobs sorts strictly BEFORE the
// eligible ones, yet repeated bounded RunOnce passes advance PAST the retained
// rows and eventually examine and clean the eligible work. Without a fair
// cursor the batch query would reselect the same oldest retained rows forever
// and the eligible rows would starve.
func TestCleanupFairTraversalNoStarvation(t *testing.T) {
	svc, _ := newTestService(t)
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, base)

	const retainedN = 3
	const eligibleN = 3
	const batch = retainedN // one batch is exactly the retained set

	// Retained (committed) blobs come FIRST with strictly earlier expires_at so
	// they always sort before the eligible blobs in the (expires_at, id)
	// candidate order — the exact starvation trigger.
	retainedRefs := map[string]Session{}
	for i := 0; i < retainedN; i++ {
		fixedClock(svc, base.Add(time.Duration(i)*time.Second))
		ref := distinctHexRef(0x1000 + i)
		retainedRefs[ref] = createExpiredFinalizedBlobAt(t, svc, "backend/api", "user:alice", fmt.Sprintf("retained-%d", i), ref)
	}
	// Eligible (uncommitted) blobs come LATER.
	var eligible []string
	for i := 0; i < eligibleN; i++ {
		fixedClock(svc, base.Add(time.Duration(10+i)*time.Second))
		ref := distinctHexRef(0x2000 + i)
		createExpiredFinalizedBlobAt(t, svc, "backend/api", "user:alice", fmt.Sprintf("eligible-%d", i), ref)
		eligible = append(eligible, ref)
	}
	runAt := fixClockAhead(svc, base.Add(time.Duration(20)*time.Second))

	committedRefs := map[string]struct{}{}
	for ref := range retainedRefs {
		committedRefs[ref] = struct{}{}
	}
	unp := &fakeUnpinner{}
	c, err := NewCleanup(svc, unp, &fakeCommitted{byRepo: map[string]map[string]struct{}{
		"backend/api": committedRefs,
	}})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}

	// Far more passes than retained+batch proves a fair cursor MUST have
	// advanced past the retained set and examined the eligible blobs.
	const passes = 20
	for i := 0; i < passes; i++ {
		if _, err := c.RunOnce(context.Background(), runAt, batch); err != nil {
			t.Fatalf("RunOnce pass %d: %v", i, err)
		}
	}

	// Every eligible blob is unpinned (and removed); NO retained ref is ever
	// unpinned.
	unpinned := unp.calls()
	if len(unpinned) != eligibleN {
		t.Fatalf("eligible unpins = %d (%v), want %d", len(unpinned), unpinned, eligibleN)
	}
	for _, r := range unpinned {
		if _, retained := retainedRefs[r]; retained {
			t.Fatalf("a retained ref %s was unpinned", r)
		}
	}
	pinned := map[string]struct{}{}
	for _, r := range unpinned {
		pinned[r] = struct{}{}
	}
	for _, r := range eligible {
		if _, ok := pinned[r]; !ok {
			t.Fatalf("eligible ref %s was never unpinned (starvation)", r)
		}
	}
	// Retained blobs survive untouched and still finalized. Status filters by
	// expiry, so rewind the clock before asserting the row survived.
	ctx := context.Background()
	fixedClock(svc, base)
	for ref, s := range retainedRefs {
		st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor)
		if err != nil {
			t.Fatalf("retained blob %s must survive, Status err=%v", ref, err)
		}
		if st.State != StateFinalized || st.BeeRef != ref {
			t.Fatalf("retained blob %s mutated: state=%q ref=%q", ref, st.State, st.BeeRef)
		}
	}
}

// TestCleanupFairTraversalSurvivesRestart proves a restart / brand-new
// independent handle cannot re-introduce permanent starvation: process A
// advances past a full batch of retained rows and cleans eligible work; a
// restart (fresh in-memory cursor) still converges to cleaning the eligible
// rows without ever unpinning a retained ref.
func TestCleanupFairTraversalSurvivesRestart(t *testing.T) {
	dir := tempPrivate(t)
	base := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

	svc1 := openServiceOn(t, dir)
	fixedClock(svc1, base)
	const retainedN = 3
	const eligibleN = 3
	retainedRefs := map[string]struct{}{}
	for i := 0; i < retainedN; i++ {
		fixedClock(svc1, base.Add(time.Duration(i)*time.Second))
		ref := distinctHexRef(0x3000 + i)
		createExpiredFinalizedBlobAt(t, svc1, "backend/api", "user:alice", fmt.Sprintf("r-%d", i), ref)
		retainedRefs[ref] = struct{}{}
	}
	for i := 0; i < eligibleN; i++ {
		fixedClock(svc1, base.Add(time.Duration(10+i)*time.Second))
		ref := distinctHexRef(0x4000 + i)
		createExpiredFinalizedBlobAt(t, svc1, "backend/api", "user:alice", fmt.Sprintf("e-%d", i), ref)
	}
	runAt := fixClockAhead(svc1, base.Add(time.Duration(20)*time.Second))

	committed := &fakeCommitted{byRepo: map[string]map[string]struct{}{"backend/api": retainedRefs}}

	// Process A runs ONE pass (batch == the retained count): it examines the
	// full retained set and advances its cursor PAST them, but does not yet
	// reach the eligible rows behind them (the starvation point on the old
	// code). Its cursor progress proves A alone would clean the eligible work.
	unpA := &fakeUnpinner{}
	c1, _ := NewCleanup(svc1, unpA, committed)
	if _, err := c1.RunOnce(context.Background(), runAt, 3); err != nil {
		t.Fatalf("A pass: %v", err)
	}
	svc1.Close()

	// Restart: brand-new handle + cleanup with a FRESH in-memory cursor. It must
	// re-traverse (retained examined again, harmlessly), ADVANCE past them, and
	// converge to cleaning every eligible row — a restart cannot re-introduce
	// permanent starvation of the eligible work.
	svc2 := openServiceOn(t, dir)
	defer svc2.Close()
	fixedClock(svc2, runAt)
	unpB := &fakeUnpinner{}
	c2, _ := NewCleanup(svc2, unpB, committed)
	for i := 0; i < 20; i++ {
		if _, err := c2.RunOnce(context.Background(), runAt, 3); err != nil {
			t.Fatalf("B pass %d: %v", i, err)
		}
	}
	// Combined across A+B: every eligible blob cleaned; NO retained ref unpinned.
	all := append(unpA.calls(), unpB.calls()...)
	if len(all) != eligibleN {
		t.Fatalf("across restart eligible unpins = %d (%v), want %d", len(all), all, eligibleN)
	}
	for _, r := range all {
		if _, retained := retainedRefs[r]; retained {
			t.Fatalf("restart unpinned a retained ref %s", r)
		}
	}
}

// TestExpireIsContentlessOnlyKeepsFinalizedAndExpiring proves generic
// Service.Expire is STRICTLY contentless-only: it never directly deletes a
// finalized blob (which would bypass the cleanup's committed-state eligibility
// and its Bee unpin) and never steals a cleanup-owned `expiring` claim.
func TestExpireIsContentlessOnlyKeepsFinalizedAndExpiring(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)

	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "blob-bytes")
	dg, ref, media, size := finalizeArgs(s)
	mustFinalize(t, svc, s, dg, ref, media, size)
	runAt := fixClockAhead(svc, now)

	// A generic Expire over an expired finalized blob must remove NOTHING: the
	// finalized blob is content-bearing and cleanup owns its eligibility.
	n, err := svc.Expire(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("Expire finalized: %v", err)
	}
	if n != 0 {
		t.Fatalf("generic Expire removed %d finalized blobs (bypasses cleanup unpin), want 0", n)
	}
	fixedClock(svc, now)
	st, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("finalized blob must survive generic Expire, Status err=%v", err)
	}
	if st.State != StateFinalized || st.BeeRef != ref {
		t.Fatalf("finalized blob mutated by Expire: state=%q ref=%q", st.State, st.BeeRef)
	}

	// Now claim it to `expiring` (cleanup-owned) and prove a generic Expire does
	// not steal the claim or remove the row.
	runAt2 := fixClockAhead(svc, now)
	if err := svc.claimExpiring(context.Background(), s.ID, &cleanupCandidate{}); err != nil {
		t.Fatalf("claim expiring: %v", err)
	}
	if st := rawState(t, dir, s.ID); st != "expiring" {
		t.Fatalf("pre-Expire state = %q, want expiring", st)
	}
	n2, err := svc.Expire(context.Background(), runAt2, 10)
	if err != nil {
		t.Fatalf("Expire expiring: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("generic Expire stole %d cleanup-owned expiring rows, want 0", n2)
	}
	if st := rawState(t, dir, s.ID); st != "expiring" {
		t.Fatalf("expiring claim stolen by Expire: state=%q", st)
	}

	// The cleanup can STILL resume the expiring row and unpins exactly once —
	// no unpin provenance is lost.
	unp := &fakeUnpinner{}
	c, _ := NewCleanup(svc, unp, &fakeCommitted{})
	res, err := c.RunOnce(context.Background(), runAt2, 10)
	if err != nil {
		t.Fatalf("cleanup resume after Expire: %v", err)
	}
	if res.Removed != 1 || res.Unpinned != 1 || res.Failed != 0 {
		t.Fatalf("cleanup resume counts = %+v, want removed=1 unpinned=1", res)
	}
	if got := unp.calls(); len(got) != 1 || got[0] != ref {
		t.Fatalf("cleanup resume unpin = %v, want exactly [%s]", got, ref)
	}
}

// TestExpireConcurrentWithCleanupDoesNotSteal forces the expiring-vs-Expire
// ownership interleaving: a generic Expire and the cleanup's own reaper race
// over the SAME expired finalized blob. The generic Expire must never delete
// content-bearing rows (its count is always 0), so the blob is removed at most
// once — via the cleanup's authoritative unpin — with no claim steal and no
// provenance loss.
func TestExpireConcurrentWithCleanupDoesNotSteal(t *testing.T) {
	svc, _ := newTestService(t)
	now := time.Date(2026, 1, 2, 4, 5, 6, 0, time.UTC)
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "race-bytes")
	dg, _, media, size := finalizeArgs(s)
	ref := distinctHexRef(0xF1)
	mustFinalize(t, svc, s, dg, ref, media, size)
	runAt := fixClockAhead(svc, now)

	unp := &fakeUnpinner{}
	c, err := NewCleanup(svc, unp, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}

	var expN int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		expN, _ = svc.Expire(context.Background(), runAt, 10)
	}()
	go func() {
		defer wg.Done()
		_, _ = c.RunOnce(context.Background(), runAt, 10)
	}()
	wg.Wait()

	if expN != 0 {
		t.Fatalf("generic Expire removed %d content-bearing rows concurrently (claim steal), want 0", expN)
	}
	// Removed exactly once, and ONLY via the cleanup's unpin.
	if got := unp.calls(); len(got) != 1 {
		t.Fatalf("unpin calls = %v, want exactly 1 (via cleanup, not a bypassing Expire)", got)
	}
	if _, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("blob must be removed after concurrent cleanup, Status err=%v", err)
	}
}
