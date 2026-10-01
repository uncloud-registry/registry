package staging

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Task 18 pre-review safety corrections.
//
// These prove the cleanup ownership model: cleanup never unpins a generic
// deleting tombstone, a durable `expiring` claim survives restart/independent
// handles, committed state revalidated immediately before the unpin retains a
// blob a publication committed in between, publications can only ever see
// genuinely finalized non-expired non-expiring blobs, and nil committed is
// rejected so an exportable constructor cannot silently unpin everything.
// ---------------------------------------------------------------------------

// openServiceOn builds a durable service over shared files without an
// auto-close cleanup, so a test can Close then reopen (restart) or open a
// second independent handle over the same store.
func openServiceOn(t *testing.T, dir string) *service {
	t.Helper()
	svc, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("NewService on shared dir: %v cause=%v", err, causeOf(err))
	}
	return svc
}

// scriptedCommitted returns a different committed-ref map per call, so a test
// can force a publication to become committed BETWEEN the claim-time check and
// the pre-unpin revalidation.
type scriptedCommitted struct {
	mu    sync.Mutex
	steps []map[string]struct{}
	call  int
}

func (s *scriptedCommitted) CommittedRefs(_ context.Context, _ string) (map[string]struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.call >= len(s.steps) {
		i := len(s.steps) - 1
		if i < 0 {
			return map[string]struct{}{}, nil
		}
		return s.steps[i], nil
	}
	m := s.steps[s.call]
	s.call++
	return m, nil
}

// rawState reads a session's durable state via raw SQL (against the service's
// own database file), so tests can assert the persisted lifecycle state.
func rawState(t *testing.T, dir, id string) string {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	var state string
	if err := db.QueryRow(`select state from upload_sessions where id = ?`, id).Scan(&state); err != nil {
		t.Fatalf("raw state query: %v", err)
	}
	return state
}

// TestCleanupGenericDeletingWithRefNeverUnpinned proves the root defect:
// a pre-existing `deleting` tombstone that still carries a bee_ref (e.g. a
// generic Delete/Expire of a finalized blob) is NEVER inferred cleanup-
// eligible. The cleanup must neither unpin it (the content may be published)
// nor remove it (the authenticated Delete/startup path owns it).
func TestCleanupGenericDeletingWithRefNeverUnpinned(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "blob-bytes")
	dg, ref, media, size := finalizeArgs(s)
	mustFinalize(t, svc, s, dg, ref, media, size)
	runAt := fixClockAhead(svc, now)

	// Simulate a generic Delete that crashed: the row is tombstoned to
	// `deleting` (a transition the state trigger allows for any live row)
	// while still carrying its finalized bee_ref, and the removal never ran.
	db := mustOpenRaw(t, dir)
	if _, err := db.Exec(`update upload_sessions set state = 'deleting' where id = ?`, s.ID); err != nil {
		t.Fatalf("simulate generic delete tombstone: %v", err)
	}
	db.Close()

	unp := &fakeUnpinner{}
	c, err := NewCleanup(svc, unp, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// The deleting-with-ref row is not even a cleanup candidate (batch refuses
	// it), so it is never unpinned and never removed.
	if res.Examined != 0 || res.Expired != 0 || res.Removed != 0 || res.Unpinned != 0 {
		t.Fatalf("generic deleting-with-ref must not be cleaned, counts = %+v", res)
	}
	if len(unp.calls()) != 0 {
		t.Fatalf("generic deleting-with-ref must never be unpinned, got %v", unp.calls())
	}
	if st := rawState(t, dir, s.ID); st != "deleting" {
		t.Fatalf("deleting-with-ref state = %q, want deleting (untouched)", st)
	}
}

// TestCleanupDeletingWithNullRefIsFinished proves contentless deleting
// tombstones (cleanup's own active-deletion residue, or a generic contentless
// Delete) are safe to finish: there is no content to unpin.
func TestCleanupDeletingWithNullRefIsFinished(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "blob-bytes")
	runAt := fixClockAhead(svc, now)

	db := mustOpenRaw(t, dir)
	if _, err := db.Exec(`update upload_sessions set state = 'deleting' where id = ?`, s.ID); err != nil {
		t.Fatalf("tombstone contentless session: %v", err)
	}
	db.Close()

	c, err := NewCleanup(svc, &fakeUnpinner{}, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Examined != 1 || res.Removed != 1 || res.Unpinned != 0 || res.Failed != 0 {
		t.Fatalf("contentless deleting finish counts = %+v, want removed=1 unpinned=0", res)
	}
	if _, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("contentless deleting row must be removed, Status err=%v", err)
	}
}

// TestCleanupCommittedAfterClaimRetains tests the durable revalidation: a blob
// that is eligible at claim time (finalized -> expiring) but whose ref becomes
// committed state BEFORE the pre-unpin revalidation is RETAINED and never
// unpinned — the exact commit-after-check window the initial read-check missed.
func TestCleanupCommittedAfterClaimRetains(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "blob-bytes")
	dg, ref, media, size := finalizeArgs(s)
	mustFinalize(t, svc, s, dg, ref, media, size)
	runAt := fixClockAhead(svc, now)

	// First committed query (claim time) sees the ref absent (eligible); the
	// second (immediately before the unpin) sees it committed — a publication
	// committed between the read-check and the unpin.
	scripted := &scriptedCommitted{steps: []map[string]struct{}{
		{},
		{ref: struct{}{}},
	}}
	unp := &fakeUnpinner{}
	c, err := NewCleanup(svc, unp, scripted)
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// The blob is claimed to expiring (durably), then RETAINED: never unpinned,
	// never removed, metadata kept.
	if res.Expired != 0 || res.Unpinned != 0 || res.Removed != 0 {
		t.Fatalf("commit-after-claim must retain, counts = %+v", res)
	}
	if len(unp.calls()) != 0 {
		t.Fatalf("commit-after-claim blob must never be unpinned, got %v", unp.calls())
	}
	if st := rawState(t, dir, s.ID); st != "expiring" {
		t.Fatalf("after commit-after-claim retention state = %q, want expiring", st)
	}
	// The staged blob metadata (incl. bee_ref) survives for a later pass.
	db := mustOpenRaw(t, dir)
	var bee sql.NullString
	if err := db.QueryRow(`select bee_ref from upload_sessions where id=?`, s.ID).Scan(&bee); err != nil {
		t.Fatalf("bee_ref read: %v", err)
	}
	db.Close()
	if !bee.Valid || bee.String != ref {
		t.Fatalf("bee_ref lost after retention: %v", bee)
	}
}

// TestCleanupExpiringSurvivesRestartAndResumes proves a cleanup-owned expiring
// claim (the bee_ref retained) survives a full service restart over the same
// file-backed store and is resumed for an idempotent unpin + removal — even by
// a different, freshly-opened service instance.
func TestCleanupExpiringSurvivesRestartAndResumes(t *testing.T) {
	dir := tempPrivate(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	svc1 := openServiceOn(t, dir)
	fixedClock(svc1, now)
	s := mustCreate(t, svc1, "backend/api", "user:alice")
	s = mustAppend(t, svc1, s, "blob-bytes")
	dg, ref, media, size := finalizeArgs(s)
	mustFinalize(t, svc1, s, dg, ref, media, size)
	runAt := fixClockAhead(svc1, now)

	// First service: unpin fails, leaving the blob durably expiring.
	failing := &fakeUnpinner{failErr: errors.New("bee unavailable"), failAfter: 0}
	c1, err := NewCleanup(svc1, failing, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup1: %v", err)
	}
	res1, err := c1.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("RunOnce1: %v", err)
	}
	if res1.Removed != 0 || res1.Failed != 1 || res1.Expired != 1 {
		t.Fatalf("pass1 counts = %+v, want expired=1 removed=0 failed=1", res1)
	}
	if st := rawState(t, dir, s.ID); st != "expiring" {
		t.Fatalf("post-failure state = %q, want expiring", st)
	}
	svc1.Close()

	// Restart with a NEW independent service handle over the same store.
	svc2 := openServiceOn(t, dir)
	defer svc2.Close()
	fixedClock(svc2, runAt)
	healthy := &fakeUnpinner{}
	// The durable cursor advanced past the row when the first pass's unpin
	// failed, and the new handle shares that persisted position (no fresh
	// re-traversal). runCleanupToRemoval lets the traversal WRAP (an empty pass
	// resets the cursor to fresh) and then re-examines and resumes the expiring
	// claim, failing if the wrap never comes.
	res2 := runCleanupToRemoval(t, svc2, healthy, &fakeCommitted{}, runAt, 10, 5)
	if res2.Removed != 1 || res2.Unpinned != 1 || res2.Failed != 0 {
		t.Fatalf("resume counts = %+v, want removed=1 unpinned=1", res2)
	}
	if got := healthy.calls(); len(got) != 1 || got[0] != ref {
		t.Fatalf("resume unpin calls = %v, want [%s]", got, ref)
	}
	if _, err := svc2.Status(context.Background(), s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("resumed blob must be removed, Status err=%v", err)
	}
}

// TestCleanupIndependentHandlesResume proves a second CONCURRENT independent
// service instance resumes (without double-unpin) a claim made by the first.
func TestCleanupIndependentHandlesResume(t *testing.T) {
	dir := tempPrivate(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	a := openServiceOn(t, dir)
	defer a.Close()
	fixedClock(a, now)
	s := mustCreate(t, a, "backend/api", "user:alice")
	s = mustAppend(t, a, s, "blob-bytes")
	dg, ref, media, size := finalizeArgs(s)
	mustFinalize(t, a, s, dg, ref, media, size)
	runAt := fixClockAhead(a, now)

	failing := &fakeUnpinner{failErr: errors.New("bee unavailable"), failAfter: 0}
	cA, _ := NewCleanup(a, failing, &fakeCommitted{})
	if res, _ := cA.RunOnce(context.Background(), runAt, 10); res.Failed != 1 {
		t.Fatalf("handle A pass failed=%d, want 1", res.Failed)
	}

	// Independent handle B over the same store resumes the single expiring claim
	// exactly once (idempotent). B shares the durable cursor A's pass advanced
	// (which is past the row), so B must let the traversal WRAP before it
	// re-examines and resumes the row; runCleanupToRemoval bounds those passes.
	b := openServiceOn(t, dir)
	defer b.Close()
	fixedClock(b, runAt)
	healthy := &fakeUnpinner{}
	r := runCleanupToRemoval(t, b, healthy, &fakeCommitted{}, runAt, 10, 5)
	if r.Removed != 1 || r.Unpinned != 1 || r.Failed != 0 {
		t.Fatalf("handle B resume counts = %+v, want removed=1 unpinned=1", r)
	}
	if got := healthy.calls(); len(got) != 1 || got[0] != ref {
		t.Fatalf("handle B resume unpin = %v, want exactly [%s]", got, ref)
	}
}

// TestCleanupCommittedNilRejected proves the exportable constructor fails
// closed: without an authoritative committed-state provider it refuses to
// build, so nil can never silently unpin every finalized ref.
func TestCleanupCommittedNilRejected(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := NewCleanup(svc, &fakeUnpinner{}, nil); err == nil {
		t.Fatal("NewCleanup with nil committed must be rejected")
	}
	if _, err := NewCleanup(svc, nil, &fakeCommitted{}); err == nil {
		t.Fatal("NewCleanup with nil unpinner must be rejected")
	}
	if _, err := NewCleanup(nil, &fakeUnpinner{}, &fakeCommitted{}); err == nil {
		t.Fatal("NewCleanup with a non-durable store must be rejected")
	}
}

// TestListFinalizedPublishabilityBoundary proves the publication input only
// ever exposes genuinely finalized, non-expired, non-tombstoned staged blobs.
func TestListFinalizedPublishabilityBoundary(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "blob-bytes")
	dg, ref, media, size := finalizeArgs(s)
	mustFinalize(t, svc, s, dg, ref, media, size)

	// A finalized, non-expired blob IS publishable.
	list, err := svc.ListFinalized(context.Background(), s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("ListFinalized: %v", err)
	}
	if len(list) != 1 || list[0].SwarmRef != ref {
		t.Fatalf("non-expired finalized blob must be publishable, got %+v", list)
	}

	// Once expired, the same blob is NOT publishable.
	fixClockAhead(svc, now)
	list, err = svc.ListFinalized(context.Background(), s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("ListFinalized expired: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expired blob must not be publishable, got %d", len(list))
	}

	// A cleanup-owned expiring claim is NOT publishable.
	fixedClock(svc, now)
	if err := svc.claimExpiring(context.Background(), s.ID, &cleanupCandidate{}); err != nil {
		t.Fatalf("claim expiring: %v", err)
	}
	list, err = svc.ListFinalized(context.Background(), s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("ListFinalized expiring: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expiring blob must not be publishable, got %d", len(list))
	}
	if st := rawState(t, dir, s.ID); st != "expiring" {
		t.Fatalf("state = %q, want expiring", st)
	}
}

// TestCleanupConcurrentIndependentInstancesConverge forces the vulnerable
// ownership interleavings with FILE-BACKED INDEPENDENT store instances: two
// cleanup reapers, each holding its own service handle over the SAME store,
// race to claim (expire) a batch of expired finalized blobs. The durable
// expiring claim serializes ownership (each blob is claimed by exactly one
// instance, and removed exactly once); unpins are idempotent so double-unpin
// is never a correctness hazard, and no unpin may reference a ref that did NOT
// belong to a removed eligible blob. Run under -race this also proves no data
// race across independent handles.
func TestCleanupConcurrentIndependentInstancesConverge(t *testing.T) {
	dir := tempPrivate(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	a := openServiceOn(t, dir)
	defer a.Close()
	fixedClock(a, now)
	const n = 6
	refs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		s := mustCreate(t, a, "backend/api", "user:alice")
		s = mustAppend(t, a, s, strings.Repeat("x", i+1))
		dg, _, media, size := finalizeArgs(s)
		// A distinct canonical (lowercase 64-hex) ref per blob so the test can
		// count EXACT unpins per eligible ref rather than sharing one symbolic
		// ref across every blob.
		ref := fmt.Sprintf("%064x", i+1)
		mustFinalize(t, a, s, dg, ref, media, size)
		refs = append(refs, ref)
	}
	runAt := fixClockAhead(a, now)

	unpA := &fakeUnpinner{}
	unpB := &fakeUnpinner{}
	cA, _ := NewCleanup(a, unpA, &fakeCommitted{})
	b := openServiceOn(t, dir)
	defer b.Close()
	fixedClock(b, runAt)
	cB, _ := NewCleanup(b, unpB, &fakeCommitted{})

	var mu sync.Mutex
	var resA, resB CleanupResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r, _ := cA.RunOnce(context.Background(), runAt, 100)
		mu.Lock()
		resA = r
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		r, _ := cB.RunOnce(context.Background(), runAt, 100)
		mu.Lock()
		resB = r
		mu.Unlock()
	}()
	wg.Wait()
	t.Logf("concurrent results: A=%+v B=%+v unpA=%d unpB=%d", resA, resB, len(unpA.calls()), len(unpB.calls()))

	// Every blob is durably removed.
	db := mustOpenRaw(t, dir)
	var remaining int
	if err := db.QueryRow(`select count(*) from upload_sessions`).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	db.Close()
	if remaining != 0 {
		t.Fatalf("concurrent cleanup left %d rows, want 0", remaining)
	}

	// Every unpin call references one of the eligible refs (never a foreign or
	// empty ref), and every eligible ref is unpinned at least once.
	calls := append(unpA.calls(), unpB.calls()...)
	want := make(map[string]struct{}, n)
	for _, r := range refs {
		want[r] = struct{}{}
	}
	seen := make(map[string]struct{})
	for _, c := range calls {
		if _, ok := want[c]; !ok {
			t.Fatalf("unpin referenced a non-eligible ref %q", c)
		}
		seen[c] = struct{}{}
	}
	if len(seen) != n {
		t.Fatalf("not every eligible ref was unpinned: got %d of %d", len(seen), n)
	}
}

func mustOpenRaw(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	return db
}

// TestCleanupResultCopy defends the scripted committed helper's behavior.
func TestCleanupScriptedStepsDistinct(t *testing.T) {
	r1 := "sha256:" + strings.Repeat("a", 64)
	sc := &scriptedCommitted{steps: []map[string]struct{}{
		{},
		{r1: struct{}{}},
	}}
	a, _ := sc.CommittedRefs(context.Background(), "repo")
	b, _ := sc.CommittedRefs(context.Background(), "repo")
	if len(a) != 0 || len(b) != 1 {
		t.Fatalf("scripted steps not distinct: %v %v", a, b)
	}
	if !reflect.DeepEqual(b, map[string]struct{}{r1: struct{}{}}) {
		t.Fatalf("step2 = %v", b)
	}
}
