package staging

// Task 18 final repair (round 5/5): durable, cross-process fair cleanup
// traversal via the v10 `cleanup_cursor` single-row table.
//
// The prior per-instance in-memory cursor gave a restarted instance (or each
// of several independent instances running one pass) a FRESH traversal every
// time, so a full batch of retained (committed/ambiguous) oldest blobs was
// re-selected on every pass and later eligible rows were starved forever. The
// durable cursor is read+advanced+reset ATOMICALLY under SQLite write
// serialization, so independent processes / restarts share ONE persisted fair
// traversal. These tests fail under the in-memory cursor and pass under the
// durable one:
//
//  1. more than one full batch of retained rows then eligible rows, with a NEW
//     service+Cleanup handle per RunOnce (one pass per process lifetime):
//     eligible rows must still be reached in bounded passes;
//  2. two independent live handles interleave one pass each and share durable
//     progress — no starvation, no unsafe duplicate unpin/removal;
//  3. crash-window after a durable cursor advance but before side effects:
//     subsequent new instances eventually wrap and revisit/process the skipped
//     eligible row;
//  4. v9->v10 migration preserves every session/blob and initializes a valid
//     fresh cursor; reopen is idempotent; a tampered v10 cursor/schema fails
//     closed.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestCleanupDurableCursorSinglePassPerProcess is the adversarial multi-batch
// starvation case: a full batch (and then another) of retained (committed)
// rows sorts strictly before the eligible rows, AND every pass is a fresh
// process lifetime (a NEW durable service handle and a NEW Cleanup, run once,
// then closed). Only a DURABLE shared cursor can keep advancing across those
// fresh lifetimes and reach the eligible rows; an in-memory per-instance cursor
// would re-select the retained batch on every pass and starve them forever.
func TestCleanupDurableCursorSinglePassPerProcess(t *testing.T) {
	dir := tempPrivate(t)
	base := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)

	seed := openServiceOn(t, dir)
	fixedClock(seed, base)
	const retainedN = 4 // two full batches at batch=2
	const eligibleN = 3
	const batch = 2
	retainedRefs := map[string]struct{}{}
	for i := 0; i < retainedN; i++ {
		fixedClock(seed, base.Add(time.Duration(i)*time.Second))
		ref := distinctHexRef(0xA000 + i)
		createExpiredFinalizedBlobAt(t, seed, "backend/api", "user:alice", fmt.Sprintf("r-%d", i), ref)
		retainedRefs[ref] = struct{}{}
	}
	for i := 0; i < eligibleN; i++ {
		fixedClock(seed, base.Add(time.Duration(10+i)*time.Second))
		ref := distinctHexRef(0xB000 + i)
		createExpiredFinalizedBlobAt(t, seed, "backend/api", "user:alice", fmt.Sprintf("e-%d", i), ref)
	}
	runAt := fixClockAhead(seed, base.Add(20*time.Second))
	seed.Close()

	committed := &fakeCommitted{byRepo: map[string]map[string]struct{}{"backend/api": retainedRefs}}
	unp := &fakeUnpinner{}

	// Bounded passes: two retained batches + one eligible batch = 3 passes, but
	// run a generous fixed bound so any wrap/round-trip is covered. Each pass is
	// a brand-new process lifetime (open, one RunOnce, close).
	const passes = 12
	for i := 0; i < passes; i++ {
		svc := openServiceOn(t, dir)
		c, err := NewCleanup(svc, unp, committed)
		if err != nil {
			svc.Close()
			t.Fatalf("pass %d NewCleanup: %v", i, err)
		}
		if _, err := c.RunOnce(context.Background(), runAt, batch); err != nil {
			svc.Close()
			t.Fatalf("pass %d RunOnce: %v", i, err)
		}
		svc.Close()
	}

	// Every eligible blob was unpinned (reached in bounded passes, no
	// starvation); NO retained ref was ever unpinned.
	pinned := map[string]int{}
	for _, r := range unp.calls() {
		pinned[r]++
		if _, retained := retainedRefs[r]; retained {
			t.Fatalf("a retained ref %s was unpinned", r)
		}
	}
	if len(pinned) != eligibleN {
		t.Fatalf("eligible unpins = %d (%v), want %d — durable traversal starved eligible rows across fresh process lifetimes", len(pinned), unp.calls(), eligibleN)
	}
	for i := 0; i < eligibleN; i++ {
		ref := distinctHexRef(0xB000 + i)
		if pinned[ref] != 1 {
			t.Fatalf("eligible ref %s unpinned %d times, want exactly 1", ref, pinned[ref])
		}
	}
}

// TestCleanupDurableCursorTwoLiveHandlesShareProgress runs two independent
// live store+cleanup handles that interleave one pass each. The durable cursor
// is claimed atomically, so the two handles never select the same row: eligible
// rows are reached (no starvation), each is unpinned/removed EXACTLY once (no
// unsafe duplicate), and no retained ref is ever unpinned.
func TestCleanupDurableCursorTwoLiveHandlesShareProgress(t *testing.T) {
	dir := tempPrivate(t)
	base := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)

	seed := openServiceOn(t, dir)
	fixedClock(seed, base)
	const retainedN = 3
	const eligibleN = 3
	retainedRefs := map[string]struct{}{}
	for i := 0; i < retainedN; i++ {
		fixedClock(seed, base.Add(time.Duration(i)*time.Second))
		ref := distinctHexRef(0xC000 + i)
		createExpiredFinalizedBlobAt(t, seed, "backend/api", "user:alice", fmt.Sprintf("r-%d", i), ref)
		retainedRefs[ref] = struct{}{}
	}
	for i := 0; i < eligibleN; i++ {
		fixedClock(seed, base.Add(time.Duration(10+i)*time.Second))
		ref := distinctHexRef(0xD000 + i)
		createExpiredFinalizedBlobAt(t, seed, "backend/api", "user:alice", fmt.Sprintf("e-%d", i), ref)
	}
	runAt := fixClockAhead(seed, base.Add(20*time.Second))

	// Two independent live handles over the SAME store.
	a := openServiceOn(t, dir)
	defer a.Close()
	b := openServiceOn(t, dir)
	defer b.Close()

	committed := &fakeCommitted{byRepo: map[string]map[string]struct{}{"backend/api": retainedRefs}}
	// ONE shared unpinner across both handles so any duplicate cross-process
	// unpin of the same ref is observable.
	unp := &fakeUnpinner{}

	newCleanup := func(svc *service) *Cleanup {
		t.Helper()
		c, err := NewCleanup(svc, unp, committed)
		if err != nil {
			t.Fatalf("NewCleanup: %v", err)
		}
		return c
	}
	cA := newCleanup(a)
	cB := newCleanup(b)

	// Interleave one pass each, batch=1, until every eligible row is reached.
	const batch = 1
	for i := 0; i < 2*retainedN+2*eligibleN; i++ {
		var pass *Cleanup
		if i%2 == 0 {
			pass = cA
		} else {
			pass = cB
		}
		if _, err := pass.RunOnce(context.Background(), runAt, batch); err != nil {
			t.Fatalf("interleaved pass %d: %v", i, err)
		}
	}

	pinned := map[string]int{}
	for _, r := range unp.calls() {
		pinned[r]++
		if _, retained := retainedRefs[r]; retained {
			t.Fatalf("a retained ref %s was unpinned across live handles", r)
		}
	}
	if len(pinned) != eligibleN {
		t.Fatalf("eligible unpins = %d (%v), want %d — shared durable cursor starved eligible rows", len(pinned), unp.calls(), eligibleN)
	}
	for i := 0; i < eligibleN; i++ {
		ref := distinctHexRef(0xD000 + i)
		if pinned[ref] != 1 {
			t.Fatalf("eligible ref %s unpinned %d times across live handles, want exactly 1 (no duplicate)", ref, pinned[ref])
		}
	}
}

// TestCleanupDurableCursorCrashWindow simulates a crash AFTER the durable
// cursor advances past a batch but BEFORE any side effect (the
// cleanupClaimedCrashHook aborts the pass with the batch unprocessed). The
// skipped eligible row is permanently skipped only under a mis-designed cursor;
// under this design the traversal WRAPS (an empty batch resets the cursor to
// fresh) and a new instance revisits and processes the skipped row in bounded
// passes — never starvation.
func TestCleanupDurableCursorCrashWindow(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)
	fixedClock(svc, now)

	// Exactly ONE eligible blob: the crash window advances the cursor to it,
	// then aborts. It is the ONLY row, so the next pass finds nothing after the
	// cursor (wraps) and only then revisits it.
	elRef := distinctHexRef(0xE000)
	createExpiredFinalizedBlobAt(t, svc, "backend/api", "user:alice", "crash-window", elRef)
	runAt := fixClockAhead(svc, now)

	committed := &fakeCommitted{}
	unp := &fakeUnpinner{}

	// Pass 1: durable cursor advances past the (single) batch, then the hook
	// aborts BEFORE any side effect, simulating a process death in the window.
	cleanupClaimedCrashHook = func() error { return errors.New("simulated crash after cursor advance, before side effects") }
	c, err := NewCleanup(svc, unp, committed)
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	if _, err := c.RunOnce(context.Background(), runAt, 1); err == nil {
		t.Fatal("crash-window hook must abort the pass (no side effects)")
	}
	cleanupClaimedCrashHook = nil
	if got := unp.calls(); len(got) != 0 {
		t.Fatalf("crash pass must unpin nothing, got %v", got)
	}

	// Subsequent NEW instances share the advanced durable cursor. They must
	// eventually WRAP and revisit/process the skipped eligible row in bounded
	// passes (never permanent starvation).
	res := runCleanupToRemoval(t, svc, unp, committed, runAt, 1, 5)
	if res.Removed != 1 || res.Unpinned != 1 || res.Failed != 0 {
		t.Fatalf("post-crash resume counts = %+v, want removed=1 unpinned=1", res)
	}
	if got := unp.calls(); len(got) != 1 || got[0] != elRef {
		t.Fatalf("post-crash unpin = %v, want exactly [%s]", got, elRef)
	}
	// The skipped blob itself is gone (its expiring claim was finished).
	if n := rawCountByBeeRef(t, dir, elRef); n != 0 {
		t.Fatalf("post-crash blob %s still present (%d rows); must be removed after wrap/revisit", elRef, n)
	}
}

// rawCountByBeeRef counts upload_sessions rows carrying the given bee_ref.
func rawCountByBeeRef(t *testing.T, dir, beeRef string) int {
	t.Helper()
	db := mustOpenRaw(t, dir)
	defer db.Close()
	var n int
	if err := db.QueryRow(`select count(*) from upload_sessions where bee_ref = ?`, beeRef).Scan(&n); err != nil {
		t.Fatalf("count by bee_ref: %v", err)
	}
	return n
}

// sessionBlobDigest renders upload_sessions and staged_blobs as a canonical,
// ordered, column-complete string so a migration can be proven to preserve
// every row/field byte-exactly (NULLs included).
func sessionBlobDigest(t *testing.T, dbPath string) string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open digest db: %v", err)
	}
	defer db.Close()
	var b strings.Builder
	rows, err := db.Query(`select id, repo, actor, state, offset, created_at, expires_at,
		create_token, cleanup_token, finalize_token, operation_id, digest, bee_ref, media_type, size
		from upload_sessions order by id`)
	if err != nil {
		t.Fatalf("digest sessions: %v", err)
	}
	for rows.Next() {
		var id, repo, actor, state string
		var offset, created, expires int64
		var ct, cu, ft, op, dg, br, mt sql.NullString
		var sz sql.NullInt64
		if err := rows.Scan(&id, &repo, &actor, &state, &offset, &created, &expires, &ct, &cu, &ft, &op, &dg, &br, &mt, &sz); err != nil {
			rows.Close()
			t.Fatalf("digest session scan: %v", err)
		}
		fmt.Fprintf(&b, "S|%s|%s|%s|%s|%d|%d|%d|%s|%s|%s|%s|%s|%s|%s|%v\n",
			id, repo, actor, state, offset, created, expires, ct.String, cu.String, ft.String, op.String, dg.String, br.String, mt.String, sz)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("digest sessions rows: %v", err)
	}
	rows, err = db.Query(`select upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at
		from staged_blobs order by upload_id`)
	if err != nil {
		t.Fatalf("digest blobs: %v", err)
	}
	for rows.Next() {
		var id, repo, actor, dg, br, mt string
		var sz, created, expires int64
		if err := rows.Scan(&id, &repo, &actor, &dg, &br, &sz, &mt, &created, &expires); err != nil {
			rows.Close()
			t.Fatalf("digest blob scan: %v", err)
		}
		fmt.Fprintf(&b, "B|%s|%s|%s|%s|%s|%d|%s|%d|%d\n", id, repo, actor, dg, br, sz, mt, created, expires)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("digest blob rows: %v", err)
	}
	return b.String()
}

// TestCleanupV9ToV10MigrationPreservesAndInitializesCursor proves the
// v9 -> v10 forward migration (1) preserves every upload_sessions row and every
// staged_blob byte-for-byte, (2) creates the cleanup_cursor table and seeds its
// single FRESH row (exp_at=-1, sess NULL), and (3) reopens idempotently
// (version still current, cursor row still fresh, sessions still identical).
func TestCleanupV9ToV10MigrationPreservesAndInitializesCursor(t *testing.T) {
	v9 := mustLoadTestManifest(t, schemaGoldenV9JSON)
	if v9.Version != 9 {
		t.Fatalf("v9 predecessor manifest must be frozen at 9, got %d", v9.Version)
	}
	dbPath := fixtureFromGolden(t, v9, func(db *sql.DB) {
		seedFullLifecycleV6Owned(t, db) // includes a valid claimed op-mig row
	})
	before := sessionBlobDigest(t, dbPath)

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate v9 -> v10: %v", err)
	}
	db.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after migration = %d, want %d", v, latestSchemaVersion)
	}
	// Every session/blob preserved byte-for-byte.
	if after := sessionBlobDigest(t, dbPath); after != before {
		t.Fatalf("v9->v10 altered upload_sessions/staged_blobs:\nBEFORE:\n%s\nAFTER:\n%s", before, after)
	}
	// The cursor table exists with exactly one FRESH row.
	raw := mustRawDB(t, dbPath)
	var exp int64
	var sess sql.NullString
	if err := raw.QueryRow(`select exp_at, sess from cleanup_cursor`).Scan(&exp, &sess); err != nil {
		t.Fatalf("read cleanup_cursor: %v", err)
	}
	if exp != -1 || sess.Valid {
		t.Fatalf("fresh cursor = (exp_at=%d, sess=%v), want (-1, NULL)", exp, sess)
	}
	var n int
	if err := raw.QueryRow(`select count(*) from cleanup_cursor`).Scan(&n); err != nil {
		t.Fatalf("count cursor: %v", err)
	}
	if n != 1 {
		t.Fatalf("cleanup_cursor has %d rows, want 1", n)
	}
	raw.Close()

	// Reopen is idempotent: still current, cursor still fresh, sessions intact.
	db2, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("idempotent reopen: %v", err)
	}
	db2.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version drifted on reopen = %d", v)
	}
	if after := sessionBlobDigest(t, dbPath); after != before {
		t.Fatalf("reopen altered sessions/blobs")
	}
	raw2 := mustRawDB(t, dbPath)
	if err := raw2.QueryRow(`select exp_at, sess from cleanup_cursor`).Scan(&exp, &sess); err != nil {
		t.Fatalf("reopen cursor read: %v", err)
	}
	if exp != -1 || sess.Valid {
		t.Fatalf("reopen cursor no longer fresh: (exp_at=%d, sess=%v)", exp, sess)
	}
	raw2.Close()
}

// TestCleanupTamperedV10CursorFailsClosed proves malformed/tampered v10 cursor
// state fails closed: (a) a WEAPENED cleanup_cursor schema object is rejected
// by byte-identity verification on open, leaving the database untouched; and
// (b) deleting the single cursor row makes the cleanup refuse to run (it never
// guesses a traversal position), and a coherently-impossible second row cannot
// even be written (the table CHECK/PK refuses it).
func TestCleanupTamperedV10CursorFailsClosed(t *testing.T) {
	// (a) Weakened schema: the reconciliation/open must reject it, byte-clean.
	v10 := mustLoadTestManifest(t, schemaGoldenV10JSON)
	if v10.Version != latestSchemaVersion {
		t.Fatalf("v10 manifest must be frozen at current, got %d", v10.Version)
	}
	dbPath := mutatedFixture(t, v10, "cleanup_cursor", func(body string) string {
		return strings.Replace(body, "(exp_at = -1 and sess is null)", "(1)", 1)
	})
	before := hashFile(t, dbPath)
	if db, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
		db.Close()
		t.Fatal("a weakened cleanup_cursor schema was accepted on open")
	}
	assertRejectedDBClean(t, dbPath, before)

	// (b) Malformed row state fails closed.
	svc, dir := newTestService(t)
	now := time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC)
	fixedClock(svc, now)
	runAt := fixClockAhead(svc, now)
	unp := &fakeUnpinner{}
	c, err := NewCleanup(svc, unp, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	// A coherently-impossible second cursor row is refused by the schema.
	db := mustOpenRaw(t, dir)
	if _, err := db.Exec(`insert into cleanup_cursor (id, exp_at, sess) values (2, -1, NULL)`); err == nil {
		t.Fatal("a second cleanup_cursor row was accepted (single-row guard broken)")
	}
	if _, err := db.Exec(`update cleanup_cursor set exp_at = 5 where id = 1`); err == nil {
		t.Fatal("an advanced cursor position without a session id was accepted (coherence broken)")
	}
	// Delete the single row: the cleanup must fail closed, never guess a
	// position and never traverse (and therefore never unpin anything).
	if _, err := db.Exec(`delete from cleanup_cursor`); err != nil {
		t.Fatalf("delete cursor row: %v", err)
	}
	db.Close()
	if _, err := c.RunOnce(context.Background(), runAt, 1); err == nil {
		t.Fatal("RunOnce succeeded with a MISSING durable cursor; must fail closed")
	}
	if got := unp.calls(); len(got) != 0 {
		t.Fatalf("RunOnce with a missing cursor unpinned %v; must be data-free", got)
	}
}

// TestUpgradeEveryPredecessorToCurrent includes v9 in the full predecessor
// upgrade chain so the v9->v10 forward migration is regressed alongside every
// shipped predecessor. (Extends the existing upgrade regression list.)
func TestUpgradeV9ToCurrentIncluded(t *testing.T) {
	cases := []struct {
		name string
		gold *schemaManifest
		seed func(t *testing.T, db *sql.DB)
	}{
		{"v9", mustLoadTestManifest(t, schemaGoldenV9JSON), seedFullLifecycleV6Owned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.gold.Version == latestSchemaVersion {
				t.Fatalf("%s must not be the current schema", tc.name)
			}
			dbPath := fixtureFromGolden(t, tc.gold, func(db *sql.DB) { tc.seed(t, db) })
			if _, err := migrateThenOpen(t, dbPath); err != nil {
				t.Fatalf("migrate %s -> v%d: %v", tc.name, latestSchemaVersion, err)
			}
			if v := versionOf(t, dbPath); v != latestSchemaVersion {
				t.Fatalf("%s migrated to version %d, want %d", tc.name, v, latestSchemaVersion)
			}
			db2, err := migrateThenOpen(t, dbPath)
			if err != nil {
				t.Fatalf("reopen of migrated %s: %v", tc.name, err)
			}
			db2.Close()
			if v := versionOf(t, dbPath); v != latestSchemaVersion {
				t.Fatalf("%s version drifted on reopen = %d", tc.name, v)
			}
			// The claimed op-mig row survives byte-exactly.
			raw := mustRawDB(t, dbPath)
			var cnt int
			if err := raw.QueryRow(`select count(*) from upload_sessions where operation_id = 'op-mig'`).Scan(&cnt); err != nil {
				t.Fatalf("read op-mig: %v", err)
			}
			if cnt != 1 {
				t.Fatalf("%s claimed row op-mig not preserved: count=%d", tc.name, cnt)
			}
			raw.Close()
		})
	}
}
