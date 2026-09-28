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
	"math"
	"os"
	"path/filepath"
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

// TestCleanupV9ToV11MigrationPreservesAndInitializesCursor proves the
// v9 -> v11 forward migration (through the shared upgrade path) (1) preserves
// every upload_sessions row and every staged_blob byte-for-byte, (2) creates
// the cleanup_cursor table and seeds its single FRESH row (exp_at=NULL,
// sess=NULL, the v11 fresh sentinel distinct from every signed timestamp), and
// (3) reopens idempotently (version still current, cursor row still fresh,
// sessions still identical).
func TestCleanupV9ToV11MigrationPreservesAndInitializesCursor(t *testing.T) {
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
		t.Fatalf("migrate v9 -> v11: %v", err)
	}
	db.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after migration = %d, want %d", v, latestSchemaVersion)
	}
	// Every session/blob preserved byte-for-byte.
	if after := sessionBlobDigest(t, dbPath); after != before {
		t.Fatalf("v9->v11 altered upload_sessions/staged_blobs:\nBEFORE:\n%s\nAFTER:\n%s", before, after)
	}
	// The cursor table exists with exactly one FRESH row (NULL, NULL).
	raw := mustRawDB(t, dbPath)
	var exp sql.NullInt64
	var sess sql.NullString
	if err := raw.QueryRow(`select exp_at, sess from cleanup_cursor`).Scan(&exp, &sess); err != nil {
		t.Fatalf("read cleanup_cursor: %v", err)
	}
	if exp.Valid || sess.Valid {
		t.Fatalf("fresh cursor = (exp_at=%v, sess=%v), want (NULL, NULL)", exp, sess)
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
	if exp.Valid || sess.Valid {
		t.Fatalf("reopen cursor no longer fresh: (exp_at=%v, sess=%v)", exp, sess)
	}
	raw2.Close()
}

// TestCleanupTamperedV11CursorFailsClosed proves malformed/tampered current
// (v11) cursor state fails closed: (a) a WEAPENED cleanup_cursor schema object
// is rejected by byte-identity verification on open, leaving the database
// untouched; (b) a coherently-impossible cursor row — a NULL/non-NULL state
// mix, a mixed-null pair, a non-INTEGER exp_at, or a second row — is refused
// by the table CHECK/PK; and (c) deleting the single cursor row makes the
// cleanup refuse to run (it never guesses a traversal position).
func TestCleanupTamperedV11CursorFailsClosed(t *testing.T) {
	// (a) Weakened schema: the reconciliation/open must reject it, byte-clean.
	v11 := mustLoadTestManifest(t, schemaGoldenV11JSON)
	if v11.Version != latestSchemaVersion {
		t.Fatalf("v11 manifest must be frozen at current, got %d", v11.Version)
	}
	dbPath := mutatedFixture(t, v11, "cleanup_cursor", func(body string) string {
		return strings.Replace(body, "(exp_at is null and sess is null)", "(1)", 1)
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
	db := mustOpenRaw(t, dir)
	// A coherently-impossible second cursor row is refused (PK id=1).
	if _, err := db.Exec(`insert into cleanup_cursor (id, exp_at, sess) values (2, NULL, NULL)`); err == nil {
		t.Fatal("a second cleanup_cursor row was accepted (single-row guard broken)")
	}
	// A NULL/non-NULL mix (advanced exp_at with NULL sess) is refused.
	if _, err := db.Exec(`update cleanup_cursor set exp_at = 5 where id = 1`); err == nil {
		t.Fatal("an advanced cursor position without a session id was accepted (coherence broken)")
	}
	// A non-INTEGER exp_at is refused (affinity-free column + typeof guard).
	if _, err := db.Exec(`update cleanup_cursor set exp_at = '5', sess = '` + strings.Repeat("a", 64) + `' where id = 1`); err == nil {
		t.Fatal("a non-INTEGER exp_at was accepted (storage-class guard broken)")
	}
	// A malformed (non-hex) sess is refused.
	if _, err := db.Exec(`update cleanup_cursor set exp_at = 5, sess = '` + strings.Repeat("z", 64) + `' where id = 1`); err == nil {
		t.Fatal("a malformed session id was accepted (grammar guard broken)")
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

// TestUpgradeV9AndV10ToCurrentIncluded includes v9 and v10 in the full
// predecessor upgrade chain so the forward migrations to v11 are regressed
// alongside every shipped predecessor. (Extends the existing upgrade
// regression list.)
func TestUpgradeV9AndV10ToCurrentIncluded(t *testing.T) {
	cases := []struct {
		name string
		gold *schemaManifest
		seed func(t *testing.T, db *sql.DB)
	}{
		{"v9", mustLoadTestManifest(t, schemaGoldenV9JSON), seedFullLifecycleV6Owned},
		{"v10", mustLoadTestManifest(t, schemaGoldenV10JSON), seedFullLifecycleV10WithCursor},
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

// seedFullLifecycleV10WithCursor seeds the full lifecycle AND the single v10
// cleanup-cursor row a genuine v10 predecessor always carries: the fresh
// sentinel (exp_at = -1, sess NULL). A real v10-database cursor is never empty.
func seedFullLifecycleV10WithCursor(t *testing.T, db *sql.DB) {
	t.Helper()
	seedFullLifecycleV6Owned(t, db)
	if _, err := db.Exec(`insert into cleanup_cursor (id, exp_at, sess) values (1, -1, NULL)`); err != nil {
		t.Fatalf("seed v10 fresh cursor: %v", err)
	}
}

// TestCleanupV10ToV11MigrationPreservesAndMapsCursor proves the v10 -> v11
// forward migration (1) preserves every upload_sessions row and staged_blob
// byte-for-byte — including a row with negative (pre-epoch) expires_at — and
// (2) maps the v10 cursor row losslessly: fresh (-1, NULL) becomes v11 fresh
// (NULL, NULL), and a valid v10 ADVANCED cursor (exp_at >= 0, sess) is carried
// unchanged. It also proves that after migration a FRESH signed-domain cursor
// reaches and cleans the negative-expired row that a v10 cursor could never
// even have selected.
func TestCleanupV10ToV11MigrationPreservesAndMapsCursor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advEx   *int64 // nil = fresh, else advanced exp_at
		reaches bool   // whether cleanup must reach the negative row after migrate
	}{
		{"fresh", nil, true},
		{"advanced", int64ptr(5), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v10 := mustLoadTestManifest(t, schemaGoldenV10JSON)
			dbPath := fixtureFromGolden(t, v10, func(db *sql.DB) {
				// Only the negative-expired finalized blob (created=-5s,
				// expires=-4s, i.e. before the 1970 epoch) is seeded, so the
				// post-migration reachability count is decisive.
				seedRawFinalizedAt(t, db, strings.Repeat("1", 64), -5_000_000_000, -4_000_000_000, strings.Repeat("f", 64))
				if tc.advEx != nil {
					if _, err := db.Exec(`insert into cleanup_cursor (id, exp_at, sess) values (1, ?, ?)`, *tc.advEx, strings.Repeat("a", 64)); err != nil {
						t.Fatalf("seed advanced cursor: %v", err)
					}
				} else {
					if _, err := db.Exec(`insert into cleanup_cursor (id, exp_at, sess) values (1, -1, NULL)`); err != nil {
						t.Fatalf("seed fresh cursor: %v", err)
					}
				}
			})
			before := sessionBlobDigest(t, dbPath)

			db, err := migrateThenOpen(t, dbPath)
			if err != nil {
				t.Fatalf("migrate v10 -> v11: %v", err)
			}
			db.Close()
			if v := versionOf(t, dbPath); v != latestSchemaVersion {
				t.Fatalf("version after migration = %d, want %d", v, latestSchemaVersion)
			}
			if after := sessionBlobDigest(t, dbPath); after != before {
				t.Fatalf("v10->v11 altered upload_sessions/staged_blobs:\nBEFORE:\n%s\nAFTER:\n%s", before, after)
			}
			// The cursor row is mapped losslessly.
			raw := mustRawDB(t, dbPath)
			var ex sql.NullInt64
			var sess sql.NullString
			if err := raw.QueryRow(`select exp_at, sess from cleanup_cursor`).Scan(&ex, &sess); err != nil {
				t.Fatalf("read migrated cursor: %v", err)
			}
			if tc.advEx != nil {
				if !ex.Valid || ex.Int64 != *tc.advEx || sess.String != strings.Repeat("a", 64) {
					t.Fatalf("advanced cursor mapped wrongly: exp=%v sess=%q, want exp=%d sess=a…a", ex, sess.String, *tc.advEx)
				}
			} else if ex.Valid || sess.Valid {
				t.Fatalf("fresh cursor mapped wrongly: exp=%v sess=%q, want (NULL,NULL)", ex, sess.String)
			}
			raw.Close()

			// A FRESH migrated cursor must reach the negative-expired row; an
			// ADVANCED cursor at exp=5 sits past it (its expires=-4s < 5), so it
			// reaches nothing.
			spool := filepath.Join(filepath.Dir(dbPath), "spool")
			if err := os.Mkdir(spool, 0o700); err != nil {
				t.Fatalf("mkdir spool: %v", err)
			}
			// Startup reconciliation verifies every file-backed row against a
			// durable spool file at the committed offset. The seeded finalized
			// blob (offset 0) needs a matching empty backing file (a real
			// contentless-finalized row never had bytes to commit).
			if err := os.WriteFile(filepath.Join(spool, strings.Repeat("1", 64)), nil, 0o600); err != nil {
				t.Fatalf("seed backing file: %v", err)
			}
			svc, err := NewService(context.Background(), spool, dbPath)
			if err != nil {
				t.Fatalf("service over migrated db: %v", err)
			}
			unp := &fakeUnpinner{}
			c, err := NewCleanup(svc, unp, &fakeCommitted{})
			if err != nil {
				svc.Close()
				t.Fatalf("NewCleanup: %v", err)
			}
			if _, err := c.RunOnce(context.Background(), time.Unix(0, 0).UTC(), 10); err != nil {
				svc.Close()
				t.Fatalf("post-migration RunOnce: %v", err)
			}
			svc.Close()
			got := unp.calls()
			if tc.reaches {
				if len(got) != 1 || got[0] != strings.Repeat("f", 64) {
					t.Fatalf("post-migration negative-expired cleanup unpins = %v, want exactly [%s]", got, strings.Repeat("f", 64))
				}
			} else if len(got) != 0 {
				t.Fatalf("advanced-cursor post-migration unpins = %v, want 0 (negative row is before the advanced position)", got)
			}
		})
	}
}

// int64ptr returns a pointer to v (test helper).
func int64ptr(v int64) *int64 { return &v }

// seedRawFinalizedAt writes a finalized blob row (active -> staged_blob ->
// finalized) with explicit signed created/expires nanosecond timestamps,
// bypassing a host-time conversion so negative and boundary values are stored
// exactly. This is the only safe way to reach the signed domain edges SQLite
// supports without time.Time/UnixNano overflow mistakes.
func seedRawFinalizedAt(t *testing.T, db *sql.DB, id string, created, expires int64, beeRef string) {
	t.Helper()
	if expires <= created {
		t.Fatalf("seed requires expires(%d) > created(%d)", expires, created)
	}
	digest := "sha256:" + strings.Repeat("d", 64)
	if _, err := db.Exec(
		`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?,?,?, 'active', 0, ?, ?)`,
		id, seedRepo, seedActor, created, expires); err != nil {
		t.Fatalf("seed active row: %v", err)
	}
	if _, err := db.Exec(
		`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at)
		 values (?,?,?,?,?, 0, 'application/octet-stream', ?, ?)`,
		id, seedRepo, seedActor, digest, beeRef, created, expires); err != nil {
		t.Fatalf("seed staged blob: %v", err)
	}
	if _, err := db.Exec(
		`update upload_sessions set state='finalized', digest=?, bee_ref=?, media_type=?, size=0 where id=?`,
		digest, beeRef, "application/octet-stream", id); err != nil {
		t.Fatalf("seed finalize transition: %v", err)
	}
}

// TestCleanupSignedDomainNegativeExpiredReached proves the CURRENT v11 cleanup
// reaches and safely removes both a negative-expired finalized blob (unpinned)
// and a negative-expired contentless active session (removed, no unpin) — the
// schema-valid rows the v10 fresh sentinel (exp_at=-1) could never select.
// Rows are written with explicit negative nanosecond timestamps via raw SQL so
// the assertion is exact and independent of service TTL clock math.
func TestCleanupSignedDomainNegativeExpiredReached(t *testing.T) {
	svc, dir := newTestService(t)
	ref := distinctHexRef(0x5000)
	raw := mustOpenRaw(t, dir)
	// finalized blob: created=-6s expires=-5s
	seedRawFinalizedAt(t, raw, strings.Repeat("5", 64), -6_000_000_000, -5_000_000_000, ref)
	// contentless active session: created=-6s expires=-5s
	if _, err := raw.Exec(
		`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?,?,?, 'active', 0, ?, ?)`,
		strings.Repeat("6", 64), seedRepo, seedActor, -6_000_000_000, -5_000_000_000); err != nil {
		raw.Close()
		t.Fatalf("seed negative active session: %v", err)
	}
	raw.Close()

	unp := &fakeUnpinner{}
	c, err := NewCleanup(svc, unp, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	// now = epoch: both rows (expires=-5s) are expired.
	res, err := c.RunOnce(context.Background(), time.Unix(0, 0).UTC(), 10)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// Both removed: finalized blob unpinned once, active session removed with
	// no unpin.
	if res.Removed != 2 || res.Unpinned != 1 || res.Failed != 0 {
		t.Fatalf("signed-domain counts = %+v, want removed=2 unpinned=1 failed=0", res)
	}
	if got := unp.calls(); len(got) != 1 || got[0] != ref {
		t.Fatalf("negative-expired unpin = %v, want exactly [%s]", got, ref)
	}
	if n := rawCountByID(t, dir, strings.Repeat("5", 64)); n != 0 {
		t.Fatalf("negative finalized blob %s not removed (%d rows)", ref, n)
	}
	if n := rawCountByID(t, dir, strings.Repeat("6", 64)); n != 0 {
		t.Fatalf("negative active session not removed (%d rows)", n)
	}
}

// rawCountByID counts upload_sessions rows carrying the given session id.
func rawCountByID(t *testing.T, dir, id string) int {
	t.Helper()
	db := mustOpenRaw(t, dir)
	defer db.Close()
	var n int
	if err := db.QueryRow(`select count(*) from upload_sessions where id = ?`, id).Scan(&n); err != nil {
		t.Fatalf("count by id: %v", err)
	}
	return n
}

// TestCleanupSignedDomainBoundaryMinInt64 proves the raw cleanup boundary at
// the most negative SQLite INTEGER reaches and removes an expired finalized
// blob whose expires_at is MinInt64+1 (the smallest span above MinInt64, whose
// very existence requires expires > created; MinInt64 itself cannot be expires
// because expires_at must exceed created_at). Stored via raw SQL to avoid any
// time.Time/UnixNano overflow or clamping.
func TestCleanupSignedDomainBoundaryMinInt64(t *testing.T) {
	svc, dir := newTestService(t)
	raw := mustOpenRaw(t, dir)
	const min = math.MinInt64
	// created=min, expires=min+1 — the least positive span, fully representable.
	seedRawFinalizedAt(t, raw, strings.Repeat("9", 64), min, min+1, strings.Repeat("e", 64))
	raw.Close()

	unp := &fakeUnpinner{}
	c, err := NewCleanup(svc, unp, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), time.Unix(0, 0).UTC(), 10)
	if err != nil {
		t.Fatalf("RunOnce boundary: %v", err)
	}
	if got := unp.calls(); len(got) != 1 || got[0] != strings.Repeat("e", 64) {
		t.Fatalf("boundary MinInt64 unpin = %v, want 1", got)
	}
	if res.Unpinned != 1 || res.Removed != 1 || res.Failed != 0 {
		t.Fatalf("boundary counts = %+v, want removed=1 unpinned=1", res)
	}
}

// TestCleanupSignedDomainFairAcrossRestartAndHandles proves a traversal that
// mixes negative (pre-epoch) and nonnegative expires_at values, spanning more
// than one full batch of retained rows, stays FAIR across a restart and across
// independent handles sharing the durable cursor. Both classes must eventually
// be reached/cleaned and no retained ref unpinned — the same durability
// guarantee as the nonnegative-only fair tests, now across the full signed
// domain the v11 cursor spans.
func TestCleanupSignedDomainFairAcrossRestartAndHandles(t *testing.T) {
	// The service Create path refuses pre-epoch now() (its MaxInt64 overflow
	// guard), so every row — retained and eligible, negative and nonnegative —
	// is written via raw SQL with explicit nanosecond timestamps, and each
	// finalized blob gets a matching empty spool backing file so a reopened
	// service's startup reconciliation has a durable file to align.
	dir := tempPrivate(t)
	svc := openServiceOn(t, dir) // establishes v11 schema + spool + cursor
	spoolRoot := filepath.Join(dir, "spool")
	seedFile := func(id string) {
		if err := os.WriteFile(filepath.Join(spoolRoot, id), nil, 0o600); err != nil {
			t.Fatalf("spool backing file: %v", err)
		}
	}
	raw := mustOpenRaw(t, dir)
	const retainedN = 4 // > one full batch at batch=1, split across domains
	const eligibleN = 2
	retainedRefs := map[string]struct{}{}
	for i := 0; i < retainedN; i++ {
		// created < expires must hold. Even i: both far in the past (negative
		// expires). Odd i: both a few seconds after epoch (nonnegative).
		id := fmt.Sprintf("%064x", 0x6000+i)
		ref := distinctHexRef(0x6000 + i)
		var created, expires int64
		if i%2 == 0 {
			created, expires = -7_200_000_000_000, -3_599_000_000_000 // negative expires
		} else {
			created, expires = 1_000_000_000, 10_000_000_000 // nonnegative expires (t=1s, t=10s)
		}
		seedRawFinalizedAt(t, raw, id, created, expires, ref)
		seedFile(id)
		retainedRefs[ref] = struct{}{}
	}
	// Eligible rows, both sorted AFTER the retained rows in (expires_at,id)
	// order so a full retained batch must be traversed first: one negative
	// expires, one nonnegative.
	for i := 0; i < eligibleN; i++ {
		id := fmt.Sprintf("%064x", 0x6200+i)
		ref := distinctHexRef(0x6200 + i)
		var created, expires int64
		if i == 0 {
			created, expires = -3_598_000_000_000, -3_597_000_000_000 // negative, later than all retained negatives
		} else {
			created, expires = 11_000_000_000, 20_000_000_000 // nonnegative, later than all retained nonnegatives
		}
		seedRawFinalizedAt(t, raw, id, created, expires, ref)
		seedFile(id)
	}
	raw.Close()
	// runAt far past every expires (largest = eligible nonnegative t=20s).
	runAt := time.Unix(200, 0).UTC()
	svc.Close()

	committed := &fakeCommitted{byRepo: map[string]map[string]struct{}{"backend/api": retainedRefs}}
	unp := &fakeUnpinner{}

	// Repeated passes across FRESH handles (restart) on the same store, batch=1,
	// until the traversal wraps enough to examine the whole signed domain.
	const batch = 1
	for i := 0; i < 4*(retainedN+eligibleN); i++ {
		h := openServiceOn(t, dir)
		c, err := NewCleanup(h, unp, committed)
		if err != nil {
			h.Close()
			t.Fatalf("pass %d NewCleanup: %v", i, err)
		}
		if _, err := c.RunOnce(context.Background(), runAt, batch); err != nil {
			h.Close()
			t.Fatalf("pass %d RunOnce: %v", i, err)
		}
		h.Close()
	}

	pinned := map[string]int{}
	for _, r := range unp.calls() {
		pinned[r]++
		if _, retained := retainedRefs[r]; retained {
			t.Fatalf("a retained ref %s was unpinned", r)
		}
	}
	for _, want := range []string{distinctHexRef(0x6200), distinctHexRef(0x6201)} {
		if pinned[want] != 1 {
			t.Fatalf("eligible ref %s unpinned %d times across restart+handles, want exactly 1 (signed-domain starvation)", want, pinned[want])
		}
	}
	if len(pinned) != eligibleN {
		t.Fatalf("eligible unpins = %d (%v), want %d across mixed signed domain", len(pinned), unp.calls(), eligibleN)
	}
	// The negative-domain eligible row was actually reached (not skipped as
	// fresh-before-cursor): its unpin proves negative expires_at is traversable.
	if pinned[distinctHexRef(0x6200)] != 1 {
		t.Fatalf("negative-domain eligible row never reached across restart+handles — fresh/negative cursor gap")
	}
}
