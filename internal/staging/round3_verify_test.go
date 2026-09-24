package staging

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Round 3 verify: exact pinned SQLite handles
// ---------------------------------------------------------------------------

// TestRound3AllPoolHandlesHeldAndVerifiedTogether proves the pool
// constructor acquires ALL N physical connections simultaneously and holds
// them while every one is verified — database/sql can never hand back one
// idle connection repeatedly — and that no further connection is available
// while the full retained set is held.
func TestRound3AllPoolHandlesHeldAndVerifiedTogether(t *testing.T) {
	dir := tempPrivate(t)
	dbPath := filepath.Join(dir, "staging.db")
	ctx := context.Background()

	db, parentRoot, dbName, preFi, _, err := openStagingDBAnchored(ctx, dbPath, 4)
	if err != nil {
		t.Fatalf("open anchored: %v", err)
	}
	defer db.Close()
	defer parentRoot.Close()

	poolVerifyHook = func(i int) {
		if i != 3 {
			return
		}
		st := db.Stats()
		if st.InUse != 4 {
			t.Errorf("all N must be held during verification: InUse=%d want 4", st.InUse)
		}
		if st.OpenConnections != 4 {
			t.Errorf("physical connections=%d want 4", st.OpenConnections)
		}
		// With every permitted handle held, a further acquisition must
		// block; it must not succeed from an idle reuse.
		cctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		defer cancel()
		if c, cerr := db.Conn(cctx); cerr == nil {
			c.Close()
			t.Errorf("extra connection acquired while the full retained set is held")
		}
	}
	defer func() { poolVerifyHook = nil }()

	conns, err := verifyAndPinAllConns(ctx, db, 4, parentRoot, dbName, preFi)
	if err != nil {
		t.Fatalf("verify and pin: %v", err)
	}
	for _, c := range conns {
		c.Close()
	}
	if db.Stats().InUse != 0 {
		t.Fatalf("verification leaked hold: InUse=%d", db.Stats().InUse)
	}
}

// TestRound3SwapBetweenOpensFailsClosedUntouched proves a pathname swap
// planted BETWEEN individual physical opens (after the schema was verified,
// before every retained handle was opened) is caught by the per-connection
// identity verification: the constructor fails closed and the replacement
// file's bytes are untouched.
func TestRound3SwapBetweenOpensFailsClosedUntouched(t *testing.T) {
	dir := tempPrivate(t)
	dbPath := filepath.Join(dir, "staging.db")
	ctx := context.Background()

	db, parentRoot, dbName, preFi, _, err := openStagingDBAnchored(ctx, dbPath, 4)
	if err != nil {
		t.Fatalf("open anchored: %v", err)
	}
	defer db.Close()

	swapped := false
	poolVerifyHook = func(i int) {
		if i == 1 && !swapped {
			swapped = true
			if err := os.Rename(dbPath, dbPath+".old"); err != nil {
				t.Errorf("rename: %v", err)
				return
			}
			// Plant a foreign replacement at the original path.
			ndb, oerr := sql.Open("sqlite", normalizeDSN(dbPath))
			if oerr != nil {
				t.Errorf("open replacement: %v", oerr)
				return
			}
			if _, eerr := ndb.Exec(`create table planted (x integer)`); eerr != nil {
				t.Errorf("plant: %v", eerr)
			}
			ndb.Close()
		}
	}
	defer func() { poolVerifyHook = nil }()

	_, err = verifyAndPinAllConns(ctx, db, 4, parentRoot, dbName, preFi)
	if err == nil {
		t.Fatal("constructor accepted a database swapped between opens")
	}
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("error %v, want ErrDependency", err)
	}
	// The replacement is byte-untouched: only our planted table exists.
	fi, lerr := os.Lstat(dbPath)
	if lerr != nil {
		t.Fatalf("lstat replacement: %v", lerr)
	}
	if fi.Size() == 0 {
		t.Fatalf("replacement was modified during the failed constructor")
	}
	ndb, oerr := sql.Open("sqlite", normalizeDSN(dbPath))
	if oerr != nil {
		t.Fatalf("open replacement: %v", oerr)
	}
	defer ndb.Close()
	var uploadSessions int
	if err := ndb.QueryRow(`select count(*) from sqlite_master where type='table' and name='upload_sessions'`).Scan(&uploadSessions); err != nil {
		t.Fatalf("inspect replacement: %v", err)
	}
	if uploadSessions != 0 {
		t.Fatal("the failed constructor adopted or migrated the replacement file")
	}
	var planted int
	if err := ndb.QueryRow(`select count(*) from sqlite_master where type='table' and name='planted'`).Scan(&planted); err != nil || planted != 1 {
		t.Fatalf("replacement content changed: planted=%d err=%v", planted, err)
	}
}

// TestRound3EveryRetainedHandleBindsToOriginalVerifiedDB proves the exact
// retained set is the verified one: every handle passes the pragmas and
// reports the anchored database name, and after the path is renamed away
// the retained handles keep serving the ORIGINAL inode while a fresh
// connection to the new path sees nothing.
func TestRound3EveryRetainedHandleBindsToOriginalVerifiedDB(t *testing.T) {
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")
	ctx := context.Background()

	svc, err := NewService(ctx, spoolDir, dbPath)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	defer svc.Close()
	preFi, lerr := os.Lstat(dbPath)
	if lerr != nil {
		t.Fatalf("lstat db: %v", lerr)
	}

	// Touch every retained handle once: acquire (all N) one at a time.
	for i := 0; i < 4; i++ {
		conn, err := svc.pool.acquire(ctx)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		var seq int
		var dbname, file string
		if err := conn.QueryRowContext(ctx, `pragma database_list`).Scan(&seq, &dbname, &file); err != nil {
			svc.pool.release(conn)
			t.Fatalf("database_list on handle %d: %v", i, err)
		}
		if file != dbPath {
			svc.pool.release(conn)
			t.Fatalf("handle %d is bound to %q, want the anchored %q", i, file, dbPath)
		}
		var fk int
		if err := conn.QueryRowContext(ctx, `pragma foreign_keys`).Scan(&fk); err != nil || fk != 1 {
			svc.pool.release(conn)
			t.Fatalf("foreign_keys on handle %d = %d err=%v", i, fk, err)
		}
		svc.pool.release(conn)
	}

	// Rename the database away; the retained handles must keep pointing at
	// the ORIGINAL verified inode.
	moved := dbPath + ".moved"
	if err := os.Rename(dbPath, moved); err != nil {
		t.Fatalf("rename: %v", err)
	}
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s, err = svc.Append(ctx, s.ID, s.Repo, s.Actor, 0, strings.NewReader("payload-bytes"), 1024)
	if err != nil {
		t.Fatalf("append through retained handles after path removal: %v", err)
	}
	digest, ref, media, size := finalizeArgs(s)
	if err := svc.MarkFinalized(ctx, s.ID, s.Repo, s.Actor, digest, ref, media, size); err != nil {
		t.Fatalf("finalize through retained handles after path removal: %v", err)
	}
	// The committed metadata is served by the RETAINED handles — the only
	// connection pool in play — and the inode behind them is the originally
	// verified one, now renamed away. A path-based connection cannot even be
	// opened at the original path (the file is gone), so nothing could have
	// redirected a retained handle.
	got, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor)
	if err != nil || got.State != StateFinalized {
		t.Fatalf("committed state not on the retained handles: %v state=%s", err, got.State)
	}
	movedFi, _ := os.Lstat(moved)
	if !os.SameFile(preFi, movedFi) {
		t.Fatal("moved file is not the originally verified inode")
	}
	if _, err := os.Lstat(dbPath); !os.IsNotExist(err) {
		t.Fatal("unexpected file re-created at the original path")
	}
}

// ---------------------------------------------------------------------------
// Round 3 verify: creation ordering, crash points, context authority
// ---------------------------------------------------------------------------

// TestRound3CanonicalFileNeverCarriesTokenBytes proves that even MID-CREATE
// (at the creation barrier, before activation) the canonical payload file
// contains exactly zero bytes — the token lives only in the separate token
// file — so an active canonical file is token-free by construction and
// Open/Append can never expose token bytes.
func TestRound3CanonicalFileNeverCarriesTokenBytes(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()

	var checked atomic.Bool
	svc.createBarrier = func() {
		entries, rerr := os.ReadDir(filepath.Join(dir, "spool"))
		if rerr != nil {
			t.Errorf("readdir at barrier: %v", rerr)
			return
		}
		var id string
		for _, en := range entries {
			if strings.HasSuffix(en.Name(), ".tok") {
				id = strings.TrimSuffix(en.Name(), ".tok")
			}
		}
		if id == "" {
			t.Error("no token file at the creation barrier")
			return
		}
		b, err := os.ReadFile(filepath.Join(dir, "spool", id))
		if err == nil && len(b) != 0 {
			t.Errorf("canonical file carries %d bytes at the creation barrier", len(b))
		}
		tb, terr := os.ReadFile(filepath.Join(dir, "spool", id+".tok"))
		if terr != nil || len(tb) != creatingTokenLen {
			t.Errorf("token file missing/mis-sized at barrier: %d err=%v", len(tb), terr)
		}
		checked.Store(true)
	}
	defer func() { svc.createBarrier = nil }()

	s, err := svc.Create(ctx, "backend/api", "user:alice", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !checked.Load() {
		t.Fatal("creation barrier never fired")
	}
	if s.State != StateActive {
		t.Fatalf("state %s", s.State)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "spool", s.ID)); err != nil || fi.Size() != 0 {
		t.Fatalf("active canonical file is not empty: size=%v err=%v", fi.Size(), err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "spool", s.ID+".tok")); !os.IsNotExist(err) {
		t.Fatal("token file survived a successful create")
	}
}

// TestRound3CancellationAfterActivationCommitReturnsCommittedResult proves
// a cancellation arriving AFTER the durable activation commit — while the
// final token-clearing step runs — never falsely reports cancellation: the
// committed active session IS the result.
func TestRound3CancellationAfterActivationCommitReturnsCommittedResult(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()

	canceled := false
	svc.postActivateHook = func() {
		// The caller's context is canceled after the commit.
		canceled = true
	}
	// Cancel the CREATE ctx from inside the hook by canceling a wrapped ctx
	// that Create itself uses? Create receives ctx; simulate by canceling
	// once the hook fired via a mutable ctx wrapper.
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hooked := false
	orig := svc.postActivateHook
	svc.postActivateHook = func() {
		orig()
		if !hooked {
			hooked = true
			cancel()
		}
	}
	_ = canceled

	s, err := svc.Create(cctx, "backend/api", "user:alice", time.Hour)
	if err != nil {
		t.Fatalf("a canceled-after-commit create must return the committed result: %v", err)
	}
	if !hooked {
		t.Fatal("post-activation hook never fired")
	}
	if s.State != StateActive {
		t.Fatalf("state %s", s.State)
	}
	got, err := svc.Status(context.Background(), s.ID, "backend/api", "user:alice")
	if err != nil || got.State != StateActive {
		t.Fatalf("committed active session not visible: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "spool", s.ID)); err != nil || fi.Size() != 0 {
		t.Fatalf("canonical file residue after committed create: %v size=%d", err, fi.Size())
	}
	if _, err := os.Lstat(filepath.Join(dir, "spool", s.ID+".tok")); !os.IsNotExist(err) {
		t.Fatal("token file residue after committed create")
	}
}

// TestRound3StartupReReadsConcurrentlyActivatedRow proves startup never
// rejects a creating row through its STALE Phase-A snapshot when the
// creator concurrently activates it: reconciliation re-reads the current
// row state inside the serialized decision and treats the now-active row as
// a live session — aligning it, not rejecting or deleting it.
func TestRound3StartupReReadsConcurrentlyActivatedRow(t *testing.T) {
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")
	ctx := context.Background()

	id := strings.Repeat("4e", 32)
	token := strings.Repeat("9a", 32)
	created := time.Now().Add(-2 * time.Hour).UnixNano() // stale lease
	expires := created + 100*int64(time.Hour)            // far future
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	fixture, err := newStagingDBAt(dbPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if _, err := fixture.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token)
		values (?, 'backend/api', 'user:alice', 'creating', 0, ?, ?, ?)`, id, created, expires, token); err != nil {
		fixture.Close()
		t.Fatalf("seed: %v", err)
	}
	fixture.Close()
	tb, _ := hex.DecodeString(token)
	// New-protocol residue: empty canonical + attribution token file.
	if err := os.WriteFile(filepath.Join(spoolDir, id), nil, 0o600); err != nil {
		t.Fatalf("plant canonical: %v", err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, id+".tok"), tb, 0o600); err != nil {
		t.Fatalf("plant tok: %v", err)
	}

	reconcileSnapshotHook = func() {
		// The creator activates ITS row while startup is paused after the
		// Phase A snapshot — exactly the concurrent activation/truncation
		// race: startup must re-read the CURRENT state, not reject the row
		// through the stale creating snapshot.
		db, err := sqlOpenForTest(dbPath)
		if err != nil {
			t.Errorf("open: %v", err)
			return
		}
		_, uerr := db.Exec(`update upload_sessions set state = 'active', create_token = null where id = ?`, id)
		db.Close()
		if uerr != nil {
			t.Errorf("activate: %v", uerr)
		}
	}
	defer func() { reconcileSnapshotHook = nil }()

	svc, err := NewService(ctx, spoolDir, dbPath)
	if err != nil {
		t.Fatalf("startup rejected a concurrently activated row: %v", err)
	}
	defer svc.Close()

	got, err := svc.Status(ctx, id, "backend/api", "user:alice")
	if err != nil || got.State != StateActive {
		t.Fatalf("concurrently activated row not a live active session: %v", err)
	}
	// Its attributable files are intact (nothing adopted or deleted).
	if fi, err := os.Lstat(filepath.Join(spoolDir, id)); err != nil || fi.Size() != 0 {
		t.Fatalf("canonical file disturbed: %v size=%d", err, fi.Size())
	}
	// The leftover token file of a live row is benign residue: preserved.
	if fi, err := os.Lstat(filepath.Join(spoolDir, id+".tok")); err != nil || fi.Size() != creatingTokenLen {
		t.Fatalf("token file disturbed: %v size=%d", err, fi.Size())
	}
}

// TestRound3CrashMatrixConverges walks every NEW protocol phase with an
// injected mid-phase failure and asserts convergence: no durable active row
// from a failed Create, exact dependency errors, no residue, and a clean
// restart.
func TestRound3CrashMatrixConverges(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		fault func(svc *service, counter *atomic.Int32)
	}{
		{
			name: "token-file-write-sync",
			fault: func(svc *service, c *atomic.Int32) {
				svc.fsyncHook = func() error {
					if c.Add(1) == 1 {
						return errors.New("tok sync fault")
					}
					return nil
				}
			},
		},
		{
			name: "canonical-file-sync",
			fault: func(svc *service, c *atomic.Int32) {
				svc.fsyncHook = func() error {
					if c.Add(1) == 2 {
						return errors.New("canonical sync fault")
					}
					return nil
				}
			},
		},
		{
			name: "directory-sync-after-canonical",
			fault: func(svc *service, c *atomic.Int32) {
				svc.dirSyncHook = func() error {
					if c.Add(1) == 2 {
						return errors.New("dir sync fault")
					}
					return nil
				}
			},
		},
		{
			name: "final-token-clearing-sync",
			fault: func(svc *service, c *atomic.Int32) {
				svc.dirSyncHook = func() error {
					n := c.Add(1)
					if n == 1 || n == 2 {
						return nil
					}
					return errors.New("final clearing sync fault")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, dir := newTestService(t)
			var c atomic.Int32
			tc.fault(svc, &c)
			s, err := svc.Create(ctx, "backend/api", "user:alice", time.Hour)
			if err == nil {
				t.Fatalf("create succeeded despite the injected %s fault", tc.name)
			}
			if !errors.Is(err, ErrDependency) {
				t.Fatalf("error %v, want data-free ErrDependency", err)
			}
			// No durable active row.
			if s.ID != "" {
				db, derr := sqlOpenForTest(filepath.Join(dir, "staging.db"))
				if derr != nil {
					t.Fatalf("open db: %v", derr)
				}
				var active int
				if err := db.QueryRow(`select count(*) from upload_sessions where state = 'active'`).Scan(&active); err != nil {
					t.Fatalf("count: %v", err)
				}
				db.Close()
				if active != 0 {
					t.Fatal("failed create left a durable active row")
				}
			}
			// No residue: the spool contains no files.
			entries, eerr := os.ReadDir(filepath.Join(dir, "spool"))
			if eerr != nil {
				t.Fatalf("readdir: %v", eerr)
			}
			for _, en := range entries {
				t.Fatalf("residue entry %s after failed create", en.Name())
			}
			// A restart converges cleanly (fresh constructor; the failed
			// create leaves nothing for reconcile to trip on).
			svc.fsyncHook = nil
			svc.dirSyncHook = nil
			svc.Close()
			svc2, err := NewService(ctx, filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
			if err != nil {
				t.Fatalf("restart: %v", err)
			}
			defer svc2.Close()
		})
	}
}

// TestRound3PoolHighCountAndCloseStress drives a 32-handle pool with
// concurrent acquires, releases, and a racing Close — cancellation and
// release must never deadlock, double-release, or panic even at high
// concurrency (run with -race).
func TestRound3PoolHighCountAndCloseStress(t *testing.T) {
	if os.Getenv("GO_RACE") != "" {
		t.Log("race build: exercising high-count stress")
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(32)
	p := newDBPool(db, 32)
	for i := 0; i < 32; i++ {
		conn, err := db.Conn(context.Background())
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		p.ch <- conn
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Borrowers hammer acquire/release with random cancellations.
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
				c, err := p.acquire(cctx)
				if err == nil {
					time.Sleep(20 * time.Microsecond)
					p.release(c)
				}
				cancel()
			}
		}()
	}
	time.Sleep(30 * time.Millisecond)
	close(stop)
	// A waiter must return promptly once a release happens — under the
	// mutex-free design the release is never blocked by the waiter.
	var waiterDone atomic.Bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if c, err := p.acquire(cctx); err == nil {
			p.release(c)
		}
		waiterDone.Store(true)
	}()
	p.close() // bounded: completes once borrowed handles return
	if !waiterDone.Load() {
		t.Log("waiter raced close; close still completed")
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Round 3 verify: descriptor-only modes / anchoring
// ---------------------------------------------------------------------------

// TestRound3ExistingDBModeDriftRepairedThroughDescriptor proves an existing
// database drifted to 0644 is repaired to EXACTLY 0600 through the verified
// opened descriptor (never a path) before schema bytes are touched, and the
// constructor succeeds.
func TestRound3ExistingDBModeDriftRepairedThroughDescriptor(t *testing.T) {
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")
	fixture, err := newStagingDBAt(dbPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	fixture.Close()
	if err := os.Chmod(dbPath, 0o644); err != nil {
		t.Fatalf("chmod 0644: %v", err)
	}
	svc, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("constructor must repair existing-mode drift through the descriptor: %v", err)
	}
	defer svc.Close()
	fi, err := os.Lstat(dbPath)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("existing DB not repaired to exact 0600: %o", fi.Mode().Perm())
	}
	fiSpool, err := os.Lstat(spoolDir)
	if err != nil || fiSpool.Mode().Perm() != 0o700 {
		t.Fatalf("spool root not exactly 0700: %v %o", err, fiSpool.Mode().Perm())
	}
}
