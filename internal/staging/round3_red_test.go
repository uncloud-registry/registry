package staging

// Round 3 RED probes: behavioral checks for the five review findings, run
// against the pre-fix code to capture RED evidence before implementation.

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// handRolledPool builds a bare dbPool (no *sql.DB) so a RED-proven
// deadlock can never poison a real service's cleanup chain.
func handRolledPool(size int) *dbPool {
	p := newDBPool(nil, size)
	for i := 0; i < size; i++ {
		p.ch <- &sql.Conn{}
	}
	return p
}

// RED 1: an exhausted pool acquire must never hold the pool mutex while
// waiting — a concurrent release must be able to hand the connection back.
// The pre-fix pool blocks the release forever (deadlock).
func TestRound3REDPoolExhaustionReleaseNotDeadlocked(t *testing.T) {
	p := handRolledPool(4)

	c1, err := p.acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Hold every remaining connection so concurrent acquires must wait.
	var rest []*sql.Conn
	for i := 0; i < 3; i++ {
		c, err := p.acquire(context.Background())
		if err != nil {
			t.Fatalf("hold: %v", err)
		}
		rest = append(rest, c)
	}
	waiterDone := make(chan struct{})
	go func() {
		c, err := p.acquire(context.Background())
		_ = c
		_ = err
		close(waiterDone)
	}()
	// Give the waiter time to block inside acquire (holding the mutex).
	time.Sleep(150 * time.Millisecond)

	released := make(chan struct{})
	go func() {
		p.release(c1)
		close(released)
	}()
	select {
	case <-released:
	case <-time.After(3 * time.Second):
		t.Fatal("RED: release deadlocked while a waiter blocks inside acquire")
	}
	select {
	case <-waiterDone:
	case <-time.After(3 * time.Second):
		t.Fatal("RED: waiter never received the released connection")
	}
	for _, c := range rest {
		p.release(c)
	}
}

// RED 2: a canceled waiter under full pool exhaustion must return promptly
// with the exact context sentinel — not block forever.
func TestRound3REDCanceledWaiterReturnsExactlyCanceled(t *testing.T) {
	p := handRolledPool(4)

	var held []*sql.Conn
	for i := 0; i < 4; i++ {
		c, err := p.acquire(context.Background())
		if err != nil {
			t.Fatalf("hold %d: %v", i, err)
		}
		held = append(held, c)
	}

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan error, 1)
	go func() {
		_, err := p.acquire(ctx)
		got <- err
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()
	// On the pre-fix code the waiter is blocked forever holding the pool
	// mutex; on the fixed code it returns the exact context sentinel.
	select {
	case err := <-got:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("acquire: %v, want exact context.Canceled", err)
		}
		for _, c := range held {
			p.release(c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RED: canceled waiter did not return promptly under exhaustion")
	}
}

// RED 3: Close must complete once borrowed handles return, and a handle
// released after Close must be closed — never leaked open.
func TestRound3REDPoolCloseWaitsForBorrowedAndClosesIt(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(4)
	p := newDBPool(db, 4)
	for i := 0; i < 4; i++ {
		conn, err := db.Conn(context.Background())
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		p.ch <- conn
	}

	c, err := p.acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	closedCh := make(chan struct{})
	go func() {
		p.close()
		close(closedCh)
	}()
	time.Sleep(150 * time.Millisecond)
	select {
	case <-closedCh:
		t.Fatal("RED: Close returned while a handle was still borrowed")
	default:
	}
	p.release(c)
	select {
	case <-closedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not complete after the borrowed handle returned")
	}
	// The handle released after close must be closed by the pool.
	var fk int
	if err := c.QueryRowContext(context.Background(), `pragma foreign_keys`).Scan(&fk); err == nil {
		t.Fatal("RED: handle released after Close leaked open")
	}
	if _, err := p.acquire(context.Background()); err == nil {
		t.Fatal("acquire after Close succeeded")
	}
}

// RED 4: a failure in the FINAL token-clearing sync (the sync after the
// activation commit in the pre-fix order) must NOT leave a durable active
// row: Create returns a data-free dependency error and the state converges
// (never a successful-looking active session).
func TestRound3REDCreateFinalSyncFailureLeavesNoActiveRow(t *testing.T) {
	ctx := context.Background()
	svc, dir := newTestService(t)

	// The LAST file sync fails. Pre-fix order: sync #1 is the token-write
	// fsync (before activation), sync #2 is the post-activation
	// token-clearing truncate sync.
	var syncs atomic.Int32
	svc.fsyncHook = func() error {
		if syncs.Add(1) == 2 {
			return errors.New("final sync fault")
		}
		return nil
	}
	if _, err := svc.Create(ctx, "backend/api", "user:alice", time.Hour); !errors.Is(err, ErrDependency) {
		t.Fatalf("Create: %v, want ErrDependency", err)
	}
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	var active int
	if err := db.QueryRow(`select count(*) from upload_sessions where state = 'active'`).Scan(&active); err != nil {
		t.Fatalf("count active: %v", err)
	}
	db.Close()
	if active != 0 {
		t.Fatal("RED: final sync failure left a durable active row")
	}
	// A restart converges cleanly.
	svc.fsyncHook = nil
	svc.Close()
	svc2, err := NewService(ctx, filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("restart after failed create: %v", err)
	}
	svc2.Close()
}

// RED 7: directory mode repair must operate ONLY through the retained
// anchored descriptor. When the retained root is (a) renamed away and
// (b) drifted to a no-exec mode, a replacement planted at the original path
// must NEVER be chmod'd; the repair fails closed instead.
func TestRound3REDAncestorSwapNeverChmodsReplacement(t *testing.T) {
	dir := tempPrivate(t)
	rootPath := filepath.Join(dir, "spool")
	sp, err := newSpool(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer sp.Close()

	// Rename the retained root away and drift it to a no-exec mode.
	moved := filepath.Join(dir, "spool-moved")
	if err := os.Rename(rootPath, moved); err != nil {
		t.Fatalf("rename retained root: %v", err)
	}
	if err := os.Chmod(moved, 0o644); err != nil {
		t.Fatalf("drift retained root: %v", err)
	}
	// Plant a DIFFERENT directory at the original path.
	if err := os.Mkdir(rootPath, 0o644); err != nil {
		t.Fatalf("plant replacement: %v", err)
	}
	if err := sp.ensureRootMode(); err == nil {
		t.Fatal("RED: no-exec retained-root mode repair must fail closed, not path-chmod")
	}
	fi, err := os.Lstat(rootPath)
	if err != nil {
		t.Fatalf("lstat replacement: %v", err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("RED: replacement directory was chmod'd to %o", fi.Mode().Perm())
	}
}

// Contract: a no-exec (0600) spool root is repaired THROUGH THE ANCHORED
// DESCENT DESCRIPTOR (the parent's openat + fchmod), never through the path.
// A root that cannot even be opened read-only (mode 0000) fails closed with
// its bytes untouched.
func TestRound3REDUnrepairableSpoolRootFailsClosed(t *testing.T) {
	dir := tempPrivate(t)
	rootPath := filepath.Join(dir, "spool")
	if err := os.Mkdir(rootPath, 0o000); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if sp, err := newSpool(context.Background(), rootPath); err == nil {
		sp.Close()
		t.Fatal("RED: an unopenable spool root must fail closed, never path-chmod")
	}
	fi, err := os.Lstat(rootPath)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode().Perm() != 0 {
		t.Fatalf("root mode was modified to %o by the failed constructor", fi.Mode().Perm())
	}
}
