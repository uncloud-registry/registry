package staging

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Round 4 issue 2: pool acquire/Close LINEARIZATION. Acceptance (reservation)
// happens under the lock BEFORE a handle is received, so Close can never see
// an idle pool while an acquire is mid-flight; Close marks closing once,
// wakes waiters, and waits for every reservation and borrow to be returned
// or canceled before draining the exact idle set and closing the database.
// ---------------------------------------------------------------------------

// TestRound4PoolCloseCannotReturnWhileReservationOutstanding proves the
// linearization barrier deterministically: (i) a canceled waiter under full
// exhaustion releases its reservation promptly and returns the EXACT
// context sentinel (it is reserved before any handle can be received, so
// its cancellation can never race an accounting gap); (ii) Close waits for
// every outstanding borrow before draining the exact idle set and closing
// the database; (iii) no acquire succeeds after Close.
func TestRound4PoolCloseCannotReturnWhileReservationOutstanding(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	p := newDBPool(db, 1)
	c, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	p.ch <- c
	ctx := context.Background()

	// Exhaust the only handle (borrowed=1, channel empty).
	held, err := p.acquire(ctx)
	if err != nil {
		t.Fatalf("acquire held: %v", err)
	}

	// A waiter reserves under the lock and blocks on the empty channel.
	wctx, wcancel := context.WithCancel(ctx)
	defer wcancel()
	waiterErr := make(chan error, 1)
	go func() {
		_, err := p.acquire(wctx)
		waiterErr <- err
	}()
	waitBorrowed(t, p, 2) // waiter's reservation is durable (borrowed==2)

	// Cancel the waiter BEFORE Close marks closing: the exact context
	// sentinel must win and the reservation must be released promptly.
	wcancel()
	if err := <-waiterErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter returned %v, want exact context.Canceled", err)
	}
	waitBorrowed(t, p, 1) // reservation released back to the held borrow

	// Close may not complete while the held borrow is outstanding.
	closeDone := make(chan struct{})
	go func() { p.close(); close(closeDone) }()
	select {
	case <-closeDone:
		t.Fatal("close returned while a borrowed handle was outstanding")
	case <-time.After(150 * time.Millisecond):
	}

	// Release the held handle: close now drains the exact idle set (the one
	// returned handle) and closes the database.
	p.release(held)
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not complete after the borrow was released")
	}

	// No successful acquire may follow Close.
	if _, err := p.acquire(context.Background()); !errors.Is(err, errPoolClosed) {
		t.Fatalf("acquire after close: %v, want errPoolClosed", err)
	}
}

// TestRound4PoolSuccessfulAcquireLinearizes proves the linearization for an
// acquire that actually WINS a free handle: once a handle is successfully
// received it is already accounted (borrowed==1), so Close must wait for that
// borrow's release instead of draining the channel mid-flight and returning a
// handle backed by a closed database. The handle is acquired synchronously
// BEFORE Close starts, so there is no select-to-resolve here (a racing acquire
// may legally take either p.ch success or the p.closing errPoolClosed branch
// — the losing branches are covered deterministically by the sibling
// reservation-vs-close test and the round5 cancellation/close race tests).
func TestRound4PoolSuccessfulAcquireLinearizes(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	p := newDBPool(db, 1)
	c, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	p.ch <- c
	ctx := context.Background()

	// Deterministically win the only handle before Close can be in play.
	h, err := p.acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if h == nil {
		t.Fatal("acquire returned a nil handle")
	}

	// Close must block on this borrowed handle: it may not drain the idle set
	// or close the database while a successful acquire is outstanding.
	closeDone := make(chan struct{})
	go func() { p.close(); close(closeDone) }()
	select {
	case <-closeDone:
		t.Fatal("close completed while a successful acquire's handle was borrowed")
	case <-time.After(150 * time.Millisecond):
	}

	// Release the borrow: close now drains the exact idle set (the released
	// handle) and closes the database.
	p.release(h)
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not complete after the successful acquirer released")
	}

	// No successful acquire may follow Close.
	if _, err := p.acquire(context.Background()); !errors.Is(err, errPoolClosed) {
		t.Fatalf("acquire after close: %v, want errPoolClosed", err)
	}
}

// waitBorrowed spins until the pool's borrow/reservation count reaches n,
// bounded (the goroutine under test is already scheduled, so this can only
// starve if the pool itself is broken).
func waitBorrowed(t *testing.T, p *dbPool, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mu.Lock()
		b := p.borrowed
		p.mu.Unlock()
		if b >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pool never reached borrow=%d (stuck at %d)", n, b)
		}
		runtime.Gosched()
	}
}

// ---------------------------------------------------------------------------
// Round 4 issue 4: leaf-replacement-safe mode/removal. Deterministic swap
// barriers prove that a foreign replacement swapped in between stat and
// open (verifyPrivateDir) or before cleanup (quarantineUnlinkRoot /
// createName / createDBFile) is NEVER chmod'd or unlinked.
// ---------------------------------------------------------------------------

// TestRound4LeafSwapNeverMutatesForeignReplacement drives the deterministic
// swap hook at two dangerous boundaries and asserts the foreign replacement
// keeps its exact mode, content, and name.
func TestRound4LeafSwapNeverMutatesForeignReplacement(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()

	// (a) verifyPrivateDir: a foreign directory swapped between the anchored
	// Lstat and the descriptor open must be left untouched (SameFile guard
	// fails closed; the fchmod is never redirected).
	foreignDir := filepath.Join(dir, "sub")
	if err := os.Mkdir(foreignDir, 0o500); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	ascLeafSwapHook = func(phase, name string) {
		if phase != "verify" || name != "sub" {
			return
		}
		// Move the inspected leaf aside and plant a foreign replacement.
		if err := os.Rename(foreignDir, filepath.Join(dir, "sub.orig")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(foreignDir, 0o500); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyPrivateDir(root, "sub", 0o700, true); err == nil {
		ascLeafSwapHook = nil
		t.Fatal("verifyPrivateDir must FAIL CLOSED on a swapped foreign replacement (never chmod a name or open-redirected inode)")
	}
	ascLeafSwapHook = nil
	fi, lerr := os.Lstat(foreignDir)
	if lerr != nil || !fi.IsDir() || fi.Mode().Perm() != 0o500 {
		t.Fatalf("verifyPrivateDir mutated the foreign replacement: mode=%v err=%v", fi.Mode().Perm(), lerr)
	}

	// (b) quarantineUnlinkRoot cleanup: a foreign file swapped in at the
	// pre-rename boundary must survive with its exact name and content — the
	// quarantine protocol authenticates the renamed occupant against the
	// observed `want` identity, never deletes a foreign/replaced leaf, and
	// restores it non-clobberingly while failing closed.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("ours"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	want, err := os.Lstat(victim)
	if err != nil {
		t.Fatalf("lstat victim: %v", err)
	}
	swapped := false
	var barrier = func(phase, name string) {
		if phase != "pre-rename" || name != "victim" {
			return
		}
		if swapped {
			return
		}
		swapped = true
		if err := os.Rename(victim, filepath.Join(dir, "victim.orig")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(victim, []byte("foreign-bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := quarantineUnlinkRoot(root, "victim", quarantineNameFor("victim"), want, nil, nil, barrier); err == nil {
		t.Fatalf("guarded remove must FAIL CLOSED on a swapped foreign replacement, got nil")
	}
	if !swapped {
		t.Fatal("quarantine barrier never fired")
	}
	fi2, lerr := os.Lstat(victim)
	if lerr != nil || fi2.Size() != int64(len("foreign-bytes")) {
		t.Fatalf("guarded cleanup removed a foreign replacement: err=%v", lerr)
	}
	data, rerr := os.ReadFile(victim)
	if rerr != nil || string(data) != "foreign-bytes" {
		t.Fatalf("guarded cleanup mutated the foreign content: %q err=%v", data, rerr)
	}
}
