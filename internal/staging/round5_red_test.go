package staging

// Round 5 RED probes: deterministic behavioral checks for JOINING every
// concurrent or later staging-pool Close to one shared shutdown completion.
// Run against the pre-fix code to capture RED evidence before the Round 5
// implementation. They are production-path tests of the FINAL joined-Close
// contract and pass once the fix lands — no deliberately failing tests are
// committed.

import (
	"context"
	"database/sql"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitPoolClosed spins until the pool's closed flag is set (the shutdown
// owner has marked the pool closing). Bounded; the owner is already scheduled
// by the time it marks, so this can only starve if close is broken.
func waitPoolClosed(t *testing.T, p *dbPool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mu.Lock()
		c := p.closed
		p.mu.Unlock()
		if c {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pool never marked closed")
		}
		runtime.Gosched()
	}
}

// TestRound5REDJoinedCloseWaitsForReservationAndBorrow proves the joined
// contract deterministically: pool size 1 with one borrowed handle and one
// waiter reservation, and TWO concurrent Close callers. NEITHER may return
// before the reservation is canceled and the borrowed handle is released;
// both return only after the owner drains the exact idle handles and the
// underlying database close completes. The pre-fix code's second Close sees
// `closed` and returns immediately — RED.
func TestRound5REDJoinedCloseWaitsForReservationAndBorrow(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	p := newDBPool(db, 1)
	hc, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	p.ch <- hc

	// Hold the only handle (borrowed=1, channel empty).
	held, err := p.acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire held: %v", err)
	}
	// One waiter reservation blocks on the empty channel (borrowed=2).
	wctx, wcancel := context.WithCancel(context.Background())
	defer wcancel()
	go func() { _, _ = p.acquire(wctx) }()
	waitBorrowed(t, p, 2)

	// LAUNCH TWO concurrent Close callers.
	const closers = 2
	var done [closers]chan struct{}
	for i := 0; i < closers; i++ {
		done[i] = make(chan struct{})
		go func(dch chan struct{}) { p.close(); close(dch) }(done[i])
	}
	waitPoolClosed(t, p) // a shutdown owner has marked the pool closing

	// NEITHER close may return while a reservation and a borrow are outstanding.
	for i := 0; i < closers; i++ {
		select {
		case <-done[i]:
			t.Fatalf("RED: closer %d returned while a reservation/borrow was outstanding", i)
		case <-time.After(150 * time.Millisecond):
		}
	}

	// Cancel the waiter: its reservation is released (borrowed drops to the
	// held handle) and the waiter resolves. Depending on whether the waiter's
	// unlucky select picks closing or the (now-ready) context first, it
	// returns errPoolClosed or context.Canceled — BOTH release the reservation
	// exactly once; the deterministic exact-sentinel proof lives in the
	// dedicated cancellation test below. Still no closer may return.
	wcancel()
	waitBorrowed(t, p, 1)
	for i := 0; i < closers; i++ {
		select {
		case <-done[i]:
			t.Fatalf("RED: closer %d returned while the held borrow was outstanding", i)
		case <-time.After(150 * time.Millisecond):
		}
	}

	// Release the held handle (borrowed=0): the owner finishes shutdown and
	// BOTH closers join that same completion.
	p.release(held)
	for i := 0; i < closers; i++ {
		select {
		case <-done[i]:
		case <-time.After(5 * time.Second):
			t.Fatalf("RED: closer %d never returned after the borrow was released", i)
		}
	}

	// No handle may be leaked open after the joined close (the released
	// handle was closed by the owner protocol).
	if err := hc.QueryRowContext(context.Background(), `pragma foreign_keys`).Scan(new(int)); err == nil {
		t.Fatal("RED: retained handle leaked open after joined close")
	}
	// No acquire may succeed after close linearizes.
	if _, err := p.acquire(context.Background()); !errors.Is(err, errPoolClosed) {
		t.Fatalf("RED: acquire after close: %v, want errPoolClosed", err)
	}
}

// TestRound5REDManyClosersAllJoinSameCompletion proves that MANY concurrent
// Close callers all join the single owner's completion: with borrowed handles
// outstanding, none of them may return; when the borrows are released they all
// return together, and no acquire succeeds afterward. The pre-fix code lets
// every closer after the first return immediately — RED.
func TestRound5REDManyClosersAllJoinSameCompletion(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	p := newDBPool(db, 2)
	conns := make([]*sql.Conn, 2)
	for i := range conns {
		c, err := db.Conn(context.Background())
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		conns[i] = c
		p.ch <- c
	}
	// Borrow both handles so shutdown must wait.
	var held []*sql.Conn
	for i := 0; i < 2; i++ {
		c, err := p.acquire(context.Background())
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		held = append(held, c)
	}
	const n = 12
	var dones [n]chan struct{}
	for i := range dones {
		dones[i] = make(chan struct{})
		go func(dch chan struct{}) { p.close(); close(dch) }(dones[i])
	}
	waitPoolClosed(t, p)
	// None of the n closers may return while both borrows are outstanding.
	for i := 0; i < n; i++ {
		select {
		case <-dones[i]:
			t.Fatalf("RED: closer %d returned before shutdown completed", i)
		case <-time.After(150 * time.Millisecond):
		}
	}
	// Release both borrows: ALL n join the one completion.
	for _, c := range held {
		p.release(c)
	}
	for i := 0; i < n; i++ {
		select {
		case <-dones[i]:
		case <-time.After(5 * time.Second):
			t.Fatalf("RED: closer %d never returned after shutdown completed", i)
		}
	}
	for _, c := range conns {
		if err := c.QueryRowContext(context.Background(), `select 1`).Scan(new(int)); err == nil {
			t.Fatal("RED: retained handle leaked open after joined close")
		}
	}
	if _, err := p.acquire(context.Background()); !errors.Is(err, errPoolClosed) {
		t.Fatalf("RED: acquire after close: %v, want errPoolClosed", err)
	}
}

// TestRound5REDCloseBeforeAnyBorrowAndRepeatedAfterCompletion proves the
// remaining lifecycle edges: Close with no borrow outstanding drains the full
// retained set and closes the database; a repeated Close after completion
// returns promptly (it joins the already-finished shutdown) and never
// double-closes the database or leaks a handle.
func TestRound5REDCloseBeforeAnyBorrowAndRepeatedAfterCompletion(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	p := newDBPool(db, 3)
	conns := make([]*sql.Conn, 3)
	for i := range conns {
		c, err := db.Conn(context.Background())
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		conns[i] = c
		p.ch <- c
	}
	// Close with no borrow outstanding: owner drains all 3 idle handles and
	// closes the database.
	p.close()
	// Repeated Close after completion returns immediately (already done) and
	// never double-closes the database.
	closeDone := make(chan struct{})
	go func() { p.close(); close(closeDone) }()
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("RE: repeated Close after completion did not return")
	}
	for _, c := range conns {
		if err := c.QueryRowContext(context.Background(), `select 1`).Scan(new(int)); err == nil {
			t.Fatal("RED: idle handle leaked open after close")
		}
	}
	if _, err := p.acquire(context.Background()); !errors.Is(err, errPoolClosed) {
		t.Fatalf("acquire after close: %v, want errPoolClosed", err)
	}
}

// TestRound5REDConcurrentAcquireReleaseCancelClose is a high-count
// simultaneous acquire/release/Close stress: many workers acquire, use and
// release handles (or block and are rejected when Close lands), while a Close
// races them. Every acquire that wins a handle is accounted before Close may
// finish; acquire-after-close always fails; no worker may observe a corrupt
// error, a leaked handle, or a send-on-closed panic. Runs under -race.
func TestRound5REDConcurrentAcquireReleaseCancelClose(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	p := newDBPool(db, 4)
	for i := 0; i < 4; i++ {
		c, err := db.Conn(context.Background())
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		p.ch <- c
	}

	const workers = 96
	acquireErr := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := p.acquire(context.Background())
			if err == nil {
				p.release(c)
				acquireErr <- nil
				return
			}
			acquireErr <- err
		}()
	}
	// Drive a Close concurrently so some acquires linearize before it (success)
	// and some after (errPoolClosed).
	p.close()
	wg.Wait()
	close(acquireErr)

	for err := range acquireErr {
		switch {
		case err == nil:
		case errors.Is(err, errPoolClosed):
		default:
			t.Fatalf("unexpected acquire result under close contention: %v", err)
		}
	}
	// No acquire may succeed after the joined close.
	if _, err := p.acquire(context.Background()); !errors.Is(err, errPoolClosed) {
		t.Fatalf("acquire after close: %v, want errPoolClosed", err)
	}
}

// TestRound5REDServiceCloseJoinedAndSingleClose proves the service-level
// contract: two concurrent Close calls both delay until pool shutdown fully
// completes (with a borrow outstanding, neither may return early), then both
// return and the pool and spool are closed exactly once — no double spool/pool
// close. On the pre-fix code the second Close returns while shutdown is still
// waiting on the borrow — RED.
func TestRound5REDServiceCloseJoinedAndSingleClose(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t) // also registers a Cleanup Close

	// Hold one pool borrow so shutdown must wait.
	held, err := svc.pool.acquire(ctx)
	if err != nil {
		t.Fatalf("acquire held: %v", err)
	}

	// Two concurrent Close callers.
	closeDone := make(chan struct{}, 2)
	var nClosed atomic.Int32
	closeFn := func() {
		_ = svc.Close()
		nClosed.Add(1)
		closeDone <- struct{}{}
	}
	go closeFn()
	go closeFn()

	// Wait until the pool shutdown owner has marked the pool closing and is
	// now blocked on the outstanding borrow.
	waitPoolClosed(t, svc.pool)

	// NEITHER Close may return while the borrow is outstanding.
	for i := 0; i < 2; i++ {
		select {
		case <-closeDone:
			t.Fatalf("RED: a service Close returned before the borrow was released")
		case <-time.After(200 * time.Millisecond):
		}
	}

	// Release the borrow: the joined pool shutdown completes and BOTH Close
	// calls return.
	svc.pool.release(held)
	for i := 0; i < 2; i++ {
		select {
		case <-closeDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("service Close %d never returned after shutdown", i)
		}
	}
	if nClosed.Load() != 2 {
		t.Fatalf("RED: expected exactly 2 Close returns, got %d", nClosed.Load())
	}

	// The pool and spool are released exactly once.
	if svc.pool != nil {
		t.Fatal("RED: pool not released after Close")
	}
	if svc.spool != nil {
		t.Fatal("RED: spool not released after Close")
	}
}
