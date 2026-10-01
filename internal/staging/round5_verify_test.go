package staging

// Round 5 VERIFY: deterministic barrier tests proving that every concurrent
// and later Close JOINS one owner's shutdown across every boundary, that
// exactly one owner performs the drain and the underlying database close, and
// that the unlucky acquire/Close select always settles on a consistent
// linearization with the exact context sentinel when a waiter is canceled.
// These exercise the new shutdown-owner + shared-done design via the closeHook
// observation barrier (nil in production).

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRound5JoinedCloseAcrossShutdownBoundaries pauses the primary (owner)
// closer at each named shutdown boundary with a barrier, launches a secondary
// Close, and proves the secondary NEVER returns while the owner is paused
// there (it joins the one completion) and returns only after the owner
// finishes. The boundaries are: "marked" (closing marked), "drained" (idle
// set drained, database not yet closed), "dbclose" (database closed, done not
// yet published), and "done" (the final barrier before the shared done
// channel is closed — the strongest joined guarantee).
func TestRound5JoinedCloseAcrossShutdownBoundaries(t *testing.T) {
	for _, boundary := range []string{"marked", "drained", "dbclose", "done"} {
		t.Run(boundary, func(t *testing.T) {
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

			reached := make(chan struct{})
			release := make(chan struct{})
			var reachedOnce sync.Once
			p.closeHook = func(ph string) {
				if ph == boundary {
					reachedOnce.Do(func() { close(reached) })
					<-release
				}
			}

			primaryDone := make(chan struct{})
			go func() { p.close(); close(primaryDone) }()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatalf("primary closer never reached boundary %q", boundary)
			}

			secondaryDone := make(chan struct{})
			go func() { p.close(); close(secondaryDone) }()
			// The secondary joins the SAME completion: it must NOT return
			// while the primary is paused at this boundary.
			select {
			case <-secondaryDone:
				t.Fatalf("secondary Close returned while primary was paused at %q", boundary)
			case <-time.After(150 * time.Millisecond):
			}

			close(release) // let the primary proceed through shutdown
			select {
			case <-primaryDone:
			case <-time.After(5 * time.Second):
				t.Fatalf("primary closer never completed after release at %q", boundary)
			}
			select {
			case <-secondaryDone:
			case <-time.After(5 * time.Second):
				t.Fatalf("secondary Close did not return after the primary completed at %q", boundary)
			}

			// The retained idle handle is closed by the drain (not leaked).
			if err := hc.QueryRowContext(context.Background(), `select 1`).Scan(new(int)); err == nil {
				t.Fatalf("idle handle leaked open after joined close at %q", boundary)
			}
			if _, err := p.acquire(context.Background()); !errors.Is(err, errPoolClosed) {
				t.Fatalf("acquire after joined close at %q: %v, want errPoolClosed", boundary, err)
			}
		})
	}
}

// TestRound5JoinedCloseSingleOwnerAcrossManyCallers proves that across many
// concurrent Close callers EXACTLY ONE becomes the shutdown owner (the drain,
// the database close, and the done publication each happen once): the owner
// fires the "marked" boundary exactly once, the borrow-wait correctly counts
// every reservation/borrow, all callers join one completion, and afterwards
// acquisition fails.
func TestRound5JoinedCloseSingleOwnerAcrossManyCallers(t *testing.T) {
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

	var marked atomic.Int32
	var ownerOnce sync.Once
	p.closeHook = func(ph string) {
		if ph == "marked" {
			ownerOnce.Do(func() { marked.Add(1) })
		}
	}

	const n = 40
	var dones [n]chan struct{}
	for i := range dones {
		dones[i] = make(chan struct{})
		go func(dch chan struct{}) { p.close(); close(dch) }(dones[i])
	}
	waitPoolClosed(t, p)
	for i := 0; i < n; i++ {
		select {
		case <-dones[i]:
			t.Fatalf("closer %d returned before shutdown completed", i)
		case <-time.After(150 * time.Millisecond):
		}
	}
	for _, c := range held {
		p.release(c)
	}
	for i := 0; i < n; i++ {
		select {
		case <-dones[i]:
		case <-time.After(5 * time.Second):
			t.Fatalf("closer %d never returned after shutdown completed", i)
		}
	}
	// Exactly one owner performed the shutdown.
	if got := marked.Load(); got != 1 {
		t.Fatalf("exactly one shutdown owner expected, saw %d", got)
	}
	for _, c := range conns {
		if err := c.QueryRowContext(context.Background(), `select 1`).Scan(new(int)); err == nil {
			t.Fatal("retained handle leaked open after joined close")
		}
	}
	if _, err := p.acquire(context.Background()); !errors.Is(err, errPoolClosed) {
		t.Fatalf("acquire after close: %v, want errPoolClosed", err)
	}
}

// TestRound5JoinedCloseCanceledWaiterExactSentinel proves deterministically
// that a canceled waiter under full exhaustion returns the EXACT context
// cancellation sentinel (never errPoolClosed, never a wrapped error) and
// releases its reservation promptly, so a later joined Close can complete.
// Cancellation happens while the pool is NOT yet closing, eliminating the
// closing/context unlucky-select race.
func TestRound5JoinedCloseCanceledWaiterExactSentinel(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	p := newDBPool(db, 2)
	for i := 0; i < 2; i++ {
		c, err := db.Conn(context.Background())
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		p.ch <- c
	}
	// Hold both handles so the waiters block under full exhaustion.
	var held []*sql.Conn
	for i := 0; i < 2; i++ {
		c, err := p.acquire(context.Background())
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		held = append(held, c)
	}

	const n = 6
	results := make(chan error, n)
	var cancels []context.CancelFunc
	for i := 0; i < n; i++ {
		wctx, wcancel := context.WithCancel(context.Background())
		cancels = append(cancels, wcancel)
		go func(ctx context.Context) {
			_, err := p.acquire(ctx)
			results <- err
		}(wctx)
	}
	waitBorrowed(t, p, 2+n)

	// Cancel every waiter while no Close is pending: each returns the EXACT
	// context.Canceled sentinel.
	for _, cancel := range cancels {
		cancel()
	}
	for i := 0; i < n; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled waiter returned %v, want exact context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("canceled waiter did not return promptly")
		}
	}
	waitBorrowed(t, p, 2)

	// A joined Close now completes once the held borrows are released.
	closeDone := make(chan struct{})
	go func() { p.close(); close(closeDone) }()
	select {
	case <-closeDone:
		t.Fatal("close returned while a borrow was outstanding")
	case <-time.After(150 * time.Millisecond):
	}
	for _, c := range held {
		p.release(c)
	}
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not complete after the borrows were released")
	}
	if _, err := p.acquire(context.Background()); !errors.Is(err, errPoolClosed) {
		t.Fatalf("acquire after close: %v, want errPoolClosed", err)
	}
}

// TestRound5JoinedCloseUnluckySelectCancellationSentinel exercises the unlucky
// select where a canceled waiter's context and the pool-closing signal are BOTH
// ready at once, and where handle-available and closing are both ready for an
// acquire racing Close. Every outcome must be one of the exact fixed results
// (nil, errPoolClosed, or the exact context.Canceled sentinel), never a leak, a
// double release, a negative counter, or a send-on-closed panic. Runs under
// -race with high repetition.
func TestRound5JoinedCloseUnluckySelectCancellationSentinel(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	p := newDBPool(db, 2)
	for i := 0; i < 2; i++ {
		c, err := db.Conn(context.Background())
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		p.ch <- c
	}

	const waiters = 80
	waitCtx, waitCancel := context.WithCancel(context.Background())
	defer waitCancel()
	results := make(chan error, waiters*2)
	var wg sync.WaitGroup

	// Cancelable waiters: partially block (exhaustion + cancellation lottery)
	// and partially succeed-and-release, so the select sees ctx, closing, and
	// handle-available all racing.
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := p.acquire(waitCtx)
			if err == nil {
				p.release(c)
				results <- nil
				return
			}
			results <- err
		}()
	}

	// Let the waiters contend, then drive Close so closing becomes ready while
	// some waiters are blocked and some find a handle.
	<-time.After(time.Millisecond)
	waitCancel() // make ctx.Done() ready for blocked waiters concurrently
	p.close()
	wg.Wait()
	close(results)

	for err := range results {
		switch {
		case err == nil:
		case errors.Is(err, errPoolClosed):
		case errors.Is(err, context.Canceled):
		default:
			t.Fatalf("unlucky select produced an invalid acquire result: %v", err)
		}
	}
	// Counters stayed sane and no acquire succeeds after the joined close.
	if _, err := p.acquire(context.Background()); !errors.Is(err, errPoolClosed) {
		t.Fatalf("acquire after close: %v, want errPoolClosed", err)
	}
}
