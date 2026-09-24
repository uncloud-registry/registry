package staging

// Round 6 RED probes, part 2: cleanup-uncertainty and rollback-failure
// poisoning. When an append's file restoration or the transaction rollback
// can no longer be confirmed safe, the service must atomically poison its
// pool BEFORE the connection's serialization is released: every acquire
// (blocked or fresh) fails with the fixed data-free dependency error, the
// broken connection is retired and never returned to the pool, and Close
// still joins a single completion without hanging. The ORIGINAL panic value
// propagates on the panic path; the ordinary path reports the fixed
// dependency. A fresh service restart reconciles or fails closed.

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// snapPool returns the pool's observable state under its lock.
func snapPool(p *dbPool) (poisoned bool, chLen, closedConns int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.poisoned, len(p.ch), p.closedConns
}

// ---------------------------------------------------------------------------
// RED 3: uncertain panic cleanup poisons the service, never masks the panic
// ---------------------------------------------------------------------------

// TestRound6FsyncFaultDuringPanicCleanupPoisonsService injects an fsync
// failure into the file restoration of a panicked append. The ORIGINAL panic
// must still propagate, the service must become fixed/data-free
// poisoned/unavailable (every later operation fails with the fixed
// dependency error carrying no raw path/offset/panic data), and a FRESH
// service restart on the same spool+db must reconcile cleanly — never
// accepting the corrupted tail. On the pre-fix code the cleanup error is
// discarded and the pool stays healthy — RED.
func TestRound6FsyncFaultDuringPanicCleanupPoisonsService(t *testing.T) {
	svc, dir := newTestServicePoolSize(t, 1)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "stable")

	svc.fsyncHook = func() error { return errors.New("inject fsync fault during panic cleanup") }
	recoverAppend(t, svc, s, &panicAfterBytesReader{remaining: 3}, "reader boom")

	// The cleanup uncertainty is an atomic pool poison: no acquire succeeds.
	poisoned, chLen, _ := snapPool(svc.pool)
	if !poisoned {
		t.Fatal("RED: service pool not poisoned after uncertain panic cleanup")
	}
	if chLen != 0 {
		t.Fatalf("poisoned size-1 pool retains %d handles", chLen)
	}
	if _, err := svc.pool.acquire(ctx); !errors.Is(err, ErrDependency) {
		t.Fatalf("RED: acquire after poison: %v, want fixed ErrDependency", err)
	}
	// The service cannot perform later operations, with a FIXED data-free
	// dependency error (no path, offset, or panic detail).
	_, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("again"), 100)
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("RED: append after poison: %v, want fixed ErrDependency", err)
	}
	if err.Error() != ErrDependency.Error() {
		t.Fatalf("RED: poisoned error leaks detail: %q, want %q", err.Error(), ErrDependency.Error())
	}
	if got := err.Error(); got == "inject fsync fault during panic cleanup" {
		t.Fatalf("RED: poisoned error leaks the raw cleanup fault")
	}
	// The file was restored as far as possible (truncate ran, sync faulted)
	// and a fresh restart reconciles to the exact committed bytes.
	assertSpoolSize(t, svc, s.ID, int64(len("stable")))

	svc.Close()
	svc2 := newTestServiceOn(t, dir)
	st, err := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
	if err != nil || st.Offset != int64(len("stable")) {
		t.Fatalf("restart after poison: offset=%d err=%v", st.Offset, err)
	}
	if got := mustOpenAll(t, svc2, st); got != "stable" {
		t.Fatalf("RED: restart accepted a corrupted tail: %q", got)
	}
}

// stringReader is a minimal io.Reader over a string (avoids allocating
// readers that would otherwise need strings.NewReader plumbing in closures).
type stringReader struct{ s string }

func (r stringReader) Read(p []byte) (int, error) {
	if len(r.s) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.s)
	r.s = r.s[n:]
	return n, nil
}

// TestRound6TruncateFaultDuringPanicCleanupPoisonsService injects a
// truncate failure into the file restoration of a panicked append: the tail
// cannot be restored, so the pool is atomically poisoned, the original panic
// propagates, later operations fail with the fixed dependency, and a fresh
// restart RECONCILES the recoverable tail (truncating it) — the corrupted
// tail is never accepted as data. Red on the pre-fix code, which neither
// consults the truncation fault nor poisons.
func TestRound6TruncateFaultDuringPanicCleanupPoisonsService(t *testing.T) {
	svc, dir := newTestServicePoolSize(t, 1)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "stable")

	svc.truncateHook = func() error { return errors.New("inject truncate fault during panic cleanup") }
	recoverAppend(t, svc, s, &panicAfterBytesReader{remaining: 3}, "reader boom")

	poisoned, _, _ := snapPool(svc.pool)
	if !poisoned {
		t.Fatal("RED: service pool not poisoned after an uncertain truncate")
	}
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, stringReader{"again"}, 100); !errors.Is(err, ErrDependency) {
		t.Fatalf("RED: append after truncate-fault poison: %v, want fixed ErrDependency", err)
	}
	if _, err := svc.pool.acquire(ctx); !errors.Is(err, ErrDependency) {
		t.Fatalf("RED: acquire after truncate-fault poison: %v", err)
	}
	// The recovery tail is still on disk (the truncate faulted) but a fresh
	// restart reconciles it away: a shorter-than-committed file is the only
	// corruption accepted-fail-closed, never a consumed tail.
	svc.Close()
	svc2 := newTestServiceOn(t, dir)
	st, err := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
	if err != nil || st.Offset != int64(len("stable")) {
		t.Fatalf("restart after truncate fault: offset=%d err=%v", st.Offset, err)
	}
	if got := mustOpenAll(t, svc2, st); got != "stable" {
		t.Fatalf("RED: restart accepted a corrupted tail: %q", got)
	}
	if fi, lerr := os.Lstat(filepath.Join(dir, "spool", s.ID)); lerr != nil || fi.Size() != int64(len("stable")) {
		t.Fatalf("restart left a raw tail: size=%v err=%v", fi.Size(), lerr)
	}
}

// ---------------------------------------------------------------------------
// RED 4: a failed rollback NEVER returns its connection to the pool
// ---------------------------------------------------------------------------

// TestRound6RollbackFailurePanicPoisonsAndWakesBlockedAcquirers drives a
// panic inside a withTx callback whose connection is broken (closed), so the
// ROLLBACK fails. On pool size 1: the broken connection is retired (never
// returned), the pool is poisoned, a BLOCKED acquirer wakes with the fixed
// dependency error (a canceled acquirer still gets its exact context error
// first), every later acquire fails fixed, and Close completes without
// hanging — the one broken handle cannot deadlock the retained pool. The
// ORIGINAL panic propagates. On the pre-fix code the rollback error is
// discarded, the broken connection is released into the pool, and the
// blocked acquirer receives it — RED.
func TestRound6RollbackFailurePanicPoisonsAndWakesBlockedAcquirers(t *testing.T) {
	svc, _ := newTestServicePoolSize(t, 1)
	ctx := context.Background()

	inFn := make(chan struct{})
	goFn := make(chan struct{})
	var goOnce sync.Once
	releaseFn := func() { goOnce.Do(func() { close(goFn) }) }
	defer releaseFn() // unblock the callback on ANY exit, so Cleanup's Close never hangs
	panicCh := make(chan any, 1)
	go func() {
		defer func() { panicCh <- recover() }()
		_ = svc.withTx(ctx, func(conn *sql.Conn) error {
			close(inFn)
			<-goFn
			_ = conn.Close() // the connection breaks mid-transaction
			panic("rollback boom")
		})
	}()
	waitChan(t, inFn, "callback to hold the single connection")

	// A canceled blocked acquirer must resolve with its EXACT context error.
	wctx, wcancel := context.WithCancel(ctx)
	waiterCtxErr := make(chan error, 1)
	go func() { _, err := svc.pool.acquire(wctx); waiterCtxErr <- err }()
	waitBorrowed(t, svc.pool, 2)
	wcancel()
	select {
	case err := <-waiterCtxErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled blocked acquirer returned %v, want exact context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled blocked acquirer never resolved")
	}
	waitBorrowed(t, svc.pool, 1)

	// A plain blocked acquirer is parked on the empty channel; it releases
	// any handle it ever wins so Close can never hang on it.
	waiterErr := make(chan error, 1)
	go func() {
		c, err := svc.pool.acquire(ctx)
		if err == nil {
			svc.pool.release(c)
		}
		waiterErr <- err
	}()
	waitBorrowed(t, svc.pool, 2)

	// Release the callback: the rollback runs on the broken connection,
	// fails, the pool is poisoned, and the waiter is woken.
	releaseFn()
	select {
	case pv := <-panicCh:
		if pv != "rollback boom" {
			t.Fatalf("panic identity = %v, want \"rollback boom\"", pv)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("callback panic never propagated")
	}
	select {
	case err := <-waiterErr:
		if !errors.Is(err, ErrDependency) {
			t.Fatalf("RED: blocked acquirer woke with %v, want fixed ErrDependency", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RED: blocked acquirer never woke after poison")
	}

	poisoned, chLen, closedConns := snapPool(svc.pool)
	if !poisoned {
		t.Fatal("RED: pool not poisoned after a failed rollback")
	}
	if chLen != 0 {
		t.Fatalf("RED: broken connection returned to the size-1 pool (channel holds %d)", chLen)
	}
	if closedConns != 1 {
		t.Fatalf("RED: broken connection closed %d times, want exactly once", closedConns)
	}
	if _, err := svc.pool.acquire(ctx); !errors.Is(err, ErrDependency) {
		t.Fatalf("acquire after poison: %v, want fixed ErrDependency", err)
	}
	// Close joins the same completion and cannot hang on the retired handle.
	closeDone := make(chan struct{})
	go func() { svc.Close(); close(closeDone) }()
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("service Close hung after pool poison")
	}
}

// TestRound6RollbackFailureOrdinaryPathReportsFixedDependency proves the
// ordinary (non-panic) rollback-failure contract on a pool of size 2: the
// callback fails with a broken connection; the failed connection is NEVER
// returned to the pool (the channel keeps exactly the one healthy handle),
// the service reports only the fixed data-free dependency (the raw callback
// fault never surfaces), later acquires fail fixed, and Close drains the
// healthy handle and completes. On the pre-fix code the raw error is
// returned, the pool is not poisoned, and the broken connection sits in the
// channel — RED.
func TestRound6RollbackFailureOrdinaryPathReportsFixedDependency(t *testing.T) {
	svc, _ := newTestServicePoolSize(t, 2)
	pool := svc.pool // Close nils svc.pool; keep the reference for post-close accounting.
	ctx := context.Background()
	_ = mustCreate(t, svc, "backend/api", "user:alice")

	err := svc.withTx(ctx, func(conn *sql.Conn) error {
		if _, cerr := conn.ExecContext(ctx, `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token)
			 values ('`+seedID(7777)+`', 'backend/api', 'user:alice', 'creating', 0, 1, 2, ?)`, seedToken()); cerr != nil {
			return cerr
		}
		_ = conn.Close()
		return errors.New("raw callback fault that must never surface")
	})
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("RED: ordinary rollback failure reported %v, want fixed ErrDependency", err)
	}
	if err.Error() != ErrDependency.Error() {
		t.Fatalf("RED: reported error leaks raw detail: %q", err.Error())
	}

	poisoned, chLen, closedConns := snapPool(pool)
	if !poisoned {
		t.Fatal("RED: pool not poisoned after an ordinary rollback failure")
	}
	if chLen != 1 {
		t.Fatalf("RED: failed connection returned to the pool (channel holds %d, want 1 healthy)", chLen)
	}
	if closedConns != 1 {
		t.Fatalf("RED: failed connection closed %d times, want exactly once", closedConns)
	}
	if _, err := pool.acquire(ctx); !errors.Is(err, ErrDependency) {
		t.Fatalf("acquire after poison: %v, want fixed ErrDependency", err)
	}

	closeDone := make(chan struct{})
	go func() { svc.Close(); close(closeDone) }()
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("service Close hung after pool poison")
	}
	_, _, closedAfter := snapPool(pool)
	if closedAfter != 2 {
		t.Fatalf("after Close %d handles were pool-closed, want exactly 2 (bad once, healthy once)", closedAfter)
	}
}
