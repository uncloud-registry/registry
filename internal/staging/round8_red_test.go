package staging

// Round 8 RED probes: ordinary (non-panic) append restoration failure must
// poison the staging service BEFORE the connection's serialization is
// released. On the pre-fix code a FAILING tail restoration on an ordinary
// primary-error path (e.g. the db write hook faults) merely folded into the
// returned error while the pool stayed usable — a later Overlay Status then
// returned the committed offset as if the file were durable. Requirement:
// ANY failed tail restoration — the truncate OR the settle fsync — means the
// file's durability is uncertain, so the pool is atomically quarantined, the
// broken handle retired (never re-enters the pool), blocked waiters wake with
// the fixed data-free ErrDependency, the exact context sentinel still wins
// when the caller's own context fired, every future operation through this
// live service fails closed, and a FRESH restart reconciles (truncating the
// tail) or fails closed. A SUCCESSFUL restoration keeps the ordinary error
// path healthy: clean pool, exact old bytes/offset, later appends work.

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Round 8 RED 1: ordinary write-hook fault + truncate-restoration fault
// poisons the service, wakes a blocked waiter, and reconciles on restart
// ---------------------------------------------------------------------------

// TestRound8OrdinaryRestoreTruncateFaultPoisonsAndWakes drives an ordinary
// (non-panic) primary failure — the db write hook faults after partial bytes
// are on disk — together with a truncate-restoration fault. The cleanup
// cannot confirm the tail is gone, so the pool must be atomically poisoned
// BEFORE the connection's serialization is released: a blocked acquirer wakes
// with the fixed data-free ErrDependency, Status/Append fail fixed, Close
// completes without hanging, the broken handle never re-enters the pool, and
// a FRESH service restart truncates the leftover tail and reconciles to the
// exact committed bytes. Red on the pre-fix code, which returns ErrDependency
// but leaves the pool usable.
func TestRound8OrdinaryRestoreTruncateFaultPoisonsAndWakes(t *testing.T) {
	for _, size := range []int{1, 2} {
		size := size
		t.Run(itoaSize(size), func(t *testing.T) {
			t.Parallel()
			svc, dir := newTestServicePoolSize(t, size)
			ctx := context.Background()
			s := mustCreate(t, svc, "backend/api", "user:alice")
			s = mustAppend(t, svc, s, "stable")

			// Hold the single/one connection inside the append so a blocked
			// acquirer can deterministically park, then land the ordinary
			// primary fault and the restoration truncate fault.
			inAppend := make(chan struct{})
			release := make(chan struct{})
			var relOnce sync.Once
			svc.dbWriteHook = func() error {
				close(inAppend)
				<-release
				return errors.New("inject ordinary update fault")
			}
			svc.truncateHook = func() error { return errors.New("inject ordinary restore truncate fault") }

			appErr := make(chan error, 1)
			go func() {
				_, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("boom"), 100)
				appErr <- err
			}()
			waitChan(t, inAppend, "append to hold the connection before the primary fault")

			// A blocked acquirer parks only when the pool is truly exhausted
			// (size 1): with a spare handle it would grab it and return nil,
			// which is not the wake contract under test.
			var waiterErr chan error
			if size == 1 {
				waiterErr = make(chan error, 1)
				go func() {
					c, err := svc.pool.acquire(ctx)
					if err == nil {
						svc.pool.release(c)
					}
					waiterErr <- err
				}()
				waitBorrowed(t, svc.pool, 2)
			}

			close(release)
			relOnce.Do(func() {})

			// The append reports ONLY the fixed data-free dependency.
			select {
			case err := <-appErr:
				if !errors.Is(err, ErrDependency) {
					t.Fatalf("RED: ordinary restore fault append reported %v, want fixed ErrDependency", err)
				}
				if err.Error() != ErrDependency.Error() {
					t.Fatalf("RED: poison error leaks detail: %q, want %q", err.Error(), ErrDependency.Error())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("append never resolved after an ordinary restore fault")
			}
			// The blocked acquirer (size 1) wakes with the SAME fixed answer.
			if waiterErr != nil {
				select {
				case err := <-waiterErr:
					if !errors.Is(err, ErrDependency) {
						t.Fatalf("RED: blocked acquirer woke with %v, want fixed ErrDependency", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("RED: blocked acquirer never woke after an ordinary restore-fault poison")
				}
			}

			poisoned, chLen, _ := snapPool(svc.pool)
			if !poisoned {
				t.Fatal("RED: pool not poisoned after an ordinary restore truncate fault")
			}
			// On a size-1 pool the broken handle was retired, not returned. On a
			// size-2 pool the spare handle is a non-reusable quarantine: it is
			// never handed out (Status/Append below fail fixed) — it is only
			// drained and closed by Close. Neither leaves the pool usable.
			if size == 1 && chLen != 0 {
				t.Fatalf("broken connection returned to the size-1 pool (channel holds %d)", chLen)
			}
			// Status and a later Append fail fixed and data-free.
			if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrDependency) || err.Error() != ErrDependency.Error() {
				t.Fatalf("RED: status after ordinary restore-fault poison: %v", err)
			}
			if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("x"), 100); !errors.Is(err, ErrDependency) {
				t.Fatalf("RED: append after ordinary restore-fault poison: %v", err)
			}

			// Close joins the single completion; the retired handle cannot deadlock it.
			closeDone := make(chan struct{})
			go func() { svc.Close(); close(closeDone) }()
			select {
			case <-closeDone:
			case <-time.After(5 * time.Second):
				t.Fatal("service Close hung after an ordinary restore-fault poison")
			}

			// A FRESH service reconciles: the leftover partial tail is
			// truncated and the exact committed bytes/offset stand.
			svc2 := newTestServiceOn(t, dir)
			st, err := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
			if err != nil || st.Offset != int64(len("stable")) {
				t.Fatalf("restart after ordinary restore fault: offset=%d err=%v", st.Offset, err)
			}
			if got := mustOpenAll(t, svc2, st); got != "stable" {
				t.Fatalf("RED: restart accepted a corrupted tail after ordinary restore fault: %q", got)
			}
			assertSpoolSize(t, svc2, s.ID, int64(len("stable")))
		})
	}
}

// ---------------------------------------------------------------------------
// Round 8 RED 2: ordinary primary failure + restoration FSYNC failure poisons
// ---------------------------------------------------------------------------

// TestRound8OrdinaryRestoreFsyncFaultPoisons forces an ordinary primary
// failure then a failed restore-time fsync: the tail was truncated but its
// durability cannot be confirmed, so the pool is atomically poisoned, later
// operations fail fixed/data-free, Close completes, and a fresh restart
// reconciles to the exact committed bytes. Red on the pre-fix code, which
// keeps the pool usable.
func TestRound8OrdinaryRestoreFsyncFaultPoisons(t *testing.T) {
	for _, size := range []int{1, 2} {
		size := size
		t.Run(itoaSize(size), func(t *testing.T) {
			t.Parallel()
			svc, dir := newTestServicePoolSize(t, size)
			ctx := context.Background()
			s := mustCreate(t, svc, "backend/api", "user:alice")
			s = mustAppend(t, svc, s, "stable")

			// The MAIN-path fsync (call 1) succeeds so the primary failure is
			// delivered by the write hook; the RESTORE fsync (call 2) faults.
			var syncCalls atomic.Int32
			svc.fsyncHook = func() error {
				if syncCalls.Add(1) == 2 {
					return errors.New("inject restore fsync fault")
				}
				return nil
			}
			svc.dbWriteHook = func() error { return errors.New("inject ordinary update fault") }

			_, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("boom"), 100)
			if !errors.Is(err, ErrDependency) || err.Error() != ErrDependency.Error() {
				t.Fatalf("RED: ordinary restore-fsync fault reported %v, want fixed data-free ErrDependency", err)
			}
			poisoned, _, _ := snapPool(svc.pool)
			if !poisoned {
				t.Fatal("RED: pool not poisoned after an ordinary restore fsync fault")
			}
			if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrDependency) {
				t.Fatalf("status after restore-fsync poison: %v", err)
			}
			if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("x"), 100); !errors.Is(err, ErrDependency) {
				t.Fatalf("append after restore-fsync poison: %v", err)
			}

			svc.Close()
			svc2 := newTestServiceOn(t, dir)
			st, err := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
			if err != nil || st.Offset != int64(len("stable")) {
				t.Fatalf("restart after restore-fsync fault: offset=%d err=%v", st.Offset, err)
			}
			if got := mustOpenAll(t, svc2, st); got != "stable" {
				t.Fatalf("RED: restart accepted a corrupted tail after restore-fsync fault: %q", got)
			}
			assertSpoolSize(t, svc2, s.ID, int64(len("stable")))
		})
	}
}

// ---------------------------------------------------------------------------
// Round 8 RED 3: an ordinary primary failure with a SUCCESSFUL restoration
// does NOT poison — the pool stays healthy and later appends work
// ---------------------------------------------------------------------------

// TestRound8OrdinaryRestoreSuccessDoesNotPoison proves the ordinary (non-
// panic) error path stays exactly healthy when the restoration succeeds: an
// ordinary primary failure (the write hook faults) with a clean truncate+fsync
// restore returns its normal fixed classification, the pool is NOT poisoned,
// the device reports the exact old bytes/offset, and a later append on the
// SAME service works. This pins the boundary of the new rule — only an
// UNCERTAIN restoration poisons.
func TestRound8OrdinaryRestoreSuccessDoesNotPoison(t *testing.T) {
	for _, size := range []int{1, 2} {
		size := size
		t.Run(itoaSize(size), func(t *testing.T) {
			t.Parallel()
			svc, dir := newTestServicePoolSize(t, size)
			ctx := context.Background()
			s := mustCreate(t, svc, "backend/api", "user:alice")
			s = mustAppend(t, svc, s, "stable")

			// No truncate/fsync fault: the restore truncates and fsyncs cleanly.
			svc.dbWriteHook = func() error { return errors.New("inject ordinary update fault") }
			_, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("boom"), 100)
			if !errors.Is(err, ErrDependency) || err.Error() != ErrDependency.Error() {
				t.Fatalf("ordinary write-hook fault with successful restore reported %v, want fixed ErrDependency", err)
			}
			svc.dbWriteHook = nil

			poisoned, _, _ := snapPool(svc.pool)
			if poisoned {
				t.Fatal("RED: pool poisoned by an ordinary failure whose restoration SUCCEEDED")
			}
			// The session still reports exactly the pre-append bytes/offset.
			st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor)
			if err != nil || st.Offset != int64(len("stable")) {
				t.Fatalf("status after successful-restore ordinary fault: offset=%d err=%v", st.Offset, err)
			}
			if got := mustOpenAll(t, svc, st); got != "stable" {
				t.Fatalf("bytes after successful-restore ordinary fault: %q", got)
			}
			// The SAME live service keeps working.
			s2 := mustAppend(t, svc, s, "-next")
			if s2.Offset != int64(len("stable-next")) {
				t.Fatalf("later append offset = %d, want %d", s2.Offset, len("stable-next"))
			}
			if got := mustOpenAll(t, svc, s2); got != "stable-next" {
				t.Fatalf("later append bytes = %q", got)
			}
			_ = dir
		})
	}
}

// ---------------------------------------------------------------------------
// Round 8 RED 4: cleanup failure + actual ctx cancellation returns the exact
// context sentinel externally while still poisoning internally
// ---------------------------------------------------------------------------

// TestRound8OrdinaryRestoreFaultWithContextCancellationReturnsSentinel drives
// an ordinary primary failure and a restoration truncate fault whose hook also
// cancels the caller's context. The EXACT context error must surface to the
// caller, yet the pool is STILL poisoned internally (a blocked/fresh acquire
// fails fixed) — context authority is preserved without weakening durability
// quarantine.
func TestRound8OrdinaryRestoreFaultWithContextCancellationReturnsSentinel(t *testing.T) {
	svc, _ := newTestServicePoolSize(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "stable")

	svc.dbWriteHook = func() error { return errors.New("inject ordinary update fault") }
	svc.truncateHook = func() error {
		cancel() // the caller's own context fires during the restoration
		return errors.New("inject restore truncate fault")
	}

	_, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("boom"), 100)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RED: cleanup failure with canceled ctx reported %v, want exact context.Canceled", err)
	}
	if err.Error() != context.Canceled.Error() {
		t.Fatalf("RED: context sentinel not exact externally: %q", err.Error())
	}
	// The pool is poisoned INTERNALLY regardless of the external sentinel.
	poisoned, _, _ := snapPool(svc.pool)
	if !poisoned {
		t.Fatal("RED: pool not poisoned internally while ctx cancellation surfaced externally")
	}
	if _, err := svc.pool.acquire(context.Background()); !errors.Is(err, ErrDependency) {
		t.Fatalf("acquire after ctx-cancel poison: %v, want fixed ErrDependency", err)
	}
}

// ---------------------------------------------------------------------------
// Round 8 RED 5: high-count / race under contention on a larger pool
// ---------------------------------------------------------------------------

// TestRound8OrdinaryRestoreFaultPoisonUnderContention runs many independent
// concurrent appends on a pool of size 4 with a ONE-SHOT ordinary primary
// fault and an always-failing restoration truncate fault. Exactly one append
// triggers the uncertainty, atomically poisoning the pool; every other result
// is either a durable commit (nil) or the fixed data-free ErrDependency (a
// poisoned acquire, or the poisoned restore). Close completes, and a fresh
// restart reconciles every session to its exact committed bytes (each partial
// tail is truncated, never accepted as data). Exercised with -race.
func TestRound8OrdinaryRestoreFaultPoisonUnderContention(t *testing.T) {
	svc, dir := newTestServicePoolSize(t, 4)
	ctx := context.Background()
	const n = 16
	sess := make([]Session, n)
	for i := 0; i < n; i++ {
		sess[i] = mustCreate(t, svc, "backend/api", "user:alice")
		sess[i] = mustAppend(t, svc, sess[i], "stable")
	}

	// ONE-SHOT ordinary primary fault and an always-failing restore fault.
	var faulted atomic.Bool
	svc.dbWriteHook = func() error {
		if !faulted.Swap(true) {
			return errors.New("one-shot ordinary update fault")
		}
		return nil
	}
	svc.truncateHook = func() error { return errors.New("restore truncate fault") }

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			_, e := svc.Append(ctx, sess[i].ID, sess[i].Repo, sess[i].Actor, sess[i].Offset, strings.NewReader("abc"), 100)
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e == nil {
			continue
		}
		if !errors.Is(e, ErrDependency) {
			t.Fatalf("RED: contention result %v, want nil commit or fixed ErrDependency", e)
		}
		if e.Error() != ErrDependency.Error() {
			t.Fatalf("RED: contention error leaks detail: %q", e.Error())
		}
	}
	poisoned, _, _ := snapPool(svc.pool)
	if !poisoned {
		t.Fatal("RED: pool not poisoned after an ordinary restore fault under contention")
	}
	if _, err := svc.Append(ctx, sess[0].ID, sess[0].Repo, sess[0].Actor, sess[0].Offset, strings.NewReader("x"), 100); !errors.Is(err, ErrDependency) {
		t.Fatalf("post-contention append: %v, want fixed ErrDependency", err)
	}

	closeDone := make(chan struct{})
	go func() { svc.Close(); close(closeDone) }()
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("service Close hung after contention poison")
	}

	// Fresh restart reconciles: each session's file is truncated to its exact
	// committed offset (either 6 or 9) and never accepts a partial tail.
	svc2 := newTestServiceOn(t, dir)
	for i := 0; i < n; i++ {
		st, err := svc2.Status(ctx, sess[i].ID, sess[i].Repo, sess[i].Actor)
		if err != nil {
			t.Fatalf("restart status session %d: %v", i, err)
		}
		wantLen := len("stable")
		if st.Offset == int64(len("stableabc")) {
			wantLen = len("stableabc")
		} else if st.Offset != int64(wantLen) {
			t.Fatalf("session %d committed offset %d is neither 6 nor 9", i, st.Offset)
		}
		assertSpoolSize(t, svc2, sess[i].ID, st.Offset)
		want := "stable"
		if wantLen == len("stableabc") {
			want = "stableabc"
		}
		if got := mustOpenAll(t, svc2, st); got != want {
			t.Fatalf("RED: session %d restart accepted a corrupted tail: %q, want %q", i, got, want)
		}
	}
}

// itoaSize names a pool-size subtest.
func itoaSize(n int) string {
	return "pool-" + strconv.Itoa(n)
}
