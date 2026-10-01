package staging

// Round 6 RED probes: deterministic production-path checks for serialized
// staging panic recovery (repair 3): file restoration that runs INSIDE the
// transaction attempt while the BEGIN IMMEDIATE write lock is held, exact
// panic identity preservation, cleanup-uncertainty poisoning of the pool,
// rollback-failure connection retirement, and commit-success behavior.
// Several of these tests are RED on the pre-fix code (they fail but never
// pass); they are committed as behavioral contracts that must stay green.

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestServiceOn builds a fresh service over the SAME private directory,
// so independent service instances share one spool and one database.
func newTestServiceOn(t *testing.T, dir string) *service {
	t.Helper()
	svc, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("NewService on shared dir: %v", err)
	}
	t.Cleanup(func() { svc.Close() })
	return svc
}

// newTestServicePoolSize builds a service whose retained pool has exactly
// size connections — the strongest reuse contract for panic-pool tests.
func newTestServicePoolSize(t *testing.T, size int) (*service, string) {
	t.Helper()
	dir := tempPrivate(t)
	spoolRoot := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")
	sp, err := newSpool(context.Background(), spoolRoot)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	pool, err := openStagingPool(context.Background(), dbPath, size)
	if err != nil {
		sp.Close()
		t.Fatalf("open pool size %d: %v", size, err)
	}
	svc := &service{spool: sp, pool: pool, now: time.Now, creationLease: creationLease}
	svc.spool.syncFile = func(f *os.File) error { return svc.syncFile(f) }
	if err := svc.reconcileStartup(context.Background()); err != nil {
		pool.close()
		sp.Close()
		t.Fatalf("reconcile: %v", err)
	}
	t.Cleanup(func() { svc.Close() })
	return svc, dir
}

// panicBeforeBytesReader panics on its very first Read — no byte is ever
// written before the panic.
type panicBeforeBytesReader struct{ sentinel string }

func (r *panicBeforeBytesReader) Read(p []byte) (int, error) { panic(r.sentinel) }

// sentinelPartialReader writes some bytes then panics with a caller-chosen
// value, so a test can assert the EXACT original panic identity after a
// partial-body panic.
type sentinelPartialReader struct {
	remaining int
	sentinel  string
}

func (r *sentinelPartialReader) Read(p []byte) (int, error) {
	if r.remaining > 0 {
		n := min(r.remaining, len(p))
		for i := 0; i < n; i++ {
			p[i] = 'x'
		}
		r.remaining -= n
		return n, nil
	}
	panic(r.sentinel)
}

// gatedReader passes reads through to a delegate and closes a gate channel
// exactly once on the first Read, so a test can observe deterministically
// whether a concurrent append ever began consuming its source.
type gatedReader struct {
	r    io.Reader
	once sync.Once
	gate chan struct{}
}

func (g *gatedReader) Read(p []byte) (int, error) {
	g.once.Do(func() { close(g.gate) })
	return g.r.Read(p)
}

// waitChan is a bounded wait on a channel that must close.
func waitChan(t *testing.T, ch chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// ---------------------------------------------------------------------------
// RED 1: an interrupted append's file restoration runs INSIDE the write lock
// ---------------------------------------------------------------------------

// TestRound6TwoServicePanicRestoreHoldsWriteLock proves requirement 1
// deterministically: first service's Append writes a tail then panics; its
// cleanup is paused mid-flight (at the fsync inside the file restoration).
// A SECOND independent service appending at the same offset must remain
// blocked by the first service's BEGIN IMMEDIATE — it may neither begin
// reading nor commit — until the first has truncated+synced and rolled back.
// After release the second commits and the exact final bytes/offset contain
// ONLY the second append; the first's cleanup runs exactly once and its
// original panic value propagates.
//
// On the pre-fix code the first service's file restoration runs in the outer
// Append defer AFTER withTx has already rolled back and released the
// serialization: the second service begins reading and commits while the
// first's cleanup is still paused — RED.
func TestRound6TwoServicePanicRestoreHoldsWriteLock(t *testing.T) {
	dir := tempPrivate(t)
	svc1 := newTestServiceOn(t, dir)
	svc2 := newTestServiceOn(t, dir)
	ctx := context.Background()
	s := mustCreate(t, svc1, "backend/api", "user:alice")

	const secondBytes = "SECOND-COMMIT"

	// Pause svc1's file restoration at its fsync, before the rollback.
	var syncCalls atomic.Int32
	cleanupSync := make(chan struct{})
	releaseCleanup := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCleanup) }) }
	defer release() // unblock the panicked append on ANY exit, so Cleanup's Close never hangs
	svc1.fsyncHook = func() error {
		if syncCalls.Add(1) == 1 {
			close(cleanupSync)
			<-releaseCleanup
		}
		return nil
	}
	defer func() { svc1.fsyncHook = nil }()

	panicCh := make(chan any, 1)
	go func() {
		defer func() { panicCh <- recover() }()
		_, _ = svc1.Append(ctx, s.ID, s.Repo, s.Actor, 0, &panicAfterBytesReader{remaining: 3}, 4096)
	}()
	waitChan(t, cleanupSync, "first service cleanup to reach its fsync")

	gate := make(chan struct{})
	src := &gatedReader{r: strings.NewReader(secondBytes), gate: gate}
	type appRes struct {
		sess Session
		err  error
	}
	svc2Done := make(chan appRes, 1)
	go func() {
		se, err := svc2.Append(ctx, s.ID, s.Repo, s.Actor, 0, src, 4096)
		svc2Done <- appRes{se, err}
	}()

	// The second append must be blocked by the first's write lock: it may
	// not begin reading nor complete while the first's cleanup is paused.
	select {
	case <-gate:
		t.Fatal("RED: second service began reading its source while the first append's restoration held the write lock")
	case <-time.After(200 * time.Millisecond):
	}
	select {
	case r := <-svc2Done:
		t.Fatalf("RED: second append completed while the first cleanup held the write lock: %+v", r)
	case <-time.After(200 * time.Millisecond):
	}

	close(releaseCleanup)
	releaseOnce.Do(func() {}) // mark consumed (idempotent with the defer)

	select {
	case r := <-svc2Done:
		if r.err != nil {
			t.Fatalf("second append after serialization release: %v", r.err)
		}
		if r.sess.Offset != int64(len(secondBytes)) {
			t.Fatalf("second append offset = %d, want %d", r.sess.Offset, len(secondBytes))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second append never completed after the first rolled back")
	}

	// The ORIGINAL panic value propagates to the first caller.
	select {
	case pv := <-panicCh:
		if pv != "reader boom" {
			t.Fatalf("first append panic identity = %v, want \"reader boom\"", pv)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first append panic never propagated")
	}

	if n := syncCalls.Load(); n != 1 {
		t.Fatalf("first cleanup ran %d times, want exactly once", n)
	}

	// Exact final bytes: only the second append, never truncated later.
	data, err := os.ReadFile(filepath.Join(dir, "spool", s.ID))
	if err != nil {
		t.Fatalf("read final spool bytes: %v", err)
	}
	if string(data) != secondBytes {
		t.Fatalf("RED: final bytes = %q, want ONLY %q (first cleanup must not erase them)", data, secondBytes)
	}
	st, err := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
	if err != nil || st.Offset != int64(len(secondBytes)) {
		t.Fatalf("final committed offset: %d err=%v", st.Offset, err)
	}
	// Stability guard: nothing may truncate the committed bytes later.
	time.Sleep(150 * time.Millisecond)
	data2, _ := os.ReadFile(filepath.Join(dir, "spool", s.ID))
	if string(data2) != secondBytes {
		t.Fatalf("committed bytes changed after completion: %q", data2)
	}
}

// ---------------------------------------------------------------------------
// RED 2: panic identity and committed state across every panic point
// ---------------------------------------------------------------------------

// TestRound6PanicIdentityPointsKeepPoolUsableSingleConn drives a panic at
// every operation stage — reader before bytes, reader after partial bytes,
// after the file sync (db write hook), a direct transaction callback, and
// the commit hook — on a pool with EXACTLY ONE retained connection, so the
// released connection is deterministically the one reused. Each panic must
// propagate the EXACT original value, leave DB offset/state and file bytes
// exactly at the committed state, and leave the single-connection pool fully
// usable: the very same physical connection is acquired, BEGINs, and commits
// next with no pollution.
func TestRound6PanicIdentityPointsKeepPoolUsableSingleConn(t *testing.T) {
	cases := []struct {
		name     string
		sentinel string
		run      func(t *testing.T, svc *service, s Session, sentinel string)
	}{
		{
			name: "reader_panics_before_any_byte",
			run: func(t *testing.T, svc *service, s Session, sentinel string) {
				recoverAppend(t, svc, s, &panicBeforeBytesReader{sentinel: sentinel}, sentinel)
			},
		},
		{
			name: "reader_panics_after_partial_bytes",
			run: func(t *testing.T, svc *service, s Session, sentinel string) {
				recoverAppend(t, svc, s, &sentinelPartialReader{remaining: 3, sentinel: sentinel}, sentinel)
			},
		},
		{
			name: "hook_panics_after_file_sync",
			run: func(t *testing.T, svc *service, s Session, sentinel string) {
				svc.dbWriteHook = func() error { panic(sentinel) }
				defer func() { svc.dbWriteHook = nil }()
				recoverAppend(t, svc, s, strings.NewReader("tail"), sentinel)
			},
		},
		{
			name: "transaction_callback_panics",
			run: func(t *testing.T, svc *service, s Session, sentinel string) {
				func() {
					defer func() {
						if r := recover(); r != sentinel {
							t.Fatalf("callback panic identity = %v, want %q", r, sentinel)
						}
					}()
					_ = svc.withTx(context.Background(), func(conn *sql.Conn) error { panic(sentinel) })
				}()
			},
		},
		{
			name: "commit_hook_panics",
			run: func(t *testing.T, svc *service, s Session, sentinel string) {
				svc.commitHook = func() error { panic(sentinel) }
				defer func() { svc.commitHook = nil }()
				recoverAppend(t, svc, s, strings.NewReader("tail"), sentinel)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, dir := newTestServicePoolSize(t, 1)
			ctx := context.Background()
			s := mustCreate(t, svc, "backend/api", "user:alice")
			s = mustAppend(t, svc, s, "stable")

			sentinel := "boom-" + tc.name
			tc.run(t, svc, s, sentinel)

			// Committed state untouched: offset and file bytes exact.
			st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor)
			if err != nil || st.Offset != int64(len("stable")) {
				t.Fatalf("committed offset changed by a panicked operation: %d err=%v", st.Offset, err)
			}
			assertSpoolSize(t, svc, s.ID, int64(len("stable")))
			// The SAME single-connection pool serves the next transaction.
			s = mustAppend(t, svc, s, "ok")
			if s.Offset != int64(len("stableok")) {
				t.Fatalf("post-panic offset = %d, want %d", s.Offset, len("stableok"))
			}
			if got := mustOpenAll(t, svc, s); got != "stableok" {
				t.Fatalf("post-panic bytes = %q, want %q", got, "stableok")
			}
			_ = dir
		})
	}
}

// recoverAppend runs an Append that must panic, asserting the EXACT value.
func recoverAppend(t *testing.T, svc *service, s Session, src io.Reader, sentinel string) {
	t.Helper()
	defer func() {
		if r := recover(); r != sentinel {
			t.Fatalf("panic identity = %v, want %q", r, sentinel)
		}
	}()
	_, _ = svc.Append(context.Background(), s.ID, s.Repo, s.Actor, s.Offset, src, 4096)
}
