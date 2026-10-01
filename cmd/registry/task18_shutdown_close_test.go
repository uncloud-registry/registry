package main

// Task 18 round-1 correction: cancelOnCloseStore must NEVER release the
// underlying staging resources until the cleanup worker has actually exited.
// Previously, when the join deadline expired it conceded and closed the store
// anyway — releasing SQLite/spool under a pass that was still mid-run. This
// test drives a REAL Cleanup.RunOnce over a real durable service parked inside
// its committed-reference dependency, calls Close, and proves: Close blocks
// for the deadline and returns a shutdown error WITHOUT closing the store;
// releasing the pass then retrying Close succeeds; and the underlying store
// close happens-before-proof only fires AFTER the worker's done channel closes.
// No sleeps, no probability: goroutines/channels are joined deterministically.

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/staging"
)

// parkedCommittedRefs is a CommittedRefs provider that parks (blocks) every
// caller inside the committed-reference dependency until release is closed —
// modelling an uncooperative but real committed-state lookup mid-pass. It
// IGNORES ctx cancellation while parked (a truly uncooperative dependency the
// shutdown must NOT close the store underneath), which is exactly the scenario
// the fail-closed Close handles. Once release is closed it returns an empty
// committed set immediately.
type parkedCommittedRefs struct {
	enteredOnce sync.Once
	entered     chan struct{}
	release     <-chan struct{}
}

func newParkedCommittedRefs(release <-chan struct{}) *parkedCommittedRefs {
	return &parkedCommittedRefs{entered: make(chan struct{}), release: release}
}

func (p *parkedCommittedRefs) CommittedRefs(ctx context.Context, repo string) (map[string]struct{}, error) {
	p.enteredOnce.Do(func() { close(p.entered) })
	<-p.release // park until released; deliberately ignores ctx cancellation.
	return map[string]struct{}{}, nil
}

type noopUnpinner struct{}
type noopCommitted struct{}

func (noopCommitted) CommittedRefs(context.Context, string) (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}
func (noopUnpinner) Unpin(context.Context, string) error { return nil }

// seedExpiredFinalizedBlob inserts an expired finalized staged blob directly
// into the live durable staging DB so a real cleanup pass has a candidate to
// reap (and therefore reaches the committed-reference dependency).
func seedExpiredFinalizedBlob(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	defer db.Close()
	now := time.Now().UTC()
	id := strings.Repeat("7f", 32)
	digest := "sha256:" + strings.Repeat("cafe", 16)
	beeRef := strings.Repeat("e7", 32)
	created := now.Add(-2 * time.Hour).UnixNano()
	expires := now.Add(-1 * time.Hour).UnixNano()
	if _, err := db.Exec(
		`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at)
		 values (?, 'backend/api', 'user:alice', 'active', 0, ?, ?)`,
		id, created, expires); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := db.Exec(
		`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at)
		 values (?, 'backend/api', 'user:alice', ?, ?, 0, 'application/octet-stream', ?, ?)`,
		id, digest, beeRef, created, expires); err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	if _, err := db.Exec(
		`update upload_sessions set state='finalized', digest=?, bee_ref=?, media_type=? , size=0 where id=?`,
		digest, beeRef, "application/octet-stream", id); err != nil {
		t.Fatalf("seed finalize: %v", err)
	}
}

func privateDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ucreg-cleanup-*")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	// The staging service fail-closes on any looser/symlinked path. On darwin
	// os.MkdirTemp may sit behind the /var -> /private/var (or /tmp ->
	// /private/tmp) symlink; resolve symlinks so the strict component walk
	// from "/" never trips on a symlink prefix. On Linux /tmp and /var are
	// real directories, so EvalSymlinks returns the path unchanged.
	if r, err := filepath.EvalSymlinks(d); err == nil {
		return r
	}
	return filepath.Clean(d)
}

// errCleanupWorkerBusy (declared in main.go) is the shutdown error returned
// when the join deadline expires while the cleanup worker is still running —
// it NEVER closes the shared staging resources.

// TestCancelOnCloseStoreNeverClosesStoreUnderInFlightPass proves Close returns
// a shutdown error WITHOUT closing the store when the worker is parked past
// the join deadline, then (after release) a retried Close joins and closes the
// store, with worker exit strictly happening-before the store close.
func TestCancelOnCloseStoreNeverClosesStoreUnderInFlightPass(t *testing.T) {
	realTimeout := cleanupShutdownTimeout
	cleanupShutdownTimeout = 150 * time.Millisecond
	defer func() { cleanupShutdownTimeout = realTimeout }()

	dir := privateDir(t)
	svc, err := staging.NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	seedExpiredFinalizedBlob(t, filepath.Join(dir, "staging.db"))

	release := make(chan struct{})
	parked := newParkedCommittedRefs(release)
	closed := make(chan struct{})
	var closedOnce sync.Once
	closeCb := func() error {
		closedOnce.Do(func() { close(closed) })
		return nil
	}

	// A real cleanup pass over the seeded expired blob.
	cleanup, err := staging.NewCleanup(svc, noopUnpinner{}, parked)
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runCleanupLoop(ctx, cleanup, time.Millisecond, 10)

	// Wait until the pass has actually reached (and parked inside) the
	// committed-reference dependency.
	select {
	case <-parked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup pass never reached the parked committed-reference lookup")
	}

	storeClosed := make(chan struct{})
	w := &cancelOnCloseStore{
		cancel: cancel,
		done:   done,
		close: func() error {
			// Assert worker exit happens-before store close.
			select {
			case <-done:
			default:
				t.Error("underlying store close ran before the cleanup worker joined")
			}
			close(storeClosed)
			return closeCb()
		},
	}

	// First Close: the worker is parked past the (short) join deadline, so it
	// must FAIL CLOSED — a shutdown error, and the store's close callback must
	// NOT have run.
	err1 := w.Close()
	if err1 == nil {
		t.Fatal("Close must return a shutdown error while the worker is still parked")
	}
	if !errors.Is(err1, errCleanupWorkerBusy) {
		t.Fatalf("Close error = %v, want errCleanupWorkerBusy", err1)
	}
	select {
	case <-storeClosed:
		t.Fatal("Close released the underlying store while the worker was still running")
	default:
	}
	select {
	case <-closed:
		t.Fatal("underlying store close callback ran before worker exit")
	default:
	}

	// Release the parked pass, then let the loop's done channel close.
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup worker did not exit after the parked dependency was released")
	}

	// Retry Close: now the worker has exited, so it joins and closes the store.
	if err := w.Close(); err != nil {
		t.Fatalf("retried Close after worker exit = %v, want nil", err)
	}
	select {
	case <-storeClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("retried Close never released the underlying store")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("worker exit did not happen before the store close")
	}
}
