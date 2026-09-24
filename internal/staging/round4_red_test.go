package staging

// Round 4 RED probes: deterministic behavioral checks for the four review
// classes, run against the pre-fix code to capture RED evidence before the
// Round 4 implementation. They are production-path tests of the FINAL
// contracts and pass once the fixes land — no deliberately failing tests are
// committed.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// seedID returns a canonical 64-hex session id derived from n.
func seedID(n int) string { return fmt.Sprintf("%064x", n) }

// seedToken returns a canonical 64-hex create token.
func seedToken() string { return strings.Repeat("9a", 32) }

// ---------------------------------------------------------------------------
// RED 1: post-activation cleanup must never roll back user data
// ---------------------------------------------------------------------------

// RED 1a: once activation is durably committed it is the point of no return.
// A failure of the post-activation token-sidecar cleanup must NOT roll the
// committed session back: user bytes appended between the activation commit
// and the cleanup failure must survive, the row must stay active, and Create
// must truthfully return the committed session. The pre-fix code tombstones
// the active row and unlinks the canonical payload on PhaseR failure —
// deleting bytes a concurrent Append already accepted.
func TestRound4REDPostActivationCleanupPreservesAppendedBytes(t *testing.T) {
	ctx := context.Background()
	svc, dir := newTestService(t)

	// Append a payload AFTER the activation commit but BEFORE the token-file
	// removal phase — the exact window the pre-fix rollback destroys.
	var appErr error
	svc.postActivateHook = func() {
		entries, err := os.ReadDir(filepath.Join(dir, "spool"))
		if err != nil {
			appErr = err
			return
		}
		var id string
		for _, en := range entries {
			if strings.HasSuffix(en.Name(), ".tok") {
				id = strings.TrimSuffix(en.Name(), ".tok")
			}
		}
		if id == "" {
			appErr = errors.New("no token file at the post-activation hook")
			return
		}
		_, appErr = svc.Append(ctx, id, "backend/api", "user:alice", 0, strings.NewReader("user-payload-bytes"), 4096)
	}
	var syncs atomic.Int32
	svc.dirSyncHook = func() error {
		// 1 = after the token file create, 2 = after the canonical file
		// create, 3 = the PhaseR token-removal directory sync.
		if syncs.Add(1) == 3 {
			return errors.New("phaseR token-removal dir sync fault")
		}
		return nil
	}

	s, err := svc.Create(ctx, "backend/api", "user:alice", time.Hour)
	if err != nil {
		t.Fatalf("RED: create must return the committed active session after a cleanup failure, got %v", err)
	}
	if appErr != nil {
		t.Fatalf("append during the cleanup window: %v", appErr)
	}
	got, err := svc.Status(ctx, s.ID, "backend/api", "user:alice")
	if err != nil || got.State != StateActive {
		t.Fatalf("RED: committed active session destroyed by cleanup: %v state=%s", err, got.State)
	}
	rc, sess, err := svc.Open(ctx, s.ID, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("RED: open after cleanup failure: %v", err)
	}
	data, rerr := io.ReadAll(rc)
	rc.Close()
	if rerr != nil || string(data) != "user-payload-bytes" {
		t.Fatalf("RED: appended bytes lost by cleanup: %q err=%v offset=%d", data, rerr, sess.Offset)
	}
}

// RED 1b: when the post-activation cleanup ALSO faults its rollback
// transaction, the pre-fix code ignores the rollback error and reports a
// failure while a durable active row remains. The committed activation must
// be returned truthfully and a restart must converge.
func TestRound4REDCleanupRollbackFaultStillReturnsCommittedSession(t *testing.T) {
	ctx := context.Background()
	svc, dir := newTestService(t)

	// After the point of no return there is NO rollback of a committed
	// activation: post-activation cleanup is best-effort and deferred.
	// Fault exactly the durable phase (the Phase-R token-removal directory
	// sync); the commit count today is only the pre-activation insert and
	// activation transactions, both of which MUST succeed.
	var syncs atomic.Int32
	svc.dirSyncHook = func() error {
		if syncs.Add(1) == 3 {
			return errors.New("phaseR token-removal dir sync fault")
		}
		return nil
	}

	s, err := svc.Create(ctx, "backend/api", "user:alice", time.Hour)
	if err != nil {
		t.Fatalf("RED: committed activation must be returned truthfully even when cleanup and its rollback both fault: %v", err)
	}
	got, err := svc.Status(ctx, s.ID, "backend/api", "user:alice")
	if err != nil || got.State != StateActive {
		t.Fatalf("RED: committed active session not visible after cleanup faults: %v state=%s", err, got.State)
	}
	// A restart converges the pending sidecar cleanup: the token sidecar is
	// gone (its unlink succeeded before the directory sync faulted), so the
	// durable provenance is cleared and the session stays active.
	svc.fsyncHook, svc.dirSyncHook, svc.commitHook = nil, nil, nil
	svc.Close()
	svc2, err := NewService(ctx, filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("RED: restart after cleanup faults: %v", err)
	}
	defer svc2.Close()
	got2, err := svc2.Status(ctx, s.ID, "backend/api", "user:alice")
	if err != nil || got2.State != StateActive {
		t.Fatalf("RED: session lost after restart: %v state=%s", err, got2.State)
	}
}

// ---------------------------------------------------------------------------
// RED 3: panic-safe transactions
// ---------------------------------------------------------------------------

// RED 3a: a panic from a withTx callback must roll the transaction back
// BEFORE the connection is released back to the pool — a handle with BEGIN
// active is never returned. The pre-fix code releases the panicked
// connection with its transaction still open, poisoning the next
// transaction on the same small pool.
func TestRound4REDCallbackPanicLeavesPoolUsable(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	// Hold every connection but one so the panicked connection is the only
	// one the next transaction can acquire — deterministic reuse.
	var held []*sql.Conn
	for i := 0; i < 3; i++ {
		c, err := svc.pool.acquire(ctx)
		if err != nil {
			t.Fatalf("hold %d: %v", i, err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			svc.pool.release(c)
		}
	}()

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("callback panic must propagate to the caller")
			}
		}()
		_ = svc.withTx(ctx, func(conn *sql.Conn) error {
			panic("callback boom")
		})
	}()

	// The SAME small pool must remain fully usable: every subsequent
	// transaction succeeds, proving no connection came back with BEGIN
	// active (a polluted connection makes BEGIN IMMEDIATE busy forever).
	for i := 0; i < 10; i++ {
		id := seedID(1000 + i)
		if err := svc.withTx(ctx, func(conn *sql.Conn) error {
			_, err := conn.ExecContext(ctx,
				`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token)
				 values (?, 'backend/api', 'user:alice', 'creating', 0, 1, 2, ?)`, id, seedToken())
			return err
		}); err != nil {
			t.Fatalf("RED: pool unusable after callback panic (attempt %d): %v", i, err)
		}
	}
}

// panicAfterBytesReader writes a few bytes then panics, simulating a
// client stream that dies mid-body.
type panicAfterBytesReader struct {
	remaining int
}

func (r *panicAfterBytesReader) Read(p []byte) (int, error) {
	if r.remaining > 0 {
		n := min(r.remaining, len(p))
		for i := 0; i < n; i++ {
			p[i] = 'x'
		}
		r.remaining -= n
		return n, nil
	}
	panic("reader boom")
}

// RED 3b: a real Append whose io.Reader panics mid-body must roll the
// transaction back, leave DB offset and spool file bytes at the committed
// state, keep the small pool usable, and still propagate the panic.
func TestRound4REDAppendReaderPanicLeavesCommittedState(t *testing.T) {
	ctx := context.Background()
	svc, dir := newTestService(t)
	s := mustCreate(t, svc, "backend/api", "user:alice")

	var held []*sql.Conn
	for i := 0; i < 3; i++ {
		c, err := svc.pool.acquire(ctx)
		if err != nil {
			t.Fatalf("hold %d: %v", i, err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			svc.pool.release(c)
		}
	}()

	r := &panicAfterBytesReader{remaining: 3}
	func() {
		defer func() {
			if rec := recover(); rec == nil {
				t.Fatal("reader panic must propagate out of Append")
			}
		}()
		_, _ = svc.Append(ctx, s.ID, s.Repo, s.Actor, 0, r, 4096)
	}()

	// Committed metadata unchanged: offset still 0, session still active.
	st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor)
	if err != nil || st.Offset != 0 {
		t.Fatalf("RED: committed offset changed by a panicked append: %v offset=%d", err, st.Offset)
	}
	// The spool file holds no uncommitted bytes and the descriptor is closed.
	fi, lerr := os.Lstat(filepath.Join(dir, "spool", s.ID))
	if lerr != nil {
		t.Fatalf("lstat spool file: %v", lerr)
	}
	if fi.Size() != 0 {
		t.Fatalf("RED: panicked append left %d uncommitted bytes in the spool file", fi.Size())
	}
	// The SAME small pool still serves transactions.
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, 0, strings.NewReader("ok"), 4096); err != nil {
		t.Fatalf("RED: pool unusable after append reader panic: %v", err)
	}
	rc, sess, err := svc.Open(ctx, s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("open after recovery: %v", err)
	}
	data, rerr := io.ReadAll(rc)
	rc.Close()
	if rerr != nil || string(data) != "ok" || sess.Offset != 2 {
		t.Fatalf("RED: committed bytes wrong after recovery: %q err=%v offset=%d", data, rerr, sess.Offset)
	}
}
