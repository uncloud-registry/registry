package staging

// Round 6 RED probes, part 3: commit-success behavior. A durable COMMIT
// disables the rollback entirely (the file restoration NEVER runs again on a
// committed append), and a cancellation that lands after the durable commit
// never falsifies the committed result — the exact context error applies
// only to SUBSEQUENT operations. Existing normal Append semantics stay
// unchanged.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestRound6CommitSuccessDisablesRollback proves the rollback/restoration is
// disabled once the transaction commits durably: on a single-connection pool
// the committed append is never truncated again (the restoration hook must
// not fire at all), the offset and file bytes are exact, and the very same
// connection serves the next transaction with no pollution.
func TestRound6CommitSuccessDisablesRollback(t *testing.T) {
	svc, _ := newTestServicePoolSize(t, 1)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")

	// If the deferred protocol ran the restoration after a durable commit it
	// would truncate committed bytes; the hook proves it never does.
	svc.truncateHook = func() error {
		t.Fatal("restoration ran after a durable commit")
		return nil
	}
	s = mustAppend(t, svc, s, "durable")
	svc.truncateHook = nil

	if s.Offset != int64(len("durable")) {
		t.Fatalf("offset = %d, want %d", s.Offset, len("durable"))
	}
	if got := mustOpenAll(t, svc, s); got != "durable" {
		t.Fatalf("committed bytes = %q, want %q", got, "durable")
	}
	// The SAME single connection serves the next transaction: no rollback
	// residue, no pollution.
	s2, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("more"), 100)
	if err != nil {
		t.Fatalf("next append after commit-success: %v", err)
	}
	if s2.Offset != int64(len("durablemore")) {
		t.Fatalf("offset after next append = %d, want %d", s2.Offset, len("durablemore"))
	}
	if got := mustOpenAll(t, svc, s2); got != "durablemore" {
		t.Fatalf("bytes after next append = %q", got)
	}
}

// TestRound6CancellationAfterCommitKeepsCommittedResult proves a
// cancellation that lands AFTER the durable commit never turns the committed
// append into a reported failure: the result stands, and the exact context
// error is authoritative only for SUBSEQUENT operations (never for the
// already-committed one).
func TestRound6CancellationAfterCommitKeepsCommittedResult(t *testing.T) {
	svc, _ := newTestServicePoolSize(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "committed")
	cancel() // cancellation lands strictly after the durable commit

	// The committed append stays successful and intact.
	if got := mustOpenAll(t, svc, s); got != "committed" {
		t.Fatalf("committed bytes falsified by a later cancellation: %q", got)
	}
	if st, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); err != nil || st.Offset != s.Offset {
		t.Fatalf("committed offset falsified by a later cancellation: %d err=%v", st.Offset, err)
	}
	// A SUBSEQUENT operation on the canceled context fails with the EXACT
	// context error — the caller's cancellation is authoritative going
	// forward, but never retroactively.
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("x"), 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled subsequent append: %v, want exact context.Canceled", err)
	}
	if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled subsequent status: %v, want exact context.Canceled", err)
	}
}

// TestRound6NormalAppendSemanticsUnchanged pins the ordinary append
// contract: streamed bounded bytes, exact committed offset, durable order,
// idempotent offset matching, and rejections.
func TestRound6NormalAppendSemanticsUnchanged(t *testing.T) {
	svc, _ := newTestServicePoolSize(t, 1)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")

	// Exact committed offset required; a stale one is rejected untouched.
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, 1, strings.NewReader("x"), 100); !errors.Is(err, ErrOffsetMismatch) {
		t.Fatalf("stale expected offset: %v, want ErrOffsetMismatch", err)
	}
	s = mustAppend(t, svc, s, "payload")
	if got := mustOpenAll(t, svc, s); got != "payload" {
		t.Fatalf("bytes = %q", got)
	}
	if st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); err != nil || st.Offset != s.Offset {
		t.Fatalf("status offset mismatch: %d err=%v", st.Offset, err)
	}
}
