package staging

// Task16 repair — the durable per-upload finalization claim (StateFinalizing),
// service level. These tests drive the PRODUCTION durable Service methods
// (never a copied logic) and prove: the claim serializes exactly one winner
// even under concurrency; the claimed snapshot's bytes are frozen (append,
// delete, and expiry all fail closed); a stale hash never claims (offset !=
// size => zero state change); release is legal only from finalizing; and a
// process restart retains the fail-closed uncertainty.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testTok is a valid canonical claim token used by plain active-path finalize
// callers in the wider test suite: the durable service validates the token's
// shape but ignores it for a finalize that starts from active (no claim).
var testTok = strings.Repeat("a", 64)

func claimTestSession(t *testing.T, svc *service, data string) Session {
	t.Helper()
	s := mustCreate(t, svc, seedRepo, seedActor)
	s = mustAppend(t, svc, s, data)
	return s
}

// TestClaimFinalizeSerializesOneWinner drives N concurrent ClaimFinalize calls
// at the same frozen size and proves exactly ONE wins; every loser gets
// ErrInvalidState (already finalizing) with zero mutation, and the winner's
// snapshot offset is frozen.
func TestClaimFinalizeSerializesOneWinner(t *testing.T) {
	svc, _ := newTestService(t)
	s := claimTestSession(t, svc, "hello world")
	const n = 8
	var wg sync.WaitGroup
	wins := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.ClaimFinalize(context.Background(), s.ID, s.Repo, s.Actor, s.Offset)
			wins <- err
		}()
	}
	wg.Wait()
	close(wins)

	ok, invalidState := 0, 0
	for err := range wins {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrInvalidState):
			invalidState++
		default:
			t.Fatalf("unexpected claim error: %v", err)
		}
	}
	if ok != 1 || invalidState != n-1 {
		t.Fatalf("claim winners=%d (want 1) losers=%d (want %d)", ok, invalidState, n-1)
	}
	st, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor)
	if err != nil || st.State != StateFinalizing {
		t.Fatalf("session must be finalizing after a claim winner: %+v err=%v", st, err)
	}
	if st.Offset != int64(len("hello world")) {
		t.Fatalf("frozen offset = %d, want %d", st.Offset, len("hello world"))
	}
}

// TestClaimFinalizeStaleHashNoWrite proves a claim whose size no longer equals
// the durable offset (a concurrent append advanced it after the caller hashed)
// is ErrOffsetMismatch with ZERO state change — no Bee write ever happens on
// stale bytes.
func TestClaimFinalizeStaleHashNoWrite(t *testing.T) {
	svc, _ := newTestService(t)
	s := claimTestSession(t, svc, "aaa")
	// Someone appends more bytes after our (stale) hash of the 3-byte prefix.
	mustAppend(t, svc, s, "bbb")
	if _, err := svc.ClaimFinalize(context.Background(), s.ID, s.Repo, s.Actor, 3); !errors.Is(err, ErrOffsetMismatch) {
		t.Fatalf("stale-size claim: got %v, want ErrOffsetMismatch", err)
	}
	st, _ := svc.Status(context.Background(), s.ID, s.Repo, s.Actor)
	if st.State != StateActive || st.Offset != 6 {
		t.Fatalf("stale claim must leave the session active+untouched, got %+v", st)
	}
}

// TestClaimFinalizeFromFinalizedRejected proves a claim on an already-finalized
// session is a conflict, not a re-finalize.
func TestClaimFinalizeFromFinalizedRejected(t *testing.T) {
	svc, _ := newTestService(t)
	s := claimTestSession(t, svc, "xyz")
	digest := "sha256:" + digestHex([]byte("xyz"))
	ref := string(bytes.Repeat([]byte{'e'}, 64))
	if err := svc.MarkFinalized(context.Background(), s.ID, s.Repo, s.Actor, testTok, digest, ref, "application/octet-stream", 3); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if _, err := svc.ClaimFinalize(context.Background(), s.ID, s.Repo, s.Actor, 3); !errors.Is(err, ErrFinalizeConflict) {
		t.Fatalf("claim on finalized: got %v, want ErrFinalizeConflict", err)
	}
}

// TestClaimedBytesFrozenFailClosed proves append, delete, and expiry cannot
// mutate a finalizing session's bytes.
func TestClaimedBytesFrozenFailClosed(t *testing.T) {
	svc, dir := newTestService(t)
	s := claimTestSession(t, svc, "frozen-bytes")
	if _, err := svc.ClaimFinalize(context.Background(), s.ID, s.Repo, s.Actor, s.Offset); err != nil {
		t.Fatalf("claim: %v", err)
	}

	// Append is rejected and the bytes are unchanged.
	if _, err := svc.Append(context.Background(), s.ID, s.Repo, s.Actor, s.Offset, bytes.NewReader([]byte("more")), 4); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("append on finalizing: got %v, want ErrInvalidState", err)
	}
	if st, _ := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); st.Offset != int64(len("frozen-bytes")) {
		t.Fatalf("claimed offset changed after rejected append: %+v", st)
	}

	// Delete fails closed and the session stays finalizing.
	if err := svc.Delete(context.Background(), s.ID, s.Repo, s.Actor); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("delete on finalizing: got %v, want ErrInvalidState", err)
	}
	if st, _ := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); st.State != StateFinalizing {
		t.Fatalf("delete must not remove a finalizing session, got %+v", st)
	}

	// Expiry in the future skips the finalizing row: it survives and its
	// bytes remain (still quota-billed).
	expiredAt := time.Now().UTC().Add(2 * time.Hour)
	if n, err := svc.Expire(context.Background(), expiredAt, 10); err != nil || n != 0 {
		t.Fatalf("expire must skip the finalizing row: count=%d err=%v", n, err)
	}
	if st, _ := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); st.State != StateFinalizing {
		t.Fatalf("expiry removed the finalizing session, got %+v", st)
	}
	if b := spoolFileBytes(t, dir, s.ID); string(b) != "frozen-bytes" {
		t.Fatalf("claimed bytes mutated: %q", b)
	}
}

// TestClaimReleaseAndCompletion proves ReleaseClaim returns a finalizing
// session to active (pre-side-effect), while MarkFinalized completes it to
// finalized, and a release on a non-finalizing session is rejected.
func TestClaimReleaseAndCompletion(t *testing.T) {
	svc, _ := newTestService(t)
	s := claimTestSession(t, svc, "data")
	claimed, err := svc.ClaimFinalize(context.Background(), s.ID, s.Repo, s.Actor, s.Offset)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Release with the WRONG (foreign) token is ownership-indistinguishable.
	if err := svc.ReleaseClaim(context.Background(), s.ID, s.Repo, s.Actor, testTok); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("foreign release: got %v, want ErrInvalidState", err)
	}
	// The winner's own token releases back to active (pre-side-effect).
	if err := svc.ReleaseClaim(context.Background(), s.ID, s.Repo, s.Actor, claimed.Token); err != nil {
		t.Fatalf("release: %v", err)
	}
	if st, _ := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); st.State != StateActive {
		t.Fatalf("release must return session to active, got %+v", st)
	}
	// Release on an active (non-finalizing) session is invalid.
	if err := svc.ReleaseClaim(context.Background(), s.ID, s.Repo, s.Actor, claimed.Token); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("release on active: got %v, want ErrInvalidState", err)
	}

	// Claim then complete via MarkFinalized to finalized (the claim identity).
	claimed2, err := svc.ClaimFinalize(context.Background(), s.ID, s.Repo, s.Actor, 4)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	digest := "sha256:" + digestHex([]byte("data"))
	ref := string(bytes.Repeat([]byte{'a'}, 64))
	// A foreign instance without the claim token cannot complete the in-flight
	// claim.
	if err := svc.MarkFinalized(context.Background(), s.ID, s.Repo, s.Actor, testTok, digest, ref, "application/octet-stream", 4); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("foreign completion: got %v, want ErrInvalidState", err)
	}
	// The winner's own claim token completes it.
	if err := svc.MarkFinalized(context.Background(), s.ID, s.Repo, s.Actor, claimed2.Token, digest, ref, "application/octet-stream", 4); err != nil {
		t.Fatalf("complete from finalizing: %v", err)
	}
	st, _ := svc.Status(context.Background(), s.ID, s.Repo, s.Actor)
	if st.State != StateFinalized || st.Digest != digest || st.BeeRef != ref {
		t.Fatalf("completion wrong: %+v", st)
	}
}

// TestRestartRetainsFinalizingUncertainty proves a fresh independent process
// over the same database leaves a finalizing row finalizing after startup
// reconciliation — never auto-completes, never auto-releases, never deletes —
// and the bytes remain frozen and readable.
func TestRestartRetainsFinalizingUncertainty(t *testing.T) {
	ctx := context.Background()
	dir := tempPrivate(t)
	spoolRoot := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")

	svc, err := NewService(ctx, spoolRoot, dbPath)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	s := claimTestSession(t, svc, "uncertain")
	if _, err := svc.ClaimFinalize(ctx, s.ID, s.Repo, s.Actor, s.Offset); err != nil {
		t.Fatalf("claim: %v", err)
	}
	svc.Close()

	svc2, err := NewService(ctx, spoolRoot, dbPath)
	if err != nil {
		t.Fatalf("restart NewService: %v", err)
	}
	defer svc2.Close()
	st, err := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
	if err != nil || st.State != StateFinalizing {
		t.Fatalf("restart must retain finalizing uncertainty: %+v err=%v", st, err)
	}
	rc, _, err := svc2.Open(ctx, s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("open after restart: %v", err)
	}
	b, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || string(b) != "uncertain" {
		t.Fatalf("frozen bytes after restart: %q err=%v", b, err)
	}
	// Nothing auto-releases or auto-completes it.
	if _, err := svc2.ClaimFinalize(ctx, s.ID, s.Repo, s.Actor, st.Offset); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reclaim after restart must lose, got %v", err)
	}
	// A fresh instance does NOT hold the winner's claim identity: it can
	// neither release nor complete the uncertain claim, so the fail-closed
	// state survives a restart.
	if err := svc2.ReleaseClaim(ctx, s.ID, s.Repo, s.Actor, testTok); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("foreign release after restart must fail, got %v", err)
	}
	st2, _ := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
	if st2.State != StateFinalizing {
		t.Fatalf("release after restart unexpectedly transitioned state: %+v", st2)
	}
}

// TestFinalizingQuotaBilled proves a finalizing row's bytes still count toward
// quota (bounded uncertainty), so a stuck uncertain session cannot be bypassed
// to admit an over-quota replacement.
func TestFinalizingQuotaBilled(t *testing.T) {
	dir := tempPrivate(t)
	dbPath := filepath.Join(dir, "staging.db")
	svc, err := NewService(context.Background(), filepath.Join(dir, "spool"), dbPath)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer svc.Close()
	svc.SetLimits(Limits{MaxRepositoryBytes: 10})
	_ = os.Mkdir(filepath.Join(dir, "spool"), 0o700) // ensure spool exists for later ops
	s := mustCreate(t, svc, seedRepo, seedActor)
	s = mustAppend(t, svc, s, "0123456789")
	if _, err := svc.ClaimFinalize(context.Background(), s.ID, s.Repo, s.Actor, 10); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// A 1-byte replacement would push usage to 11 > 10: the finalizing bytes
	// must still block it.
	b := mustCreate(t, svc, seedRepo, seedActor)
	if _, err := svc.Append(context.Background(), b.ID, b.Repo, b.Actor, 0, bytes.NewReader([]byte("z")), 1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("finalizing bytes must still count toward quota, got %v", err)
	}
}
