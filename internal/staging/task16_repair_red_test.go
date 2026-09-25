package staging

// Task16 repair — quota admission (Finding A) and deleting-tombstone
// accounting (Finding B).
//
// Finding A: staging.service.Append previously wrote the FULL request body
// (bounded only by the caller's maxBytes, which can be up to the configured
// per-upload cap or the 1 GiB default) into the spool BEFORE checkQuota ran,
// so an attacker with only tiny quota remaining could stream huge payload
// bytes into the spool before the rejection. The fix computes the maximum
// admissible growth from EVERY configured limit inside the same BEGIN
// IMMEDIATE transaction, before opening the spool file or reading src, and
// (a) preflight-rejects a DECLARED Content-Range span that exceeds the
// allowance with ZERO payload consumed and no spool write, while (b) bounding
// an IMPLICIT stream's copy at the allowance so an over-quota body consumes
// at most allowance+1 bytes and leaves zero durable mutation.
//
// Finding B: usageSum counted only active+finalized, so a deleting tombstone
// (whose physical bytes still occupy the disk until cleanup completes and the
// metadata row is removed) prematurely released its quota. Deleting rows now
// count their byte-bearing offset until the durable cleanup removes the row;
// expired active/finalized rows still count (expiry alone never removes
// bytes); creating rows stay offset 0.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// countingReader wraps a source and counts exactly how many bytes the service
// pulled out of it, proving bounded consumption.
type countingReader struct {
	src io.Reader
	n   int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.n += int64(n)
	return n, err
}

// spoolFileBytes reads the raw spool payload file, so a test can prove zero
// spool writes / zero uncommitted-tail residue independently of the offset.
func spoolFileBytes(t *testing.T, dir, id string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "spool", id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read spool %s: %v", id, err)
	}
	return b
}

// TestRepairImplicitOverQuotaConsumesBoundedBytes proves an IMPLICIT (no
// Content-Range) append whose caller bound is huge does not stream the whole
// body into the spool when the per-upload quota is exhausted: the copy is
// bounded at the remaining allowance (0 here) plus its one-byte probe, so a
// counting reader observes at most 1 byte consumed and the session stays
// byte-exact (zero mutation).
func TestRepairImplicitOverQuotaConsumesBoundedBytes(t *testing.T) {
	svc, dir := newTestService(t)
	svc.SetLimits(Limits{MaxUploadBytes: 100})
	ctx := context.Background()

	s := mustCreateSvc(t, svc, "backend/api", "user:alice")
	if _, err := svc.Append(ctx, s.ID, "backend/api", "user:alice", 0, bytes.NewReader(bytes.Repeat([]byte{'a'}, 100)), 100); err != nil {
		t.Fatalf("base append: %v", err)
	}
	// Attacker streams a large body while the per-upload allowance is 0,
	// advertising a loose 1 MiB caller bound.
	counting := &countingReader{src: bytes.NewReader(bytes.Repeat([]byte{'x'}, 1<<20))}
	if _, err := svc.Append(ctx, s.ID, "backend/api", "user:alice", 100, counting, 1<<20); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over-quota implicit append: got %v, want ErrTooLarge", err)
	}
	// allowance = MaxUploadBytes(100) - oldOffset(100) = 0: bound copy at 0 +
	// one probe byte => at most 1 payload byte consumed, never ~1 MiB.
	if counting.n > 1 {
		t.Fatalf("implicit over-quota consumed %d payload bytes, want at most %d", counting.n, 1)
	}
	if snap, _ := svc.Status(ctx, s.ID, "backend/api", "user:alice"); snap.Offset != 100 {
		t.Fatalf("implicit over-quota mutated offset to %d, want 100", snap.Offset)
	}
	if b := spoolFileBytes(t, dir, s.ID); len(b) != 100 {
		t.Fatalf("implicit over-quota left %d durable spool bytes, want 100 (zero mutation)", len(b))
	}
}

// TestRepairRepoOverQuotaConsumesBoundedBytes is the per-repository analogue:
// a cross-session repository quota exhausted by another session bounds the
// copy at the remaining allowance, so an attacker cannot stream a huge body
// into a new session above the repo limit.
func TestRepairRepoOverQuotaConsumesBoundedBytes(t *testing.T) {
	svc, dir := newTestService(t)
	svc.SetLimits(Limits{MaxRepositoryBytes: 10})
	ctx := context.Background()

	a := mustCreateSvc(t, svc, "backend/api", "user:alice")
	if _, err := svc.Append(ctx, a.ID, "backend/api", "user:alice", 0, bytes.NewReader(bytes.Repeat([]byte{'a'}, 10)), 10); err != nil {
		t.Fatalf("base append: %v", err)
	}
	b := mustCreateSvc(t, svc, "backend/api", "user:alice")
	counting := &countingReader{src: bytes.NewReader(bytes.Repeat([]byte{'x'}, 1<<20))}
	if _, err := svc.Append(ctx, b.ID, "backend/api", "user:alice", 0, counting, 1<<20); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("repo over-quota implicit append: got %v, want ErrTooLarge", err)
	}
	// allowance = MaxRepositoryBytes(10) - usage(10) = 0.
	if counting.n > 1 {
		t.Fatalf("repo over-quota consumed %d payload bytes, want at most %d", counting.n, 1)
	}
	if snap, _ := svc.Status(ctx, b.ID, "backend/api", "user:alice"); snap.Offset != 0 {
		t.Fatalf("rejected repo session offset = %d, want 0", snap.Offset)
	}
	if bf := spoolFileBytes(t, dir, b.ID); len(bf) != 0 {
		t.Fatalf("rejected repo session wrote %d spool bytes, want 0", len(bf))
	}
}

// TestRepairRetainedTombstoneBlocksThenCleanupReleases proves Finding B: a
// deleting tombstone whose physical bytes still occupy the disk counts toward
// the repository quota until the durable cleanup removes the metadata row, so
// it blocks an over-quota replacement upload; a successful cleanup then
// releases the quota.
func TestRepairRetainedTombstoneBlocksThenCleanupReleases(t *testing.T) {
	ctx := context.Background()
	svc, dir := newTestService(t)
	svc.SetLimits(Limits{MaxRepositoryBytes: 15})

	a := mustCreateSvc(t, svc, "backend/api", "user:alice")
	if _, err := svc.Append(ctx, a.ID, "backend/api", "user:alice", 0, bytes.NewReader(bytes.Repeat([]byte{'a'}, 10)), 10); err != nil {
		t.Fatalf("append a 10: %v", err)
	}

	// Fail the delete so the deleting tombstone (offset 10) is retained.
	svc.dirSyncHook = func() error { return errors.New("dir-sync fault") }
	if err := svc.Delete(ctx, a.ID, "backend/api", "user:alice"); !errors.Is(err, ErrDependency) {
		svc.dirSyncHook = nil
		t.Fatalf("faulted Delete must fail closed, got %v", err)
	}
	svc.dirSyncHook = nil
	if found, st, _, _ := rowState(t, dir, a.ID); !found || st != "deleting" {
		svc.dirSyncHook = nil
		t.Fatalf("row must be a retained deleting tombstone: found=%v state=%q", found, st)
	}

	// A replacement upload of 6 bytes would make usage 10(deleting)+6=16 > 15:
	// the retained tombstone MUST block it. (RED on Finding B: the old
	// usageSum dropped the deleting row, so usage would be 0 and this succeeds.)
	b := mustCreateSvc(t, svc, "backend/api", "user:alice")
	if _, err := svc.Append(ctx, b.ID, "backend/api", "user:alice", 0, bytes.NewReader([]byte("bbbbbb")), 6); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("retained tombstone must block the over-quota replacement, got %v", err)
	}
	if snap, _ := svc.Status(ctx, b.ID, "backend/api", "user:alice"); snap.Offset != 0 {
		t.Fatalf("blocked replacement session offset = %d, want 0", snap.Offset)
	}
	if bf := spoolFileBytes(t, dir, b.ID); len(bf) != 0 {
		t.Fatalf("blocked replacement wrote %d spool bytes, want 0", len(bf))
	}

	// Successful durable cleanup removes the tombstone row and releases quota.
	if err := svc.Delete(ctx, a.ID, "backend/api", "user:alice"); err != nil {
		t.Fatalf("retry Delete: %v", err)
	}
	if found, _, _, _ := rowState(t, dir, a.ID); found {
		t.Fatalf("deleting row survived the successful cleanup")
	}
	// Now usage is 0 again: a 14-byte replacement fits the 15-byte quota.
	c := mustCreateSvc(t, svc, "backend/api", "user:alice")
	if _, err := svc.Append(ctx, c.ID, "backend/api", "user:alice", 0, bytes.NewReader(bytes.Repeat([]byte{'c'}, 14)), 14); err != nil {
		t.Fatalf("quota must be released after the durable cleanup: %v", err)
	}
}

// TestRepairRestartReconcileReleasesQuotaForTombstone proves a fresh
// independent process's startup reconciliation finishes a crash-retained
// deleting tombstone and thereby releases its quota for a later upload.
func TestRepairRestartReconcileReleasesQuotaForTombstone(t *testing.T) {
	ctx := context.Background()
	dir := tempPrivate(t)
	spoolRoot := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")

	svc, err := NewService(ctx, spoolRoot, dbPath)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.SetLimits(Limits{MaxRepositoryBytes: 15})
	a := mustCreateSvc(t, svc, "backend/api", "user:alice")
	if _, err := svc.Append(ctx, a.ID, "backend/api", "user:alice", 0, bytes.NewReader(bytes.Repeat([]byte{'a'}, 10)), 10); err != nil {
		t.Fatalf("append a: %v", err)
	}
	svc.dirSyncHook = func() error { return errors.New("dir-sync fault") }
	if err := svc.Delete(ctx, a.ID, "backend/api", "user:alice"); !errors.Is(err, ErrDependency) {
		svc.dirSyncHook = nil
		t.Fatalf("faulted Delete must fail closed, got %v", err)
	}
	svc.dirSyncHook = nil
	if found, st, _, _ := rowState(t, dir, a.ID); !found || st != "deleting" {
		t.Fatalf("row must be a retained deleting tombstone: found=%v state=%q", found, st)
	}
	svc.Close()

	// Restart: a fresh independent process's reconcileStartup finishes the
	// tombstone's durable deletion and removes the row.
	svc2, err := NewService(ctx, spoolRoot, dbPath)
	if err != nil {
		t.Fatalf("restart NewService: %v", err)
	}
	defer svc2.Close()
	svc2.SetLimits(Limits{MaxRepositoryBytes: 15})
	if found, _, _, _ := rowState(t, dir, a.ID); found {
		t.Fatalf("deleting row survived restart reconciliation")
	}
	// The released quota now admits a 14-byte replacement upload.
	b := mustCreateSvc(t, svc2, "backend/api", "user:alice")
	if _, err := svc2.Append(ctx, b.ID, "backend/api", "user:alice", 0, bytes.NewReader(bytes.Repeat([]byte{'b'}, 14)), 14); err != nil {
		t.Fatalf("restart must release the tombstone quota: %v", err)
	}
}

// TestRepairDeclaredOverQuotaConsumesZero proves a DECLARED Content-Range span
// that exceeds the available quota allowance is preflight-rejected BEFORE the
// spool file is opened or any source byte is read: a counting reader observes
// ZERO payload consumed and the spool file stays empty (no write). This is the
// strict declared-range preflight — distinct from the implicit bound-copy that
// may consume at most allowance+1.
func TestRepairDeclaredOverQuotaConsumesZero(t *testing.T) {
	svc, dir := newTestService(t)
	svc.SetLimits(Limits{MaxRepositoryBytes: 10})
	ctx := context.Background()

	s := mustCreateSvc(t, svc, "backend/api", "user:alice")
	// Declared span of 100 exceeds the 10-byte repository allowance.
	counting := &countingReader{src: bytes.NewReader(bytes.Repeat([]byte{'x'}, 100))}
	dctx := WithDeclaredSpan(ctx)
	if _, err := svc.Append(dctx, s.ID, "backend/api", "user:alice", 0, counting, 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("declared over-quota preflight: got %v, want ErrTooLarge", err)
	}
	if counting.n != 0 {
		t.Fatalf("declared over-quota consumed %d payload bytes, want zero", counting.n)
	}
	if snap, _ := svc.Status(ctx, s.ID, "backend/api", "user:alice"); snap.Offset != 0 {
		t.Fatalf("declared over-quota mutated offset to %d, want 0", snap.Offset)
	}
	if b := spoolFileBytes(t, dir, s.ID); len(b) != 0 {
		t.Fatalf("declared over-quota wrote %d spool bytes, want 0 (no spool write)", len(b))
	}
}

// TestRepairDeclaredWithinAllowanceStillAppends proves the declared span
// preflight does NOT over-reject: a declared span that fits the allowance is
// accepted and committed exactly (offset advances by the full span), so valid
// Content-Range appends behave unchanged.
func TestRepairDeclaredWithinAllowanceStillAppends(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetLimits(Limits{MaxRepositoryBytes: 10})
	ctx := context.Background()

	s := mustCreateSvc(t, svc, "backend/api", "user:alice")
	counting := &countingReader{src: bytes.NewReader(bytes.Repeat([]byte{'a'}, 6))}
	dctx := WithDeclaredSpan(ctx)
	got, err := svc.Append(dctx, s.ID, "backend/api", "user:alice", 0, counting, 6)
	if err != nil {
		t.Fatalf("in-allowance declared append must succeed: %v", err)
	}
	if got.Offset != 6 {
		t.Fatalf("in-allowance declared append offset = %d, want 6", got.Offset)
	}
	if counting.n != 6 {
		t.Fatalf("in-allowance declared append consumed %d bytes, want 6", counting.n)
	}
}

// TestRepairRestartRetainedTombstoneBlocksThenRelease proves a RESTART that
// rediscovers a byte-bearing deleting tombstone (a crash-between-phases state)
// whose cleanup is still failing keeps accounting for its bytes: it blocks an
// over-quota replacement upload. When the same restart then finishes the
// durable cleanup, the quota is released.
func TestRepairRestartRetainedTombstoneBlocksThenRelease(t *testing.T) {
	ctx := context.Background()
	dir := newV3StagingDir(t)
	id := factID('9')
	now := time.Now().UTC().UnixNano()
	// A deleting tombstone carrying 10 committed bytes, expiry in the future so
	// only the durable cleanup (never Expire) may release it. (The schema only
	// allows be born as active/creating at offset 0 and forbids setting the
	// deleting state on INSERT, so grow the offset then transition — the exact
	// crash-between-phases state.)
	rawExec(t, dir,
		`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?,?,?, 'active', 0, ?, ?)`,
		id, factRepo, factActor, now-int64(time.Hour), now+int64(time.Hour))
	rawExec(t, dir,
		`update upload_sessions set offset = 10 where id = ?`, id)
	rawExec(t, dir,
		`update upload_sessions set state = 'deleting' where id = ?`, id)

	svc := buildServiceNoReconcile(t, dir)
	svc.SetLimits(Limits{MaxRepositoryBytes: 15})

	// A restart attempt whose cleanup also fails retains the tombstone.
	svc.dirSyncHook = func() error { return errors.New("dir-sync fault") }
	if err := svc.reconcileStartup(ctx); !errors.Is(err, ErrDependency) {
		svc.dirSyncHook = nil
		t.Fatalf("restart with failing cleanup must retain the tombstone, got %v", err)
	}
	svc.dirSyncHook = nil
	if found, st, _, _ := rowState(t, dir, id); !found || st != "deleting" {
		t.Fatalf("tombstone must be retained after the failed restart cleanup: found=%v state=%q", found, st)
	}

	// The retained tombstone (10 bytes) blocks a 6-byte replacement: 16 > 15.
	b := mustCreateSvc(t, svc, "backend/api", "user:alice")
	if _, err := svc.Append(ctx, b.ID, "backend/api", "user:alice", 0, bytes.NewReader(bytes.Repeat([]byte{'b'}, 6)), 6); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("retained tombstone after restart must block the over-quota replacement, got %v", err)
	}

	// A restart whose cleanup succeeds removes the tombstone and releases quota.
	if err := svc.reconcileStartup(ctx); err != nil {
		t.Fatalf("cleanup reconcile: %v", err)
	}
	if found, _, _, _ := rowState(t, dir, id); found {
		t.Fatalf("tombstone survived the cleanup reconcile")
	}
	if _, err := svc.Append(ctx, b.ID, "backend/api", "user:alice", 0, bytes.NewReader(bytes.Repeat([]byte{'b'}, 6)), 6); err != nil {
		t.Fatalf("quota must be released after the restart cleanup: %v", err)
	}
}

// TestRepairExpiredActiveStillCounted is a regression guard proving expiry
// alone (without the Expire deletion) NEVER removes bytes from quota: an
// expired-but-present active session still occupies the repository allowance,
// so a concurrent append is bounded by it. State (not expiry) governs the
// accounting.
func TestRepairExpiredActiveStillCounted(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)
	fixedClock(svc, time.Unix(1_600_000_000, 0).UTC())
	svc.SetLimits(Limits{MaxRepositoryBytes: 10})

	// Create a session that is already expired (expiresAt in the past) but
	// still present and active with 10 committed bytes.
	s := mustCreateSvc(t, svc, "backend/api", "user:alice")
	if _, err := svc.Append(ctx, s.ID, "backend/api", "user:alice", 0, bytes.NewReader(bytes.Repeat([]byte{'a'}, 10)), 10); err != nil {
		t.Fatalf("append expired session: %v", err)
	}

	o := mustCreateSvc(t, svc, "backend/api", "user:alice")
	counting := &countingReader{src: bytes.NewReader(bytes.Repeat([]byte{'x'}, 1<<20))}
	if _, err := svc.Append(ctx, o.ID, "backend/api", "user:alice", 0, counting, 1<<20); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expired-but-present active bytes must count toward quota, got %v", err)
	}
	if counting.n > 1 {
		t.Fatalf("expired-but-present bytes not bounded: consumed %d bytes, want at most %d", counting.n, 1)
	}
	if snap, _ := svc.Status(ctx, o.ID, "backend/api", "user:alice"); snap.Offset != 0 {
		t.Fatalf("blocked by expired bytes: offset %d, want 0", snap.Offset)
	}
}
