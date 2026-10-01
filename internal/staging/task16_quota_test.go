package staging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// mustCreateFrom returns a created session from service svc.
func mustCreateSvc(t *testing.T, svc Service, repo, actor string) Session {
	t.Helper()
	s, err := svc.Create(context.Background(), repo, actor, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return s
}

// TestQuotaPerUpload proves MaxUploadBytes bounds a single session's
// cumulative offset and that a rejected append performs zero state change.
func TestQuotaPerUpload(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetLimits(Limits{MaxUploadBytes: 10})
	ctx := context.Background()

	s := mustCreateSvc(t, svc, "backend/api", "user:alice")
	if _, err := svc.Append(ctx, s.ID, "backend/api", "user:alice", 0, bytes.NewReader([]byte("abcdef")), 10); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := svc.Append(ctx, s.ID, "backend/api", "user:alice", 6, bytes.NewReader([]byte("abcdef")), 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over-quota upload append: got %v, want ErrTooLarge", err)
	}
	snap, err := svc.Status(ctx, s.ID, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if snap.Offset != 6 {
		t.Fatalf("rejected append mutated offset to %d, want 6", snap.Offset)
	}
}

// TestQuotaPerRepository proves MaxRepositoryBytes sums active+finalized
// offsets across sessions of one repository atomically.
func TestQuotaPerRepository(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetLimits(Limits{MaxRepositoryBytes: 10})
	ctx := context.Background()

	a := mustCreateSvc(t, svc, "backend/api", "user:alice")
	b := mustCreateSvc(t, svc, "backend/api", "user:alice")
	if _, err := svc.Append(ctx, a.ID, "backend/api", "user:alice", 0, bytes.NewReader([]byte("abcdef")), 10); err != nil {
		t.Fatalf("append a: %v", err)
	}
	if _, err := svc.Append(ctx, b.ID, "backend/api", "user:alice", 0, bytes.NewReader([]byte("abcdef")), 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over repo quota append: got %v, want ErrTooLarge", err)
	}
	if snap, _ := svc.Status(ctx, b.ID, "backend/api", "user:alice"); snap.Offset != 0 {
		t.Fatalf("rejected repo append mutated offset to %d", snap.Offset)
	}
}

// TestQuotaTotalStaging proves MaxTotalStagingBytes sums active+finalized
// offsets across every repository atomically.
func TestQuotaTotalStaging(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetLimits(Limits{MaxTotalStagingBytes: 10})
	ctx := context.Background()

	a := mustCreateSvc(t, svc, "backend/api", "user:alice")
	b := mustCreateSvc(t, svc, "other/app", "user:bob")
	if _, err := svc.Append(ctx, a.ID, "backend/api", "user:alice", 0, bytes.NewReader([]byte("abcdef")), 10); err != nil {
		t.Fatalf("append a: %v", err)
	}
	if _, err := svc.Append(ctx, b.ID, "other/app", "user:bob", 0, bytes.NewReader([]byte("abcdef")), 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over total quota append: got %v, want ErrTooLarge", err)
	}
	if snap, _ := svc.Status(ctx, b.ID, "other/app", "user:bob"); snap.Offset != 0 {
		t.Fatalf("rejected total append mutated offset to %d", snap.Offset)
	}
}

// TestQuotaAtomicAcrossServices proves quota boundaries are admitted only to
// one valid winner when TWO independent durable services (separate handles,
// same spool+DB) append concurrently right at the per-repository boundary.
func TestQuotaAtomicAcrossServices(t *testing.T) {
	dir := tempPrivate(t)
	spoolRoot := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")

	svcA, err := NewService(context.Background(), spoolRoot, dbPath)
	if err != nil {
		t.Fatalf("NewService A: %v", err)
	}
	defer svcA.Close()
	svcB, err := NewService(context.Background(), spoolRoot, dbPath)
	if err != nil {
		t.Fatalf("NewService B: %v", err)
	}
	defer svcB.Close()

	limits := Limits{MaxRepositoryBytes: 10, MaxTotalStagingBytes: 10}
	svcA.SetLimits(limits)
	svcB.SetLimits(limits)

	ctx := context.Background()
	sa := mustCreateSvc(t, svcA, "backend/api", "user:alice")
	sb := mustCreateSvc(t, svcB, "backend/api", "user:alice")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = svcA.Append(ctx, sa.ID, "backend/api", "user:alice", 0, bytes.NewReader([]byte("abcdefg")), 10)
	}()
	go func() {
		defer wg.Done()
		_, errs[1] = svcB.Append(ctx, sb.ID, "backend/api", "user:alice", 0, bytes.NewReader([]byte("abcdefg")), 10)
	}()
	wg.Wait()

	wins, oversized := 0, 0
	for _, e := range errs {
		switch {
		case e == nil:
			wins++
		case errors.Is(e, ErrTooLarge):
			oversized++
		default:
			t.Fatalf("unexpected race error: %v", e)
		}
	}
	if wins != 1 || oversized != 1 {
		t.Fatalf("expected exactly one winner and one rejection, got wins=%d oversized=%d (%v %v)", wins, oversized, errs[0], errs[1])
	}
	// The committing winner's 7 bytes are durable; exactly one session holds 7
	// and the rejected session stayed at 0.
	var ok int
	for _, sess := range []Session{sa, sb} {
		if snap, _ := svcA.Status(ctx, sess.ID, "backend/api", "user:alice"); snap.Offset == 7 {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("expected exactly one session at offset 7, got %d", ok)
	}
}

// TestConsumeFinalizedReferencedOnly proves ClearStagedBlobsByDigest consumes
// only the referenced digests and leaves unrelated finalized blobs and active
// sessions intact.
func TestConsumeFinalizedReferencedOnly(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	finalize := func(repo, actor string, data []byte) (Session, string) {
		t.Helper()
		s := mustCreateSvc(t, svc, repo, actor)
		if _, err := svc.Append(ctx, s.ID, repo, actor, 0, bytes.NewReader(data), 1<<20); err != nil {
			t.Fatalf("append: %v", err)
		}
		digest := "sha256:" + digestHex(data)
		if err := svc.MarkFinalized(ctx, s.ID, repo, actor, testTok, digest, digestHex(data), "application/octet-stream", int64(len(data))); err != nil {
			t.Fatalf("finalize: %v", err)
		}
		return s, digest
	}

	sA, digA := finalize("backend/api", "user:alice", []byte("aaaa"))
	_, digB := finalize("backend/api", "user:alice", []byte("bbbb"))
	// An unrelated active (un-finalized) session survives consumption.
	active := mustCreateSvc(t, svc, "backend/api", "user:alice")

	if err := svc.ClearStagedBlobsByDigest(ctx, "backend/api", "user:alice", []string{digA}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	remaining, err := svc.ListStagedBlobs(ctx, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Digest != digB {
		t.Fatalf("only digest B must survive; got %+v", remaining)
	}
	// Unknown (but well-formed) digest is a no-op.
	if err := svc.ClearStagedBlobsByDigest(ctx, "backend/api", "user:alice", []string{"sha256:" + digestHex([]byte("nonexistent"))}); err != nil {
		t.Fatalf("unknown digest must be a no-op: %v", err)
	}
	// The consumed session's metadata row and file are gone.
	if _, err := svc.Status(ctx, sA.ID, "backend/api", "user:alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed session must be removed, got %v", err)
	}
	// Active session untouched.
	if snap, err := svc.Status(ctx, active.ID, "backend/api", "user:alice"); err != nil || snap.Offset != 0 {
		t.Fatalf("active session must survive consumption: snap=%+v err=%v", snap, err)
	}
}

func digestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
