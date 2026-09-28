package staging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Task 18: staging cleanup (expired session/blob reaping + eligible Bee unpin).
// ---------------------------------------------------------------------------

// fakeUnpinner records every Unpin call so a test can prove eligibility and
// ordering. When failAfter > 0 the first failAfter calls return failErr;
// afterwards calls succeed and are recorded. When failErr != nil and
// alwaysFail it returns failErr for every call. Non-nil recorded refs are
// always the caller-provided header value (exactly as passed).
type fakeUnpinner struct {
	mu        sync.Mutex
	refs      []string
	failErr   error
	failAfter int
}

func (f *fakeUnpinner) Unpin(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failErr != nil && len(f.refs) >= f.failAfter {
		return f.failErr
	}
	f.refs = append(f.refs, ref)
	return nil
}

func (f *fakeUnpinner) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.refs))
	copy(out, f.refs)
	return out
}

// fakeCommitted is a fixed committed-refs source keyed by repo.
type fakeCommitted struct {
	byRepo map[string]map[string]struct{}
}

func (f *fakeCommitted) CommittedRefs(_ context.Context, repo string) (map[string]struct{}, error) {
	return f.byRepo[repo], nil
}

// mustFinalize transitions a live active session to finalized with durable
// metadata and asserts it succeeded.
func mustFinalize(t *testing.T, svc *service, s Session, digest, ref, media string, size int64) Session {
	t.Helper()
	if err := svc.MarkFinalized(context.Background(), s.ID, s.Repo, s.Actor, testTok, digest, ref, media, size); err != nil {
		t.Fatalf("MarkFinalized: %v", err)
	}
	return s
}

// expireOneSession finalizes s and returns it after the service clock passes
// its expiry, so a later RunOnce(now) sees it as expired.
func fixClockAhead(svc *service, base time.Time) time.Time {
	after := base.Add(2 * time.Hour)
	fixedClock(svc, after)
	return after
}

func TestCleanupExpiredActiveSessionRemoved(t *testing.T) {
	svc, _ := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "blob-bytes")
	runAt := fixClockAhead(svc, now)

	unp := &fakeUnpinner{}
	c, err := NewCleanup(svc, unp, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Examined != 1 || res.Expired != 1 || res.Removed != 1 || res.Unpinned != 0 || res.Failed != 0 {
		t.Fatalf("counts = %+v, want examined=1 expired=1 removed=1 unpinned=0 failed=0", res)
	}
	if _, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired active session must be removed, Status err = %v", err)
	}
	if len(unp.calls()) != 0 {
		t.Fatalf("active session must not be unpinned, unpinned %v", unp.calls())
	}
}

func TestCleanupExpiredFinalizedBlobUnpinsAndRemoves(t *testing.T) {
	svc, _ := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "blob-bytes")
	digest, ref, media, size := finalizeArgs(s)
	mustFinalize(t, svc, s, digest, ref, media, size)
	runAt := fixClockAhead(svc, now)

	unp := &fakeUnpinner{}
	c, err := NewCleanup(svc, unp, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Examined != 1 || res.Expired != 1 || res.Removed != 1 || res.Unpinned != 1 || res.Failed != 0 {
		t.Fatalf("counts = %+v, want removed=1 unpinned=1", res)
	}
	if got := unp.calls(); len(got) != 1 || got[0] != ref {
		t.Fatalf("unpin called with %v, want [%s]", got, ref)
	}
	if _, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired finalized blob must be removed, Status err = %v", err)
	}
	list, err := svc.ListFinalized(context.Background(), s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("ListFinalized: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("staged blob list after cleanup = %d, want 0", len(list))
	}
}

func TestCleanupCommittedReferencedBlobNeverUnpinned(t *testing.T) {
	svc, _ := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "blob-bytes")
	digest, ref, media, size := finalizeArgs(s)
	mustFinalize(t, svc, s, digest, ref, media, size)
	runAt := fixClockAhead(svc, now)

	unp := &fakeUnpinner{}
	// The blob's Bee ref is now referenced by committed repository state:
	// cleanup must treat it as published and NEVER unpin or remove it.
	committed := &fakeCommitted{byRepo: map[string]map[string]struct{}{
		s.Repo: {ref: struct{}{}},
	}}
	c, err := NewCleanup(svc, unp, committed)
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Examined != 1 || res.Expired != 0 || res.Removed != 0 || res.Unpinned != 0 || res.Failed != 0 {
		t.Fatalf("committed-referenced blob must be skipped, counts = %+v", res)
	}
	if len(unp.calls()) != 0 {
		t.Fatalf("committed-referenced blob must never be unpinned, got %v", unp.calls())
	}
	// The staged blob and its metadata must survive untouched. Status filters by
	// expiry, so rewind the clock to prove the row (not just the files) survived.
	fixedClock(svc, now)
	st, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("committed-referenced blob must survive cleanup, Status err = %v", err)
	}
	if st.State != StateFinalized {
		t.Fatalf("committed-referenced blob state = %q, want finalized", st.State)
	}
	if st.BeeRef != ref {
		t.Fatalf("committed-referenced blob bee ref = %q, want %q", st.BeeRef, ref)
	}
	if opened := mustOpenAll(t, svc, s); opened != "blob-bytes" {
		t.Fatalf("committed-referenced blob bytes damaged: %q", opened)
	}
	list, err := svc.ListFinalized(context.Background(), s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("ListFinalized: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("committed-referenced staged blob must survive, list = %d, want 1", len(list))
	}
}

func TestCleanupMissingFileTolerated(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "doomed-bytes")
	runAt := fixClockAhead(svc, now)

	// Scrub the staged file behind the service's back, as though a foreign
	// process or disk stagger already removed it.
	canonical := filepath.Join(dir, "spool", s.ID)
	if err := os.Remove(canonical); err != nil {
		t.Fatalf("remove staged file %s: %v", canonical, err)
	}

	c, err := NewCleanup(svc, &fakeUnpinner{}, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("RunOnce with missing file must not error: %v", err)
	}
	if res.Examined != 1 || res.Expired != 1 || res.Removed != 1 || res.Failed != 0 {
		t.Fatalf("missing-file cleanup counts = %+v, want removed=1", res)
	}
	if _, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing-file session must still be removed, Status err = %v", err)
	}
}

func TestCleanupUnpinFailureRetainsMetadataAndRetries(t *testing.T) {
	svc, _ := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "blob-bytes")
	digest, ref, media, size := finalizeArgs(s)
	mustFinalize(t, svc, s, digest, ref, media, size)
	runAt := fixClockAhead(svc, now)

	unp := &fakeUnpinner{failErr: errors.New("bee unavailable"), failAfter: 0}
	c, err := NewCleanup(svc, unp, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("RunOnce with unpin failure must not abort: %v", err)
	}
	if res.Examined != 1 || res.Expired != 1 || res.Removed != 0 || res.Unpinned != 0 || res.Failed != 1 {
		t.Fatalf("unpin-failure counts = %+v, want failed=1 removed=0", res)
	}
	// The metadata must survive so a retry can re-attempt the unpin. Status
	// filters by expiry, so rewind the clock before asserting the row's Bee ref.
	fixedClock(svc, now)
	st, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("metadata lost on unpin failure, Status err = %v", err)
	}
	if st.BeeRef != ref {
		t.Fatalf("bee ref lost on unpin failure: %q", st.BeeRef)
	}

	// A later pass with a healthy Bee completes the same logical blob.
	healthy := &fakeUnpinner{}
	ch, err := NewCleanup(svc, healthy, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res2, err := ch.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("retry RunOnce: %v", err)
	}
	if res2.Examined != 1 || res2.Removed != 1 || res2.Unpinned != 1 || res2.Failed != 0 {
		t.Fatalf("retry counts = %+v, want removed=1 unpinned=1", res2)
	}
	if _, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retried blob must be removed, Status err = %v", err)
	}
}

func TestCleanupBoundedBatch(t *testing.T) {
	svc, _ := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(svc, now)
	refs := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		s := mustCreate(t, svc, "backend/api", "user:alice")
		s = mustAppend(t, svc, s, strings.Repeat("x", i+1))
		digest, ref, media, size := finalizeArgs(s)
		mustFinalize(t, svc, s, digest, ref, media, size)
		refs = append(refs, ref)
	}
	runAt := fixClockAhead(svc, now)

	unp := &fakeUnpinner{}
	c, err := NewCleanup(svc, unp, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	// A batch limit of 2 bounds how many expired rows one pass examines.
	res, err := c.RunOnce(context.Background(), runAt, 2)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Examined != 2 || res.Expired != 2 || res.Removed != 2 || res.Unpinned != 2 {
		t.Fatalf("batch counts = %+v, want examined=2 removed=2 unpinned=2", res)
	}
	if len(unp.calls()) != 2 {
		t.Fatalf("batch unpin calls = %d, want 2", len(unp.calls()))
	}

	// The third expired blob is NOT cleaned yet — but because it is expired it
	// is no longer publishable: only genuinely FINALIZED, non-expired blobs are
	// listed for publication (a cleanup-eligible blob outside the publication
	// window can never be newly referenced).
	remaining, err := svc.ListFinalized(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("ListFinalized: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expired leftover must not be publishable, listed %d, want 0", len(remaining))
	}
}
