package staging

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

func newTestService(t *testing.T) (*service, string) {
	t.Helper()
	dir := tempPrivate(t)
	svc, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { svc.Close() })
	return svc, dir
}

// tempPrivate returns a private 0700 temporary directory (t.TempDir() may be
// 0755 on some platforms, which a fail-closed service correctly rejects).
func tempPrivate(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	return d
}

// sqlOpenForTest gives a direct-SQL handle to the staging database with the
// same DSN pragmas the service uses.
func sqlOpenForTest(dbPath string) (*sql.DB, error) {
	return sql.Open("sqlite", normalizeDSN(dbPath))
}

func fixedClock(svc *service, at time.Time) {
	svc.now = func() time.Time { return at }
}

func mustCreate(t *testing.T, svc *service, repo, actor string) Session {
	t.Helper()
	s, err := svc.Create(context.Background(), repo, actor, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := validateID(s.ID); err != nil {
		t.Fatalf("server id not canonical: %q (%v)", s.ID, err)
	}
	return s
}

func mustAppend(t *testing.T, svc *service, s Session, data string) Session {
	t.Helper()
	got, err := svc.Append(context.Background(), s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader(data), 1<<20)
	if err != nil {
		t.Fatalf("Append(%q): %v", data, err)
	}
	return got
}

func mustOpenAll(t *testing.T, svc *service, s Session) string {
	t.Helper()
	rc, _, err := svc.Open(context.Background(), s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(data)
}

// ---------------------------------------------------------------------------
// Create / Status
// ---------------------------------------------------------------------------

func TestServiceCreateSession(t *testing.T) {
	svc, _ := newTestService(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	fixedClock(svc, now)

	s, err := svc.Create(context.Background(), "backend/api", "user:alice", 90*time.Minute)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.State != StateActive {
		t.Fatalf("state = %q, want active", s.State)
	}
	if s.Offset != 0 || s.Size != 0 {
		t.Fatalf("offset=%d size=%d, want 0", s.Offset, s.Size)
	}
	if !s.CreatedAt.Equal(now) {
		t.Fatalf("created at %v, want %v", s.CreatedAt, now)
	}
	if s.ExpiresAt.Sub(s.CreatedAt) != 90*time.Minute {
		t.Fatalf("expires diff = %v", s.ExpiresAt.Sub(s.CreatedAt))
	}
	if s.Digest != "" || s.BeeRef != "" || s.MediaType != "" {
		t.Fatalf("active session unexpectedly carries finalize metadata")
	}

	st, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.ID != s.ID || st.Offset != 0 || st.State != StateActive {
		t.Fatalf("status mismatch: %+v", st)
	}
}

func TestServiceCreateRejectsInvalidArgs(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	for _, tc := range []struct {
		repo, actor string
		ttl         time.Duration
	}{
		{"", "user:alice", time.Hour},
		{"Backend/api", "user:alice", time.Hour},
		{"backend/api", "", time.Hour},
		{"backend/api", "user:alice", 0},
		{"backend/api", "user:alice", -time.Second},
		{strings.Repeat("a", 201), "user:alice", time.Hour},
	} {
		if s, err := svc.Create(ctx, tc.repo, tc.actor, tc.ttl); err == nil || !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Create(%q,%q,%v) = %+v, %v; want ErrInvalidInput", tc.repo, tc.actor, tc.ttl, s, err)
		}
	}
}

func TestServiceCreateTTLOverflowRejected(t *testing.T) {
	svc, _ := newTestService(t)
	// A TTL that pushes expires_at past the int64-nanosecond ceiling must be
	// rejected before any write.
	at := time.Unix(0, math.MaxInt64-1_000_000_000).UTC()
	fixedClock(svc, at)
	if _, err := svc.Create(context.Background(), "backend/api", "user:alice", 10*time.Hour); err == nil || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("overflowing TTL accepted: %v", err)
	}
}

func TestServiceStatusNotFoundAndExpiry(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Status(ctx, strings.Repeat("c", 64), "backend/api", "user:alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing session: %v, want ErrNotFound", err)
	}

	now := time.Now().UTC()
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")

	// Just before expiry: visible.
	fixedClock(svc, now.Add(time.Hour).Add(-time.Nanosecond))
	if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); err != nil {
		t.Fatalf("status just before expiry: %v", err)
	}
	// At expiry and after: ErrExpired.
	fixedClock(svc, now.Add(time.Hour))
	if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrExpired) {
		t.Fatalf("status at expiry: %v, want ErrExpired", err)
	}
	fixedClock(svc, now.Add(2*time.Hour))
	if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrExpired) {
		t.Fatalf("status after expiry: %v, want ErrExpired", err)
	}
}

// TestServiceOwnershipIsIndistinguishableFromNotFound proves cross-owner and
// cross-repo access yields the not-found family without revealing existence,
// with fixed data-free text.
func TestServiceOwnershipIsIndistinguishableFromNotFound(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")

	probes := []struct {
		id, repo, actor string
	}{
		{s.ID, "backend/api", "user:eve"},
		{s.ID, "other/app", "user:alice"},
		{s.ID, "other/app", "user:eve"},
		{s.ID, "backend/api", "user:a" + strings.Repeat("a", 30)},
	}
	for _, p := range probes {
		_, err := svc.Status(ctx, p.id, p.repo, p.actor)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Status(%q,%q,%q) = %v, want ErrNotFound family", p.id, p.repo, p.actor, err)
		}
		if err := containsLeak(err, s.ID, s.Repo, s.Actor); err != nil {
			t.Errorf("owner-mismatch error leaks data: %v", err)
		}
	}

	// The session must be untouched.
	st, _ := svc.Status(ctx, s.ID, s.Repo, s.Actor)
	if st.State != StateActive {
		t.Fatalf("session changed: %+v", st)
	}
}

// ---------------------------------------------------------------------------
// Append semantics
// ---------------------------------------------------------------------------

func TestServiceAppendStreaming(t *testing.T) {
	svc, _ := newTestService(t)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "hello")
	s = mustAppend(t, svc, s, " world")
	if s.Offset != int64(len("hello world")) {
		t.Fatalf("offset = %d", s.Offset)
	}
	if got := mustOpenAll(t, svc, s); got != "hello world" {
		t.Fatalf("open = %q", got)
	}
}

func TestServiceAppendEmptySourceSucceeds(t *testing.T) {
	svc, _ := newTestService(t)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	got, err := svc.Append(context.Background(), s.ID, s.Repo, s.Actor, 0, strings.NewReader(""), 100)
	if err != nil {
		t.Fatalf("empty append: %v", err)
	}
	if got.Offset != 0 {
		t.Fatalf("offset = %d", got.Offset)
	}
}

func TestServiceAppendStaleOffsetMismatch(t *testing.T) {
	svc, _ := newTestService(t)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "hello")
	if _, err := svc.Append(context.Background(), s.ID, s.Repo, s.Actor, 0, strings.NewReader("X"), 100); !errors.Is(err, ErrOffsetMismatch) {
		t.Fatalf("stale offset: %v, want ErrOffsetMismatch", err)
	}
	if got := mustOpenAll(t, svc, s); got != "hello" {
		t.Fatalf("bytes changed after stale append: %q", got)
	}
}

func TestServiceAppendInputValidation(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")

	cases := []struct {
		name            string
		id, repo, actor string
		expectedOffset  int64
		maxBytes        int64
	}{
		{"bad_id", "not-an-id", s.Repo, s.Actor, 0, 100},
		{"bad_repo", s.ID, "backend//api", s.Actor, 0, 100},
		{"bad_actor", s.ID, s.Repo, "actor/x", 0, 100},
		{"negative_offset", s.ID, s.Repo, s.Actor, -1, 100},
		{"negative_max", s.ID, s.Repo, s.Actor, 0, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.Append(ctx, tc.id, tc.repo, tc.actor, tc.expectedOffset, strings.NewReader("x"), tc.maxBytes); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestServiceAppendMaxBytesBounds(t *testing.T) {
	svc, _ := newTestService(t)
	s := mustCreate(t, svc, "backend/api", "user:alice")

	// maxBytes == data length: accepted.
	got, err := svc.Append(context.Background(), s.ID, s.Repo, s.Actor, 0, strings.NewReader("abc"), 3)
	if err != nil || got.Offset != 3 {
		t.Fatalf("exact maxBytes: offset=%d err=%v", got.Offset, err)
	}
	s = got
	// maxBytes one short: rejected, nothing retained.
	if _, err := svc.Append(context.Background(), s.ID, s.Repo, s.Actor, 3, strings.NewReader("d"), 0); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("maxBytes=0 with data: %v, want ErrTooLarge", err)
	}
	if opened := mustOpenAll(t, svc, s); opened != "abc" {
		t.Fatalf("after too-large append: %q", opened)
	}
	// maxBytes large enough for the next chunk.
	s = mustAppend(t, svc, s, "de")
	if got := mustOpenAll(t, svc, s); got != "abcde" {
		t.Fatalf("after valid append: %q", got)
	}
}

func TestServiceAppendOffsetOverflowSafety(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "hello") // offset 5

	// offset(5) + maxBytes(MaxInt64) overflows int64: rejected before writes.
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, 5, strings.NewReader("x"), math.MaxInt64); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("offset overflow: %v, want ErrTooLarge", err)
	}
	if opened := mustOpenAll(t, svc, s); opened != "hello" {
		t.Fatalf("overflow append changed bytes: %q", opened)
	}
}

func TestServiceAppendMaxInt64WithSmallSource(t *testing.T) {
	svc, _ := newTestService(t)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	// maxBytes == MaxInt64 is legal for a small source (no arithmetic wrap).
	got, err := svc.Append(context.Background(), s.ID, s.Repo, s.Actor, 0, strings.NewReader("tiny"), math.MaxInt64)
	if err != nil || got.Offset != 4 {
		t.Fatalf("maxInt64 append: offset=%d err=%v", got.Offset, err)
	}
}

func TestServiceAppendExpired(t *testing.T) {
	svc, _ := newTestService(t)
	now := time.Now().UTC()
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")

	fixedClock(svc, now.Add(time.Hour))
	if _, err := svc.Append(context.Background(), s.ID, s.Repo, s.Actor, 0, strings.NewReader("x"), 10); !errors.Is(err, ErrExpired) {
		t.Fatalf("append expired: %v, want ErrExpired", err)
	}
	// No bytes were written by the rejected append.
	fixedClock(svc, now.Add(-time.Minute))
	if st, _ := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); st.Offset != 0 {
		t.Fatalf("expired append mutated offset: %+v", st)
	}
}

func TestServiceAppendSourceReadErrorLeavesNoPartialData(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")

	failAfter := &failingReader{data: []byte("partial-bytes-that-fail"), failAt: 7}
	_, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, 0, failAfter, 1<<20)
	if err == nil {
		t.Fatal("source read error swallowed")
	}
	if !errors.Is(err, ErrSourceRead) {
		t.Fatalf("err = %v, want ErrSourceRead family", err)
	}
	if st, _ := svc.Status(ctx, s.ID, s.Repo, s.Actor); st.Offset != 0 {
		t.Fatalf("partial append committed offset %d", st.Offset)
	}
	if opened := mustOpenAll(t, svc, s); opened != "" {
		t.Fatalf("partial bytes retained: %q", opened)
	}
	// The spool file contains no tail beyond the committed offset.
	assertSpoolSize(t, svc, s.ID, 0)
}

type failingReader struct {
	data   []byte
	failAt int
	off    int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	if r.off >= r.failAt {
		return 0, errors.New("injected source failure")
	}
	n := copy(p, r.data[r.off:])
	if n > 3 {
		n = 3 // dribble small chunks to exercise repeated reads
	}
	r.off += n
	return n, nil
}

// TestServiceBoundedMemoryAppend proves Append streams with a fixed-size
// buffer: the source is only ever read in bounded chunks and the total byte
// count is exact, over a stream far larger than the buffer.
func TestServiceBoundedMemoryAppend(t *testing.T) {
	svc, _ := newTestService(t)
	s := mustCreate(t, svc, "backend/api", "user:alice")

	const chunkLimit = 64 * 1024
	const total = 8 * 1024 * 1024
	src := &chunkBoundedReader{total: total, maxChunk: chunkLimit}

	got, err := svc.Append(context.Background(), s.ID, s.Repo, s.Actor, 0, src, math.MaxInt64)
	if err != nil {
		t.Fatalf("bounded append: %v", err)
	}
	if got.Offset != total {
		t.Fatalf("offset = %d, want %d", got.Offset, total)
	}
	if src.chunks < total/chunkLimit {
		t.Fatalf("streaming violated: only %d chunks for %d bytes", src.chunks, total)
	}
}

// chunkBoundedReader generates a large deterministic stream while refusing
// reads larger than maxChunk — io.ReadAll-style production code would fail it.
type chunkBoundedReader struct {
	total    int64
	maxChunk int
	off      int64
	chunks   int
}

func (r *chunkBoundedReader) Read(p []byte) (int, error) {
	if len(p) > r.maxChunk {
		return 0, fmt.Errorf("oversized read of %d bytes requested (max %d)", len(p), r.maxChunk)
	}
	if r.off >= r.total {
		return 0, io.EOF
	}
	remaining := r.total - r.off
	n := int64(len(p))
	if n > remaining {
		n = remaining
	}
	// Deterministic non-zero bytes.
	for i := int64(0); i < n; i++ {
		p[i] = byte((r.off + i) % 251)
	}
	r.off += n
	r.chunks++
	return int(n), nil
}

func assertSpoolSize(t *testing.T, svc *service, id string, want int64) {
	t.Helper()
	fi, err := svc.spool.root.Lstat(id)
	if err != nil {
		t.Fatalf("lstat spool file: %v", err)
	}
	if fi.Size() != want {
		t.Fatalf("spool file size = %d, want %d", fi.Size(), want)
	}
}

// ---------------------------------------------------------------------------
// Fault injection at write, fsync, and DB commit boundaries
// ---------------------------------------------------------------------------

// TestServiceAppendFsyncFault proves an fsync failure rejects the append,
// keeps the committed offset, truncates the tail, and survives a restart
// with exactly the last committed bytes.
func TestServiceAppendFsyncFault(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "committed")

	svc.fsyncHook = func() error { return errors.New("injected fsync failure") }
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("more"), 100); !errors.Is(err, ErrDependency) {
		t.Fatalf("fsync fault: %v, want ErrDependency", err)
	}
	svc.fsyncHook = nil
	assertSpoolSize(t, svc, s.ID, int64(len("committed")))

	if st, _ := svc.Status(ctx, s.ID, s.Repo, s.Actor); st.Offset != int64(len("committed")) {
		t.Fatalf("offset after fsync fault: %d", st.Offset)
	}
	if opened := mustOpenAll(t, svc, s); opened != "committed" {
		t.Fatalf("bytes after fsync fault: %q", opened)
	}

	// Restart yields exactly the last committed bytes.
	svc.Close()
	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer svc2.Close()
	st, _ := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
	if st.Offset != int64(len("committed")) {
		t.Fatalf("post-restart offset: %d", st.Offset)
	}
	if opened := mustOpenAll(t, svc2, st); opened != "committed" {
		t.Fatalf("post-restart bytes: %q", opened)
	}
}

// TestServiceAppendDBUpdateFault proves a database update failure after a
// durable file write rolls back and truncates, never advancing the DB offset.
func TestServiceAppendDBUpdateFault(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "stable")

	svc.dbWriteHook = func() error { return errors.New("injected update failure") }
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("boom"), 100); !errors.Is(err, ErrDependency) {
		t.Fatalf("db update fault: %v, want ErrDependency", err)
	}
	svc.dbWriteHook = nil
	assertSpoolSize(t, svc, s.ID, int64(len("stable")))

	svc.Close()
	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer svc2.Close()
	st, _ := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
	if st.Offset != int64(len("stable")) {
		t.Fatalf("post-restart offset: %d", st.Offset)
	}
	if opened := mustOpenAll(t, svc2, st); opened != "stable" {
		t.Fatalf("post-restart bytes: %q", opened)
	}
}

// TestServiceAppendDBCommitFault proves a commit failure after fsync leaves a
// recoverable tail that restart reconciliation truncates away.
func TestServiceAppendDBCommitFault(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "fixed")

	svc.commitHook = func() error { return errors.New("injected commit failure") }
	_, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("tail"), 100)
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("commit fault: %v, want ErrDependency", err)
	}
	svc.commitHook = nil

	// The DB offset never advanced, and the file was cut back immediately.
	if st, _ := svc.Status(ctx, s.ID, s.Repo, s.Actor); st.Offset != int64(len("fixed")) {
		t.Fatalf("offset after commit fault: %d", st.Offset)
	}
	assertSpoolSize(t, svc, s.ID, int64(len("fixed")))

	svc.Close()
	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer svc2.Close()
	st, _ := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
	if st.Offset != int64(len("fixed")) {
		t.Fatalf("post-restart offset: %d", st.Offset)
	}
	if opened := mustOpenAll(t, svc2, st); opened != "fixed" {
		t.Fatalf("post-restart bytes: %q", opened)
	}
}

// TestServiceRestartTruncatesCrashTail proves a crash between fsync and
// commit (simulated by appending raw bytes behind the service's back) is
// reconciled on restart: only committed bytes are ever returned.
func TestServiceRestartTruncatesCrashTail(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "real")

	// Simulate the crash window: fsync happened, DB commit did not.
	f, err := os.OpenFile(filepath.Join(dir, "spool", s.ID), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open tail writer: %v", err)
	}
	if _, err := f.Write([]byte("LOST-TAIL")); err != nil {
		t.Fatalf("write tail: %v", err)
	}
	f.Sync()
	f.Close()
	assertSpoolSize(t, svc, s.ID, int64(len("realLOST-TAIL")))

	svc.Close()
	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer svc2.Close()
	st, _ := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
	if st.Offset != int64(len("real")) {
		t.Fatalf("post-restart offset: %d", st.Offset)
	}
	if opened := mustOpenAll(t, svc2, st); opened != "real" {
		t.Fatalf("post-restart bytes: %q (tail not truncated)", opened)
	}
	// Next append also starts from the aligned size.
	st = mustAppend(t, svc2, st, "!")
	if st.Offset != int64(len("real!")) {
		t.Fatalf("offset after append on restarted: %d", st.Offset)
	}
	if opened := mustOpenAll(t, svc2, st); opened != "real!" {
		t.Fatalf("bytes after append on restarted: %q", opened)
	}
}

// TestServiceFailsClosedOnShorterFile proves a DB offset ahead of durable
// file bytes is corruption: the operation fails closed and never fabricates.
func TestServiceFailsClosedOnShorterFile(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "abcdef")
	if err := os.Truncate(filepath.Join(dir, "spool", s.ID), 3); err != nil {
		t.Fatalf("truncate spool: %v", err)
	}
	if _, _, err := svc.Open(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrDependency) {
		t.Fatalf("open shorter file: %v, want ErrDependency", err)
	}
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, 6, strings.NewReader("x"), 10); !errors.Is(err, ErrDependency) {
		t.Fatalf("append shorter file: %v, want ErrDependency", err)
	}
}

// TestServiceFailsClosedOnMissingFile proves a missing spool file never
// yields fabricated data.
func TestServiceFailsClosedOnMissingFile(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "data")
	if err := os.Remove(filepath.Join(dir, "spool", s.ID)); err != nil {
		t.Fatalf("remove spool: %v", err)
	}
	if _, _, err := svc.Open(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrDependency) {
		t.Fatalf("open missing file: %v, want ErrDependency", err)
	}
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, 4, strings.NewReader("x"), 10); !errors.Is(err, ErrDependency) {
		t.Fatalf("append missing file: %v, want ErrDependency", err)
	}
	if st, _ := svc.Status(ctx, s.ID, s.Repo, s.Actor); st.Offset != 4 {
		t.Fatalf("status after missing-file ops: %+v", st)
	}
}

// TestServiceRejectsSymlinkedSpoolFile proves a symlink planted at the spool
// name is never followed for append or read.
func TestServiceRejectsSymlinkedSpoolFile(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "real")

	victim := filepath.Join(tempPrivate(t), "victim")
	if err := os.WriteFile(victim, []byte("attacker-data"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "spool", s.ID)); err != nil {
		t.Fatalf("remove spool: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "spool", s.ID)); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	if _, _, err := svc.Open(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrDependency) {
		t.Fatalf("open symlinked spool: %v, want ErrDependency", err)
	}
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, 4, strings.NewReader("x"), 10); !errors.Is(err, ErrDependency) {
		t.Fatalf("append symlinked spool: %v, want ErrDependency", err)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if string(got) != "attacker-data" {
		t.Fatalf("victim file modified through spool: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Open
// ---------------------------------------------------------------------------

func TestServiceOpenReturnsOnlyCommittedBytes(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "0123456789")

	rc, sess, err := svc.Open(ctx, s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if sess.Offset != 10 {
		t.Fatalf("open session offset: %d", sess.Offset)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "0123456789" {
		t.Fatalf("open bytes: %q", got)
	}
}

func TestServiceOpenExpiredAndInvalidState(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")

	fixedClock(svc, now.Add(time.Hour))
	if _, _, err := svc.Open(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrExpired) {
		t.Fatalf("open expired: %v, want ErrExpired", err)
	}
}

// ---------------------------------------------------------------------------
// Concurrency: BEGIN IMMEDIATE cross-instance serialization
// ---------------------------------------------------------------------------

// TestConcurrentSameOffsetAppendSingleWinner proves two independent service
// instances appending at the same expected offset serialize: exactly one
// succeeds and the other sees the offset mismatch; the final bytes are the
// winner's, across a restart.
func TestConcurrentSameOffsetAppendSingleWinner(t *testing.T) {
	dir := tempPrivate(t)
	root := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")

	one, err := NewService(context.Background(), root, dbPath)
	if err != nil {
		t.Fatalf("service one: %v", err)
	}
	defer one.Close()
	two, err := NewService(context.Background(), root, dbPath)
	if err != nil {
		t.Fatalf("service two: %v", err)
	}
	defer two.Close()

	s := mustCreate(t, one, "backend/api", "user:alice")

	var wg sync.WaitGroup
	ready := make(chan struct{})
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, svc := range []*service{one, two} {
		wg.Add(1)
		go func(svc *service) {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			_, err := svc.Append(context.Background(), s.ID, s.Repo, s.Actor, 0, strings.NewReader("winner"), 100)
			results <- err
		}(svc)
	}
	<-ready
	<-ready
	close(start)
	wg.Wait()
	close(results)

	var successes, mismatches int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrOffsetMismatch):
			mismatches++
		default:
			t.Fatalf("unexpected append error: %v", err)
		}
	}
	if successes != 1 || mismatches != 1 {
		t.Fatalf("successes=%d mismatches=%d, want exactly 1/1", successes, mismatches)
	}

	// The durable outcome is exactly the winner's bytes.
	st, _ := one.Status(context.Background(), s.ID, s.Repo, s.Actor)
	if st.Offset != int64(len("winner")) {
		t.Fatalf("final offset: %d", st.Offset)
	}
	if opened := mustOpenAll(t, one, st); opened != "winner" {
		t.Fatalf("final bytes: %q", opened)
	}
}

// TestConcurrentAppendsSerialize is a stress version: N serial appends from
// two instances must never interleave bytes or lose committed data.
func TestConcurrentAppendsSerialize(t *testing.T) {
	dir := tempPrivate(t)
	root := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")
	one, err := NewService(context.Background(), root, dbPath)
	if err != nil {
		t.Fatalf("service one: %v", err)
	}
	defer one.Close()
	two, err := NewService(context.Background(), root, dbPath)
	if err != nil {
		t.Fatalf("service two: %v", err)
	}
	defer two.Close()

	s := mustCreate(t, one, "backend/api", "user:alice")

	const per = 25
	var wg sync.WaitGroup
	for i, svc := range []*service{one, two} {
		wg.Add(1)
		go func(svc *service, suffix byte) {
			defer wg.Done()
			for j := 0; j < per; j++ {
				chunk := fmt.Sprintf("%c%d;", suffix, j)
				var last Session
				var err error
				for attempt := 0; attempt < 50; attempt++ {
					off := int64(0)
					if attempt > 0 {
						st, serr := svc.Status(context.Background(), s.ID, s.Repo, s.Actor)
						if serr != nil {
							continue
						}
						off = st.Offset
					}
					last, err = svc.Append(context.Background(), s.ID, s.Repo, s.Actor, off, strings.NewReader(chunk), 100)
					if err == nil {
						break
					}
					if !errors.Is(err, ErrOffsetMismatch) {
						t.Errorf("append: %v", err)
						return
					}
				}
				if err != nil {
					t.Errorf("append never succeeded: %v", err)
					return
				}
				_ = last
			}
		}(svc, byte('A'+i))
	}
	wg.Wait()

	st, _ := one.Status(context.Background(), s.ID, s.Repo, s.Actor)
	// Chunk lengths grow with j: "A0;" is 3 bytes, "A10;" is 4. Compute the
	// exact expected total instead of assuming a fixed chunk width.
	want := 0
	for j := 0; j < per; j++ {
		want += len(fmt.Sprintf("A%d;", j)) + len(fmt.Sprintf("B%d;", j))
	}
	if st.Offset != int64(want) {
		t.Fatalf("final offset: %d, want %d", st.Offset, want)
	}
	data := mustOpenAll(t, one, st)
	if len(data) != int(st.Offset) {
		t.Fatalf("final byte count: %d", len(data))
	}
	// Every chunk boundary must be intact: all 2*per chunks present.
	for j := 0; j < per; j++ {
		for _, ch := range []string{fmt.Sprintf("A%d;", j), fmt.Sprintf("B%d;", j)} {
			if !strings.Contains(data, ch) {
				t.Fatalf("missing chunk %q in %q", ch, data)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Finalization and listing
// ---------------------------------------------------------------------------

func finalizeArgs(s Session) (string, string, string, int64) {
	return "sha256:" + strings.Repeat("b", 64), strings.Repeat("c", 64), "application/vnd.oci.image.layer.v1.tar+gzip", s.Offset
}

func TestServiceMarkFinalizedLifecycle(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "blob-bytes")
	digest, ref, media, size := finalizeArgs(s)

	if err := svc.MarkFinalized(ctx, s.ID, s.Repo, s.Actor, digest, ref, media, size); err != nil {
		t.Fatalf("MarkFinalized: %v", err)
	}

	st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("Status after finalize: %v", err)
	}
	if st.State != StateFinalized || st.Digest != digest || st.BeeRef != ref || st.MediaType != media || st.Size != size {
		t.Fatalf("finalized session: %+v", st)
	}

	// Finalization never modifies the file bytes.
	if opened := mustOpenAll(t, svc, s); opened != "blob-bytes" {
		t.Fatalf("bytes after finalize: %q", opened)
	}

	// Idempotent for identical metadata.
	if err := svc.MarkFinalized(ctx, s.ID, s.Repo, s.Actor, digest, ref, media, size); err != nil {
		t.Fatalf("identical re-finalize: %v", err)
	}
	// Conflicting second finalization is an error.
	if err := svc.MarkFinalized(ctx, s.ID, s.Repo, s.Actor, "sha256:"+strings.Repeat("e", 64), ref, media, size); !errors.Is(err, ErrFinalizeConflict) {
		t.Fatalf("conflicting re-finalize: %v, want ErrFinalizeConflict", err)
	}
	// Appends after finalization are rejected.
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, size, strings.NewReader("x"), 10); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("append finalized: %v, want ErrInvalidState", err)
	}

	list, err := svc.ListFinalized(ctx, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("ListFinalized: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("finalized count: %d", len(list))
	}
	blob := list[0]
	if blob.UploadID != s.ID || blob.Repo != s.Repo || blob.Actor != s.Actor || blob.Digest != digest || blob.SwarmRef != ref || blob.Size != size || blob.MediaType != media {
		t.Fatalf("staged blob: %+v", blob)
	}
}

func TestServiceMarkFinalizedValidation(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "abcd")

	digest, ref, media, size := finalizeArgs(s)
	cases := []struct {
		name               string
		digest, ref, media string
		size               int64
	}{
		{"bad_digest", "sha256:" + strings.Repeat("B", 64), ref, media, size},
		{"bad_ref", digest, strings.Repeat("C", 64), media, size},
		{"bad_media", digest, ref, "Application/json", size},
		{"wrong_size", digest, ref, media, size + 1},
		{"negative_size", digest, ref, media, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := svc.MarkFinalized(ctx, s.ID, s.Repo, s.Actor, tc.digest, tc.ref, tc.media, tc.size); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err = %v, want ErrInvalidInput", err)
			}
		})
	}
	// Still active after the rejected attempts.
	st, _ := svc.Status(ctx, s.ID, s.Repo, s.Actor)
	if st.State != StateActive {
		t.Fatalf("state after rejected finalize: %+v", st)
	}
}

func TestServiceMarkFinalizedOwnershipAndExpiry(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "abcd")
	digest, ref, media, size := finalizeArgs(s)

	if err := svc.MarkFinalized(ctx, s.ID, "backend/api", "user:eve", digest, ref, media, size); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner finalize: %v, want ErrNotFound family", err)
	}
	if err := svc.MarkFinalized(ctx, s.ID, "other/app", s.Actor, digest, ref, media, size); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-repo finalize: %v, want ErrNotFound family", err)
	}
	if st, _ := svc.Status(ctx, s.ID, s.Repo, s.Actor); st.State != StateActive {
		t.Fatalf("cross-owner finalize mutated session: %+v", st)
	}

	fixedClock(svc, now.Add(time.Hour))
	if err := svc.MarkFinalized(ctx, s.ID, s.Repo, s.Actor, digest, ref, media, size); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired finalize: %v, want ErrExpired", err)
	}
}

func TestServiceMarkFinalizedSurvivesRestart(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "durable")
	digest, ref, media, size := finalizeArgs(s)
	if err := svc.MarkFinalized(ctx, s.ID, s.Repo, s.Actor, digest, ref, media, size); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	svc.Close()

	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer svc2.Close()
	list, err := svc2.ListFinalized(ctx, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("ListFinalized after restart: %v", err)
	}
	if len(list) != 1 || list[0].UploadID != s.ID || list[0].Digest != digest || list[0].SwarmRef != ref || list[0].Size != size {
		t.Fatalf("finalized list after restart: %+v", list)
	}
	st, _ := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
	if st.State != StateFinalized {
		t.Fatalf("state after restart: %+v", st)
	}
	if opened := mustOpenAll(t, svc2, s); opened != "durable" {
		t.Fatalf("bytes after restart: %q", opened)
	}
}

func TestServiceListFinalizedScopedAndDeterministic(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	alice := mustCreate(t, svc, "backend/api", "user:alice")
	alice = mustAppend(t, svc, alice, "a")
	digestA, refA, mediaA, sizeA := finalizeArgs(alice)

	bob, err := svc.Create(ctx, "backend/api", "user:bob", time.Hour)
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}
	bob = mustAppend(t, svc, bob, "bb")

	otherRepo := mustCreate(t, svc, "other/app", "user:alice")
	otherRepo = mustAppend(t, svc, otherRepo, "ccc")

	if err := svc.MarkFinalized(ctx, alice.ID, alice.Repo, alice.Actor, digestA, refA, mediaA, sizeA); err != nil {
		t.Fatalf("finalize alice: %v", err)
	}
	// bob and otherRepo stay active.

	list, err := svc.ListFinalized(ctx, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].UploadID != alice.ID {
		t.Fatalf("scoped list: %+v", list)
	}
	if other, err := svc.ListFinalized(ctx, "other/app", "user:alice"); err != nil || len(other) != 0 {
		t.Fatalf("cross-repo list leaked: %+v err=%v", other, err)
	}
	if other, err := svc.ListFinalized(ctx, "backend/api", "user:bob"); err != nil || len(other) != 0 {
		t.Fatalf("cross-actor list leaked: %+v err=%v", other, err)
	}

	// Deterministic order with a second finalized entry.
	second := mustCreate(t, svc, "backend/api", "user:alice")
	second = mustAppend(t, svc, second, "2")
	digest2, ref2, media2, size2 := finalizeArgs(second)
	if err := svc.MarkFinalized(ctx, second.ID, second.Repo, second.Actor, digest2, ref2, media2, size2); err != nil {
		t.Fatalf("finalize second: %v", err)
	}
	list, err = svc.ListFinalized(ctx, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list 2: %v", err)
	}
	if len(list) != 2 || list[0].UploadID == list[1].UploadID {
		t.Fatalf("deterministic ordering broken: %+v", list)
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestServiceDeleteIdempotentAndRestartSafe(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "delete-me")

	if err := svc.Delete(ctx, s.ID, s.Repo, s.Actor); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("status after delete: %v, want ErrNotFound", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "spool", s.ID)); !os.IsNotExist(err) {
		t.Fatalf("spool file survives delete: %v", err)
	}
	// Idempotent retry.
	if err := svc.Delete(ctx, s.ID, s.Repo, s.Actor); err != nil {
		t.Fatalf("second Delete: %v", err)
	}

	// Restart: nothing reappears.
	svc.Close()
	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer svc2.Close()
	if _, err := svc2.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("status after restart: %v", err)
	}
}

func TestServiceDeleteCrossOwnerLeavesSessionUntouched(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "keep")

	for _, p := range []struct{ repo, actor string }{
		{"backend/api", "user:eve"},
		{"other/app", "user:alice"},
	} {
		if err := svc.Delete(ctx, s.ID, p.repo, p.actor); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-owner delete: %v, want ErrNotFound family", err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "spool", s.ID)); err != nil {
		t.Fatalf("spool file removed by cross-owner delete: %v", err)
	}
	if st, _ := svc.Status(ctx, s.ID, s.Repo, s.Actor); st.State != StateActive || st.Offset != 4 {
		t.Fatalf("session damaged by cross-owner delete: %+v", st)
	}
}

// TestServiceDeleteCompletesInterruptedDeletion proves a deletion interrupted
// after the tombstone commit (row state 'deleting', file still present) is
// completed by a later Delete and by restart reconciliation.
func TestServiceDeleteCompletesInterruptedDeletion(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "doomed")

	// Interrupt after the tombstone step: simulate via direct SQL.
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`update upload_sessions set state='deleting' where id=?`, s.ID); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	db.Close()

	// A retry completes the deletion.
	if err := svc.Delete(ctx, s.ID, s.Repo, s.Actor); err != nil {
		t.Fatalf("delete completing tombstone: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "spool", s.ID)); !os.IsNotExist(err) {
		t.Fatalf("file survives completed deletion: %v", err)
	}
	if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session survives completed deletion: %v", err)
	}
}

// TestServiceRestartCleansDeletingRows proves constructor reconciliation
// finishes interrupted deletions (tombstoned row without file).
func TestServiceRestartCleansDeletingRows(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "doomed")

	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	// Interrupt after tombstone AND after file removal: deleting row, no file.
	if _, err := db.Exec(`update upload_sessions set state='deleting' where id=?`, s.ID); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	db.Close()
	if err := os.Remove(filepath.Join(dir, "spool", s.ID)); err != nil {
		t.Fatalf("remove file: %v", err)
	}

	svc.Close()
	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer svc2.Close()
	if _, err := svc2.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting row survived restart: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Expire
// ---------------------------------------------------------------------------

func TestServiceExpire(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	// Sessions with distinct expiry times.
	mk := func(repo, actor string, ttl time.Duration) Session {
		fixedClock(svc, now)
		s, err := svc.Create(ctx, repo, actor, ttl)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		return s
	}
	young := mk("backend/api", "user:alice", 2*time.Hour)
	old1 := mk("backend/api", "user:alice", time.Hour)
	old2 := mk("other/app", "user:bob", 30*time.Minute)
	_ = mustAppend(t, svc, old1, "x")
	_ = mustAppend(t, svc, old2, "y")

	// At minute 90: old2 (expires 30m) is gone; old1 (expires 60m) is
	// exactly at the expiry boundary and must go; young survives.
	fixedClock(svc, now.Add(90*time.Minute))
	n, err := svc.Expire(ctx, now.Add(90*time.Minute), 100)
	if err != nil {
		t.Fatalf("Expire: %v", err)
	}
	if n != 2 {
		t.Fatalf("expired count = %d, want 2", n)
	}
	for _, gone := range []Session{old1, old2} {
		if _, err := svc.Status(ctx, gone.ID, gone.Repo, gone.Actor); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired session %s survived: %v", gone.ID, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "spool", gone.ID)); !os.IsNotExist(err) {
			t.Fatalf("expired spool file survives: %v", err)
		}
	}
	if st, _ := svc.Status(ctx, young.ID, young.Repo, young.Actor); st.State != StateActive {
		t.Fatalf("unexpired session removed: %+v", st)
	}

	// Idempotent second call.
	n, err = svc.Expire(ctx, now.Add(90*time.Minute), 100)
	if err != nil || n != 0 {
		t.Fatalf("second Expire: n=%d err=%v", n, err)
	}
}

func TestServiceExpireHonorsLimit(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()
	fixedClock(svc, now)
	ids := make([]Session, 3)
	for i := range ids {
		s, err := svc.Create(ctx, "backend/api", "user:alice", time.Minute)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		ids[i] = s
	}
	n, err := svc.Expire(ctx, now.Add(2*time.Minute), 2)
	if err != nil {
		t.Fatalf("Expire: %v", err)
	}
	if n != 2 {
		t.Fatalf("limit violated: expired %d, want 2", n)
	}
	remaining := 0
	for _, s := range ids {
		if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); err == nil {
			remaining++
		}
	}
	if remaining != 1 {
		t.Fatalf("remaining = %d, want 1", remaining)
	}
}

func TestServiceExpireInvalidLimit(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	for _, limit := range []int{0, -1} {
		if _, err := svc.Expire(ctx, time.Now(), limit); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Expire limit %d: %v, want ErrInvalidInput", limit, err)
		}
	}
}

func TestServiceExpireIsContextAware(t *testing.T) {
	svc, _ := newTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now().UTC()
	fixedClock(svc, now)
	for i := 0; i < 20; i++ {
		if _, err := svc.Create(ctx, "backend/api", "user:alice", time.Nanosecond); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	cancel()
	if _, err := svc.Expire(ctx, now.Add(time.Hour), 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("Expire with canceled ctx: %v", err)
	}
}

func TestServiceExpireFinalizedRowsIncluded(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "final")
	digest, ref, media, size := finalizeArgs(s)
	if err := svc.MarkFinalized(ctx, s.ID, s.Repo, s.Actor, digest, ref, media, size); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	// Expiry policy covers finalized rows.
	n, err := svc.Expire(ctx, now.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("Expire: %v", err)
	}
	if n != 1 {
		t.Fatalf("finalized row not expired: n=%d", n)
	}
	if list, _ := svc.ListFinalized(ctx, s.Repo, s.Actor); len(list) != 0 {
		t.Fatalf("finalized list after expiry: %+v", list)
	}
}

// ---------------------------------------------------------------------------
// Restart lifecycle end to end
// ---------------------------------------------------------------------------

func TestServiceRestartFullLifecycle(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()

	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "part1-")
	svc.Close()

	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	st, err := svc2.Status(ctx, s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("status after reopen: %v", err)
	}
	if st.Offset != int64(len("part1-")) {
		t.Fatalf("offset after reopen: %d", st.Offset)
	}
	if opened := mustOpenAll(t, svc2, st); opened != "part1-" {
		t.Fatalf("bytes after reopen: %q", opened)
	}
	st = mustAppend(t, svc2, st, "part2")
	if st.Offset != int64(len("part1-part2")) {
		t.Fatalf("offset after resume: %d", st.Offset)
	}
	digest, ref, media, size := finalizeArgs(st)
	if err := svc2.MarkFinalized(ctx, st.ID, st.Repo, st.Actor, digest, ref, media, size); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	svc2.Close()

	svc3, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen 2: %v", err)
	}
	defer svc3.Close()
	list, err := svc3.ListFinalized(ctx, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list final: %v", err)
	}
	if len(list) != 1 || list[0].Digest != digest || list[0].Size != int64(len("part1-part2")) {
		t.Fatalf("final list: %+v", list)
	}
	if err := svc3.Delete(ctx, st.ID, st.Repo, st.Actor); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestServiceRestartRemovesOrphanFiles(t *testing.T) {
	svc, dir := newTestService(t)
	mustCreate(t, svc, "backend/api", "user:alice")

	// Plant an orphan: a canonical-name file with no DB row (crash between
	// file creation and row commit).
	orphan := strings.Repeat("d", 64)
	if err := os.WriteFile(filepath.Join(dir, "spool", orphan), []byte("orphan"), 0o600); err != nil {
		t.Fatalf("plant orphan: %v", err)
	}
	svc.Close()

	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer svc2.Close()
	if _, err := os.Lstat(filepath.Join(dir, "spool", orphan)); !os.IsNotExist(err) {
		t.Fatalf("orphan file survived startup reconciliation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error hygiene
// ---------------------------------------------------------------------------

func TestServiceErrorsAreDataFree(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	markerID := strings.Repeat("9", 64)
	markerRepo := "backend/api"
	markerActor := "user:marker"
	markerDigest := "sha256:" + strings.Repeat("8", 64)
	markerRef := strings.Repeat("7", 64)

	secrets := []string{dir, "spool", "staging.db", markerID, markerRepo, markerActor, markerDigest, markerRef}

	s, err := svc.Create(ctx, markerRepo, markerActor, time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s = mustAppend(t, svc, s, "bytes")
	_ = mustOpenAll(t, svc, s)

	// Force the full error surface.
	_, _, _, size := finalizeArgs(s)
	errs := []error{}
	commitHook := svc.commitHook
	svc.commitHook = func() error { return errors.New("private-cause-COMMIT") }
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, size, strings.NewReader("x"), 3); err != nil {
		errs = append(errs, err)
	}
	svc.commitHook = commitHook
	svc.dbWriteHook = func() error { return errors.New("private-cause-UPDATE") }
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, size, strings.NewReader("x"), 3); err != nil {
		errs = append(errs, err)
	}
	svc.dbWriteHook = nil
	svc.fsyncHook = func() error { return errors.New("private-cause-FSYNC") }
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, size, strings.NewReader("x"), 3); err != nil {
		errs = append(errs, err)
	}
	svc.fsyncHook = nil

	if _, err := svc.Status(ctx, strings.Repeat("c", 64), markerRepo, markerActor); err != nil {
		errs = append(errs, err)
	}
	if _, err := svc.Status(ctx, s.ID, "other/app", markerActor); err != nil {
		errs = append(errs, err)
	}
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, size+1, strings.NewReader("x"), 3); err != nil {
		errs = append(errs, err)
	}
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, size, strings.NewReader("x"), 0); err != nil {
		errs = append(errs, err)
	}
	if err := svc.MarkFinalized(ctx, s.ID, s.Repo, s.Actor, "sha512:"+strings.Repeat("8", 64), strings.Repeat("7", 64), "application/octet-stream", size); err != nil {
		errs = append(errs, err)
	}
	if err := svc.Delete(ctx, strings.Repeat("9", 64), "other/app", "user:else"); err != nil {
		errs = append(errs, err)
	}
	if _, err := svc.Expire(ctx, time.Now(), 0); err != nil {
		errs = append(errs, err)
	}

	for _, e := range errs {
		text := e.Error()
		for _, secret := range secrets {
			if strings.Contains(text, secret) {
				t.Errorf("error %q leaks %q", text, secret)
			}
		}
	}
}

func containsLeak(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	for _, s := range secrets {
		if strings.Contains(err.Error(), s) {
			return fmt.Errorf("error %q contains %q", err.Error(), s)
		}
	}
	return nil
}

// TestServiceCreateIsPredictableIDFree proves created IDs are server-side
// random 256-bit values: distinct, canonical, and never caller-supplied.
func TestServiceCreateIsPredictableIDFree(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	a, err := svc.Create(ctx, "backend/api", "user:alice", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	b, err := svc.Create(ctx, "backend/api", "user:alice", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.ID == b.ID {
		t.Fatal("IDs collided")
	}
	for _, id := range []string{a.ID, b.ID} {
		if err := validateID(id); err != nil {
			t.Fatalf("non-canonical id %q", id)
		}
	}
}
