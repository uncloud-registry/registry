package staging

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
// On darwin the /var -> /private/var symlink prefix is rewritten to the real
// directory because the strict component walk from "/" rejects symlink
// components by design.
func tempPrivate(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	return symlinkFreeBase(d)
}

// symlinkFreeBase rewrites the OS-standard /var and /tmp symlink prefixes to
// their real directories so the strict component walk never trips on them.
func symlinkFreeBase(p string) string {
	if runtime.GOOS != "darwin" {
		return p
	}
	switch {
	case p == "/var":
		return "/private/var"
	case strings.HasPrefix(p, "/var/"):
		return "/private" + p
	case p == "/tmp":
		return "/private/tmp"
	case strings.HasPrefix(p, "/tmp/"):
		return "/private" + p
	}
	return p
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
// keeps the committed offset, truncates the tail, and — because the restore
// fsync also faulted (durability uncertain) — atomically poisons the live
// service so it fails closed; a FRESH service restart reconciles to exactly
// the last committed bytes.
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

	// The RESTORE fsync also faulted (the same persistent hook fired during
	// the tail truncation), so the tail's durability is uncertain: the live
	// service is atomically poisoned and must not remain usable.
	if poisoned, _, _ := snapPool(svc.pool); !poisoned {
		t.Fatal("pool not poisoned after a failed restore fsync on the ordinary path")
	}
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("x"), 100); !errors.Is(err, ErrDependency) {
		t.Fatalf("poisoned service still accepts an append: %v", err)
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
		if err := svc.Delete(ctx, s.ID, p.repo, p.actor); err != nil {
			t.Fatalf("cross-owner delete must be idempotent nil, got %v", err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "spool", s.ID)); err != nil {
		t.Fatalf("spool file removed by cross-owner delete: %v", err)
	}
	if st, _ := svc.Status(ctx, s.ID, s.Repo, s.Actor); st.State != StateActive || st.Offset != 4 {
		t.Fatalf("session damaged by cross-owner delete: %+v", st)
	}

	// The absent-id and wrong-owner surfaces must be EXACTLY identical (nil),
	// with the foreign row untouched: Delete is never an existence oracle.
	missing := strings.Repeat("e", 64)
	if a, b := svc.Delete(ctx, missing, "backend/api", "user:alice"), svc.Delete(ctx, s.ID, "backend/api", "user:eve"); a != b {
		t.Fatalf("absent=%v wrongOwner=%v, want the identical nil surface", a, b)
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

// TestServiceRestartFailsClosedOnUnknownSpoolFiles proves startup refuses to
// sweep files it cannot attribute: an unknown canonical file is preserved
// byte-for-byte and NewService fails closed with a data-free dependency
// error, so a foreign or interrupted create can never be silently deleted.
func TestServiceRestartFailsClosedOnUnknownSpoolFiles(t *testing.T) {
	svc, dir := newTestService(t)
	mustCreate(t, svc, "backend/api", "user:alice")
	svc.Close()

	orphan := strings.Repeat("d", 64)
	planted := filepath.Join(dir, "spool", orphan)
	if err := os.WriteFile(planted, []byte("unknown-file-content"), 0o600); err != nil {
		t.Fatalf("plant file: %v", err)
	}
	_, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("startup with unknown canonical file: %v, want ErrDependency", err)
	}
	if err.Error() != ErrDependency.Error() {
		t.Fatalf("startup error leaks data: %q", err.Error())
	}
	// The unknown file is preserved, not swept.
	data, err := os.ReadFile(planted)
	if err != nil {
		t.Fatalf("unknown canonical file was removed: %v", err)
	}
	if string(data) != "unknown-file-content" {
		t.Fatalf("unknown canonical file was modified: %q", data)
	}
	// A directory planted at a canonical name is preserved too.
	if err := os.Remove(planted); err != nil {
		t.Fatalf("remove planted: %v", err)
	}
	if err := os.Mkdir(planted, 0o700); err != nil {
		t.Fatalf("mkdir planted: %v", err)
	}
	if _, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db")); !errors.Is(err, ErrDependency) {
		t.Fatalf("startup with planted directory: %v, want ErrDependency", err)
	}
	fi, err := os.Lstat(planted)
	if err != nil || !fi.IsDir() {
		t.Fatalf("planted directory was modified: %v", err)
	}
	// After clearing the obstruction the same database reopens.
	if err := os.RemoveAll(planted); err != nil {
		t.Fatalf("clear: %v", err)
	}
	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen after clear: %v", err)
	}
	svc2.Close()
}

// TestServiceRestartRollsBackCreatingRowWithoutFile proves an interrupted
// create whose row committed but whose file never became durable is rolled
// back on startup once the lease is stale: the row disappears, no file
// appears, and the next restart is clean.
func TestServiceRestartRollsBackCreatingRowWithoutFile(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	id := strings.Repeat("e", 64)
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, ?, ?, ?)`, id, now.Add(-time.Hour).UnixNano(), now.Add(time.Hour).UnixNano(), strings.Repeat("5", 64)); err != nil {
		t.Fatalf("seed creating row: %v", err)
	}
	db.Close()
	svc.Close()

	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer svc2.Close()
	if _, err := svc2.Status(context.Background(), id, "backend/api", "user:alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("creating row survived rollback: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "spool", id)); !os.IsNotExist(err) {
		t.Fatalf("rollback left a file: %v", err)
	}
	// A second restart is clean: no residue from the interrupted create.
	svc2.Close()
	svc3, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("second restart: %v", err)
	}
	svc3.Close()
}

// TestServiceRestartRollsBackCreatingRowWithTokenFile proves a stale
// interrupted create whose file IS durable (crash after file fsync, before
// the activating commit) is rolled back — never adopted: the session is
// gone, and its attributable file is removed with it.
func TestServiceRestartRollsBackCreatingRowWithTokenFile(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Now().UTC()
	id := strings.Repeat("f", 64)
	token := strings.Repeat("7", 64)
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, ?, ?, ?)`, id, now.Add(-time.Hour).UnixNano(), now.Add(time.Hour).UnixNano(), token); err != nil {
		t.Fatalf("seed creating row: %v", err)
	}
	db.Close()
	tokenBytes, err := hex.DecodeString(token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	// New-protocol residue: the canonical payload file (EMPTY) plus the
	// attribution token file carrying the row token.
	if err := os.WriteFile(filepath.Join(dir, "spool", id), nil, 0o600); err != nil {
		t.Fatalf("plant canonical file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "spool", id+".tok"), tokenBytes, 0o600); err != nil {
		t.Fatalf("plant token file: %v", err)
	}
	svc.Close()

	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer svc2.Close()
	if _, err := svc2.Status(context.Background(), id, "backend/api", "user:alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale creating row survived as a session: %v", err)
	}
	for _, name := range []string{id, id + ".tok"} {
		if _, err := os.Lstat(filepath.Join(dir, "spool", name)); !os.IsNotExist(err) {
			t.Fatalf("attributable file %s survived rollback: %v", name, err)
		}
	}
}

// TestServiceRestartLeavesLiveCreatingAlone proves startup never touches a
// LIVE creating lease (created_at fresh): with and without a durable token
// file the row and the file are left exactly as they are, and a subsequent
// Create still works.
func TestServiceRestartLeavesLiveCreatingAlone(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Now().UTC()
	id := strings.Repeat("a", 64)
	token := strings.Repeat("6", 64)
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, ?, ?, ?)`, id, now.Add(-time.Second).UnixNano(), now.Add(time.Hour).UnixNano(), token); err != nil {
		t.Fatalf("seed live creating row: %v", err)
	}
	db.Close()
	tokenBytes, err := hex.DecodeString(token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "spool", id), tokenBytes, 0o600); err != nil {
		t.Fatalf("plant durable token file: %v", err)
	}
	svc.Close()

	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen with live lease: %v", err)
	}
	defer svc2.Close()
	if _, err := svc2.Status(context.Background(), id, "backend/api", "user:alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("creating row became visible: %v", err)
	}
	// The file is untouched and unadopted.
	fi, err := os.Lstat(filepath.Join(dir, "spool", id))
	if err != nil || fi.Size() != int64(len(tokenBytes)) {
		t.Fatalf("live lease file was modified: %v size=%v", err, fi.Size())
	}
	// A genuinely new create still works alongside the live lease.
	s := mustCreate(t, svc2, "backend/api", "user:alice")
	if s.ID == id {
		t.Fatalf("create collided with the live creating id")
	}
}

// TestServiceRestartRejectsWrongTokenFile proves a creating-row file that
// does NOT carry the row's token is unknown residue: startup fails closed
// and the file is never touched.
func TestServiceRestartRejectsWrongTokenFile(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Now().UTC()
	id := strings.Repeat("b", 64)
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, ?, ?, ?)`, id, now.Add(-time.Hour).UnixNano(), now.Add(time.Hour).UnixNano(), strings.Repeat("8", 64)); err != nil {
		t.Fatalf("seed creating row: %v", err)
	}
	db.Close()
	// Attacker plants a 32-byte file with a DIFFERENT token.
	if err := os.WriteFile(filepath.Join(dir, "spool", id), make([]byte, 32), 0o600); err != nil {
		t.Fatalf("plant file: %v", err)
	}
	svc.Close()

	svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err == nil {
		svc2.Close()
		t.Fatal("startup accepted a wrong-token creating file")
	}
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("startup error: %v, want ErrDependency", err)
	}
	fi, err := os.Lstat(filepath.Join(dir, "spool", id))
	if err != nil || fi.Size() != 32 {
		t.Fatalf("attacker file was modified: %v size=%v", err, fi.Size())
	}
}

// TestServiceCreateBarrierAcrossInstances proves startup never touches a
// live Create on another instance: A is paused after its durable token file
// (before activation), B constructs cleanly, and A's guarded activation
// still completes. A stale variant proves a rollback by a third instance
// makes A's activation fail closed with no residue.
func TestServiceCreateBarrierAcrossInstances(t *testing.T) {
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")

	svcA, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	defer svcA.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	var barrierOnce sync.Once
	svcA.createBarrier = func() {
		barrierOnce.Do(func() {
			close(entered)
			<-release
		})
	}

	var ses Session
	var createErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ses, createErr = svcA.Create(context.Background(), "backend/api", "user:alice", time.Hour)
	}()
	<-entered // A is at the activation barrier with a durable token file.

	// B constructs while A's create is live: the lease is fresh, so startup
	// leaves A's row and file alone.
	svcB, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("B during live create: %v", err)
	}
	defer svcB.Close()
	if _, err := svcB.Status(context.Background(), strings.Repeat("a", 64), "backend/api", "user:alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("B sees a phantom session: %v", err)
	}

	close(release)
	wg.Wait()
	if createErr != nil {
		t.Fatalf("A create after barrier: %v", createErr)
	}
	// The session is active and usable by both instances.
	st, err := svcB.Status(context.Background(), ses.ID, "backend/api", "user:alice")
	if err != nil || st.State != StateActive {
		t.Fatalf("B cannot see the completed session: %+v %v", st, err)
	}
	_ = mustAppend(t, svcB, st, "data")

	// Stale variant: another instance rolls the live create back by aging
	// its lease, and A's guarded activation then fails closed.
	svcA2, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("A2: %v", err)
	}
	entered2 := make(chan struct{})
	release2 := make(chan struct{})
	svcA2.createBarrier = func() {
		close(entered2)
		<-release2
	}
	var createErr2 error
	wg = sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, createErr2 = svcA2.Create(context.Background(), "backend/api", "user:alice", time.Hour)
	}()
	<-entered2
	// Age the lease: recreate the SAME creating row with the same token but
	// an old created_at (the identity trigger forbids updating timestamps,
	// so the row is tombstoned and re-inserted). The durable token file
	// stays in place, so the row becomes stale-and-attributable to a third
	// instance, and A2's activation — guarded by the created_at anchor —
	// must then fail closed.
	db, err := sqlOpenForTest(dbPath)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	var rowID, rowTok string
	if err := db.QueryRow(`select id, create_token from upload_sessions where state='creating'`).Scan(&rowID, &rowTok); err != nil {
		t.Fatalf("read live row: %v", err)
	}
	if _, err := db.Exec(`update upload_sessions set state='deleting', create_token=null where id = ?`, rowID); err != nil {
		t.Fatalf("tombstone live row: %v", err)
	}
	if _, err := db.Exec(`delete from upload_sessions where id = ?`, rowID); err != nil {
		t.Fatalf("drop live row: %v", err)
	}
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, ?, ?, ?)`,
		rowID, time.Now().Add(-time.Hour).UnixNano(), time.Now().Add(time.Hour).UnixNano(), rowTok); err != nil {
		t.Fatalf("recreate aged row: %v", err)
	}
	db.Close()
	// C's startup sees a stale, token-attributable creating row: it rolls it
	// back AND removes its attributable file.
	svcC, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("C during stale create: %v", err)
	}
	var creating sql.NullString
	dbb, err := sqlOpenForTest(dbPath)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if err := dbb.QueryRow(`select state from upload_sessions where id = ?`, rowID).Scan(&creating); err == nil || !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("C left the stale creating row (state=%v err=%v)", creating, err)
	}
	dbb.Close()
	if _, err := os.Lstat(filepath.Join(spoolDir, rowID)); !os.IsNotExist(err) {
		t.Fatalf("C left the stale create's attributable file: %v", err)
	}
	close(release2)
	wg.Wait()
	if createErr2 == nil || !errors.Is(createErr2, ErrDependency) {
		t.Fatalf("A's stale activation must fail closed, got %v", createErr2)
	}
	files, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	// The stale create left no residue: the only spool entry is the first
	// (successful) session.
	var names []string
	for _, e := range files {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != ses.ID {
		t.Fatalf("stale create left residue: %v (want only %s)", names, ses.ID)
	}
	svcC.Close()
	svcA2.Close()
}

// TestServiceCreateActivationCommitFault proves a commit fault on the
// ACTIVATING transaction (the creating row committed, the activation did
// not) is rolled back fully: the attributable file is removed and the row
// disappears.
func TestServiceCreateActivationCommitFault(t *testing.T) {
	svc, dir := newTestService(t)
	var once atomic.Int32
	svc.commitHook = func() error {
		if once.Add(1) == 2 {
			return errors.New("activation commit fault")
		}
		return nil
	}
	if _, err := svc.Create(context.Background(), "backend/api", "user:alice", time.Hour); !errors.Is(err, ErrDependency) {
		t.Fatalf("Create: %v, want ErrDependency", err)
	}
	// The rollback is convergent: no row, no file.
	var n int
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if err := db.QueryRow(`select count(*) from upload_sessions`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	db.Close()
	if n != 0 {
		t.Fatalf("activation fault left %d rows", n)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "spool"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("activation fault left spool entries: %v", entries)
	}
}

// TestServiceCreateFaultsLeaveNoResidue proves every durability fault during
// Create (file fsync, directory fsync, activating commit) returns a
// data-free dependency error and leaves no user-visible residue: no rows, or
// at most a durable deleting tombstone that a restart completes.
func TestServiceCreateFaultsLeaveNoResidue(t *testing.T) {
	ctx := context.Background()
	scenarios := []struct {
		name string
		arm  func(svc *service)
	}{
		{"file_sync", func(svc *service) { svc.fsyncHook = func() error { return errors.New("file-sync fault") } }},
		{"dir_sync", func(svc *service) { svc.dirSyncHook = func() error { return errors.New("dir-sync fault") } }},
		// The commit fault fires exactly once: the creating-row transaction
		// commits, the ACTIVATING transaction faults, and the rollback
		// transactions succeed afterwards.
		{"activate_commit", func(svc *service) {
			var once atomic.Int32
			svc.commitHook = func() error {
				if once.Add(1) == 1 {
					return errors.New("commit fault")
				}
				return nil
			}
		}},
	}
	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			svc, dir := newTestService(t)
			tc.arm(svc)
			if _, err := svc.Create(ctx, "backend/api", "user:alice", time.Hour); !errors.Is(err, ErrDependency) {
				t.Fatalf("Create with %s: %v, want ErrDependency", tc.name, err)
			}
			// No durably-visible residue. A dir-sync fault may leave the
			// durable deleting tombstone by design (unlink durability could
			// not be confirmed); every other phase is fully clean.
			var id, state sql.NullString
			db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
			if err != nil {
				t.Fatalf("raw open: %v", err)
			}
			if err := db.QueryRow(`select id, state from upload_sessions`).Scan(&id, &state); err != nil {
				if err != sql.ErrNoRows {
					t.Fatalf("scan rows: %v", err)
				}
			}
			db.Close()
			entries, err := os.ReadDir(filepath.Join(dir, "spool"))
			if err != nil {
				t.Fatalf("readdir spool: %v", err)
			}
			// A dir-sync fault correctly RETAINS an already-quarantined leaf (the
			// rename's durability could not be confirmed, so it is never unlinked),
			// which is exactly the fail-closed contract. The only acceptable
			// residue is a deterministic `q-` quarantine name; no managed canonical
			// or token file may remain. The restart below converges any retained
			// quarantine.
			for _, en := range entries {
				if strings.HasPrefix(en.Name(), "q-") {
					continue
				}
				t.Fatalf("faulted create left a non-quarantine spool entry: %s", en.Name())
			}
			if state.Valid && State(state.String) != StateDeleting {
				t.Fatalf("faulted create left non-tombstone row in state %q", state.String)
			}
			if state.Valid && id.Valid {
				if _, err := os.Lstat(filepath.Join(dir, "spool", id.String)); !os.IsNotExist(err) {
					t.Fatalf("tombstoned row still owns a spool file: %v", err)
				}
			}
			// The service remains healthy, and a restart is clean even when a
			// tombstone was retained.
			svc.fsyncHook = nil
			svc.dirSyncHook = nil
			svc.commitHook = nil
			svc.Close()
			svc2, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
			if err != nil {
				t.Fatalf("restart: %v", err)
			}
			svc2.Close()
			db2, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
			if err != nil {
				t.Fatalf("raw reopen: %v", err)
			}
			var rows int
			if err := db2.QueryRow(`select count(*) from upload_sessions`).Scan(&rows); err != nil {
				t.Fatalf("count after restart: %v", err)
			}
			db2.Close()
			if rows != 0 {
				t.Fatalf("restart left %d rows", rows)
			}
			svc3, err := NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
			if err != nil {
				t.Fatalf("service after restart: %v", err)
			}
			mustCreate(t, svc3, "backend/api", "user:alice")
			svc3.Close()
		})
	}
}

// TestServiceDeleteUnlinkFailureRetainsTombstone proves a failed unlink keeps
// the durable deleting tombstone and the foreign file intact; once the
// obstruction clears, the same Delete retries and completes.
func TestServiceDeleteUnlinkFailureRetainsTombstone(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "doomed")

	// Plant a non-empty directory at the session name so unlink fails.
	planted := filepath.Join(dir, "spool", s.ID)
	if err := os.Remove(planted); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	if err := os.Mkdir(planted, 0o700); err != nil {
		t.Fatalf("mkdir planted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(planted, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatalf("plant content: %v", err)
	}

	if err := svc.Delete(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrDependency) {
		t.Fatalf("Delete with unlink failure: %v, want ErrDependency", err)
	}
	// Tombstone retained: the row still exists in deleting state and the
	// foreign directory is intact.
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	var state string
	if err := db.QueryRow(`select state from upload_sessions where id = ?`, s.ID).Scan(&state); err != nil {
		t.Fatalf("row gone after failed unlink: %v", err)
	}
	db.Close()
	if state != "deleting" {
		t.Fatalf("state = %q, want deleting tombstone", state)
	}
	if _, err := os.Lstat(filepath.Join(planted, "keep")); err != nil {
		t.Fatalf("planted directory was damaged: %v", err)
	}
	// Clear the obstruction; the retry completes the deletion.
	if err := os.RemoveAll(planted); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if err := svc.Delete(ctx, s.ID, s.Repo, s.Actor); err != nil {
		t.Fatalf("Delete after clear: %v", err)
	}
	if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session survived: %v", err)
	}
}

// TestServiceExpireFaultAtEveryPhase proves Expire fail-closes at each phase:
// tombstone commit, unlink, directory fsync, and metadata-delete commit.
// The row or tombstone is retained for a later retry and the count only
// reports fully completed deletions.
func TestServiceExpireFaultAtEveryPhase(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	fixedClock(svc, now)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	_ = mustAppend(t, svc, s, "expired")
	future := now.Add(2 * time.Hour)
	stateOf := func() string {
		db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
		if err != nil {
			t.Fatalf("raw open: %v", err)
		}
		defer db.Close()
		var st string
		if err := db.QueryRow(`select state from upload_sessions where id = ?`, s.ID).Scan(&st); err != nil {
			t.Fatalf("row missing: %v", err)
		}
		return st
	}
	fileGone := func() bool {
		_, err := os.Lstat(filepath.Join(dir, "spool", s.ID))
		return os.IsNotExist(err)
	}

	// Phase 1: tombstone commit fails -> row untouched, file intact.
	svc.commitHook = func() error { return errors.New("tombstone commit fault") }
	if n, err := svc.Expire(ctx, future, 10); !errors.Is(err, ErrDependency) || n != 0 {
		t.Fatalf("phase 1: n=%d err=%v", n, err)
	}
	svc.commitHook = nil
	if got := stateOf(); got != "active" {
		t.Fatalf("phase 1 state = %q, want active", got)
	}
	if fileGone() {
		t.Fatal("phase 1 removed the file")
	}

	// Phase 2: unlink fails (planted non-empty directory).
	planted := filepath.Join(dir, "spool", s.ID)
	if err := os.Remove(planted); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	if err := os.Mkdir(planted, 0o700); err != nil {
		t.Fatalf("mkdir planted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(planted, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}
	if n, err := svc.Expire(ctx, future, 10); !errors.Is(err, ErrDependency) || n != 0 {
		t.Fatalf("phase 2: n=%d err=%v", n, err)
	}
	if got := stateOf(); got != "deleting" {
		t.Fatalf("phase 2 state = %q, want deleting tombstone", got)
	}
	if _, err := os.Lstat(filepath.Join(planted, "keep")); err != nil {
		t.Fatalf("phase 2 damaged the obstruction: %v", err)
	}
	if err := os.RemoveAll(planted); err != nil {
		t.Fatalf("clear: %v", err)
	}

	// Phase 3: directory fsync fails after the unlink -> count 0, tombstone
	// retained, file durably gone.
	svc.dirSyncHook = func() error { return errors.New("dir-sync fault") }
	if n, err := svc.Expire(ctx, future, 10); !errors.Is(err, ErrDependency) || n != 0 {
		t.Fatalf("phase 3: n=%d err=%v", n, err)
	}
	svc.dirSyncHook = nil
	if got := stateOf(); got != "deleting" {
		t.Fatalf("phase 3 state = %q, want deleting", got)
	}
	if !fileGone() {
		t.Fatal("phase 3 left the file")
	}
	if got := stateOf(); got != "deleting" {
		t.Fatalf("phase 3 state = %q, want deleting", got)
	}

	// Phase 4: metadata-delete commit fails -> count 0, row retained.
	svc.commitHook = func() error { return errors.New("metadata delete fault") }
	if n, err := svc.Expire(ctx, future, 10); !errors.Is(err, ErrDependency) || n != 0 {
		t.Fatalf("phase 4: n=%d err=%v", n, err)
	}
	svc.commitHook = nil
	if got := stateOf(); got != "deleting" {
		t.Fatalf("phase 4 state = %q, want deleting", got)
	}

	// Complete: the retry finishes the deletion and counts it.
	n, err := svc.Expire(ctx, future, 10)
	if err != nil || n != 1 {
		t.Fatalf("final Expire: n=%d err=%v", n, err)
	}
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	var rows int
	if err := db.QueryRow(`select count(*) from upload_sessions`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	db.Close()
	if rows != 0 {
		t.Fatalf("final state left %d rows", rows)
	}
}

// TestServiceExpireCountsOnlyCompletedDeletions proves the returned count is
// the number of fully completed deletions: a mid-list failure stops the run,
// leaves the remaining rows coherent, and later runs finish them.
func TestServiceExpireCountsOnlyCompletedDeletions(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	fixedClock(svc, now)
	mk := func(repo string, ttl time.Duration) Session {
		s, err := svc.Create(ctx, repo, "user:alice", ttl)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		return s
	}
	a := mk("a/app", time.Minute)
	b := mk("b/app", 2*time.Minute)
	c := mk("c/app", 3*time.Minute)
	future := now.Add(10 * time.Minute)

	// Sabotage the SECOND row in deterministic expiry order so only the first
	// completes; the run must fail at b and leave c untouched.
	planted := filepath.Join(dir, "spool", b.ID)
	if err := os.Remove(planted); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(planted, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(planted, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}

	n, err := svc.Expire(ctx, future, 3)
	if err == nil || !errors.Is(err, ErrDependency) {
		t.Fatalf("Expire with obstruction: n=%d err=%v", n, err)
	}
	if n != 1 {
		t.Fatalf("completed count = %d, want exactly 1 (only the first)", n)
	}
	if _, err := svc.Status(ctx, a.ID, a.Repo, a.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a survived: %v", err)
	}
	for _, s := range []Session{b, c} {
		if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); err != nil {
			t.Fatalf("%s lost coherence: %v", s.ID[:8], err)
		}
	}

	// Clear the obstruction; a later run finishes b (already tombstoned) and
	// c, and only counts the two completed this run.
	if err := os.RemoveAll(planted); err != nil {
		t.Fatalf("clear: %v", err)
	}
	n, err = svc.Expire(ctx, future, 3)
	if err != nil || n != 2 {
		t.Fatalf("resume Expire: n=%d err=%v", n, err)
	}
	for _, s := range []Session{a, b, c} {
		if _, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s survived final expire: %v", s.ID[:8], err)
		}
	}
}

// TestServiceExpireCrossInstance proves concurrent Expire runs over the same
// spool/database from two service handles both succeed and converge: every
// expired row is removed exactly once and no row or file is left behind.
func TestServiceExpireCrossInstance(t *testing.T) {
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")
	svcA, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	defer svcA.Close()
	svcB, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	defer svcB.Close()

	ctx := context.Background()
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	fixedClock(svcA, now)
	var sessions []Session
	for i := 0; i < 8; i++ {
		s, err := svcA.Create(ctx, "backend/api", "user:alice", time.Minute)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		sessions = append(sessions, s)
	}
	future := now.Add(time.Hour)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, svc := range []*service{svcA, svcB} {
		wg.Add(1)
		go func(i int, svc *service) {
			defer wg.Done()
			_, errs[i] = svc.Expire(ctx, future, 100)
		}(i, svc)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("concurrent Expire %d: %v", i, e)
		}
	}
	// Everything is gone: no rows, no files, and both handles agree.
	db, err := sqlOpenForTest(dbPath)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	var rows int
	if err := db.QueryRow(`select count(*) from upload_sessions`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	db.Close()
	if rows != 0 {
		t.Fatalf("cross-instance expire left %d rows", rows)
	}
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("cross-instance expire left files: %v", entries)
	}
	for _, svc := range []*service{svcA, svcB} {
		if n, err := svc.Expire(ctx, future, 100); err != nil || n != 0 {
			t.Fatalf("post-converge Expire: n=%d err=%v", n, err)
		}
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

// assertDataFreeDependency verifies an error is the data-free ErrDependency
// family: identical fixed text, Is/Unwrap identity, no leaked formatting
// fields, and an empty JSON surface.
func assertDataFreeDependency(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("want ErrDependency, got %T %v", err, err)
	}
	if err.Error() != ErrDependency.Error() {
		t.Fatalf("error text differs: %q vs %q", err.Error(), ErrDependency.Error())
	}
	formatted := fmt.Sprintf("%v|%+v|%#v|%q", err, err, err, err)
	for _, s := range secrets {
		if s != "" && strings.Contains(formatted, s) {
			t.Fatalf("error leaks %q: %s", s, formatted)
		}
	}
	if u := errors.Unwrap(err); u != nil && !errors.Is(u, ErrDependency) && u != context.Canceled && u != context.DeadlineExceeded {
		t.Fatalf("unwrap leaked a foreign error: %v", u)
	}
	b, jerr := json.Marshal(err)
	if jerr != nil {
		t.Fatalf("json marshal: %v", jerr)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if len(fields) != 0 {
		t.Fatalf("error serializes data: %s", b)
	}
}

// TestServiceOwnerMismatchIdentityEqualsNotFound proves missing and
// wrong-owner outcomes are indistinguishable by error identity across every
// operation: same value, same text, same unwrap, same Is/As surfaces, same
// formatted and JSON output. The exported ErrOwnerMismatch is gone; only
// ErrNotFound is observable.
func TestServiceOwnerMismatchIdentityEqualsNotFound(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	missingID := strings.Repeat("c", 64)
	digest, ref, media, size := finalizeArgs(s)

	type pair struct {
		name    string
		missing func() error
		foreign func() error
	}
	pairs := []pair{
		{
			name: "Status",
			missing: func() error {
				_, err := svc.Status(ctx, missingID, "backend/api", "user:alice")
				return err
			},
			foreign: func() error {
				_, err := svc.Status(ctx, s.ID, "other/app", "user:alice")
				return err
			},
		},
		{
			name: "Append",
			missing: func() error {
				_, err := svc.Append(ctx, missingID, "backend/api", "user:alice", 0, strings.NewReader("x"), 3)
				return err
			},
			foreign: func() error {
				_, err := svc.Append(ctx, s.ID, "other/app", "user:alice", 0, strings.NewReader("x"), 3)
				return err
			},
		},
		{
			name: "Open",
			missing: func() error {
				_, _, err := svc.Open(ctx, missingID, "backend/api", "user:alice")
				return err
			},
			foreign: func() error {
				_, _, err := svc.Open(ctx, s.ID, "other/app", "user:alice")
				return err
			},
		},
		{
			name: "MarkFinalized",
			missing: func() error {
				return svc.MarkFinalized(ctx, missingID, "backend/api", "user:alice", digest, ref, media, size)
			},
			foreign: func() error {
				return svc.MarkFinalized(ctx, s.ID, "other/app", "user:alice", digest, ref, media, size)
			},
		},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			missing := p.missing()
			foreign := p.foreign()
			if missing == nil || foreign == nil {
				t.Fatalf("missing=%v foreign=%v, both must fail", missing, foreign)
			}
			if missing != foreign {
				t.Fatal("owner mismatch error differs from not-found by identity")
			}
			if missing != ErrNotFound {
				t.Fatal("missing error is not the exported ErrNotFound sentinel")
			}
			if foreign != ErrNotFound {
				t.Fatal("wrong-owner error is not the exported ErrNotFound sentinel")
			}
			if errors.Unwrap(missing) != nil || errors.Unwrap(foreign) != nil {
				t.Fatal("ErrNotFound must not unwrap")
			}
			if !errors.Is(missing, ErrNotFound) || !errors.Is(foreign, ErrNotFound) {
				t.Fatal("Is(ErrNotFound) failed")
			}
			var target interface{ Error() string }
			if !errors.As(missing, &target) {
				t.Fatal("As to error interface failed")
			}
			if fmt.Sprintf("%v|%+v|%#v|%q", missing, missing, missing, missing) !=
				fmt.Sprintf("%v|%+v|%#v|%q", foreign, foreign, foreign, foreign) {
				t.Fatal("formatted surfaces differ")
			}
			bm, _ := json.Marshal(missing)
			bf, _ := json.Marshal(foreign)
			if string(bm) != string(bf) {
				t.Fatalf("json surfaces differ: %s vs %s", bm, bf)
			}
		})
	}
	// Delete is idempotent and confidential: absent and wrong-owner ids are
	// EXACTLY nil and identical, and the foreign row is untouched (no
	// existence oracle).
	if a, b := svc.Delete(ctx, missingID, "backend/api", "user:alice"), svc.Delete(ctx, s.ID, "other/app", "user:alice"); a != nil || b != nil {
		t.Fatalf("absent delete = %v, wrong-owner delete = %v; both must be identical nil", a, b)
	}
	// Wrong-owner Delete over the REAL owner's session was already exercised
	// above (foreign Delete); the session must still be owned by alice.
	st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor)
	if err != nil || st.State != StateActive {
		t.Fatalf("wrong-owner Delete damaged the session: %+v %v", st, err)
	}
}

// TestServiceCreatingInvisible proves a committed creating row is invisible
// to every read path (Status/Append/Open/MarkFinalized) even for its owner,
// while Delete may tombstone it (so interrupted creates can be cleaned).
func TestServiceCreatingInvisible(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	id := strings.Repeat("e", 64)
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, ?, ?, ?)`, id, now.UnixNano(), now.Add(time.Hour).UnixNano(), strings.Repeat("2", 64)); err != nil {
		t.Fatalf("seed creating row: %v", err)
	}
	db.Close()

	digest, ref, media, size := finalizeArgs(Session{ID: id, Repo: "backend/api", Actor: "user:alice", Offset: 0})
	pairs := []struct {
		name string
		call func() error
	}{
		{"Status", func() error { _, err := svc.Status(ctx, id, "backend/api", "user:alice"); return err }},
		{"Append", func() error {
			_, err := svc.Append(ctx, id, "backend/api", "user:alice", 0, strings.NewReader("x"), 3)
			return err
		}},
		{"Open", func() error { _, _, err := svc.Open(ctx, id, "backend/api", "user:alice"); return err }},
		{"MarkFinalized", func() error { return svc.MarkFinalized(ctx, id, "backend/api", "user:alice", digest, ref, media, size) }},
	}
	for _, p := range pairs {
		if err := p.call(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s on creating row = %v, want ErrNotFound", p.name, err)
		}
	}
	// The owner can tombstone it (crash-recovery surface), and it then goes
	// away entirely.
	if err := svc.Delete(ctx, id, "backend/api", "user:alice"); err != nil {
		t.Fatalf("Delete creating row: %v", err)
	}
	if _, err := svc.Status(ctx, id, "backend/api", "user:alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("creating row survived delete: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "spool", id)); !os.IsNotExist(err) {
		t.Fatal("creating file survived delete")
	}
}

// TestServiceOperationsAnchoredAcrossRootSwap proves every spool operation
// stays anchored to the ORIGINAL directory when the root path is renamed
// away and replaced with a symlink: reads and writes land in the original
// directory, never through the planted link.
func TestServiceOperationsAnchoredAcrossRootSwap(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "stable")

	// Rename the spool directory away and plant a symlink to a decoy dir at
	// the original path.
	spoolPath := filepath.Join(dir, "spool")
	moved := filepath.Join(dir, "spool-moved")
	if err := os.Rename(spoolPath, moved); err != nil {
		t.Fatalf("rename: %v", err)
	}
	decoy := filepath.Join(dir, "decoy")
	if err := os.Mkdir(decoy, 0o700); err != nil {
		t.Fatalf("mkdir decoy: %v", err)
	}
	if err := os.Symlink(decoy, spoolPath); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	// Existing session still readable and appendable.
	if opened := mustOpenAll(t, svc, s); opened != "stable" {
		t.Fatalf("bytes after swap: %q", opened)
	}
	s = mustAppend(t, svc, s, "more")
	if s.Offset != int64(len("stablemore")) {
		t.Fatalf("offset after swap: %d", s.Offset)
	}
	// New sessions land in the ORIGINAL directory.
	s3 := mustCreate(t, svc, "backend/api", "user:alice")
	if _, err := os.Lstat(filepath.Join(moved, s3.ID)); err != nil {
		t.Fatalf("new file not in the anchored directory: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(decoy, s3.ID)); !os.IsNotExist(err) {
		t.Fatal("new file reached through the planted symlink")
	}
	// Deletes remove from the original directory.
	if err := svc.Delete(ctx, s3.ID, s3.Repo, s3.Actor); err != nil {
		t.Fatalf("delete after swap: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(moved, s3.ID)); !os.IsNotExist(err) {
		t.Fatal("deleted file still in anchored directory")
	}
}

// TestNewServiceConstructorErrorConfidentiality proves NewService failures
// (spool path problems, database problems, startup reconciliation problems)
// return fixed data-free ErrDependency errors: no paths, DSNs, SQL, or raw
// causes through Error/Unwrap/formatted/JSON/reflection surfaces.
func TestNewServiceConstructorErrorConfidentiality(t *testing.T) {
	dir := tempPrivate(t)
	secret := "CONSTRUCTOR-SECRET-" + strings.Repeat("x", 8)

	cases := []struct {
		name    string
		setup   func() (spool, db string)
		secrets []string
	}{
		{
			"spool_root_is_a_file",
			func() (string, string) {
				spool := filepath.Join(dir, secret)
				if err := os.WriteFile(spool, []byte("x"), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
				return spool, filepath.Join(dir, "staging.db")
			},
			nil,
		},
		{
			"spool_root_symlink_component",
			func() (string, string) {
				real := filepath.Join(dir, "real")
				if err := os.Mkdir(real, 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				link := filepath.Join(dir, "link")
				if err := os.Symlink(real, link); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return filepath.Join(link, secret), filepath.Join(dir, "staging.db")
			},
			[]string{secret},
		},
		{
			"database_is_symlink",
			func() (string, string) {
				real := filepath.Join(dir, "real.db")
				if err := os.WriteFile(real, []byte("FOREIGN"), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
				dbPath := filepath.Join(dir, secret+".db")
				if err := os.Symlink(real, dbPath); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return filepath.Join(dir, "spool"), dbPath
			},
			[]string{secret},
		},
		{
			"database_parent_is_a_file",
			func() (string, string) {
				parent := filepath.Join(dir, "parent-file")
				if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
				return filepath.Join(dir, "spool"), filepath.Join(parent, secret+".db")
			},
			[]string{secret},
		},
		{
			"database_foreign_schema",
			func() (string, string) {
				dbPath := filepath.Join(dir, "foreign.db")
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				if _, err := db.Exec(`create table other_thing (id integer)`); err != nil {
					t.Fatalf("create: %v", err)
				}
				db.Close()
				return filepath.Join(dir, "spool"), dbPath
			},
			[]string{},
		},
		{
			"unknown_spool_file_at_startup",
			func() (string, string) {
				// A clean database first so failure comes from reconciliation.
				// The seed service creates the spool root itself.
				spool := filepath.Join(dir, "spool")
				dbPath := filepath.Join(dir, "staging.db")
				svc, err := NewService(context.Background(), spool, dbPath)
				if err != nil {
					t.Fatalf("seed service: %v", err)
				}
				svc.Close()
				if err := os.WriteFile(filepath.Join(spool, strings.Repeat("f", 64)), []byte(secret), 0o600); err != nil {
					t.Fatalf("plant: %v", err)
				}
				return spool, dbPath
			},
			[]string{secret},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spool, dbPath := tc.setup()
			_, err := NewService(context.Background(), spool, dbPath)
			secrets := append([]string{dir}, tc.secrets...)
			assertDataFreeDependency(t, err, secrets...)
		})
	}
	// The symlink database target must remain byte-identical after rejection.
	real := filepath.Join(dir, "real.db")
	if _, err := os.Lstat(real); err == nil {
		before := hashFile(t, real)
		dbPath := filepath.Join(dir, secret+".db")
		if db, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
			db.Close()
			t.Fatal("symlinked db accepted by constructor path")
		}
		if after := hashFile(t, real); after != before {
			t.Fatal("symlink target modified after constructor rejection")
		}
	}
}

// TestNewServiceContextCancellation proves a canceled context surfaces as the
// exact context error (the one sanctioned sentinel payload), not as a
// dependency error.
func TestNewServiceContextCancellation(t *testing.T) {
	dir := tempPrivate(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewService(ctx, filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled constructor: %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrDependency) {
		t.Fatal("canceled constructor surfaced as ErrDependency")
	}
}
