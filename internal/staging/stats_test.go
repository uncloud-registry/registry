package staging

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCheckStagingRootAccess proves the /readyz staging check passes while
// the spool root exists, fails once the root is removed, and carries a
// data-free error (never the path).
func TestCheckStagingRootAccess(t *testing.T) {
	svc, dir := newTestService(t)
	if err := svc.CheckStagingRootAccess(context.Background()); err != nil {
		t.Fatalf("root check on a healthy service: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "spool")); err != nil {
		t.Fatalf("remove spool root: %v", err)
	}
	err := svc.CheckStagingRootAccess(context.Background())
	if err == nil {
		t.Fatal("root check must fail after the spool root was removed")
	}
	if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "spool") {
		t.Fatalf("root check error must never carry the path: %v", err)
	}
}

// TestStagingStatsReportsByteBearingSessions proves the durable service's
// bounded aggregate stats snapshot counts exactly the byte-bearing staged
// rows and their total staged bytes — the values exposed on /metrics.
func TestStagingStatsReportsByteBearingSessions(t *testing.T) {
	svc, _ := newTestService(t)

	// Empty staging reports zero bytes and zero sessions.
	bytes, sessions, err := svc.StagingStats(context.Background())
	if err != nil {
		t.Fatalf("StagingStats on empty service: %v", err)
	}
	if bytes != 0 || sessions != 0 {
		t.Fatalf("empty staging stats = bytes %d sessions %d, want 0/0", bytes, sessions)
	}

	// One active session with 10 bytes appended.
	sess, err := svc.Create(context.Background(), "backend/api", "user:alice", time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := svc.Append(context.Background(), sess.ID, "backend/api", "user:alice", 0, strings.NewReader("0123456789"), 64); err != nil {
		t.Fatalf("append: %v", err)
	}

	bytes, sessions, err = svc.StagingStats(context.Background())
	if err != nil {
		t.Fatalf("StagingStats: %v", err)
	}
	if bytes != 10 {
		t.Fatalf("staged bytes = %d, want 10", bytes)
	}
	if sessions != 1 {
		t.Fatalf("staged sessions = %d, want 1", sessions)
	}
}

// TestStagingStatsIncludesFinalizedRows proves finalized rows still count
// toward the byte-bearing snapshot until consumption/cleanup removes them.
func TestStagingStatsIncludesFinalizedRows(t *testing.T) {
	svc, _ := newTestService(t)

	sess, err := svc.Create(context.Background(), "backend/api", "user:alice", time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := svc.Append(context.Background(), sess.ID, "backend/api", "user:alice", 0, strings.NewReader("abcd"), 64); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Finalize without a Bee sidecar: MarkFinalized at plain service level.
	digest := "sha256:" + digestHex([]byte("abcd"))
	ref := string(bytes.Repeat([]byte{'e'}, 64))
	if err := svc.MarkFinalized(context.Background(), sess.ID, "backend/api", "user:alice", strings.Repeat("a", 64), digest, ref, "application/octet-stream", 4); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	bytes, sessions, err := svc.StagingStats(context.Background())
	if err != nil {
		t.Fatalf("StagingStats: %v", err)
	}
	if bytes != 4 {
		t.Fatalf("staged bytes after finalize = %d, want 4", bytes)
	}
	if sessions != 1 {
		t.Fatalf("staged sessions after finalize = %d, want 1", sessions)
	}
}
