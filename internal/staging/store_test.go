package staging

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"testing"
	"time"
)

func TestMemoryStoreSessionLifecycle(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()
	session, err := store.Create(ctx, "backend/api", "user:alice", time.Minute)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	updated, err := store.Append(ctx, session.ID, "backend/api", "user:alice", 0, bytes.NewReader([]byte("hello")), 100)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if updated.Offset != 5 {
		t.Fatalf("append offset = %d, want 5", updated.Offset)
	}
	if _, err := store.Append(ctx, session.ID, "backend/api", "user:alice", 5, bytes.NewReader([]byte(" world")), 100); err != nil {
		t.Fatalf("append 2: %v", err)
	}

	rc, snap, err := store.Open(ctx, session.ID, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("unexpected bytes: %q", got)
	}
	if snap.Offset != 11 {
		t.Fatalf("snapshot offset = %d, want 11", snap.Offset)
	}
}

func TestMemoryStoreStaleOffsetRejected(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	ctx := context.Background()
	s, err := store.Create(ctx, "backend/api", "user:alice", time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := store.Append(ctx, s.ID, "backend/api", "user:alice", 0, bytes.NewReader([]byte("abcd")), 100); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Stale expected offset must be rejected with no mutation.
	if _, err := store.Append(ctx, s.ID, "backend/api", "user:alice", 2, bytes.NewReader([]byte("xy")), 100); err != ErrOffsetMismatch {
		t.Fatalf("stale offset: got %v, want ErrOffsetMismatch", err)
	}
	snap, err := store.Status(ctx, s.ID, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if snap.Offset != 4 {
		t.Fatalf("stale append mutated offset to %d", snap.Offset)
	}
}

func TestMemoryStoreOverflowRejected(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	ctx := context.Background()
	s, err := store.Create(ctx, "backend/api", "user:alice", time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// A 6-byte body against a 5-byte bound must be rejected with ErrTooLarge
	// and leave the session at offset 0.
	if _, err := store.Append(ctx, s.ID, "backend/api", "user:alice", 0, bytes.NewReader([]byte("hello!")), 5); err != ErrTooLarge {
		t.Fatalf("oversized append: got %v, want ErrTooLarge", err)
	}
	snap, err := store.Status(ctx, s.ID, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if snap.Offset != 0 {
		t.Fatalf("overflow mutated offset to %d", snap.Offset)
	}
}

func TestMemoryStoreFinalizeListAndClearByDigest(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	// dig returns a canonical "sha256:<64hex>" digest; ref returns a valid
	// 64-hex swarm reference (digest without the scheme prefix).
	dig := func(b byte) string { return "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	ref := func(b byte) string { return hex.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

	finalize := func(repo, actor string, data []byte, v byte) Session {
		t.Helper()
		s, err := store.Create(ctx, repo, actor, time.Minute)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := store.Append(ctx, s.ID, repo, actor, 0, bytes.NewReader(data), 100); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := store.MarkFinalized(ctx, s.ID, repo, actor, dig(v), ref(v), "application/octet-stream", int64(len(data))); err != nil {
			t.Fatalf("finalize: %v", err)
		}
		final, err := store.Status(ctx, s.ID, repo, actor)
		if err != nil {
			t.Fatalf("status after finalize: %v", err)
		}
		return final
	}

	a := finalize("backend/api", "user:alice", []byte("a"), 'a')
	b := finalize("backend/api", "user:alice", []byte("bb"), 'b')
	other := finalize("other/app", "user:bob", []byte("c"), 'c')

	blobs, err := store.ListStagedBlobs(ctx, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged blobs: %v", err)
	}
	if len(blobs) != 2 {
		t.Fatalf("unexpected staged blob count: %d", len(blobs))
	}

	// Clear ONLY digest a; b and other survive.
	if err := store.ClearStagedBlobsByDigest(ctx, "backend/api", "user:alice", []string{a.Digest}); err != nil {
		t.Fatalf("clear by digest: %v", err)
	}
	remaining, _ := store.ListStagedBlobs(ctx, "backend/api", "user:alice")
	if len(remaining) != 1 || remaining[0].Digest != b.Digest {
		t.Fatalf("unrelated staged digest must survive; got %+v", remaining)
	}
	// Clearing an unknown digest is a no-op, not an error.
	if err := store.ClearStagedBlobsByDigest(ctx, "backend/api", "user:alice", []string{"sha256:nope"}); err != nil {
		t.Fatalf("clear unknown digest must be a no-op: %v", err)
	}
	if err := store.ClearStagedBlobsByDigest(ctx, "backend/api", "user:alice", []string{b.Digest}); err != nil {
		t.Fatalf("clear second digest: %v", err)
	}
	if rest, _ := store.ListStagedBlobs(ctx, "backend/api", "user:alice"); len(rest) != 0 {
		t.Fatalf("all digests must clear: %+v", rest)
	}
	// Other repos/actors are untouched by a scalar clear of this repo/actor.
	if got, _ := store.Status(ctx, other.ID, "other/app", "user:bob"); got.Digest != other.Digest {
		t.Fatalf("other repo/actor must be untouched: got %+v", got)
	}
	// Other repo/actor blob still listed.
	if blobsOther, _ := store.ListStagedBlobs(ctx, "other/app", "user:bob"); len(blobsOther) != 1 {
		t.Fatalf("other repo/actor staged list must survive: %+v", blobsOther)
	}
}

// TestMemoryStoreConfidentiality proves a foreign repo/actor can never observe
// or mutate a session, and Delete of an absent/foreign owner is idempotent nil.
func TestMemoryStoreConfidentiality(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	ctx := context.Background()
	s, err := store.Create(ctx, "backend/api", "user:alice", time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := store.Status(ctx, s.ID, "backend/api", "user:bob"); err != ErrNotFound {
		t.Fatalf("foreign actor status: got %v, want ErrNotFound", err)
	}
	if _, err := store.Status(ctx, s.ID, "other/api", "user:alice"); err != ErrNotFound {
		t.Fatalf("foreign repo status: got %v, want ErrNotFound", err)
	}
	if _, err := store.Append(ctx, s.ID, "backend/api", "user:bob", 0, bytes.NewReader([]byte("x")), 100); err != ErrNotFound {
		t.Fatalf("foreign append: got %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, s.ID, "backend/api", "user:bob"); err != nil {
		t.Fatalf("foreign delete should be idempotent nil, got %v", err)
	}
	// The original owner still owns the alive session.
	if snap, err := store.Status(ctx, s.ID, "backend/api", "user:alice"); err != nil || snap.ID != s.ID {
		t.Fatalf("foreign delete must not remove the session: snap=%+v err=%v", snap, err)
	}
	// Own delete idempotently removes it.
	if err := store.Delete(ctx, s.ID, "backend/api", "user:alice"); err != nil {
		t.Fatalf("own delete: %v", err)
	}
	if err := store.Delete(ctx, s.ID, "backend/api", "user:alice"); err != nil {
		t.Fatalf("repeat delete must be idempotent nil, got %v", err)
	}
	if _, err := store.Status(ctx, s.ID, "backend/api", "user:alice"); err != ErrNotFound {
		t.Fatalf("after delete: got %v, want ErrNotFound", err)
	}
}

// The memory store must satisfy the registry-facing contract.
var _ RegistryStore = (*MemoryStore)(nil)
