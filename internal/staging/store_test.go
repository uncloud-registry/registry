package staging

import (
	"context"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

func TestMemoryStoreSessionLifecycle(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	session, err := store.CreateSession(context.Background(), "backend/api", "user:alice", time.Minute)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	if _, err := store.Append(context.Background(), session.ID, []byte("hello")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := store.Append(context.Background(), session.ID, []byte(" world")); err != nil {
		t.Fatalf("append 2: %v", err)
	}

	got, err := store.Bytes(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("unexpected bytes: %q", got)
	}
}

func TestMemoryStoreStageBlob(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	blob := spec.StagedBlob{
		UploadID:  "upload-1",
		Repo:      "backend/api",
		Actor:     "user:alice",
		Digest:    "sha256:blob1",
		SwarmRef:  "swarm-ref-1",
		Size:      12,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339),
	}

	if err := store.StageBlob(context.Background(), blob); err != nil {
		t.Fatalf("stage blob: %v", err)
	}

	got, ok, err := store.GetStagedBlob(context.Background(), blob.UploadID)
	if err != nil {
		t.Fatalf("get staged blob: %v", err)
	}
	if !ok {
		t.Fatal("expected staged blob")
	}
	if got.SwarmRef != blob.SwarmRef {
		t.Fatalf("unexpected staged blob ref: %s", got.SwarmRef)
	}
}

func TestMemoryStoreListAndClearStagedBlobs(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	first := spec.StagedBlob{UploadID: "u1", Repo: "backend/api", Actor: "user:alice", Digest: "sha256:1", SwarmRef: "ref1"}
	second := spec.StagedBlob{UploadID: "u2", Repo: "backend/api", Actor: "user:alice", Digest: "sha256:2", SwarmRef: "ref2"}
	other := spec.StagedBlob{UploadID: "u3", Repo: "backend/api", Actor: "user:bob", Digest: "sha256:3", SwarmRef: "ref3"}

	_ = store.StageBlob(context.Background(), first)
	_ = store.StageBlob(context.Background(), second)
	_ = store.StageBlob(context.Background(), other)

	blobs, err := store.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged blobs: %v", err)
	}
	if len(blobs) != 2 {
		t.Fatalf("unexpected staged blob count: %d", len(blobs))
	}

	if err := store.ClearStagedBlobs(context.Background(), "backend/api", "user:alice"); err != nil {
		t.Fatalf("clear staged blobs: %v", err)
	}

	blobs, err = store.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged blobs after clear: %v", err)
	}
	if len(blobs) != 0 {
		t.Fatalf("expected no staged blobs after clear, got %d", len(blobs))
	}
}

// TestMemoryStoreClearStagedBlobsByDigest proves digests can be cleared from
// staging SCALARLY (by digest list, not whole sessions): consumed/referenced
// digests are removed and unrelated staged entries survive, and clearing an
// unknown digest is a no-op.
func TestMemoryStoreClearStagedBlobsByDigest(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()

	// Cross-repo/cross-actor isolation for the scalar clear.
	if err := store.StageBlob(ctx, spec.StagedBlob{UploadID: "u-other", Repo: "other/app", Actor: "user:bob", Digest: "sha256:a", SwarmRef: "ref-other", Size: 9, MediaType: "application/octet-stream"}); err != nil {
		t.Fatalf("seed other repo: %v", err)
	}

	entries := []spec.StagedBlob{
		{UploadID: "u-a", Repo: "backend/api", Actor: "user:alice", Digest: "sha256:a", SwarmRef: "ref-a", Size: 1, MediaType: "application/octet-stream"},
		{UploadID: "u-b", Repo: "backend/api", Actor: "user:alice", Digest: "sha256:b", SwarmRef: "ref-b", Size: 2, MediaType: "application/octet-stream"},
	}
	for _, blob := range entries {
		if err := store.StageBlob(ctx, blob); err != nil {
			t.Fatalf("stage %s: %v", blob.UploadID, err)
		}
	}

	if err := store.ClearStagedBlobsByDigest(ctx, "backend/api", "user:alice", []string{"sha256:a"}); err != nil {
		t.Fatalf("clear by digest: %v", err)
	}
	remaining, err := store.ListStagedBlobs(ctx, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Digest != "sha256:b" {
		t.Fatalf("unrelated staged digest must survive; got %+v", remaining)
	}
	// Clearing an unknown digest is a no-op, not an error.
	if err := store.ClearStagedBlobsByDigest(ctx, "backend/api", "user:alice", []string{"sha256:nope"}); err != nil {
		t.Fatalf("clear unknown digest must be a no-op: %v", err)
	}
	if err := store.ClearStagedBlobsByDigest(ctx, "backend/api", "user:alice", []string{"sha256:b"}); err != nil {
		t.Fatalf("clear second digest: %v", err)
	}
	if rest, _ := store.ListStagedBlobs(ctx, "backend/api", "user:alice"); len(rest) != 0 {
		t.Fatalf("all digests must clear: %+v", rest)
	}
	// Other repos/actors are untouched by a scalar clear of this repo/actor.
	if got, found, err := store.GetStagedBlob(ctx, "u-other"); err != nil || !found || got.Digest != "sha256:a" {
		t.Fatalf("other repo/actor must be untouched: got=%+v found=%v err=%v", got, found, err)
	}
}
