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
