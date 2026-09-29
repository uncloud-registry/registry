package swarm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBeeObjectStoreOpenObject proves the streaming immutable /bytes reader
// used by pull-integrity pre-verification: GET /bytes/<ref> with an EXPLICIT
// upper bound enforced DURING streaming (an object larger than maxBytes fails
// closed at the reader, never delivering a truncated payload), exact-size
// objects stream unchanged, non-200 and missing objects are data-free
// failures, and the stream is always closeable and closed.
func TestBeeObjectStoreOpenObject(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/bytes/") {
			http.NotFound(w, r)
			return
		}
		ref := strings.TrimPrefix(r.URL.Path, "/bytes/")
		switch ref {
		case "obj-exact":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("0123456789")) // 10 bytes, exact
		case "obj-oversize":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("0123456789ABCDEF")) // 16 bytes > any 10-byte bound
		case "obj-error":
			w.WriteHeader(http.StatusInternalServerError)
			// An untrusted error body: the client must never echo it.
			_, _ = w.Write([]byte("internal detail secret"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	store := NewBeeObjectStore(server.URL, server.Client())
	ctx := context.Background()

	// Exact-size stream within the bound returns the full body unchanged.
	rc, err := store.OpenObject(ctx, "obj-exact", 10)
	if err != nil {
		t.Fatalf("open exact stream: %v", err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read exact stream: %v", err)
	}
	if closeErr := rc.Close(); closeErr != nil {
		t.Fatalf("close exact stream: %v", closeErr)
	}
	if string(got) != "0123456789" {
		t.Fatalf("stream returned corrupted data: %q", got)
	}

	// A LARGER bound still delivers the exact object.
	rc, err = store.OpenObject(ctx, "obj-exact", 100)
	if err != nil {
		t.Fatalf("open generous stream: %v", err)
	}
	got, err = io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("read generous stream: %v", err)
	}
	if string(got) != "0123456789" {
		t.Fatalf("generous bound corrupted data: %q", got)
	}

	// Overflow: an object larger than maxBytes fails the STREAM closed — the
	// read must error (never silently truncate to maxBytes bytes), and the
	// failure must be data-free (no ref, no body text).
	rc, err = store.OpenObject(ctx, "obj-oversize", 10)
	if err != nil {
		t.Fatalf("oversize open: %v", err)
	}
	readErr := func() error {
		_, err := io.ReadAll(rc)
		return err
	}()
	_ = rc.Close()
	if readErr == nil {
		t.Fatal("oversize stream must fail the read past the bound")
	}
	if strings.Contains(readErr.Error(), "obj-oversize") {
		t.Fatalf("oversize failure must be data-free, got %v", readErr)
	}

	// Non-200 and missing objects fail BEFORE any byte is streamed, with
	// data-free errors (the untrusted error body must never surface).
	if rc, err = store.OpenObject(ctx, "obj-error", 100); err == nil {
		_ = rc.Close()
		t.Fatal("non-200 open must fail")
	} else if strings.Contains(err.Error(), "internal detail secret") {
		t.Fatalf("error body must never leak, got %v", err)
	}
	if rc, err = store.OpenObject(ctx, "obj-missing", 100); err == nil {
		_ = rc.Close()
		t.Fatal("missing object open must fail")
	}

	// A nil receiver fails closed instead of panicking.
	var nilStore *BeeObjectStore
	if rc, err := nilStore.OpenObject(ctx, "anything", 10); err == nil {
		if rc != nil {
			_ = rc.Close()
		}
		t.Fatal("nil receiver must fail closed")
	}
}

// TestBeeObjectStoreOpenObjectNonNegativeBound pins the contract that a
// negative bound is rejected before any request.
func TestBeeObjectStoreOpenObjectNonNegativeBound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	store := NewBeeObjectStore(server.URL, server.Client())
	if rc, err := store.OpenObject(context.Background(), "any", -1); err == nil {
		if rc != nil {
			_ = rc.Close()
		}
		t.Fatal("negative bound must fail closed")
	}
}
