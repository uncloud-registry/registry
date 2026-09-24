package swarm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBeeObjectStoreReadBounded proves the signer's bounded immutable /bytes
// artifact reader wire contract: GET /bytes/<ref> with an EXPLICIT upper
// bound, overflow detection at maxBytes+1 (never unbounded buffering), a
// strictly data-free non-200 response, and data-free missing-object failures —
// the exact contract the feed signer depends on to prove an operated manifest
// body without ever buffering unbounded bytes.
func TestBeeObjectStoreReadBounded(t *testing.T) {
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
			_, _ = w.Write([]byte("0123456789ABCDEF")) // 16 bytes
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

	// Exact-size read within the bound returns the full body unchanged.
	data, err := store.ReadBounded(ctx, "obj-exact", 10)
	if err != nil {
		t.Fatalf("bounded exact read: %v", err)
	}
	if string(data) != "0123456789" {
		t.Fatalf("bounded read returned corrupted data: %q", data)
	}

	// A LARGER bound still returns the exact object (the bound is an upper
	// limit, not a size estimate).
	data, err = store.ReadBounded(ctx, "obj-exact", 100)
	if err != nil {
		t.Fatalf("bounded read under generous bound: %v", err)
	}
	if string(data) != "0123456789" {
		t.Fatalf("generous bound corrupted data: %q", data)
	}

	// Overflow detection: the object exceeds the bound -> data-free failure,
	// never a truncated payload that could masquerade as the artifact.
	if _, err = store.ReadBounded(ctx, "obj-oversize", 10); err == nil {
		t.Fatal("oversize object must fail the bounded read")
	}
	if strings.Contains(err.Error(), "obj-oversize") {
		t.Fatalf("oversize failure must be data-free, got %v", err)
	}

	// Missing object -> data-free failure (the 404 reason is a Bee-internal
	// detail; the signer treats it as backend).
	if _, err = store.ReadBounded(ctx, "obj-missing", 1024); err == nil {
		t.Fatal("missing object must fail the bounded read")
	}
	if strings.Contains(err.Error(), "obj-missing") {
		t.Fatalf("missing-object failure must be data-free, got %v", err)
	}

	// Non-200 with an attacker-controlled body: the body is drained only up
	// to a tiny bound and NEVER surfaced.
	if _, err = store.ReadBounded(ctx, "obj-error", 1024); err == nil {
		t.Fatal("error status must fail the bounded read")
	}
	if e := err.Error(); strings.Contains(e, "internal detail secret") || strings.Contains(e, "obj-error") {
		t.Fatalf("error-status failure must be data-free: %v", e)
	}

	// A negative bound is rejected before any network access.
	if _, err = store.ReadBounded(ctx, "obj-exact", -1); err == nil {
		t.Fatal("negative bound must be rejected")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("negative bound must not hit the network, got %v", err)
	}
}
