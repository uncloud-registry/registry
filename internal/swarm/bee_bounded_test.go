package swarm

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// beeTestRefExact / beeTestRefOversize / beeTestRefError / beeTestRefMissing
// are distinct genuine 64-hex Swarm object references used to exercise the
// /bytes wire contract. ReadBounded and OpenObject accept ONLY the canonical
// 64-hex form; symbolic in-memory test refs never flow through the production
// object store (tests that need symbolic refs use a BoundedBytesReader fake).
const (
	beeTestRefExact    = "1111111111111111111111111111111111111111111111111111111111111111"
	beeTestRefOversize = "2222222222222222222222222222222222222222222222222222222222222222"
	beeTestRefError    = "3333333333333333333333333333333333333333333333333333333333333333"
	beeTestRefMissing  = "4444444444444444444444444444444444444444444444444444444444444444"
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
		case beeTestRefExact:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("0123456789")) // 10 bytes, exact
		case beeTestRefOversize:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("0123456789ABCDEF")) // 16 bytes
		case beeTestRefError:
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
	data, err := store.ReadBounded(ctx, beeTestRefExact, 10)
	if err != nil {
		t.Fatalf("bounded exact read: %v", err)
	}
	if string(data) != "0123456789" {
		t.Fatalf("bounded read returned corrupted data: %q", data)
	}

	// A LARGER bound still returns the exact object (the bound is an upper
	// limit, not a size estimate).
	data, err = store.ReadBounded(ctx, beeTestRefExact, 100)
	if err != nil {
		t.Fatalf("bounded read under generous bound: %v", err)
	}
	if string(data) != "0123456789" {
		t.Fatalf("generous bound corrupted data: %q", data)
	}

	// Overflow detection: the object exceeds the bound -> data-free failure,
	// never a truncated payload that could masquerade as the artifact.
	if _, err = store.ReadBounded(ctx, beeTestRefOversize, 10); err == nil {
		t.Fatal("oversize object must fail the bounded read")
	}
	if strings.Contains(err.Error(), beeTestRefOversize) {
		t.Fatalf("oversize failure must be data-free, got %v", err)
	}

	// Missing object -> data-free failure (the 404 reason is a Bee-internal
	// detail; the signer treats it as backend).
	if _, err = store.ReadBounded(ctx, beeTestRefMissing, 1024); err == nil {
		t.Fatal("missing object must fail the bounded read")
	}
	if strings.Contains(err.Error(), beeTestRefMissing) {
		t.Fatalf("missing-object failure must be data-free, got %v", err)
	}

	// Non-200 with an attacker-controlled body: the body is drained only up
	// to a tiny bound and NEVER surfaced.
	if _, err = store.ReadBounded(ctx, beeTestRefError, 1024); err == nil {
		t.Fatal("error status must fail the bounded read")
	}
	if e := err.Error(); strings.Contains(e, "internal detail secret") || strings.Contains(e, beeTestRefError) {
		t.Fatalf("error-status failure must be data-free: %v", e)
	}

	// A negative bound is rejected before any network access.
	if _, err = store.ReadBounded(ctx, beeTestRefExact, -1); err == nil {
		t.Fatal("negative bound must be rejected")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("negative bound must not hit the network, got %v", err)
	}
}

// TestBeeObjectStoreReadBoundedValidation proves the fail-closed pre-flight
// contract of ReadBounded: a nil receiver, an empty BaseURL, a nil
// HTTPClient, and a non-canonical (non-64-hex) ref are rejected with
// data-free errors BEFORE any network I/O, and a bound at math.MaxInt64
// (whose maxBytes+1 overflow probe would wrap negative and disable the
// limit) is rejected BEFORE the hostile oversized body is ever read.
func TestBeeObjectStoreReadBoundedValidation(t *testing.T) {
	t.Parallel()

	t.Run("nil receiver", func(t *testing.T) {
		t.Parallel()
		var store *BeeObjectStore
		if _, err := store.ReadBounded(context.Background(), beeTestRefExact, 10); err == nil {
			t.Fatal("nil receiver must fail closed")
		}
	})

	t.Run("empty base url", func(t *testing.T) {
		t.Parallel()
		store := &BeeObjectStore{BaseURL: "   ", HTTPClient: http.DefaultClient}
		_, err := store.ReadBounded(context.Background(), beeTestRefExact, 10)
		if err == nil {
			t.Fatal("empty base url must be rejected")
		}
		if strings.Contains(err.Error(), beeTestRefExact) {
			t.Fatalf("empty-base-url error must be data-free: %v", err)
		}
	})

	t.Run("nil http client", func(t *testing.T) {
		t.Parallel()
		store := &BeeObjectStore{BaseURL: "http://bee.invalid", HTTPClient: nil}
		if _, err := store.ReadBounded(context.Background(), beeTestRefExact, 10); err == nil {
			t.Fatal("nil http client must be rejected")
		}
	})

	t.Run("non-canonical ref", func(t *testing.T) {
		t.Parallel()
		store := &BeeObjectStore{BaseURL: "http://bee.invalid", HTTPClient: http.DefaultClient}
		for _, ref := range []string{
			"",
			"short",
			strings.Repeat("z", 64), // 64 non-hex characters
			strings.Repeat("1", 63), // too short
			strings.Repeat("1", 65), // too long
		} {
			if _, err := store.ReadBounded(context.Background(), ref, 10); err == nil {
				t.Fatalf("non-canonical ref %q must be rejected", ref)
			}
		}
	})

	t.Run("max int64 bound", func(t *testing.T) {
		t.Parallel()
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusOK)
			// A hostile oversized body: it must never be read.
			_, _ = w.Write([]byte(strings.Repeat("x", 1<<20)))
		}))
		defer server.Close()

		store := NewBeeObjectStore(server.URL, server.Client())
		if _, err := store.ReadBounded(context.Background(), beeTestRefExact, math.MaxInt64); err == nil {
			t.Fatal("a math.MaxInt64 bound must be rejected")
		}
		if got := requests.Load(); got != 0 {
			t.Fatalf("a math.MaxInt64 bound must be rejected before any I/O; server saw %d requests", got)
		}
	})
}
