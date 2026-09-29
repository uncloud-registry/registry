package swarm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// hangingServer returns an httptest server that accepts connections and never
// sends a response until the test closes the returned channel. Its Close is
// safe: the handler unblocks first, so httptest does not wait on a stuck
// handler.
func hangingServer(t *testing.T) (*httptest.Server, chan struct{}) {
	t.Helper()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	t.Cleanup(func() {
		close(done)
		srv.Close()
	})
	return srv, done
}

// TestBeeDocumentReadTimeoutPreservesDeadlineExceeded proves a Bee document
// read against a peer that never responds returns within the configured
// client timeout and keeps context.DeadlineExceeded intact in the error chain.
func TestBeeDocumentReadTimeoutPreservesDeadlineExceeded(t *testing.T) {
	hang, _ := hangingServer(t)
	client := &http.Client{Timeout: 200 * time.Millisecond}
	store := NewBeeDocumentStore(hang.URL, client)

	start := time.Now()
	_, err := store.Read(context.Background(), "deadbeef")
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read error must wrap context.DeadlineExceeded, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("read exceeded the configured timeout: %v", elapsed)
	}
}

// TestBeeObjectGetTimeoutPreservesDeadlineExceeded proves a Bee object read
// (the manifest/blob GET path) is bounded by the configured client timeout and
// preserves the deadline sentinel.
func TestBeeObjectGetTimeoutPreservesDeadlineExceeded(t *testing.T) {
	hang, _ := hangingServer(t)
	client := &http.Client{Timeout: 200 * time.Millisecond}
	store := NewBeeObjectStore(hang.URL, client)

	start := time.Now()
	_, err := store.Get(context.Background(), "deadbeef")
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("object get error must wrap context.DeadlineExceeded, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("object get exceeded the configured timeout: %v", elapsed)
	}
}

// TestBeeDefaultClientTimeoutBounded asserts constructors never fall back to
// the bare http.DefaultClient: a nil client yields a bounded client, so a
// zero-value store can never hang a request forever.
func TestBeeDefaultClientTimeoutBounded(t *testing.T) {
	clients := []*http.Client{
		NewBeeDocumentStore("http://bee.invalid", nil).HTTPClient,
		NewBeeObjectStore("http://bee.invalid", nil).HTTPClient,
		NewBeeFeedResolver("http://bee.invalid", nil).HTTPClient,
	}
	for i, c := range clients {
		if c == nil {
			t.Fatalf("constructor %d returned a nil client", i)
		}
		if c == http.DefaultClient {
			t.Fatalf("constructor %d fell back to http.DefaultClient", i)
		}
		if c.Timeout <= 0 {
			t.Fatalf("constructor %d default client is unbounded (Timeout=%v)", i, c.Timeout)
		}
	}
}
