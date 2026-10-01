package staging

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/swarm"
)

// ---------------------------------------------------------------------------
// Task 18 exceptional fix (round 1): Bee unpin redirect safety, end to end.
//
// A configured Bee DELETE /pins/{ref} that answers with any 3xx redirect is a
// fixed dependency failure, NOT a successful unpin. The production cleanup
// passes the REAL *swarm.BeeObjectStore as the Unpinner, so this regression
// drives the REAL store over a REAL file-backed staging service and proves:
//
//   - a redirect-failing unpin keeps the durable cleanup-owned `expiring` row
//     with its Bee ref + provenance, performs NO metadata or file deletion,
//     and never contacts the cross-origin redirect target;
//   - the cleanup's shared (caller-owned) HTTP client is never mutated;
//   - a later pass against a DIRECT-success Bee resumes the expiring row and
//     unpins + removes the blob exactly once.
// ---------------------------------------------------------------------------

// TestCleanupBeeUnpinRedirectRetainsExpiringRow then DirectRetryRemovesOnce
// drives the production file-backed cleanup against a REAL BeeObjectStore and
// a REAL staging service. First the configured Bee answers the unpin DELETE
// with a cross-origin 302; the cleanup must fail closed and retain the durable
// expiring claim (Bee ref + provenance) with no metadata/file deletion. Then a
// direct-success Bee serves the retry, which must resume the expiring row and
// unpin + remove it EXACTLY once.
func TestCleanupBeeUnpinRedirectRetainsExpiringRow(t *testing.T) {
	svc, dir := newTestService(t)
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	fixedClock(svc, now)

	ref := strings.Repeat("d", 64)
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "redirect-cleanup-bytes")
	dg, _, media, size := finalizeArgs(s)
	mustFinalize(t, svc, s, dg, ref, media, size)
	runAt := fixClockAhead(svc, now)

	// A real on-disk staged blob file that a successful removal would delete.
	blobFile := filepath.Join(dir, "spool", s.ID)
	if _, err := os.Lstat(blobFile); err != nil {
		t.Fatalf("fixture staged blob file must exist: %v", err)
	}

	// Cross-origin redirect target that MUST never be contacted.
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	// Redirecting Bee: DELETE /pins/<ref> answers 302 cross-origin.
	var beeDeleteHits atomic.Int64
	redirectBee := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("unexpected method %s on Bee", r.Method)
		}
		beeDeleteHits.Add(1)
		w.Header().Set("Location", target.URL+"/evil/"+ref[:8])
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("REDIRECT-CLEANUP-MARKER-" + ref[:8]))
	}))
	defer redirectBee.Close()

	// The cleanup's Unpinner is the REAL BeeObjectStore over a shared client
	// with the DEFAULT redirect-following policy — the exact vuln the fix must
	// neutralize without mutating that caller-owned client.
	sharedClient := redirectBee.Client()
	beeStore := swarm.NewBeeObjectStore(redirectBee.URL, sharedClient)
	if sharedClient.CheckRedirect != nil {
		t.Fatalf("fixture: httptest client must have default nil CheckRedirect, got %T", sharedClient.CheckRedirect)
	}

	cleanup, err := NewCleanup(svc, beeStore, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := cleanup.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("RunOnce redirect pass: %v", err)
	}
	if res.Examined != 1 || res.Expired != 1 || res.Unpinned != 0 || res.Removed != 0 || res.Failed != 1 {
		t.Fatalf("redirect pass counts = %+v, want examined=1 expired=1 failed=1 (no unpin/removal)", res)
	}
	if targetHits.Load() != 0 {
		t.Fatalf("the cross-origin redirect target was contacted %d times; the DELETE left the configured Bee", targetHits.Load())
	}
	if beeDeleteHits.Load() != 1 {
		t.Fatalf("configured Bee must have been hit exactly once, got %d", beeDeleteHits.Load())
	}
	// The shared client is NOT mutated by the redirects.
	if sharedClient.CheckRedirect != nil {
		t.Fatal("cleanup/BeeObjectStore must not mutate the shared client's CheckRedirect")
	}

	// The row is durably `expiring` with its Bee ref + provenance retained, and
	// NO metadata or staged file was deleted. Status filters by expiry, so
	// rewind the service clock to the creation time before re-reading it.
	fixedClock(svc, now)
	st, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("expiring row must survive a redirect-failed unpin, Status err=%v", err)
	}
	if st.State != StateExpiring {
		t.Fatalf("redirect-failed unpin left state=%q, want %q (durable cleanup claim)", st.State, StateExpiring)
	}
	if st.BeeRef != ref {
		t.Fatalf("expiring row must retain the Bee ref %q, got %q", ref, st.BeeRef)
	}
	if _, err := os.Lstat(blobFile); err != nil {
		t.Fatalf("staged file must NOT be deleted on a redirect-failed unpin: %v", err)
	}
	// The metadata row itself is still present (Status found it), so no
	// metadata deletion occurred.

	// -------- Later pass against a DIRECT-success Bee: unpin + remove once.
	var successHits atomic.Int64
	successBee := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/pins/"+ref {
			t.Fatalf("retry must DELETE exactly the Bee pin %s, got %s %s", ref, r.Method, r.URL.Path)
		}
		successHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer successBee.Close()

	// The durable traversal wrapped past the claimed row (an empty pass resets
	// the fresh cursor), so bounded repeated passes converge to removal.
	var final CleanupResult
	for i := 0; i < 10; i++ {
		beeStore := swarm.NewBeeObjectStore(successBee.URL, successBee.Client())
		c, err := NewCleanup(svc, beeStore, &fakeCommitted{})
		if err != nil {
			t.Fatalf("NewCleanup retry %d: %v", i, err)
		}
		r, err := c.RunOnce(context.Background(), runAt, 10)
		if err != nil {
			t.Fatalf("RunOnce retry %d: %v", i, err)
		}
		final = r
		if r.Removed > 0 {
			break
		}
	}
	if final.Removed != 1 || final.Unpinned != 1 {
		t.Fatalf("direct-success retry counts = %+v, want removed=1 unpinned=1", final)
	}
	// Exactly once: the retry Bee served exactly one successful DELETE (the
	// expiring row is unpinned on the first resume and removed; nothing re-unpins
	// it).
	if successHits.Load() != 1 {
		t.Fatalf("direct-success retry must unpin exactly once, got %d DELETEs", successHits.Load())
	}
	if _, err := svc.Status(context.Background(), s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("blob must be removed after the direct-success retry, Status err=%v", err)
	}
	if _, err := os.Lstat(blobFile); err == nil {
		t.Fatal("staged file must be removed after the direct-success retry")
	}
}
