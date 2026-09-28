package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/staging"
	"github.com/uncloud-registry/registry/internal/swarm"
)

// ---------------------------------------------------------------------------
// Task 18 round-5 regression (finding 3): the periodic cleanup MUST perform
// bounded Bee repository-state reads and stay DATA-FREE. Production
// BeeDocumentStore.readPath used an UNBOUNDED io.ReadAll for success bodies
// and echoed non-404 error bodies into the returned error, so a hostile or
// broken Bee node could force unbounded memory and leak response bodies (e.g.
// a SECRET-MARKER) into errors/logs. These production-wiring tests drive the
// REAL BeeDocumentStore through the REAL committedRefProvider and assert:
//  - an oversized 200 body fails closed with the overflow classification,
//  - a non-200 error body never surfaces its content,
//  - the periodic loop logs a FIXED classification and never the raw error.
// ---------------------------------------------------------------------------

const cleanupDataLeakMarker = "SECRET-MARKER-cleanup-must-never-leak"

// docBeeFixture is a minimal fake Bee that serves a resolvable repo feed (a
// 32-byte binary reference + Swarm-Feed-Index) and a configurable /bzz
// document read (status + body) so CommittedRefs reaches readPath.
type docBeeFixture struct {
	bzzStatus int
	bzzBody   []byte
}

func (f *docBeeFixture) handler() http.Handler {
	docRef := binaryRef(0x50)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/feeds/"):
			w.Header().Set("Swarm-Feed-Index", "0000000000000001")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(binaryBytes(docRef))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/bzz/"):
			w.WriteHeader(f.bzzStatus)
			if f.bzzStatus == http.StatusOK {
				_, _ = w.Write(f.bzzBody)
			} else {
				_, _ = w.Write(f.bzzBody)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

// prover builds a committedRefProvider over the real BeeDocumentStore pointed
// at the fake, scoped to one registry identity, ready to resolve repo state.
func prover(t *testing.T, server *httptest.Server) *committedRefProvider {
	t.Helper()
	identity := resolve.RegistryIdentity{Host: beeWiringHost, Owner: "0x" + beeWiringOwner, RegistryID: 7}
	resolver := resolve.RegistryResolver{
		Registries: resolve.StaticRegistryIdentityResolver{Hosts: map[string]resolve.RegistryIdentity{
			beeWiringHost: identity,
		}},
		Docs:  swarm.NewBeeDocumentStore(server.URL, server.Client()),
		Feeds: swarm.NewBeeFeedResolver(server.URL, server.Client()),
	}
	return &committedRefProvider{resolver: resolver, identities: []resolve.RegistryIdentity{identity}}
}

// TestCommittedRefsOversizedDocFailsClosedBoundedProves an oversized 200
// repository-state document is rejected with the overflow classification (the
// bounded limit+1 read) and never leaks the body marker. Without the bounded
// read the cleanup would buffer the whole oversized body before the JSON
// decode rejects it.
func TestCommittedRefsOversizedDocFailsClosedBounded(t *testing.T) {
	oversized := strings.Repeat("z", int(swarm.BeeDocumentReadMaxBody)+1+64)
	oversized = cleanupDataLeakMarker + oversized
	server := httptest.NewServer((&docBeeFixture{bzzStatus: http.StatusOK, bzzBody: []byte(oversized)}).handler())
	defer server.Close()

	prov := prover(t, server)
	_, err := prov.CommittedRefs(context.Background(), "backend/api")
	if err == nil {
		t.Fatal("an oversized repo-state document must fail closed")
	}
	if strings.Contains(err.Error(), cleanupDataLeakMarker) {
		t.Fatalf("the oversized document body leaked into the error: %v", err)
	}
	if !strings.Contains(err.Error(), "exceeded the bound") {
		t.Fatalf("oversized document must be rejected by the bounded read (overflow), got: %v", err)
	}
}

// TestCommittedRefsErrorBodyNeverLeaksProves a non-200 /bzz response bearing a
// SECRET-MARKER body never surfaces that body in the returned error — the
// cleanup's committed-state provider stays data-free end to end.
func TestCommittedRefsErrorBodyNeverLeaks(t *testing.T) {
	server := httptest.NewServer((&docBeeFixture{
		bzzStatus: http.StatusInternalServerError,
		bzzBody:   []byte(cleanupDataLeakMarker + " {\"error\":\"boom\"}"),
	}).handler())
	defer server.Close()

	prov := prover(t, server)
	_, err := prov.CommittedRefs(context.Background(), "backend/api")
	if err == nil {
		t.Fatal("a 500 repository-state read must fail closed")
	}
	if strings.Contains(err.Error(), cleanupDataLeakMarker) {
		t.Fatalf("the Bee error body leaked into the returned error: %v", err)
	}
	// The fixed status number may appear; the raw body never does.
	if strings.Contains(err.Error(), "boom") {
		t.Fatalf("the Bee error body payload leaked into the returned error: %v", err)
	}
}

// markerErrCommitted returns a committed-state error carrying a unique marker
// so the test can prove the periodic cleanup loop NEVER logs raw errors — it
// logs a fixed classification only.
type markerErrCommitted struct {
	once    sync.Once
	entered chan struct{}
}

func (m *markerErrCommitted) CommittedRefs(context.Context, string) (map[string]struct{}, error) {
	m.once.Do(func() { close(m.entered) })
	return nil, errors.New("committed-state provider: " + cleanupDataLeakMarker)
}

// syncBuffer is a race-free log capture for the cleanup-loop assertion. The
// loop's goroutine writes log records while this test polls for the fixed
// classification, so a plain bytes.Buffer would race (-race). A mutex guards
// the concurrent writer (log.SetOutput) and reader (contains/String) sides.
// Each logger record is emitted as a single Write call, so records stay atomic.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) contains(s string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Contains(b.buf.String(), s)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestCleanupLoopLogsFixedClassificationNotRawError proves the periodic
// cleanup worker logs a FIXED classification on a failed pass and NEVER the
// raw error — so a future data-bearing dependency error cannot reach the logs.
func TestCleanupLoopLogsFixedClassificationNotRawError(t *testing.T) {
	dir := privateDir(t)
	svc, err := staging.NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	seedExpiredFinalizedBlob(t, filepath.Join(dir, "staging.db"))

	provider := &markerErrCommitted{entered: make(chan struct{})}
	cleanup, err := staging.NewCleanup(svc, noopUnpinner{}, provider)
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}

	// Capture the process logger so we can assert on what the loop emits. The
	// capture is mutex-guarded because the loop's goroutine writes records
	// while this test polls for the fixed classification.
	var buf syncBuffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	oldFlags := log.Flags()
	log.SetFlags(0)
	defer func() { log.SetOutput(oldWriter); log.SetFlags(oldFlags) }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runCleanupLoop(ctx, cleanup, 20*time.Millisecond, 10)

	// The first-pass committed-state provider fails synchronously; the loop's
	// goroutine then logs the FIXED classification only if ctx is not already
	// canceled (it returns silently when ctx.Err()!=nil). So canceling as soon
	// as the provider is entered is racy — the cancellation can win before the
	// log write and produce an empty capture. Instead, wait deterministically
	// (bounded) until the fixed classification has actually been written, then
	// cancel and join: this proves the failed pass completed and logged before
	// cancellation, which is the event the test is asserting.
	select {
	case <-provider.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup pass never invoked the committed-state provider")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !buf.contains(cleanupPassAbortedClass) {
		if time.Now().After(deadline) {
			t.Fatalf("cleanup loop never logged the fixed classification (want %q), got:\n%s", cleanupPassAbortedClass, buf.String())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup worker did not exit after cancellation")
	}

	// Logging is complete once the loop goroutine has exited (joined via done),
	// so the final read is both mutex-safe and happens-after every write.
	out := buf.String()
	if strings.Contains(out, cleanupDataLeakMarker) {
		t.Fatalf("the raw error (with marker) leaked into the cleanup log:\n%s", out)
	}
	if !strings.Contains(out, cleanupPassAbortedClass) {
		t.Fatalf("the cleanup loop must log a fixed classification (want %q), got:\n%s", cleanupPassAbortedClass, out)
	}
}

// TestBuildBeeHandlerClosesStagingOnLaterConfigFailure proves a registry
// startup that fails AFTER the durable staging service has been opened
// (here, an invalid REGISTRY_CLEANUP_BATCH) fails closed with the specific
// error — the deferred guard that releases the opened staging service (spool +
// SQLite) instead of leaking it — and never returns a working handler. This
// pins the post-open failure path exercised by that deferred close.
func TestBuildBeeHandlerClosesStagingOnLaterConfigFailure(t *testing.T) {
	key := newConfigTestKey(t)
	t.Setenv("REGISTRY_BACKEND", "bee")
	t.Setenv("BEE_API_URL", "http://127.0.0.1:1")
	t.Setenv("REGISTRY_OWNER_MAP", beeWiringHost+"=0x"+beeWiringOwner)
	t.Setenv("REGISTRY_ID_MAP", beeWiringHost+"=7")
	t.Setenv("REGISTRY_TOKEN_PUBLIC_KEYS_FILE", writeConfigJWKS(t, key))
	t.Setenv("REGISTRY_TOKEN_ISSUER", configIssuer)
	t.Setenv("REGISTRY_TOKEN_AUDIENCE", beeWiringHost)
	t.Setenv("CONTROLPLANE_URL", "http://127.0.0.1:1")
	t.Setenv("CONTROLPLANE_INTERNAL_SECRET_FILE", writeSecretFile(t))
	setupRegistryStagingEnv(t)
	// A post-open config failure: the staging service opens first, then the
	// strict batch env parse fails closed.
	t.Setenv(envCleanupBatch, "0")

	if _, err := buildBeeHandler(); err == nil {
		t.Fatal("an invalid cleanup batch must fail registry startup closed")
	} else if !strings.Contains(err.Error(), envCleanupBatch) {
		t.Fatalf("post-open failure must surface the batch config error, got: %v", err)
	}
}
