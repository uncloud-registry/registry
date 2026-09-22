package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var reconcilerSeq uint64

// failObjectStore wraps a memory object store with injectable failures:
// failPut simulates an upload outage, failGet a read-back outage, and
// mismatched simulates content that fails read-back verification.
type failObjectStore struct {
	inner      *memoryUploader
	failPut    bool
	failGet    bool
	mismatched bool
	putCount   int
	getCount   int
	mu         sync.Mutex
}

func (f *failObjectStore) Put(c context.Context, data []byte, batchID string) (string, error) {
	f.mu.Lock()
	f.putCount++
	shouldFail := f.failPut
	f.mu.Unlock()
	if shouldFail {
		return "", errors.New("injected put failure")
	}
	return f.inner.Put(c, data, batchID)
}

func (f *failObjectStore) Get(c context.Context, ref string) ([]byte, error) {
	f.mu.Lock()
	f.getCount++
	fail := f.failGet
	mismatch := f.mismatched
	f.mu.Unlock()
	if fail {
		return nil, errors.New("injected get failure")
	}
	data, err := f.inner.Get(c, ref)
	if err != nil {
		return nil, err
	}
	if mismatch {
		return []byte("WRONG-CONTENT"), nil
	}
	return data, nil
}

func (f *failObjectStore) putCalls() int { f.mu.Lock(); defer f.mu.Unlock(); return f.putCount }

// failFeedUpdater wraps a memory feed store with per-feed failure injection.
// The wrapped store is the SAME MemoryRegistryFeedStore used as the feed
// resolver, so a successful update is independently resolvable and a failed
// (or mis-directed) update resolves to a mismatch.
type failFeedUpdater struct {
	inner   *MemoryRegistryFeedStore
	failFor map[string]bool
	mu      sync.Mutex
}

func (f *failFeedUpdater) UpdateRegistryFeed(c context.Context, reg Registry, feed, ref string) error {
	f.mu.Lock()
	shouldFail := f.failFor[feed]
	f.mu.Unlock()
	if shouldFail {
		return errors.New("injected feed update failure")
	}
	return f.inner.UpdateRegistryFeed(c, reg, feed, ref)
}

func (f *failFeedUpdater) fail(feed string) { f.mu.Lock(); f.failFor[feed] = true; f.mu.Unlock() }

func (f *failFeedUpdater) allow(feed string) { f.mu.Lock(); f.failFor[feed] = false; f.mu.Unlock() }

// provisioningHarness wires a real store, publisher-backed service, and a
// reconciler with an advancing injectable clock for deterministic retry tests.
type provisioningHarness struct {
	store      *Store
	service    *Service
	uploader   *failObjectStore
	feeds      *failFeedUpdater
	feedStore  *MemoryRegistryFeedStore
	reconciler *Reconciler
	ownerID    int64
	now        time.Time
}

func newProvisioningHarness(t *testing.T) *provisioningHarness {
	t.Helper()
	name := fmt.Sprintf("file:provh_%d?mode=memory&cache=shared", atomic.AddUint64(&reconcilerSeq, 1))
	store, err := OpenSQLite(name)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	uploader := &failObjectStore{inner: &memoryUploader{refs: map[string][]byte{}}}
	feedStore := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	feeds := &failFeedUpdater{
		inner:   feedStore,
		failFor: map[string]bool{},
	}
	service := &Service{
		Store:          store,
		Tokens:         newTestSessionManager(t),
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
		Publisher:      &Publisher{Documents: uploader, Feeds: feeds, FeedsReader: feedStore},
	}
	owner, _, err := service.RegisterUser(context.Background(), "reconciler@example.com", "password123")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	reconciler, err := service.NewReconciler()
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	// Small, fast backoff so retry determinism does not depend on wall clock.
	reconciler.BackoffBase = 0
	reconciler.BackoffMax = 0
	reconciler.Lease = 10 * time.Second

	h := &provisioningHarness{
		store: store, service: service, uploader: uploader, feeds: feeds, feedStore: feedStore,
		reconciler: reconciler, ownerID: owner.ID, now: time.Now().UTC().Add(5 * time.Second),
	}
	reconciler.now = func() time.Time { return h.now }
	return h
}

func (h *provisioningHarness) advance(d time.Duration) { h.now = h.now.Add(d) }

func (h *provisioningHarness) createRegistry(t *testing.T) CreatedRegistry {
	t.Helper()
	slug := fmt.Sprintf("reg%d", atomic.AddUint64(&reconcilerSeq, 1000))
	created, err := h.service.CreateRegistry(context.Background(), h.ownerID, slug, slug+".eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	return created
}

func (h *provisioningHarness) runOnce(t *testing.T) {
	t.Helper()
	if err := h.reconciler.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once: %v", err)
	}
}

// TestProvisioningAuthSuccessThenStampFailureIsResumable pins the core
// partial-publication contract: auth succeeds, stamp fails; the registry stays
// 'provisioning', both jobs are durable, a retry does NOT re-upload the finished
// auth work, and the registry becomes 'ready' only after stamp completes verified
// read-back.
func TestProvisioningAuthSuccessThenStampFailureIsResumable(t *testing.T) {
	h := newProvisioningHarness(t)
	created := h.createRegistry(t)
	reg := created.Registry
	stampFeed := stampPolicyFeedRef(reg)

	// Stamp feed update fails on the first pass; auth is fine.
	h.feeds.fail(stampFeed)
	h.runOnce(t)

	// Partial success remains provisioning; auth succeeded, stamp retries.
	registry, err := h.store.FindRegistryByID(context.Background(), reg.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if registry.ProvisioningState != ProvisioningStateProvisioning {
		t.Fatalf("partial success must remain provisioning, got %q", registry.ProvisioningState)
	}
	jobs, err := h.store.listJobsForRegistry(context.Background(), reg.ID)
	if err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	var authDone, stampPending bool
	for _, j := range jobs {
		switch j.Kind {
		case PublicationKindAuth:
			authDone = j.State == PublicationStateSucceeded && j.ObjectRef != "" && j.FeedRef != ""
		case PublicationKindStamp:
			stampPending = j.State == PublicationStatePending && j.Attempts == 1 && j.LastError == "feed update failed"
		}
	}
	if !authDone || !stampPending {
		t.Fatalf("expected auth succeeded and stamp pending-after-1 with sanitized error, got jobs: %+v", jobs)
	}

	// Both jobs upload their object in stage 1 before stamp's feed stage fails,
	// so exactly 2 object uploads happen on the first pass (one per logical
	// job) — never duplicate uploads of the same job.
	uploadsAfterFirst := h.uploader.putCalls()
	if uploadsAfterFirst != 2 {
		t.Fatalf("expected exactly two object uploads (auth, stamp) on first pass, got %d", uploadsAfterFirst)
	}
	if h.feeds.inner.Feeds[stampFeed] != "" {
		t.Fatalf("stamp feed must not be published while it is failing")
	}

	// Retry after stamp recovers: stamp skips re-upload (object ref persisted),
	// auth is already succeeded. Registry becomes ready.
	h.feeds.allow(stampFeed)
	h.runOnce(t)

	registry, err = h.store.FindRegistryByID(context.Background(), reg.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if registry.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("expected registry ready after stamp recovers, got %q", registry.ProvisioningState)
	}
	// One upload per job, never more: auth once + stamp once.
	if got := h.uploader.putCalls(); got != 2 {
		t.Fatalf("expected exactly two uploads total (auth, stamp), got %d", got)
	}
	if h.feeds.inner.Feeds[stampFeed] == "" {
		t.Fatal("expected stamp feed to be published after recovery")
	}
}

// TestProvisioningCrashBetweenUploadAndFeedUpdateResumesWithoutReupload proves
// the stage-progress persistence contract: once an object ref is committed, a
// crash/failure before the feed update must NOT re-upload on retry.
func TestProvisioningCrashBetweenUploadAndFeedUpdateResumesWithoutReupload(t *testing.T) {
	h := newProvisioningHarness(t)
	created := h.createRegistry(t)
	reg := created.Registry
	authFeed := authPolicyFeedRef(reg)

	// First pass: auth feed update fails AFTER the auth object uploaded and its
	// object_ref was persisted (crash between upload and feed update). Both
	// jobs upload their object in stage 1, so exactly 2 uploads occur; the
	// auth job is left with a committed object_ref but no feed_ref.
	h.feeds.fail(authFeed)
	h.runOnce(t)
	crashBaseline := h.uploader.putCalls()
	if crashBaseline != 2 {
		t.Fatalf("expected two object uploads before the feed crash, got %d", crashBaseline)
	}

	// Auth job must have persisted object_ref (upload committed) but no feed_ref.
	jobs, _ := h.store.listJobsForRegistry(context.Background(), reg.ID)
	var auth PublicationJob
	for _, j := range jobs {
		if j.Kind == PublicationKindAuth {
			auth = j
		}
	}
	if auth.ObjectRef == "" || auth.FeedRef != "" {
		t.Fatalf("expected crash between upload and feed-update stages, got %+v", auth)
	}

	// Recover: the retry skips re-upload (putCount unchanged) and finishes.
	h.feeds.allow(authFeed)
	h.runOnce(t)

	if got := h.uploader.putCalls(); got != crashBaseline {
		t.Fatalf("retry must not re-upload completed stage, got %d uploads", got)
	}
	registry, err := h.store.FindRegistryByID(context.Background(), reg.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if registry.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("expected ready after crash-resume, got %q", registry.ProvisioningState)
	}
}

// TestProvisioningReadBackMismatchStaysProvisioning proves a read-back mismatch
// is a retryable, non-terminal failure: the job is never falsely completed and
// the registry stays provisioning until read-back verifies, then becomes ready.
func TestProvisioningReadBackMismatchStaysProvisioning(t *testing.T) {
	h := newProvisioningHarness(t)
	created := h.createRegistry(t)
	reg := created.Registry

	h.uploader.mismatched = true
	h.runOnce(t)

	registry, err := h.store.FindRegistryByID(context.Background(), reg.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if registry.ProvisioningState != ProvisioningStateProvisioning {
		t.Fatalf("read-back mismatch must not complete provisioning, got %q", registry.ProvisioningState)
	}
	jobs, _ := h.store.listJobsForRegistry(context.Background(), reg.ID)
	for _, j := range jobs {
		if j.State == PublicationStateSucceeded {
			t.Fatalf("no job may succeed on read-back mismatch, got %+v", j)
		}
		if j.Attempts != 1 || j.LastError != "read-back mismatch" {
			t.Fatalf("expected a durable sanitized read-back-mismatch failure, got %+v", j)
		}
	}

	// Object + feed refs were committed before read-back; recovery verifies and
	// completes without re-uploading.
	uploadsBefore := h.uploader.putCalls()
	h.uploader.mismatched = false
	h.runOnce(t)

	registry, err = h.store.FindRegistryByID(context.Background(), reg.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if registry.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("expected ready after read-back verified, got %q", registry.ProvisioningState)
	}
	if got := h.uploader.putCalls(); got != uploadsBefore {
		t.Fatalf("read-back recovery must not re-upload, got %d vs %d", got, uploadsBefore)
	}
}

// TestProvisioningDuplicateRunOnceConcurrentClaim publishes each logical job
// exactly once under concurrent reconciler passes: claiming is atomic, so two
// racing workers never duplicate a publication.
func TestProvisioningDuplicateRunOnceConcurrentClaim(t *testing.T) {
	h := newProvisioningHarness(t)
	created := h.createRegistry(t)
	h.reconciler.MaxAttempts = 3

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- h.reconciler.RunOnce(context.Background())
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent run once: %v", err)
		}
	}

	// Exactly one upload per logical job (auth, stamp), never more.
	if got := h.uploader.putCalls(); got != 2 {
		t.Fatalf("concurrent claim must publish each job exactly once, got %d uploads", got)
	}
	registry, err := h.store.FindRegistryByID(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if registry.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("expected ready after concurrent claim, got %q", registry.ProvisioningState)
	}
}

// TestProvisioningTerminalFailureMarksFailed proves the bounded terminal rule:
// a persistently failing job exhausts attempts and the registry is marked
// 'failed' only under that explicit rule (never 'ready').
func TestProvisioningTerminalFailureMarksFailed(t *testing.T) {
	h := newProvisioningHarness(t)
	created := h.createRegistry(t)
	h.reconciler.MaxAttempts = 2

	// Make BOTH feed updates fail so the registry can only reach the terminal
	// state, not be partially completed.
	h.feeds.fail(authPolicyFeedRef(created.Registry))
	h.feeds.fail(stampPolicyFeedRef(created.Registry))

	h.runOnce(t) // attempt 1 on each job
	h.advance(time.Nanosecond)
	h.runOnce(t) // attempt 2 → terminal failed

	registry, err := h.store.FindRegistryByID(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if registry.ProvisioningState != ProvisioningStateFailed {
		t.Fatalf("expected bounded-attempts terminal failure, got %q", registry.ProvisioningState)
	}
	jobs, _ := h.store.listJobsForRegistry(context.Background(), created.Registry.ID)
	for _, j := range jobs {
		if j.State != PublicationStateFailed {
			t.Fatalf("expected both jobs terminal failed, got %+v", j)
		}
		if j.LastError == "" {
			t.Fatal("expected a sanitized LastError on failure")
		}
	}
}

// TestReconcilerCancellationAndLoopShutdown proves cancellation is honored and
// the Run loop joins gracefully (no goroutine leak): Run returns promptly after
// context cancellation and RunOnce aborts on a cancelled context.
func TestReconcilerCancellationAndLoopShutdown(t *testing.T) {
	h := newProvisioningHarness(t)
	h.createRegistry(t)

	// Cancelled RunOnce returns the context error promptly.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.reconciler.RunOnce(cctx); err == nil {
		t.Fatal("expected cancelled RunOnce to return an error")
	}

	// Run joins gracefully after cancellation, with a deadline so a leak fails
	// the test instead of hanging.
	ctx, cancel2 := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = h.reconciler.Run(ctx)
		close(done)
	}()
	cancel2()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not join within 5s after cancellation")
	}
}

// TestCreateRegistryReturnsProvisioningNotClaimedBootstrap pins that creation
// returns deterministic refs and the provisioning state, without ever
// publishing: no object/feed is populated until reconciliation.
func TestCreateRegistryReturnsProvisioningNotClaimedBootstrap(t *testing.T) {
	h := newProvisioningHarness(t)
	created := h.createRegistry(t)

	if created.State != ProvisioningStateProvisioning {
		t.Fatalf("expected provisioning state, got %q", created.State)
	}
	if created.Bootstrap.FeedOwnerAddress == "" || created.Bootstrap.AuthPolicyFeed == "" || created.Bootstrap.StampPolicyFeed == "" {
		t.Fatalf("expected deterministic feed refs (not publications), got %+v", created.Bootstrap)
	}
	// Nothing published yet: no uploads, no feed entries.
	if got := h.uploader.putCalls(); got != 0 {
		t.Fatalf("expected zero uploads at creation, got %d", got)
	}
	if len(h.feeds.inner.Feeds) != 0 {
		t.Fatalf("expected zero published feeds at creation, got %v", h.feeds.inner.Feeds)
	}
	if created.Registry.ProvisioningState != ProvisioningStateProvisioning {
		t.Fatalf("expected registry row provisioning, got %q", created.Registry.ProvisioningState)
	}
}
