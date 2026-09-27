package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/staging"
)

// ---------------------------------------------------------------------------
// Authoritative control-plane model
// ---------------------------------------------------------------------------

// generationCommitter is an in-process model of the AUTHORITATIVE
// control-plane feed signer for concurrency tests. On every commit it decodes
// the document the effective feed currently points at and compares its
// generation to the request's expected generation — the SAME check the real
// signer performs — advancing the feed only on an exact match and returning
// the signer's stable conflict sentinel otherwise. It can additionally gate
// the FIRST commit it ever receives on a caller-supplied channel so tests can
// deterministically force two concurrent publications to both resolve the OLD
// generation before either advances the feed.
type generationCommitter struct {
	feeds *resolve.MemoryFeedStore
	docs  *resolve.MemoryDocumentStore

	// gate, when non-nil, blocks the FIRST commit call until the channel is
	// released (consumed exactly once), so a test can hold one publication's
	// commit while another proceeds. blockSeen ensures only the FIRST caller to
	// reach Commit is gated; later callers pass straight through.
	gate      chan struct{}
	blockSeen atomic.Bool
	blocked   chan struct{} // closed when the gated commit is blocked

	mu        sync.Mutex
	commits   int
	conflicts int
}

func (g *generationCommitter) Commit(_ context.Context, req publish.FeedCommitRequest) (publish.FeedCommitResult, error) {
	if g.gate != nil && g.blockSeen.CompareAndSwap(false, true) {
		close(g.blocked)
		<-g.gate
	}

	topic := publish.CanonicalTopic(req.Topic)
	// Read the CURRENT authoritative generation by resolving the effective feed
	// through the (lock-protected) memory store APIs and decoding its document.
	// Only the memory store's own mutex serializes these map accesses, so no
	// false data races with the handler's verification reads.
	curGen := int64(0)
	if ref, err := g.feeds.ResolveFeed(context.Background(), topic); err == nil {
		if data, derr := g.docs.Get(context.Background(), ref); derr == nil {
			if doc, derr := spec.DecodeRepoStateDocument(data); derr == nil {
				curGen = doc.Generation
			}
		}
	}

	g.mu.Lock()
	g.commits++
	// Authoritative generation comparison: the feed must be EXACTLY at the
	// expected generation, never ahead or behind the caller's read. This is
	// the RECOVERABLE conflict class — the real signer's 412
	// errFeedSignerGenerationConflict — never the permanent operation/binding
	// conflict, so IsGenerationConflict recognizes it and the publisher's
	// one-time rebuild triggers.
	if req.ExpectedGeneration != curGen {
		g.conflicts++
		g.mu.Unlock()
		return publish.FeedCommitResult{}, publish.ErrCommitGenerationConflict
	}
	g.mu.Unlock()

	if err := g.feeds.UpdateFeed(context.Background(), topic, publish.CanonicalReference(req.Reference)); err != nil {
		return publish.FeedCommitResult{}, publish.ErrCommitBackend
	}
	return publish.FeedCommitResult{
		OperationID: req.OperationID,
		Feed:        topic,
		Reference:   publish.CanonicalReference(req.Reference),
	}, nil
}

func (g *generationCommitter) count() (commits, conflicts int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.commits, g.conflicts
}

// failOnceAfterAdvance models a crash AFTER the effective feed update but
// before the commit response reaches the caller: on its first call it advances
// the feed exactly like a real signer but returns the retryable backend class,
// so the lost response is recovered through the feed read-back on retry.
type failOnceAfterAdvance struct {
	inner *generationCommitter
	fail  atomic.Bool
}

func (c *failOnceAfterAdvance) Commit(ctx context.Context, req publish.FeedCommitRequest) (publish.FeedCommitResult, error) {
	if c.fail.CompareAndSwap(true, false) {
		// The feed advances; the response is lost.
		_, _ = c.inner.Commit(ctx, req)
		return publish.FeedCommitResult{}, publish.ErrCommitBackend
	}
	return c.inner.Commit(ctx, req)
}

// failNthUploader fails the n-th immutable object Put it receives, exactly
// once, then succeeds — used to inject a crash AFTER the manifest object upload
// but BEFORE the state object upload (a durable orphan manifest, feed unchanged).
type failNthUploader struct {
	inner publish.ObjectUploader
	n     int
	puts  int
}

func (f *failNthUploader) Put(ctx context.Context, data []byte, batchID string) (string, error) {
	f.puts++
	if f.puts == f.n {
		return "", errors.New("injected object upload failure")
	}
	return f.inner.Put(ctx, data, batchID)
}

// failOnceClearStaging fails the FIRST staging consumption after a verified
// publication (models a crash AFTER read-back verification but BEFORE staging
// clean-up) without touching the committed feed.
type failOnceClearStaging struct {
	staging.RegistryStore
	fail atomic.Bool
}

func (c *failOnceClearStaging) ClearStagedBlobsByDigest(ctx context.Context, repo, actor string, digests []string) error {
	if c.fail.CompareAndSwap(true, false) {
		return errors.New("injected staging clear failure")
	}
	return c.RegistryStore.ClearStagedBlobsByDigest(ctx, repo, actor, digests)
}

// ---------------------------------------------------------------------------
// Worlds
// ---------------------------------------------------------------------------

// putManifestTag PUTs a manifest body under an explicit tag and returns the raw
// response so a caller can read the status/headers without auto-closing.
func putManifestTag(t *testing.T, url string, issuer *auth.RegistryTokenIssuer, tag string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url+"/v2/backend/api/manifests/"+tag, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create manifest request: %v", err)
	}
	pushTo(t, req, issuer)
	req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("manifest publish request failed: %v", err)
	}
	return resp
}

// twoHandlerWorld builds TWO independent registry handlers that SHARE the same
// authoritative control-plane stores and committer but each own a SEPARATE
// in-process locker and staging pool — the exact topology in which the control
// plane's generation comparison, not any local lock, must enforce serialization.
func twoHandlerWorld(t *testing.T, committer *generationCommitter) (h1, h2 *Handler, docs *resolve.MemoryDocumentStore, feeds *resolve.MemoryFeedStore, issuer *auth.RegistryTokenIssuer, url1, url2 string) {
	t.Helper()
	docs = resolve.NewMemoryDocumentStore()
	feeds = resolve.NewMemoryFeedStore()
	docs.Documents["auth-policy-ref"] = []byte(`{
		"version":1,
		"defaultAccess":"deny",
		"repos":{"backend/api":{"pull":["anonymous","user:alice"],"push":["user:alice"]}}
	}`)
	docs.Documents["stamp-policy-ref"] = []byte(`{
		"version":1,
		"defaultPolicy":{"batchID":"batch-default","allowPushFor":["user:alice"]},
		"repos":{"backend/api":{"batchID":"batch-repo","allowPushFor":["user:alice"]}}
	}`)
	feeds.Feeds[spec.AuthPolicyFeedRef("0xaliceowner")] = "auth-policy-ref"
	feeds.Feeds[spec.StampPolicyFeedRef("0xaliceowner")] = "stamp-policy-ref"

	// Both handlers SHARE one key pair so a single issuer signs tokens valid for
	// both (they are independent registry instances otherwise — separate lockers
	// and staging pools).
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	h1raw, issuer := newTestHandlerWithKeys(t, docs, feeds, pub, priv)
	h1 = h1raw
	h1.Publisher.Commits = committer
	h2raw, _ := newTestHandlerWithKeys(t, docs, feeds, pub, priv)
	h2 = h2raw
	h2.Publisher.Commits = committer

	s1 := httptest.NewServer(h1)
	s2 := httptest.NewServer(h2)
	t.Cleanup(s1.Close)
	t.Cleanup(s2.Close)
	return h1, h2, docs, feeds, issuer, s1.URL, s2.URL
}

func configFor(kind string) []byte { return []byte(`{"architecture":"` + kind + `"}`) }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestConcurrentPushesDifferentTagsBothSurvive proves per-repository publication
// is serialized in ONE handler: two concurrent PUTs to the SAME repository but
// DIFFERENT tags overlap at the commit boundary (first commit held on a gate),
// yet the second does not run until the first has fully published — and both
// tags survive with monotonically advanced generations.
func TestConcurrentPushesDifferentTagsBothSurvive(t *testing.T) {
	h, docs, feeds, issuer, serverURL := task14World(t)
	committer := &generationCommitter{
		feeds:   feeds,
		docs:    docs,
		gate:    make(chan struct{}),
		blocked: make(chan struct{}),
	}
	h.Publisher.Commits = committer

	configA := configFor("amd64")
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))
	configB := configFor("arm64")
	configBDigest := stageBlob(t, serverURL, issuer, configB, "application/vnd.oci.image.config.v1+json")
	manifestB := manifestFor(configBDigest, len(configB))

	type result struct {
		status int
		opID   string
	}
	results := make(chan result, 2)

	go func() {
		resp := putManifestTag(t, serverURL, issuer, "latest", manifestA)
		opID := resp.Header.Get(OperationIDHeader)
		results <- result{resp.StatusCode, opID}
		resp.Body.Close()
	}()
	<-committer.blocked // push A is now gated inside its commit, holding the lock

	// Start push B (different tag) for the same repository; it must WAIT on the
	// in-process lock until A fully releases.
	go func() {
		resp := putManifestTag(t, serverURL, issuer, "v2", manifestB)
		opID := resp.Header.Get(OperationIDHeader)
		results <- result{resp.StatusCode, opID}
		resp.Body.Close()
	}()

	select {
	case r := <-results:
		t.Fatalf("push B finished before push A released the lock (status %d)", r.status)
	case <-time.After(80 * time.Millisecond):
		// Correctly waiting.
	}

	close(committer.gate) // let A's commit complete and release the lock

	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.status != http.StatusCreated {
				t.Fatalf("concurrent push returned %d, want 201", r.status)
			}
			if r.opID == "" {
				t.Fatal("201 must carry the operation identity header")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for concurrent pushes")
		}
	}

	state := loadRepoState(t, docs, feeds)
	if state.Generation != 2 {
		t.Fatalf("expected generation 2, got %d", state.Generation)
	}
	if state.Tags["latest"] != publish.ComputeDigest(manifestA) || state.Tags["v2"] != publish.ComputeDigest(manifestB) {
		t.Fatalf("both tags must survive serialized publication, got %+v", state.Tags)
	}
}

// TestConcurrentPushesIndependentHandlersConflictSingleRebuild proves the AUTHORITATIVE
// control-plane generation comparison resolves a genuine cross-handler
// (cross-process) race: two independent registry handlers with SEPARATE locks
// share one feed; the later commit is rejected as a generation conflict and then
// rebuilt exactly ONCE from the newest state. Both publications succeed, both
// tags survive, and the feed advances monotonically with exactly one conflict
// and exactly one rebuild (no spin).
func TestConcurrentPushesIndependentHandlersConflictSingleRebuild(t *testing.T) {
	committer := &generationCommitter{feeds: nil, docs: nil}
	h1, h2, docs, feeds, issuer, url1, url2 := twoHandlerWorld(t, committer)
	committer.feeds = feeds
	committer.docs = docs
	committer.gate = make(chan struct{})
	committer.blocked = make(chan struct{})

	configA := configFor("amd64")
	configADigest := stageBlob(t, url1, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))
	configB := configFor("arm64")
	configBDigest := stageBlob(t, url2, issuer, configB, "application/vnd.oci.image.config.v1+json")
	manifestB := manifestFor(configBDigest, len(configB))

	type result struct {
		status int
		opID   string
	}
	results := make(chan result, 2)
	go func() {
		resp := putManifestTag(t, url1, issuer, "amd-tag", manifestA)
		results <- result{resp.StatusCode, resp.Header.Get(OperationIDHeader)}
		resp.Body.Close()
	}()
	select {
	case <-committer.blocked:
	case <-time.After(3 * time.Second):
		c, cf := committer.count()
		t.Fatalf("push A never reached the gated commit (commits=%d conflicts=%d feed=%v)", c, cf, feeds.Feeds[repoStateFeed()])
	}

	go func() {
		resp := putManifestTag(t, url2, issuer, "arm-tag", manifestB)
		results <- result{resp.StatusCode, resp.Header.Get(OperationIDHeader)}
		resp.Body.Close()
	}()

	// The ungated publish advances to generation 1 first.
	select {
	case r := <-results:
		if r.status != http.StatusCreated {
			t.Fatalf("first cross-handler push returned %d, want 201", r.status)
		}
	case <-time.After(3 * time.Second):
		c, cf := committer.count()
		t.Fatalf("timed out waiting for the un-gated push (commits=%d conflicts=%d feed=%v)", c, cf, feeds.Feeds[repoStateFeed()])
	}

	close(committer.gate) // release the gated handler; it must conflict and rebuild once

	select {
	case r := <-results:
		if r.status != http.StatusCreated {
			t.Fatalf("conflicted cross-handler push must rebuild and return 201, got %d", r.status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the conflict-rebuilt push")
	}

	commits, conflicts := committer.count()
	if conflicts != 1 {
		t.Fatalf("expected exactly one authoritative generation conflict, got %d", conflicts)
	}
	if commits != 3 { // two successes + one conflicted attempt before its rebuild
		t.Fatalf("expected exactly 3 commit calls (2 successes + 1 conflict), got %d", commits)
	}

	state := loadRepoState(t, docs, feeds)
	if state.Generation != 2 {
		t.Fatalf("expected generation 2 after a single rebuild, got %d", state.Generation)
	}
	if state.Tags["amd-tag"] != publish.ComputeDigest(manifestA) || state.Tags["arm-tag"] != publish.ComputeDigest(manifestB) {
		t.Fatalf("both tags must survive the conflict rebuild, got %+v", state.Tags)
	}
	_ = h1
	_ = h2
}

// TestConcurrentPushesSameTagConflictPreservesUnrelated proves that when two independent
// handlers race on the SAME tag with DIFFERENT digests, the deterministically
// rebuilt latecomer clones the winner's current state onto its own — unrelated
// tags, manifests, and blobs are never deleted, the feed advances monotonically,
// and the conflict resolves with exactly one rebuild.
func TestConcurrentPushesSameTagConflictPreservesUnrelated(t *testing.T) {
	committer := &generationCommitter{feeds: nil, docs: nil}
	h1, h2, docs, feeds, issuer, url1, url2 := twoHandlerWorld(t, committer)
	committer.feeds = feeds
	committer.docs = docs

	// Seed an unrelated "stable" tag through a full real publication so the
	// concurrent same-tag race must preserve it.
	seedConfig := configFor("seed")
	seedDigest := stageBlob(t, url1, issuer, seedConfig, "application/vnd.oci.image.config.v1+json")
	seedResp := putManifestTag(t, url1, issuer, "stable", manifestFor(seedDigest, len(seedConfig)))
	if seedResp.StatusCode != http.StatusCreated {
		t.Fatalf("seed push status %d, want 201", seedResp.StatusCode)
	}
	seedResp.Body.Close()

	// Now a fresh authoritative committer for the racy same-tag phase.
	committer2 := &generationCommitter{feeds: feeds, docs: docs, gate: make(chan struct{}), blocked: make(chan struct{})}
	h1.Publisher.Commits = committer2
	h2.Publisher.Commits = committer2

	configA := configFor("amd64")
	configADigest := stageBlob(t, url1, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))
	configB := configFor("arm64")
	configBDigest := stageBlob(t, url2, issuer, configB, "application/vnd.oci.image.config.v1+json")
	manifestB := manifestFor(configBDigest, len(configB))

	type result struct{ status int }
	results := make(chan result, 2)

	go func() {
		resp := putManifestTag(t, url1, issuer, "latest", manifestA)
		results <- result{resp.StatusCode}
		resp.Body.Close()
	}()
	select {
	case <-committer2.blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("same-tag push A never reached the gated commit")
	}

	go func() {
		resp := putManifestTag(t, url2, issuer, "latest", manifestB)
		results <- result{resp.StatusCode}
		resp.Body.Close()
	}()

	// The un-gated same-tag push lands first (advancing the feed); then release
	// the gated push so it conflicts and rebuilds once onto the newer state.
	select {
	case r := <-results:
		if r.status != http.StatusCreated {
			t.Fatalf("un-gated same-tag push returned %d, want 201", r.status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the un-gated same-tag push")
	}
	close(committer2.gate)

	select {
	case r := <-results:
		if r.status != http.StatusCreated {
			t.Fatalf("conflict-rebuilt same-tag push returned %d, want 201", r.status)
		}
	case <-time.After(3 * time.Second):
		c, cf := committer2.count()
		t.Fatalf("timed out waiting for the conflict-rebuilt same-tag push (commits=%d conflicts=%d)", c, cf)
	}

	commits, conflicts := committer2.count()
	if conflicts != 1 {
		t.Fatalf("expected exactly one same-tag generation conflict, got %d", conflicts)
	}
	if commits != 3 {
		t.Fatalf("expected exactly 3 commit calls, got %d", commits)
	}

	state := loadRepoState(t, docs, feeds)
	if state.Generation != 3 { // seed(1) + two same-tag publications (2,3)
		t.Fatalf("expected generation 3, got %d", state.Generation)
	}
	// The unrelated seeded tag must be preserved.
	if _, ok := state.Tags["stable"]; !ok {
		t.Fatalf("same-tag conflict deleted the unrelated stable tag: %+v", state.Tags)
	}
	// The two raced manifests/blobs must both remain (no deletion).
	digestA := publish.ComputeDigest(manifestA)
	digestB := publish.ComputeDigest(manifestB)
	if _, ok := state.Manifests[digestA]; !ok {
		t.Fatalf("winner/loser manifest A missing after conflict: %+v", state.Manifests)
	}
	if _, ok := state.Manifests[digestB]; !ok {
		t.Fatalf("winner/loser manifest B missing after conflict: %+v", state.Manifests)
	}
	if _, ok := state.Blobs[configADigest]; !ok {
		t.Fatalf("referenced blob A missing after conflict")
	}
	if _, ok := state.Blobs[configBDigest]; !ok {
		t.Fatalf("referenced blob B missing after conflict")
	}
	// The tag deterministically points at ONE of the raced digests (last writer wins).
	if state.Tags["latest"] != digestA && state.Tags["latest"] != digestB {
		t.Fatalf("same-tag must end at one of the raced digests, got %s", state.Tags["latest"])
	}
}

// TestConcurrentPushesCancellationZeroSideEffects proves a waiter whose context is
// canceled while waiting on the publication lock performs ZERO immutable, feed,
// or staging writes — and returns promptly with the retryable dependency class.
func TestConcurrentPushesCancellationZeroSideEffects(t *testing.T) {
	h, docs, feeds, _ := newFirstPushWorld(t)
	h.PushAuthorizer = &recordingPushAuthorizer{allowed: true, batchID: "batch-repo"}
	counter := &countingObjectUploader{inner: docs}
	h.Publisher.Objects = counter
	committer := &generationCommitter{feeds: feeds, docs: docs}
	h.Publisher.Commits = committer

	identity := resolve.RegistryIdentity{Host: testServiceHost, Owner: "0xaliceowner"}

	// Hold the publication lock for backend/api directly (same canonical key the
	// handler serializes on), so any handler request blocks deterministically.
	held := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan struct{})
	go func() {
		_ = h.Locker.WithLock(context.Background(), identity.Owner, "backend/api", func(_ context.Context) error {
			close(held)
			<-release
			return nil
		})
		close(holderDone)
	}()
	<-held

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPut, "https://"+testServiceHost+"/v2/backend/api/manifests/latest", strings.NewReader(string(manifestFor("sha256:"+strings.Repeat("a", 64), 24))))
	req = req.WithContext(ctx)
	req.Host = testServiceHost
	req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.handleManifestPut(rec, req, identity, "backend/api", "latest", auth.Principal{Subject: "user:alice"})
		close(done)
	}()

	// Give the handler time to reach the lock and begin waiting.
	time.Sleep(60 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("handler returned while it must still be waiting on the publication lock")
	default:
	}

	cancel() // the waiter's context is canceled while waiting

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled waiter did not return promptly")
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("canceled waiter must map to 503 DEPENDENCY_UNAVAILABLE, got %d", rec.Code)
	}
	if counter.puts != 0 {
		t.Fatalf("canceled waiter performed %d immutable object writes, want 0", counter.puts)
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("canceled waiter must not create/advance the repo-state feed")
	}
	if state, err := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice"); err != nil || len(state) != 0 {
		t.Fatalf("canceled waiter disturbed staging: %+v (err %v)", state, err)
	}

	close(release)
	<-holderDone
}

// TestPublishRetryCrashAfterStatePut models a crash after the manifest
// object upload but before the state object upload: the retry re-uploads the
// immutable manifest (transport-only, same content address) and commits exactly
// once, advancing the feed a single generation with the exact operation
// provenance.
func TestPublishRetryCrashAfterStatePut(t *testing.T) {
	h, docs, feeds, issuer, serverURL := task14World(t)
	committer := &generationCommitter{feeds: feeds, docs: docs}
	h.Publisher.Commits = committer
	// Fail the SECOND put (the repo-state object) on the first attempt only.
	h.Publisher.Objects = &failNthUploader{inner: docs, n: 2}

	configBytes := configFor("amd64")
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	first := putManifestTag(t, serverURL, issuer, "latest", manifestBody)
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusInternalServerError {
		t.Fatalf("crash-after-state-put must surface 500 UNKNOWN (an object-store failure is not a retryable dependency), got %d (%s)", first.StatusCode, firstBody)
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("failed first attempt must not advance the feed")
	}

	retry := putManifestTag(t, serverURL, issuer, "latest", manifestBody)
	retryBody, _ := io.ReadAll(retry.Body)
	opID := retry.Header.Get(OperationIDHeader)
	retry.Body.Close()
	if retry.StatusCode != http.StatusCreated {
		t.Fatalf("retry must return 201, got %d (%s)", retry.StatusCode, retryBody)
	}

	state := loadRepoState(t, docs, feeds)
	if state.Generation != 1 {
		t.Fatalf("crash-point retry must advance the feed exactly once, got generation %d", state.Generation)
	}
	pub, ok := state.TagPublications["latest"]
	if !ok || pub.OperationID != opID {
		t.Fatalf("retry must retain the exact committed operation provenance, got %+v", pub)
	}
}

// TestPublishRetryCrashAfterCommitFeedUpdate models a crash after the
// effective feed update but before the commit response: the first attempt
// advances the feed, the retry is recognized through the feed read-back and
// answered WITHOUT another commit — the feed advances exactly once.
func TestPublishRetryCrashAfterCommitFeedUpdate(t *testing.T) {
	h, docs, feeds, issuer, serverURL := task14World(t)
	inner := &generationCommitter{feeds: feeds, docs: docs}
	committer := &failOnceAfterAdvance{inner: inner}
	committer.fail.Store(true)
	h.Publisher.Commits = committer

	configBytes := configFor("amd64")
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	first := putManifestTag(t, serverURL, issuer, "latest", manifestBody)
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("crash-after-feed-update must surface 503, got %d (%s)", first.StatusCode, firstBody)
	}

	// Feed already advanced despite the lost response.
	feedRefAfterFirst := feeds.Feeds[repoStateFeed()]
	if feedRefAfterFirst == "" {
		t.Fatal("feed must have advanced before the lost response")
	}

	retry := putManifestTag(t, serverURL, issuer, "latest", manifestBody)
	retryBody, _ := io.ReadAll(retry.Body)
	opID := retry.Header.Get(OperationIDHeader)
	retry.Body.Close()
	if retry.StatusCode != http.StatusCreated {
		t.Fatalf("lost-response retry must return 201, got %d (%s)", retry.StatusCode, retryBody)
	}
	if feeds.Feeds[repoStateFeed()] != feedRefAfterFirst {
		t.Fatal("lost-response retry must NOT advance the feed a second time")
	}
	commits, _ := inner.count()
	if commits != 1 {
		t.Fatalf("lost-response retry must not commit a second time, got %d commits", commits)
	}
	if opID == "" {
		t.Fatal("retry must carry the exact prior operation identity")
	}
	state := loadRepoState(t, docs, feeds)
	if state.Generation != 1 {
		t.Fatalf("expected generation 1 (single advancement), got %d", state.Generation)
	}
	if pub, ok := state.TagPublications["latest"]; !ok || pub.OperationID != opID {
		t.Fatalf("committed provenance must match the returned operation identity: %+v", pub)
	}
}

// TestPublishRetryCrashAfterVerificationBeforeStagingClear models a crash
// after read-back verification passed but before the staging clean-up: the
// committed result stays effective, the retry is recognized and answered without
// advancing the feed, and the un-cleared staged blob is retained (never
// prematurely cleared and never re-consumed by the retry).
func TestPublishRetryCrashAfterVerificationBeforeStagingClear(t *testing.T) {
	h, docs, feeds, issuer, serverURL := task14World(t)
	committer := &generationCommitter{feeds: feeds, docs: docs}
	h.Publisher.Commits = committer
	clearFail := &failOnceClearStaging{RegistryStore: h.Staging}
	clearFail.fail.Store(true)
	h.Staging = clearFail

	configBytes := configFor("amd64")
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	first := putManifestTag(t, serverURL, issuer, "latest", manifestBody)
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusInternalServerError {
		t.Fatalf("staging-clear crash must surface 500 UNKNOWN, got %d (%s)", first.StatusCode, firstBody)
	}

	feedRefAfterFirst := feeds.Feeds[repoStateFeed()]
	if feedRefAfterFirst == "" {
		t.Fatal("verified publication must have advanced the feed")
	}

	retry := putManifestTag(t, serverURL, issuer, "latest", manifestBody)
	retryBody, _ := io.ReadAll(retry.Body)
	opID := retry.Header.Get(OperationIDHeader)
	retry.Body.Close()
	if retry.StatusCode != http.StatusCreated {
		t.Fatalf("retry of a verified publication must return 201, got %d (%s)", retry.StatusCode, retryBody)
	}
	if feeds.Feeds[repoStateFeed()] != feedRefAfterFirst {
		t.Fatal("retry must NOT advance the feed")
	}
	commits, _ := committer.count()
	if commits != 1 {
		t.Fatalf("retry must not commit again, got %d commits", commits)
	}
	state := loadRepoState(t, docs, feeds)
	if state.Generation != 1 {
		t.Fatalf("expected generation 1, got %d", state.Generation)
	}
	if pub, ok := state.TagPublications["latest"]; !ok || pub.OperationID != opID {
		t.Fatalf("retry must return the exact prior operation identity: %+v", pub)
	}
	// The referenced blob stayed staged (clean-up crashed); a retried publication
	// is recognized as already-published and must neither clear nor orphan it.
	remaining, err := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Digest != configDigest {
		t.Fatalf("un-cleared staged blob must be retained, got %+v", remaining)
	}
}
