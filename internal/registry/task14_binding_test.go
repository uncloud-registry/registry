package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
)

// durableBindingStore models the control-plane publication-binding table for
// Handler-level tests: a mutex-guarded, keyed map that is SHARED across
// reconstructed handlers exactly like the control-plane database survives a
// process restart. Binding a fresh operation key records it; rebinding the
// SAME key to an identical logical payload (registry + owner + repo + tag +
// manifest digest) is an idempotent pass; rebinding it to a DIFFERENT payload
// is a hard conflict — the same atomic insert-or-compare decision the real
// store makes under one write transaction, so concurrent changed requests
// have exactly one binding winner.
type durableBindingStore struct {
	mu        sync.Mutex
	bindings  map[string]bindingRecord
	calls     int
	conflicts int
}

type bindingRecord struct {
	registryID int64
	owner      string
	repo       string
	tag        string
	digest     string
}

func newDurableBindingStore() *durableBindingStore {
	return &durableBindingStore{bindings: map[string]bindingRecord{}}
}

func (d *durableBindingStore) Bind(_ context.Context, req publish.OperationBindingRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	rec := bindingRecord{registryID: req.RegistryID, owner: req.Owner, repo: req.Repo, tag: req.Tag, digest: req.ManifestDigest}
	if existing, ok := d.bindings[req.OperationID]; ok {
		if existing != rec {
			d.conflicts++
			return publish.ErrCommitConflict
		}
		return nil
	}
	d.bindings[req.OperationID] = rec
	return nil
}

// atomicCountingUploader counts immutable object writes safely under
// concurrent requests so zero-write assertions hold on race builds.
type atomicCountingUploader struct {
	inner publish.ObjectUploader
	puts  atomic.Int32
}

func (c *atomicCountingUploader) Put(ctx context.Context, data []byte, batchID string) (string, error) {
	c.puts.Add(1)
	return c.inner.Put(ctx, data, batchID)
}

// bindingWorld assembles the task-14 first-push world with the durable
// binding store, a counting object uploader, and the scripted control-plane
// committer wired in — the production-like path the real fix runs.
func bindingWorld(t *testing.T) (*Handler, *durableBindingStore, *atomicCountingUploader, *scriptedCommitter, *resolve.MemoryDocumentStore, *resolve.MemoryFeedStore, *auth.RegistryTokenIssuer, string) {
	t.Helper()
	h, docs, feeds, issuer, serverURL := task14World(t)
	binder := newDurableBindingStore()
	h.Preflight = binder
	counter := &atomicCountingUploader{inner: docs}
	h.Publisher.Objects = counter
	committer := &scriptedCommitter{feeds: feeds, writeFeed: true}
	h.Publisher.Commits = committer
	return h, binder, counter, committer, docs, feeds, issuer, serverURL
}

// TestExplicitKeyReuseConflictRejectedBeforeAnyObjectWrite is the adversarial
// core: reusing one explicit operation key with a DIFFERENT payload must be a
// 409 with ZERO new immutable object writes, zero feed writes, and zero
// staging consumption — the durable key binding is decided before the
// publisher ever uploads the manifest or the draft state.
func TestExplicitKeyReuseConflictRejectedBeforeAnyObjectWrite(t *testing.T) {
	const key = "client-t14r2-key-0001"
	h, binder, counter, _, docs, feeds, issuer, serverURL := bindingWorld(t)

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))

	putWith := func(tag string, body []byte) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/"+tag, strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		pushTo(t, req, issuer)
		req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
		req.Header.Set(OperationIDHeader, key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	first := putWith("latest", manifestA)
	defer first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first push must be 201, got %d", first.StatusCode)
	}
	if counter.puts.Load() != 2 {
		t.Fatalf("first publication must write exactly the manifest + state objects (2 puts), got %d", counter.puts.Load())
	}
	if binder.calls != 1 || len(binder.bindings) != 1 {
		t.Fatalf("first publication must bind the key once: calls=%d bindings=%d", binder.calls, len(binder.bindings))
	}
	docCount := len(docs.Documents)
	feedRef := feeds.Feeds[repoStateFeed()]

	// Same key, DIFFERENT manifest digest (new staged config) — must 409
	// BEFORE the manifest and draft-state objects are uploaded.
	configB := []byte(`{"architecture":"arm64"}`)
	configBDigest := stageBlob(t, serverURL, issuer, configB, "application/vnd.oci.image.config.v1+json")
	manifestB := manifestFor(configBDigest, len(configB))
	docCount = len(docs.Documents) // staging configB records its own doc; the conflicting REQUEST must add none.

	second := putWith("latest", manifestB)
	defer second.Body.Close()
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("key reuse with a different digest must be 409, got %d", second.StatusCode)
	}
	if counter.puts.Load() != 2 {
		t.Fatalf("conflicted key reuse caused %d object writes, want exactly the first publication's 2", counter.puts.Load())
	}
	if len(docs.Documents) != docCount {
		t.Fatalf("conflicted key reuse created %d new objects, want zero", len(docs.Documents)-docCount)
	}
	if feeds.Feeds[repoStateFeed()] != feedRef {
		t.Fatal("conflicted key reuse must leave the feed exactly at the first publication")
	}
	if binder.conflicts != 1 {
		t.Fatalf("expected exactly one binding conflict, got %d", binder.conflicts)
	}
	remaining, err := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil || len(remaining) != 1 || remaining[0].Digest != configBDigest {
		t.Fatalf("conflicted key reuse must not consume the new staged blob, got %+v (err %v)", remaining, err)
	}
	if state := loadRepoState(t, docs, feeds); state.Generation != 1 {
		t.Fatalf("conflicted key reuse must not advance generation, got %d", state.Generation)
	}
}

// TestExplicitKeyConflictSurvivesHandlerReconstruction proves the durable
// binding is consulted again after a process-style reconstruction: a rebuilt
// handler over the same stores and the same binding table rejects the same
// key with a changed tag BEFORE any object write, while the same key with the
// SAME payload is answered as the prior verified 201 with zero writes.
func TestExplicitKeyConflictSurvivesHandlerReconstruction(t *testing.T) {
	const key = "client-t14r2-key-0002"
	h, binder, counter, _, docs, feeds, issuer, serverURL := bindingWorld(t)

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))

	putOn := func(t *testing.T, baseURL string, iss *auth.RegistryTokenIssuer, tag string, body []byte, wantStatus int) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPut, baseURL+"/v2/backend/api/manifests/"+tag, strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		pushTo(t, req, iss)
		req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
		req.Header.Set(OperationIDHeader, key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != wantStatus {
			t.Fatalf("expected %d, got %d", wantStatus, resp.StatusCode)
		}
	}

	putOn(t, serverURL, issuer, "latest", manifestA, http.StatusCreated)
	if counter.puts.Load() != 2 {
		t.Fatalf("first publication must write 2 objects, got %d", counter.puts.Load())
	}
	docCount := len(docs.Documents)
	feedRef := feeds.Feeds[repoStateFeed()]
	_ = h

	// Reconstructed handler: fresh staging store, same durable stores and the
	// SAME durable binding table (survives the restart).
	rebuiltHandler, issuer2 := newTestHandler(t, docs, feeds)
	rebuilt := rebuiltHandler.(*Handler)
	rebuilt.Preflight = binder
	counter2 := &atomicCountingUploader{inner: docs}
	rebuilt.Publisher.Objects = counter2
	committer2 := &scriptedCommitter{feeds: feeds, writeFeed: true}
	rebuilt.Publisher.Commits = committer2
	server2 := httptest.NewServer(rebuilt)
	defer server2.Close()

	// Same key, SAME payload, tag changed away from the bound one: 409 AFTER
	// the restart, still before any object write.
	putOn(t, server2.URL, issuer2, "v2", manifestA, http.StatusConflict)
	if counter2.puts.Load() != 0 {
		t.Fatalf("post-restart conflict caused %d object writes, want 0", counter2.puts.Load())
	}
	if len(docs.Documents) != docCount {
		t.Fatalf("post-restart conflict created %d new objects, want zero", len(docs.Documents)-docCount)
	}
	if feeds.Feeds[repoStateFeed()] != feedRef {
		t.Fatal("post-restart conflict must leave the feed unchanged")
	}
	if binder.conflicts != 1 {
		t.Fatalf("expected exactly one binding conflict after reconstruction, got %d", binder.conflicts)
	}

	// Same key, SAME payload, SAME tag: the prior publication is recognized
	// from the durable feed read-back and answered as the verified 201 with
	// zero writes (restart-safe idempotency preserved).
	req, err := http.NewRequest(http.MethodPut, server2.URL+"/v2/backend/api/manifests/latest", strings.NewReader(string(manifestA)))
	if err != nil {
		t.Fatal(err)
	}
	pushTo(t, req, issuer2)
	req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
	req.Header.Set(OperationIDHeader, key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("same-key same-payload retry after reconstruction must be a verified 201, got %d", resp.StatusCode)
	}
	if counter2.puts.Load() != 0 {
		t.Fatalf("restart-safe retry must not write objects, got %d puts", counter2.puts.Load())
	}
	if committer2.calls != 0 {
		t.Fatalf("restart-safe retry must not call the committer again, got %d calls", committer2.calls)
	}
	if len(docs.Documents) != docCount {
		t.Fatalf("restart-safe retry must not create objects, docs %d -> %d", docCount, len(docs.Documents))
	}
}

// TestKeyedMatchingRetryNotBlockedByPreflight proves a preflight reservation
// NEVER blocks its matching later commit: after a backend failure (the first
// attempt bound the key, wrote its objects, and failed at the commit
// boundary), the retry of the SAME logical request passes the binding and
// completes the publication.
func TestKeyedMatchingRetryNotBlockedByPreflight(t *testing.T) {
	const key = "client-t14r2-key-0003"
	h, binder, counter, committer, docs, feeds, issuer, serverURL := bindingWorld(t)
	committer.err = publish.ErrCommitBackend

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))

	putWith := func() *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", strings.NewReader(string(manifestA)))
		if err != nil {
			t.Fatal(err)
		}
		pushTo(t, req, issuer)
		req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
		req.Header.Set(OperationIDHeader, key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	first := putWith()
	first.Body.Close()
	if first.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("backend failure must be 503, got %d", first.StatusCode)
	}
	if binder.calls != 1 || len(binder.bindings) != 1 {
		t.Fatalf("failed attempt must have bound the key once: calls=%d bindings=%d", binder.calls, len(binder.bindings))
	}
	if counter.puts.Load() != 2 {
		t.Fatalf("failed attempt wrote %d objects (manifest + state), want 2", counter.puts.Load())
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("failed commit must not advance the feed")
	}

	// Retry the same logical request: the binding MATCHES, so the preflight
	// passes and the publication completes — 201, one advancement.
	committer.err = nil
	second := putWith()
	second.Body.Close()
	if second.StatusCode != http.StatusCreated {
		t.Fatalf("matching retry must complete with 201, got %d", second.StatusCode)
	}
	if binder.conflicts != 0 {
		t.Fatalf("matching retry must not conflict, got %d conflicts", binder.conflicts)
	}
	if counter.puts.Load() != 4 {
		t.Fatalf("matching retry must write exactly the second attempt's manifest + state (4 total), got %d", counter.puts.Load())
	}
	if committer.calls != 2 {
		t.Fatalf("expected two commit calls (one failed, one succeeded), got %d", committer.calls)
	}
	if state := loadRepoState(t, docs, feeds); state.Generation != 1 {
		t.Fatalf("matching retry must advance to generation 1, got %d", state.Generation)
	}
	_ = h
}

// TestConcurrentKeyedDifferentBindingsSingleWinnerBeforeObjectWrites proves
// the atomic binding decision under concurrency: two concurrent requests that
// reuse one explicit key with DIFFERENT tags must have exactly ONE binding
// winner, decided BEFORE any object write — one 201, one 409, and exactly the
// winner's two object puts.
func TestConcurrentKeyedDifferentBindingsSingleWinnerBeforeObjectWrites(t *testing.T) {
	const key = "client-t14r2-key-0004"
	h, binder, counter, _, docs, feeds, issuer, serverURL := bindingWorld(t)
	// The concurrent winner publishes through the world's DEFAULT in-memory
	// commit path (MemoryFeedStore.UpdateFeed is mutex-guarded). A
	// scriptedCommitter writes the feeds map directly and would race the
	// loser's authz read of the same map — the real signer boundary is the
	// durable binder, which is mutex-guarded and decides the single winner.
	h.Publisher.Commits = nil

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))

	var wg sync.WaitGroup
	statuses := make([]int, 2)
	tags := []string{"latest", "v2"}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/"+tags[i], strings.NewReader(string(manifestA)))
			if err != nil {
				t.Errorf("create request: %v", err)
				return
			}
			pushTo(t, req, issuer)
			req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
			req.Header.Set(OperationIDHeader, key)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("request failed: %v", err)
				return
			}
			resp.Body.Close()
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	created, conflicted := 0, 0
	for _, s := range statuses {
		switch s {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicted++
		}
	}
	if created != 1 || conflicted != 1 {
		t.Fatalf("expected exactly one 201 and one 409, got %+v", statuses)
	}
	if counter.puts.Load() != 2 {
		t.Fatalf("only the binding winner may write objects: expected 2 puts, got %d", counter.puts.Load())
	}
	if len(binder.bindings) != 1 {
		t.Fatalf("exactly one binding winner expected, got %d bindings", len(binder.bindings))
	}
	if state := loadRepoState(t, docs, feeds); state.Generation != 1 {
		t.Fatalf("exactly one logical advancement expected, got generation %d", state.Generation)
	}
}

// TestInvalidExplicitKeyDoesNotReachBinding proves an invalid/oversized key is
// rejected as 400 with zero object writes AND never invokes the durable
// binding at all: validation precedes the preflight.
func TestInvalidExplicitKeyDoesNotReachBinding(t *testing.T) {
	h, docs, feeds, issuer, serverURL := task14World(t)
	binder := newDurableBindingStore()
	h.Preflight = binder
	counter := &atomicCountingUploader{inner: docs}
	h.Publisher.Objects = counter
	h.Publisher.Feeds = feeds

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	for _, key := range []string{strings.Repeat("k", publish.OperationIDMaxLen+1), `bad"quote`} {
		req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", strings.NewReader(string(manifestBody)))
		if err != nil {
			t.Fatal(err)
		}
		pushTo(t, req, issuer)
		req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
		req.Header.Set(OperationIDHeader, key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid key must be 400, got %d", resp.StatusCode)
		}
	}
	if binder.calls != 0 {
		t.Fatalf("invalid key must never reach the durable binding, got %d calls", binder.calls)
	}
	if counter.puts.Load() != 0 {
		t.Fatalf("invalid key caused %d object writes, want 0", counter.puts.Load())
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("invalid key must not create the repo-state feed")
	}
}
