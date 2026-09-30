package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/policy"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/staging"
)

// ---------------------------------------------------------------------------
// Task 18 handler-level publication/cleanup interleaving proof.
//
// The staging-package fence tests prove the claim semantics at the SERVICE
// level. These tests prove the SAME two cross-process orderings THROUGH the
// real HTTP manifest-PUT handler, using two independent durable staging
// services/handlers sharing one staging directory (the exact two-process
// topology) plus deterministic barriers at the claim and commit boundaries.
// No sleeps, no probability: cleanup and publication are sequenced by
// explicit channels.
// ---------------------------------------------------------------------------

// claimBarrierStaging pauses the handler's FIRST ClaimStagedForPublish call
// (after it has already listed the candidate) until the test releases it. It
// wraps the durable service, passing through to the real atomic claim, so the
// interleaving is driven against the production claim, not a fake.
type claimBarrierStaging struct {
	staging.RegistryStore
	once    sync.Once
	atClaim chan struct{} // closed when the handler reaches the atomic claim
	release <-chan struct{}
}

func (c *claimBarrierStaging) ClaimStagedForPublish(ctx context.Context, repo, actor, operationID string, digests []string) ([]spec.StagedBlob, error) {
	c.once.Do(func() {
		close(c.atClaim)
		<-c.release
	})
	return c.RegistryStore.ClaimStagedForPublish(ctx, repo, actor, operationID, digests)
}

// recordingUnpinner records every Bee unpin so a cleanup pass's side effects
// can be counted exactly.
type recordingUnpinner struct {
	mu   sync.Mutex
	refs []string
}

func (u *recordingUnpinner) Unpin(_ context.Context, ref string) error {
	u.mu.Lock()
	u.refs = append(u.refs, ref)
	u.mu.Unlock()
	return nil
}

func (u *recordingUnpinner) calls() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string{}, u.refs...)
}

// emptyCommittedRefs is the authoritative committed-state provider for a
// repository nothing has ever published: no blob is committed, so every
// eligible expired finalized row is unpinnable.
type emptyCommittedRefs struct{}

func (emptyCommittedRefs) CommittedRefs(context.Context, string) (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}

// contentAddressedStore stores each payload into the shared MemoryDocumentStore
// (also the resolver's Reader) under a canonical sha256-hex key — exactly the
// 64-lowercase-hex bee ref the durable staging service requires — while staying
// readable by the production read-after-write verification path.
type contentAddressedStore struct {
	docs *resolve.MemoryDocumentStore
}

func (c *contentAddressedStore) Put(_ context.Context, data []byte, _ string) (string, error) {
	return c.store(data), nil
}

func (c *contentAddressedStore) PutStream(_ context.Context, src io.Reader, _ int64, _ string) (string, error) {
	data, err := io.ReadAll(src)
	if err != nil {
		return "", err
	}
	return c.store(data), nil
}

func (c *contentAddressedStore) store(data []byte) string {
	sum := sha256.Sum256(data)
	ref := hex.EncodeToString(sum[:])
	c.docs.Documents[ref] = append([]byte{}, data...)
	return ref
}

func (c *contentAddressedStore) Get(ctx context.Context, ref string) ([]byte, error) {
	return c.docs.Get(ctx, ref)
}

// durableTempDir returns a private 0700 directory on the real (symlink-free)
// path — the staging service fail-closes on anything looser or on symlink
// components, and t.TempDir() may be 0755 and sit behind /var on darwin.
// EvalSymlinks resolves the /var -> /private/var (or /tmp -> /private/tmp)
// symlink prefix on darwin and returns the path unchanged on Linux, where
// /var and /tmp are real directories.
func durableTempDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	if r, err := filepath.EvalSymlinks(d); err == nil {
		return r
	}
	return d
}

// durableHandlerPair builds TWO independent registry handlers that OWN
// SEPARATE durable staging services over the SAME staging directory/DB —
// modelling two processes sharing staging — while sharing the authoritative
// control-plane docs/feeds and one key pair. svc2 doubles as the independent
// cleanup instance over the same DB.
func durableHandlerPair(t *testing.T) (h1, h2 *Handler, svc1, svc2 staging.RegistryStore, docs *resolve.MemoryDocumentStore, feeds *resolve.MemoryFeedStore, issuer *auth.RegistryTokenIssuer, dbPath, url1, url2 string) {
	t.Helper()
	dir := durableTempDir(t)
	dbPath = dir + "/staging.db"
	spool := dir + "/spool"

	open := func() staging.RegistryStore {
		s, err := staging.NewService(context.Background(), spool, dbPath)
		if err != nil {
			t.Fatalf("NewService over %s: %v", dir, err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	svc1 = open()
	svc2 = open()

	docs = resolve.NewMemoryDocumentStore()
	feeds = resolve.NewMemoryFeedStore()
	docs.Documents["auth-policy-ref"] = []byte(`{
		"version":1,
		"defaultAccess":"deny",
		"repos":{"backend/api":{"pull":["user:alice"],"push":["user:alice"]}}
	}`)
	docs.Documents["stamp-policy-ref"] = []byte(`{
		"version":1,
		"defaultPolicy":{"batchID":"batch-default","allowPushFor":["user:alice"]},
		"repos":{"backend/api":{"batchID":"batch-repo","allowPushFor":["user:alice"]}}
	}`)
	feeds.Feeds[spec.AuthPolicyFeedRef("0xaliceowner")] = "auth-policy-ref"
	feeds.Feeds[spec.StampPolicyFeedRef("0xaliceowner")] = "stamp-policy-ref"

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keys := testKeySet{testKeyID: pub}
	issuer, err = auth.NewRegistryTokenIssuer(priv, auth.RegistryIssuer, testKeyID)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	verifier := auth.NewRegistryTokenVerifier(keys, auth.RegistryIssuer, testServiceHost)

	// The durable staging service requires every finalized blob's bee ref to be
	// EXACTLY 64 lowercase hex, while the shared in-memory document store (also
	// the resolver's Reader) returns arbitrary refs. So the object store is a
	// CONTENT-ADDRESSED wrapper that writes each payload into the shared
	// documents map under a sha256-hex key — valid for the durable service and
	// readable by the production verification path (docs) that finalizes a 201.
	storeSet := func(h *Handler) {
		objs := &contentAddressedStore{docs: docs}
		h.Uploader = objs
		h.Objects = objs
		h.Publisher.Objects = objs
	}

	build := func(store staging.RegistryStore) *Handler {
		h := NewHandler(
			resolve.RegistryResolver{
				Registries: resolve.StaticRegistryIdentityResolver{Hosts: map[string]resolve.RegistryIdentity{
					testServiceHost:     {Host: testServiceHost, Owner: "0xaliceowner"},
					"evil.example.test": {Host: "evil.example.test", Owner: "0xevilowner"},
				}},
				Docs:  docs,
				Feeds: feeds,
			},
			docs, docs,
			policy.PullAuthorizer{Policies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}},
			policy.PushAuthorizer{AuthPolicies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}, StampPolicies: policy.StampPolicyResolver{Docs: docs, Feeds: feeds}},
			BearerAuthenticator{Tokens: verifier},
			store,
			publish.Publisher{Builder: publish.DefaultBuilder{}, Objects: docs, Feeds: feeds},
			nil,
			"https://auth.uncloud-registry.com/token",
		).(*Handler)
		storeSet(h)
		return h
	}
	h1 = build(svc1)
	h2 = build(svc2)

	s1 := httptest.NewServer(h1)
	s2 := httptest.NewServer(h2)
	t.Cleanup(s1.Close)
	t.Cleanup(s2.Close)
	return h1, h2, svc1, svc2, docs, feeds, issuer, dbPath, s1.URL, s2.URL
}

// rawClaimedRows counts every publication-owned `claimed` row for the
// repo/actor directly in the shared DB — the introspection that proves a claim
// is retained or consumed when the request itself carries no operation id.
func rawClaimedRows(t *testing.T, dbPath, repo, actor string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open claimed: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(
		`select count(*) from upload_sessions u where u.repo = ? and u.actor = ? and u.state = 'claimed'`,
		repo, actor).Scan(&n); err != nil {
		t.Fatalf("count claimed: %v", err)
	}
	return n
}

// TestManifestPutCleanupWinsBeforeClaimFailsClosedThroughHandler proves
// interleaving (a) THROUGH THE REAL HANDLER: the handler lists the staged
// candidate, an independent cleanup then wins (unpins + removes the expired
// row) BEFORE the handler's atomic claim, and the manifest PUT fails closed
// (409 MANIFEST_CONFLICT, fixed data-free message) at the atomic claim with
// ZERO immutable-object writes and ZERO feed commits, and nothing claimed.
func TestManifestPutCleanupWinsBeforeClaimFailsClosedThroughHandler(t *testing.T) {
	h1, _, svc1, svc2, docs, feeds, issuer, dbPath, url1, _ := durableHandlerPair(t)
	committer := &generationCommitter{feeds: feeds, docs: docs}
	h1.Publisher.Commits = committer
	objects := &countingObjectUploader{inner: docs}
	h1.Publisher.Objects = objects

	configBytes := configFor("amd64")
	configDigest := stageBlob(t, url1, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	// Pause the real HTTP request at the atomic claim (after it has listed the
	// candidate), so cleanup deterministically wins in the window.
	atClaim := make(chan struct{})
	release := make(chan struct{})
	h1.Staging = &claimBarrierStaging{RegistryStore: svc1, atClaim: atClaim, release: release}

	type result struct {
		status int
		body   []byte
	}
	resCh := make(chan result, 1)
	go func() {
		resp := putManifestTag(t, url1, issuer, "latest", manifestBody)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		resCh <- result{resp.StatusCode, body}
	}()

	<-atClaim // handler has listed the candidate and is paused BEFORE its atomic claim

	// Independent cleanup over the SECOND durable service (same DB) wins, at an
	// eligibility the candidate now meets: the never-published blob is expired
	// and its ref is uncommitted, so cleanup claims, unpins, and removes it.
	unp := &recordingUnpinner{}
	clean, err := staging.NewCleanup(svc2, unp, emptyCommittedRefs{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := clean.RunOnce(context.Background(), time.Now().Add(2*time.Hour), 10)
	if err != nil {
		t.Fatalf("cleanup RunOnce: %v", err)
	}
	if res.Unpinned != 1 || res.Removed != 1 {
		t.Fatalf("cleanup-wins counts = %+v, want unpinned=1 removed=1", res)
	}
	if pins := unp.calls(); len(pins) != 1 {
		t.Fatalf("cleanup-wins unpin calls = %v, want exactly one", pins)
	}

	close(release)
	r := <-resCh
	if r.status != http.StatusConflict {
		t.Fatalf("claim-failed manifest PUT status = %d, want 409 (body %s)", r.status, r.body)
	}
	code, msg := decodeErrorPayload(t, r.body)
	if code != ErrorCodeManifestConflict || msg != messageClaimConflict {
		t.Fatalf("claim-failed manifest PUT = (%s, %q), want MANIFEST_CONFLICT / %q", code, msg, messageClaimConflict)
	}

	// Zero external writes: no immutable-object put, no feed commit, feed absent.
	if objects.puts != 0 {
		t.Fatalf("claim-failed publication performed %d immutable object writes, want 0", objects.puts)
	}
	if commits, conflicts := committer.count(); commits != 0 || conflicts != 0 {
		t.Fatalf("claim-failed publication must not commit, got commits=%d conflicts=%d", commits, conflicts)
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("claim-failed publication must not create the repo-state feed")
	}
	if n := rawClaimedRows(t, dbPath, "backend/api", "user:alice"); n != 0 {
		t.Fatalf("claim-failed publication left %d claimed rows, want 0", n)
	}
	live, err := svc1.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("cleanup-wins must leave no publishable row, got %+v", live)
	}
}

// TestManifestPutClaimWinsCleanupZeroUnpinsThroughHandler proves interleaving
// (b) THROUGH THE REAL HANDLER: the handler durably claims the staged blob and
// pauses before its external commit; an independent cleanup then runs at an
// eligibility the row would meet — yet unpins EXACTLY ZERO refs because the
// row is publication-owned. The publication completes, consumes exactly its
// own claim, and returns 201.
func TestManifestPutClaimWinsCleanupZeroUnpinsThroughHandler(t *testing.T) {
	h1, _, svc1, svc2, docs, feeds, issuer, _, url1, _ := durableHandlerPair(t)
	committer := &generationCommitter{feeds: feeds, docs: docs, gate: make(chan struct{}), blocked: make(chan struct{})}
	h1.Publisher.Commits = committer

	configBytes := configFor("amd64")
	configDigest := stageBlob(t, url1, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	type result struct {
		status int
		opID   string
		body   []byte
	}
	resCh := make(chan result, 1)
	go func() {
		resp := putManifestTag(t, url1, issuer, "latest", manifestBody)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		resCh <- result{resp.StatusCode, resp.Header.Get(OperationIDHeader), body}
	}()

	select {
	case <-committer.blocked: // the publication durably claimed and paused BEFORE its feed commit
	case <-time.After(5 * time.Second):
		t.Fatal("manifest PUT never reached the gated commit; the durable claim should already be held")
	}

	// Independent cleanup over the SECOND durable service (same DB) at an
	// eligibility the finished blob would otherwise meet: zero unpins, because
	// the row is claimed by the in-flight publication.
	unp := &recordingUnpinner{}
	clean, err := staging.NewCleanup(svc2, unp, emptyCommittedRefs{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := clean.RunOnce(context.Background(), time.Now().Add(2*time.Hour), 10)
	if err != nil {
		t.Fatalf("cleanup RunOnce: %v", err)
	}
	if res.Unpinned != 0 {
		t.Fatalf("cleanup must unpin ZERO publication-owned rows, res=%+v", res)
	}
	if pins := unp.calls(); len(pins) != 0 {
		t.Fatalf("cleanup unpinned a claimed ref: %v", pins)
	}

	close(committer.gate)
	r := <-resCh
	if r.status != http.StatusCreated {
		t.Fatalf("publication after claim-wins must return 201, got %d (body %s)", r.status, r.body)
	}
	if r.opID == "" {
		t.Fatal("201 must carry the operation identity header")
	}
	if commits, _ := committer.count(); commits != 1 {
		t.Fatalf("claim-wins publication must commit exactly once, got %d commits", commits)
	}
	state := loadRepoState(t, docs, feeds)
	if state.Generation != 1 {
		t.Fatalf("expected generation 1, got %d", state.Generation)
	}

	// The publication completed by consuming EXACTLY its own claim.
	owned, err := svc1.ClaimedDigests(context.Background(), "backend/api", "user:alice", r.opID)
	if err != nil {
		t.Fatalf("ClaimedDigests: %v", err)
	}
	if len(owned) != 0 {
		t.Fatalf("publication must consume its own claim, got %v", owned)
	}
	live, err := svc1.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("post-publication publishable rows = %+v, want none", live)
	}
	if pins := unp.calls(); len(pins) != 0 {
		t.Fatalf("consume/commit must never unpin, got %v", pins)
	}
}

// failNConsumeStaging fails the FIRST N ConsumeStagedForPublish calls it
// receives, then passes through to the underlying store — used to arm a
// deterministic sequence of interrupted consumptions.
type failNConsumeStaging struct {
	staging.RegistryStore
	remaining int64
	err       error
}

func (f *failNConsumeStaging) ConsumeStagedForPublish(ctx context.Context, repo, actor, operationID string, digests []string) error {
	if atomic.AddInt64(&f.remaining, -1) >= 0 {
		return f.err
	}
	return f.RegistryStore.ConsumeStagedForPublish(ctx, repo, actor, operationID, digests)
}

// TestRetryFastPathConsumeFailClosedThenRetrySucceeds proves the verified
// fast-path retry now FAILS CLOSED on a claim-consumption error instead of
// returning a spurious 201 that would strand a quota-charged claim forever.
// First the main attempt commits and verifies but its consume is interrupted
// (500, feed advanced, claim survives). The FIRST exact retry re-verifies but
// its consume fails again: it must return the sanitized 500 with ZERO new
// feed/object writes and the claim still retained. The SECOND exact retry
// consumes and returns the verified 201 with zero new external writes.
func TestRetryFastPathConsumeFailClosedThenRetrySucceeds(t *testing.T) {
	h, docs, feeds, issuer, serverURL := task14World(t)
	committer := &generationCommitter{feeds: feeds, docs: docs}
	h.Publisher.Commits = committer
	counters := &countingObjectUploader{inner: docs}
	h.Publisher.Objects = counters

	const marker = "INJECTED_CONSUME_FAIL_9f2b"
	consume := &failNConsumeStaging{RegistryStore: h.Staging, remaining: 2, err: errors.New(marker)}
	h.Staging = consume
	ms := consume.RegistryStore.(*staging.MemoryStore)

	configBytes := configFor("amd64")
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	// Attempt 1 (main path): commit + verify succeed, then the consume is
	// interrupted -> 500, feed advanced, the publication-owned claim survives.
	first := putManifestTag(t, serverURL, issuer, "latest", manifestBody)
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusInternalServerError {
		t.Fatalf("interrupted main-path consume must surface 500, got %d (%s)", first.StatusCode, firstBody)
	}
	if bytes.Contains(firstBody, []byte(marker)) {
		t.Fatalf("500 echoes injected consume marker: %s", firstBody)
	}
	code, msg := decodeErrorPayload(t, firstBody)
	if code != ErrorCodeInternal || msg != messageUnknown {
		t.Fatalf("interrupted consume error surface = (%s, %q), want (UNKNOWN, internal error)", code, msg)
	}
	feedRefAfterFirst := feeds.Feeds[repoStateFeed()]
	if feedRefAfterFirst == "" {
		t.Fatal("verified publication must have advanced the feed")
	}
	putsAfterFirst := counters.puts
	if claimed := ms.ClaimedStagedBlobs(context.Background(), "backend/api", "user:alice"); len(claimed) != 1 {
		t.Fatalf("interrupted main-path consume must retain the claim, got %+v", claimed)
	}

	// Retry A (fast path): re-verifies, but its consume FAILS CLOSED -> 500, the
	// claim is retained, and there are ZERO new external writes.
	ra := putManifestTag(t, serverURL, issuer, "latest", manifestBody)
	raBody, _ := io.ReadAll(ra.Body)
	ra.Body.Close()
	if ra.StatusCode != http.StatusInternalServerError {
		t.Fatalf("fast-path consume failure must FAIL CLOSED with 500, got %d (%s)", ra.StatusCode, raBody)
	}
	if bytes.Contains(raBody, []byte(marker)) {
		t.Fatalf("500 echoes injected consume marker on retry: %s", raBody)
	}
	raCode, raMsg := decodeErrorPayload(t, raBody)
	if raCode != ErrorCodeInternal || raMsg != messageUnknown {
		t.Fatalf("fast-path consume-fail error surface = (%s, %q), want (UNKNOWN, internal error)", raCode, raMsg)
	}
	if feeds.Feeds[repoStateFeed()] != feedRefAfterFirst {
		t.Fatal("failed fast-path retry must not advance the feed")
	}
	if c, _ := committer.count(); c != 1 {
		t.Fatalf("failed fast-path retry must not commit again, got %d commits", c)
	}
	if counters.puts != putsAfterFirst {
		t.Fatalf("failed fast-path retry performed %d new object writes, want 0 (was %d)", counters.puts-putsAfterFirst, putsAfterFirst)
	}
	if claimed := ms.ClaimedStagedBlobs(context.Background(), "backend/api", "user:alice"); len(claimed) != 1 {
		t.Fatalf("failed fast-path retry must retain the claim, got %+v (want the surviving claim)", claimed)
	}

	// Retry B (exact retry): re-verifies and its consume SUCCEEDS -> verified 201
	// with zero new external writes, and the surviving claim is consumed.
	rb := putManifestTag(t, serverURL, issuer, "latest", manifestBody)
	rbBody, _ := io.ReadAll(rb.Body)
	opID := rb.Header.Get(OperationIDHeader)
	rb.Body.Close()
	if rb.StatusCode != http.StatusCreated {
		t.Fatalf("exact retry must consume and return verified 201, got %d (%s)", rb.StatusCode, rbBody)
	}
	if opID == "" {
		t.Fatal("verified 201 must carry the operation identity")
	}
	if feeds.Feeds[repoStateFeed()] != feedRefAfterFirst {
		t.Fatal("verified 201 retry must not advance the feed")
	}
	if c, _ := committer.count(); c != 1 {
		t.Fatalf("verified 201 retry must not commit again, got %d commits", c)
	}
	if counters.puts != putsAfterFirst {
		t.Fatalf("verified 201 retry performed %d new object writes, want 0 (was %d)", counters.puts-putsAfterFirst, putsAfterFirst)
	}
	if claimed := ms.ClaimedStagedBlobs(context.Background(), "backend/api", "user:alice"); len(claimed) != 0 {
		t.Fatalf("verified 201 retry must consume its own surviving claim, got %+v", claimed)
	}
	if live, err := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice"); err != nil || len(live) != 0 {
		t.Fatalf("post-consumption publishable rows = %+v (err %v), want none", live, err)
	}
}
