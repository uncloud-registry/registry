package registry

// Task 18 round-1 correction: a verified publication retried by ANOTHER
// authorized actor must finish consuming the ORIGINAL actor's surviving
// claims. Previously the fast-path consume was scoped by the retrying
// principal, so Bob's exact retry of a publication Alice claimed and committed
// (but crashed before consuming) got a fast-path 201 while Alice's durable
// claim/goal forever charged quota. This test drives the real handler over two
// independent durable staging services sharing one DB, with two authorized
// actors, and proves Bob's retry releases Alice's original claim + quota with
// ZERO new object/feed writes, clears no foreign claim, and stays fail-closed.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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

// twoActorDurableWorld builds two independent registry handlers owning
// SEPARATE durable staging services over the SAME staging directory/DB, with
// BOTH user:alice and user:bob authorized to push. This is the exact two-
// process topology where the fast-path retry must consume the original
// actor's surviving claim.
func twoActorDurableWorld(t *testing.T) (h1, h2 *Handler, svc1, svc2 staging.RegistryStore, docs *resolve.MemoryDocumentStore, feeds *resolve.MemoryFeedStore, issuer *auth.RegistryTokenIssuer, dbPath, url1, url2 string) {
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
		"repos":{"backend/api":{"pull":["user:alice","user:bob"],"push":["user:alice","user:bob"]}}
	}`)
	docs.Documents["stamp-policy-ref"] = []byte(`{
		"version":1,
		"defaultPolicy":{"batchID":"batch-default","allowPushFor":["user:alice","user:bob"]},
		"repos":{"backend/api":{"batchID":"batch-repo","allowPushFor":["user:alice","user:bob"]}}
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
					testServiceHost: {Host: testServiceHost, Owner: "0xaliceowner"},
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

// pushToAs signs a push token for an explicit subject.
func pushToAs(t *testing.T, req *http.Request, issuer *auth.RegistryTokenIssuer, subject string) {
	t.Helper()
	req.Host = testServiceHost
	req.Header.Set("Authorization",
		registryBearer(t, issuer, subject, testServiceHost, "backend/api", []auth.Action{auth.ActionPush}, time.Hour))
}

// putManifestAs issues a manifest PUT (no explicit key) authenticated as the
// given subject.
func putManifestAs(t *testing.T, url string, issuer *auth.RegistryTokenIssuer, subject string, tag string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url+"/v2/backend/api/manifests/"+tag, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create manifest request: %v", err)
	}
	pushToAs(t, req, issuer, subject)
	req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("manifest publish (subject %s) failed: %v", subject, err)
	}
	return resp
}

// stageBlobAs drives the full upload lifecycle for one blob authenticated as
// the given subject and returns its manifest digest. Mirrors stageBlob exactly
// except for the signed subject.
func stageBlobAs(t *testing.T, url string, issuer *auth.RegistryTokenIssuer, subject string, body []byte, contentType string) string {
	t.Helper()
	digest := publish.ComputeDigest(body)

	startReq, err := http.NewRequest(http.MethodPost, url+"/v2/backend/api/blobs/uploads/", nil)
	if err != nil {
		t.Fatalf("create start upload: %v", err)
	}
	pushToAs(t, startReq, issuer, subject)
	startResp, err := http.DefaultClient.Do(startReq)
	if err != nil {
		t.Fatalf("start upload: %v", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusAccepted {
		t.Fatalf("start upload status: %d", startResp.StatusCode)
	}
	uploadURL := url + startResp.Header.Get("Location")

	patchReq, err := http.NewRequest(http.MethodPatch, uploadURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create patch: %v", err)
	}
	pushToAs(t, patchReq, issuer, subject)
	patchResp, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("patch upload: %v", err)
	}
	patchResp.Body.Close()
	if patchResp.StatusCode != http.StatusAccepted {
		t.Fatalf("patch upload status: %d", patchResp.StatusCode)
	}

	finalizeReq, err := http.NewRequest(http.MethodPut, uploadURL+"?digest="+digest, nil)
	if err != nil {
		t.Fatalf("create finalize: %v", err)
	}
	pushToAs(t, finalizeReq, issuer, subject)
	if contentType != "" {
		finalizeReq.Header.Set("Content-Type", contentType)
	}
	finalizeResp, err := http.DefaultClient.Do(finalizeReq)
	if err != nil {
		t.Fatalf("finalize upload: %v", err)
	}
	defer finalizeResp.Body.Close()
	if finalizeResp.StatusCode != http.StatusCreated {
		t.Fatalf("finalize upload status = %d", finalizeResp.StatusCode)
	}
	return digest
}

// foreignClaimOnService durably claims a SECOND blob under `op` by `actor`
// directly on a durable service (no HTTP round needed).
func foreignClaimOnService(t *testing.T, svc staging.RegistryStore, repo, actor, op string, digest string) {
	t.Helper()
	if _, err := svc.ClaimStagedForPublish(context.Background(), repo, actor, op, []string{digest}); err != nil {
		t.Fatalf("foreign claim (%s/%s/%s): %v", actor, op, digest, err)
	}
}

// oneFailConsumeStaging fails the FIRST ConsumeStagedForPublish call (the main
// path's post-verify consume) then passes through — modelling Alice's crash
// immediately after verify, leaving her durable claim.
type oneFailConsumeStaging struct {
	staging.RegistryStore
	remaining int64
	err       error
}

func (f *oneFailConsumeStaging) ConsumeStagedForPublish(ctx context.Context, repo, actor, operationID string, digests []string) error {
	if atomic.AddInt64(&f.remaining, -1) >= 0 {
		return f.err
	}
	return f.RegistryStore.ConsumeStagedForPublish(ctx, repo, actor, operationID, digests)
}

// TestRetryByOtherAuthorizedActorReleasesOriginalClaim proves Alice's commit
// verifies but crashes before consume; Bob (a different authorized actor)
// issues the exact no-key retry, gets the fast-path verified 201, AND releases
// Alice's original durable claim + quota — with ZERO new object/feed writes,
// no foreign claim cleared, and consume failures still fail closed.
func TestRetryByOtherAuthorizedActorReleasesOriginalClaim(t *testing.T) {
	h1, h2, svc1, svc2, docs, feeds, issuer, dbPath, url1, url2 := twoActorDurableWorld(t)
	committer := &generationCommitter{feeds: feeds, docs: docs}
	// h1.Publisher uses the same committer; object uploads counted.
	objects := &countingObjectUploader{inner: h1.Publisher.Objects}
	h1.Publisher.Commits = committer
	h1.Publisher.Objects = objects
	h2.Publisher.Commits = committer

	// Alice stages the config blob that the manifest will reference.
	configBytes := configFor("amd64")
	configDigest := stageBlobAs(t, url1, issuer, "user:alice", configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	// Alice's FIRST publish: commit + verify succeed, then the post-verify
	// consume is interrupted -> 500. Her durable claim (op-publication) survives.
	h1.Staging = &oneFailConsumeStaging{RegistryStore: svc1, remaining: 1, err: errors.New("INJECTED_CONSUME_FAIL_9f2b")}
	first := putManifestAs(t, url1, issuer, "user:alice", "latest", manifestBody)
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusInternalServerError {
		t.Fatalf("alice interrupted consume must surface 500, got %d (%s)", first.StatusCode, firstBody)
	}
	if n := rawClaimedRows(t, dbPath, "backend/api", "user:alice"); n != 1 {
		t.Fatalf("alice claim must survive her interrupted consume, got %d claimed rows", n)
	}
	feedRef := feeds.Feeds[repoStateFeed()]
	if feedRef == "" {
		t.Fatal("alice's verified publication must have advanced the feed")
	}
	commitsAfterFirst, _ := committer.count()
	putsAfterFirst := objects.puts

	// A FOREIGN claim (op=<other>, bob, different digest) that Bob's retry must
	// NEVER clear. Bio staging as bob, then claim directly.
	foreignBytes := configFor("arm64")
	foreignDigest := stageBlobAs(t, url2, issuer, "user:bob", foreignBytes, "application/vnd.oci.image.config.v1+json")
	foreignClaimOnService(t, svc2, "backend/api", "user:bob", "foreign-op", foreignDigest)
	if n := rawClaimedRows(t, dbPath, "backend/api", "user:bob"); n != 1 {
		t.Fatalf("foreign claim setup failed, bob claimed rows = %d", n)
	}

	// Bob issues the EXACT no-key retry of Alice's publication. FIRST Bob's
	// consume is injected to fail: the fast-path must FAIL CLOSED (500, fixed
	// data-free message, no feed/object commit) and RETAIN Alice's claim.
	const marker = "INJECTED_CONSUME_FAIL_9f2b"
	h2.Staging = &failNConsumeStaging{RegistryStore: svc2, remaining: 1, err: errors.New(marker)}
	r1 := putManifestAs(t, url2, issuer, "user:bob", "latest", manifestBody)
	r1Body, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	if r1.StatusCode != http.StatusInternalServerError {
		t.Fatalf("bob's fast-path consume failure must FAIL CLOSED with 500, got %d (%s)", r1.StatusCode, r1Body)
	}
	if bytes.Contains(r1Body, []byte(marker)) {
		t.Fatalf("500 echoes injected consume marker on bob's retry: %s", r1Body)
	}
	if code, msg := decodeErrorPayload(t, r1Body); code != ErrorCodeInternal || msg != messageUnknown {
		t.Fatalf("bob's failed retry error surface = (%s, %q), want (UNKNOWN, internal error)", code, msg)
	}
	if n := rawClaimedRows(t, dbPath, "backend/api", "user:alice"); n != 1 {
		t.Fatalf("failed bob retry must retain alice's claim, alice claimed rows = %d (want 1)", n)
	}
	if feeds.Feeds[repoStateFeed()] != feedRef {
		t.Fatal("failed bob fast-path retry must not advance the feed")
	}
	if c, _ := committer.count(); c != commitsAfterFirst {
		t.Fatalf("failed bob retry committed again: %d commits (want %d)", c, commitsAfterFirst)
	}
	if objects.puts != putsAfterFirst {
		t.Fatalf("failed bob retry performed %d new object writes (want 0)", objects.puts-putsAfterFirst)
	}

	// Bob's SECOND exact retry (consume now succeeds): the verified 201 MUST be
	// returned AND ALICE'S ORIGINAL CLAIM + QUOTA RELEASED.
	h2.Staging = svc2
	rb := putManifestAs(t, url2, issuer, "user:bob", "latest", manifestBody)
	rbBody, _ := io.ReadAll(rb.Body)
	opID := rb.Header.Get(OperationIDHeader)
	rb.Body.Close()
	if rb.StatusCode != http.StatusCreated {
		t.Fatalf("bob's exact retry must return verified 201, got %d (%s)", rb.StatusCode, rbBody)
	}
	if opID == "" {
		t.Fatal("verified 201 must carry the operation identity")
	}

	// ALICE'S ORIGINAL CLAIM AND QUOTA MUST BE RELEASED.
	if n := rawClaimedRows(t, dbPath, "backend/api", "user:alice"); n != 0 {
		t.Fatalf("bob's retry must release alice's original claim, %d alice claimed rows remain", n)
	}
	// A foreign claim (different operation) is never cleared.
	if n := rawClaimedRows(t, dbPath, "backend/api", "user:bob"); n != 1 {
		t.Fatalf("bob's retry cleared a foreign claim (bob/foreign-op), bob claimed rows = %d (want 1)", n)
	}

	// ZERO new external writes across the whole retry sequence: no feed advance,
	// no object put, no commit.
	if feeds.Feeds[repoStateFeed()] != feedRef {
		t.Fatal("bob's fast-path retry must not advance the feed")
	}
	if c, _ := committer.count(); c != commitsAfterFirst {
		t.Fatalf("bob's fast-path retry committed again: %d commits (want %d)", c, commitsAfterFirst)
	}
	if objects.puts != putsAfterFirst {
		t.Fatalf("bob's fast-path retry performed %d new object writes (want 0, was %d)", objects.puts-putsAfterFirst, putsAfterFirst)
	}

	// Consumed clean: no publishable rows remain for alice's repo.
	live, err := h1.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("post-retry publishable rows = %+v, want none", live)
	}
}
