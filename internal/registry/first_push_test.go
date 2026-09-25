package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/staging"
)

// newFirstPushWorld assembles a handler whose registry has AUTH and STAMP
// feeds only — the repository feed for backend/api is deliberately ABSENT
// (generation zero, no pre-seeded repository feed or object).
func newFirstPushWorld(t *testing.T) (*Handler, *resolve.MemoryDocumentStore, *resolve.MemoryFeedStore, *auth.RegistryTokenIssuer) {
	t.Helper()
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
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

	handler, issuer := newTestHandler(t, docs, feeds)
	return handler.(*Handler), docs, feeds, issuer
}

// repoStateFeed is the deterministic repo-state feed for the fixture registry.
func repoStateFeed() string { return spec.RepoStateFeedRef("0xaliceowner", "backend/api") }

// pushTo sets Host + push bearer on a request.
func pushTo(t *testing.T, req *http.Request, issuer *auth.RegistryTokenIssuer) {
	t.Helper()
	req.Host = testServiceHost
	req.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPush}, time.Hour))
}

// stageBlob drives the full upload lifecycle (start, patch, finalize) for one
// blob and returns its digest.
func stageBlob(t *testing.T, serverURL string, issuer *auth.RegistryTokenIssuer, body []byte, contentType string) string {
	t.Helper()
	digest := publish.ComputeDigest(body)

	startReq, err := http.NewRequest(http.MethodPost, serverURL+"/v2/backend/api/blobs/uploads/", nil)
	if err != nil {
		t.Fatalf("create start upload: %v", err)
	}
	pushTo(t, startReq, issuer)
	startResp, err := http.DefaultClient.Do(startReq)
	if err != nil {
		t.Fatalf("start upload: %v", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusAccepted {
		t.Fatalf("start upload status: %d", startResp.StatusCode)
	}
	uploadURL := serverURL + startResp.Header.Get("Location")

	patchReq, err := http.NewRequest(http.MethodPatch, uploadURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create patch: %v", err)
	}
	pushTo(t, patchReq, issuer)
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
	pushTo(t, finalizeReq, issuer)
	if contentType != "" {
		finalizeReq.Header.Set("Content-Type", contentType)
	}
	finalizeResp, err := http.DefaultClient.Do(finalizeReq)
	if err != nil {
		t.Fatalf("finalize upload: %v", err)
	}
	defer finalizeResp.Body.Close()
	if finalizeResp.StatusCode != http.StatusCreated {
		t.Fatalf("finalize upload status: %d", finalizeResp.StatusCode)
	}
	return digest
}

// putManifest PUTs a manifest body and returns the response.
func putManifest(t *testing.T, serverURL string, issuer *auth.RegistryTokenIssuer, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create manifest request: %v", err)
	}
	pushTo(t, req, issuer)
	req.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("manifest publish request failed: %v", err)
	}
	return resp
}

// loadRepoState resolves the repo-state feed and decodes its document.
func loadRepoState(t *testing.T, docs *resolve.MemoryDocumentStore, feeds *resolve.MemoryFeedStore) spec.RepoStateDocument {
	t.Helper()
	ref, ok := feeds.Feeds[repoStateFeed()]
	if !ok {
		t.Fatal("repo-state feed was not created")
	}
	data, err := docs.Get(context.Background(), ref)
	if err != nil {
		t.Fatalf("read repo state doc: %v", err)
	}
	doc, err := spec.DecodeRepoStateDocument(data)
	if err != nil {
		t.Fatalf("decode repo state doc: %v", err)
	}
	return doc
}

// countingObjectUploader counts immutable object writes so zero-write
// assertions can be made at the exact publish boundary.
type countingObjectUploader struct {
	inner publish.ObjectUploader
	puts  int
}

func (c *countingObjectUploader) Put(ctx context.Context, data []byte, batchID string) (string, error) {
	c.puts++
	return c.inner.Put(ctx, data, batchID)
}

// TestFirstPushUnseededRepositoryPublishesGenerationOne is the full unseeded
// first push: registry root/auth/stamp ready, repository feed ABSENT,
// referenced blob staged, PUT manifest → 201, generation-one state, correct
// tag, EXACTLY the referenced blob, and manifest + blob pulls succeed.
func TestFirstPushUnseededRepositoryPublishesGenerationOne(t *testing.T) {
	t.Parallel()

	h, docs, feeds, issuer := newFirstPushWorld(t)
	server := httptest.NewServer(h)
	defer server.Close()

	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("fixture must start with NO repository feed")
	}

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, server.URL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")

	manifestBody := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":` + fmt.Sprintf("%d", len(configBytes)) + `,"digest":"` + configDigest + `"},"layers":[]}`)
	resp := putManifest(t, server.URL, issuer, manifestBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("first push status %d, want 201 (body %s)", resp.StatusCode, body)
	}

	state := loadRepoState(t, docs, feeds)
	if state.Version != 1 || state.Repo != "backend/api" {
		t.Fatalf("unexpected state identity: %+v", state)
	}
	if state.Generation != 1 {
		t.Fatalf("expected generation 1, got %d", state.Generation)
	}
	manifestDigest := publish.ComputeDigest(manifestBody)
	if state.Tags["latest"] != manifestDigest {
		t.Fatalf("tag did not point at the manifest: %+v", state.Tags)
	}
	if len(state.Blobs) != 1 || state.Blobs[configDigest].Size != int64(len(configBytes)) {
		t.Fatalf("state must contain EXACTLY the referenced blob, got %+v", state.Blobs)
	}
	man, ok := state.Manifests[manifestDigest]
	if !ok || man.MediaType != "application/vnd.oci.image.manifest.v1+json" || man.Size != int64(len(manifestBody)) {
		t.Fatalf("manifest descriptor not recorded: %+v", state.Manifests)
	}

	// Pull the manifest by tag.
	getReq, _ := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	getReq.Host = testServiceHost
	getReq.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour))
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("manifest pull: %v", err)
	}
	defer getResp.Body.Close()
	body, _ := io.ReadAll(getResp.Body)
	if getResp.StatusCode != http.StatusOK || !bytes.Equal(body, manifestBody) {
		t.Fatalf("manifest pull status=%d body=%q", getResp.StatusCode, body)
	}

	// Pull the blob by digest.
	blobReq, _ := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/blobs/"+configDigest, nil)
	blobReq.Host = testServiceHost
	blobReq.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour))
	blobResp, err := http.DefaultClient.Do(blobReq)
	if err != nil {
		t.Fatalf("blob pull: %v", err)
	}
	defer blobResp.Body.Close()
	blobBody, _ := io.ReadAll(blobResp.Body)
	if blobResp.StatusCode != http.StatusOK || !bytes.Equal(blobBody, configBytes) {
		t.Fatalf("blob pull status=%d body=%q", blobResp.StatusCode, blobBody)
	}
}

// TestManifestPublishesOnlyReferencedStagedBlobs stages TWO blobs A and B,
// submits a manifest that references A only, and proves the published state
// contains A but NOT B, while B remains staged (unrelated staged blobs are
// neither published nor cleared).
func TestManifestPublishesOnlyReferencedStagedBlobs(t *testing.T) {
	t.Parallel()

	h, docs, feeds, issuer := newFirstPushWorld(t)
	server := httptest.NewServer(h)
	defer server.Close()

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, server.URL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	unrelatedBytes := []byte("unrelated-staged-blob")
	unrelatedDigest := stageBlob(t, server.URL, issuer, unrelatedBytes, "application/octet-stream")

	manifestBody := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":` + fmt.Sprintf("%d", len(configBytes)) + `,"digest":"` + configDigest + `"},"layers":[]}`)
	resp := putManifest(t, server.URL, issuer, manifestBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("publish status %d, want 201 (body %s)", resp.StatusCode, body)
	}

	state := loadRepoState(t, docs, feeds)
	if _, ok := state.Blobs[configDigest]; !ok {
		t.Fatalf("referenced staged blob A must be published: %+v", state.Blobs)
	}
	if _, ok := state.Blobs[unrelatedDigest]; ok {
		t.Fatalf("unrelated staged blob B must NOT enter repository state: %+v", state.Blobs)
	}

	// B must remain staged for the actor/repo.
	remaining, err := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Digest != unrelatedDigest {
		t.Fatalf("only the unrelated staged blob B must remain staged, got %+v", remaining)
	}
}

// TestFirstPushWithExistingStateRetainsReferencedBlobs seeds an existing repo
// state with a published blob and pushes a manifest that references BOTH the
// existing blob (no re-stage) and a newly staged blob: both appear in the new
// state, the existing blob keeps its authoritative current record, and the
// newly staged blob is consumed.
func TestFirstPushWithExistingStateRetainsReferencedBlobs(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	existing := "sha256:" + strings.Repeat("f", 64)
	existingManifest := "sha256:" + strings.Repeat("e", 64)
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
	docs.Documents["repo-state-ref"] = []byte(`{
		"version":1,
		"repo":"backend/api",
		"generation":3,
		"updatedAt":"2026-04-05T12:00:00Z",
		"tags":{"latest":"` + existingManifest + `"},
		"manifests":{"` + existingManifest + `":{"swarmRef":"manifest-ref","mediaType":"application/vnd.oci.image.manifest.v1+json","size":19}},
		"blobs":{"` + existing + `":{"swarmRef":"blob-ref","size":10,"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip"}}
	}`)
	feeds.Feeds[repoStateFeed()] = "repo-state-ref"

	handler, issuer := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	configBytes := []byte(`{"architecture":"arm64"}`)
	configDigest := stageBlob(t, server.URL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")

	manifestBody := []byte(`{"schemaVersion":2,` +
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":` + fmt.Sprintf("%d", len(configBytes)) + `,"digest":"` + configDigest + `"},` +
		`"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","size":10,"digest":"` + existing + `"}]}`)
	resp := putManifest(t, server.URL, issuer, manifestBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("publish status %d, want 201 (body %s)", resp.StatusCode, body)
	}

	state := loadRepoState(t, docs, feeds)
	if got := state.Blobs[existing]; got.SwarmRef != "blob-ref" || got.Size != 10 {
		t.Fatalf("existing referenced blob must be retained with its current record: %+v", got)
	}
	if got := state.Blobs[configDigest]; got.Size != int64(len(configBytes)) {
		t.Fatalf("newly staged referenced blob must be published: %+v", state.Blobs)
	}
}

// TestFirstPushMissingReferenceZeroWrites proves a manifest referencing a blob
// that is neither in current state nor staged fails TYPED (400) with ZERO
// object writes, ZERO feed updates, and staging unchanged.
func TestFirstPushMissingReferenceZeroWrites(t *testing.T) {
	t.Parallel()

	h, docs, feeds, issuer := newFirstPushWorld(t)
	counter := &countingObjectUploader{inner: docs}
	h.Publisher.Objects = counter
	server := httptest.NewServer(h)
	defer server.Close()

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, server.URL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	missing := "sha256:" + strings.Repeat("b", 64)

	manifestBody := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":` + fmt.Sprintf("%d", len(configBytes)) + `,"digest":"` + configDigest + `"},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","size":7,"digest":"` + missing + `"}]}`)
	resp := putManifest(t, server.URL, issuer, manifestBody)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing reference must be a 400, got %d (body %s)", resp.StatusCode, body)
	}

	if counter.puts != 0 {
		t.Fatalf("missing reference caused %d object writes, want 0", counter.puts)
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("missing reference must not create or update the repo-state feed")
	}
	remaining, err := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Digest != configDigest {
		t.Fatalf("staging must be unchanged by a failed publication, got %+v", remaining)
	}
}

// TestUnauthorizedFirstPushZeroWrites proves an unauthenticated manifest PUT on
// an unseeded repository creates NO state, NO feed, and NO staging sessions.
func TestUnauthorizedFirstPushZeroWrites(t *testing.T) {
	t.Parallel()

	h, _, feeds, _ := newFirstPushWorld(t)
	stage := &countingStaging{RegistryStore: staging.NewMemoryStore()}
	h.Staging = stage
	server := httptest.NewServer(h)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPut, server.URL+"/v2/backend/api/manifests/latest", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = testServiceHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("unauthorized first push created the repo-state feed")
	}
	if stage.created != 0 {
		t.Fatalf("unauthorized first push created %d staging sessions", stage.created)
	}
}

// TestPullBeforeFirstPushDoesNotSynthesizeState proves pull/resolution paths
// NEVER synthesize missing state: an authorized pull of an unseeded repository
// is a 404 and leaves no feed/document behind.
func TestPullBeforeFirstPushDoesNotSynthesizeState(t *testing.T) {
	t.Parallel()

	h, docs, feeds, issuer := newFirstPushWorld(t)
	server := httptest.NewServer(h)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = testServiceHost
	req.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("pull of an unseeded repository must be 404, got %d", resp.StatusCode)
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("pull must not create the repo-state feed")
	}
	if len(docs.Documents) != 2 { // only the seeded auth + stamp policy docs
		t.Fatalf("pull must not synthesize documents, got %d docs", len(docs.Documents))
	}
}

// TestFirstPushErrorIsTypedAndDataFree proves the malformed-manifest 400
// carries the stable MANIFEST_INVALID error code and never echoes
// attacker-controlled body detail (unknown-member key as marker).
func TestFirstPushErrorIsTypedAndDataFree(t *testing.T) {
	t.Parallel()

	const marker = "MARKERATTACKER_T13_9f2b"
	h, _, _, issuer := newFirstPushWorld(t)
	server := httptest.NewServer(h)
	defer server.Close()

	manifestBody := []byte(`{"schemaVersion":2,` + fmt.Sprintf("%q", marker) + `:1,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":24,"digest":"` + "sha256:" + strings.Repeat("a", 64) + `"},"layers":[]}`)
	resp := putManifest(t, server.URL, issuer, manifestBody)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed manifest must be 400, got %d", resp.StatusCode)
	}
	if bytes.Contains(body, []byte(marker)) {
		t.Fatalf("400 response echoes attacker marker: %s", body)
	}
	var payload struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode error payload: %v (%s)", err, body)
	}
	if len(payload.Errors) != 1 || payload.Errors[0].Code != "MANIFEST_INVALID" {
		t.Fatalf("expected stable MANIFEST_INVALID error code, got %+v", payload.Errors)
	}
}

// staleFeedUpdater models a signer that reports success while the effective
// feed settles on a DIFFERENT (stale) reference than the committed one — the
// exact read-after-write hazard the verification gate must fail closed on.
type staleFeedUpdater struct {
	inner publish.FeedUpdater
}

func (s staleFeedUpdater) UpdateFeed(ctx context.Context, feed string, ref string) error {
	return s.inner.UpdateFeed(ctx, feed, "stale-ref-"+ref)
}

// TestManifestPutStaleFeedReadBackFailsClosed502 proves the read-after-write
// gate end to end: a reported commit success whose EFFECTIVE feed read-back
// does not resolve to the exact committed state reference is a 502
// PUBLICATION_UNVERIFIED, and the referenced staging is retained for a safe
// retry — a 201 is only ever produced after exact verification.
func TestManifestPutStaleFeedReadBackFailsClosed502(t *testing.T) {
	t.Parallel()

	h, _, feeds, issuer := newFirstPushWorld(t)
	h.Publisher.Feeds = staleFeedUpdater{inner: feeds}
	server := httptest.NewServer(h)
	defer server.Close()

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, server.URL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":` +
		fmt.Sprintf("%d", len(configBytes)) + `,"digest":"` + configDigest + `"},"layers":[]}`)
	resp := putManifest(t, server.URL, issuer, manifestBody)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("stale feed read-back must fail closed with 502, got %d (body %s)", resp.StatusCode, body)
	}
	code, _ := decodeErrorPayload(t, body)
	if code != ErrorCodePublicationUnverified {
		t.Fatalf("expected PUBLICATION_UNVERIFIED code, got %q (body %s)", code, body)
	}
	remaining, err := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Digest != configDigest {
		t.Fatalf("verification failure must retain the referenced staging for retry, got %+v", remaining)
	}
}
