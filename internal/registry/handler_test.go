package registry

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/policy"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/staging"
)

func TestManifestAndBlobPullViaRepoState(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)
	docs.Documents["manifest-ref"] = []byte(`{"schemaVersion":2}`)
	docs.Documents["blob-ref"] = []byte("blob-bytes")

	handler := newTestHandler(docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	manifestReq, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create manifest request: %v", err)
	}
	manifestReq.Host = "alice.uncloud-registry.com"

	manifestResp, err := http.DefaultClient.Do(manifestReq)
	if err != nil {
		t.Fatalf("manifest request failed: %v", err)
	}
	defer manifestResp.Body.Close()

	if manifestResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected manifest status: %d", manifestResp.StatusCode)
	}

	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(manifestResp.Body); err != nil {
		t.Fatalf("read manifest body: %v", err)
	}
	if got := body.String(); got != `{"schemaVersion":2}` {
		t.Fatalf("unexpected manifest body: %s", got)
	}

	blobReq, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/blobs/sha256:blob1", nil)
	if err != nil {
		t.Fatalf("create blob request: %v", err)
	}
	blobReq.Host = "alice.uncloud-registry.com"

	blobResp, err := http.DefaultClient.Do(blobReq)
	if err != nil {
		t.Fatalf("blob request failed: %v", err)
	}
	defer blobResp.Body.Close()

	if blobResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected blob status: %d", blobResp.StatusCode)
	}
}

func TestPullRequiresAuthWhenAnonymousNotAllowed(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)
	docs.Documents["auth-policy-ref"] = []byte(`{
		"version":1,
		"defaultAccess":"deny",
		"repos":{"backend/api":{"pull":["user:alice"],"push":["user:alice"]}}
	}`)

	handler := newTestHandler(docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = "alice.uncloud-registry.com"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	if challenge := resp.Header.Get("WWW-Authenticate"); challenge == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestAuthenticatedPullAllowedByPolicy(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)
	docs.Documents["auth-policy-ref"] = []byte(`{
		"version":1,
		"defaultAccess":"deny",
		"repos":{"backend/api":{"pull":["user:alice"],"push":["user:alice"]}}
	}`)

	handler := newTestHandler(docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = "alice.uncloud-registry.com"
	req.Header.Set("Authorization", "Bearer user:alice")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
}

func TestPushBlobAndPublishManifest(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler := newTestHandler(docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	startReq, err := http.NewRequest(http.MethodPost, server.URL+"/v2/backend/api/blobs/uploads/", nil)
	if err != nil {
		t.Fatalf("create start upload request: %v", err)
	}
	startReq.Host = "alice.uncloud-registry.com"
	startReq.Header.Set("Authorization", "Bearer user:alice")

	startResp, err := http.DefaultClient.Do(startReq)
	if err != nil {
		t.Fatalf("start upload request failed: %v", err)
	}
	defer startResp.Body.Close()

	if startResp.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected start upload status: %d", startResp.StatusCode)
	}

	uploadURL := server.URL + startResp.Header.Get("Location")
	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := publish.ComputeDigest(configBytes)

	patchReq, err := http.NewRequest(http.MethodPatch, uploadURL, bytes.NewReader(configBytes))
	if err != nil {
		t.Fatalf("create patch request: %v", err)
	}
	patchReq.Host = "alice.uncloud-registry.com"
	patchReq.Header.Set("Authorization", "Bearer user:alice")

	patchResp, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("patch request failed: %v", err)
	}
	defer patchResp.Body.Close()

	if patchResp.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected patch status: %d", patchResp.StatusCode)
	}

	finalizeReq, err := http.NewRequest(http.MethodPut, uploadURL+"?digest="+configDigest, nil)
	if err != nil {
		t.Fatalf("create finalize request: %v", err)
	}
	finalizeReq.Host = "alice.uncloud-registry.com"
	finalizeReq.Header.Set("Authorization", "Bearer user:alice")
	finalizeReq.Header.Set("Content-Type", "application/vnd.oci.image.config.v1+json")

	finalizeResp, err := http.DefaultClient.Do(finalizeReq)
	if err != nil {
		t.Fatalf("finalize request failed: %v", err)
	}
	defer finalizeResp.Body.Close()

	if finalizeResp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected finalize status: %d", finalizeResp.StatusCode)
	}

	manifestBody := []byte(`{
		"schemaVersion":2,
		"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":24,"digest":"` + configDigest + `"},
		"layers":[]
	}`)

	manifestReq, err := http.NewRequest(http.MethodPut, server.URL+"/v2/backend/api/manifests/latest", bytes.NewReader(manifestBody))
	if err != nil {
		t.Fatalf("create manifest request: %v", err)
	}
	manifestReq.Host = "alice.uncloud-registry.com"
	manifestReq.Header.Set("Authorization", "Bearer user:alice")
	manifestReq.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")

	manifestResp, err := http.DefaultClient.Do(manifestReq)
	if err != nil {
		t.Fatalf("manifest publish request failed: %v", err)
	}
	defer manifestResp.Body.Close()

	if manifestResp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected manifest publish status: %d", manifestResp.StatusCode)
	}

	getReq, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create get manifest request: %v", err)
	}
	getReq.Host = "alice.uncloud-registry.com"

	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get manifest request failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected get manifest status: %d", getResp.StatusCode)
	}
}

func newTestHandler(docs *resolve.MemoryDocumentStore, feeds *resolve.MemoryFeedStore) http.Handler {
	stageStore := staging.NewMemoryStore()
	subjects := auth.SubjectResolver{}
	return NewHandler(
		resolve.RegistryResolver{
			Registries: resolve.StaticRegistryIdentityResolver{
				Hosts: map[string]resolve.RegistryIdentity{
					"alice.uncloud-registry.com": {
						Host:  "alice.uncloud-registry.com",
						Owner: "0xaliceowner",
					},
				},
			},
			Docs:  docs,
			Feeds: feeds,
		},
		docs,
		docs,
		policy.PullAuthorizer{Policies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}, Subjects: subjects},
		policy.PushAuthorizer{
			AuthPolicies:  policy.AuthPolicyResolver{Docs: docs, Feeds: feeds},
			StampPolicies: policy.StampPolicyResolver{Docs: docs, Feeds: feeds},
			Subjects:      subjects,
		},
		subjects,
		stageStore,
		publish.Publisher{
			Builder: publish.DefaultBuilder{},
			Objects: docs,
			Feeds:   feeds,
		},
		"https://auth.uncloud-registry.com/token",
	)
}

func seedRegistryDocuments(t *testing.T, docs *resolve.MemoryDocumentStore, feeds *resolve.MemoryFeedStore) {
	t.Helper()

	docs.Documents["repo-state-ref"] = []byte(`{
		"version":1,
		"repo":"backend/api",
		"generation":3,
		"updatedAt":"2026-04-05T12:00:00Z",
		"tags":{"latest":"sha256:manifest1"},
		"manifests":{
			"sha256:manifest1":{"swarmRef":"manifest-ref","mediaType":"application/vnd.oci.image.manifest.v1+json","size":19}
		},
		"blobs":{
			"sha256:blob1":{"swarmRef":"blob-ref","size":10,"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip"}
		}
	}`)
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
	docs.Documents["manifest-ref"] = []byte(`{"schemaVersion":2}`)
	docs.Documents["blob-ref"] = []byte("blob-bytes")
	feeds.Feeds[spec.RepoStateFeedRef("0xaliceowner", "backend/api")] = "repo-state-ref"
	feeds.Feeds[spec.AuthPolicyFeedRef("0xaliceowner")] = "auth-policy-ref"
	feeds.Feeds[spec.StampPolicyFeedRef("0xaliceowner")] = "stamp-policy-ref"
}

func TestMemoryDocumentStoreRoundTrip(t *testing.T) {
	t.Parallel()

	store := resolve.NewMemoryDocumentStore()
	ref, err := store.Put(context.Background(), []byte("hello"), "batch")
	if err != nil {
		t.Fatalf("put failed: %v", err)
	}
	got, err := store.Get(context.Background(), ref)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("unexpected stored data: %q", got)
	}
}
