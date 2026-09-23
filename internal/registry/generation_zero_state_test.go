package registry

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// recordingBuilder wraps the default builder and captures EVERY current
// repo-state document the Builder sees — with the exact values the handler
// passed down — so tests can assert the precise generation-zero construction
// (and per-request independence) at the Builder boundary.
type recordingBuilder struct {
	inner  publish.Builder
	mu     sync.Mutex
	states []spec.RepoStateDocument
}

func (r *recordingBuilder) BuildNext(current spec.RepoStateDocument, input publish.BuildInput) (spec.RepoStateDocument, error) {
	r.mu.Lock()
	r.states = append(r.states, current)
	r.mu.Unlock()
	return r.inner.BuildNext(current, input)
}

func (r *recordingBuilder) snapshot() []spec.RepoStateDocument {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]spec.RepoStateDocument, len(r.states))
	copy(out, r.states)
	return out
}

// exactGenerationZero is the EXACT current document the authorized first push
// must feed the Builder when the repository feed is conclusively absent:
// Version 1, the canonical request repo, Generation 0, and NON-NIL EMPTY
// Tags/Manifests/Blobs maps.
func exactGenerationZero(repo string) spec.RepoStateDocument {
	return spec.RepoStateDocument{
		Version:    1,
		Repo:       repo,
		Generation: 0,
		Tags:       map[string]string{},
		Manifests:  map[string]spec.ManifestDescriptor{},
		Blobs:      map[string]spec.BlobDescriptor{},
	}
}

// TestFirstPushConstructsExactGenerationZeroState proves the handler BRANCHES
// on found=false and constructs the exact generation-zero document BEFORE
// passing it to the Publisher/Builder: the recording builder must see the
// precise struct, never a zero-value with nil maps.
func TestFirstPushConstructsExactGenerationZeroState(t *testing.T) {
	t.Parallel()

	h, _, _, issuer := newFirstPushWorld(t)
	rec := &recordingBuilder{inner: publish.DefaultBuilder{}}
	h.Publisher.Builder = rec
	server := httptest.NewServer(h)
	defer server.Close()

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, server.URL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":` + fmt.Sprintf("%d", len(configBytes)) + `,"digest":"` + configDigest + `"},"layers":[]}`)
	resp := putManifest(t, server.URL, issuer, manifestBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first push must be 201, got %d", resp.StatusCode)
	}

	states := rec.snapshot()
	if len(states) != 1 {
		t.Fatalf("builder must be called exactly once, got %d snapshots", len(states))
	}
	got := states[0]
	want := exactGenerationZero("backend/api")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("builder must see the EXACT generation-zero document:\n got %+v\nwant %+v", got, want)
	}
	if got.Tags == nil || got.Manifests == nil || got.Blobs == nil {
		t.Fatal("generation-zero Tags/Manifests/Blobs must be non-nil empty maps")
	}
}

// TestGenerationZeroStateMapsIndependentPerRequest proves each authorized first
// push constructs a FRESH generation-zero document: two unseeded repositories
// pushed through one handler see independent (non-aliased) map instances.
func TestGenerationZeroStateMapsIndependentPerRequest(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	docs.Documents["auth-policy-ref"] = []byte(`{
		"version":1,
		"defaultAccess":"deny",
		"repos":{
			"backend/api":{"pull":["anonymous","user:alice"],"push":["user:alice"]},
			"backend/db":{"pull":["anonymous","user:alice"],"push":["user:alice"]}
		}
	}`)
	docs.Documents["stamp-policy-ref"] = []byte(`{
		"version":1,
		"defaultPolicy":{"batchID":"batch-default","allowPushFor":["user:alice"]},
		"repos":{
			"backend/api":{"batchID":"batch-repo","allowPushFor":["user:alice"]},
			"backend/db":{"batchID":"batch-repo","allowPushFor":["user:alice"]}
		}
	}`)
	feeds.Feeds[spec.AuthPolicyFeedRef("0xaliceowner")] = "auth-policy-ref"
	feeds.Feeds[spec.StampPolicyFeedRef("0xaliceowner")] = "stamp-policy-ref"

	handler, issuer := newTestHandler(t, docs, feeds)
	h, ok := handler.(*Handler)
	if !ok {
		t.Fatalf("unexpected handler type %T", handler)
	}
	rec := &recordingBuilder{inner: publish.DefaultBuilder{}}
	h.Publisher.Builder = rec
	server := httptest.NewServer(h)
	defer server.Close()

	stageAndPut := func(repo string, tag string) {
		t.Helper()
		configBytes := []byte(`{"architecture":"` + repo + `"}`)
		configDigest := stageBlobForRepo(t, server.URL, issuer, repo, configBytes, "application/vnd.oci.image.config.v1+json")
		manifestBody := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":` + fmt.Sprintf("%d", len(configBytes)) + `,"digest":"` + configDigest + `"},"layers":[]}`)
		req, err := http.NewRequest(http.MethodPut, server.URL+"/v2/"+repo+"/manifests/"+tag, bytes.NewReader(manifestBody))
		if err != nil {
			t.Fatalf("create manifest request: %v", err)
		}
		req.Host = testServiceHost
		req.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, repo, []auth.Action{auth.ActionPush}, time.Hour))
		req.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("manifest request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("first push for %s must be 201, got %d", repo, resp.StatusCode)
		}
	}

	stageAndPut("backend/api", "latest")
	stageAndPut("backend/db", "v1")

	states := rec.snapshot()
	if len(states) != 2 {
		t.Fatalf("expected two builder calls, got %d", len(states))
	}
	for i, got := range states {
		want := exactGenerationZero([]string{"backend/api", "backend/db"}[i])
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("state %d must be the exact generation-zero document:\n got %+v\nwant %+v", i, got, want)
		}
	}
	// Maps must be INDEPENDENT instances, never shared/aliased across
	// requests: mutating the first recorded document leaves the second
	// untouched, and the map identities differ.
	if reflect.ValueOf(states[0].Tags).Pointer() == reflect.ValueOf(states[1].Tags).Pointer() {
		t.Fatal("Tags map must be a fresh instance per request")
	}
	if reflect.ValueOf(states[0].Manifests).Pointer() == reflect.ValueOf(states[1].Manifests).Pointer() {
		t.Fatal("Manifests map must be a fresh instance per request")
	}
	if reflect.ValueOf(states[0].Blobs).Pointer() == reflect.ValueOf(states[1].Blobs).Pointer() {
		t.Fatal("Blobs map must be a fresh instance per request")
	}
	recorded := rec.snapshot()
	recorded[0].Tags["mutated"] = "x"
	if _, ok := recorded[1].Tags["mutated"]; ok {
		t.Fatal("generation-zero map instances must be independent per request")
	}
}

// TestUnauthorizedFirstPushNeverConstructsGenerationZero proves the
// unauthorized path NEVER constructs generation-zero state and NEVER calls the
// Publisher/Builder: a 401 leaves the builder untouched and no state behind.
func TestUnauthorizedFirstPushNeverConstructsGenerationZero(t *testing.T) {
	t.Parallel()

	h, _, feeds, _ := newFirstPushWorld(t)
	rec := &recordingBuilder{inner: publish.DefaultBuilder{}}
	h.Publisher.Builder = rec
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
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("unauthorized path must never construct generation-zero state or call the builder, got %d calls", len(got))
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("unauthorized first push created the repo-state feed")
	}
}

// stageBlobForRepo is stageBlob parameterized by the target repository.
func stageBlobForRepo(t *testing.T, serverURL string, issuer *auth.RegistryTokenIssuer, repo string, body []byte, contentType string) string {
	t.Helper()
	digest := publish.ComputeDigest(body)

	pushTo := func(req *http.Request) {
		req.Host = testServiceHost
		req.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, repo, []auth.Action{auth.ActionPush}, time.Hour))
	}

	startReq, err := http.NewRequest(http.MethodPost, serverURL+"/v2/"+repo+"/blobs/uploads/", nil)
	if err != nil {
		t.Fatalf("create start upload: %v", err)
	}
	pushTo(startReq)
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
	pushTo(patchReq)
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
	pushTo(finalizeReq)
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
