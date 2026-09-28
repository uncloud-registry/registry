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
)

const (
	indexTestMT       = "application/vnd.oci.image.index.v1+json"
	indexTestManMT    = "application/vnd.oci.image.manifest.v1+json"
	indexTestListMT   = "application/vnd.docker.distribution.manifest.list.v2+json"
	indexTestDockerMT = "application/vnd.docker.distribution.manifest.v2+json"
)

// indexChildAmd64 and indexChildArm64 are the two committed single-platform
// child manifests an index test publishes against.
var indexChildAmd64 = []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":11,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[]}`)

var indexChildArm64 = []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":17,"digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"layers":[]}`)

// newIndexWorld seeds a repository whose state already contains the two
// committed child manifests (each with its object bytes), plus auth/stamp
// policy feeds, so an index publication can reference them by digest.
func newIndexWorld(t *testing.T) (*Handler, *resolve.MemoryDocumentStore, *resolve.MemoryFeedStore, *auth.RegistryTokenIssuer) {
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

	amd := publish.ComputeDigest(indexChildAmd64)
	arm := publish.ComputeDigest(indexChildArm64)
	docs.Documents["child-amd64-ref"] = indexChildAmd64
	docs.Documents["child-arm64-ref"] = indexChildArm64

	docs.Documents["repo-state-ref"] = []byte(fmt.Sprintf(`{
		"version":1,
		"repo":"backend/api",
		"generation":2,
		"updatedAt":"2026-04-05T12:00:00Z",
		"tags":{"amd":"%s","arm":"%s"},
		"manifests":{
			"%s":{"swarmRef":"child-amd64-ref","mediaType":"%s","size":%d},
			"%s":{"swarmRef":"child-arm64-ref","mediaType":"%s","size":%d}
		},
		"blobs":{}
	}`, amd, arm, amd, indexTestManMT, len(indexChildAmd64), arm, indexTestManMT, len(indexChildArm64)))
	feeds.Feeds[repoStateFeed()] = "repo-state-ref"

	handler, issuer := newTestHandler(t, docs, feeds)
	return handler.(*Handler), docs, feeds, issuer
}

// putIndex PUTs an index body for the given tag and Content-Type.
func putIndex(t *testing.T, serverURL string, issuer *auth.RegistryTokenIssuer, tag string, contentType string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/"+tag, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create index request: %v", err)
	}
	pushTo(t, req, issuer)
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("index publish request failed: %v", err)
	}
	return resp
}

// indexBody assembles an OCI index with the given child digest/media/size
// tuples and optional per-child platforms.
type indexChild struct {
	digest string
	media  string
	size   int
	arch   string
	os     string
}

func indexBody(t *testing.T, children ...indexChild) []byte {
	t.Helper()
	if len(children) == 0 {
		return []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[]}`, indexTestMT))
	}
	var b strings.Builder
	fmt.Fprintf(&b, `{"schemaVersion":2,"mediaType":%q,"manifests":[`, indexTestMT)
	for i, c := range children {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"mediaType":%q,"size":%d,"digest":%q`, c.media, c.size, c.digest)
		if c.arch != "" || c.os != "" {
			fmt.Fprintf(&b, `,"platform":{"architecture":%q,"os":%q}`, c.arch, c.os)
		}
		b.WriteString("}")
	}
	b.WriteString("]}")
	return []byte(b.String())
}

// twoPlatformIndexBody returns a valid two-platform OCI index referencing the
// two committed children.
func twoPlatformIndexBody(t *testing.T) []byte {
	t.Helper()
	return indexBody(t,
		indexChild{digest: publish.ComputeDigest(indexChildAmd64), media: indexTestManMT, size: len(indexChildAmd64), arch: "amd64", os: "linux"},
		indexChild{digest: publish.ComputeDigest(indexChildArm64), media: indexTestManMT, size: len(indexChildArm64), arch: "arm64", os: "linux"},
	)
}

// pullManifest performs a GET manifest by tag or digest with an optional Accept
// header (empty = none).
func indexPullManifest(t *testing.T, serverURL string, issuer *auth.RegistryTokenIssuer, reference string, accept string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, serverURL+"/v2/backend/api/manifests/"+reference, nil)
	if err != nil {
		t.Fatalf("create pull request: %v", err)
	}
	req.Host = testServiceHost
	req.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour))
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pull request failed: %v", err)
	}
	return resp
}

// TestIndexPublishPullByTagAndDigest is the core multi-platform happy path:
// publishing a two-platform OCI index returns 201, the index is recorded under
// its digest in state, and pulling it by tag AND by digest returns the
// BYTE-IDENTICAL stored body with the exact Content-Type, Docker-Content-Digest
// and Content-Length. The committed children remain pullable.
func TestIndexPublishPullByTagAndDigest(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	server := httptest.NewServer(h)
	defer server.Close()

	indexBodyBytes := twoPlatformIndexBody(t)
	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, indexBodyBytes)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("index publish status %d, want 201 (body %s)", resp.StatusCode, body)
	}

	indexDigest := publish.ComputeDigest(indexBodyBytes)

	// Pull by tag.
	tagResp := indexPullManifest(t, server.URL, issuer, "multi", "")
	defer tagResp.Body.Close()
	tagBody, _ := io.ReadAll(tagResp.Body)
	if tagResp.StatusCode != http.StatusOK || !bytes.Equal(tagBody, indexBodyBytes) {
		t.Fatalf("index pull by tag status=%d body=%q", tagResp.StatusCode, tagBody)
	}
	if tagResp.Header.Get("Content-Type") != indexTestMT {
		t.Fatalf("index Content-Type=%q", tagResp.Header.Get("Content-Type"))
	}
	if tagResp.Header.Get("Docker-Content-Digest") != indexDigest {
		t.Fatalf("index Docker-Content-Digest=%q want %q", tagResp.Header.Get("Docker-Content-Digest"), indexDigest)
	}
	if tagResp.Header.Get("Content-Length") != fmt.Sprintf("%d", len(indexBodyBytes)) {
		t.Fatalf("index Content-Length=%q", tagResp.Header.Get("Content-Length"))
	}

	// Pull by digest.
	digResp := indexPullManifest(t, server.URL, issuer, indexDigest, "")
	defer digResp.Body.Close()
	digBody, _ := io.ReadAll(digResp.Body)
	if digResp.StatusCode != http.StatusOK || !bytes.Equal(digBody, indexBodyBytes) {
		t.Fatalf("index pull by digest status=%d body=%q", digResp.StatusCode, digBody)
	}
	if digResp.Header.Get("Content-Type") != indexTestMT {
		t.Fatalf("index by digest Content-Type=%q", digResp.Header.Get("Content-Type"))
	}

	// A committed child manifest remains pullable by digest.
	childResp := indexPullManifest(t, server.URL, issuer, publish.ComputeDigest(indexChildAmd64), "")
	defer childResp.Body.Close()
	childBody, _ := io.ReadAll(childResp.Body)
	if childResp.StatusCode != http.StatusOK || !bytes.Equal(childBody, indexChildAmd64) {
		t.Fatalf("child manifest pull status=%d body=%q", childResp.StatusCode, childBody)
	}
}

// TestIndexDockerManifestListPublish proves a Docker manifest list (Docker's
// index form) publishes and pulls byte-identically.
func TestIndexDockerManifestListPublish(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	server := httptest.NewServer(h)
	defer server.Close()

	amd := publish.ComputeDigest(indexChildAmd64)
	body := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":%d,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}]}`,
		indexTestListMT, indexTestDockerMT, len(indexChildAmd64), amd))

	// Seed a Docker schema-2 child into state (the only child in the list).
	docs := h.Resolver.Docs.(*resolve.MemoryDocumentStore)
	feeds := h.Resolver.Feeds.(*resolve.MemoryFeedStore)
	current := mustDecodeRepoState(t, docs, feeds, repoStateFeed())
	newManifests := map[string]spec.ManifestDescriptor{
		amd: {SwarmRef: "child-amd64-ref", MediaType: indexTestDockerMT, Size: int64(len(indexChildAmd64))},
	}
	current.Manifests = newManifests
	current.Tags = map[string]string{"amd": amd}
	seedRepoState(t, docs, feeds, current)

	resp := putIndex(t, server.URL, issuer, "dockerlist", indexTestListMT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("docker manifest list publish status %d, want 201 (body %s)", resp.StatusCode, b)
	}
	p := indexPullManifest(t, server.URL, issuer, "dockerlist", "")
	defer p.Body.Close()
	pb, _ := io.ReadAll(p.Body)
	if p.StatusCode != http.StatusOK || !bytes.Equal(pb, body) {
		t.Fatalf("docker manifest list pull status=%d body=%q", p.StatusCode, pb)
	}
	if p.Header.Get("Content-Type") != indexTestListMT {
		t.Fatalf("manifest list Content-Type=%q", p.Header.Get("Content-Type"))
	}
}

// TestIndexMissingChildZeroWrites proves an index referencing a child digest
// that is not committed fails 400 with ZERO object writes, no feed update, and
// unchanged staging.
func TestIndexMissingChildZeroWrites(t *testing.T) {
	t.Parallel()
	h, _, feeds, issuer := newIndexWorld(t)
	counter := &countingObjectUploader{inner: h.Publisher.Objects}
	h.Publisher.Objects = counter
	server := httptest.NewServer(h)
	defer server.Close()

	missing := "sha256:" + strings.Repeat("e", 64)
	body := indexBody(t, indexChild{digest: missing, media: indexTestManMT, size: 99, arch: "amd64", os: "linux"})
	before := mustDecodeRepoState(t, h.Resolver.Docs.(*resolve.MemoryDocumentStore), h.Resolver.Feeds.(*resolve.MemoryFeedStore), repoStateFeed())

	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, body)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing child must be 400, got %d (body %s)", resp.StatusCode, respBody)
	}
	if counter.puts != 0 {
		t.Fatalf("missing child caused %d object writes, want 0", counter.puts)
	}
	after := mustDecodeRepoState(t, h.Resolver.Docs.(*resolve.MemoryDocumentStore), h.Resolver.Feeds.(*resolve.MemoryFeedStore), repoStateFeed())
	if after.Generation != before.Generation || after.UpdatedAt != before.UpdatedAt {
		t.Fatal("missing child mutated repository state")
	}
	_ = feeds
}

// TestIndexWrongChildSizeZeroWrites proves a child descriptor whose size
// disagrees with the committed record is a 400 with zero writes.
func TestIndexWrongChildSizeZeroWrites(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	counter := &countingObjectUploader{inner: h.Publisher.Objects}
	h.Publisher.Objects = counter
	server := httptest.NewServer(h)
	defer server.Close()

	body := indexBody(t,
		indexChild{digest: publish.ComputeDigest(indexChildAmd64), media: indexTestManMT, size: len(indexChildAmd64) + 1000, arch: "amd64", os: "linux"})
	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("wrong child size must be 400, got %d (body %s)", resp.StatusCode, b)
	}
	if counter.puts != 0 {
		t.Fatalf("wrong child size caused %d object writes, want 0", counter.puts)
	}
}

// TestIndexWrongChildMediaTypeZeroWrites proves a child descriptor whose media
// type disagrees with the committed record is a 400 with zero writes.
func TestIndexWrongChildMediaTypeZeroWrites(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	counter := &countingObjectUploader{inner: h.Publisher.Objects}
	h.Publisher.Objects = counter
	server := httptest.NewServer(h)
	defer server.Close()

	body := indexBody(t,
		indexChild{digest: publish.ComputeDigest(indexChildAmd64), media: "application/vnd.oci.image.layer.v1.tar+gzip", size: len(indexChildAmd64), arch: "amd64", os: "linux"})
	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("wrong child media type must be 400, got %d (body %s)", resp.StatusCode, b)
	}
	if counter.puts != 0 {
		t.Fatalf("wrong child media type caused %d object writes, want 0", counter.puts)
	}
}

// TestIndexUnsupportedNestedMediaType rejects an index whose child is itself
// an index (recursive nested index is not supported) with 400 and zero writes.
func TestIndexUnsupportedNestedMediaType(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	counter := &countingObjectUploader{inner: h.Publisher.Objects}
	h.Publisher.Objects = counter
	server := httptest.NewServer(h)
	defer server.Close()

	body := indexBody(t,
		indexChild{digest: publish.ComputeDigest(indexChildAmd64), media: indexTestMT, size: len(indexChildAmd64), arch: "amd64", os: "linux"})
	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("nested index must be 400, got %d (body %s)", resp.StatusCode, b)
	}
	if counter.puts != 0 {
		t.Fatalf("nested index caused %d object writes, want 0", counter.puts)
	}
}

// TestIndexMalformedPlatformRejected rejects an index child with a malformed
// platform (missing required architecture) as a 400 with zero writes.
func TestIndexMalformedPlatformRejected(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	counter := &countingObjectUploader{inner: h.Publisher.Objects}
	h.Publisher.Objects = counter
	server := httptest.NewServer(h)
	defer server.Close()

	amd := publish.ComputeDigest(indexChildAmd64)
	body := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":%d,"digest":%q,"platform":{"os":"linux"}}]}`,
		indexTestMT, indexTestManMT, len(indexChildAmd64), amd))
	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("malformed platform must be 400, got %d (body %s)", resp.StatusCode, b)
	}
	if counter.puts != 0 {
		t.Fatalf("malformed platform caused %d object writes, want 0", counter.puts)
	}
}

// TestIndexDuplicatePlatformRejected rejects an index with TWO children under
// the SAME platform as a 400 with zero writes.
func TestIndexDuplicatePlatformRejected(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	counter := &countingObjectUploader{inner: h.Publisher.Objects}
	h.Publisher.Objects = counter
	server := httptest.NewServer(h)
	defer server.Close()

	body := indexBody(t,
		indexChild{digest: publish.ComputeDigest(indexChildAmd64), media: indexTestManMT, size: len(indexChildAmd64), arch: "amd64", os: "linux"},
		indexChild{digest: publish.ComputeDigest(indexChildArm64), media: indexTestManMT, size: len(indexChildArm64), arch: "amd64", os: "linux"},
	)
	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("duplicate platform must be 400, got %d (body %s)", resp.StatusCode, b)
	}
	if counter.puts != 0 {
		t.Fatalf("duplicate platform caused %d object writes, want 0", counter.puts)
	}
}

// TestIndexPullAcceptNegotiation covers the Accept header matrix for an index
// pull: absent, exact match, type wildcard, global wildcard, and an
// unsupported concrete type that must yield the documented data-free 404
// without changing state.
func TestIndexPullAcceptNegotiation(t *testing.T) {
	t.Parallel()
	h, docs, feeds, issuer := newIndexWorld(t)
	server := httptest.NewServer(h)
	defer server.Close()

	indexBodyBytes := twoPlatformIndexBody(t)
	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, indexBodyBytes)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("index seed publish status %d", resp.StatusCode)
	}
	indexDigest := publish.ComputeDigest(indexBodyBytes)

	before := mustDecodeRepoState(t, docs, feeds, repoStateFeed())

	cases := []struct {
		name   string
		accept string
		wantOK bool
	}{
		{"absent Accept", "", true},
		{"exact index type", indexTestMT, true},
		{"wildcard type/subtype", "application/*", true},
		{"global wildcard", "*/*", true},
		{"docker list acceptable alongside", indexTestListMT + ", " + indexTestMT, true},
		{"concrete mismatch rejected", indexTestManMT, false},
		{"docker-only rejected", indexTestListMT, false},
		{"text/plain rejected", "text/plain", false},
		{"q=0 refuses the matching type", indexTestMT + "; q=0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := indexPullManifest(t, server.URL, issuer, indexDigest, tc.accept)
			defer p.Body.Close()
			b, _ := io.ReadAll(p.Body)
			if tc.wantOK && p.StatusCode != http.StatusOK {
				t.Fatalf("expected 200 for %q, got %d (body %s)", tc.accept, p.StatusCode, b)
			}
			if !tc.wantOK {
				if p.StatusCode != http.StatusNotFound {
					t.Fatalf("expected 404 for %q, got %d (body %s)", tc.accept, p.StatusCode, b)
				}
				code, msg := decodeErrorPayload(t, b)
				if code != "MANIFEST_UNKNOWN" {
					t.Fatalf("expected MANIFEST_UNKNOWN code, got %q", code)
				}
				// Fixed data-free message; must not echo the Accept value.
				if msg != messageManifestNotAcceptable {
					t.Fatalf("expected fixed data-free message, got %q", msg)
				}
			}
		})
	}

	// Unsupported Accept must not change any state.
	after := mustDecodeRepoState(t, docs, feeds, repoStateFeed())
	if after.Generation != before.Generation || after.UpdatedAt != before.UpdatedAt {
		t.Fatal("a rejected Accept changed repository state")
	}
}

// TestIndexPullHttpMethodsParity proves HEAD returns the SAME metadata headers
// as GET with no body and 200 parity.
func TestIndexPullHttpMethodsParity(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	server := httptest.NewServer(h)
	defer server.Close()

	indexBodyBytes := twoPlatformIndexBody(t)
	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, indexBodyBytes)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("index seed publish status %d", resp.StatusCode)
	}

	getR := indexPullManifest(t, server.URL, issuer, "multi", indexTestMT)
	defer getR.Body.Close()
	getBody, _ := io.ReadAll(getR.Body)

	headReq, err := http.NewRequest(http.MethodHead, server.URL+"/v2/backend/api/manifests/multi", nil)
	if err != nil {
		t.Fatal(err)
	}
	headReq.Host = testServiceHost
	headReq.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour))
	headReq.Header.Set("Accept", indexTestMT)
	headResp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		t.Fatal(err)
	}
	defer headResp.Body.Close()
	headBody, _ := io.ReadAll(headResp.Body)

	if getR.StatusCode != http.StatusOK || headResp.StatusCode != http.StatusOK {
		t.Fatalf("GET=%d HEAD=%d, want 200/200", getR.StatusCode, headResp.StatusCode)
	}
	if len(headBody) != 0 {
		t.Fatalf("HEAD must have no body, got %d bytes", len(headBody))
	}
	if headResp.Header.Get("Content-Type") != indexTestMT ||
		headResp.Header.Get("Docker-Content-Digest") != getR.Header.Get("Docker-Content-Digest") ||
		headResp.Header.Get("Content-Length") != getR.Header.Get("Content-Length") {
		t.Fatalf("HEAD metadata differs from GET: ct=%q get-ct=%q", headResp.Header.Get("Content-Type"), getR.Header.Get("Content-Type"))
	}
	_ = getBody
	_ = headBody
}

// TestOrdinaryManifestBehaviorUnchanged proves Task 19 does not regress the
// ordinary single-platform manifest path: push and pull still work, and an
// ordinary manifest pull with an explicit matching Accept still succeeds.
func TestOrdinaryManifestBehaviorUnchanged(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newFirstPushWorld(t)
	server := httptest.NewServer(h)
	defer server.Close()

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, server.URL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":` + fmt.Sprintf("%d", len(configBytes)) + `,"digest":"` + configDigest + `"},"layers":[]}`)
	resp := putManifest(t, server.URL, issuer, manifestBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("ordinary manifest publish status %d, want 201 (body %s)", resp.StatusCode, b)
	}

	// Pull with an explicit matching OCI manifest Accept.
	p := indexPullManifest(t, server.URL, issuer, "latest", indexTestManMT)
	defer p.Body.Close()
	b, _ := io.ReadAll(p.Body)
	if p.StatusCode != http.StatusOK || !bytes.Equal(b, manifestBody) {
		t.Fatalf("ordinary manifest pull with matching Accept status=%d body=%q", p.StatusCode, b)
	}
}

// mustDecodeRepoState decodes the repo-state document behind a feed.
func mustDecodeRepoState(t *testing.T, docs *resolve.MemoryDocumentStore, feeds *resolve.MemoryFeedStore, feed string) spec.RepoStateDocument {
	t.Helper()
	ref, ok := feeds.Feeds[feed]
	if !ok {
		t.Fatalf("feed %q absent", feed)
	}
	data, err := docs.Get(context.Background(), ref)
	if err != nil {
		t.Fatalf("read repo state: %v", err)
	}
	doc, err := spec.DecodeRepoStateDocument(data)
	if err != nil {
		t.Fatalf("decode repo state: %v", err)
	}
	return doc
}

// seedRepoState overwrites the repo-state document a feed points at.
func seedRepoState(t *testing.T, docs *resolve.MemoryDocumentStore, feeds *resolve.MemoryFeedStore, doc spec.RepoStateDocument) {
	t.Helper()
	ref, ok := feeds.Feeds[repoStateFeed()]
	if !ok {
		t.Fatal("repo-state feed absent")
	}
	newRef := "seeded-" + ref
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	docs.Documents[newRef] = data
	feeds.Feeds[repoStateFeed()] = newRef
}
