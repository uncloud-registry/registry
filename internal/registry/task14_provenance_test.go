package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
)

// taggedPusher PUTs a manifest body under an explicit tag with an optional
// caller operation key — the finding-1 retry-identity driving helper.
type taggedPusher struct {
	t         *testing.T
	serverURL string
	issuer    *auth.RegistryTokenIssuer
	key       string
}

func (p *taggedPusher) put(tag string, body []byte) *http.Response {
	t := p.t
	req, err := http.NewRequest(http.MethodPut, p.serverURL+"/v2/backend/api/manifests/"+tag, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create manifest request: %v", err)
	}
	pushTo(t, req, p.issuer)
	req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
	if p.key != "" {
		req.Header.Set(OperationIDHeader, p.key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("manifest publish request failed: %v", err)
	}
	return resp
}

// TestRetryAfterUnrelatedPublicationReturnsExactRecordedOperationID is the
// core Finding-1 regression: after operation A publishes tag latest at
// generation 1, an UNRELATED operation B advances the feed to generation 2.
// A lost-response retry of A (no explicit key) must be recognized from the
// durable per-tag provenance and answered with A's EXACT recorded operation
// ID — never a re-fabricated ComputeOperationID derived from the CURRENT
// generation — and must not advance the feed. A reconstructed handler over
// the same durable stores answers identically.
func TestRetryAfterUnrelatedPublicationReturnsExactRecordedOperationID(t *testing.T) {
	_, _, counter, committer, docs, feeds, issuer, serverURL := bindingWorld(t)

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))

	keyed := &taggedPusher{t: t, serverURL: serverURL, issuer: issuer}
	first := keyed.put("latest", manifestA)
	bodyA, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("push A status %d (%s)", first.StatusCode, bodyA)
	}
	opA := first.Header.Get(OperationIDHeader)
	if opA == "" {
		t.Fatal("push A must return an operation identity")
	}
	stateAfterA := loadRepoState(t, docs, feeds)
	if stateAfterA.Generation != 1 {
		t.Fatalf("expected generation 1 after A, got %d", stateAfterA.Generation)
	}
	if pub := stateAfterA.TagPublications["latest"]; pub.OperationID != opA || pub.Generation != 1 || pub.Digest != publish.ComputeDigest(manifestA) {
		t.Fatalf("A must be recorded in durable provenance: %+v", stateAfterA.TagPublications)
	}

	// Unrelated operation B: a different tag advances the feed to generation 2.
	configB := []byte(`{"architecture":"arm64"}`)
	configBDigest := stageBlob(t, serverURL, issuer, configB, "application/vnd.oci.image.config.v1+json")
	manifestB := manifestFor(configBDigest, len(configB))
	second := keyed.put("v2", manifestB)
	bodyB, _ := io.ReadAll(second.Body)
	second.Body.Close()
	if second.StatusCode != http.StatusCreated {
		t.Fatalf("push B status %d (%s)", second.StatusCode, bodyB)
	}
	stateAfterB := loadRepoState(t, docs, feeds)
	if stateAfterB.Generation != 2 {
		t.Fatalf("expected generation 2 after B, got %d", stateAfterB.Generation)
	}
	if pub := stateAfterB.TagPublications["latest"]; pub.OperationID != opA {
		t.Fatalf("unrelated publication must RETAIN A's provenance, got %+v", stateAfterB.TagPublications["latest"])
	}
	targetAfterB := feeds.Feeds[repoStateFeed()]
	docCountAfterB := len(docs.Documents)
	commitsAfterB := committer.calls

	// Lost-response retry of A after the unrelated advancement: answered with
	// A's EXACT recorded operation ID, zero writes.
	retry := keyed.put("latest", manifestA)
	defer retry.Body.Close()
	bodyRetry, _ := io.ReadAll(retry.Body)
	if retry.StatusCode != http.StatusCreated {
		t.Fatalf("retry of A status %d (%s)", retry.StatusCode, bodyRetry)
	}
	if got := retry.Header.Get(OperationIDHeader); got != opA {
		t.Fatalf("retry must return A's EXACT recorded operation ID %q, got %q", opA, got)
	}
	if feeds.Feeds[repoStateFeed()] != targetAfterB {
		t.Fatal("retry of A must NOT advance the feed")
	}
	if len(docs.Documents) != docCountAfterB {
		t.Fatalf("retry of A must not create objects: docs %d -> %d", docCountAfterB, len(docs.Documents))
	}
	if committer.calls != commitsAfterB {
		t.Fatalf("retry of A must not commit again: %d -> %d", commitsAfterB, committer.calls)
	}
	if counter.puts.Load() != 4 {
		t.Fatalf("exactly two publications' object writes expected (4), got %d", counter.puts.Load())
	}
	if state := loadRepoState(t, docs, feeds); state.Generation != 2 {
		t.Fatalf("retry of A must not advance generation, got %d", state.Generation)
	}

	// Reconstructed handler (fresh staging, same durable stores + a durable
	// binder): the same no-key retry is answered with A's exact recorded ID.
	rebuiltHandler, issuer2 := newTestHandler(t, docs, feeds)
	rebuilt := rebuiltHandler.(*Handler)
	rebuilt.Preflight = newDurableBindingStore()
	counter2 := &atomicCountingUploader{inner: docs}
	rebuilt.Publisher.Objects = counter2
	rebuilt.Publisher.Commits = &scriptedCommitter{feeds: feeds, writeFeed: true}
	server2 := httptest.NewServer(rebuilt)
	defer server2.Close()

	rebuiltPusher := &taggedPusher{t: t, serverURL: server2.URL, issuer: issuer2}
	third := rebuiltPusher.put("latest", manifestA)
	third.Body.Close()
	if third.StatusCode != http.StatusCreated {
		t.Fatalf("reconstructed retry of A status %d", third.StatusCode)
	}
	if got := third.Header.Get(OperationIDHeader); got != opA {
		t.Fatalf("reconstructed retry must return A's exact recorded operation ID %q, got %q", opA, got)
	}
	if feeds.Feeds[repoStateFeed()] != targetAfterB {
		t.Fatal("reconstructed retry must NOT advance the feed")
	}
	if counter2.puts.Load() != 0 {
		t.Fatalf("reconstructed retry must not write objects, got %d puts", counter2.puts.Load())
	}
}

// TestNewExplicitKeyOnPublishedTargetBecomesFreshOperation proves a distinct
// explicit key is NEVER echoed as a prior success: it bypasses the retry fast
// path, is durably bound through the preflight, and becomes a genuine NEW
// operation that advances the feed — exactly what the durable record shows.
func TestNewExplicitKeyOnPublishedTargetBecomesFreshOperation(t *testing.T) {
	const key = "client-t14r2-newkey-0001"
	_, binder, counter, committer, docs, feeds, issuer, serverURL := bindingWorld(t)

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))

	plain := &taggedPusher{t: t, serverURL: serverURL, issuer: issuer}
	first := plain.put("latest", manifestA)
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("push A status %d", first.StatusCode)
	}
	opA := first.Header.Get(OperationIDHeader)
	if counter.puts.Load() != 2 || committer.calls != 1 {
		t.Fatalf("A must be exactly one publication: puts=%d commits=%d", counter.puts.Load(), committer.calls)
	}

	// Same target, NEW explicit key: must preflight-bind, then publish FRESH.
	keyed := &taggedPusher{t: t, serverURL: serverURL, issuer: issuer, key: key}
	second := keyed.put("latest", manifestA)
	bodySecond, _ := io.ReadAll(second.Body)
	second.Body.Close()
	if second.StatusCode != http.StatusCreated {
		t.Fatalf("distinct-key request must become a genuine new publication, got %d (%s)", second.StatusCode, bodySecond)
	}
	if got := second.Header.Get(OperationIDHeader); got != key {
		t.Fatalf("new operation must return the caller key %q, got %q", key, got)
	}
	if got := second.Header.Get(OperationIDHeader); got == opA {
		t.Fatal("the distinct key must never be echoed as A's prior operation")
	}
	if binder.calls != 1 || binder.conflicts != 0 {
		t.Fatalf("distinct key must be durably bound exactly once through the preflight: calls=%d conflicts=%d", binder.calls, binder.conflicts)
	}
	if committer.calls != 2 {
		t.Fatalf("distinct-key request must be a second publication: commits=%d", committer.calls)
	}
	if counter.puts.Load() != 4 {
		t.Fatalf("distinct-key request must write its own manifest+state (4 total), got %d", counter.puts.Load())
	}
	state := loadRepoState(t, docs, feeds)
	if state.Generation != 2 {
		t.Fatalf("distinct-key fresh operation must advance to generation 2, got %d", state.Generation)
	}
	if pub := state.TagPublications["latest"]; pub.OperationID != key || pub.Generation != 2 {
		t.Fatalf("provenance must record the fresh operation: %+v", state.TagPublications["latest"])
	}
}

// TestConflictingExplicitKeyOnPublishedTargetNotEchoed proves a
// previously-conflicting explicit key is still a hard conflict on an
// already-published target — it is NEVER echoed 201 as prior success and
// never reaches the object store.
func TestConflictingExplicitKeyOnPublishedTargetNotEchoed(t *testing.T) {
	const keyA = "client-t14r2-conf-a-0001"
	const keyB = "client-t14r2-conf-b-0001"
	_, binder, counter, _, docs, feeds, issuer, serverURL := bindingWorld(t)

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))

	// Publish A under keyA (durably bound to this payload).
	keyedA := &taggedPusher{t: t, serverURL: serverURL, issuer: issuer, key: keyA}
	first := keyedA.put("latest", manifestA)
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("push A status %d", first.StatusCode)
	}
	feedAfterFirst := feeds.Feeds[repoStateFeed()]

	// Seed a DIFFERENT durable binding for keyB (a previously-conflicting key).
	if err := binder.Bind(context.Background(), publish.OperationBindingRequest{
		OperationID:    keyB,
		RegistryID:     0,
		Owner:          "0xaliceowner",
		Repo:           "backend/api",
		Tag:            "stale",
		ManifestDigest: publish.ComputeDigest([]byte("some other payload")),
	}); err != nil {
		t.Fatalf("seed conflicting binding: %v", err)
	}
	docCount := len(docs.Documents)

	// Retry A's exact target with the previously-conflicting keyB: the gate
	// must NOT fast-path; the preflight must conflict.
	keyedB := &taggedPusher{t: t, serverURL: serverURL, issuer: issuer, key: keyB}
	second := keyedB.put("latest", manifestA)
	defer second.Body.Close()
	bodySecond, _ := io.ReadAll(second.Body)
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("previously-conflicting key on a published target must be 409, got %d (%s)", second.StatusCode, bodySecond)
	}
	if code, _ := decodeErrorPayload(t, bodySecond); code != ErrorCodeManifestConflict {
		t.Fatalf("expected MANIFEST_CONFLICT, got %q", code)
	}
	if strings.Contains(string(bodySecond), keyB) {
		t.Fatalf("conflict response must never echo the key: %s", bodySecond)
	}
	if counter.puts.Load() != 2 {
		t.Fatalf("conflicted key must cause no new object writes, got %d", counter.puts.Load())
	}
	if len(docs.Documents) != docCount {
		t.Fatalf("conflicted key must not create objects: %d -> %d", docCount, len(docs.Documents))
	}
	if feeds.Feeds[repoStateFeed()] != feedAfterFirst {
		t.Fatal("conflicted key must leave the feed at A's publication")
	}
	if binder.conflicts != 1 {
		t.Fatalf("expected exactly one binding conflict, got %d", binder.conflicts)
	}
}

// TestKeyedManifestPutRejectedWithoutDurableBinderZeroWrites is the core
// Finding-2 regression: the public endpoint must REQUIRE a durable binder
// whenever it accepts an explicit operation key. In a mode without one
// (identity/dev), a keyed manifest PUT is rejected with a fixed 503
// dependency response BEFORE any resolver read, object write, feed write, or
// staging consumption — the key is never echoed and no-key identity mode
// remains fully supported.
func TestKeyedManifestPutRejectedWithoutDurableBinderZeroWrites(t *testing.T) {
	const key = "client-t14r2-nobinder-0001"
	h, docs, feeds, issuer, serverURL := task14World(t)
	if h.Preflight != nil {
		t.Fatal("identity-mode fixture must have no durable binder")
	}
	counter := &countingObjectUploader{inner: docs}
	h.Publisher.Objects = counter
	h.Publisher.Feeds = feeds

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))
	stagedAfterBlob, _ := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if len(stagedAfterBlob) != 1 {
		t.Fatalf("fixture must start with exactly one staged config blob, got %+v", stagedAfterBlob)
	}

	keyed := &taggedPusher{t: t, serverURL: serverURL, issuer: issuer, key: key}
	resp := keyed.put("latest", manifestA)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("keyed manifest PUT without a durable binder must be 503, got %d (%s)", resp.StatusCode, body)
	}
	code, _ := decodeErrorPayload(t, body)
	if code != ErrorCodeDependencyUnavailable {
		t.Fatalf("expected DEPENDENCY_UNAVAILABLE, got %q", code)
	}
	if strings.Contains(string(body), key) {
		t.Fatalf("503 must never echo the caller key: %s", body)
	}
	if resp.Header.Get(OperationIDHeader) != "" {
		t.Fatal("503 must not carry an operation identity header")
	}
	if counter.puts != 0 {
		t.Fatalf("keyed PUT without binder caused %d object writes, want 0", counter.puts)
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("keyed PUT without binder must not create the repo-state feed")
	}
	stagedAfter, _ := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if len(stagedAfter) != 1 || stagedAfter[0].Digest != configADigest {
		t.Fatalf("keyed PUT without binder must not consume staging, got %+v", stagedAfter)
	}
}

// TestKeyedRetryWithoutBinderRejectedEvenWhenPublished proves the same rule
// for the retry shape: an already-published target retried WITH an explicit
// key in a binderless mode is still rejected 503 with zero writes — a keyed
// request is never echoed as prior success without a durable binder.
func TestKeyedRetryWithoutBinderRejectedEvenWhenPublished(t *testing.T) {
	const key = "client-t14r2-nobinder-0002"
	h, docs, feeds, issuer, serverURL := task14World(t)
	counter := &countingObjectUploader{inner: docs}
	h.Publisher.Objects = counter

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))

	plain := &taggedPusher{t: t, serverURL: serverURL, issuer: issuer}
	first := plain.put("latest", manifestA)
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("no-key push must still succeed in identity mode, got %d", first.StatusCode)
	}
	feedRef := feeds.Feeds[repoStateFeed()]
	docCount := len(docs.Documents)
	putsAfterFirst := counter.puts
	if putsAfterFirst == 0 {
		t.Fatalf("the no-key push must have written its objects (got 0)")
	}

	keyed := &taggedPusher{t: t, serverURL: serverURL, issuer: issuer, key: key}
	second := keyed.put("latest", manifestA)
	defer second.Body.Close()
	body, _ := io.ReadAll(second.Body)
	if second.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("keyed retry without a durable binder must be 503, got %d (%s)", second.StatusCode, body)
	}
	code, _ := decodeErrorPayload(t, body)
	if code != ErrorCodeDependencyUnavailable {
		t.Fatalf("expected DEPENDENCY_UNAVAILABLE, got %q", code)
	}
	if strings.Contains(string(body), key) {
		t.Fatalf("503 must never echo the caller key: %s", body)
	}
	if got := counter.puts; got != putsAfterFirst {
		t.Fatalf("keyed retry without binder caused %d new object writes, want 0 (baseline %d)", got-putsAfterFirst, putsAfterFirst)
	}
	if feeds.Feeds[repoStateFeed()] != feedRef || len(docs.Documents) != docCount {
		t.Fatal("keyed retry without binder must not advance or create anything")
	}
	if state := loadRepoState(t, docs, feeds); state.Generation != 1 {
		t.Fatalf("keyed retry without binder must not advance generation, got %d", state.Generation)
	}
}

// TestLegacyStateWithoutProvenanceRetryIsFreshPublication proves backward
// compatibility: a schema-valid document written BEFORE provenance carries
// the target mapping but no recoverable operation identity. A retry of it is
// NOT answered with a fabricated prior ID — it becomes a fresh publication
// whose NEW operation identity is durably recorded, and the echoed ID is
// exactly that recorded identity.
func TestLegacyStateWithoutProvenanceRetryIsFreshPublication(t *testing.T) {
	_, _, _, _, docs, feeds, issuer, serverURL := bindingWorld(t)

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := publish.ComputeDigest(configA)
	manifestA := manifestFor(configADigest, len(configA))
	manifestDigest := publish.ComputeDigest(manifestA)

	// Seed a LEGACY repo state (generation 2, tag latest→manifestDigest) with
	// NO provenance field, plus the manifest/config objects so the retry
	// resolves coherently.
	legacy := spec.RepoStateDocument{
		Version:    1,
		Repo:       "backend/api",
		Generation: 2,
		UpdatedAt:  "2026-04-05T12:00:00Z",
		Tags:       map[string]string{"latest": manifestDigest},
		Manifests: map[string]spec.ManifestDescriptor{
			manifestDigest: {SwarmRef: "manifest-ref", MediaType: publish.MediaTypeOCIManifest, Size: int64(len(manifestA))},
		},
		Blobs: map[string]spec.BlobDescriptor{
			configADigest: {SwarmRef: "config-ref", Size: int64(len(configA)), MediaType: "application/vnd.oci.image.config.v1+json"},
		},
	}
	legacyBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}
	feeds.Feeds[repoStateFeed()] = "legacy-state-ref"
	docs.Documents["legacy-state-ref"] = legacyBytes
	docs.Documents["manifest-ref"] = manifestA
	docs.Documents["config-ref"] = configA

	decoded, err := spec.DecodeRepoStateDocument(legacyBytes)
	if err != nil {
		t.Fatalf("legacy state must stay schema-valid: %v", err)
	}
	if len(decoded.TagPublications) != 0 {
		t.Fatalf("legacy state must carry no provenance entries: %+v", decoded.TagPublications)
	}

	// No-key retry of the legacy target: a FRESH publication (no fabrication).
	plain := &taggedPusher{t: t, serverURL: serverURL, issuer: issuer}
	resp := plain.put("latest", manifestA)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("legacy-target retry must become a fresh publication 201, got %d (%s)", resp.StatusCode, body)
	}
	echoed := resp.Header.Get(OperationIDHeader)
	if echoed == "" {
		t.Fatal("fresh publication must return its operation identity")
	}
	state := loadRepoState(t, docs, feeds)
	if state.Generation != 3 {
		t.Fatalf("fresh publication must advance to generation 3, got %d", state.Generation)
	}
	pub, ok := state.TagPublications["latest"]
	if !ok {
		t.Fatalf("fresh publication must record provenance: %+v", state.TagPublications)
	}
	if pub.OperationID != echoed {
		t.Fatalf("echoed operation ID must be the EXACT recorded identity %q, got %q", pub.OperationID, echoed)
	}
	if pub.Generation != 3 || pub.Digest != manifestDigest {
		t.Fatalf("provenance entry must match the fresh publication: %+v", pub)
	}
}

// TestForgedProvenanceFailsClosedThroughRealHandler proves forged per-tag
// provenance (a document whose provenance entry violates strict decode)
// fails closed at the handler: the request is answered with a fixed generic
// error, the forged operation ID is never echoed in the status line, body, or
// headers, and no publication happens.
func TestForgedProvenanceFailsClosedThroughRealHandler(t *testing.T) {
	_, _, _, _, docs, feeds, issuer, serverURL := bindingWorld(t)

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := publish.ComputeDigest(configA)
	manifestA := manifestFor(configADigest, len(configA))
	manifestDigest := publish.ComputeDigest(manifestA)
	forgedID := `forge"d-id`

	forged := spec.RepoStateDocument{
		Version:    1,
		Repo:       "backend/api",
		Generation: 2,
		UpdatedAt:  "2026-04-05T12:00:00Z",
		Tags:       map[string]string{"latest": manifestDigest},
		Manifests: map[string]spec.ManifestDescriptor{
			manifestDigest: {SwarmRef: "manifest-ref", MediaType: publish.MediaTypeOCIManifest, Size: int64(len(manifestA))},
		},
		Blobs: map[string]spec.BlobDescriptor{
			configADigest: {SwarmRef: "config-ref", Size: int64(len(configA)), MediaType: "application/vnd.oci.image.config.v1+json"},
		},
		TagPublications: map[string]spec.TagPublication{
			"latest": {OperationID: forgedID, Generation: 2, Digest: manifestDigest},
		},
	}
	forgedBytes, err := json.Marshal(forged)
	if err != nil {
		t.Fatalf("marshal forged state: %v", err)
	}
	feeds.Feeds[repoStateFeed()] = "forged-state-ref"
	docs.Documents["forged-state-ref"] = forgedBytes
	docs.Documents["manifest-ref"] = manifestA
	docs.Documents["config-ref"] = configA

	if _, err := spec.DecodeRepoStateDocument(forgedBytes); err == nil {
		t.Fatal("forged provenance must fail strict decode")
	}

	plain := &taggedPusher{t: t, serverURL: serverURL, issuer: issuer}
	resp := plain.put("latest", manifestA)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusCreated {
		t.Fatalf("forged provenance must never produce a 201, got 201 (%s)", body)
	}
	if strings.Contains(string(body), forgedID) || strings.Contains(resp.Header.Get(OperationIDHeader), forgedID) {
		t.Fatalf("forged provenance operation ID must never be echoed: body=%s header=%q", body, resp.Header.Get(OperationIDHeader))
	}
}
