package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// scriptedCommitter is an in-process model of the control-plane feed signer
// for Handler-level tests: on success it points the (in-memory) feed at the
// committed reference exactly like the real signer's Bee write, so the
// read-after-write verification can resolve the effective feed. It can inject
// the signer's stable sentinel classes and force a stale feed target.
type scriptedCommitter struct {
	feeds         *resolve.MemoryFeedStore
	err           error // returned on EVERY commit call (signer failure class)
	writeFeed     bool  // success ALSO advances the feed (like a real signer)
	wrongRef      string
	conflictAfter int // succeed for the first N calls, then ErrCommitConflict
	calls         int
	lastReq       publish.FeedCommitRequest
}

func (s *scriptedCommitter) Commit(_ context.Context, req publish.FeedCommitRequest) (publish.FeedCommitResult, error) {
	s.calls++
	s.lastReq = req
	if s.conflictAfter > 0 && s.calls > s.conflictAfter {
		return publish.FeedCommitResult{}, publish.ErrCommitConflict
	}
	if s.err != nil {
		return publish.FeedCommitResult{}, s.err
	}
	ref := publish.CanonicalReference(req.Reference)
	if s.writeFeed {
		if s.wrongRef != "" {
			s.feeds.Feeds[publish.CanonicalTopic(req.Topic)] = s.wrongRef
		} else {
			s.feeds.Feeds[publish.CanonicalTopic(req.Topic)] = ref
		}
	}
	return publish.FeedCommitResult{
		OperationID: req.OperationID,
		Feed:        publish.CanonicalTopic(req.Topic),
		Reference:   ref,
	}, nil
}

// failingBuilder injects an unknown internal failure BELOW the publisher's
// validation boundary.
type failingBuilder struct{ err error }

func (b failingBuilder) BuildNext(spec.RepoStateDocument, publish.BuildInput) (spec.RepoStateDocument, error) {
	return spec.RepoStateDocument{}, b.err
}

// task14World builds the first-push world plus a live test server.
func task14World(t *testing.T) (*Handler, *resolve.MemoryDocumentStore, *resolve.MemoryFeedStore, *auth.RegistryTokenIssuer, string) {
	t.Helper()
	h, docs, feeds, issuer := newFirstPushWorld(t)
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return h, docs, feeds, issuer, server.URL
}

// decodeErrorPayload decodes the fixed Distribution error envelope.
func decodeErrorPayload(t *testing.T, body []byte) (code string, message string) {
	t.Helper()
	var payload struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode error payload: %v (%s)", err, body)
	}
	if len(payload.Errors) != 1 {
		t.Fatalf("expected exactly one error entry, got %+v", payload.Errors)
	}
	return payload.Errors[0].Code, payload.Errors[0].Message
}

// manifestFor builds a valid OCI manifest body referencing the given config
// digest and returns the body.
func manifestFor(configDigest string, configSize int) []byte {
	return []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":` +
		fmt.Sprintf("%d", configSize) + `,"digest":"` + configDigest + `"},"layers":[]}`)
}

// TestPublicationErrorMatrixThroughRealHandler drives every stable public
// error class through the REAL handler: 401 authentication, 403 policy
// denial, 400 validation, 409 idempotency/generation conflict, 503
// dependency, 502 verified-integrity mismatch, and 500 unknown internal —
// with generic messages and no injected marker leakage in the public body.
func TestPublicationErrorMatrixThroughRealHandler(t *testing.T) {
	const marker = "MARKER_T14_9f2b"

	t.Run("401 missing token", func(t *testing.T) {
		h, _, feeds, _, serverURL := task14World(t)
		stage := &countingStaging{RegistryStore: h.Staging}
		h.Staging = stage
		req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = testServiceHost
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
		if stage.created != 0 {
			t.Fatalf("401 created %d staging sessions", stage.created)
		}
		if _, ok := feeds.Feeds[repoStateFeed()]; ok {
			t.Fatal("401 must not create the repo-state feed")
		}
	})

	t.Run("403 policy denial", func(t *testing.T) {
		h, _, _, issuer, serverURL := task14World(t)
		h.PushAuthorizer = &recordingPushAuthorizer{allowed: false, batchID: "batch-repo"}
		body := manifestFor("sha256:"+strings.Repeat("a", 64), 24)
		req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		pushTo(t, req, issuer)
		req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("policy denial must be 403, got %d (%s)", resp.StatusCode, respBody)
		}
		code, _ := decodeErrorPayload(t, respBody)
		if code != ErrorCodeDenied {
			t.Fatalf("expected DENIED code, got %q", code)
		}
	})

	t.Run("400 malformed manifest", func(t *testing.T) {
		_, _, _, issuer, serverURL := task14World(t)
		req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", strings.NewReader(`{"`+marker+`":1}`))
		if err != nil {
			t.Fatal(err)
		}
		pushTo(t, req, issuer)
		req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
		code, _ := decodeErrorPayload(t, respBody)
		if code != ErrorCodeManifestInvalid {
			t.Fatalf("expected MANIFEST_INVALID, got %q", code)
		}
		if bytes.Contains(respBody, []byte(marker)) {
			t.Fatalf("400 echoes attacker marker: %s", respBody)
		}
	})

	t.Run("400 oversized manifest body", func(t *testing.T) {
		h, _, feeds, issuer, serverURL := task14World(t)
		h.PushAuthorizer = &recordingPushAuthorizer{allowed: true, batchID: "batch-repo"}
		big := bytes.Repeat([]byte("x"), publish.MaxArtifactBodyBytes+1)
		req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", bytes.NewReader(big))
		if err != nil {
			t.Fatal(err)
		}
		pushTo(t, req, issuer)
		req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("oversized body must be 400, got %d", resp.StatusCode)
		}
		if _, ok := feeds.Feeds[repoStateFeed()]; ok {
			t.Fatal("oversized body must not create the repo-state feed")
		}
	})

	t.Run("409 idempotency conflict", func(t *testing.T) {
		h, _, feeds, issuer, serverURL := task14World(t)
		committer := &scriptedCommitter{feeds: feeds, err: publish.ErrCommitConflict}
		h.Publisher.Commits = committer
		configBytes := []byte(`{"architecture":"amd64"}`)
		configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
		resp := putManifest(t, serverURL, issuer, manifestFor(configDigest, len(configBytes)))
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("commit conflict must be 409, got %d (%s)", resp.StatusCode, respBody)
		}
		code, message := decodeErrorPayload(t, respBody)
		if code != ErrorCodeManifestConflict {
			t.Fatalf("expected MANIFEST_CONFLICT, got %q", code)
		}
		if strings.Contains(message, marker) {
			t.Fatalf("409 leaks injected marker: %s", respBody)
		}
		if _, ok := feeds.Feeds[repoStateFeed()]; ok {
			t.Fatal("conflicted publication must never advance the feed")
		}
		remaining, err := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
		if err != nil || len(remaining) != 1 {
			t.Fatalf("conflicted publication must retain staging, got %+v (err %v)", remaining, err)
		}
	})

	t.Run("503 dependency unavailable", func(t *testing.T) {
		h, _, feeds, issuer, serverURL := task14World(t)
		committer := &scriptedCommitter{feeds: feeds, err: fmt.Errorf("%w: "+marker, publish.ErrCommitBackend)}
		h.Publisher.Commits = committer
		configBytes := []byte(`{"architecture":"amd64"}`)
		configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
		resp := putManifest(t, serverURL, issuer, manifestFor(configDigest, len(configBytes)))
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("commit backend failure must be 503, got %d (%s)", resp.StatusCode, respBody)
		}
		code, message := decodeErrorPayload(t, respBody)
		if code != ErrorCodeDependencyUnavailable {
			t.Fatalf("expected DEPENDENCY_UNAVAILABLE, got %q", code)
		}
		if strings.Contains(message, marker) {
			t.Fatalf("503 leaks injected marker: %s", respBody)
		}
		remaining, _ := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
		if len(remaining) != 1 {
			t.Fatalf("dependency failure must retain staging, got %+v", remaining)
		}
	})

	t.Run("502 verification integrity mismatch", func(t *testing.T) {
		h, _, feeds, issuer, serverURL := task14World(t)
		// The signer "succeeds" but the effective feed points at a different
		// reference than the committed one — verification must fail closed.
		committer := &scriptedCommitter{feeds: feeds, writeFeed: true, wrongRef: "wrong-state-ref-" + marker}
		h.Publisher.Commits = committer
		configBytes := []byte(`{"architecture":"amd64"}`)
		configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
		resp := putManifest(t, serverURL, issuer, manifestFor(configDigest, len(configBytes)))
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("stale feed read-back must be 502, got %d (%s)", resp.StatusCode, respBody)
		}
		code, message := decodeErrorPayload(t, respBody)
		if code != ErrorCodePublicationUnverified {
			t.Fatalf("expected PUBLICATION_UNVERIFIED, got %q", code)
		}
		if strings.Contains(message, marker) {
			t.Fatalf("502 leaks injected marker: %s", respBody)
		}
		remaining, _ := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
		if len(remaining) != 1 || remaining[0].Digest != configDigest {
			t.Fatalf("verification failure must retain the referenced staging, got %+v", remaining)
		}
	})

	t.Run("500 unknown internal", func(t *testing.T) {
		h, _, _, issuer, serverURL := task14World(t)
		h.Publisher.Builder = failingBuilder{err: errors.New(marker)}
		configBytes := []byte(`{"architecture":"amd64"}`)
		configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
		resp := putManifest(t, serverURL, issuer, manifestFor(configDigest, len(configBytes)))
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("unknown internal failure must be 500, got %d (%s)", resp.StatusCode, respBody)
		}
		code, message := decodeErrorPayload(t, respBody)
		if code != ErrorCodeInternal {
			t.Fatalf("expected UNKNOWN code, got %q", code)
		}
		if message != "internal server error" {
			t.Fatalf("500 must carry the fixed generic message, got %q", message)
		}
		if strings.Contains(message, marker) {
			t.Fatalf("500 leaks injected marker: %s", respBody)
		}
	})
}

// TestLostResponseRetryVerifiedOneAdvancement is the restart-safe core: after
// an effective publication whose 201 response is lost, the retry (same
// process, then a RECONSTRUCTED handler over the same durable stores) is
// recognized through the feed read-back, fully verified, and answered with the
// same verified 201 — exactly one feed advancement, no new object targets, and
// the same operation identity.
func TestLostResponseRetryVerifiedOneAdvancement(t *testing.T) {
	h, docs, feeds, issuer, serverURL := task14World(t)

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	first := putManifest(t, serverURL, issuer, manifestBody)
	defer first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first push status %d, want 201", first.StatusCode)
	}
	firstOpID := first.Header.Get(OperationIDHeader)
	if firstOpID == "" {
		t.Fatal("successful publication must return the operation identity header")
	}
	feedRefAfterFirst := feeds.Feeds[repoStateFeed()]
	docCountAfterFirst := len(docs.Documents)
	stateAfterFirst := loadRepoState(t, docs, feeds)
	if stateAfterFirst.Generation != 1 {
		t.Fatalf("expected generation 1 after first push, got %d", stateAfterFirst.Generation)
	}

	// Same-process retry: the client re-sends the identical request.
	second := putManifest(t, serverURL, issuer, manifestBody)
	defer second.Body.Close()
	if second.StatusCode != http.StatusCreated {
		t.Fatalf("lost-response retry status %d, want 201", second.StatusCode)
	}
	if got := second.Header.Get(OperationIDHeader); got != firstOpID {
		t.Fatalf("retry must return the same operation identity, got %q want %q", got, firstOpID)
	}
	if feeds.Feeds[repoStateFeed()] != feedRefAfterFirst {
		t.Fatal("retry must NOT advance the feed a second time")
	}
	if len(docs.Documents) != docCountAfterFirst {
		t.Fatalf("retry must not create new object targets: docs %d -> %d", docCountAfterFirst, len(docs.Documents))
	}
	if again := loadRepoState(t, docs, feeds); again.Generation != 1 {
		t.Fatalf("retry must not advance generation, got %d", again.Generation)
	}
	remaining, err := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil || len(remaining) != 0 {
		t.Fatalf("consumed staging must stay consumed after the retry, got %+v (err %v)", remaining, err)
	}

	// Restart reconstruction: a NEW handler built over the SAME durable
	// stores (fresh staging store simulates a restarted process) sees the
	// already-published target and returns the prior verified 201.
	rebuilt, issuer2 := newTestHandler(t, docs, feeds)
	server2 := httptest.NewServer(rebuilt)
	defer server2.Close()
	third := putManifest(t, server2.URL, issuer2, manifestBody)
	defer third.Body.Close()
	if third.StatusCode != http.StatusCreated {
		t.Fatalf("reconstructed-handler retry status %d, want 201", third.StatusCode)
	}
	if got := third.Header.Get(OperationIDHeader); got != firstOpID {
		t.Fatalf("reconstructed retry must return the same operation identity, got %q want %q", got, firstOpID)
	}
	if feeds.Feeds[repoStateFeed()] != feedRefAfterFirst {
		t.Fatal("reconstructed retry must NOT advance the feed")
	}
	if again := loadRepoState(t, docs, feeds); again.Generation != 1 {
		t.Fatalf("reconstructed retry must not advance generation, got %d", again.Generation)
	}
}

// TestLostResponseRetryWithCommitterExactlyOneCommit pins the same guarantee
// on the control-plane commit path: the retry never touches the signer again,
// so exactly one feed advancement and exactly one commit call occur.
func TestLostResponseRetryWithCommitterExactlyOneCommit(t *testing.T) {
	h, _, feeds, issuer, serverURL := task14World(t)
	committer := &scriptedCommitter{feeds: feeds, writeFeed: true}
	h.Publisher.Commits = committer

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	first := putManifest(t, serverURL, issuer, manifestBody)
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first push status %d, want 201", first.StatusCode)
	}
	retry := putManifest(t, serverURL, issuer, manifestBody)
	retry.Body.Close()
	if retry.StatusCode != http.StatusCreated {
		t.Fatalf("retry status %d, want 201", retry.StatusCode)
	}
	if committer.calls != 1 {
		t.Fatalf("retry must not commit again: exactly one commit call expected, got %d", committer.calls)
	}
	if feedRef := feeds.Feeds[repoStateFeed()]; feedRef != committer.lastReq.Reference {
		t.Fatalf("feed must point at the single committed reference %q, got %q", committer.lastReq.Reference, feedRef)
	}
}

// TestExplicitIdempotencyKeySameRequestSucceedsThenVerifies pins the
// caller-supplied operation identity: the SAME explicit key on the SAME
// request succeeds, is returned in the successful response, and is recognized
// as the already-published operation on a retry — zero additional writes.
func TestExplicitIdempotencyKeySameRequestSucceedsThenVerifies(t *testing.T) {
	const key = "client-t14-key-0001"
	h, docs, feeds, issuer, serverURL := task14World(t)
	// An explicit key is only ever accepted with a durable binder attached.
	binder := newDurableBindingStore()
	h.Preflight = binder

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	put := func() (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", bytes.NewReader(manifestBody))
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
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(body)
	}

	first, firstBody := put()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first push status %d (%s)", first.StatusCode, firstBody)
	}
	if got := first.Header.Get(OperationIDHeader); got != key {
		t.Fatalf("response must echo the explicit operation key, got %q", got)
	}
	feedRef := feeds.Feeds[repoStateFeed()]
	docCount := len(docs.Documents)

	// Retry with the same key: verified 201, no writes.
	second, secondBody := put()
	if second.StatusCode != http.StatusCreated {
		t.Fatalf("retry status %d (%s)", second.StatusCode, secondBody)
	}
	if got := second.Header.Get(OperationIDHeader); got != key {
		t.Fatalf("retry must echo the same operation key, got %q", got)
	}
	if feeds.Feeds[repoStateFeed()] != feedRef || len(docs.Documents) != docCount {
		t.Fatal("explicit-key retry must not write a second time")
	}
	if state := loadRepoState(t, docs, feeds); state.Generation != 1 {
		t.Fatalf("explicit-key retry must not advance generation, got %d", state.Generation)
	}
}

// TestExplicitIdempotencyKeyReuseWithDifferentPayloadConflicts pins the
// cross-request reuse rule: reusing one operation key with a DIFFERENT
// digest is a 409 with ZERO new object writes, zero feed writes, and zero
// staging consumption. The conflict is decided at the durable key binding
// BEFORE the publisher uploads the manifest or draft-state objects (the
// counting uploader proves the second request never reaches the object
// store), and the durable binding survives restarts (covered in depth by
// TestExplicitKeyConflictSurvivesHandlerReconstruction).
func TestExplicitIdempotencyKeyReuseWithDifferentPayloadConflicts(t *testing.T) {
	const key = "client-t14-key-0002"
	h, docs, feeds, issuer, serverURL := task14World(t)
	committer := &scriptedCommitter{feeds: feeds, writeFeed: true, conflictAfter: 1}
	h.Publisher.Commits = committer
	binder := newDurableBindingStore()
	h.Preflight = binder
	counter := &countingObjectUploader{inner: docs}
	h.Publisher.Objects = counter

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))

	putWith := func(body []byte) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", bytes.NewReader(body))
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

	first := putWith(manifestA)
	bodyA, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first push status %d (%s)", first.StatusCode, bodyA)
	}
	feedAfterFirst := feeds.Feeds[repoStateFeed()]

	// Same key, DIFFERENT payload: must conflict BEFORE any feed write.
	configB := []byte(`{"architecture":"arm64"}`)
	configBDigest := stageBlob(t, serverURL, issuer, configB, "application/vnd.oci.image.config.v1+json")
	manifestB := manifestFor(configBDigest, len(configB))

	second := putWith(manifestB)
	defer second.Body.Close()
	bodyB, _ := io.ReadAll(second.Body)
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("key reuse with different payload must be 409, got %d (%s)", second.StatusCode, bodyB)
	}
	code, _ := decodeErrorPayload(t, bodyB)
	if code != ErrorCodeManifestConflict {
		t.Fatalf("expected MANIFEST_CONFLICT, got %q", code)
	}
	if counter.puts != 2 {
		t.Fatalf("key-reuse conflict caused %d object writes, want exactly the first publication's 2 (manifest + state before the conflict is decided)", counter.puts)
	}
	if binder.conflicts != 1 {
		t.Fatalf("expected exactly one durable binding conflict, got %d", binder.conflicts)
	}
	if feeds.Feeds[repoStateFeed()] != feedAfterFirst {
		t.Fatal("key-reuse conflict must leave the feed exactly at the first publication")
	}
	remaining, _ := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if len(remaining) != 1 || remaining[0].Digest != configBDigest {
		t.Fatalf("key-reuse conflict must not consume the new staged blob, got %+v", remaining)
	}
	if state := loadRepoState(t, docs, feeds); state.Generation != 1 {
		t.Fatalf("key-reuse conflict must not advance generation, got %d", state.Generation)
	}
}

// TestInvalidIdempotencyKeyZeroWrites proves an invalid or oversized explicit
// operation key is rejected BEFORE any object, feed, or staging write.
func TestInvalidIdempotencyKeyZeroWrites(t *testing.T) {
	badKeys := []string{
		strings.Repeat("k", publish.OperationIDMaxLen+1), // oversized
		`bad"quote`,
		"a<b",
		"a>b",
		"a&b",
		"é",
		"a\u00a0b", // U+00A0: non-ASCII byte the server must reject
	}

	for i, key := range badKeys {
		t.Run(fmt.Sprintf("key_%d", i), func(t *testing.T) {
			h, docs, feeds, issuer, serverURL := task14World(t)
			counter := &countingObjectUploader{inner: docs}
			h.Publisher.Objects = counter
			h.Publisher.Feeds = feeds

			configBytes := []byte(`{"architecture":"amd64"}`)
			configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
			manifestBody := manifestFor(configDigest, len(configBytes))

			req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", bytes.NewReader(manifestBody))
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
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("invalid key must be 400, got %d (%s)", resp.StatusCode, respBody)
			}
			code, message := decodeErrorPayload(t, respBody)
			if code != ErrorCodeManifestInvalid {
				t.Fatalf("expected MANIFEST_INVALID, got %q", code)
			}
			if strings.Contains(message, key) {
				t.Fatalf("invalid key value must never be echoed: %q (body %s)", key, respBody)
			}
			if counter.puts != 0 {
				t.Fatalf("invalid key caused %d object writes, want 0", counter.puts)
			}
			if _, ok := feeds.Feeds[repoStateFeed()]; ok {
				t.Fatal("invalid key must not create the repo-state feed")
			}
			remaining, _ := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
			if len(remaining) != 1 {
				t.Fatalf("invalid key must leave staging untouched, got %+v", remaining)
			}
		})
	}
}

// TestRepublishOldDigestAfterTagChangeIsNotReplayedAsRetry proves a later
// intentional republish of an old digest after the tag changed away is NOT
// mistaken for a retry: it is a real publication that advances the feed,
// never a silently replayed ancient success.
func TestRepublishOldDigestAfterTagChangeIsNotReplayedAsRetry(t *testing.T) {
	h, docs, feeds, issuer, serverURL := task14World(t)
	committer := &scriptedCommitter{feeds: feeds, writeFeed: true}
	h.Publisher.Commits = committer

	configA := []byte(`{"architecture":"amd64"}`)
	configADigest := stageBlob(t, serverURL, issuer, configA, "application/vnd.oci.image.config.v1+json")
	manifestA := manifestFor(configADigest, len(configA))

	first := putManifest(t, serverURL, issuer, manifestA)
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first push status %d, want 201", first.StatusCode)
	}

	configB := []byte(`{"architecture":"arm64"}`)
	configBDigest := stageBlob(t, serverURL, issuer, configB, "application/vnd.oci.image.config.v1+json")
	manifestB := manifestFor(configBDigest, len(configB))
	second := putManifest(t, serverURL, issuer, manifestB)
	second.Body.Close()
	if second.StatusCode != http.StatusCreated {
		t.Fatalf("second push status %d, want 201", second.StatusCode)
	}
	if refAfterB := feeds.Feeds[repoStateFeed()]; refAfterB == "" {
		t.Fatal("second push must have advanced the feed")
	}

	// Republish the OLD digest A after the tag moved to B: a REAL new
	// publication (the feed advances), never the replayed first success.
	third := putManifest(t, serverURL, issuer, manifestA)
	defer third.Body.Close()
	body, _ := io.ReadAll(third.Body)
	if third.StatusCode != http.StatusCreated {
		t.Fatalf("republish of old digest must be 201 as a new publication, got %d (%s)", third.StatusCode, body)
	}
	if committer.calls != 3 {
		t.Fatalf("each publication must commit exactly once: got %d commits", committer.calls)
	}
	state := loadRepoState(t, docs, feeds)
	if state.Generation != 3 {
		t.Fatalf("republish must advance the feed to generation 3, got %d", state.Generation)
	}
	if state.Tags["latest"] != publish.ComputeDigest(manifestA) {
		t.Fatalf("tag must point at the republished digest, got %+v", state.Tags)
	}
}

// TestVerifiedSuccessClearsOnlyConsumedStaging re-pins the referenced-only
// consumption rule with the verification gate in place: only the digests the
// verified manifest referenced are consumed; unrelated staged blobs survive.
func TestVerifiedSuccessClearsOnlyConsumedStaging(t *testing.T) {
	h, docs, feeds, issuer, serverURL := task14World(t)

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	unrelated := []byte("unrelated-staged-blob")
	unrelatedDigest := stageBlob(t, serverURL, issuer, unrelated, "application/octet-stream")

	manifestBody := manifestFor(configDigest, len(configBytes))
	resp := putManifest(t, serverURL, issuer, manifestBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("publish status %d, want 201", resp.StatusCode)
	}
	state := loadRepoState(t, docs, feeds)
	if _, ok := state.Blobs[configDigest]; !ok {
		t.Fatalf("referenced blob must be published: %+v", state.Blobs)
	}
	if _, ok := state.Blobs[unrelatedDigest]; ok {
		t.Fatalf("unrelated staged blob must not enter state: %+v", state.Blobs)
	}
	remaining, _ := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if len(remaining) != 1 || remaining[0].Digest != unrelatedDigest {
		t.Fatalf("unrelated staged blob must survive verification-clear, got %+v", remaining)
	}
}

// TestConcurrentIdenticalFirstPushSingleVerifiedPublication proves exactly one
// verified publication under concurrency: two identical first pushes produce
// two verified 201s, one feed target, generation one, and no data race.
func TestConcurrentIdenticalFirstPushSingleVerifiedPublication(t *testing.T) {
	_, docs, feeds, issuer, serverURL := task14World(t)

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	const workers = 2
	var wg sync.WaitGroup
	statuses := make([]int, workers)
	opIDs := make([]string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", bytes.NewReader(manifestBody))
			if err != nil {
				t.Errorf("create request: %v", err)
				return
			}
			pushTo(t, req, issuer)
			req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("request failed: %v", err)
				return
			}
			defer resp.Body.Close()
			statuses[i] = resp.StatusCode
			opIDs[i] = resp.Header.Get(OperationIDHeader)
		}(i)
	}
	wg.Wait()

	for i := 0; i < workers; i++ {
		if statuses[i] != http.StatusCreated {
			t.Fatalf("worker %d: expected 201, got %d", i, statuses[i])
		}
		if opIDs[i] == "" || opIDs[i] != opIDs[0] {
			t.Fatalf("workers must share one deterministic operation identity, got %+v", opIDs)
		}
	}
	state := loadRepoState(t, docs, feeds)
	if state.Generation != 1 {
		t.Fatalf("exactly one logical advancement expected, got generation %d", state.Generation)
	}
	if len(feeds.Feeds) != 3 { // auth + stamp + repo-state
		t.Fatalf("expected exactly one repo-state feed target, got %d feeds", len(feeds.Feeds))
	}
}

// TestManifestPutReturnsOperationIdentityHeaderOnEveryVerifiedSuccess pins the
// response contract on the plain (no explicit key) path too.
func TestManifestPutReturnsOperationIdentityHeaderOnEveryVerifiedSuccess(t *testing.T) {
	_, _, _, issuer, serverURL := task14World(t)
	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	resp := putManifest(t, serverURL, issuer, manifestBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("publish status %d, want 201", resp.StatusCode)
	}
	opID := resp.Header.Get(OperationIDHeader)
	if opID == "" {
		t.Fatal("201 must carry the X-Uncloud-Operation-Id header")
	}
	if err := publish.ValidateOperationID(opID); err != nil {
		t.Fatalf("returned operation identity must satisfy the operation-ID grammar: %v", err)
	}
}
