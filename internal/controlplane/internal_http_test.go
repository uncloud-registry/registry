package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
)

const testInternalSecret = "super-secret-high-entropy-credential-256b"

func postFeedUpdate(t *testing.T, srv http.Handler, path, secret, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if secret != "" {
		req.Header.Set(publish.InternalAuthHeader, secret)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func newTestInternalServer(signer *FeedSigner) (*InternalFeedServer, error) {
	return NewInternalFeedServer(signer, &PublicationBinder{}, []byte(testInternalSecret), nil)
}

// withCurrentAttempt returns a copy of req carrying the STABLE publicationID
// and a FRESHLY recomputed deterministic attempt OperationID for req's
// CURRENT fields — so a test can mutate a field (registryID,
// expectedGeneration, ...) and still pass the current protocol's
// attempt-identity derivation check.
func withCurrentAttempt(req publish.FeedCommitRequest, publicationID string) publish.FeedCommitRequest {
	req.PublicationID = publicationID
	req.OperationID = publish.ComputeCommitAttemptID(publicationID, req.RegistryID, req.Owner, req.Topic, req.Reference, req.ExpectedGeneration)
	return req
}

func TestNewInternalFeedServerRequiresSignerAndSecret(t *testing.T) {
	if _, err := NewInternalFeedServer(nil, &PublicationBinder{}, []byte(testInternalSecret), nil); err == nil {
		t.Fatal("expected error when signer is nil")
	}
	var empty *FeedSigner
	if _, err := NewInternalFeedServer(empty, &PublicationBinder{}, []byte(testInternalSecret), nil); err == nil {
		t.Fatal("expected error when signer is typed nil")
	}
	if _, err := NewInternalFeedServer(&FeedSigner{}, nil, []byte(testInternalSecret), nil); err == nil {
		t.Fatal("expected error when binder is nil")
	}
	if _, err := NewInternalFeedServer(&FeedSigner{}, &PublicationBinder{}, nil, nil); err == nil {
		t.Fatal("expected error when secret is empty")
	}
}

func TestInternalFeedServerAuthRejectsMissingAndDuplicateCredentials(t *testing.T) {
	srv, err := newTestInternalServer(&FeedSigner{})
	if err != nil {
		t.Fatal(err)
	}
	// Missing credential.
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePathV2, "", `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing credential: got %d want 401", rec.Code)
	}
	// Wrong credential.
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePathV2, "wrong-secret", `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong credential: got %d want 401", rec.Code)
	}
	// Duplicate (even identical) header values.
	req := httptest.NewRequest(http.MethodPost, publish.InternalFeedUpdatePathV2, strings.NewReader(`{}`))
	req.Header.Add(publish.InternalAuthHeader, testInternalSecret)
	req.Header.Add(publish.InternalAuthHeader, testInternalSecret)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate credential: got %d want 401", rec.Code)
	}
	// Blank credential.
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePathV2, "   ", `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("blank credential: got %d want 401", rec.Code)
	}
}

func TestInternalFeedServerRouteAndMethod(t *testing.T) {
	srv, err := newTestInternalServer(&FeedSigner{})
	if err != nil {
		t.Fatal(err)
	}
	// Wrong path → 404.
	if rec := postFeedUpdate(t, srv, "/other", testInternalSecret, `{}`); rec.Code != http.StatusNotFound {
		t.Fatalf("wrong path: got %d want 404", rec.Code)
	}
	// Wrong method on route → 405.
	req := httptest.NewRequest(http.MethodGet, publish.InternalFeedUpdatePathV2, nil)
	req.Header.Set(publish.InternalAuthHeader, testInternalSecret)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on route: got %d want 405", rec.Code)
	}
}

// TestInternalFeedServerLegacyV1PathIsRetired proves the round-3 / Finding 2
// explicit retirement: publish.InternalFeedUpdatePath (the pre-round-3 legacy
// feed-update path) is not a recognized route AT ALL on this server. It
// yields the SAME generic 404 as any unknown path regardless of method,
// credential (even a genuinely CORRECT one), or body (even a genuinely
// well-formed current-shaped request) — proving there is no second active
// identity mode reachable through it, ever, for any input.
func TestInternalFeedServerLegacyV1PathIsRetired(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	fx := simpleArtifact(t, 'd', 'e', 'f', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
		targetTags: map[string]string{"latest": "sha256:" + refHex('a')},
		artifact:   &fx,
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	publicationID := req.OperationID
	req = withCurrentAttempt(req, publicationID)

	srv, err := NewInternalFeedServer(w.signer, &PublicationBinder{Store: w.store}, []byte(testInternalSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	// POST with the CORRECT credential and a genuinely valid, current-shaped
	// body: still 404, never routed to the signer.
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePath, testInternalSecret, string(body)); rec.Code != http.StatusNotFound {
		t.Fatalf("legacy v1 path with valid credential+body: got %d want 404, body=%s", rec.Code, rec.Body.String())
	}
	// GET on the same path: still 404 (not 405 — it is not a recognized
	// route to apply method-checking to at all).
	getReq := httptest.NewRequest(http.MethodGet, publish.InternalFeedUpdatePath, nil)
	getReq.Header.Set(publish.InternalAuthHeader, testInternalSecret)
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("legacy v1 path GET: got %d want 404", getRec.Code)
	}
	// No credential at all: still 404, not 401 — the route does not exist,
	// so it never even reaches the credential check.
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePath, "", string(body)); rec.Code != http.StatusNotFound {
		t.Fatalf("legacy v1 path with no credential: got %d want 404", rec.Code)
	}

	// The feed must never have advanced, and no durable operation/execution
	// row was ever created for this attempt/publication.
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("the feed must be untouched, got %q", got)
	}
	if _, err := w.store.GetFeedSignerOperation(context.Background(), req.OperationID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("the retired legacy path must never create a durable feed_signer_operations row")
	}
	if _, err := w.store.GetPublicationExecution(context.Background(), publicationID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("the retired legacy path must never create a durable publication_states row")
	}
}

func TestInternalFeedServerRejectsMalformedBody(t *testing.T) {
	srv, err := newTestInternalServer(&FeedSigner{})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"not json":        `not json`,
		"duplicate field": `{"operationID":"a","operationID":"b"}`,
		"unknown field":   `{"registryID":1,"unknown":true}`,
		"trailing data":   `{"operationID":"a"} trailing`,
	}
	for name, body := range cases {
		if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePathV2, testInternalSecret, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d want 400 (body=%q)", name, rec.Code, body)
		}
	}
	// Oversized body rejected before decode.
	big := `{"operationID":"` + strings.Repeat("x", 66000) + `"}`
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePathV2, testInternalSecret, big); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d want 400", rec.Code)
	}
}

// TestInternalFeedServerV2RequiresPublicationID proves the current endpoint
// rejects a well-formed-but-legacy-shaped request (PublicationID empty)
// BEFORE it ever reaches the signer: 400, zero durable mutation. This closes
// the round-3 / Finding 2 gap where an omitted PublicationID could otherwise
// be silently treated as its own stable identity.
func TestInternalFeedServerV2RequiresPublicationID(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	fx := simpleArtifact(t, '0', '1', '2', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
		targetTags: map[string]string{"latest": "sha256:" + refHex('a')},
		artifact:   &fx,
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	// Deliberately legacy-shaped: PublicationID left empty.

	srv, err := NewInternalFeedServer(w.signer, &PublicationBinder{Store: w.store}, []byte(testInternalSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePathV2, testInternalSecret, string(body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty publicationID at v2: got %d want 400, body=%s", rec.Code, rec.Body.String())
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("the feed must be untouched, got %q", got)
	}
	if _, err := w.store.GetFeedSignerOperation(context.Background(), req.OperationID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("a rejected empty-publicationID request must never create a durable feed_signer_operations row")
	}
}

// TestInternalFeedServerHappyPath drives a real signed feed commit through the
// full internal HTTP endpoint (current v2 route) with the correct
// credential and the current stable-PublicationID/attempt-OperationID shape.
func TestInternalFeedServerHappyPath(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
		targetTags: map[string]string{"latest": "sha256:" + refHex('a')},
		artifact:   &fx,
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	publicationID := req.OperationID
	req = withCurrentAttempt(req, publicationID)

	srv, err := NewInternalFeedServer(w.signer, &PublicationBinder{Store: w.store}, []byte(testInternalSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePathV2, testInternalSecret, string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d want 200: %s", rec.Code, rec.Body.String())
	}
	var result publish.FeedCommitResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("bad result body: %v", err)
	}
	if result.OperationID != req.OperationID || result.Reference != req.Reference || result.Feed != req.Topic {
		t.Fatalf("unexpected result: %+v", result)
	}
	exec, err := w.store.GetPublicationExecution(context.Background(), publicationID)
	if err != nil {
		t.Fatalf("publication execution lookup: %v", err)
	}
	if exec.State != PublicationExecutionSucceeded || exec.AttemptID != req.OperationID {
		t.Fatalf("execution must terminate succeeded under this attempt, got %+v", exec)
	}
}

func TestInternalFeedServerErrorMapping(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	fx := simpleArtifact(t, 'e', 'f', 'g', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
		targetTags: map[string]string{"latest": "sha256:" + refHex('a')},
		artifact:   &fx,
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	publicationID := req.OperationID
	srv, err := NewInternalFeedServer(w.signer, &PublicationBinder{Store: w.store}, []byte(testInternalSecret), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Unknown registry (registryID not found) → 404.
	notFound := req
	notFound.RegistryID = 87878787
	notFound = withCurrentAttempt(notFound, publicationID)
	body, _ := json.Marshal(notFound)
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePathV2, testInternalSecret, string(body)); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown registry: got %d want 404", rec.Code)
	}

	// Generation conflict → 412 (the RECOVERABLE class, distinct from the
	// PERMANENT operation/binding conflict's 409 — see mapFeedSignerError).
	conflict := req
	conflict.ExpectedGeneration = 99
	conflict = withCurrentAttempt(conflict, publicationID)
	body, _ = json.Marshal(conflict)
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePathV2, testInternalSecret, string(body)); rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("generation conflict: got %d want 412", rec.Code)
	}

	// Unconfigured signer backend → 503.
	unconfigured, err := newTestInternalServer(&FeedSigner{})
	if err != nil {
		t.Fatal(err)
	}
	fresh := withCurrentAttempt(req, publicationID+"-unconfigured")
	body, _ = json.Marshal(fresh)
	if rec := postFeedUpdate(t, unconfigured, publish.InternalFeedUpdatePathV2, testInternalSecret, string(body)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured backend: got %d want 503", rec.Code)
	}
}
