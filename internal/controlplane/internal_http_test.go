package controlplane

import (
	"encoding/json"
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
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePath, "", `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing credential: got %d want 401", rec.Code)
	}
	// Wrong credential.
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePath, "wrong-secret", `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong credential: got %d want 401", rec.Code)
	}
	// Duplicate (even identical) header values.
	req := httptest.NewRequest(http.MethodPost, publish.InternalFeedUpdatePath, strings.NewReader(`{}`))
	req.Header.Add(publish.InternalAuthHeader, testInternalSecret)
	req.Header.Add(publish.InternalAuthHeader, testInternalSecret)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate credential: got %d want 401", rec.Code)
	}
	// Blank credential.
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePath, "   ", `{}`); rec.Code != http.StatusUnauthorized {
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
	req := httptest.NewRequest(http.MethodGet, publish.InternalFeedUpdatePath, nil)
	req.Header.Set(publish.InternalAuthHeader, testInternalSecret)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on route: got %d want 405", rec.Code)
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
		if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePath, testInternalSecret, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d want 400 (body=%q)", name, rec.Code, body)
		}
	}
	// Oversized body rejected before decode.
	big := `{"operationID":"` + strings.Repeat("x", 66000) + `"}`
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePath, testInternalSecret, big); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d want 400", rec.Code)
	}
}

// TestInternalFeedServerHappyPath drives a real signed feed commit through the
// full internal HTTP endpoint with the correct credential.
func TestInternalFeedServerHappyPath(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
		targetTags: map[string]string{"latest": "sha256:" + refHex('a')},
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	srv, err := NewInternalFeedServer(w.signer, &PublicationBinder{Store: w.store}, []byte(testInternalSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePath, testInternalSecret, string(body))
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
}

func TestInternalFeedServerErrorMapping(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	srv, err := NewInternalFeedServer(w.signer, &PublicationBinder{Store: w.store}, []byte(testInternalSecret), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Unknown registry (registryID not found) → 404.
	notFound := req
	notFound.RegistryID = 87878787
	body, _ := json.Marshal(notFound)
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePath, testInternalSecret, string(body)); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown registry: got %d want 404", rec.Code)
	}

	// Generation conflict → 409.
	conflict := req
	conflict.ExpectedGeneration = 99
	body, _ = json.Marshal(conflict)
	if rec := postFeedUpdate(t, srv, publish.InternalFeedUpdatePath, testInternalSecret, string(body)); rec.Code != http.StatusConflict {
		t.Fatalf("generation conflict: got %d want 409", rec.Code)
	}

	// Unconfigured signer backend → 503.
	unconfigured, err := newTestInternalServer(&FeedSigner{})
	if err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(req)
	if rec := postFeedUpdate(t, unconfigured, publish.InternalFeedUpdatePath, testInternalSecret, string(body)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured backend: got %d want 503", rec.Code)
	}
}
