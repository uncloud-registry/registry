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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
)

// pullBlobDigest is the canonical digest of the seeded blob body
// ("blob-bytes"), matching the descriptor seedRegistryDocuments records.
func pullBlobDigest(t *testing.T) string {
	t.Helper()
	return publish.ComputeDigest([]byte("blob-bytes"))
}

// pullManifestDigest is the canonical digest of the seeded manifest body
// ({"schemaVersion":2}), matching the descriptor seedRegistryDocuments
// records.
func pullManifestDigest(t *testing.T) string {
	t.Helper()
	return publish.ComputeDigest([]byte(`{"schemaVersion":2}`))
}

// newPullWorld seeds the shared registry repo state and returns a handler
// wired to in-memory documents and feeds (the handler's bounded reader and
// object stream are both backed by the same MemoryDocumentStore) plus the
// token issuer its verifier accepts.
func newPullWorld(t *testing.T) (*Handler, *resolve.MemoryDocumentStore, *resolve.MemoryFeedStore, *auth.RegistryTokenIssuer) {
	t.Helper()
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)
	h, issuer := newTestHandler(t, docs, feeds)
	return h.(*Handler), docs, feeds, issuer
}

// pullGet issues an authenticated-free GET (anonymous pull is allowed for the
// seeded repo) against the given path on the test server with a canonical
// Host header.
func pullGet(t *testing.T, baseURL string, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if err != nil {
		t.Fatalf("create pull request: %v", err)
	}
	req.Host = testServiceHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pull request failed: %v", err)
	}
	return resp
}

// decodeErrorCode extracts the first Distribution error code from an error
// payload.
func decodeErrorCode(t *testing.T, body []byte) string {
	t.Helper()
	var payload struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode error payload: %v (body %s)", err, body)
	}
	if len(payload.Errors) == 0 {
		t.Fatalf("error payload has no errors: %s", body)
	}
	return payload.Errors[0].Code
}

// --- manifest integrity ---

// TestPullManifestRejectsWrongBytes proves a manifest whose stored bytes do
// not match its committed digest is rejected BEFORE any body is written: the
// response is a data-free 502 INTEGRITY_ERROR and the corrupt manifest bytes
// never reach the client.
func TestPullManifestRejectsWrongBytes(t *testing.T) {
	t.Parallel()

	h, docs, _, _ := newPullWorld(t)
	corrupt := []byte(`{"schemaVersion":9}`)
	docs.Documents["manifest-ref"] = corrupt

	server := httptest.NewServer(h)
	defer server.Close()

	resp := pullGet(t, server.URL, "/v2/backend/api/manifests/latest")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("corrupt manifest must be 502, got %d (body %s)", resp.StatusCode, body)
	}
	if code := decodeErrorCode(t, body); code != ErrorCodeIntegrity {
		t.Fatalf("corrupt manifest must be INTEGRITY_ERROR, got %q", code)
	}
	if bytes.Contains(body, corrupt) || bytes.Contains(body, []byte("schemaVersion")) {
		t.Fatalf("corrupt manifest bytes must never be returned: %s", body)
	}
}

// TestPullManifestRejectsSizeMismatch proves a manifest whose stored byte
// LENGTH disagrees with its committed descriptor size is rejected data-free,
// never returned as success.
func TestPullManifestRejectsSizeMismatch(t *testing.T) {
	t.Parallel()

	h, docs, _, _ := newPullWorld(t)
	stored := []byte(`{"schemaVersion":2}` + "x") // 20 bytes vs committed 19
	docs.Documents["manifest-ref"] = stored

	server := httptest.NewServer(h)
	defer server.Close()

	resp := pullGet(t, server.URL, "/v2/backend/api/manifests/latest")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("size-mismatched manifest must be 502, got %d (body %s)", resp.StatusCode, body)
	}
	if code := decodeErrorCode(t, body); code != ErrorCodeIntegrity {
		t.Fatalf("size-mismatched manifest must be INTEGRITY_ERROR, got %q", code)
	}
	if bytes.Contains(body, stored) {
		t.Fatalf("stored manifest bytes must never be returned: %s", body)
	}
}

// TestPullManifestRejectsBackendReadError proves a manifest object read
// failure is a DISTINCT data-free 502 MANIFEST_BLOB_UNKNOWN (the content is
// unavailable, not corrupt) — the failure text and refs never reach the body.
func TestPullManifestRejectsBackendReadError(t *testing.T) {
	t.Parallel()

	h, _, _, _ := newPullWorld(t)
	h.BoundedBytes = &failingBoundedReader{err: fmt.Errorf("bee read %q: %w", "manifest-ref", errors.New(errMarker))}

	server := httptest.NewServer(h)
	defer server.Close()

	resp := pullGet(t, server.URL, "/v2/backend/api/manifests/latest")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("manifest read failure must be 502, got %d (body %s)", resp.StatusCode, body)
	}
	if code := decodeErrorCode(t, body); code != "MANIFEST_BLOB_UNKNOWN" {
		t.Fatalf("manifest read failure must be MANIFEST_BLOB_UNKNOWN (distinct from integrity), got %q", code)
	}
	// No marker, ref, or manifest content may leak.
	for _, leak := range []string{"manifest-ref", errMarker, "schemaVersion"} {
		if bytes.Contains(body, []byte(leak)) {
			t.Fatalf("manifest read failure leaked %q: %s", leak, body)
		}
	}
}

// --- blob integrity ---

// TestPullBlobRejectsWrongBytes proves a blob whose stored bytes do not match
// its committed digest is pre-verified into a temp file and REJECTED before
// any success header is committed: 502 INTEGRITY_ERROR, data-free.
func TestPullBlobRejectsWrongBytes(t *testing.T) {
	t.Parallel()

	h, docs, _, _ := newPullWorld(t)
	corrupt := []byte("WRONG-BYTES")
	docs.Documents["blob-ref"] = corrupt

	server := httptest.NewServer(h)
	defer server.Close()

	resp := pullGet(t, server.URL, "/v2/backend/api/blobs/"+pullBlobDigest(t))
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("corrupt blob must be 502, got %d (body %s)", resp.StatusCode, body)
	}
	if code := decodeErrorCode(t, body); code != ErrorCodeIntegrity {
		t.Fatalf("corrupt blob must be INTEGRITY_ERROR, got %q", code)
	}
	if bytes.Contains(body, corrupt) {
		t.Fatalf("corrupt blob bytes must never be returned: %s", body)
	}
}

// TestPullBlobRejectsSizeMismatch proves a blob stored at a length that
// disagrees with its committed descriptor size is rejected data-free.
func TestPullBlobRejectsSizeMismatch(t *testing.T) {
	t.Parallel()

	h, docs, _, _ := newPullWorld(t)
	docs.Documents["blob-ref"] = []byte("tiny") // 4 bytes vs committed 10

	server := httptest.NewServer(h)
	defer server.Close()

	resp := pullGet(t, server.URL, "/v2/backend/api/blobs/"+pullBlobDigest(t))
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("size-mismatched blob must be 502, got %d (body %s)", resp.StatusCode, body)
	}
	if code := decodeErrorCode(t, body); code != ErrorCodeIntegrity {
		t.Fatalf("size-mismatched blob must be INTEGRITY_ERROR, got %q", code)
	}
	if bytes.Contains(body, []byte("tiny")) {
		t.Fatalf("stored blob bytes must never be returned: %s", body)
	}
}

// TestPullBlobRejectsBackendReadError proves a blob object read failure is a
// DISTINCT data-free 502 BLOB_UNKNOWN — never INTEGRITY_ERROR and never the
// raw failure text.
func TestPullBlobRejectsBackendReadError(t *testing.T) {
	t.Parallel()

	h, _, _, _ := newPullWorld(t)
	h.ObjectStream = &failingObjectStreamer{err: fmt.Errorf("bee stream %q: %w", "blob-ref", errors.New(errMarker))}

	server := httptest.NewServer(h)
	defer server.Close()

	resp := pullGet(t, server.URL, "/v2/backend/api/blobs/"+pullBlobDigest(t))
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("blob read failure must be 502, got %d (body %s)", resp.StatusCode, body)
	}
	if code := decodeErrorCode(t, body); code != "BLOB_UNKNOWN" {
		t.Fatalf("blob read failure must be BLOB_UNKNOWN (distinct from integrity), got %q", code)
	}
	for _, leak := range []string{"blob-ref", errMarker, "blob-bytes"} {
		if bytes.Contains(body, []byte(leak)) {
			t.Fatalf("blob read failure leaked %q: %s", leak, body)
		}
	}
}

// TestPullBlobHeadMetadataOnly pins the documented HEAD strategy: HEAD is
// descriptor-metadata-only (200, length from the committed descriptor, no
// content read), while the SAME corrupt content on GET fails closed with 502.
// HTTP status cannot change after bytes are sent, so integrity enforcement
// lives on the body-bearing GET.
func TestPullBlobHeadMetadataOnly(t *testing.T) {
	t.Parallel()

	h, docs, _, _ := newPullWorld(t)
	docs.Documents["blob-ref"] = []byte("WRONG-BYTES") // corrupt: digest mismatch

	server := httptest.NewServer(h)
	defer server.Close()

	headReq, err := http.NewRequest(http.MethodHead, server.URL+"/v2/backend/api/blobs/"+pullBlobDigest(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	headReq.Host = testServiceHost
	headResp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		t.Fatalf("blob HEAD failed: %v", err)
	}
	headBody, _ := io.ReadAll(headResp.Body)
	headResp.Body.Close()

	if headResp.StatusCode != http.StatusOK {
		t.Fatalf("blob HEAD must stay 200 metadata-only, got %d", headResp.StatusCode)
	}
	if len(headBody) != 0 {
		t.Fatalf("blob HEAD must have no body, got %d bytes", len(headBody))
	}
	if headResp.Header.Get("Content-Length") != "10" {
		t.Fatalf("blob HEAD Content-Length must come from the descriptor (10), got %q", headResp.Header.Get("Content-Length"))
	}
	if headResp.Header.Get("Docker-Content-Digest") != pullBlobDigest(t) {
		t.Fatalf("blob HEAD must carry the descriptor digest, got %q", headResp.Header.Get("Docker-Content-Digest"))
	}

	// The SAME corrupt content on GET must fail closed.
	getResp := pullGet(t, server.URL, "/v2/backend/api/blobs/"+pullBlobDigest(t))
	body, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusBadGateway {
		t.Fatalf("corrupt blob GET must fail closed, got %d (body %s)", getResp.StatusCode, body)
	}
}

// --- host normalization at the token boundary ---

// TestPullResolvesNormalizedHostForTokenComparison proves the request-boundary
// host normalization feeds BOTH registry resolution and the token service
// comparison: an uppercase request host resolves the configured canonical
// identity, and a token issued for the CANONICAL service name verifies, while
// a token issued for the RAW uppercase request host is rejected (the service
// comparison never sees the raw host).
func TestPullResolvesNormalizedHostForTokenComparison(t *testing.T) {
	t.Parallel()

	h, _, _, issuer := newPullWorld(t)
	h.PullAuthorizer = &recordingPullAuthorizer{allowed: true}

	server := httptest.NewServer(h)
	defer server.Close()

	// Token issued for the canonical service name must VERIFY when the
	// client sends the raw uppercase host (normalization happens before
	// registry resolution AND before the token service comparison).
	canonicalToken := registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour)
	req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = strings.ToUpper(testServiceHost)
	req.Header.Set("Authorization", canonicalToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("canonical-token request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("canonical-service token against raw uppercase host must verify, got %d (body %s)", resp.StatusCode, body)
	}

	// A token issued for the RAW uppercase service name must be REJECTED:
	// the comparison uses the normalized canonical host, never the raw host.
	rawToken := registryBearer(t, issuer, "user:alice", strings.ToUpper(testServiceHost), "backend/api", []auth.Action{auth.ActionPull}, time.Hour)
	req2, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Host = strings.ToUpper(testServiceHost)
	req2.Header.Set("Authorization", rawToken)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("raw-token request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("raw uppercase service token must be rejected 401, got %d (body %s)", resp2.StatusCode, body2)
	}
}

// --- failure-injection helpers ---

const errMarker = "MARKER_T20_PULL_9f31"

// failingBoundedReader injects a bounded artifact-body read failure carrying a
// marker and a ref for the pull-integrity classification tests.
type failingBoundedReader struct{ err error }

func (f *failingBoundedReader) ReadBounded(context.Context, string, int64) ([]byte, error) {
	return nil, f.err
}

// failingObjectStreamer injects an object-open failure carrying a marker and a
// ref for the blob pull-integrity classification tests.
type failingObjectStreamer struct{ err error }

func (f *failingObjectStreamer) OpenObject(context.Context, string, int64) (io.ReadCloser, error) {
	return nil, f.err
}

// concurrentPulls runs count concurrent anonymous blob GETs and asserts every
// response is the verified 200 with the exact seeded bytes — the concurrency
// safety contract for pull verification (per-request temp files, no shared
// state).
func concurrentPulls(t *testing.T, h http.Handler, count int) {
	t.Helper()
	server := httptest.NewServer(h)
	defer server.Close()

	var wg sync.WaitGroup
	errs := make(chan string, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := pullGet(t, server.URL, "/v2/backend/api/blobs/"+pullBlobDigest(t))
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Sprintf("status %d (body %s)", resp.StatusCode, body)
				return
			}
			if string(body) != "blob-bytes" {
				errs <- fmt.Sprintf("corrupted body %q", body)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

// TestPullConcurrentBlobGetsAllVerified exercises the handler's per-request
// verification temp files under concurrency.
func TestPullConcurrentBlobGetsAllVerified(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newPullWorld(t)
	concurrentPulls(t, h, 8)
}

// TestPullVerificationTempFilesCleanedUp proves the bounded verification temp
// file never survives the request, on BOTH the success and every failure path.
func TestPullVerificationTempFilesCleanedUp(t *testing.T) {
	h, docs, _, _ := newPullWorld(t)
	h.blobTempDir = t.TempDir()

	server := httptest.NewServer(h)
	defer server.Close()

	cases := []struct {
		name      string
		content   []byte
		wantCode  int
		streamErr bool
	}{
		{"verified success", []byte("blob-bytes"), http.StatusOK, false},
		{"wrong bytes", []byte("WRONG-BYTES"), http.StatusBadGateway, false},
		{"size mismatch", []byte("tiny"), http.StatusBadGateway, false},
		{"backend read error", nil, http.StatusBadGateway, true},
	}
	for _, c := range cases {
		if c.streamErr {
			h.ObjectStream = &failingObjectStreamer{err: errors.New(errMarker)}
		} else {
			docs.Documents["blob-ref"] = c.content
			h.ObjectStream = docs // restore streaming from the in-memory store
		}
		resp := pullGet(t, server.URL, "/v2/backend/api/blobs/"+pullBlobDigest(t))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.wantCode {
			t.Fatalf("%s: status %d, want %d (body %s)", c.name, resp.StatusCode, c.wantCode, body)
		}
		entries, err := os.ReadDir(h.blobTempDir)
		if err != nil {
			t.Fatalf("%s: read temp dir: %v", c.name, err)
		}
		if len(entries) != 0 {
			t.Fatalf("%s: %d verification temp files leaked: %v", c.name, len(entries), entries)
		}
	}
}
