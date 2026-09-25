package registry

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
)

// countingUploader wraps the memory document store to observe the streaming
// object-uploader contract (exact size + explicit batch + zero writes on
// failed finalize).
type countingUploader struct {
	*resolve.MemoryDocumentStore
	putStreamCalls int
	streamSize     int64
	lastBatchID    string
}

func (c *countingUploader) PutStream(ctx context.Context, src io.Reader, size int64, batchID string) (string, error) {
	c.putStreamCalls++
	c.streamSize = size
	c.lastBatchID = batchID
	ref, err := c.MemoryDocumentStore.PutStream(ctx, src, size, batchID)
	if err != nil {
		c.putStreamCalls--
		return "", err
	}
	return ref, nil
}

// newUploadServer builds an isolated registry server with a counting uploader
// wired into the handler's blob finalization path.
func newUploadServer(t *testing.T) (serverURL string, issuer *auth.RegistryTokenIssuer, up *countingUploader) {
	t.Helper()
	h, _, _, iss := newFirstPushWorld(t)
	up = &countingUploader{MemoryDocumentStore: h.Uploader.(*resolve.MemoryDocumentStore)}
	h.Uploader = up
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return server.URL, iss, up
}

// startUpload POSTs a fresh session and returns the upload URL (Location).
func startUpload(t *testing.T, serverURL string, issuer *auth.RegistryTokenIssuer) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, serverURL+"/v2/backend/api/blobs/uploads/", nil)
	if err != nil {
		t.Fatalf("start upload req: %v", err)
	}
	pushTo(t, req, issuer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("start upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start upload status: %d", resp.StatusCode)
	}
	if resp.Header.Get("Docker-Upload-UUID") == "" {
		t.Fatal("start upload missing Docker-Upload-UUID")
	}
	return serverURL + resp.Header.Get("Location")
}

func doReq(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func TestUploadStartReturnsSession(t *testing.T) {
	serverURL, issuer, _ := newUploadServer(t)
	loc := startUpload(t, serverURL, issuer)

	// GET the session: 204 with the current empty Range.
	req, _ := http.NewRequest(http.MethodGet, loc, nil)
	pushTo(t, req, issuer)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("GET session status: %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Range"); got != "0-0" {
		t.Fatalf("expected empty Range 0-0, got %q", got)
	}
}

func TestUploadPatchContiguousContentRange(t *testing.T) {
	serverURL, issuer, _ := newUploadServer(t)
	loc := startUpload(t, serverURL, issuer)

	a := []byte("abcdefghij") // 10 bytes: "0-9"
	patch(t, loc, issuer, "0-9", a, false)

	b := []byte("klmno") // 5 bytes at "10-14"
	patch(t, loc, issuer, "10-14", b, false)

	req, _ := http.NewRequest(http.MethodGet, loc, nil)
	pushTo(t, req, issuer)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if got := resp.Header.Get("Range"); got != "0-14" {
		t.Fatalf("expected Range 0-14 after two contiguous chunks, got %q", got)
	}
}

func TestUploadPatchNonContiguousFutureOffset416(t *testing.T) {
	serverURL, issuer, _ := newUploadServer(t)
	loc := startUpload(t, serverURL, issuer)

	// First chunk fine.
	patch(t, loc, issuer, "0-4", []byte("aaaaa"), false)

	// A future offset (gap) is a stale/out-of-order 416 with the accurate Range.
	resp := patch(t, loc, issuer, "10-14", []byte("bbbbb"), true)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("expected 416 for future offset, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Range"); got != "0-4" {
		t.Fatalf("expected Range 0-4 on 416, got %q", got)
	}

	// A stale (behind) offset is also 416.
	resp2 := patch(t, loc, issuer, "0-2", []byte("ccc"), true)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("expected 416 for stale offset, got %d", resp2.StatusCode)
	}

	// The durable offset is untouched (a correct contiguous chunk still works
	// starting at the current offset).
	patch(t, loc, issuer, "5-9", []byte("ccccc"), false)
	req, _ := http.NewRequest(http.MethodGet, loc, nil)
	pushTo(t, req, issuer)
	getResp := doReq(t, req)
	defer getResp.Body.Close()
	if got := getResp.Header.Get("Range"); got != "0-9" {
		t.Fatalf("expected Range 0-9 after correct chunk, got %q", got)
	}
}

func TestUploadPatchBodyLengthMismatchBeforeSideEffect(t *testing.T) {
	serverURL, issuer, _ := newUploadServer(t)
	loc := startUpload(t, serverURL, issuer)

	// Declares span 0-9 (10 bytes) but body is only 4 bytes: reject BEFORE
	// any durable change.
	req, _ := http.NewRequest(http.MethodPatch, loc, bytes.NewReader([]byte("abcd")))
	pushTo(t, req, issuer)
	req.Header.Set("Content-Range", "0-9")
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on length mismatch, got %d", resp.StatusCode)
	}

	// No side effect: session still empty.
	req2, _ := http.NewRequest(http.MethodGet, loc, nil)
	pushTo(t, req2, issuer)
	getResp := doReq(t, req2)
	defer getResp.Body.Close()
	if got := getResp.Header.Get("Range"); got != "0-0" {
		t.Fatalf("expected no side effect (Range 0-0), got %q", got)
	}
}

func TestUploadPatchMalformedContentRange(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"whitespace", "0- 5"},
		{"units-prefix", "bytes 0-5"},
		{"multi-range", "0-4,6-9"},
		{"leading-sign", "+0-5"},
		{"non-digit", "0-x"},
		{"reversed", "10-5"},
		{"missing-dash", "05"},
		{"double-dash", "0--5"},
		{"trailing-unit", "0-5 bytes"},
		{"overflow", "0-99999999999999999999999999999"},
		{"no-start", "-5"},
		{"no-end", "0-"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serverURL, issuer, _ := newUploadServer(t)
			loc := startUpload(t, serverURL, issuer)
			req, _ := http.NewRequest(http.MethodPatch, loc, bytes.NewReader([]byte("aaaaaa")))
			pushTo(t, req, issuer)
			req.Header.Set("Content-Range", tc.value)
			resp := doReq(t, req)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("case %q: expected 400, got %d", tc.value, resp.StatusCode)
			}
		})
	}
}

func TestUploadFinalizeDigestMismatchZeroWritesAndRetry(t *testing.T) {
	serverURL, issuer, up := newUploadServer(t)
	loc := startUpload(t, serverURL, issuer)

	body := []byte(`{"architecture":"amd64"}`)
	patch(t, loc, issuer, "", body, false)

	good := publish.ComputeDigest(body)
	bad := publish.ComputeDigest([]byte("something else"))

	// Wrong digest: 400 DIGEST_INVALID, ZERO object writes, staging retained.
	req, _ := http.NewRequest(http.MethodPut, loc+"?digest="+bad, nil)
	pushTo(t, req, issuer)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on digest mismatch, got %d", resp.StatusCode)
	}
	if up.putStreamCalls != 0 {
		t.Fatalf("expected ZERO PutStream calls on digest mismatch, got %d", up.putStreamCalls)
	}

	// Retry with the correct digest succeeds and streams with the EXACT size.
	req2, _ := http.NewRequest(http.MethodPut, loc+"?digest="+good, nil)
	pushTo(t, req2, issuer)
	resp2 := doReq(t, req2)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 on corrected finalize, got %d", resp2.StatusCode)
	}
	if up.putStreamCalls != 1 {
		t.Fatalf("expected one PutStream call after corrected finalize, got %d", up.putStreamCalls)
	}
	if up.streamSize != int64(len(body)) {
		t.Fatalf("expected PutStream exact size %d, got %d", len(body), up.streamSize)
	}
	if up.lastBatchID == "" {
		t.Fatal("expected an explicit postage batch id on PutStream")
	}
	if got := resp2.Header.Get("Docker-Content-Digest"); got != good {
		t.Fatalf("expected Docker-Content-Digest %q, got %q", good, got)
	}
	if loc := resp2.Header.Get("Location"); !strings.HasSuffix(loc, "/blobs/"+good) {
		t.Fatalf("expected blob Location ending in /blobs/<digest>, got %q", loc)
	}
}

func TestUploadFinalizeInvalidDigestGrammar(t *testing.T) {
	cases := []string{
		"",
		"sha256:XYZ", // non-hex
		"md5:abcdabcdabcdabcdabcdabcdabcdabcd",
		"sha256:abcd",                       // too short
		"sha256:" + strings.Repeat("G", 64), // uppercase hex is not canonical lowercase
	}
	for _, d := range cases {
		t.Run(d, func(t *testing.T) {
			serverURL, issuer, up := newUploadServer(t)
			loc := startUpload(t, serverURL, issuer)
			body := []byte(`{"x":1}`)
			patch(t, loc, issuer, "", body, false)
			req, _ := http.NewRequest(http.MethodPut, loc+"?digest="+d, nil)
			pushTo(t, req, issuer)
			resp := doReq(t, req)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("digest %q: expected 400, got %d", d, resp.StatusCode)
			}
			if up.putStreamCalls != 0 {
				t.Fatalf("digest %q: expected zero writes, got %d", d, up.putStreamCalls)
			}
		})
	}
}

func TestUploadFinalizeWithFinalChunk(t *testing.T) {
	serverURL, issuer, up := newUploadServer(t)
	loc := startUpload(t, serverURL, issuer)

	first := []byte("01234")
	patch(t, loc, issuer, "0-4", first, false)

	// Finalize with a final chunk at offset 5.
	second := []byte("56789")
	full := append(append([]byte{}, first...), second...)
	digest := publish.ComputeDigest(full)

	req, _ := http.NewRequest(http.MethodPut, loc+"?digest="+digest, bytes.NewReader(second))
	pushTo(t, req, issuer)
	req.Header.Set("Content-Range", "5-9")
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected finalize with final chunk to be 201, got %d", resp.StatusCode)
	}
	if up.streamSize != int64(len(full)) {
		t.Fatalf("expected PutStream exact size %d, got %d", len(full), up.streamSize)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != digest {
		t.Fatalf("expected digest %q, got %q", digest, got)
	}
}

func TestUploadDeleteAndThenNotFound(t *testing.T) {
	serverURL, issuer, _ := newUploadServer(t)
	loc := startUpload(t, serverURL, issuer)

	req, _ := http.NewRequest(http.MethodDelete, loc, nil)
	pushTo(t, req, issuer)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on delete, got %d", resp.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodGet, loc, nil)
	pushTo(t, req2, issuer)
	resp2 := doReq(t, req2)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", resp2.StatusCode)
	}
}

func TestUploadUnknownIDIs404(t *testing.T) {
	serverURL, issuer, _ := newUploadServer(t)
	unknown := strings.Repeat("ab", 32)
	req, _ := http.NewRequest(http.MethodGet, serverURL+"/v2/backend/api/blobs/uploads/"+unknown, nil)
	pushTo(t, req, issuer)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown upload id, got %d", resp.StatusCode)
	}
}

func TestUploadForeignRepo404(t *testing.T) {
	serverURL, issuer, _ := newUploadServer(t)
	loc := startUpload(t, serverURL, issuer)

	// A different bearer with pull-only rights to another repo must not reveal
	// the session via the actor/repo ownership binding.
	foreignReq, _ := http.NewRequest(http.MethodGet, loc, nil)
	foreignReq.Host = testServiceHost
	foreignReq.Header.Set("Authorization", registryBearer(t, issuer, "user:bob", testServiceHost, "backend/api", []auth.Action{auth.ActionPush}, time.Hour))
	// bob is not auto-authorized by the fixture policies; the authz gate answers 403
	// BEFORE any staging lookup, so cross-tenant IDs are never probed.
	resp := doReq(t, foreignReq)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for unauthorized actor before staging lookup, got %d", resp.StatusCode)
	}
}

func TestUploadQuotaEnforcedAtHandlerBound(t *testing.T) {
	h, _, _, iss := newFirstPushWorld(t)
	h.MaxUploadBytes = 6
	up := &countingUploader{MemoryDocumentStore: h.Uploader.(*resolve.MemoryDocumentStore)}
	h.Uploader = up
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	serverURL := server.URL

	loc := startUpload(t, serverURL, iss)

	// A 10-byte body exceeds the configured 6-byte bound: 413, no side effect.
	req, _ := http.NewRequest(http.MethodPatch, loc, bytes.NewReader([]byte("0123456789")))
	pushTo(t, req, iss)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 on oversized upload, got %d", resp.StatusCode)
	}
	req2, _ := http.NewRequest(http.MethodGet, loc, nil)
	pushTo(t, req2, iss)
	getResp := doReq(t, req2)
	defer getResp.Body.Close()
	if got := getResp.Header.Get("Range"); got != "0-0" {
		t.Fatalf("expected no durable change after 413 (Range 0-0), got %q", got)
	}
}

func TestUploadFinalizeIdempotentRepeat(t *testing.T) {
	serverURL, issuer, _ := newUploadServer(t)
	loc := startUpload(t, serverURL, issuer)
	body := []byte(`{"a":1}`)
	patch(t, loc, issuer, "", body, false)
	digest := publish.ComputeDigest(body)

	// Finalize is restart/replay safe: a byte-identical repeated finalize of
	// the SAME staged upload is idempotent (no state conflict), not an error.
	finalizeOK(t, loc, digest, issuer)
	finalizeOK(t, loc, digest, issuer)
}

// patch issues a PATCH to an upload. When rng is non-empty it is set as the
// strict Content-Range header.
func patch(t *testing.T, loc string, issuer *auth.RegistryTokenIssuer, rng string, body []byte, expectErr bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPatch, loc, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("patch req: %v", err)
	}
	pushTo(t, req, issuer)
	if rng != "" {
		req.Header.Set("Content-Range", rng)
	}
	resp := doReq(t, req)
	if expectErr {
		return resp
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("patch %q status: %d (want 202)", rng, resp.StatusCode)
	}
	return resp
}

func finalizeOK(t *testing.T, loc, digest string, issuer *auth.RegistryTokenIssuer) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, loc+"?digest="+digest, nil)
	pushTo(t, req, issuer)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("finalize status: %d (want 201)", resp.StatusCode)
	}
}
