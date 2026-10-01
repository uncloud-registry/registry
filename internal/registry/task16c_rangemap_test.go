package registry

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/staging"
)

// ---------------------------------------------------------------------------
// Pre-review Task 16 consistency: a chunked (unknown-length) body LARGER than
// its declared Content-Range span is a FRAMING / range mismatch, not an
// upload-quota overflow. An equivalent known Content-Length mismatch already
// maps 400; the chunked over-long body must too, with zero staging mutation and
// zero uploader calls. A body that exceeds the ACTUAL configured upload quota
// (no published range governing it) stays a genuine 413 quota overflow.
//
// These tests serve the handler DIRECTLY (like the reader-fault tests) so the
// request body is observed byte-exactly, deterministically overriding the
// Go-transport chunked framing that can hide the one-extra-byte case.
// ---------------------------------------------------------------------------

// directMemoryWorld builds a memory-backing handler over the standard fixture
// policies/feeds with a counting uploader wired in.
func directMemoryWorld(t *testing.T) (*Handler, *auth.RegistryTokenIssuer, *countingUploader) {
	t.Helper()
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	docs.Documents["auth-policy-ref"] = []byte(`{"version":1,"defaultAccess":"deny","repos":{"backend/api":{"pull":["anonymous","user:alice"],"push":["user:alice"]}}}`)
	docs.Documents["stamp-policy-ref"] = []byte(`{"version":1,"defaultPolicy":{"batchID":"batch-default","allowPushFor":["user:alice"]},"repos":{"backend/api":{"batchID":"batch-repo","allowPushFor":["user:alice"]}}}`)
	feeds.Feeds[spec.AuthPolicyFeedRef("0xaliceowner")] = "auth-policy-ref"
	feeds.Feeds[spec.StampPolicyFeedRef("0xaliceowner")] = "stamp-policy-ref"
	h, issuer := newHandlerWithStage(t, docs, feeds, staging.NewMemoryStore())
	up := &countingUploader{MemoryDocumentStore: h.Uploader.(*resolve.MemoryDocumentStore)}
	h.Uploader = up
	return h, issuer, up
}

func directStart(t *testing.T, h *Handler, issuer *auth.RegistryTokenIssuer) string {
	t.Helper()
	start, _ := http.NewRequest(http.MethodPost, "/v2/backend/api/blobs/uploads/", nil)
	pushTo(t, start, issuer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, start)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("direct start: %d", rec.Code)
	}
	return uploadIDFromLoc(rec.Header().Get("Location"))
}

// directChunked builds a chunked (ContentLength -1) request whose body is a
// byte-exact reader, so the handler observes every byte deterministically.
func directChunked(t *testing.T, method, path string, issuer *auth.RegistryTokenIssuer, rng string, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, path, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		t.Fatalf("direct chunked req: %v", err)
	}
	req.ContentLength = -1
	if rng != "" {
		req.Header.Set("Content-Range", rng)
	}
	pushTo(t, req, issuer)
	return req
}

func serveDirect(t *testing.T, h *Handler, req *http.Request) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestUploadPatchChunkedOneExtraByteBeyondSpanMaps400 proves a chunked body one
// byte past the declared span is a RANGE/framing mismatch -> 400 (never 413),
// with ZERO staging mutation and ZERO uploader calls. It fails at HEAD (413).
func TestUploadPatchChunkedOneExtraByteBeyondSpanMaps400(t *testing.T) {
	h, issuer, up := directMemoryWorld(t)
	id := directStart(t, h, issuer)

	code := serveDirect(t, h, directChunked(t, http.MethodPatch, "/v2/backend/api/blobs/uploads/"+id, issuer, "0-4", []byte("abcdeX")))
	if code != http.StatusBadRequest {
		t.Fatalf("one-extra-byte PATCH: got %d, want 400", code)
	}
	if up.putStreamCalls != 0 {
		t.Fatalf("over-long PATCH caused %d PutStream calls, want 0", up.putStreamCalls)
	}
	if got := stagedBytes(t, h.Staging, id); len(got) != 0 {
		t.Fatalf("expected empty staged bytes, got %q", got)
	}
	if st, _ := h.Staging.Status(context.Background(), id, "backend/api", "user:alice"); st.Offset != 0 {
		t.Fatalf("offset moved: %+v", st)
	}
	// The error is the fixed range-invalid payload, not a quota-too-large one.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, directChunked(t, http.MethodPatch, "/v2/backend/api/blobs/uploads/"+id, issuer, "0-4", []byte("abcdeXY")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("repeat one-extra PATCH: got %d, want 400", rec.Code)
	}
	if code, msg := decodeErrorPayload(t, rec.Body.Bytes()); code != "BLOB_UPLOAD_INVALID" || msg != messageRangeInvalid {
		t.Fatalf("over-long range must answer range-invalid 400, got code=%q msg=%q", code, msg)
	}
}

// TestUploadPutChunkedOneExtraByteFinalChunkMaps400 proves a final PUT chunk one
// byte past its declared span is rejected 400 with ZERO uploader calls, the
// committed bytes/offset stay byte-exact, and the session is not finalized.
func TestUploadPutChunkedOneExtraByteFinalChunkMaps400(t *testing.T) {
	h, issuer, up := directMemoryWorld(t)
	id := directStart(t, h, issuer)

	// Establish a 5-byte base chunk.
	if code := serveDirect(t, h, directChunked(t, http.MethodPatch, "/v2/backend/api/blobs/uploads/"+id, issuer, "0-4", []byte("aaaaa"))); code != http.StatusAccepted {
		t.Fatalf("base PATCH: %d", code)
	}

	digest := publish.ComputeDigest([]byte("aaaaabbbbbX"))
	code := serveDirect(t, h, directChunked(t, http.MethodPut, "/v2/backend/api/blobs/uploads/"+id+"?digest="+digest, issuer, "5-9", []byte("bbbbbX")))
	if code != http.StatusBadRequest {
		t.Fatalf("one-extra-byte final chunk: got %d, want 400", code)
	}
	if up.putStreamCalls != 0 {
		t.Fatalf("over-long final chunk caused %d PutStream calls, want 0", up.putStreamCalls)
	}
	if got := stagedBytes(t, h.Staging, id); !bytes.Equal(got, []byte("aaaaa")) {
		t.Fatalf("staged bytes changed: got %q, want %q", got, "aaaaa")
	}
	if st, _ := h.Staging.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateActive || st.Offset != 5 {
		t.Fatalf("session must remain active at offset 5, got %+v", st)
	}
}

// TestUploadPatchChunkedNoRangeOversizeStays413 proves the DISCRIMINATOR: a
// chunked body with NO Content-Range that exceeds the ACTUAL configured upload
// quota (h.MaxUploadBytes) is a genuine quota overflow and stays 413, with zero
// staging mutation. It must not be reclassified as a range/framing error.
func TestUploadPatchChunkedNoRangeOversizeStays413(t *testing.T) {
	h, issuer, up := directMemoryWorld(t)
	h.MaxUploadBytes = 6
	id := directStart(t, h, issuer)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, directChunked(t, http.MethodPatch, "/v2/backend/api/blobs/uploads/"+id, issuer, "", []byte("0123456789")))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-quota chunked PATCH: got %d, want 413", rec.Code)
	}
	if up.putStreamCalls != 0 {
		t.Fatalf("over-quota PATCH caused %d PutStream calls, want 0", up.putStreamCalls)
	}
	if got := stagedBytes(t, h.Staging, id); len(got) != 0 {
		t.Fatalf("expected empty staged bytes, got %q", got)
	}
	if st, _ := h.Staging.Status(context.Background(), id, "backend/api", "user:alice"); st.Offset != 0 {
		t.Fatalf("offset moved: %+v", st)
	}
	if code, msg := decodeErrorPayload(t, rec.Body.Bytes()); code != "BLOB_UPLOAD_INVALID" || msg != messageUploadTooLarge {
		t.Fatalf("over-quota body must answer too-large 413, got code=%q msg=%q", code, msg)
	}
}
