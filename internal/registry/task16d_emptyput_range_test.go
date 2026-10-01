package registry

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/staging"
)

// ---------------------------------------------------------------------------
// Task 16 repair round 2: Content-Range must be parsed INDEPENDENTLY of the
// request body length. At HEAD, uploadPut parsed Content-Range only inside the
// `if r.ContentLength != 0` guard, so an ACTIVE empty-body final PUT above an
// existing session — with a malformed, a positive-span, or a stale/future
// Content-Range — bypassed grammar/offset/span/length validation and FINALIZED
// the already staged bytes. These tests close that gap: every declared range
// on an active PUT is fully validated even when the body is empty; an empty
// body can never satisfy a positive inclusive span; and a truly absent range
// with an empty body remains a valid body-free finalize.
// ---------------------------------------------------------------------------

// emptyPut builds an empty-body PUT (Body nil => known Content-Length 0, the
// served "Content-Length: 0" wire form) with an optional Content-Range.
func emptyPut(t *testing.T, loc, digest string, issuer *auth.RegistryTokenIssuer, rng string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, loc+"?digest="+digest, nil)
	if err != nil {
		t.Fatalf("empty put req: %v", err)
	}
	if rng != "" {
		req.Header.Set("Content-Range", rng)
	}
	pushTo(t, req, issuer)
	return req
}

// assertActiveUnchanged asserts the active session is byte/offset/state intact.
func assertActiveUnchanged(t *testing.T, h *Handler, id string, want []byte) {
	t.Helper()
	if got := stagedBytes(t, h.Staging, id); !bytes.Equal(got, want) {
		t.Fatalf("staged bytes changed: got %q, want %q", got, want)
	}
	if st, err := h.Staging.Status(context.Background(), id, "backend/api", "user:alice"); err != nil || st.State != staging.StateActive || st.Offset != int64(len(want)) {
		t.Fatalf("session must stay active at offset %d, got %+v err=%v", len(want), st, err)
	}
}

// RED: empty (known Content-Length 0) PUT with a MALFORMED Content-Range must
// be rejected 400 with ZERO uploader calls and no byte/offset/state change —
// not silently finalize the staged bytes.
func TestUploadPutEmptyKnownLengthMalformedRangeZeroMutation(t *testing.T) {
	serverURL, issuer, up, h := newUploadWorld(t)
	loc := startUpload(t, serverURL, issuer)
	id := uploadIDFromLoc(loc)
	patch(t, loc, issuer, "0-4", []byte("aaaaa"), false)
	digest := publish.ComputeDigest([]byte("aaaaa"))

	resp := doReqExpect(t, emptyPut(t, loc, digest, issuer, "garbage"), http.StatusBadRequest)
	resp.Body.Close()
	if up.putStreamCalls != 0 {
		t.Fatalf("malformed-range empty PUT caused %d PutStream calls, want 0", up.putStreamCalls)
	}
	assertActiveUnchanged(t, h, id, []byte("aaaaa"))

	// A corrected retry WITHOUT the range still finalizes the staged bytes.
	resp2 := doReqExpect(t, emptyPut(t, loc, digest, issuer, ""), http.StatusCreated)
	resp2.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("range-free retry caused %d PutStream calls, want exactly 1", up.putStreamCalls)
	}
}

// RED: an empty (known Content-Length 0) PUT with a POSITIVE declared span on
// a session whose offset matches cannot be satisfied by zero bytes: reject 400
// before any staging/hash/uploader side effect.
func TestUploadPutEmptyKnownLengthPositiveSpanZeroMutation(t *testing.T) {
	serverURL, issuer, up, h := newUploadWorld(t)
	loc := startUpload(t, serverURL, issuer)
	id := uploadIDFromLoc(loc)
	// Empty session: offset 0, so declared start 0 == current offset and the
	// ONLY reason this must fail is that the positive span (1 byte) is
	// unsatisfiable by an empty body.
	digest := publish.ComputeDigest([]byte{}) // digest of the (unreached) empty blob

	resp := doReqExpect(t, emptyPut(t, loc, digest, issuer, "0-0"), http.StatusBadRequest)
	resp.Body.Close()
	if up.putStreamCalls != 0 {
		t.Fatalf("positive-span empty PUT caused %d PutStream calls, want 0", up.putStreamCalls)
	}
	assertActiveUnchanged(t, h, id, []byte{})
}

// RED: an empty (known Content-Length 0) PUT with a STALE or FUTURE range must
// be rejected 416 with the accurate current Range — never finalize staged bytes.
func TestUploadPutEmptyKnownLengthStaleFutureRange416(t *testing.T) {
	serverURL, issuer, up, h := newUploadWorld(t)
	loc := startUpload(t, serverURL, issuer)
	id := uploadIDFromLoc(loc)
	patch(t, loc, issuer, "0-4", []byte("aaaaa"), false) // offset 5
	digest := publish.ComputeDigest([]byte("aaaaa"))

	for _, tc := range []struct {
		name string
		rng  string
	}{
		{"stale", "0-2"},
		{"future", "6-9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := doReqExpect(t, emptyPut(t, loc, digest, issuer, tc.rng), http.StatusRequestedRangeNotSatisfiable)
			if got := resp.Header.Get("Range"); got != "0-4" {
				t.Fatalf("expected authoritative Range 0-4, got %q", got)
			}
			resp.Body.Close()
			if up.putStreamCalls != 0 {
				t.Fatalf("%s-range empty PUT caused %d PutStream calls, want 0", tc.name, up.putStreamCalls)
			}
			assertActiveUnchanged(t, h, id, []byte("aaaaa"))
		})
	}

	// The range-free retry still finalizes.
	resp2 := doReqExpect(t, emptyPut(t, loc, digest, issuer, ""), http.StatusCreated)
	resp2.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("range-free retry caused %d PutStream calls, want exactly 1", up.putStreamCalls)
	}
}

// Coverage: a chunked (unknown Content-Length) EMPTY body declaring a positive
// span is rejected 400 via the exact-span reader, with ZERO uploader calls and
// no state change. Served directly for a deterministic byte-exact body.
func TestUploadPutChunkedEmptyBodyPositiveRangeZeroMutation(t *testing.T) {
	h, issuer, up := directMemoryWorld(t)
	id := directStart(t, h, issuer)
	if code := serveDirect(t, h, directChunked(t, http.MethodPatch, "/v2/backend/api/blobs/uploads/"+id, issuer, "0-4", []byte("aaaaa"))); code != http.StatusAccepted {
		t.Fatalf("base patch: got %d, want 202", code)
	}
	digest := publish.ComputeDigest([]byte("aaaaa"))

	if code := serveDirect(t, h, directChunked(t, http.MethodPut, "/v2/backend/api/blobs/uploads/"+id+"?digest="+digest, issuer, "5-9", []byte{})); code != http.StatusBadRequest {
		t.Fatalf("chunked empty final chunk with positive span: got %d, want 400", code)
	}
	if up.putStreamCalls != 0 {
		t.Fatalf("chunked empty final chunk caused %d PutStream calls, want 0", up.putStreamCalls)
	}
	if got := stagedBytes(t, h.Staging, id); !bytes.Equal(got, []byte("aaaaa")) {
		t.Fatalf("staged bytes changed: got %q", got)
	}
	if st, _ := h.Staging.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateActive || st.Offset != 5 {
		t.Fatalf("session must stay active at offset 5, got %+v", st)
	}
}

// Coverage: a truly absent Content-Range with an empty body remains a VALID
// body-free finalize of the already staged bytes (201, one uploader call).
func TestUploadPutEmptyBodyNoRangeStillFinalizes(t *testing.T) {
	serverURL, issuer, up, _ := newUploadWorld(t)
	loc := startUpload(t, serverURL, issuer)
	body := []byte(`{"finalize":true}`)
	patch(t, loc, issuer, "", body, false)
	digest := publish.ComputeDigest(body)

	resp := doReqExpect(t, emptyPut(t, loc, digest, issuer, ""), http.StatusCreated)
	resp.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("range-free finalize caused %d PutStream calls, want exactly 1", up.putStreamCalls)
	}
}

// Coverage: on a FINALIZED session, an empty PUT with a Content-Range is a 409
// (immutable), with ZERO uploader calls and the staged bytes untouched.
func TestUploadFinalizedRetryRangeOnEmptyConflict409(t *testing.T) {
	serverURL, issuer, up, h := newUploadWorld(t)
	loc := startUpload(t, serverURL, issuer)
	id := uploadIDFromLoc(loc)
	body := []byte(`{"a":1}`)
	patch(t, loc, issuer, "", body, false)
	digest := publish.ComputeDigest(body)
	finalizeOK(t, loc, digest, issuer)
	if up.putStreamCalls != 1 {
		t.Fatalf("first finalize expect exactly 1 PutStream, got %d", up.putStreamCalls)
	}

	resp := doReqExpect(t, emptyPut(t, loc, digest, issuer, "0-4"), http.StatusConflict)
	resp.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("range-on-finalized empty PUT caused %d PutStream calls, want 1", up.putStreamCalls)
	}
	if st, _ := h.Staging.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateFinalized {
		t.Fatalf("session must stay finalized, got %+v", st)
	}
}
