package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/policy"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/staging"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// privateTempDir returns a 0700, symlink-free temp dir for the durable service
// (the fail-closed service rejects 0755 dirs and symlink path components).
func privateTempDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	if runtime.GOOS != "darwin" {
		return d
	}
	switch {
	case d == "/var":
		return "/private/var"
	case strings.HasPrefix(d, "/var/"):
		return "/private" + d
	case d == "/tmp":
		return "/private/tmp"
	case strings.HasPrefix(d, "/tmp/"):
		return "/private" + d
	}
	return d
}

// uploadIDFromLoc extracts the upload id from a /v2/<repo>/blobs/uploads/<id>
// Location header value.
func uploadIDFromLoc(loc string) string {
	idx := strings.LastIndex(loc, "/")
	return loc[idx+1:]
}

// newUploadWorld is newUploadServer but also returns the concrete handler so a
// test can read staged bytes and durable state directly.
func newUploadWorld(t *testing.T) (serverURL string, issuer *auth.RegistryTokenIssuer, up *countingUploader, h *Handler) {
	t.Helper()
	h, _, _, iss := newFirstPushWorld(t)
	up = &countingUploader{MemoryDocumentStore: h.Uploader.(*resolve.MemoryDocumentStore)}
	h.Uploader = up
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return server.URL, iss, up, h
}

// stagedBytes reads the current staged bytes for the fixture repo/actor.
func stagedBytes(t *testing.T, stage staging.RegistryStore, uploadID string) []byte {
	t.Helper()
	rc, _, err := stage.Open(context.Background(), uploadID, "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("open staged: %v", err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read staged: %v", err)
	}
	return b
}

// chunkedReq builds a request with an UNKNOWN content length (Transfer-Encoding:
// chunked on the wire) so the server sees ContentLength == -1 and exercises the
// exact-span reader path.
func chunkedReq(t *testing.T, method, loc string, issuer *auth.RegistryTokenIssuer, rng string, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, loc, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("chunked req: %v", err)
	}
	req.ContentLength = -1 // force chunked / unknown length
	if rng != "" {
		req.Header.Set("Content-Range", rng)
	}
	pushTo(t, req, issuer)
	return req
}

func doReqExpect(t *testing.T, req *http.Request, wantStatus int) *http.Response {
	t.Helper()
	resp := doReq(t, req)
	if resp.StatusCode != wantStatus {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected %d, got %d (body %s)", wantStatus, resp.StatusCode, body)
	}
	return resp
}

func rangeOf(t *testing.T, fullURL string, issuer *auth.RegistryTokenIssuer) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, fullURL, nil)
	pushTo(t, req, issuer)
	resp := doReq(t, req)
	defer resp.Body.Close()
	return resp.Header.Get("Range")
}

func retryPut(t *testing.T, loc, digest string, issuer *auth.RegistryTokenIssuer) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, loc+"?digest="+digest, nil)
	if err != nil {
		t.Fatalf("retry req: %v", err)
	}
	pushTo(t, req, issuer)
	return req
}

// ---------------------------------------------------------------------------
// Defect 1: short/over-long declared range must NEVER advance the durable
// offset for chunked (unknown Content-Length) PATCH and final PUT bodies. The
// byte-exact "old bytes" invariants are asserted on the DURABLE service, where
// Task-15 rollback actually trims the spool tail.
// ---------------------------------------------------------------------------

func TestUploadPatchChunkedShortRangeZeroMutation(t *testing.T) {
	dir := privateTempDir(t)
	svc, err := staging.NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("new durable service: %v", err)
	}
	defer svc.Close()
	h, issuer, _ := durableHandler(t, svc)
	server := httptest.NewServer(h)
	defer server.Close()

	loc := startUpload(t, server.URL, issuer)
	id := uploadIDFromLoc(loc)
	patch(t, loc, issuer, "0-4", []byte("aaaaa"), false)

	// Chunked PATCH declaring span 5-9 (5 bytes) with only 3 bytes of body:
	// rejected 400 BEFORE the durable offset advances; the spool tail is
	// rolled back so the OLD bytes are preserved exactly.
	resp := doReqExpect(t, chunkedReq(t, http.MethodPatch, loc, issuer, "5-9", []byte("bbb")), http.StatusBadRequest)
	defer resp.Body.Close()

	if got, want := stagedBytes(t, svc, id), []byte("aaaaa"); !bytes.Equal(got, want) {
		t.Fatalf("staged bytes changed: got %q want %q", got, want)
	}
	if st, _ := svc.Status(context.Background(), id, "backend/api", "user:alice"); st.Offset != 5 || st.State != staging.StateActive {
		t.Fatalf("session not preserved: %+v", st)
	}
	if got := rangeOf(t, loc, issuer); got != "0-4" {
		t.Fatalf("expected Range 0-4 after refused short chunk, got %q", got)
	}

	// A correct continuation at the unchanged offset still works.
	patch(t, loc, issuer, "5-9", []byte("bbbbb"), false)
	if got := rangeOf(t, loc, issuer); got != "0-9" {
		t.Fatalf("expected Range 0-9 after correct chunk, got %q", got)
	}
}

func TestUploadPatchChunkedLongRangeZeroMutation(t *testing.T) {
	dir := privateTempDir(t)
	svc, err := staging.NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("new durable service: %v", err)
	}
	defer svc.Close()
	h, issuer, _ := durableHandler(t, svc)
	server := httptest.NewServer(h)
	defer server.Close()

	loc := startUpload(t, server.URL, issuer)
	id := uploadIDFromLoc(loc)

	// Chunked PATCH declaring span 0-9 (10 bytes) with a 13-byte body: the
	// over-long body trips the bounded overflow probe → 413, zero mutation.
	resp := doReqExpect(t, chunkedReq(t, http.MethodPatch, loc, issuer, "0-9", []byte("0123456789abc")), http.StatusRequestEntityTooLarge)
	defer resp.Body.Close()

	if got := stagedBytes(t, svc, id); len(got) != 0 {
		t.Fatalf("expected empty staged bytes, got %q", got)
	}
	if st, _ := svc.Status(context.Background(), id, "backend/api", "user:alice"); st.Offset != 0 {
		t.Fatalf("offset moved: %+v", st)
	}
	if got := rangeOf(t, loc, issuer); got != "0-0" {
		t.Fatalf("expected Range 0-0 after refused long chunk, got %q", got)
	}
}

func TestUploadPutChunkedShortFinalChunkZeroMutation(t *testing.T) {
	dir := privateTempDir(t)
	svc, err := staging.NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("new durable service: %v", err)
	}
	defer svc.Close()
	h, issuer, up := durableHandler(t, svc)
	server := httptest.NewServer(h)
	defer server.Close()

	loc := startUpload(t, server.URL, issuer)
	id := uploadIDFromLoc(loc)
	patch(t, loc, issuer, "0-4", []byte("aaaaa"), false)
	digest := publish.ComputeDigest([]byte("aaaaabbbbb"))

	// Final PUT with a chunked final chunk declaring 5-9 but only 3 bytes:
	// 400, ZERO uploader calls, bytes/offset intact, not finalized.
	resp := doReqExpect(t, chunkedReq(t, http.MethodPut, loc+"?digest="+digest, issuer, "5-9", []byte("bbb")), http.StatusBadRequest)
	defer resp.Body.Close()

	if up.putStreamCalls != 0 {
		t.Fatalf("short final chunk caused %d PutStream calls, want 0", up.putStreamCalls)
	}
	if got := stagedBytes(t, svc, id); !bytes.Equal(got, []byte("aaaaa")) {
		t.Fatalf("staged bytes changed: got %q", got)
	}
	if st, _ := svc.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateActive || st.Offset != 5 {
		t.Fatalf("session must remain active at offset 5, got %+v", st)
	}
}

func TestUploadPutChunkedLongFinalChunkZeroMutation(t *testing.T) {
	dir := privateTempDir(t)
	svc, err := staging.NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("new durable service: %v", err)
	}
	defer svc.Close()
	h, issuer, up := durableHandler(t, svc)
	server := httptest.NewServer(h)
	defer server.Close()

	loc := startUpload(t, server.URL, issuer)
	id := uploadIDFromLoc(loc)
	patch(t, loc, issuer, "0-4", []byte("aaaaa"), false)
	digest := publish.ComputeDigest([]byte("aaaaabbbbbbbbb"))

	resp := doReqExpect(t, chunkedReq(t, http.MethodPut, loc+"?digest="+digest, issuer, "5-9", []byte("bbbbbbbb")), http.StatusRequestEntityTooLarge)
	defer resp.Body.Close()

	if up.putStreamCalls != 0 {
		t.Fatalf("over-long final chunk caused %d PutStream calls, want 0", up.putStreamCalls)
	}
	if got := stagedBytes(t, svc, id); !bytes.Equal(got, []byte("aaaaa")) {
		t.Fatalf("staged bytes changed: got %q", got)
	}
}

func TestUploadPatchChunkedShortRangePreservedRestart(t *testing.T) {
	dir := privateTempDir(t)
	svc, err := staging.NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("new durable service: %v", err)
	}
	h1, issuer, _ := durableHandler(t, svc)
	server1 := httptest.NewServer(h1)
	loc := startUpload(t, server1.URL, issuer)
	id := uploadIDFromLoc(loc)
	patch(t, loc, issuer, "0-4", []byte("aaaaa"), false)
	resp := doReqExpect(t, chunkedReq(t, http.MethodPatch, loc, issuer, "5-9", []byte("bbb")), http.StatusBadRequest)
	resp.Body.Close()

	// Simulate a service restart: close the old service+server and open a NEW
	// durable service over the SAME spool/db, then a new handler; the refused
	// short tail must not reappear and must not advance the offset.
	server1.Close()
	svc.Close()

	svc2, err := staging.NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen durable service: %v", err)
	}
	defer svc2.Close()
	h2, issuer2, _ := durableHandler(t, svc2)
	server2 := httptest.NewServer(h2)
	defer server2.Close()

	if got := stagedBytes(t, svc2, id); !bytes.Equal(got, []byte("aaaaa")) {
		t.Fatalf("after restart staged bytes corrupted: got %q", got)
	}
	if st, _ := svc2.Status(context.Background(), id, "backend/api", "user:alice"); st.Offset != 5 || st.State != staging.StateActive {
		t.Fatalf("after restart session wrong: %+v", st)
	}
	patch(t, server2.URL+"/v2/backend/api/blobs/uploads/"+id, issuer2, "5-9", []byte("bbbbb"), false)
	if got := rangeOf(t, server2.URL+"/v2/backend/api/blobs/uploads/"+id, issuer2); got != "0-9" {
		t.Fatalf("expected Range 0-9 after restart continuation, got %q", got)
	}
}

// --- Reader fault (a genuine transport-ish error, distinct from short EOF) ---

type faultReader struct {
	data []byte
	read int
}

func (f *faultReader) Read(p []byte) (int, error) {
	if f.read >= len(f.data) {
		return 0, errors.New("boom") // a non-EOF reader fault
	}
	n := copy(p, f.data[f.read:])
	f.read += n
	return n, nil
}

func TestUploadPatchChunkedReaderFaultZeroMutation(t *testing.T) {
	// Direct-serve so we can inject a body that faults mid-stream (unreachable
	// through the httptest transport, which frames the body itself).
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	docs.Documents["auth-policy-ref"] = []byte(`{"version":1,"defaultAccess":"deny","repos":{"backend/api":{"pull":["anonymous","user:alice"],"push":["user:alice"]}}}`)
	docs.Documents["stamp-policy-ref"] = []byte(`{"version":1,"defaultPolicy":{"batchID":"batch-default","allowPushFor":["user:alice"]},"repos":{"backend/api":{"batchID":"batch-repo","allowPushFor":["user:alice"]}}}`)
	feeds.Feeds[spec.AuthPolicyFeedRef("0xaliceowner")] = "auth-policy-ref"
	feeds.Feeds[spec.StampPolicyFeedRef("0xaliceowner")] = "stamp-policy-ref"
	h, issuer := newHandlerWithStage(t, docs, feeds, staging.NewMemoryStore())

	start, _ := http.NewRequest(http.MethodPost, "/v2/backend/api/blobs/uploads/", nil)
	pushTo(t, start, issuer)
	startRec := httptest.NewRecorder()
	h.ServeHTTP(startRec, start)
	if startRec.Code != http.StatusAccepted {
		t.Fatalf("direct start: %d", startRec.Code)
	}
	id := uploadIDFromLoc(startRec.Header().Get("Location"))

	cp, _ := http.NewRequest(http.MethodPatch, "/v2/backend/api/blobs/uploads/"+id, bytes.NewReader([]byte("aaaaa")))
	pushTo(t, cp, issuer)
	cp.Header.Set("Content-Range", "0-4")
	cpRec := httptest.NewRecorder()
	h.ServeHTTP(cpRec, cp)
	if cpRec.Code != http.StatusAccepted {
		t.Fatalf("direct initial patch: %d", cpRec.Code)
	}

	// Chunked patch with a faulting body: the genuine reader fault must NOT be
	// classified as a short range; it surfaces as a body-read failure and the
	// durable offset does not advance.
	faulty := io.NopCloser(&faultReader{data: []byte("xyz")})
	fReq, _ := http.NewRequest(http.MethodPatch, "/v2/backend/api/blobs/uploads/"+id, faulty)
	fReq.ContentLength = -1
	fReq.Header.Set("Content-Range", "5-9")
	pushTo(t, fReq, issuer)
	fRec := httptest.NewRecorder()
	h.ServeHTTP(fRec, fReq)
	if fRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on reader fault, got %d", fRec.Code)
	}
	if code, msg := decodeErrorPayload(t, fRec.Body.Bytes()); code != "BLOB_UPLOAD_INVALID" || msg == messageRangeInvalid {
		t.Fatalf("reader fault must NOT be misclassified as range-invalid: code=%q msg=%q", code, msg)
	}
	if st, _ := h.Staging.Status(context.Background(), id, "backend/api", "user:alice"); st.Offset != 5 {
		t.Fatalf("reader fault advanced offset: %+v", st)
	}
}

// ---------------------------------------------------------------------------
// Defect 3: the 416 Range refetch must run under the REQUEST context, never a
// detached context.Background that could start a read after the request dies.
// ---------------------------------------------------------------------------

// ctxSpyRegistryStore records the context handed to Status so a test can prove
// the Range refetch uses the request's cancellable context.
type ctxSpyRegistryStore struct {
	staging.RegistryStore
	statusCtx <-chan struct{}
}

func (s *ctxSpyRegistryStore) Status(ctx context.Context, id, repo, actor string) (staging.Session, error) {
	s.statusCtx = ctx.Done()
	return s.RegistryStore.Status(ctx, id, repo, actor)
}

func TestRangeRefetchUsesRequestContext(t *testing.T) {
	h, _, _, issuer := newFirstPushWorld(t)
	spy := &ctxSpyRegistryStore{RegistryStore: h.Staging}
	h.Staging = spy
	server := httptest.NewServer(h)
	defer server.Close()

	loc := startUpload(t, server.URL, issuer)
	patch(t, loc, issuer, "0-4", []byte("aaaaa"), false)

	// A future (non-contiguous) offset triggers the 416 Range refetch; the
	// refetch MUST run under the request context (Done() non-nil), never a
	// detached context.Background (Done() nil).
	resp := patch(t, loc, issuer, "10-14", []byte("bbbbb"), true)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("expected 416, got %d", resp.StatusCode)
	}
	if spy.statusCtx == nil {
		t.Fatal("Range refetch must run under the REQUEST context, not a detached context.Background read")
	}
}

// ---------------------------------------------------------------------------
// Defect 2: finalized-session retry must be externally idempotent with ZERO
// uploader calls; a body / range / changed digest on finalized is a 409.
// ---------------------------------------------------------------------------

type sharedWorld struct {
	docs  *resolve.MemoryDocumentStore
	feeds *resolve.MemoryFeedStore
}

func newSharedMemoryWorld(t *testing.T) *sharedWorld {
	t.Helper()
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	docs.Documents["auth-policy-ref"] = []byte(`{"version":1,"defaultAccess":"deny","repos":{"backend/api":{"pull":["anonymous","user:alice"],"push":["user:alice"]}}}`)
	docs.Documents["stamp-policy-ref"] = []byte(`{"version":1,"defaultPolicy":{"batchID":"batch-default","allowPushFor":["user:alice"]},"repos":{"backend/api":{"batchID":"batch-repo","allowPushFor":["user:alice"]}}}`)
	feeds.Feeds[spec.AuthPolicyFeedRef("0xaliceowner")] = "auth-policy-ref"
	feeds.Feeds[spec.StampPolicyFeedRef("0xaliceowner")] = "stamp-policy-ref"
	return &sharedWorld{docs: docs, feeds: feeds}
}

func TestUploadFinalizedRetrySameDigestZeroWrite(t *testing.T) {
	// Fresh memory world with a counting uploader.
	serverURL, issuer, up, h := newUploadWorld(t)
	loc := startUpload(t, serverURL, issuer)
	id := uploadIDFromLoc(loc)
	body := []byte(`{"architecture":"amd64"}`)
	patch(t, loc, issuer, "", body, false)
	digest := publish.ComputeDigest(body)

	finalizeOK(t, loc, digest, issuer)
	if up.putStreamCalls != 1 {
		t.Fatalf("first finalize expect exactly 1 PutStream, got %d", up.putStreamCalls)
	}

	// Idempotent retry: matching digest, no body, no range → 201 with ZERO
	// uploader calls.
	resp := doReqExpect(t, retryPut(t, loc, digest, issuer), http.StatusCreated)
	defer resp.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("retry performed %d PutStream calls, want still 1", up.putStreamCalls)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != digest {
		t.Fatalf("retry digest mismatch: got %q want %q", got, digest)
	}
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "/blobs/"+digest) {
		t.Fatalf("retry Location wrong: %q", loc)
	}
	if st, err := h.Staging.Status(context.Background(), id, "backend/api", "user:alice"); err != nil || st.State != staging.StateFinalized {
		t.Fatalf("session not finalized after retry: %+v err=%v", st, err)
	}
}

func TestUploadFinalizedRetryChangedDigestOrBody409(t *testing.T) {
	serverURL, issuer, up, h := newUploadWorld(t)
	loc := startUpload(t, serverURL, issuer)
	id := uploadIDFromLoc(loc)
	body := []byte(`{"x":1}`)
	patch(t, loc, issuer, "", body, false)
	good := publish.ComputeDigest(body)
	finalizeOK(t, loc, good, issuer)
	if up.putStreamCalls != 1 {
		t.Fatalf("first finalize expect exactly 1 PutStream, got %d", up.putStreamCalls)
	}

	// Differing digest, no body.
	other := publish.ComputeDigest([]byte("other content"))
	resp := doReqExpect(t, retryPut(t, loc, other, issuer), http.StatusConflict)
	defer resp.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("changed-digest retry caused %d PutStream calls, want 1", up.putStreamCalls)
	}

	// Same digest but WITH a body on a finalized session.
	bad, _ := http.NewRequest(http.MethodPut, loc+"?digest="+good, bytes.NewReader([]byte("extra")))
	pushTo(t, bad, issuer)
	resp2 := doReqExpect(t, bad, http.StatusConflict)
	resp2.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("body-on-finalized retry caused %d PutStream calls, want 1", up.putStreamCalls)
	}

	// Same digest but WITH a Content-Range header on a finalized session.
	badRange, _ := http.NewRequest(http.MethodPut, loc+"?digest="+good, nil)
	pushTo(t, badRange, issuer)
	badRange.Header.Set("Content-Range", "0-4")
	resp3 := doReqExpect(t, badRange, http.StatusConflict)
	resp3.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("range-on-finalized retry caused %d PutStream calls, want 1", up.putStreamCalls)
	}
	if st, _ := h.Staging.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateFinalized {
		t.Fatalf("session must stay finalized, got %+v", st)
	}
}

func TestUploadFinalizedRetryHandlerRecreationZeroWrite(t *testing.T) {
	// Handler recreation: two distinct Handler structs sharing one stage store.
	// The retry decision must read the DURABLE stored digest, not any
	// per-handler state.
	w := newSharedMemoryWorld(t)
	stage := staging.NewMemoryStore()

	h1, iss1 := newHandlerWithStage(t, w.docs, w.feeds, stage)
	s1 := httptest.NewServer(h1)
	loc := startUpload(t, s1.URL, iss1)
	body := []byte(`{"a":1}`)
	patch(t, loc, iss1, "", body, false)
	digest := publish.ComputeDigest(body)
	finalizeOK(t, loc, digest, iss1)
	id := uploadIDFromLoc(loc)
	s1.Close()

	// Stateless second handler over the SAME stage store: its own key pair and
	// verifier, its own server, and a fresh bearer from ITS issuer.
	h2, iss2 := newHandlerWithStage(t, w.docs, w.feeds, stage)
	s2 := httptest.NewServer(h2)
	defer s2.Close()
	resp := doReqExpect(t, retryPut(t, s2.URL+"/v2/backend/api/blobs/uploads/"+id, digest, iss2), http.StatusCreated)
	defer resp.Body.Close()
	if st, err := stage.Status(context.Background(), id, "backend/api", "user:alice"); err != nil || st.State != staging.StateFinalized || st.Digest != digest {
		t.Fatalf("session must stay finalized across handler recreation: %+v err=%v", st, err)
	}
}

func TestUploadFinalizedRetryAcrossServiceRestartZeroWrite(t *testing.T) {
	dir := privateTempDir(t)
	svc, err := staging.NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("new durable service: %v", err)
	}
	h1, issuer, up1 := durableHandler(t, svc)
	s1 := httptest.NewServer(h1)
	loc := startUpload(t, s1.URL, issuer)
	id := uploadIDFromLoc(loc)
	body := []byte(`{"restart":true}`)
	patch(t, loc, issuer, "", body, false)
	digest := publish.ComputeDigest(body)
	finalizeOK(t, loc, digest, issuer)
	if up1.putStreamCalls != 1 {
		t.Fatalf("first finalize expect exactly 1 PutStream, got %d", up1.putStreamCalls)
	}
	s1.Close()
	svc.Close()

	// Restart: a new durable service over the SAME spool/db (reconciliation)
	// and a fresh handler must answer the identical retry with ZERO uploader
	// calls and the exact digest/location.
	svc2, err := staging.NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("reopen durable service: %v", err)
	}
	defer svc2.Close()
	h2, issuer2, up2 := durableHandler(t, svc2)
	s2 := httptest.NewServer(h2)
	defer s2.Close()

	resp := doReqExpect(t, retryPut(t, s2.URL+"/v2/backend/api/blobs/uploads/"+id, digest, issuer2), http.StatusCreated)
	defer resp.Body.Close()
	if up2.putStreamCalls != 0 {
		t.Fatalf("restart retry caused %d PutStream calls, want ZERO", up2.putStreamCalls)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != digest {
		t.Fatalf("restart retry digest mismatch: got %q want %q", got, digest)
	}
	if st, err := svc2.Status(context.Background(), id, "backend/api", "user:alice"); err != nil || st.State != staging.StateFinalized || st.Digest != digest {
		t.Fatalf("restart retry must not disturb durable finalized metadata: %+v err=%v", st, err)
	}
}

// ---------------------------------------------------------------------------
// World / handler machinery
// ---------------------------------------------------------------------------

// hexRefUploader is a durable-friendly object uploader that returns a valid
// 64-hex bee reference (the durable service rejects "mem-ref" refs) and counts
// PutStream calls.
type hexRefUploader struct {
	putStreamCalls int
	streamSize     int64
	lastBatchID    string
}

func (u *hexRefUploader) Put(ctx context.Context, data []byte, batchID string) (string, error) {
	return "", nil
}

func (u *hexRefUploader) PutStream(ctx context.Context, src io.Reader, size int64, batchID string) (string, error) {
	u.putStreamCalls++
	u.streamSize = size
	u.lastBatchID = batchID
	if _, err := io.Copy(io.Discard, src); err != nil {
		u.putStreamCalls--
		return "", err
	}
	return "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef", nil
}

// newHandlerWithStage is the newTestHandler wiring but takes an explicit stage
// store and returns the concrete *Handler.
func newHandlerWithStage(t *testing.T, docs *resolve.MemoryDocumentStore, feeds *resolve.MemoryFeedStore, stageStore staging.RegistryStore) (*Handler, *auth.RegistryTokenIssuer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keys := testKeySet{testKeyID: pub}
	issuer, err := auth.NewRegistryTokenIssuer(priv, auth.RegistryIssuer, testKeyID)
	if err != nil {
		t.Fatalf("new registry token issuer: %v", err)
	}
	verifier := auth.NewRegistryTokenVerifier(keys, auth.RegistryIssuer, testServiceHost)
	h := NewHandler(
		resolve.RegistryResolver{
			Registries: resolve.StaticRegistryIdentityResolver{
				Hosts: map[string]resolve.RegistryIdentity{
					testServiceHost: {Host: testServiceHost, Owner: "0xaliceowner"},
				},
			},
			Docs: docs, Feeds: feeds,
		},
		docs, docs,
		policy.PullAuthorizer{Policies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}},
		policy.PushAuthorizer{
			AuthPolicies:  policy.AuthPolicyResolver{Docs: docs, Feeds: feeds},
			StampPolicies: policy.StampPolicyResolver{Docs: docs, Feeds: feeds},
		},
		BearerAuthenticator{Tokens: verifier},
		stageStore,
		publish.Publisher{Builder: publish.DefaultBuilder{}, Objects: docs, Feeds: feeds},
		nil,
		"https://auth.uncloud-registry.com/token",
	)
	return h.(*Handler), issuer
}

// durableHandler builds a handler over a durable staging service with a fresh
// hexRefUploader wired in.
func durableHandler(t *testing.T, svc staging.RegistryStore) (*Handler, *auth.RegistryTokenIssuer, *hexRefUploader) {
	t.Helper()
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	docs.Documents["auth-policy-ref"] = []byte(`{"version":1,"defaultAccess":"deny","repos":{"backend/api":{"pull":["anonymous","user:alice"],"push":["user:alice"]}}}`)
	docs.Documents["stamp-policy-ref"] = []byte(`{"version":1,"defaultPolicy":{"batchID":"batch-default","allowPushFor":["user:alice"]},"repos":{"backend/api":{"batchID":"batch-repo","allowPushFor":["user:alice"]}}}`)
	feeds.Feeds[spec.AuthPolicyFeedRef("0xaliceowner")] = "auth-policy-ref"
	feeds.Feeds[spec.StampPolicyFeedRef("0xaliceowner")] = "stamp-policy-ref"
	h, issuer := newHandlerWithStage(t, docs, feeds, svc)
	up := &hexRefUploader{}
	h.Uploader = up
	return h, issuer, up
}
