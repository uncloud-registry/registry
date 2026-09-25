package registry

// Task16 repair — per-upload durable finalization protocol, driven through the
// PRODUCTION HTTP Handler and the PRODUCTION durable staging Service (never a
// copied state machine). These tests prove a single uploader write per upload
// no matter how many concurrent or retried finalize requests arrive, that a
// successful external write is always durably completed through the claim
// identity, and that an AMBIGUOUS failure (transport or post-write metadata)
// retains the claim fail-closed so every automatic retry makes ZERO object
// writes.
//
// LIMITATION (documented, by design): exactly-once external side effects plus
// automatic liveness are impossible whenever the object store has no
// idempotency key and the returned reference is lost between the write
// response and the receipt's database commit. In that window a claimed
// session legitimately stays finalizing (never reset to active, never
// re-written) and every retry returns the fixed conflict/retryable response
// until an explicit reconciliation path has authoritative receipt
// information. Bounded fail-closed uncertainty is preferred over a duplicate
// write.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/staging"
)

// programUploader is a fault-injectable object uploader whose PutStream can be
// programmed to always fail (conclusively pre-side-effect, or ambiguous). It
// delegates success and Put() to the durable-friendly hexRefUploader.
type programUploader struct {
	relay          *hexRefUploader
	err            error // non-nil => PutStream consumes src then returns err
	putStreamCalls int
}

func (u *programUploader) Put(ctx context.Context, data []byte, batchID string) (string, error) {
	return u.relay.Put(ctx, data, batchID)
}

func (u *programUploader) PutStream(ctx context.Context, src io.Reader, size int64, batchID string) (string, error) {
	u.putStreamCalls++
	if u.err != nil {
		if _, cerr := io.Copy(io.Discard, src); cerr != nil {
			u.putStreamCalls--
			return "", cerr
		}
		return "", u.err
	}
	return u.relay.PutStream(ctx, src, size, batchID)
}

// completionFaultStore wraps the production durable service and fails
// MarkFinalized when armed, simulating a metadata-receipt fault AFTER a
// successful external object-store write (bytes in Bee, reference lost).
// Everything else delegates to the real service.
type completionFaultStore struct {
	staging.RegistryStore
	arm bool
}

func (s *completionFaultStore) MarkFinalized(ctx context.Context, id, repo, actor, token, digest, beeRef, mediaType string, size int64) error {
	if s.arm {
		return staging.ErrDependency
	}
	return s.RegistryStore.MarkFinalized(ctx, id, repo, actor, token, digest, beeRef, mediaType, size)
}

// newDurableHandler builds a handler over a durable staging service with a
// fault-injectable programUploader wired in.
func newDurableHandler(t *testing.T, store staging.RegistryStore) (base string, issuer *auth.RegistryTokenIssuer, svc staging.RegistryStore, up *programUploader) {
	t.Helper()
	h, issuer, hex := durableHandler(t, store)
	up = &programUploader{relay: hex}
	h.Uploader = up
	s1 := httptest.NewServer(h)
	t.Cleanup(s1.Close)
	return s1.URL, issuer, store, up
}

func newDurableService(t *testing.T) staging.RegistryStore {
	t.Helper()
	dir := privateTempDir(t)
	svc, err := staging.NewService(context.Background(), filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("new durable service: %v", err)
	}
	t.Cleanup(func() { svc.Close() })
	return svc
}

func stageBody(t *testing.T, base string, issuer *auth.RegistryTokenIssuer, body []byte) (string, string, string) {
	t.Helper()
	loc := startUpload(t, base, issuer)
	patch(t, loc, issuer, "", body, false)
	return loc, uploadIDFromLoc(loc), publish.ComputeDigest(body)
}

// TestUploadConcurrentFinalizersExactlyOneWrite is the core reproduction: N
// concurrent finalize requests race the same upload; the durable claim
// serializes EXACTLY one winner, exactly ONE Bee write happens, and every
// loser makes ZERO uploader calls and receives the fixed conflict response.
func TestUploadConcurrentFinalizersExactlyOneWrite(t *testing.T) {
	svc := newDurableService(t)
	base, issuer, _, up := newDurableHandler(t, svc)

	body := []byte(`{"concurrent":true}`)
	_, id, digest := stageBody(t, base, issuer, body)

	const n = 6
	statuses := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := doReq(t, retryPut(t, base+"/v2/backend/api/blobs/uploads/"+id, digest, issuer))
			statuses[i] = resp.StatusCode
			resp.Body.Close()
		}(i)
	}
	wg.Wait()

	// The response distribution is NONDETERMINISTIC but strictly bounded. The
	// single claim winner always returns 201 with exactly ONE PutStream. Every
	// contender that arrives while the claim is mid-write (or after an
	// ambiguous loss that left the session finalizing) sees the durable
	// finalizing state and gets the fixed 409 conflict; a contender that
	// OBSERVES the already-committed finalization re-plays the byte-identical
	// finalize and correctly receives an IDEMPOTENT 201 with ZERO additional
	// uploader calls. So the real invariant is: at least one 201, every
	// response in {201,409}, exactly one PutStream, and one durable, unmutated
	// finalized receipt — never a fixed created=1/conflict=N-1 split, which is
	// timing-dependent and flakes when a delayed contender lands after commit.
	created, conflict := 0, 0
	for _, st := range statuses {
		switch st {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflict++
		default:
			t.Fatalf("nontrivial status %d in concurrent finalize", st)
		}
	}
	if created < 1 || created+conflict != n {
		t.Fatalf("concurrent finalize: created=%d conflict=%d (n=%d); want >=1 201 and every response in {201,409}", created, conflict, n)
	}
	if up.putStreamCalls != 1 {
		t.Fatalf("concurrent finalizers caused %d PutStream calls, want exactly 1", up.putStreamCalls)
	}
	// Durable exact finalized receipt: the winning claim identity is written
	// with the exact digest and a non-empty object reference, and is never
	// mutated by the concurrent idempotent 201s.
	if st, err := svc.Status(context.Background(), id, "backend/api", "user:alice"); err != nil || st.State != staging.StateFinalized || st.Digest != digest || st.BeeRef == "" {
		t.Fatalf("winner must durably finalize with the exact claim identity: %+v err=%v", st, err)
	}
}

// TestUploadAmbiguousFailureRetainsClaimZeroWriteOnRetry proves a generic
// transport error (conclusively NOT pre-side-effect) retains the finalizing
// claim; the session is never reset to active and a byte-identical retry makes
// ZERO additional object writes while returning the fixed conflict response.
func TestUploadAmbiguousFailureRetainsClaimZeroWriteOnRetry(t *testing.T) {
	svc := newDurableService(t)
	base, issuer, _, up := newDurableHandler(t, svc)
	up.err = errors.New("bee connection reset mid-stream")

	body := []byte(`{"ambiguous":true}`)
	_, id, digest := stageBody(t, base, issuer, body)

	first := doReqExpect(t, retryPut(t, base+"/v2/backend/api/blobs/uploads/"+id, digest, issuer), http.StatusServiceUnavailable)
	first.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("first ambiguous attempt must make exactly 1 PutStream, got %d", up.putStreamCalls)
	}
	if st, _ := svc.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateFinalizing {
		t.Fatalf("ambiguous failure must retain finalizing (never reset to active), got %+v", st)
	}

	second := doReqExpect(t, retryPut(t, base+"/v2/backend/api/blobs/uploads/"+id, digest, issuer), http.StatusConflict)
	second.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("retry after ambiguous failure caused %d PutStream calls, want ZERO new", up.putStreamCalls)
	}
	if st, _ := svc.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateFinalizing {
		t.Fatalf("retry must leave the claim finalizing, got %+v", st)
	}
}

// TestUploadPreSideEffectFailureReleasesClaim proves a CONCLUSIVELY
// pre-side-effect uploader failure releases the claim back to active, so a
// corrected retry re-claims and writes exactly once.
func TestUploadPreSideEffectFailureReleasesClaim(t *testing.T) {
	svc := newDurableService(t)
	base, issuer, _, up := newDurableHandler(t, svc)

	body := []byte(`{"pre":true}`)
	_, id, digest := stageBody(t, base, issuer, body)

	up.err = fmt.Errorf("%w: request never sent", resolve.ErrUploaderPreSideEffect)
	resp := doReqExpect(t, retryPut(t, base+"/v2/backend/api/blobs/uploads/"+id, digest, issuer), http.StatusBadGateway)
	resp.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("pre-side-effect attempt must make 1 PutStream, got %d", up.putStreamCalls)
	}
	if st, _ := svc.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateActive {
		t.Fatalf("pre-side-effect failure must release the claim to active, got %+v", st)
	}

	up.err = nil
	ok := doReqExpect(t, retryPut(t, base+"/v2/backend/api/blobs/uploads/"+id, digest, issuer), http.StatusCreated)
	ok.Body.Close()
	if up.putStreamCalls != 2 {
		t.Fatalf("corrected retry must write exactly once more (total 2), got %d", up.putStreamCalls)
	}
	if st, _ := svc.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateFinalized || st.Digest != digest {
		t.Fatalf("corrected retry must durably finalize: %+v", st)
	}
}

// TestUploadCompletionFaultAfterSuccessfulWriteRetainsClaim proves a metadata
// (DB completion) fault AFTER the external write succeeded leaves the session
// finalizing (fail-closed) — never reset to active, never re-written — and a
// retry makes ZERO writes while returning the fixed conflict response.
func TestUploadCompletionFaultAfterSuccessfulWriteRetainsClaim(t *testing.T) {
	svc := newDurableService(t)
	store := &completionFaultStore{RegistryStore: svc}
	base, issuer, _, up := newDurableHandler(t, store)

	store.arm = true // the completion commit will fail; the external write already happened
	body := []byte(`{"receipt":true}`)
	_, id, digest := stageBody(t, base, issuer, body)

	resp := doReqExpect(t, retryPut(t, base+"/v2/backend/api/blobs/uploads/"+id, digest, issuer), http.StatusServiceUnavailable)
	resp.Body.Close()
	store.arm = false
	if up.putStreamCalls != 1 {
		t.Fatalf("completion-fault attempt must make exactly 1 PutStream, got %d", up.putStreamCalls)
	}
	if st, _ := svc.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateFinalizing {
		t.Fatalf("post-write metadata fault must retain finalizing, got %+v", st)
	}

	resp2 := doReqExpect(t, retryPut(t, base+"/v2/backend/api/blobs/uploads/"+id, digest, issuer), http.StatusConflict)
	resp2.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("retry after post-write fault caused %d PutStream calls, want ZERO new", up.putStreamCalls)
	}
	if st, _ := svc.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateFinalizing {
		t.Fatalf("post-write fault retry must not reset the claim, got %+v", st)
	}
}

// TestUploadDigestMismatchZeroClaimZeroWrite proves an invalid digest is
// rejected BEFORE any claim and BEFORE any object-store write, leaving the
// upload active and fully retryable.
func TestUploadDigestMismatchZeroClaimZeroWrite(t *testing.T) {
	svc := newDurableService(t)
	base, issuer, _, up := newDurableHandler(t, svc)

	body := []byte(`{"mismatch":true}`)
	_, id, _ := stageBody(t, base, issuer, body)

	wrongDigest := publish.ComputeDigest([]byte("different-bytes"))
	resp := doReqExpect(t, retryPut(t, base+"/v2/backend/api/blobs/uploads/"+id, wrongDigest, issuer), http.StatusBadRequest)
	resp.Body.Close()
	if up.putStreamCalls != 0 {
		t.Fatalf("digest mismatch must make ZERO PutStream calls, got %d", up.putStreamCalls)
	}
	if st, _ := svc.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateActive {
		t.Fatalf("digest mismatch must not claim/finalize, got %+v", st)
	}
	correct := doReqExpect(t, retryPut(t, base+"/v2/backend/api/blobs/uploads/"+id, publish.ComputeDigest(body), issuer), http.StatusCreated)
	correct.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("corrected finalize after digest mismatch must write exactly once, got %d", up.putStreamCalls)
	}
}

// TestUploadAlreadyFinalizedByteIdenticalRetryZeroWrite proves a byte-identical
// finalize retry on an already-finalized session returns 201 with ZERO
// additional object writes and does not disturb the stored receipt.
func TestUploadAlreadyFinalizedByteIdenticalRetryZeroWrite(t *testing.T) {
	svc := newDurableService(t)
	base, issuer, _, up := newDurableHandler(t, svc)

	body := []byte(`{"idempotent":true}`)
	_, id, digest := stageBody(t, base, issuer, body)

	first := doReqExpect(t, retryPut(t, base+"/v2/backend/api/blobs/uploads/"+id, digest, issuer), http.StatusCreated)
	first.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("first finalize must write once, got %d", up.putStreamCalls)
	}
	retry := doReqExpect(t, retryPut(t, base+"/v2/backend/api/blobs/uploads/"+id, digest, issuer), http.StatusCreated)
	retry.Body.Close()
	if up.putStreamCalls != 1 {
		t.Fatalf("already-finalized retry must make ZERO new PutStream, got %d", up.putStreamCalls)
	}
	if st, _ := svc.Status(context.Background(), id, "backend/api", "user:alice"); st.State != staging.StateFinalized || st.Digest != digest {
		t.Fatalf("idempotent retry must leave the finalized receipt intact: %+v", st)
	}
}
