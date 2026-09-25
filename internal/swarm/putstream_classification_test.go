package swarm

// Production contract tests for the CONCLUSIVELY-PRE-SIDE-EFFECT uploader
// classification. These prove BeeObjectStore.PutStream emits
// resolve.ErrUploaderPreSideEffect ONLY for failures that are known to occur
// BEFORE any external write (a rejected request argument, or a request that
// could not even be constructed), and NEVER for the ambiguous post-dispatch
// outcomes (an HTTPClient.Do transport failure, a non-201 status, or a body
// read/decode/reference failure), any of which may mean the store accepted the
// bytes. This is the discriminator the registry finalization protocol relies
// on to decide RELEASE (pre-side-effect) vs RETAIN (ambiguous) for the
// durable claim.
//
// Trust note: a deliberately malicious uploader implementation is trusted by
// the ObjectUploader interface — Go cannot cryptographically prevent it from
// mislabeling its errors. These tests pin the CONTRACT for well-behaved
// adapters (the production swarm store) so a regression that widens or
// narrows the release window fails firs.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/resolve"
)

const validPutStreamBatch = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

// cannedResponseTransport returns a fixed status + readable body, so a test
// can exercise every post-dispatch response path with no real network.
type cannedResponseTransport struct {
	status int
	body   string
}

func (t cannedResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: t.status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(t.body)),
		Request:    req,
	}, nil
}

// TestBeeObjectStorePutStreamEmitsMarkerOnlyBeforeDispatch proves the
// pre-side-effect marker is emitted for exactly the pre-dispatch rejections,
// and that NONE of them issue a single HTTP request.
func TestBeeObjectStorePutStreamEmitsMarkerOnlyBeforeDispatch(t *testing.T) {
	t.Parallel()
	rt := &countingFailTransport{err: errors.New("transport must never be reached")}
	store := &BeeObjectStore{
		BaseURL:    "http://secret marker.invalid",
		HTTPClient: &http.Client{Transport: rt},
	}
	payload := strings.NewReader("streamed payload")

	cases := []struct {
		name string
		call func() error
	}{
		{"nil source", func() error {
			_, err := store.PutStream(context.Background(), nil, 5, validPutStreamBatch)
			return err
		}},
		{"negative size", func() error {
			_, err := store.PutStream(context.Background(), payload, -1, validPutStreamBatch)
			return err
		}},
		{"empty batch id", func() error {
			_, err := store.PutStream(context.Background(), payload, 5, "")
			return err
		}},
		{"oversized batch id", func() error {
			_, err := store.PutStream(context.Background(), payload, 5, strings.Repeat("z", beeFeedWriteMaxRef+1))
			return err
		}},
		{"request construction failure", func() error {
			_, err := store.PutStream(context.Background(), payload, 5, validPutStreamBatch)
			return err
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatalf("expected a pre-side-effect error")
			}
			if !errors.Is(err, resolve.ErrUploaderPreSideEffect) {
				t.Fatalf("expected the pre-side-effect marker, got: %v", err)
			}
		})
	}
	if n := rt.calls(); n != 0 {
		t.Fatalf("pre-side-effect rejections must never reach HTTPClient.Do, got %d requests", n)
	}
	// The request-construction failure error must stay data-free (never echo
	// the offending base URL).
	if _, err := store.PutStream(context.Background(), payload, 5, validPutStreamBatch); err != nil {
		if strings.Contains(err.Error(), "secret marker") {
			t.Fatalf("request-construction error must not echo the URL, got: %v", err)
		}
	}
}

// TestBeeObjectStorePutStreamNeverEmitsMarkerAfterDispatch proves every
// AMBIGUOUS post-dispatch failure — transport/Do error, non-201 status, body
// read error, decode error, reference failure — is NOT classified as
// pre-side-effect, so the registry claim is retained fail-closed.
func TestBeeObjectStorePutStreamNeverEmitsMarkerAfterDispatch(t *testing.T) {
	t.Parallel()
	payload := "payload"
	validSrc := func() (io.Reader, int64) { return strings.NewReader(payload), int64(len(payload)) }

	cases := []struct {
		name      string
		transport http.RoundTripper
	}{
		{"Do transport error", failTransport{errors.New("bee connection reset")}},
		{"non-201 status", cannedResponseTransport{http.StatusConflict, `{"error":"conflict"}`}},
		{"body read error on 201", statusBodyFailTransport{http.StatusCreated, errors.New("injected read marker")}},
		{"malformed JSON body", cannedResponseTransport{http.StatusCreated, `not-json`}},
		{"missing reference", cannedResponseTransport{http.StatusCreated, `{}`}},
		{"empty reference", cannedResponseTransport{http.StatusCreated, `{"reference":""}`}},
		{"non-hex reference", cannedResponseTransport{http.StatusCreated, `{"reference":"not-a-reference"}`}},
		{"wrong-size reference", cannedResponseTransport{http.StatusCreated, `{"reference":"abcd"}`}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			store := &BeeObjectStore{
				BaseURL:    "https://bee.invalid",
				HTTPClient: &http.Client{Transport: tc.transport},
			}
			src, size := validSrc()
			_, err := store.PutStream(context.Background(), src, size, validPutStreamBatch)
			if err == nil {
				t.Fatalf("expected an error for %s", tc.name)
			}
			if errors.Is(err, resolve.ErrUploaderPreSideEffect) {
				t.Fatalf("%s: must NOT be classified pre-side-effect (it may have side effects), got marker: %v", tc.name, err)
			}
		})
	}
}
