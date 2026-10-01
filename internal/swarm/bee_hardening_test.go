package swarm

// Fix Round 1 RED/GREEN suites: data-free Bee feed I/O errors, strict /chunks
// response parsing, and typed-nil resolver safety. Every test here was written
// FIRST against the pre-fix code and failed (RED), then the implementation was
// hardened to make them pass (GREEN).
//
// Fix Round 2 RED suites: the request CONTEXT is the sole authority for the
// context.Canceled / context.DeadlineExceeded outcome. A malicious transport
// that forges sentinel-wrapping errors while the request context is live must
// NOT get its sentinel preserved, and a genuinely cancelled / expired request
// context must surface its own sentinel even when the transport error is
// unrelated or forged. Every Round 2 test was written FIRST against the
// round-1 sanitizer (which trusted errors.Is on the untrusted error) and
// failed (RED); the sanitizer was then re-bound to the real derived request
// context to make them pass (GREEN).

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/uncloud-registry/registry/internal/resolve"
)

// failTransport is a RoundTripper that always fails with the given error. It
// models a failing or MALICIOUS network endpoint whose error text could smuggle
// the request URL (for SOC that URL carries the signature query), a hostname,
// or injected marker text into an error that must be data-free.
type failTransport struct{ err error }

func (t failTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

// countingFailTransport additionally records how many RoundTrip calls occurred,
// so a test can prove an error path issued zero requests.
type countingFailTransport struct {
	err error
	mu  sync.Mutex
	n   int
}

func (t *countingFailTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.n++
	t.mu.Unlock()
	return nil, t.err
}

func (t *countingFailTransport) calls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

// requireDataFree asserts err is non-nil and that its message contains none of
// the caller-supplied markers (full URLs, hostnames, owner/topic/batch/ref/sig
// values, injected transport text).
func requireDataFree(t *testing.T, err error, op string, markers ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error", op)
	}
	msg := err.Error()
	for _, m := range markers {
		if m != "" && strings.Contains(msg, m) {
			t.Fatalf("%s: error must not contain %q, got: %v", op, m, err)
		}
	}
}

// markerReadCloser is a response body whose Read always fails with the wrapped
// error, smuggling injected text into a body-read error path.
type markerReadCloser struct{ err error }

func (m markerReadCloser) Read([]byte) (int, error) { return 0, m.err }
func (m markerReadCloser) Close() error             { return nil }

// syntheticResponseTransport returns a 200 response whose body read fails with
// the injected error, bypassing a real network stack.
type syntheticResponseTransport struct{ err error }

func (t syntheticResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       markerReadCloser{err: t.err},
		Request:    req,
	}, nil
}

const (
	dataFreeSigMarker = "TOPSECRET"
	dataFreeHost      = "secret.invalid"
	dataFreeText      = "injected-transport-marker"
	dataFreeBodyText  = "injected-body-read-marker"
)

// ---- Reader: transport / request-creation / feed-parse / body-read errors ----

func TestReadFeedTransportErrorIsDataFree(t *testing.T) {
	t.Parallel()
	transportErr := &url.Error{
		URL: "https://" + dataFreeHost + "/soc/owner-" + dataFreeSigMarker + "/id?" +
			"x=1&sig=" + dataFreeSigMarker,
		Err: errors.New(dataFreeText),
	}
	for _, tc := range []struct {
		name string
		fn   func(t *testing.T, r *BeeFeedResolver)
	}{
		{"ReadFeed", func(t *testing.T, r *BeeFeedResolver) {
			_, err := r.ReadFeed(context.Background(), "feed://OWNERMARK/TOPICMARK")
			requireDataFree(t, err, "ReadFeed transport error",
				dataFreeHost, dataFreeSigMarker, dataFreeText, "sig=", "OWNERMARK", "TOPICMARK", "bee.invalid")
		}},
		{"ResolveFeed", func(t *testing.T, r *BeeFeedResolver) {
			_, err := r.ResolveFeed(context.Background(), "feed://OWNERMARK/TOPICMARK")
			requireDataFree(t, err, "ResolveFeed transport error",
				dataFreeHost, dataFreeSigMarker, dataFreeText, "sig=", "OWNERMARK", "TOPICMARK", "bee.invalid")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := NewBeeFeedResolver("https://bee.invalid",
				&http.Client{Transport: failTransport{transportErr}})
			tc.fn(t, resolver)
		})
	}
}

func TestReadFeedRequestCreationErrorIsDataFree(t *testing.T) {
	t.Parallel()
	// A base URL with an invalid host (space) makes http.NewRequestWithContext
	// fail after URL parsing; the parse error NAMES the offending URL, so it
	// must never be wrapped into the returned error.
	base := "http://secret " + dataFreeSigMarker + ".invalid"
	for _, tc := range []struct {
		name string
		fn   func(t *testing.T, r *BeeFeedResolver)
	}{
		{"ReadFeed", func(t *testing.T, r *BeeFeedResolver) {
			_, err := r.ReadFeed(context.Background(), "feed://owner/topic")
			requireDataFree(t, err, "ReadFeed request creation", dataFreeSigMarker, "http://secret")
		}},
		{"ResolveFeed", func(t *testing.T, r *BeeFeedResolver) {
			_, err := r.ResolveFeed(context.Background(), "feed://owner/topic")
			requireDataFree(t, err, "ResolveFeed request creation", dataFreeSigMarker, "http://secret")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := NewBeeFeedResolver(base,
				&http.Client{Transport: failTransport{errors.New(dataFreeText)}})
			tc.fn(t, resolver)
		})
	}
}

func TestReadFeedMalformedFeedErrorIsDataFree(t *testing.T) {
	t.Parallel()
	transport := &countingFailTransport{err: errors.New(dataFreeText)}
	resolver := NewBeeFeedResolver("https://bee.invalid", &http.Client{Transport: transport})
	for _, feed := range []string{
		"feed://" + dataFreeSigMarker,
		"not-a-feed-" + dataFreeSigMarker,
		"feed://OWNERMARK",
		"feed://OWNERMARK/",
	} {
		if _, err := resolver.ReadFeed(context.Background(), feed); err == nil {
			t.Fatalf("feed %q must be rejected", feed)
		} else if strings.Contains(err.Error(), dataFreeSigMarker) ||
			strings.Contains(err.Error(), "OWNERMARK") {
			t.Fatalf("feed %q: malformed-feed error must not quote the raw caller feed, got: %v", feed, err)
		}
	}
	if n := transport.calls(); n != 0 {
		t.Fatalf("malformed feeds must be rejected before any request, got %d requests", n)
	}
}

func TestReadFeedBodyReadErrorIsDataFree(t *testing.T) {
	t.Parallel()
	// A malicious RoundTripper returns a 200 whose BODY read fails with
	// injected text; the body-read error must be data-free.
	resolver := NewBeeFeedResolver("https://bee.invalid",
		&http.Client{Transport: syntheticResponseTransport{errors.New(dataFreeBodyText)}})
	_, err := resolver.ReadFeed(context.Background(), "feed://owner/topic")
	requireDataFree(t, err, "ReadFeed body read", dataFreeBodyText, dataFreeHost)
}

// ---- Writer: lookup / chunk / SOC transport, request-creation errors ----

func TestBeeSequenceFeedUpdaterTransportErrorsAreDataFree(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	batch := strings.Repeat("cd", 32)

	transportErr := &url.Error{
		URL: "https://" + dataFreeHost + "/soc/" + owner + "/" + strings.Repeat("11", 32) +
			"?sig=" + dataFreeSigMarker,
		Err: errors.New(dataFreeText),
	}
	newUpdater := func() *BeeSequenceFeedUpdater {
		return &BeeSequenceFeedUpdater{
			BaseURL:    "https://bee.invalid",
			HTTPClient: &http.Client{Transport: failTransport{transportErr}},
			PrivateKey: privateKey,
		}
	}
	markers := []string{dataFreeHost, dataFreeSigMarker, dataFreeText, "sig=", "bee.invalid", owner}

	t.Run("lookup", func(t *testing.T) {
		u := newUpdater()
		_, err := u.nextSequenceIndex(context.Background(), "OWNERMARK", "TOPICMARK", false)
		requireDataFree(t, err, "lookup transport error", append(markers, "OWNERMARK", "TOPICMARK")...)
	})
	t.Run("chunk", func(t *testing.T) {
		u := newUpdater()
		_, err := u.uploadChunk(context.Background(), []byte("data"), batch)
		requireDataFree(t, err, "chunk transport error", markers...)
	})
	t.Run("soc", func(t *testing.T) {
		u := newUpdater()
		err := u.uploadSOC(context.Background(), owner, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}, []byte("data"), batch, false)
		requireDataFree(t, err, "soc transport error", markers...)
	})
}

func TestBeeSequenceFeedUpdaterRequestCreationErrorsAreDataFree(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	// Invalid base URL: NewRequest fails after URL parsing and the parse error
	// names the URL (including, for SOC, the signature query). It must never
	// be wrapped into the returned error.
	u := &BeeSequenceFeedUpdater{
		BaseURL:    "http://secret " + dataFreeSigMarker + ".invalid",
		HTTPClient: &http.Client{Transport: failTransport{errors.New(dataFreeText)}},
		PrivateKey: privateKey,
	}
	if _, err := u.nextSequenceIndex(context.Background(), "abcd", "abcd", false); err != nil {
		requireDataFree(t, err, "lookup request creation", dataFreeSigMarker, "http://secret")
	} else {
		t.Fatal("expected lookup request creation to fail")
	}
	if _, err := u.uploadChunk(context.Background(), []byte("data"), "batch"); err != nil {
		requireDataFree(t, err, "chunk request creation", dataFreeSigMarker, "http://secret")
	} else {
		t.Fatal("expected chunk request creation to fail")
	}
	if err := u.uploadSOC(context.Background(), "abcd", []byte{1}, []byte{2}, []byte("data"), "batch", false); err != nil {
		requireDataFree(t, err, "soc request creation", dataFreeSigMarker, "http://secret", "sig=")
	} else {
		t.Fatal("expected soc request creation to fail")
	}
}

// ---- Round 2: the request CONTEXT is the sole sentinel authority ----

// statusBodyFailTransport returns a response with the given status whose BODY
// read always fails with the wrapped error, smuggling injected text into a
// body-read error path (used for the chunk upload body-read sanitizer path).
type statusBodyFailTransport struct {
	status int
	err    error
}

func (t statusBodyFailTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: t.status,
		Header:     make(http.Header),
		Body:       markerReadCloser{err: t.err},
		Request:    req,
	}, nil
}

// cancelledContext returns an already-cancelled context whose Err() is
// deterministically context.Canceled.
func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// expiredContext returns an already-expired-deadline context whose Err() is
// deterministically context.DeadlineExceeded (the deadline is in the past and
// <-ctx.Done() guarantees the timer has fired before the caller uses it).
func expiredContext() context.Context {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-10*time.Millisecond))
	defer cancel()
	<-ctx.Done()
	return ctx
}

// forgedSentinelTransportErr is a fully attacker-controlled transport error: a
// *url.Error carrying the full request URL (hostname, SOC signature query) and
// injected marker text, whose inner error wraps BOTH context.Canceled and
// context.DeadlineExceeded. Round 1 trusted errors.Is on this error and
// preserved the forged sentinel; Round 2 must treat the request context as the
// authority and ignore it.
func forgedSentinelTransportErr() error {
	return &url.Error{
		URL: "https://" + dataFreeHost + "/soc/owner-" + dataFreeSigMarker + "/id?x=1&sig=" + dataFreeSigMarker,
		Err: fmt.Errorf("%s: %w: %w", dataFreeText, context.Canceled, context.DeadlineExceeded),
	}
}

// unrelatedAttackerTransportErr is a fully attacker-controlled transport error
// that does NOT wrap any context sentinel: the classic data-leak shape with a
// forged URL and injected marker text.
func unrelatedAttackerTransportErr() error {
	return &url.Error{
		URL: "https://" + dataFreeHost + "/feeds/OWNERMARK/TOPICMARK",
		Err: errors.New(dataFreeText),
	}
}

// sentinelMatrixCase is one scenario in the Round 2 matrix.
type sentinelMatrixCase struct {
	name         string
	ctx          context.Context
	transportErr error
	wantCanceled bool
	wantDeadline bool
}

// requireSentinelMatrix runs the given path under the Round 2 sentinel matrix
// and asserts, for each scenario, the exact errors.Is outcome AND that the
// returned error is data-free (no attacker markers / URLs / signatures leak
// through, even when a sentinel is preserved). run wires the transportErr into
// whatever error path the path uses (client.Do failure, body-read failure) and
// returns the sanitized error.
func requireSentinelMatrix(t *testing.T, path string, markers []string, run func(ctx context.Context, transportErr error) error) {
	t.Helper()
	cases := []sentinelMatrixCase{
		{"live context + forged sentinel error", context.Background(), forgedSentinelTransportErr(), false, false},
		{"cancelled context + unrelated error", cancelledContext(), unrelatedAttackerTransportErr(), true, false},
		{"cancelled context + forged error", cancelledContext(), forgedSentinelTransportErr(), true, false},
		{"expired deadline + unrelated error", expiredContext(), unrelatedAttackerTransportErr(), false, true},
		{"expired deadline + forged error", expiredContext(), forgedSentinelTransportErr(), false, true},
	}
	allMarkers := append(append([]string{}, markers...), dataFreeHost, dataFreeSigMarker, dataFreeText, "sig=")
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.ctx, tc.transportErr)
			if err == nil {
				t.Fatal("expected an error")
			}
			requireDataFree(t, err, path, allMarkers...)
			if got := errors.Is(err, context.Canceled); got != tc.wantCanceled {
				t.Fatalf("%s: errors.Is(context.Canceled) = %v, want %v (err: %v)", path, got, tc.wantCanceled, err)
			}
			if got := errors.Is(err, context.DeadlineExceeded); got != tc.wantDeadline {
				t.Fatalf("%s: errors.Is(context.DeadlineExceeded) = %v, want %v (err: %v)", path, got, tc.wantDeadline, err)
			}
		})
	}
}

func TestReadFeedContextSentinelsFollowRequestContext(t *testing.T) {
	t.Parallel()
	t.Run("request", func(t *testing.T) {
		requireSentinelMatrix(t, "ReadFeed request", []string{"OWNERMARK", "TOPICMARK", "bee.invalid"},
			func(ctx context.Context, transportErr error) error {
				resolver := NewBeeFeedResolver("https://bee.invalid",
					&http.Client{Transport: failTransport{transportErr}})
				_, err := resolver.ReadFeed(ctx, "feed://OWNERMARK/TOPICMARK")
				return err
			})
	})
	t.Run("body read", func(t *testing.T) {
		requireSentinelMatrix(t, "ReadFeed body read", []string{"OWNERMARK", "TOPICMARK", "bee.invalid"},
			func(ctx context.Context, transportErr error) error {
				resolver := NewBeeFeedResolver("https://bee.invalid",
					&http.Client{Transport: statusBodyFailTransport{http.StatusOK, transportErr}})
				_, err := resolver.ReadFeed(ctx, "feed://OWNERMARK/TOPICMARK")
				return err
			})
	})
}

func TestBeeSequenceFeedUpdaterLookupContextSentinelsFollowRequestContext(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	requireSentinelMatrix(t, "lookup request", []string{"OWNERMARK", "TOPICMARK", "bee.invalid"},
		func(ctx context.Context, transportErr error) error {
			updater := &BeeSequenceFeedUpdater{
				BaseURL:    "https://bee.invalid",
				HTTPClient: &http.Client{Transport: failTransport{transportErr}},
				PrivateKey: privateKey,
			}
			_, err := updater.nextSequenceIndex(ctx, "OWNERMARK", "TOPICMARK", false)
			return err
		})
}

func TestBeeSequenceFeedUpdaterChunkContextSentinelsFollowRequestContext(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	batch := strings.Repeat("cd", 32)
	markers := []string{"bee.invalid", batch}
	t.Run("request", func(t *testing.T) {
		requireSentinelMatrix(t, "chunk upload request", markers,
			func(ctx context.Context, transportErr error) error {
				updater := &BeeSequenceFeedUpdater{
					BaseURL:    "https://bee.invalid",
					HTTPClient: &http.Client{Transport: failTransport{transportErr}},
					PrivateKey: privateKey,
				}
				_, err := updater.uploadChunk(ctx, []byte("data"), batch)
				return err
			})
	})
	t.Run("body read", func(t *testing.T) {
		requireSentinelMatrix(t, "chunk upload body read", markers,
			func(ctx context.Context, transportErr error) error {
				updater := &BeeSequenceFeedUpdater{
					BaseURL:    "https://bee.invalid",
					HTTPClient: &http.Client{Transport: statusBodyFailTransport{http.StatusCreated, transportErr}},
					PrivateKey: privateKey,
				}
				_, err := updater.uploadChunk(ctx, []byte("data"), batch)
				return err
			})
	})
}

func TestBeeSequenceFeedUpdaterSOCContextSentinelsFollowRequestContext(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	batch := strings.Repeat("cd", 32)
	requireSentinelMatrix(t, "soc upload request", []string{"bee.invalid", owner, batch},
		func(ctx context.Context, transportErr error) error {
			updater := &BeeSequenceFeedUpdater{
				BaseURL:    "https://bee.invalid",
				HTTPClient: &http.Client{Transport: failTransport{transportErr}},
				PrivateKey: privateKey,
			}
			return updater.uploadSOC(ctx, owner, []byte{1, 2, 3}, []byte{4, 5, 6}, []byte("data"), batch, false)
		})
}

// TestRequestCreationErrorsFollowRequestContext proves request-creation
// failures (malformed base URL fails http.NewRequestWithContext) STILL route
// through the sanitizer with the real derived context: a live context stays
// opaque (no sentinel from the parse error), while a genuinely cancelled or
// expired context surfaces ITS OWN sentinel. The parse error names the
// offending URL (for SOC that URL carries sig=...), so it must never leak.
func TestRequestCreationErrorsFollowRequestContext(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	base := "http://secret " + dataFreeSigMarker + ".invalid"
	batch := strings.Repeat("cd", 32)
	creationErr := func(run func(ctx context.Context) error) func(ctx context.Context, transportErr error) error {
		return func(ctx context.Context, transportErr error) error { return run(ctx) }
	}
	markers := []string{dataFreeSigMarker, "http://secret", "sig="}
	runs := []struct {
		name string
		run  func(ctx context.Context, transportErr error) error
	}{
		{"reader creation", creationErr(func(ctx context.Context) error {
			resolver := NewBeeFeedResolver(base, &http.Client{Transport: failTransport{errors.New(dataFreeText)}})
			_, err := resolver.ReadFeed(ctx, "feed://owner/topic")
			return err
		})},
		{"lookup creation", creationErr(func(ctx context.Context) error {
			updater := &BeeSequenceFeedUpdater{
				BaseURL:    base,
				HTTPClient: &http.Client{Transport: failTransport{errors.New(dataFreeText)}},
				PrivateKey: privateKey,
			}
			_, err := updater.nextSequenceIndex(ctx, "abcd", "abcd", false)
			return err
		})},
		{"chunk creation", creationErr(func(ctx context.Context) error {
			updater := &BeeSequenceFeedUpdater{
				BaseURL:    base,
				HTTPClient: &http.Client{Transport: failTransport{errors.New(dataFreeText)}},
				PrivateKey: privateKey,
			}
			_, err := updater.uploadChunk(ctx, []byte("data"), batch)
			return err
		})},
		{"soc creation", creationErr(func(ctx context.Context) error {
			updater := &BeeSequenceFeedUpdater{
				BaseURL:    base,
				HTTPClient: &http.Client{Transport: failTransport{errors.New(dataFreeText)}},
				PrivateKey: privateKey,
			}
			return updater.uploadSOC(ctx, "abcd", []byte{1}, []byte{2}, []byte("data"), batch, false)
		})},
	}
	for _, r := range runs {
		r := r
		t.Run(r.name, func(t *testing.T) {
			requireSentinelMatrix(t, r.name, markers, r.run)
		})
	}
}

// TestSanitizeBeeTransportErrorContextIsAuthority pins the sanitizer's core
// rule directly: ctx nil fails opaque; a live context NEVER preserves a
// sentinel no matter what the untrusted error wraps; a done context ALWAYS
// surfaces its own sentinel no matter how unrelated or forged the untrusted
// error is.
func TestSanitizeBeeTransportErrorContextIsAuthority(t *testing.T) {
	t.Parallel()
	forged := fmt.Errorf("%s: %w: %w", dataFreeText, context.Canceled, context.DeadlineExceeded)
	plain := errors.New(dataFreeText)
	cases := []struct {
		name         string
		ctx          context.Context
		err          error
		wantCanceled bool
		wantDeadline bool
	}{
		{"nil context fails opaque", nil, forged, false, false},
		{"live context + plain error is opaque", context.Background(), plain, false, false},
		{"live context + forged sentinels is opaque", context.Background(), forged, false, false},
		{"cancelled context + plain error", cancelledContext(), plain, true, false},
		{"cancelled context + forged error", cancelledContext(), forged, true, false},
		{"expired context + plain error", expiredContext(), plain, false, true},
		{"expired context + forged error", expiredContext(), forged, false, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := sanitizeBeeTransportError(tc.ctx, "probe op", tc.err)
			if err == nil {
				t.Fatal("expected an error")
			}
			requireDataFree(t, err, "sanitizer", dataFreeText)
			if got := errors.Is(err, context.Canceled); got != tc.wantCanceled {
				t.Fatalf("errors.Is(context.Canceled) = %v, want %v (err: %v)", got, tc.wantCanceled, err)
			}
			if got := errors.Is(err, context.DeadlineExceeded); got != tc.wantDeadline {
				t.Fatalf("errors.Is(context.DeadlineExceeded) = %v, want %v (err: %v)", got, tc.wantDeadline, err)
			}
		})
	}
}

// ---- Strict /chunks response parsing ----

func TestChunkUploadStrictResponseParsing(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	valid64 := strings.Repeat("ab", 32)

	invalid := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"null body", `null`},
		{"array wrapper", fmt.Sprintf(`[{"reference":%q}]`, valid64)},
		{"scalar json", `"reference"`},
		{"number json", `123`},
		{"empty object", `{}`},
		{"missing reference", `{"other":"x"}`},
		{"empty reference", `{"reference":""}`},
		{"short reference", fmt.Sprintf(`{"reference":%q}`, strings.Repeat("ab", 31))},          // 62 chars
		{"odd-length reference", fmt.Sprintf(`{"reference":%q}`, strings.Repeat("ab", 31)+"a")}, // 63 chars
		{"long reference", fmt.Sprintf(`{"reference":%q}`, strings.Repeat("ab", 33))},           // 66 chars
		{"non-hex reference", fmt.Sprintf(`{"reference":%q}`, strings.Repeat("zz", 32))},
		{"non-hex mixed reference", fmt.Sprintf(`{"reference":%q}`, strings.Repeat("ab", 20)+"TOPSECRET"+strings.Repeat("ab", 7)+"a")},
		{"non-string number", `{"reference":123}`},
		{"non-string bool", `{"reference":true}`},
		{"non-string null", `{"reference":null}`},
		{"non-string object", `{"reference":{"nested":1}}`},
		{"non-string array", `{"reference":["ab"]}`},
		{"duplicate reference", fmt.Sprintf(`{"reference":%q,"reference":%q}`, valid64, strings.Repeat("bb", 32))},
		{"unknown member", fmt.Sprintf(`{"reference":%q,"other":1}`, valid64)},
		{"trailing token", fmt.Sprintf(`{"reference":%q} x`, valid64)},
		{"trailing object", fmt.Sprintf(`{"reference":%q}{"a":1}`, valid64)},
		{"trailing array", fmt.Sprintf(`{"reference":%q}[1]`, valid64)},
		{"unterminated", `{"reference":"` + valid64},
		{"structural junk", `{"reference":"` + valid64 + `"`}, // missing close brace
	}
	for _, tc := range invalid {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			updater := &BeeSequenceFeedUpdater{
				BaseURL:    server.URL,
				HTTPClient: server.Client(),
				PrivateKey: privateKey,
			}
			refBytes, err := updater.uploadChunk(context.Background(), []byte("data"), "batch")
			if err == nil {
				t.Fatalf("%s: expected strict rejection, got ref %x", tc.name, refBytes)
			}
			// Data-free: never echo hex-decode jargon or raw reference bytes.
			for _, marker := range []string{"invalid byte", "TOPSECRET", "zzzz"} {
				if strings.Contains(err.Error(), marker) {
					t.Fatalf("%s: error must stay data-free, got: %v", tc.name, err)
				}
			}
		})
	}

	valid := []struct {
		name string
		body string
	}{
		{"lowercase ref", fmt.Sprintf(`{"reference":%q}`, valid64)},
		{"uppercase ref", fmt.Sprintf(`{"reference":%q}`, strings.ToUpper(valid64))},
		{"whitespace padded", "  " + fmt.Sprintf(`{"reference":%q}`, valid64) + "\n\t "},
	}
	for _, tc := range valid {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			updater := &BeeSequenceFeedUpdater{
				BaseURL:    server.URL,
				HTTPClient: server.Client(),
				PrivateKey: privateKey,
			}
			refBytes, err := updater.uploadChunk(context.Background(), []byte("data"), "batch")
			if err != nil {
				t.Fatalf("%s: expected acceptance, got %v", tc.name, err)
			}
			want, _ := hex.DecodeString(valid64)
			if string(refBytes) != string(want) {
				t.Fatalf("%s: decoded bytes mismatch: got %x want %x", tc.name, refBytes, want)
			}
		})
	}
}

// TestChunkMalformedResponseStopsBeforeFurtherRequests proves a malformed
// /chunks success response fails the WHOLE update before any SOC upload:
// since Task 13 reordered the sequence lookup BEFORE the chunk upload, the
// only requests issued are the sequence lookup (read-only) and the /chunks
// POST — never the /soc write.
func TestChunkMalformedResponseStopsBeforeFurtherRequests(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	valid64 := strings.Repeat("ab", 32)

	for _, tc := range []struct {
		name string
		body string
	}{
		{"duplicate reference",
			fmt.Sprintf(`{"reference":%q,"reference":%q}`, valid64, strings.Repeat("bb", 32))},
		{"unknown member",
			fmt.Sprintf(`{"reference":%q,"unknown":true}`, valid64)},
		{"trailing token",
			fmt.Sprintf(`{"reference":%q} trailing`, valid64)},
		{"non-hex reference",
			fmt.Sprintf(`{"reference":%q}`, strings.Repeat("zz", 32))},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var requests []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests = append(requests, r.Method+" "+r.URL.Path)
				mu.Unlock()
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/chunks":
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(tc.body))
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/feeds/"):
					http.NotFound(w, r)
				case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"):
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			updater := &BeeSequenceFeedUpdater{
				BaseURL:    server.URL,
				HTTPClient: server.Client(),
				PrivateKey: privateKey,
			}
			err := updater.Update(context.Background(), FeedUpdate{
				Feed:      "feed://" + owner + "/" + strings.Repeat("ab", 32),
				Reference: valid64,
				BatchID:   strings.Repeat("cd", 32),
			})
			if err == nil {
				t.Fatal("expected a malformed /chunks response to fail the update")
			}
			mu.Lock()
			defer mu.Unlock()
			// Sequence lookup (read-only, first) + /chunks only; the malformed
			// /chunks response must stop before the SOC write.
			if len(requests) != 2 || requests[0] != "GET /feeds/"+owner+"/"+strings.Repeat("ab", 32) || requests[1] != "POST /chunks" {
				t.Fatalf("malformed /chunks response must stop before the SOC write, got %d requests: %v",
					len(requests), requests)
			}
		})
	}
}

// ---- Typed-nil resolver / updater ----

func TestBeeFeedResolverTypedNilFailsClosed(t *testing.T) {
	t.Parallel()
	t.Run("direct ReadFeed", func(t *testing.T) {
		var r *BeeFeedResolver
		if _, err := r.ReadFeed(context.Background(), "feed://owner/topic"); err == nil {
			t.Fatal("typed-nil resolver ReadFeed must fail closed, not panic")
		}
	})
	t.Run("direct ResolveFeed", func(t *testing.T) {
		var r *BeeFeedResolver
		if _, err := r.ResolveFeed(context.Background(), "feed://owner/topic"); err == nil {
			t.Fatal("typed-nil resolver ResolveFeed must fail closed, not panic")
		}
	})
	t.Run("assigned to interface", func(t *testing.T) {
		var resolver resolve.FeedResolver = (*BeeFeedResolver)(nil)
		if _, err := resolver.ResolveFeed(context.Background(), "feed://owner/topic"); err == nil {
			t.Fatal("interface-assigned typed-nil resolver must fail closed, not panic")
		}
	})
	t.Run("zero value still fails closed", func(t *testing.T) {
		r := &BeeFeedResolver{}
		if _, err := r.ReadFeed(context.Background(), "feed://owner/topic"); err == nil {
			t.Fatal("zero-value resolver must fail closed")
		}
		if _, err := r.ResolveFeed(context.Background(), "feed://owner/topic"); err == nil {
			t.Fatal("zero-value resolver must fail closed")
		}
	})
}

func TestBeeSequenceFeedUpdaterTypedNilFailsClosed(t *testing.T) {
	t.Parallel()
	// Update already guards u == nil before any receiver dereference; the
	// writer helpers guard via writerBaseURL. This test pins that a typed-nil
	// updater fails closed with an error on every entry point, never panics.
	var u *BeeSequenceFeedUpdater
	if err := u.Update(context.Background(), FeedUpdate{
		Feed:      "feed://" + strings.Repeat("ab", 20) + "/" + strings.Repeat("ab", 32),
		Reference: strings.Repeat("ab", 32),
		BatchID:   strings.Repeat("cd", 32),
	}); err == nil {
		t.Fatal("typed-nil updater Update must fail closed, not panic")
	}
	if _, err := u.nextSequenceIndex(context.Background(), "abcd", "abcd", false); err == nil {
		t.Fatal("typed-nil updater lookup must fail closed, not panic")
	}
	if _, err := u.uploadChunk(context.Background(), []byte("data"), "batch"); err == nil {
		t.Fatal("typed-nil updater chunk must fail closed, not panic")
	}
	if err := u.uploadSOC(context.Background(), "abcd", []byte{1}, []byte{2}, []byte("data"), "batch", false); err == nil {
		t.Fatal("typed-nil updater soc must fail closed, not panic")
	}
}
