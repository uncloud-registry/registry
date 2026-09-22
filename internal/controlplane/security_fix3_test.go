package controlplane

import (
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
)

// ---------------------------------------------------------------------------
// Fix round 3/5: multipart/media-type precedence
// ---------------------------------------------------------------------------
//
// Body size is bounded FIRST for every body-capable method (oversized -> 413,
// even for multipart and unknown routes); only after bounded buffering is the
// Content-Type parsed with mime.ParseMediaType (case-insensitive/canonical,
// parameter/OWS aware, never substring matching), rejecting malformed
// Content-Types and any multipart/* body with an under-limit 415. Substring
// lookalikes (application/x-notmultipart, "multipart/form-data" inside a
// quoted parameter) must not false-match.

func TestContentTypeParsedCanonicallyNotSubstring(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix3_ct?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	do := func(ct, body string) int {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
		resp := doReq(t, client, req)
		resp.Body.Close()
		return resp.StatusCode
	}
	okBody := url.Values{"slug": {"c1"}, "ens_name": {"c1.eth"}, "default_stamp_batch_id": {"b"}, "_csrf": {csrf}}.Encode()

	// A mixed-case urlencoded Content-Type with OWS and a parameter is a real
	// form (canonical media type, carried by ParseMediaType) -> 303, NOT 415.
	if code := do(" Application/X-Www-Form-Urlencoded ; charset=utf-8  ", okBody); code != http.StatusSeeOther {
		t.Fatalf("mixed-case urlencoded form must proceed (canonical match), got %d", code)
	}

	// Multipart casing + any multipart/* subtype -> 415.
	for _, ct := range []string{
		"Multipart/Form-Data ; boundary=xxx",
		"multipart/mixed; boundary=xxx",
		" multipart/related; boundary=a ",
	} {
		if code := do(ct, okBody); code != http.StatusUnsupportedMediaType {
			t.Errorf("multipart %q must be 415, got %d", ct, code)
		}
	}

	// Substring lookalikes are NOT multipart and NOT a form body CSRF source:
	// they are header-only, so a cookie POST without a header is 403 missing
	// CSRF — never a spurious 415.
	for _, ct := range []string{
		"application/x-notmultipart",
		`text/plain; note="multipart/form-data"`,
	} {
		if code := do(ct, okBody); code != http.StatusForbidden {
			t.Errorf("lookalike %q must be treated as non-form/non-multipart (403 missing header CSRF), got %d", ct, code)
		}
	}

	// A malformed Content-Type is rejected 415 consistently.
	if code := do("application/; odd", "x"); code != http.StatusUnsupportedMediaType {
		t.Fatalf("malformed content-type must be 415, got %d", code)
	}

	// Only the single canonical urlencoded form created a registry.
	regs, _ := service.ListRegistries(context.Background(), 1)
	if len(regs) != 1 {
		t.Fatalf("expected exactly the canonical form to create one registry, got %d", len(regs))
	}
}

// TestMediaTypeGateAppliesAfterBodySize proves size-before-media-type: an
// oversized body on a multipart route (and on an unknown route) is 413, while
// an under-limit multipart body is 415.
func TestMediaTypeGateAppliesAfterBodySize(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix3_sz?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	post := func(path, ct string, body string, cl int64) int {
		req, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		if cl != 0 {
			req.ContentLength = cl
		} else {
			req.ContentLength = -1
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Oversized multipart on a known route -> 413 (size first, not 415).
	if code := post("/ui/login", "multipart/form-data; boundary=x", strings.Repeat("a", maxBodyBytes+5), -1); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized multipart must be 413, got %d", code)
	}
	// Oversized multipart on an UNKNOWN route -> 413 (size first).
	if code := post("/no/such", "multipart/form-data; boundary=x", strings.Repeat("a", maxBodyBytes+5), -1); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized multipart on unknown route must be 413, got %d", code)
	}
	// Under-limit multipart on an unknown route -> 415 (media type).
	if code := post("/no/such", "multipart/form-data; boundary=x", "small", 5); code != http.StatusUnsupportedMediaType {
		t.Errorf("under-limit multipart must be 415, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// Fix round 3/5: non-caching CSRF form parsing
// ---------------------------------------------------------------------------

func TestCSRFMalformedFormPartialTokenRejected400(t *testing.T) {
	// A malformed urlencoded body carrying a nominally-valid partial `_csrf`
	// must be rejected 400 before CSRF or the handler runs, with no effects:
	// checkCSRF parses the bounded bytes via url.ParseQuery and rejects ANY
	// parse error rather than silently accepting the partial token.
	store, _ := OpenSQLite("file:csec_fix3_partial?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	// Body: a VALID `_csrf` plus a malformed URL escape elsewhere.
	body := "_csrf=" + url.QueryEscape(csrf) + "&bad=%zz"
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, client, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed form with partial valid _csrf must be 400, got %d", resp.StatusCode)
	}
	regs, _ := service.ListRegistries(context.Background(), 1)
	if len(regs) != 0 {
		t.Fatal("400-rejected malformed form must have zero side effects (handler not reached)")
	}
}

func TestCSRFDuplicateEqualsStillConflicts(t *testing.T) {
	// Two IDENTICAL valid `_csrf` values are still two candidates -> 403
	// conflicting: the exact-candidate semantics are preserved (duplicates,
	// even identical, never pass).
	store, _ := OpenSQLite("file:csec_fix3_dup?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	form := url.Values{"slug": {"x"}, "ens_name": {"x.eth"}, "default_stamp_batch_id": {"b"}, "_csrf": {csrf, csrf}}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, client, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("identical duplicate _csrf must be 403 conflicting, got %d", resp.StatusCode)
	}
	if regs, _ := service.ListRegistries(context.Background(), 1); len(regs) != 0 {
		t.Fatal("duplicate-CSRF rejection must have zero side effects")
	}
}

func TestCSRFEmptyFormMissingToken(t *testing.T) {
	// An empty urlencoded form (no `_csrf`) with a valid cookie is a missing
	// token -> 403, no effects.
	store, _ := OpenSQLite("file:csec_fix3_empty?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, client, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("empty form with cookie must be 403 missing CSRF, got %d", resp.StatusCode)
	}
	if regs, _ := service.ListRegistries(context.Background(), 1); len(regs) != 0 {
		t.Fatal("empty-form rejection must have zero side effects")
	}
}

// TestCSRFHandlerSeesSameFormBytes proves checkCSRF's context-based inspection
// never consumes the body: after a valid CSRF passes, the handler's own
// ParseForm independently reads the same restored bytes and creates the
// registry (the fields are still present).
func TestCSRFHandlerSeesSameFormBytes(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix3_same?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	form := url.Values{"slug": {"alice"}, "ens_name": {"a.eth"}, "default_stamp_batch_id": {"b"}, "_csrf": {csrf}}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, client, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("valid form must proceed to handler, got %d", resp.StatusCode)
	}
	if regs, _ := service.ListRegistries(context.Background(), 1); len(regs) != 1 {
		t.Fatalf("handler must parse the same bounded bytes and create the registry, got %d registries", len(regs))
	}
}

// ---------------------------------------------------------------------------
// Fix round 3/5: bufferRequestBody body lifecycle (instrumented ReadCloser)
// ---------------------------------------------------------------------------

// tracingReadCloser counts reads and closes and can inject a read error.
type tracingReadCloser struct {
	r      io.Reader
	err    error
	closes int
	reads  int
}

func (c *tracingReadCloser) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	c.reads++
	return c.r.Read(p)
}

func (c *tracingReadCloser) Close() error { c.closes++; return nil }

func TestBufferRequestBodyBodyLifecycleAllPaths(t *testing.T) {
	type want struct {
		dataLen   int
		overflow  bool
		err       bool
		closes    int
		reads     int // 0 means the fast reject must not read at all
		bodyReads string
	}

	run := func(name string, method string, body string, contentLength int64, injErr error, w want) {
		t.Helper()
		tc := &tracingReadCloser{r: strings.NewReader(body), err: injErr}
		req := httptest.NewRequest(method, "/x", tc)
		req.ContentLength = contentLength
		data, overflow, err := bufferRequestBody(req)
		if w.overflow != overflow {
			t.Fatalf("%s: overflow got %v want %v", name, overflow, w.overflow)
		}
		if w.err != (err != nil) {
			t.Fatalf("%s: err got %v want err=%v", name, err, w.err)
		}
		if w.err && !errors.Is(err, injErr) {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if w.closes != tc.closes {
			t.Errorf("%s: original body closed %d times, want %d", name, tc.closes, w.closes)
		}
		if w.reads == 0 {
			// reads==0 means the path must not read the body at all (e.g. the
			// known-ContentLength fast reject and read-error/empty cases).
			if tc.reads != 0 {
				t.Errorf("%s: must not read the body, read %d times", name, tc.reads)
			}
		} else if tc.reads == 0 {
			// reads!=0 means the path must perform at least one body read.
			t.Errorf("%s: must read the body, read 0 times", name)
		}
		if w.dataLen >= 0 && len(data) != w.dataLen {
			t.Errorf("%s: returned data len %d want %d", name, len(data), w.dataLen)
		}
		// After bufferRequestBody, the current r.Body must be fully readable
		// (success) or empty (over flow/error -> replaced, never the closed
		// original), and must never represent the original reader's bytes on
		// the closed paths.
		rest, rerr := io.ReadAll(req.Body)
		if rerr != nil {
			t.Fatalf("%s: reading replaced body: %v", name, rerr)
		}
		if string(rest) != w.bodyReads {
			t.Errorf("%s: replaced body reads %q, want %q", name, string(rest), w.bodyReads)
		}
	}

	const small = "hello form data"
	run("success", http.MethodPost, small, int64(len(small)), nil,
		want{dataLen: len(small), overflow: false, err: false, closes: 1, reads: 1, bodyReads: small})
	// Known ContentLength overflow: reject without reading a byte.
	run("known-content-length-overflow", http.MethodPost, strings.Repeat("x", maxBodyBytes+5), int64(maxBodyBytes+5), nil,
		want{dataLen: 0, overflow: true, err: false, closes: 1, reads: 0, bodyReads: ""})
	// Chunked (unknown-length) overflow: rejected after reading limit+1 bytes.
	run("chunked-overflow", http.MethodPost, strings.Repeat("x", maxBodyBytes+5), -1, nil,
		want{dataLen: 0, overflow: true, err: false, closes: 1, reads: 1, bodyReads: ""})
	// Read error: rejected, body closed once.
	run("read-error", http.MethodPost, "whatever", 0, errors.New("injected read failure"),
		want{dataLen: 0, overflow: false, err: true, closes: 1, reads: 0, bodyReads: ""})
	// Safe method: body untouched, never read nor closed.
	run("safe-method", http.MethodGet, small, int64(len(small)), nil,
		want{dataLen: 0, overflow: false, err: false, closes: 0, reads: 0, bodyReads: small})
}

// TestMultipartNeverParsedAsCSRF proves an under-limit multipart body carrying
// the CORRECT `_csrf` still cannot satisfy CSRF (rejected 415 with zero side
// effects) — a multipart `_csrf` is never extracted from the body.
func TestMultipartNeverParsedAsCSRF(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix3_mp?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	var buf strings.Builder
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("_csrf", csrf)
	_ = w.WriteField("slug", "abc")
	w.Close()

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, client, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("multipart with correct _csrf must still be 415, got %d", resp.StatusCode)
	}
	if regs, _ := service.ListRegistries(context.Background(), 1); len(regs) != 0 {
		t.Fatal("multipart attempt must have zero side effects")
	}
}
