package controlplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
)

// ---------------------------------------------------------------------------
// Fix round 2/5: multipart CSRF
// ---------------------------------------------------------------------------

// TestCSRFMultipartRejected415 proves a multipart/form-data request can never
// leak an unparsed `_csrf` candidate through the CSRF gate: the control plane
// rejects multipart entirely with 415 before any handler/CSRF processing, so a
// multipart CSRF value cannot be silently treated absent AND cannot pass.
func TestCSRFMultipartRejected415(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix2_multipart?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	postMultipart := func(fields map[string]string) int {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, v := range fields {
			if err := mw.WriteField(k, v); err != nil {
				t.Fatalf("write field: %v", err)
			}
		}
		mw.Close()
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
		resp := doReq(t, client, req)
		resp.Body.Close()
		return resp.StatusCode
	}

	// Even a multipart body carrying the CORRECT `_csrf` field is rejected 415:
	// multipart is never parsed, so its token can never be accepted.
	if code := postMultipart(map[string]string{"_csrf": csrf, "slug": "x", "ens_name": "x.eth", "default_stamp_batch_id": "b"}); code != http.StatusUnsupportedMediaType {
		t.Fatalf("multipart with correct _csrf must be 415, got %d", code)
	}
	// A multipart body WITHOUT _csrf is also 415 (not silently treated absent).
	if code := postMultipart(map[string]string{"slug": "y", "ens_name": "y.eth", "default_stamp_batch_id": "b"}); code != http.StatusUnsupportedMediaType {
		t.Fatalf("multipart without _csrf must be 415, got %d", code)
	}
	// Zero side effects: no registry created by any multipart attempt.
	regs, _ := service.ListRegistries(context.Background(), 1)
	if len(regs) != 0 {
		t.Fatal("multipart attempt must have zero side effects")
	}
}

// TestMultipartRejected415AppliesBeforeRouting proves even an unknown POST
// route carrying a multipart body is rejected 415 (bounded/routed safely).
func TestMultipartRejected415AppliesBeforeRouting(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix2_mp_route?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("a", "b")
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/does/not/exist", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp := doReq(t, &http.Client{}, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("multipart on unknown route must be 415, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Fix round 2/5: request ID never empty
// ---------------------------------------------------------------------------

func TestRequestIDNeverEmptyOnRNGFailure(t *testing.T) {
	orig := requestIDRandom
	requestIDRandom = func([]byte) (int, error) { return 0, errors.New("injected rng failure") }
	defer func() { requestIDRandom = orig }()

	a := newRequestID()
	b := newRequestID()
	if a == "" || b == "" {
		t.Fatalf("request IDs must never be empty on RNG failure, got %q and %q", a, b)
	}
	if len(a) != 32 || len(b) != 32 {
		t.Fatalf("request ID must be 32 hex chars, got %q and %q", a, b)
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Fatalf("fallback request ID must be hex, got %q: %v", a, err)
	}
	if a == b {
		t.Fatal("deterministic fallback must still be process-unique across calls")
	}
	// A resumption of the crypto path returns to 32 hex.
	requestIDRandom = orig
	if c := newRequestID(); len(c) != 32 {
		t.Fatalf("crypto request ID must be 32 hex, got %q", c)
	}
}

// ---------------------------------------------------------------------------
// Fix round 2/5: token endpoint public-error classification
// ---------------------------------------------------------------------------

// buildTokenServer assembles a registry-token server with an owner + registry so
// the full IssueRegistryToken path is reachable, optionally without a working
// issuer (nil) to exercise the signing/not-configured class.
func buildTokenServer(t *testing.T, withIssuer bool, logger *slog.Logger) (*Service, *httptest.Server, string) {
	t.Helper()
	store, _ := OpenSQLite("file:csec_fix2_token_" + withIssuerName(withIssuer) + "?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	if withIssuer {
		service.RegistryTokens, _ = newTestRegistryPair(t)
	}
	admin, _, _ := service.RegisterUser(context.Background(), "admin@example.com", "admin-pass")
	created, _ := service.CreateRegistry(context.Background(), admin.ID, "acc", "acc.eth", false, "b")
	_, _, _ = service.RegisterUser(context.Background(), "guest@example.com", "guest-pass")

	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p, Logger: logger}
	server := httptest.NewServer(svr)
	return service, server, created.Registry.Host
}

func withIssuerName(b bool) string {
	if b {
		return "iss"
	}
	return "noiss"
}

func TestTokenEndpointClassifiedFailuresNoInternalText(t *testing.T) {
	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	_, server, host := buildTokenServer(t, true, logger)
	defer server.Close()

	doToken := func(user, pass, service, scope string) (int, map[string]any) {
		u := server.URL + "/token"
		if service != "" {
			u += "?service=" + url.QueryEscape(service)
			if scope != "" {
				u += "&scope=" + url.QueryEscape(scope)
			}
		}
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp := doReq(t, &http.Client{}, req)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		return resp.StatusCode, payload
	}

	// 1. Missing basic auth -> generic 401, no internal text.
	code, payload := doToken("", "", "", "")
	if code != http.StatusUnauthorized || payload["error"] != "basic auth required" {
		t.Fatalf("missing basic auth: got %d %v", code, payload)
	}

	// 2. Unknown-user credential -> generic 401, identical public message.
	code, payload = doToken("ghost@example.com", "nope", host, "repository:repo:pull")
	if code != http.StatusUnauthorized || payload["error"] != errInvalidCredentials.Error() {
		t.Fatalf("unknown user: got %d %v", code, payload)
	}

	// 3. Wrong password -> generic 401, identical message.
	code, payload = doToken("admin@example.com", "wrong-pass", host, "repository:repo:pull")
	if code != http.StatusUnauthorized || payload["error"] != errInvalidCredentials.Error() {
		t.Fatalf("wrong password: got %d %v", code, payload)
	}

	// 4. Malformed scope -> generic 400.
	code, payload = doToken("admin@example.com", "admin-pass", host, "not a valid scope")
	if code != http.StatusBadRequest || payload["error"] != "invalid request" {
		t.Fatalf("malformed scope: got %d %v", code, payload)
	}

	// 5. Forbidden (non-member pull on private registry) -> generic 403.
	code, payload = doToken("guest@example.com", "guest-pass", host, "repository:repo:pull")
	if code != http.StatusForbidden || payload["error"] != "access denied" {
		t.Fatalf("forbidden: got %d %v", code, payload)
	}

	// 6. Caller-chosen registry missing -> 404, never "registry not found" from
	//    an internal error string.
	code, payload = doToken("admin@example.com", "admin-pass", "nonexistent.example.com", "repository:repo:pull")
	if code != http.StatusNotFound || payload["error"] != "registry not found" {
		t.Fatalf("missing registry: got %d %v", code, payload)
	}

	// Public bodies must never leak credentials, scope, or internal error text.
	// (The literal "password" is deliberately NOT banned — the safe internal
	// cause strings "invalid_password" legitimately contain it.)
	bufStr := buf.String()
	for _, forbidden := range []string{"admin@example.com", "guest@example.com", "admin-pass", "guest-pass", "repository:repo:pull", "not a valid scope", "sql:"} {
		if strings.Contains(bufStr, forbidden) {
			t.Errorf("auth-failure log leaked %q", forbidden)
		}
	}
	if !strings.Contains(bufStr, "request_id=") {
		t.Fatal("auth-failure log must carry a request_id")
	}
}

func TestTokenEndpointSigningBackendGeneric500(t *testing.T) {
	// Issuer not configured -> generic 500 (signing), never the internal text
	// "registry token issuer is not configured".
	_, server, host := buildTokenServer(t, false, nil)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/token?service="+url.QueryEscape(host)+"&scope=repository:repo:pull", nil)
	req.SetBasicAuth("admin@example.com", "admin-pass")
	resp := doReq(t, &http.Client{}, req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("issuer-not-configured must be generic 500, got %d %s", resp.StatusCode, body)
	}
	if payload["error"] != "token could not be issued" {
		t.Fatalf("signing failure must use a fixed generic message, got %s", body)
	}
	if strings.Contains(string(body), "issuer is not configured") {
		t.Fatal("internal issuer text must never reach the public body")
	}
}

func TestTokenFailureMappingUnit(t *testing.T) {
	// Every class maps to a fixed generic public status+message, never internal
	// error text.
	want := map[tokenFailureClass]struct {
		status int
		msg    string
	}{
		tokenClassCredential: {http.StatusUnauthorized, errInvalidCredentials.Error()},
		tokenClassMalformed:  {http.StatusBadRequest, "invalid request"},
		tokenClassForbidden:  {http.StatusForbidden, "access denied"},
		tokenClassNotFound:   {http.StatusNotFound, "registry not found"},
		tokenClassBackend:    {http.StatusServiceUnavailable, "temporary service failure"},
		tokenClassSigning:    {http.StatusInternalServerError, "token could not be issued"},
	}
	for class, exp := range want {
		status, msg := tokenFailureResponse(class)
		if status != exp.status || msg != exp.msg {
			t.Errorf("class %v: got (%d,%q), want (%d,%q)", class, status, msg, exp.status, exp.msg)
		}
	}
}

// ---------------------------------------------------------------------------
// Fix round 2/5: bounded form body (no masked overflow)
// ---------------------------------------------------------------------------

func TestOversizedURLEncodedLoginRejected413NoSideEffects(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix2_urlenc?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	// Oversized urlencoded body on /ui/login.
	form := url.Values{"email": {strings.Repeat("a", maxBodyBytes) + "@example.com"}, "password": {"x"}}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(form.Encode()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("oversized form login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized urlencoded body must be 413, got %d", resp.StatusCode)
	}
	if _, err := store.FindUserByEmail(context.Background(), strings.Repeat("a", maxBodyBytes)+"@example.com"); err == nil {
		t.Fatal("oversized form login must have zero side effects")
	}
}

func TestOversizedMalformedFormReturns400NotMasked(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix2_form400?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	// A malformed urlencoded body (bare '%' invalid escape) under the limit must
	// propagate a 400 parse error, never be swallowed.
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/login", strings.NewReader("email=x@e.com&password=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len("email=x@e.com&password=%zz"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("malformed form: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed urlencoded body must be 400, got %d", resp.StatusCode)
	}
}

func TestOversizedUnknownPOSTRejected413BeforeRouting(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix2_unknown?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	// Oversized body on an UNKNOWN POST route must still be bounded -> 413,
	// even though no handler will read it.
	body := strings.Repeat("x", maxBodyBytes+50)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/no/such/route", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("oversized unknown post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized unknown POST must be 413 before routing, got %d", resp.StatusCode)
	}
}

// TestOversizedCookieFormPOST413NotCSRF403 is the masked-overflow regression:
// an oversized cookie-authenticated urlencoded form POST must be bounded to a
// 413 BEFORE CSRF runs, so the CSRF path can never swallow the overflow and
// surface a misleading 403 "missing CSRF token" instead of the honest 413.
func TestOversizedCookieFormPOST413NotCSRF403(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix2_csrfmask?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	form := url.Values{"slug": {"x"}, "ens_name": {"x.eth"}, "default_stamp_batch_id": {"b"}, "_csrf": {sessionCSRFForTest(t, session)}}
	overflow := form.Encode() + "&pad=" + strings.Repeat("y", maxBodyBytes)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(overflow))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(overflow))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, client, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized cookie form POST must be 413 (not a CSRF 403), got %d", resp.StatusCode)
	}
	// Zero side effects.
	if regs, _ := service.ListRegistries(context.Background(), 1); len(regs) != 0 {
		t.Fatal("413-rejected request must have zero side effects")
	}
}

func TestOversizedMultipartRejected413(t *testing.T) {
	// Multipart is rejected entirely (415) when under the size bound, BUT body
	// size is enforced FIRST for every body-capable method: an OVERSIZED
	// multipart body is 413 (size wins over media type), never reaching any
	// handler or being silently treated as absent.
	store, _ := OpenSQLite("file:csec_fix2_mp_big?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/login", strings.NewReader(strings.Repeat("a", maxBodyBytes+10)))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=xxx")
	req.ContentLength = -1
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("oversized multipart: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized multipart must be 413 (size first), got %d", resp.StatusCode)
	}
}

func TestOversizedChunkedJSONLoginRejected413(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix2_chunk?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	body := strings.Repeat("a", maxBodyBytes*2)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1 // force chunked
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("chunked oversized login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized chunked JSON must be 413, got %d", resp.StatusCode)
	}
}

// countingReader records every Read call so a test can prove a safe GET/HEAD
// never reads the request body.
type countingReader struct {
	inner io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.inner.Read(p)
}

func TestGETTokenCustomReaderProvesZeroReads(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix2_token_reads?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	service.RegistryTokens, _ = newTestRegistryPair(t)
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}

	// Drive the handler directly with a body reader that counts reads. A safe
	// GET /token must never read the request body even once (the network
	// transport is bypassed, so any read here is a handler-side read).
	cr := &countingReader{inner: strings.NewReader(strings.Repeat("x", 100))}
	req := httptest.NewRequest(http.MethodGet, "/token?service=s&scope=repository:repo:pull", cr)
	req.RemoteAddr = "203.0.113.7:12345"
	req.SetBasicAuth("someone@example.com", "pw")
	rec := httptest.NewRecorder()
	svr.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /token (no session registry valid) expected 401, got %d", rec.Code)
	}
	if cr.reads != 0 {
		t.Fatalf("GET /token must read the request body zero times, got %d reads", cr.reads)
	}
}

// TestOversizedRegistrationAndInviteRejected413 covers the remaining body-capable
// routes: registration (API JSON) and invite creation (API JSON).
func TestOversizedRegistrationAndInviteRejected413(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix2_reginv?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	service.RegistryTokens, _ = newTestRegistryPair(t)
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	owner, session, _ := service.RegisterUser(context.Background(), "owner@example.com", "pw")
	created, _ := service.CreateRegistry(context.Background(), owner.ID, "ow", "o.eth", false, "b")

	postJSONBig := func(path string) int {
		req, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(strings.Repeat(" ", maxBodyBytes+100)))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(maxBodyBytes + 100)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("oversized %s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := postJSONBig("/api/users/register"); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized registration must be 413, got %d", code)
	}
	invitePath := "/api/registries/" + strconv.FormatInt(created.Registry.ID, 10) + "/invites"
	req, _ := http.NewRequest(http.MethodPost, server.URL+invitePath, strings.NewReader(strings.Repeat(" ", maxBodyBytes+100)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+session)
	req.ContentLength = int64(maxBodyBytes + 100)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("oversized invite: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized invite must be 413, got %d", resp.StatusCode)
	}
}
