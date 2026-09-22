package controlplane

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
)

// ---------------------------------------------------------------------------
// Fix round 4/5: absent Content-Type is UNSPECIFIED (not malformed) while the
// body-size bound stays first and PRESENT malformed/multipart/ambiguous values
// are still rejected.
//
// The round-3 media-type gate rejected an absent/empty Content-Type with 415
// because mime.ParseMediaType("") errors. That is the blanket-415 regression
// this round closes: a request with NO Content-Type (a bodyless POST /ui/logout,
// a JSON login/register body sent without a header, or an unknown unsafe route)
// is a legitimate, common request and must reach routing/CSRF/handler. Only a
// PRESENT value must parse canonically and be non-multipart; ambiguity (multiple
// header values even when identical, or a comma-joined value) is rejected 415.
// Body size is still enforced FIRST, so oversized bodies are 413 regardless of
// Content-Type being absent, malformed, or multipart.
// ---------------------------------------------------------------------------

// doDirect serves `req` through the given policy with a recorder, the way the
// real HTTP path does, so repeated/blank Content-Type header lines survive
// exactly as bytes (no client/transport coalescing).
func doDirect(t *testing.T, p *securityPolicy, service *Service, tokens *auth.SessionTokenManager, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	rec := httptest.NewRecorder()
	svr.ServeHTTP(rec, req)
	return rec
}

func TestAbsentContentTypeBodylessLogoutClearsCookie(t *testing.T) {
	// A bodyless POST /ui/logout with a valid cookie and the correct CSRF
	// header and NO Content-Type must execute (303) and clear the cookie —
	// never a blanket 415.
	store, _ := OpenSQLite("file:csec_fix4_logout?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	p := buildPolicy(t, tokens, false, "")
	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)

	req := httptest.NewRequest(http.MethodPost, "/ui/logout", nil) // bodyless, NO Content-Type
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := doDirect(t, p, service, tokens, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bodyless logout with no Content-Type must proceed (303), got %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Fatalf("logout must clear the cookie (MaxAge<0), got %+v", cookies)
	}
}

func TestBlankContentTypeTreatedAsAbsent(t *testing.T) {
	// A single whitespace-only (or empty) Content-Type value counts as absent
	// (unspecified), NOT malformed 415 — the bodyless logout still executes.
	store, _ := OpenSQLite("file:csec_fix4_blank?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	p := buildPolicy(t, tokens, false, "")
	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)

	for _, ct := range []string{"   ", "\t", ""} {
		req := httptest.NewRequest(http.MethodPost, "/ui/logout", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", ct)
		rec := doDirect(t, p, service, tokens, req)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("Content-Type %q (blank) must be treated as absent: logout proceeds (303), got %d", ct, rec.Code)
			continue
		}
		if cookies := rec.Result().Cookies(); len(cookies) != 1 || cookies[0].MaxAge >= 0 {
			t.Errorf("Content-Type %q (blank): logout must clear the cookie, got %+v", ct, cookies)
		}
	}
}

func TestUnknownUnsafeAbsentContentTypeReachesRouteNot415(t *testing.T) {
	// An unknown bodyless POST/DELETE with no Content-Type reaches the normal
	// route result (404), never a media-type 415.
	store, _ := OpenSQLite("file:csec_fix4_unknown?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, false, "")

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		req := httptest.NewRequest(method, "/no/such/route", nil) // no Content-Type
		rec := doDirect(t, p, service, tokens, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s unknown route with absent Content-Type must reach the route result (404), got %d", method, rec.Code)
		}
	}
}

func TestJSONLoginRegisterAbsentContentTypePriorBehavior(t *testing.T) {
	// Valid JSON login/register WITHOUT a Content-Type retains its prior
	// behavior: the handlers' JSON decoders are content-type agnostic, so the
	// body is parsed and the request proceeds normally (register -> 201 plus a
	// created user; login -> 200 with a session). Never a 415.
	store, _ := OpenSQLite("file:csec_fix4_json?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, false, "")

	register := httptest.NewRequest(http.MethodPost, "/api/users/register", strings.NewReader(`{"email":"nova@example.com","password":"password123"}`))
	register.Header.Set("Origin", "") // development allows absent Origin
	rec := doDirect(t, p, service, tokens, register)
	if rec.Code != http.StatusCreated {
		t.Fatalf("JSON register without Content-Type must create the user (201), got %d", rec.Code)
	}
	if _, err := store.FindUserByEmail(context.Background(), "nova@example.com"); err != nil {
		t.Fatalf("registered user must exist: %v", err)
	}

	login := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"email":"nova@example.com","password":"password123"}`))
	rec = doDirect(t, p, service, tokens, login)
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON login without Content-Type must succeed (200), got %d", rec.Code)
	}
}

func TestBlankContentTypeAbsentOnUnknownRoute(t *testing.T) {
	// A single whitespace-only Content-Type on an unknown POST is ALSO
	// unspecified: reaches 404, not 415.
	store, _ := OpenSQLite("file:csec_fix4_unknown_blank?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, false, "")

	req := httptest.NewRequest(http.MethodPost, "/no/such/route", nil)
	req.Header.Set("Content-Type", " \t ")
	rec := doDirect(t, p, service, tokens, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("blank Content-Type must count absent (404), got %d", rec.Code)
	}
}

func TestPresentMalformedContentType415(t *testing.T) {
	// A PRESENT but unparseable Content-Type is still 415.
	store, _ := OpenSQLite("file:csec_fix4_malformed?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, false, "")

	req := httptest.NewRequest(http.MethodPost, "/no/such/route", strings.NewReader("x"))
	req.Header.Set("Content-Type", "not/a valid; media")
	rec := doDirect(t, p, service, tokens, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("present malformed Content-Type must be 415, got %d", rec.Code)
	}
}

func TestDuplicateContentTypeRejected415EvenIdentical(t *testing.T) {
	// Multiple Content-Type header values are ambiguous — even when identical
	// — and rejected 415 rather than trusting Header.Get's first value.
	store, _ := OpenSQLite("file:csec_fix4_dup?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, false, "")

	for _, vals := range [][]string{
		{"application/json", "application/json"},                  // identical duplicates
		{"application/json", "application/x-www-form-urlencoded"}, // conflicting
		{" ", "application/json"},                                 // blank + present
	} {
		req := httptest.NewRequest(http.MethodPost, "/no/such/route", strings.NewReader("x"))
		for _, v := range vals {
			req.Header.Add("Content-Type", v)
		}
		rec := doDirect(t, p, service, tokens, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("duplicate Content-Type %v must be 415, got %d", vals, rec.Code)
		}
	}
}

func TestCommaJoinedContentTypeRejected415(t *testing.T) {
	// A single header value that comma-joins multiple media types is malformed
	// per the media-type grammar -> 415.
	store, _ := OpenSQLite("file:csec_fix4_comma?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, false, "")

	req := httptest.NewRequest(http.MethodPost, "/no/such/route", strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/json, text/plain")
	rec := doDirect(t, p, service, tokens, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("comma-joined Content-Type must be 415, got %d", rec.Code)
	}
}

func TestUnderlimitMultipartContentType415(t *testing.T) {
	// A PRESENT under-limit multipart/* is still rejected 415 on any route.
	store, _ := OpenSQLite("file:csec_fix4_mp?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, false, "")

	for _, ct := range []string{"multipart/form-data; boundary=x", "Multipart/Mixed; boundary=y"} {
		req := httptest.NewRequest(http.MethodPost, "/no/such/route", strings.NewReader("small"))
		req.Header.Set("Content-Type", ct)
		rec := doDirect(t, p, service, tokens, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("under-limit multipart %q must be 415, got %d", ct, rec.Code)
		}
	}
}

func TestOversizedBodyDominatesAnyContentTypeState(t *testing.T) {
	// Body size is enforced FIRST for every body-capable method: an oversized
	// body is 413 whether Content-Type is absent, malformed, or multipart.
	store, _ := OpenSQLite("file:csec_fix4_oversize?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	big := strings.Repeat("a", maxBodyBytes+50)
	for _, ct := range []string{"", "not/a valid;", "multipart/form-data; boundary=x"} {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/auth/login", strings.NewReader(big))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		req.ContentLength = int64(len(big))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("oversized CT=%q: %v", ct, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("oversized body with Content-Type %q must be 413 (size first), got %d", ct, resp.StatusCode)
		}
	}
}

// Guard: the standard urlencoded form POST (with Content-Type and a form CSRF)
// must still work after the gate change — one canonical form value parses and
// proceeds, exactly as round 3 established.
func TestCanonicalUrlencodedFormStillProceeds(t *testing.T) {
	store, _ := OpenSQLite("file:csec_fix4_form?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	p := buildPolicy(t, tokens, false, "")
	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)

	form := url.Values{"slug": {"alice"}, "ens_name": {"a.eth"}, "default_stamp_batch_id": {"b"}, "_csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/ui/registries/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	rec := doDirect(t, p, service, tokens, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("canonical urlencoded form must proceed (303), got %d", rec.Code)
	}
	if regs, _ := service.ListRegistries(context.Background(), 1); len(regs) != 1 {
		t.Fatalf("expected one registry created, got %d", len(regs))
	}
}
