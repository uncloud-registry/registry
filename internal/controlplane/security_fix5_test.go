package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

// ---------------------------------------------------------------------------
// Fix round 5/5: blank Content-Type means ASCII SP/HTAB OWS ONLY.
//
// HTTP header OWS is exactly ASCII SP (0x20) and HTAB (0x09). The round-4
// fix used strings.TrimFunc(v, unicode.IsSpace), which also trims NBSP
// (U+00A0), EM SPACE (U+2003), and every other Unicode whitespace code point.
// A single Content-Type value whose bytes are ONLY Unicode whitespace (no
// SP/HTAB) is therefore a PRESENT value — not blank — and must go on to
// mime.ParseMediaType, where a non-media-type string is malformed and rejected
// 415. It must NEVER be treated as absent (which would let a bodyless
// authenticated request proceed to the handler).
//
// The existing round-4 blank tests ("   ", "\t", "") prove genuine ASCII
// OWS-only values still count as absent. These tests add the RED edge: NBSP,
// em-space, and mixed SP/HTAB around NBSP each count as PRESENT (415) — and
// 415 means the handler never runs, so no session-cookie clearing and no
// handler side effect occurs.
// ---------------------------------------------------------------------------

// uniStoreSeq gives each unicodeWSLogout call its own in-memory SQLite store
// (a shared dsn would collide on the second RegisterUser with the same email).
var uniStoreSeq atomic.Uint64

// unicodeWSLogout runs a real bodyless authenticated POST /ui/logout carrying
// the given Content-Type header value through the REAL wrap() middleware path
// (doDirect -> HTTPServer.ServeHTTP), asserts it is rejected 415 (the
// Unicode-whitespace bytes are PRESENT/malformed, so the handler never runs),
// and that the response carries NO clearing cookie while the session token
// remains verifiable (no handler side effect).
func unicodeWSLogout(t *testing.T, ct string) {
	t.Helper()
	uniStoreSeq.Add(1)
	store, _ := OpenSQLite("file:csec_fix5_uni_ws_" + strconv.FormatUint(uniStoreSeq.Load(), 10) + "?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	_, session, _ := service.RegisterUser(context.Background(), "uni@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)

	req := httptest.NewRequest(http.MethodPost, "/ui/logout", nil) // bodyless
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Content-Type", ct)
	rec := doDirect(t, p, service, tokens, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("Content-Type %q (bytes %d): Unicode whitespace is PRESENT -> must be 415, got %d", ct, []byte(ct), rec.Code)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("Content-Type %q: a 415 must not emit any (clearing) cookie, got %+v", ct, cookies)
	}
	if _, err := tokens.Verify(session); err != nil {
		t.Fatalf("Content-Type %q: handler must not have run (session still valid), got err %v", ct, err)
	}
}

// classify pins the PRESENT-versus-blank semantics to resolveContentType
// itself, in addition to (not instead of) the real middleware path above.
func classify(t *testing.T, r *http.Request) contentTypeState {
	t.Helper()
	return resolveContentType(r)
}

func TestNBSPContentTypeIsPresent415(t *testing.T) {
	// NBSP alone (U+00A0) must be PRESENT (never blank) -> 415.
	unicodeWSLogout(t, "\u00a0")
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Content-Type", "\u00a0")
	if st := classify(t, req); st != contentTypeMalformed {
		t.Fatalf("NBSP Content-Type must classify as MALFORMED (present), got %v", st)
	}
}

func TestEmSpaceContentTypeIsPresent415(t *testing.T) {
	// EM SPACE (U+2003) alone must be PRESENT (never blank) -> 415.
	unicodeWSLogout(t, "\u2003")
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Content-Type", "\u2003")
	if st := classify(t, req); st != contentTypeMalformed {
		t.Fatalf("EM SPACE Content-Type must classify as MALFORMED (present), got %v", st)
	}
}

func TestMixedSPHTABAroundNBSPContentTypeIsPresent415(t *testing.T) {
	// Mixed ASCII OWS around NBSP must NOT collapse the value to blank: the
	// NBSP byte remains present, so it is malformed -> 415, never unspecified.
	unicodeWSLogout(t, "  \t\u00a0\t  ")
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Content-Type", "  \t\u00a0\t  ")
	if st := classify(t, req); st != contentTypeMalformed {
		t.Fatalf("SP/HTAB+NBSP Content-Type must classify as MALFORMED (present), got %v", st)
	}
}

// Guard: genuine ASCII OWS-only values stay ABSENT (round-4 behavior retained)
// — pinned at both the classifier and the real middleware path.
func TestASCIIOWSOnlyContentTypeStillAbsent(t *testing.T) {
	for _, ct := range []string{"   ", "\t", "\t  \t"} {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Header.Set("Content-Type", ct)
		if st := classify(t, req); st != contentTypeUnspecified {
			t.Errorf("Content-Type %q (ASCII OWS only) must classify as UNSPECIFIED, got %v", ct, st)
		}
	}

	// Real path: ASCII OWS-only bodyless logout still clears the cookie (303).
	store, _ := OpenSQLite("file:csec_fix5_ascii?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	_, session, _ := service.RegisterUser(context.Background(), "a@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)
	req := httptest.NewRequest(http.MethodPost, "/ui/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Content-Type", "\t ")
	if rec := doDirect(t, p, service, tokens, req); rec.Code != http.StatusSeeOther {
		t.Fatalf("ASCII OWS-only logout must still proceed (303), got %d", rec.Code)
	}
}
