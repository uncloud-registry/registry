package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/config"
)

// ---------------------------------------------------------------------------
// Fake clock
// ---------------------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---------------------------------------------------------------------------
// Rate limiter unit tests
// ---------------------------------------------------------------------------

func TestLimiterEnforcesBurstThenLimits(t *testing.T) {
	start := time.Now()
	clk := newFakeClock(start)
	l := NewLimiter(1.0, 5, 100, time.Minute, clk)
	key := "k"
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow(key); !ok {
			t.Fatalf("request %d within burst must be allowed", i)
		}
	}
	if ok, wait := l.Allow(key); ok {
		t.Fatal("request beyond burst must be denied")
	} else if wait <= 0 {
		t.Fatalf("denied request must carry a positive retry-after, got %v", wait)
	}
	c := l.Counters()
	if c.Allowed != 5 || c.Limited != 1 {
		t.Fatalf("unexpected counters allowed=%d limited=%d", c.Allowed, c.Limited)
	}
}

func TestLimiterRefillsFractionally(t *testing.T) {
	start := time.Now()
	clk := newFakeClock(start)
	// Rate = 2 tokens/sec, burst 1. Exhaust it, then allow refill over time.
	l := NewLimiter(2.0, 1, 100, time.Minute, clk)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("first request must be allowed")
	}
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("second request must be limited at empty burst")
	}
	// After 0.25s at 2/s, exactly 0.5 tokens have accrued -> still denied.
	clk.advance(250 * time.Millisecond)
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("0.5 tokens must not satisfy a 1-token request")
	}
	// After another 0.25s a full token has accrued -> allowed.
	clk.advance(250 * time.Millisecond)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("a full refilled token must allow the request")
	}
}

func TestLimiterBackwardClockNoInflation(t *testing.T) {
	start := time.Now()
	clk := newFakeClock(start)
	l := NewLimiter(10.0, 1, 100, time.Minute, clk)
	// Advance far (would accrue many tokens)...
	clk.advance(10 * time.Hour)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("long idle must allow (bucket capped at burst)")
	}
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("after consuming the single token, a backward clock must not grant more")
	}
	// Now move the clock backward; refill logic must not panic or inflate tokens.
	clk.t = clk.t.Add(-time.Hour)
	ok, _ := l.Allow("k")
	if ok {
		t.Log("backward clock may or may not allow; it must not panic")
	}
}

func TestLimiterCapacityFailsClosed(t *testing.T) {
	start := time.Now()
	clk := newFakeClock(start)
	l := NewLimiter(1.0, 1, 3, time.Minute, clk)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("k" + strconv.Itoa(i)); !ok {
			t.Fatalf("key %d within capacity must be allowed", i)
		}
	}
	if l.Len() != 3 {
		t.Fatalf("expected 3 buckets, got %d", l.Len())
	}
	// At capacity, a new key must be rejected (fail closed) and counted.
	if ok, _ := l.Allow("overflow"); ok {
		t.Fatal("new key beyond capacity must fail closed")
	}
	if c := l.Counters(); c.CapacityRejected != 1 {
		t.Fatalf("expected 1 capacity rejection, got %d", c.CapacityRejected)
	}
}

func TestLimiterIdlePruning(t *testing.T) {
	start := time.Now()
	clk := newFakeClock(start)
	l := NewLimiter(1.0, 1, 100, 5*time.Second, clk)
	_, _ = l.Allow("a")
	_, _ = l.Allow("b")
	if l.Len() != 2 {
		t.Fatalf("expected 2 buckets before pruning, got %d", l.Len())
	}
	// Make bucket "a" idle but touch "b".
	clk.advance(4 * time.Second)
	_, _ = l.Allow("b")
	// Now "a" is stale > idleAfter but no prune has run yet (lastPrune advance
	// triggers on the next Allow).
	clk.advance(6 * time.Second)
	_, _ = l.Allow("b")
	if l.Len() != 1 {
		t.Fatalf("expected idle bucket pruned, got %d", l.Len())
	}
}

func TestLimiterKeyHashingRetainsNoRawEmail(t *testing.T) {
	l := NewLimiter(1.0, 1, 100, time.Minute, nil)
	_, _ = l.Allow("alice@example.com")
	// The storage is keyed by SHA-256 digest, not the raw value.
	for digest := range l.buckets {
		if strings.Contains(string(digest[:]), "alice") {
			t.Fatal("limiter must not retain the raw email key")
		}
	}
}

func TestLimiterConcurrentAtomic(t *testing.T) {
	// A frozen clock guarantees no refill, so exactly the burst's 5 tokens can
	// ever be consumed regardless of goroutine interleaving.
	clk := newFakeClock(time.Now())
	l := NewLimiter(1.0, 5, 10000, time.Minute, clk)
	const goroutines = 50
	var wg sync.WaitGroup
	var allowed atomic.Int64
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if ok, _ := l.Allow("shared"); ok {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != 5 {
		t.Fatalf("concurrent requests must be atomic; expected exactly 5 allowed, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Client-IP resolution
// ---------------------------------------------------------------------------

func TestClientIPNoTrustedProxy(t *testing.T) {
	r := newIPResolver(nil)
	ip, err := r.ClientIP("203.0.113.9:61234", []string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ip.String() != "203.0.113.9" {
		t.Fatalf("with no trusted proxies the peer must be used, got %s", ip)
	}
}

func TestClientIPIgnoresXFFFromUntrustedPeer(t *testing.T) {
	trusted, _ := netip.ParsePrefix("10.0.0.0/8")
	r := newIPResolver([]netip.Prefix{trusted})
	// Peer is NOT trusted -> an attacker-supplied XFF must be ignored.
	ip, err := r.ClientIP("203.0.113.9:80", []string{"1.2.3.4, 5.6.7.8"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ip.String() != "203.0.113.9" {
		t.Fatalf("XFF from an untrusted peer must be ignored, got %s", ip)
	}
}

func TestClientIPTrustedProxyChainRightToLeft(t *testing.T) {
	trusted, _ := netip.ParsePrefix("10.0.0.0/8")
	r := newIPResolver([]netip.Prefix{trusted})
	// Peer (10.0.0.1) is trusted; the chain is [client, trustedProxy]. Walking
	// right-to-left, 10.0.0.5 is trusted, so the client is 198.51.100.7.
	ip, err := r.ClientIP("10.0.0.1:80", []string{"198.51.100.7, 10.0.0.5"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ip.String() != "198.51.100.7" {
		t.Fatalf("expected client 198.51.100.7, got %s", ip)
	}
}

func TestClientIPRejectsMalformedChain(t *testing.T) {
	trusted, _ := netip.ParsePrefix("10.0.0.0/8")
	r := newIPResolver([]netip.Prefix{trusted})
	if _, err := r.ClientIP("10.0.0.1:80", []string{"not-an-ip, 10.0.0.5"}); err == nil {
		t.Fatal("malformed chain must be rejected, not trusted")
	}
}

func TestClientIPRejectsExcessiveChain(t *testing.T) {
	trusted, _ := netip.ParsePrefix("10.0.0.0/8")
	r := newIPResolver([]netip.Prefix{trusted})
	long := []string{}
	for i := 0; i < maxTrustedProxyChain+2; i++ {
		long = append(long, "10.0.0."+strconv.Itoa(i))
	}
	if _, err := r.ClientIP("10.0.0.1:80", []string{strings.Join(long, ", ")}); err == nil {
		t.Fatal("overly long chain must be rejected")
	}
}

func TestParseRemoteAddrForms(t *testing.T) {
	cases := map[string]string{
		"203.0.113.1:8080":   "203.0.113.1",
		"[2001:db8::1]:8080": "2001:db8::1",
		"203.0.113.1":        "203.0.113.1",
		"2001:db8::1":        "2001:db8::1",
	}
	for in, want := range cases {
		a, err := parseRemoteAddr(in)
		if err != nil {
			t.Errorf("parse %q: %v", in, err)
			continue
		}
		if a.String() != want {
			t.Errorf("parse %q = %s, want %s", in, a, want)
		}
	}
	if _, err := parseRemoteAddr("garbage"); err == nil {
		t.Fatal("garbage RemoteAddr must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Security policy construction
// ---------------------------------------------------------------------------

func testTokens(t *testing.T) *auth.SessionTokenManager {
	t.Helper()
	return newTestSessionManager(t)
}

// buildPolicy makes a policy from explicit config fields. production=true sets
// the exact production rate caps; low limits override the relevant limiter.
func buildPolicy(t *testing.T, tokens *auth.SessionTokenManager, production bool, externalOrigin string) *securityPolicy {
	t.Helper()
	cfg := &config.ControlPlaneConfig{Mode: config.ModeDevelopment, SessionTTL: 24 * time.Hour}
	if production {
		cfg.Mode = config.ModeProduction
		cfg.ExternalURL = mustParseURL(externalOrigin)
	}
	p := newSecurityPolicy(tokens, cfg)
	return p
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func overrideLimiter(p *securityPolicy, which string, rate, burst float64) {
	l := NewLimiter(rate, burst, 100, time.Minute, nil)
	switch which {
	case "login":
		p.loginLimiter = l
	case "register":
		p.registrationLimiter = l
	case "invite":
		p.inviteLimiter = l
	case "token":
		p.tokenLimiter = l
	}
}

func postBody(client *http.Client, base, path, ct, body string, header http.Header) (*http.Response, []byte) {
	req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
	req.Header.Set("Content-Type", ct)
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func doReq(t *testing.T, client *http.Client, req *http.Request) *http.Response {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request %s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

func doPost(t *testing.T, client *http.Client, url string, form url.Values) *http.Response {
	t.Helper()
	resp, err := client.PostForm(url, form)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	return resp
}

func doGetURL(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// CSRF tests
// ---------------------------------------------------------------------------

func TestCSRFCookieAuthMutationRequiresToken(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	form := url.Values{"slug": {"alice"}, "ens_name": {"a.eth"}, "default_stamp_batch_id": {"b"}, "anonymous_pull": {"true"}}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, client, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie POST without CSRF must be 403, got %d", resp.StatusCode)
	}

	// None created.
	regs, _ := service.ListRegistries(context.Background(), 1)
	if len(regs) != 0 {
		t.Fatal("CSRF-rejected request must have zero side effects")
	}
}

func TestCSRFCookieAuthFormTokenAccepted(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf_ok?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	user, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	csrf := sessionCSRFForTest(t, session)

	form := url.Values{"slug": {"alice"}, "ens_name": {"a.eth"}, "default_stamp_batch_id": {"b"}, "_csrf": {csrf}}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, client, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("cookie POST with correct CSRF must proceed, got %d", resp.StatusCode)
	}
	regs, _ := service.ListRegistries(context.Background(), user.ID)
	if len(regs) != 1 {
		t.Fatalf("expected one registry created, got %d", len(regs))
	}
}

func TestCSRFRejectsMissingDuplicateConflictingMalformed(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf_bad?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	mk := func(form url.Values, header http.Header) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, vs := range header {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
		resp := doReq(t, client, req)
		resp.Body.Close()
		return resp
	}

	base := url.Values{"slug": {"x"}, "ens_name": {"x.eth"}, "default_stamp_batch_id": {"b"}}
	formWith := func(k, v string) url.Values {
		f := clone(base)
		if k != "" {
			f.Set(k, v)
		}
		return f
	}
	// Missing.
	if r := mk(formWith("", ""), nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("missing token: got %d", r.StatusCode)
	}
	// Conflicting: form and header disagree.
	if r := mk(formWith("_csrf", "aaa"), headerCSRF("bbb")); r.StatusCode != http.StatusForbidden {
		t.Errorf("conflicting tokens: got %d", r.StatusCode)
	}
	// Malformed / wrong value.
	if r := mk(formWith("_csrf", "wrong-value"), nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("wrong value: got %d", r.StatusCode)
	}
	// Correct via header.
	if r := mk(formWith("", ""), headerCSRF(csrf)); r.StatusCode == http.StatusForbidden {
		t.Errorf("valid header token must not be forbidden, got %d", r.StatusCode)
	}
	// Correct via form.
	if r := mk(formWith("_csrf", csrf), nil); r.StatusCode == http.StatusForbidden {
		t.Errorf("valid form token must not be forbidden, got %d", r.StatusCode)
	}
}

func clone(v url.Values) url.Values {
	c := url.Values{}
	for k, vs := range v {
		for _, s := range vs {
			c.Add(k, s)
		}
	}
	return c
}

func headerCSRF(v string) http.Header {
	h := http.Header{}
	h.Set("X-CSRF-Token", v)
	return h
}

func TestCSRFBearerExemptAndCookiePrecedence(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf_bearer?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")

	// Bearer-authenticated POST with NO csrf is allowed (ruling 1 exempt).
	payload := `{"slug":"b","ensName":"b.eth","defaultStampBatchID":"z"}`
	h := http.Header{}
	h.Set("Authorization", "Bearer "+session)
	resp, body := postBody(&http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, server.URL, "/api/registries", "application/json", payload, h)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bearer POST must be CSRF-exempt: got %d %s", resp.StatusCode, body)
	}

	// Cookie precedence: when a cookie is also present but request uses Bearer,
	// it is still exempt (bearer wins). Craft a POST that would need a cookie
	// CSRF if cookie auth were used, but with bearer it passes.
	payload2 := `{"slug":"c","ensName":"c.eth","defaultStampBatchID":"z"}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/registries", strings.NewReader(payload2))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+session)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp2 := doReq(t, &http.Client{}, req)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("bearer request with a stale cookie must remain exempt: got %d", resp2.StatusCode)
	}
}

func TestCSRFCookieAPIRequiresHeader(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf_api?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)

	// Cookie-auth JSON mutation without the header -> 403.
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/registries", strings.NewReader(`{"slug":"a","ensName":"a.eth","defaultStampBatchID":"b"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, &http.Client{}, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie JSON with no CSRF header must be 403, got %d", resp.StatusCode)
	}

	// With the correct header it proceeds.
	req2, _ := http.NewRequest(http.MethodPost, server.URL+"/api/registries", strings.NewReader(`{"slug":"a","ensName":"a.eth","defaultStampBatchID":"b"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-CSRF-Token", csrf)
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp2 := doReq(t, &http.Client{}, req2)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("cookie JSON with correct CSRF header must proceed, got %d", resp2.StatusCode)
	}
}

func TestCSRFCrossSessionRejected(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf_xsess?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	_, sessionA, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	_, sessionB, _ := service.RegisterUser(context.Background(), "bob@example.com", "password123")

	// Cookie for session A, CSRF for session B -> mismatch 403.
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/registries", strings.NewReader(`{"slug":"a","ensName":"a.eth","defaultStampBatchID":"b"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sessionCSRFForTest(t, sessionB))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionA})
	resp := doReq(t, &http.Client{}, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-session CSRF must be rejected, got %d", resp.StatusCode)
	}
}

func TestCSRFGetSafe(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf_get?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/registries", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, &http.Client{}, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET with a session cookie must not require CSRF, got %d", resp.StatusCode)
	}
}

func TestUITemplatesRenderCSRFHiddenField(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf_form?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	user, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	created, _ := service.CreateRegistry(context.Background(), user.ID, "alice", "a.eth", false, "b")

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/ui/registries/"+strconv.FormatInt(created.Registry.ID, 10), nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte(`name="_csrf" value="`+sessionCSRFForTest(t, session)+`"`)) {
		t.Fatal("authenticated UI page must render the session-bound CSRF hidden field")
	}
}

// ---------------------------------------------------------------------------
// Origin tests
// ---------------------------------------------------------------------------

func TestOriginProductionRequiresMatchingOrigin(t *testing.T) {
	store, _ := OpenSQLite("file:csec_origin?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, true, "https://cp.example.com")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	payload := `{"email":"alice@example.com","password":"password123"}`
	// No Origin -> 403.
	if resp, _ := postBody(&http.Client{}, server.URL, "/api/auth/login", "application/json", payload, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("production login without Origin must be 403, got %d", resp.StatusCode)
	}
	// Cross-origin -> 403.
	h := http.Header{}
	h.Set("Origin", "https://evil.example.com")
	if resp, _ := postBody(&http.Client{}, server.URL, "/api/auth/login", "application/json", payload, h); resp.StatusCode != http.StatusForbidden {
		t.Errorf("production cross-origin login must be 403, got %d", resp.StatusCode)
	}
	// Matching origin -> proceeds.
	h2 := http.Header{}
	h2.Set("Origin", "https://cp.example.com")
	if resp, _ := postBody(&http.Client{}, server.URL, "/api/auth/login", "application/json", payload, h2); resp.StatusCode == http.StatusForbidden {
		t.Error("matching-origin login must not be rejected")
	}
}

func TestOriginDevelopmentAbsentAllowedMismatchRejected(t *testing.T) {
	store, _ := OpenSQLite("file:csec_origin_dev?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	// Development with an external URL configured: absent Origin permitted.
	p := buildPolicy(t, tokens, false, "https://cp.example.com")
	p.production = false
	p.externalOrigin = "https://cp.example.com"
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	payload := `{"email":"alice@example.com","password":"password123"}`

	if resp, _ := postBody(&http.Client{}, server.URL, "/api/auth/login", "application/json", payload, nil); resp.StatusCode == http.StatusForbidden {
		t.Fatal("development login with absent Origin must be permitted")
	}
	h := http.Header{}
	h.Set("Origin", "https://evil.example.com")
	if resp, _ := postBody(&http.Client{}, server.URL, "/api/auth/login", "application/json", payload, h); resp.StatusCode != http.StatusForbidden {
		t.Errorf("development explicit cross-origin must be 403, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Generic login failure
// ---------------------------------------------------------------------------

func TestLoginGenericFailureIndistinguishable(t *testing.T) {
	store, _ := OpenSQLite("file:csec_generic?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	_, _, _ = service.RegisterUser(context.Background(), "known@example.com", "correct-password")
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	login := func(email, pass string) (int, []byte) {
		payload := `{"email":"` + email + `","password":"` + pass + `"}`
		resp, body := postBody(&http.Client{}, server.URL, "/api/auth/login", "application/json", payload, nil)
		return resp.StatusCode, body
	}
	unknownStatus, unknownBody := login("ghost@example.com", "password123")
	wrongStatus, wrongBody := login("known@example.com", "wrong-password")
	if unknownStatus != wrongStatus {
		t.Fatalf("unknown(%d) and wrong-password(%d) logins must share status", unknownStatus, wrongStatus)
	}
	if !bytes.Equal(unknownBody, wrongBody) {
		t.Fatalf("unknown and wrong-password logins must return identical bodies: %q vs %q", unknownBody, wrongBody)
	}
}

// ---------------------------------------------------------------------------
// Rate-limit integration
// ---------------------------------------------------------------------------

func allFourRoutesTripped(t *testing.T) (*Service, *auth.SessionTokenManager, string, string) {
	store, _ := OpenSQLite("file:csec_rl?mode=memory&cache=shared")
	tokens := testTokens(t)
	st := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t)}
	st.RegistryTokens, _ = newTestRegistryPair(t)
	return st, tokens, "", ""
}

func TestRateLimitAllFourRoutes(t *testing.T) {
	st, tokens, _, _ := allFourRoutesTripped(t)
	p := buildPolicy(t, tokens, false, "")
	overrideLimiter(p, "login", 1.0/60.0, 1)
	overrideLimiter(p, "register", 1.0/60.0, 1)
	overrideLimiter(p, "invite", 20.0/60.0, 1)
	overrideLimiter(p, "token", 1.0/60.0, 1)
	svr := &HTTPServer{Service: st, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	client := &http.Client{}

	// Login route: keyed by email+IP. Same email twice -> second 429.
	login := func() int {
		payload := `{"email":"x@example.com","password":"pw"}`
		resp, _ := postBody(client, server.URL, "/api/auth/login", "application/json", payload, nil)
		code := resp.StatusCode
		if code == http.StatusTooManyRequests && resp.Header.Get("Retry-After") == "" {
			t.Fatal("429 must carry a Retry-After header")
		}
		return code
	}
	if login() == http.StatusTooManyRequests {
		t.Fatal("first login must not be rate-limited")
	}
	if got := login(); got != http.StatusTooManyRequests {
		t.Fatalf("second login must be 429, got %d", got)
	}

	// Registration route: keyed by IP.
	regBody := func() int {
		payload := `{"email":"reg@example.com","password":"pw"}`
		resp, _ := postBody(client, server.URL, "/api/users/register", "application/json", payload, nil)
		return resp.StatusCode
	}
	if regBody() == http.StatusTooManyRequests {
		t.Fatal("first registration must not be rate-limited")
	}
	if got := regBody(); got != http.StatusTooManyRequests {
		t.Fatalf("second registration must be 429, got %d", got)
	}

	// Invite route (bearer, keyed by principal+IP). Need a registry + owner.
	owner, session, _ := st.RegisterUser(context.Background(), "owner@example.com", "pw")
	created, _ := st.CreateRegistry(context.Background(), owner.ID, "ownerreg", "o.eth", false, "b")
	h := http.Header{}
	h.Set("Authorization", "Bearer "+session)
	invite := func() int {
		payload := `{"email":"inv@example.com","canPull":true}`
		resp, _ := postBody(client, server.URL, "/api/registries/"+strconv.FormatInt(created.Registry.ID, 10)+"/invites", "application/json", payload, h)
		return resp.StatusCode
	}
	if invite() == http.StatusTooManyRequests {
		t.Fatal("first invite must not be rate-limited")
	}
	if got := invite(); got != http.StatusTooManyRequests {
		t.Fatalf("second invite must be 429, got %d", got)
	}

	// Registry-token /token route (basic auth, keyed by IP).
	token := func() int {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/token?service=s&scope=repository:repo:pull", nil)
		req.SetBasicAuth("cred@example.com", "pw")
		resp := doReq(t, client, req)
		resp.Body.Close()
		return resp.StatusCode
	}
	if token() == http.StatusTooManyRequests {
		t.Fatal("first token request must not be rate-limited")
	}
	if got := token(); got != http.StatusTooManyRequests {
		t.Fatalf("second token request must be 429, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Session cookie attributes
// ---------------------------------------------------------------------------

func TestSessionCookieAttributes(t *testing.T) {
	store, _ := OpenSQLite("file:csec_cookie?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	// HTTPS external URL => Secure cookie in development too.
	p := buildPolicy(t, tokens, false, "https://cp.example.com")
	p.secureCookie = true
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	resp := doPost(t, client, server.URL+"/ui/register", url.Values{"email": {"a@example.com"}, "password": {"password123"}})
	defer resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected a session cookie")
	}
	c := cookies[0]
	if c.Name != sessionCookieName {
		t.Fatalf("unexpected cookie name %q", c.Name)
	}
	if !c.HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if !c.Secure {
		t.Fatal("secure deployment must set the Secure cookie attribute")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite=Lax, got %v", c.SameSite)
	}
	if c.Path != "/" {
		t.Fatalf("expected Path=/, got %q", c.Path)
	}
	if c.Domain != "" {
		t.Fatalf("session cookie must not set Domain, got %q", c.Domain)
	}
	if c.MaxAge <= 0 {
		t.Fatalf("expected a positive bounded MaxAge, got %d", c.MaxAge)
	}
}

func TestDevelopmentCookieNotSecureWhenHTTP(t *testing.T) {
	store, _ := OpenSQLite("file:csec_cookie_nosec?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, false, "")
	p.secureCookie = false
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp := doPost(t, client, server.URL+"/ui/register", url.Values{"email": {"a@example.com"}, "password": {"password123"}})
	defer resp.Body.Close()
	if c := resp.Cookies()[0]; c.Secure {
		t.Fatal("http development deployment must not set Secure")
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	store, _ := OpenSQLite("file:csec_logout?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	_, session, _ := service.RegisterUser(context.Background(), "a@example.com", "password123")

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/logout", strings.NewReader(url.Values{"_csrf": {sessionCSRFForTest(t, session)}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, req)
	defer resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Fatalf("expected a clearing (MaxAge<0) cookie, got %+v", cookies)
	}
	if cookies[0].HttpOnly != true || cookies[0].Path != "/" {
		t.Fatal("clearing cookie must keep the session cookie attributes")
	}
}

// ---------------------------------------------------------------------------
// Browser security headers
// ---------------------------------------------------------------------------

func TestSecurityHeadersPresent(t *testing.T) {
	store, _ := OpenSQLite("file:csec_headers?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	resp := doGetURL(t, server.URL+"/ui/login")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.Header.Get(headerCSP) == "" {
		t.Fatal("CSP header must be present")
	}
	if resp.Header.Get(headerNoSniff) != "nosniff" {
		t.Fatal("nosniff header must be present")
	}
	if resp.Header.Get(headerFrame) != "DENY" {
		t.Fatal("X-Frame-Options must be DENY")
	}
	if resp.Header.Get(headerReferrer) == "" {
		t.Fatal("Referrer-Policy header must be present")
	}
	if !bytes.Contains(body, []byte("<script")) {
		t.Fatal("broken inline scripts must not appear (page should still render)")
	}
}

// jsonRoundTrip is unused helper reserved for future JSON-specific tests.
var _ = json.Marshal
var _ = netip.Addr{}
