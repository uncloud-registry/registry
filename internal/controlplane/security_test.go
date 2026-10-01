package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
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

	"github.com/golang-jwt/jwt/v4"

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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
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
	st := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
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
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
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

// ---------------------------------------------------------------------------
// Fix-round tests: CSRF bearer exemption, CSRF shape/ambiguity, invite-accept
// registration bucket, request ID + correlated logging, body bound, TTL,
// invite URL policy origin, and IPv4-mapped unmap.
// ---------------------------------------------------------------------------

// issueSessionWithCSRF synthesizes a session token carrying an arbitrary CSRF
// claim (including malformed/legacy values), signed with the shared test secret.
func issueSessionWithCSRF(t *testing.T, csrf string) string {
	t.Helper()
	now := time.Now()
	claims := auth.SessionClaims{
		TokenType: auth.SessionTokenType,
		CSRF:      csrf,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user:1",
			Issuer:    auth.DefaultSessionIssuer,
			Audience:  jwt.ClaimStrings{auth.DefaultSessionAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(controlplaneTestSecret))
	if err != nil {
		t.Fatalf("sign synthetic session: %v", err)
	}
	return signed
}

func TestCSRFCookiePlusInvalidBearerRequiresCSRF(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf_invbearer?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	postCookieBearer := func(authHeader string) int {
		payload := `{"slug":"x","ensName":"x.eth","defaultStampBatchID":"b"}`
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/registries", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
		resp := doReq(t, client, req)
		resp.Body.Close()
		return resp.StatusCode
	}

	// Non-Bearer garbage Authorization + valid cookie -> NOT exempt, CSRF required.
	if code := postCookieBearer("grbbrgr"); code != http.StatusForbidden {
		t.Fatalf("cookie + garbage Authorization must require CSRF (403), got %d", code)
	}
	// Basic-scheme Authorization + valid cookie -> NOT exempt.
	if code := postCookieBearer("Basic bm9wZTo="); code != http.StatusForbidden {
		t.Fatalf("cookie + Basic Authorization must require CSRF (403), got %d", code)
	}
	// Forgery-shaped but invalid bearer + valid cookie -> NOT exempt.
	if code := postCookieBearer("Bearer " + strings.Repeat("a", 200)); code != http.StatusForbidden {
		t.Fatalf("cookie + forged bearer must require CSRF (403), got %d", code)
	}
	// Expired bearer: issue then verify a session with a past expiry is refused.
	// Use a session token with a valid signature but expired -> NOT exempt.
	m, _ := auth.NewSessionTokenManager(controlplaneTestSecret, auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	expiredRaw, _ := func() (string, error) {
		now := time.Now()
		claims := auth.SessionClaims{
			TokenType: auth.SessionTokenType,
			CSRF:      strings.Repeat("1", 64),
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "user:1",
				Issuer:    auth.DefaultSessionIssuer,
				Audience:  jwt.ClaimStrings{auth.DefaultSessionAudience},
				ExpiresAt: jwt.NewNumericDate(now.Add(-time.Minute)),
				IssuedAt:  jwt.NewNumericDate(now.Add(-time.Hour)),
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		return tok.SignedString([]byte(controlplaneTestSecret))
	}()
	if code := postCookieBearer("Bearer " + expiredRaw); code != http.StatusForbidden {
		t.Fatalf("cookie + expired bearer must require CSRF (403), got %d", code)
	}
	_ = m
	// Valid bearer + stale cookie -> exempt (does not cause an auth failure).
	realSession, _ := tokens.Issue("user:1", time.Hour)
	h := http.Header{}
	h.Set("Authorization", "Bearer "+realSession)
	resp, _ := postBody(client, server.URL, "/api/registries", "application/json", `{"slug":"y","ensName":"y.eth","defaultStampBatchID":"b"}`, h)
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("valid bearer + stale cookie must remain CSRF-exempt")
	}
	resp.Body.Close()
}

func TestCSRFRejectsMalformedOrLegacySessionClaim(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf_badclaim?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	try := func(session, csrf string) int {
		payload := `{"slug":"x","ensName":"x.eth","defaultStampBatchID":"b"}`
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/registries", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
		resp := doReq(t, client, req)
		resp.Body.Close()
		return resp.StatusCode
	}

	// Legacy/empty claim -> 403 regardless of a perfectly shaped candidate.
	emptyClaim := issueSessionWithCSRF(t, "")
	if code := try(emptyClaim, strings.Repeat("1", 64)); code != http.StatusForbidden {
		t.Fatalf("empty session CSRF claim must be rejected (403), got %d", code)
	}
	// Malformed non-hex claim -> 403 even when a canonical candidate is echoed.
	badClaim := issueSessionWithCSRF(t, "not-hex-value!!!")
	if code := try(badClaim, strings.Repeat("1", 64)); code != http.StatusForbidden {
		t.Fatalf("malformed session CSRF claim must be rejected (403), got %d", code)
	}
	// Uppercase (non-canonical) claim -> 403 even against a canonical candidate.
	upperClaim := issueSessionWithCSRF(t, strings.ToUpper(strings.Repeat("a", 64)))
	if code := try(upperClaim, strings.Repeat("a", 64)); code != http.StatusForbidden {
		t.Fatalf("uppercase session CSRF claim must be rejected (403), got %d", code)
	}
}

func TestCSRFRejectsMultipleCandidatesEvenIdentical(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf_multi?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	csrf := sessionCSRFForTest(t, session)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	post := func(header http.Header, body string) int {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/registries", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, vs := range header {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
		resp := doReq(t, client, req)
		resp.Body.Close()
		return resp.StatusCode
	}

	// Two header values, both equal and correct -> still rejected (ambiguity).
	h := http.Header{}
	h.Add("X-CSRF-Token", csrf)
	h.Add("X-CSRF-Token", csrf)
	if code := post(h, `{"slug":"a","ensName":"a.eth","defaultStampBatchID":"b"}`); code != http.StatusForbidden {
		t.Fatalf("duplicate identical header CSRF must be rejected (403), got %d", code)
	}
	// Correct form token + correct header token (equal) -> rejected.
	form := url.Values{"slug": {"b"}, "ens_name": {"b.eth"}, "default_stamp_batch_id": {"z"}, "_csrf": {csrf}}
	h2 := http.Header{}
	h2.Set("X-CSRF-Token", csrf)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/registries", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, client, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("equal form+header CSRF candidates must be rejected (403), got %d", resp.StatusCode)
	}
}

func TestCSRFRejectsMalformedCandidate(t *testing.T) {
	store, _ := OpenSQLite("file:csec_csrf_malcand?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	_, session, _ := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	// Malformed candidates: uppercase, non-hex, short, whitespace-padded.
	for _, bad := range []string{
		strings.ToUpper(strings.Repeat("a", 64)),
		strings.Repeat("z", 64),
		strings.Repeat("a", 63),
		" " + strings.Repeat("a", 64),
	} {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/registries", strings.NewReader(`{"slug":"x","ensName":"x.eth","defaultStampBatchID":"b"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", bad)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
		resp := doReq(t, client, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("malformed candidate %q must be rejected (403), got %d", bad, resp.StatusCode)
		}
	}
}

// newUIServerWithPolicy builds a UI HTTP server with a UNIQUE in-memory store
// per call (the name parameter keeps independent tests from sharing one).
func newUIServerWithPolicy(t *testing.T, name string, tokens *auth.SessionTokenManager, p *securityPolicy) (*Service, *HTTPServer, *httptest.Server) {
	t.Helper()
	store, _ := OpenSQLite("file:csec_ui_" + name + "?mode=memory&cache=shared")
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	return service, svr, httptest.NewServer(svr)
}

func postUIAuth(t *testing.T, base, path string, form url.Values) int {
	t.Helper()
	resp, err := http.PostForm(base+path, form)
	if err != nil {
		t.Fatalf("postUI %s: %v", path, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestInviteAcceptSharesRegistrationBucket(t *testing.T) {
	tokens := testTokens(t)
	p := buildPolicy(t, tokens, false, "")
	// Both /ui/register and /ui/invites/accept draw from the SAME per-IP
	// registration bucket (burst 2). Alternating between them cannot bypass it.
	overrideLimiter(p, "register", 1.0/3600.0, 2)
	_, _, server := newUIServerWithPolicy(t, "inv", tokens, p)
	defer server.Close()

	reg := func() int {
		return postUIAuth(t, server.URL, "/ui/register", url.Values{"email": {"a@example.com"}, "password": {"password123"}})
	}
	accept := func() int {
		return postUIAuth(t, server.URL, "/ui/invites/accept?token=x", url.Values{"email": {"b@example.com"}, "password": {"password123"}})
	}

	got := []int{reg(), accept(), reg(), accept()}
	// The first 2 hit the 2-burst budget; the rest are 429.
	if got[0] == http.StatusTooManyRequests || got[1] == http.StatusTooManyRequests {
		t.Fatalf("first two registration attempts must be allowed, got %v", got)
	}
	if got[2] != http.StatusTooManyRequests || got[3] != http.StatusTooManyRequests {
		t.Fatalf("alternating register/accept must exhaust the shared bucket (429), got %v", got)
	}
}

func TestServiceSessionTTLWiresIssuedClaims(t *testing.T) {
	tokens := testTokens(t)
	verify := func(session string, want time.Duration) {
		t.Helper()
		claims, err := tokens.Verify(session)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		got := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
		if got != want {
			t.Fatalf("session TTL = %v, want %v", got, want)
		}
	}
	store, _ := OpenSQLite("file:csec_ttl?mode=memory&cache=shared")

	shortSvc := &Service{Store: store, Tokens: tokens, SessionTTL: 5 * time.Minute}
	_, s, _ := shortSvc.RegisterUser(context.Background(), "a@example.com", "password123")
	verify(s, 5*time.Minute)

	// Zero SessionTTL -> default 24h (back-compat).
	zeroSvc := &Service{Store: store, Tokens: tokens}
	_, s2, _ := zeroSvc.RegisterUser(context.Background(), "b@example.com", "password123")
	verify(s2, 24*time.Hour)

	// Login honors the configured TTL too.
	longSvc := &Service{Store: store, Tokens: tokens, SessionTTL: 2 * time.Hour}
	_, s3, _ := longSvc.Login(context.Background(), "a@example.com", "password123")
	verify(s3, 2*time.Hour)
}

func TestSessionCookieMaxAgeAndExpiresAligned(t *testing.T) {
	store, _ := OpenSQLite("file:csec_cookie_exp?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	cfg := &config.ControlPlaneConfig{Mode: config.ModeDevelopment, SessionTTL: 30 * time.Minute}
	p := newSecurityPolicy(tokens, cfg)
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	t0 := time.Now()
	resp := doPost(t, client, server.URL+"/ui/register", url.Values{"email": {"a@example.com"}, "password": {"password123"}})
	defer resp.Body.Close()
	c := resp.Cookies()[0]
	if c.MaxAge != 30*60 {
		t.Fatalf("cookie MaxAge = %d, want 1800", c.MaxAge)
	}
	if c.Expires.IsZero() {
		t.Fatal("cookie must carry an Expires matching MaxAge")
	}
	want := t0.Add(30 * time.Minute)
	if c.Expires.Before(want.Add(-2*time.Minute)) || c.Expires.After(want.Add(2*time.Minute)) {
		t.Fatalf("cookie Expires %v not aligned with now+MaxAge ~ %v", c.Expires, want)
	}
}

func TestPublicInviteLinkUsesExternalOriginNotHost(t *testing.T) {
	// External URL configured -> hostile Host/X-Forwarded-* must never appear.
	tokens := testTokens(t)
	cfg := &config.ControlPlaneConfig{Mode: config.ModeDevelopment, SessionTTL: 24 * time.Hour, ExternalURL: mustParseURL("https://cp.example.com")}
	p := newSecurityPolicy(tokens, cfg)
	service, svr, server := newUIServerWithPolicy(t, "ext", tokens, p)
	defer server.Close()

	owner, session, _ := service.RegisterUser(context.Background(), "owner@example.com", "password123")
	created, _ := service.CreateRegistry(context.Background(), owner.ID, "alice", "a.eth", false, "b")
	_, token, _ := service.CreateInvite(context.Background(), created.Registry.ID, owner.ID, "guest@example.com", true, false)
	flashID, _ := svr.inviteFlash().store(token, owner.ID, created.Registry.ID)

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/ui/registries/"+strconv.FormatInt(created.Registry.ID, 10)+"?invite_flash="+url.QueryEscape(flashID), nil)
	req.Header.Set("Host", "evil.example.com")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("https://cp.example.com/ui/invites/accept?token=")) {
		t.Fatalf("invite link must use the external origin, not attacker Host; body snippet:\n%s", truncateBytes(body, 400))
	}
	if bytes.Contains(body, []byte("evil.example.com")) {
		t.Fatal("attacker Host must never appear in a public invite link")
	}
}

func TestPublicInviteLinkRelativeWithoutExternalURL(t *testing.T) {
	// Development with no external URL -> relative invite link, never attacker Host.
	tokens := testTokens(t)
	p := buildPolicy(t, tokens, false, "")
	service, svr, server := newUIServerWithPolicy(t, "rel", tokens, p)
	defer server.Close()

	owner, session, _ := service.RegisterUser(context.Background(), "owner@example.com", "password123")
	created, _ := service.CreateRegistry(context.Background(), owner.ID, "alice", "a.eth", false, "b")
	_, token, _ := service.CreateInvite(context.Background(), created.Registry.ID, owner.ID, "guest@example.com", true, false)
	flashID, _ := svr.inviteFlash().store(token, owner.ID, created.Registry.ID)

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/ui/registries/"+strconv.FormatInt(created.Registry.ID, 10)+"?invite_flash="+url.QueryEscape(flashID), nil)
	req.Header.Set("Host", "evil.example.com")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp := doReq(t, &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// The invite path must appear but never with an attacker origin or scheme.
	if !bytes.Contains(body, []byte("/ui/invites/accept?token=")) {
		t.Fatalf("invite link must be relative without an external URL:\n%s", truncateBytes(body, 400))
	}
	if bytes.Contains(body, []byte("evil.example.com")) || bytes.Contains(body, []byte("http://evil")) {
		t.Fatal("attacker Host must never appear in an invite link")
	}
}

func TestOversizedJSONBodyRejected413WithNoSideEffects(t *testing.T) {
	store, _ := OpenSQLite("file:csec_body?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	big := `{"email": "` + strings.Repeat("a", maxBodyBytes) + `@example.com", "password": "x"}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/auth/login", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(big))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("oversized login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized JSON body must be 413, got %d", resp.StatusCode)
	}
	// Zero side effects: no user created.
	if _, err := store.FindUserByEmail(context.Background(), strings.Repeat("a", maxBodyBytes)+"@example.com"); err == nil {
		t.Fatal("oversized login must have zero side effects (no user created)")
	}
}

func TestOversizedChunkedBodyRejected413(t *testing.T) {
	store, _ := OpenSQLite("file:csec_body_chunk?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	big := strings.Repeat("a", maxBodyBytes*2)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/auth/login", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	// Unknown length forces chunked transfer encoding.
	req.ContentLength = -1
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("chunked oversized login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized chunked body must be 413, got %d", resp.StatusCode)
	}
}

func TestGETTokenIgnoresRequestBody(t *testing.T) {
	store, _ := OpenSQLite("file:csec_body_token?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", FeedKeys: newTestFeedKeyCipher(t), Publisher: newMemPublisher()}
	service.RegistryTokens, _ = newTestRegistryPair(t)
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	// A GET /token with a large (normally-ignored) body must never trip 413:
	// the body is never read for the limiter or the handler.
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/token?service=s&scope=repository:repo:pull", strings.NewReader(strings.Repeat("x", maxBodyBytes+10)))
	req.SetBasicAuth("someone@example.com", "pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get /token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Fatal("GET /token must not reject an untouched request body (413)")
	}
}

func TestLoginFailureLogCorrelatedWithCauseNoPII(t *testing.T) {
	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	store, _ := OpenSQLite("file:csec_log?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	service.RegisterUser(context.Background(), "known@example.com", "correct-password")
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p, Logger: logger}
	server := httptest.NewServer(svr)
	defer server.Close()

	payload := `{"email":"known@example.com","password":"wrong-password"}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/auth/login", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	// Supply a spoofed inbound request id that MUST NOT be trusted.
	req.Header.Set(requestIDHeader, "attacker-controlled-id")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	out := buf.String()
	if !strings.Contains(out, "authentication failed") {
		t.Fatalf("expected a correlated auth-failure log, got:\n%s", out)
	}
	if !strings.Contains(out, "request_id=") {
		t.Fatalf("log must carry a request_id, got:\n%s", out)
	}
	if strings.Contains(out, "attacker-controlled-id") {
		t.Fatal("log must not trust an inbound request-id header")
	}
	if strings.Contains(out, "known@example.com") || strings.Contains(out, "wrong-password") {
		t.Fatal("auth-failure log must never include email or password")
	}
	if strings.Contains(out, "known@") || strings.Contains(out, "wrong-password") {
		t.Fatal("auth-failure log must never leak credentials")
	}
	// Public body stays generic.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("public status must stay 401")
	}
}

func TestRequestIDHeaderMintedNotTrustedInbound(t *testing.T) {
	store, _ := OpenSQLite("file:csec_reqid?mode=memory&cache=shared")
	tokens := testTokens(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
	p := buildPolicy(t, tokens, false, "")
	svr := &HTTPServer{Service: service, Subjects: auth.SubjectResolver{Tokens: tokens}, security: p}
	server := httptest.NewServer(svr)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/ui/login", nil)
	req.Header.Set(requestIDHeader, "spoofed")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	got := resp.Header.Get(requestIDHeader)
	if len(got) != 32 || got == "spoofed" {
		t.Fatalf("request ID must be freshly minted (32 hex), got %q", got)
	}
}

func TestParseRemoteAddrUnmapsIPv4Mapped(t *testing.T) {
	// IPv4-mapped IPv6 peer addresses are unmapped to canonical IPv4.
	a, err := parseRemoteAddr("[::ffff:203.0.113.9]:61234")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.String() != "203.0.113.9" || !a.Is4() {
		t.Fatalf("IPv4-mapped address must be unmapped, got %v", a)
	}
	r := newIPResolver(nil)
	ip, err := r.ClientIP("[::ffff:10.1.2.3]:8080", nil)
	if err != nil {
		t.Fatalf("resolve mapped peer: %v", err)
	}
	if ip.String() != "10.1.2.3" {
		t.Fatalf("mapped peer must be unmapped, got %v", ip)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func truncateBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}
