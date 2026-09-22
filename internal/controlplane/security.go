package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/config"
)

// This file implements the control plane's hard security boundary: production
// configuration defaults, session-bound CSRF, secure cookies, same-origin
// checks, trusted-proxy client-IP resolution, bounded rate limiting, generic
// login failures, and browser security headers. It is enforced for every
// request the control plane serves, regardless of mode (development only
// relaxes the caps, never the controls).

// ---------------------------------------------------------------------------
// Injectable clock (so rate-limit and refill logic is testable deterministically)
// ---------------------------------------------------------------------------

// Clock abstracts the current time for the rate limiter.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// ---------------------------------------------------------------------------
// Bounded token-bucket rate limiter
// ---------------------------------------------------------------------------

// LimiterLimits carries the bounded-bucket configuration for one limiter.
type RateLimitConfig struct {
	Rate      float64 // tokens added per second
	Burst     float64 // bucket capacity (maximum burst)
	MaxKeys   int     // hard cap on tracked keys; fail closed beyond it
	IdleAfter time.Duration
}

// Limiter counters exposed for later metrics. Read with Counters().
type LimiterCounters struct {
	Allowed          uint64
	Limited          uint64
	CapacityRejected uint64
}

type tokenBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

// Limiter is a concurrency-safe, bounded, in-memory token bucket keyed by a
// SHA-256 digest of the caller key (so raw emails/identifiers are never kept in
// memory). It refills fractionally, tolerates a backward clock, prunes idle
// buckets, and fails closed at its key capacity.
type Limiter struct {
	mu        sync.Mutex
	rate      float64
	burst     float64
	maxKeys   int
	idleAfter time.Duration
	clock     Clock
	buckets   map[[32]byte]*tokenBucket
	lastPrune time.Time

	allowed          atomic.Uint64
	limited          atomic.Uint64
	capacityRejected atomic.Uint64
}

const defaultMaxKeys = 10000

const minNeededTokens = 1.0

// NewLimiter returns a bounded token-bucket limiter. The clock may be nil to
// use the system clock.
func NewLimiter(rate, burst float64, maxKeys int, idleAfter time.Duration, clock Clock) *Limiter {
	if maxKeys <= 0 {
		maxKeys = defaultMaxKeys
	}
	if clock == nil {
		clock = realClock{}
	}
	if rate <= 0 {
		rate = 1e-9 // never divide by zero; effectively one token per ~31 years
	}
	if burst <= 0 {
		burst = 1
	}
	return &Limiter{
		rate:      rate,
		burst:     burst,
		maxKeys:   maxKeys,
		idleAfter: idleAfter,
		clock:     clock,
		buckets:   make(map[[32]byte]*tokenBucket),
	}
}

// Allow reports whether the request for key may proceed, consuming one token
// when it may. Returned retryAfter is the duration to advertise on a 429 when
// the request is denied.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	digest := sha256.Sum256([]byte(key))
	return l.allowDigest(digest)
}

func (l *Limiter) allowDigest(key [32]byte) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock.Now()
	if l.idleAfter > 0 && now.Sub(l.lastPrune) > l.idleAfter {
		l.prune(now)
		l.lastPrune = now
	}

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			// Try to make room by pruning idle buckets; fail closed if still full.
			if l.idleAfter > 0 {
				l.prune(now)
			}
			if len(l.buckets) >= l.maxKeys {
				l.capacityRejected.Add(1)
				return false, l.capacityRetryAfter()
			}
		}
		b = &tokenBucket{tokens: l.burst, last: now, lastSeen: now}
		l.buckets[key] = b
	}

	b.lastSeen = now

	// Fractional refill: only positive elapsed time adds tokens. A backward
	// clock yields no refill and is otherwise harmless.
	var elapsed float64
	if now.After(b.last) {
		elapsed = now.Sub(b.last).Seconds()
	}
	b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
	b.last = now

	if b.tokens >= minNeededTokens {
		b.tokens -= minNeededTokens
		l.allowed.Add(1)
		return true, 0
	}
	l.limited.Add(1)
	return false, l.retryAfter(b.tokens)
}

func (l *Limiter) retryAfter(tokens float64) time.Duration {
	secs := (minNeededTokens - tokens) / l.rate
	wait := time.Duration(secs * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return wait
}

func (l *Limiter) capacityRetryAfter() time.Duration {
	if l.idleAfter > 0 {
		return l.idleAfter
	}
	return time.Minute
}

// prune removes buckets idle for longer than idleAfter. Caller holds mu.
func (l *Limiter) prune(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.idleAfter {
			delete(l.buckets, k)
		}
	}
}

// Counters returns concurrency-safe cumulative counters for metrics.
func (l *Limiter) Counters() LimiterCounters {
	return LimiterCounters{
		Allowed:          l.allowed.Load(),
		Limited:          l.limited.Load(),
		CapacityRejected: l.capacityRejected.Load(),
	}
}

// Len reports the number of tracked keys (test/observability only).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// ---------------------------------------------------------------------------
// Trusted-proxy client-IP resolution
// ---------------------------------------------------------------------------

const maxTrustedProxyChain = 10

type ipResolver struct {
	trusted []netip.Prefix
}

func newIPResolver(prefixes []netip.Prefix) *ipResolver {
	return &ipResolver{trusted: prefixes}
}

func (r *ipResolver) isTrusted(addr netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ClientIP resolves the effective client address from the TCP peer and the
// X-Forwarded-For chain. RemoteAddr is parsed robustly (IPv4, IPv6 with port,
// optional zone). When no trusted proxies are configured the peer is used
// unconditionally and XFF is ignored. When proxies are configured, the peer
// must itself be trusted before any forwarded hop is believed, and the chain is
// walked right-to-left only through trusted hops; a malformed chain is rejected
// rather than trusting attacker-controlled leftmost entries.
func (r *ipResolver) ClientIP(remoteAddr string, xffHeaders []string) (netip.Addr, error) {
	peer, err := parseRemoteAddr(remoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(r.trusted) == 0 {
		return peer, nil
	}
	if !r.isTrusted(peer) {
		// The immediate peer is not a trusted proxy; its forwarded claims are
		// attacker-controlled, so use the peer itself.
		return peer, nil
	}

	entries := flattenForwardedFor(xffHeaders)
	if len(entries) == 0 {
		return peer, nil
	}
	if len(entries) > maxTrustedProxyChain {
		return netip.Addr{}, errMalformedForwardChain
	}

	// Walk right-to-left across the header, the appended order being the order
	// the proxies saw the request. The first hop from the right that is not a
	// trusted proxy is the original client; every hop in between must parse and
	// be trusted. Every parsed address is unmapped to canonical IPv4 first.
	for i := len(entries) - 1; i >= 0; i-- {
		addr, perr := netip.ParseAddr(strings.TrimSpace(entries[i]))
		if perr != nil {
			return netip.Addr{}, errMalformedForwardChain
		}
		addr = addr.Unmap()
		if !r.isTrusted(addr) {
			return addr, nil
		}
	}
	// Every hop is trusted; the leftmost entry is the client boundary.
	left, perr := netip.ParseAddr(strings.TrimSpace(entries[0]))
	if perr != nil {
		return netip.Addr{}, errMalformedForwardChain
	}
	return left.Unmap(), nil
}

var errMalformedForwardChain = &forwardChainError{}

type forwardChainError struct{}

func (*forwardChainError) Error() string { return "malformed or spoofed forwarded IP chain" }

// parseRemoteAddr extracts the IP from a TCP peer address string, tolerating
// IPv4, IPv6-with-brackets-and-port, and zone-qualified forms. IPv4-mapped
// IPv6 addresses are unmapped to their canonical IPv4 form at every boundary.
func parseRemoteAddr(remoteAddr string) (netip.Addr, error) {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return netip.Addr{}, &forwardChainError{}
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		if a, aerr := netip.ParseAddr(host); aerr == nil {
			return a.Unmap(), nil
		}
	}
	if a, err := netip.ParseAddr(remoteAddr); err == nil {
		return a.Unmap(), nil
	}
	return netip.Addr{}, &forwardChainError{}
}

// flattenForwardedFor combines potentially multiple X-Forwarded-For headers
// into a single right-to-left chain (values concatenate in header order).
func flattenForwardedFor(headers []string) []string {
	var out []string
	for _, h := range headers {
		for _, part := range strings.Split(h, ",") {
			if v := strings.TrimSpace(part); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Security policy (per-server, built from config)
// ---------------------------------------------------------------------------

// securityPolicy bundles every request-time control derived from config.
type securityPolicy struct {
	verifySession  func(string) (auth.SessionClaims, error)
	production     bool
	secureCookie   bool
	externalOrigin string
	// externalBase is the validated external origin (scheme://host), used to
	// render public absolute URLs for invite links. Empty when no external URL
	// is configured (development), in which case relative paths are used.
	externalBase string
	sessionTTL   time.Duration
	resolver     *ipResolver

	loginLimiter        *Limiter
	registrationLimiter *Limiter
	inviteLimiter       *Limiter
	tokenLimiter        *Limiter
}

// Session-bound CSRF is always enforced. Development relaxes only the rate
// caps (a local server exercises many registrations fast) and the origin rule
// (tests/CLI clients omit Origin); every state-changing cookie-authenticated
// request still needs its session-bound CSRF token in both modes.
func newSecurityPolicy(tokens *auth.SessionTokenManager, cfg *config.ControlPlaneConfig) *securityPolicy {
	p := &securityPolicy{verifySession: func(_ string) (auth.SessionClaims, error) {
		return auth.SessionClaims{}, &forwardChainError{}
	}, sessionTTL: 24 * time.Hour}
	if tokens != nil {
		p.verifySession = tokens.Verify
	}

	login, reg, invite, token := defaultRateCaps()
	trusted := []netip.Prefix(nil)
	if cfg != nil {
		p.production = cfg.IsProduction()
		p.secureCookie = cfg.SecureCookie
		p.externalOrigin = cfg.ExternalOrigin()
		if cfg.ExternalURL != nil {
			p.externalBase = cfg.ExternalOrigin()
		}
		p.sessionTTL = cfg.SessionTTL
		trusted = cfg.TrustedProxyCIDRs
	}
	p.resolver = newIPResolver(trusted)
	if !p.production {
		login, reg, invite, token = generousRateCaps()
	}
	p.loginLimiter = NewLimiter(login.Rate, login.Burst, login.MaxKeys, login.IdleAfter, nil)
	p.registrationLimiter = NewLimiter(reg.Rate, reg.Burst, reg.MaxKeys, reg.IdleAfter, nil)
	p.inviteLimiter = NewLimiter(invite.Rate, invite.Burst, invite.MaxKeys, invite.IdleAfter, nil)
	p.tokenLimiter = NewLimiter(token.Rate, token.Burst, token.MaxKeys, token.IdleAfter, nil)
	return p
}

// defaultRateCaps are the production bounds (binding): login 5/min burst 5 by
// email+IP; registration 5/hour burst 5 by IP; invite creation 20/min burst 20
// by principal+IP; registry-token issuance 30/min burst 30 by IP.
func defaultRateCaps() (RateLimitConfig, RateLimitConfig, RateLimitConfig, RateLimitConfig) {
	return RateLimitConfig{Rate: 5.0 / 60.0, Burst: 5, MaxKeys: defaultMaxKeys, IdleAfter: 15 * time.Minute},
		RateLimitConfig{Rate: 5.0 / 3600.0, Burst: 5, MaxKeys: defaultMaxKeys, IdleAfter: time.Hour},
		RateLimitConfig{Rate: 20.0 / 60.0, Burst: 20, MaxKeys: defaultMaxKeys, IdleAfter: 15 * time.Minute},
		RateLimitConfig{Rate: 30.0 / 60.0, Burst: 30, MaxKeys: defaultMaxKeys, IdleAfter: 15 * time.Minute}
}

// generousRateCaps keep the controls in place but let a single development
// server register/login many times within a minute during development without
// tripping a production-grade throttle.
func generousRateCaps() (RateLimitConfig, RateLimitConfig, RateLimitConfig, RateLimitConfig) {
	return RateLimitConfig{Rate: 1000.0 / 60.0, Burst: 1000, MaxKeys: defaultMaxKeys, IdleAfter: 15 * time.Minute},
		RateLimitConfig{Rate: 1000.0 / 3600.0, Burst: 1000, MaxKeys: defaultMaxKeys, IdleAfter: time.Hour},
		RateLimitConfig{Rate: 1000.0 / 60.0, Burst: 1000, MaxKeys: defaultMaxKeys, IdleAfter: 15 * time.Minute},
		RateLimitConfig{Rate: 1000.0 / 60.0, Burst: 1000, MaxKeys: defaultMaxKeys, IdleAfter: 15 * time.Minute}
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

var csrfContextKey = struct{}{}

// sessionClaimsFromCookie verifies the session cookie token, returning its
// claims and whether it is a valid signed session.
func (p *securityPolicy) sessionClaimsFromCookie(r *http.Request) (auth.SessionClaims, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return auth.SessionClaims{}, false
	}
	claims, err := p.verifySession(cookie.Value)
	if err != nil {
		return auth.SessionClaims{}, false
	}
	return claims, true
}

// methodIsSafe reports whether the method is non-mutating.
func methodIsSafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func isFormContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.Contains(ct, "application/x-www-form-urlencoded") || strings.Contains(ct, "multipart/form-data")
}

// checkCSRF enforces the session-bound CSRF rule for cookie-authenticated
// unsafe methods. An explicit Authorization header exempts ONLY when it is a
// syntactically canonical Bearer whose session token the configured
// verifier successfully validates. Any invalid or non-Bearer Authorization
// does NOT exempt the request — if a valid session cookie is present the
// cookie is authoritative and CSRF is required. Requests with an invalid
// bearer and no valid cookie fall through so the router's authorization
// boundary 401s. Returns false after writing a 403 when the request must be
// rejected. It never consumes a JSON body in a way that breaks the handler:
// form bodies go through the cached ParseForm path and JSON bodies are only
// checked via the header.
func (p *securityPolicy) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	if methodIsSafe(r.Method) {
		return true
	}
	if p.verifiedBearer(r) {
		// Only a verified, canonical bearer is CSRF-exempt.
		return true
	}
	claims, ok := p.sessionClaimsFromCookie(r)
	if !ok {
		// No valid session cookie: the router will 401 at the authorization
		// boundary; there is no authenticated session to protect.
		return true
	}

	// The stored session claim must itself be canonical lowercase 64-hex
	// decoding to exactly 32 bytes before comparison; a legacy or malformed
	// claim is rejected outright (403), so it can never be compared or pass.
	expected, err := decodeCSRFCandidate(claims.CSRF)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid session CSRF"})
		return false
	}

	// Collect EVERY candidate from all form fields and all headers. Exactly
	// one candidate total is required: duplicates (even identical), conflicting
	// form-vs-header pairs, and any extra value are all rejected.
	var candidates []string
	if isFormContentType(r) {
		// ParseForm caches its result, so the handler's later ParseForm reuses it.
		_ = r.ParseForm()
		candidates = append(candidates, r.PostForm["_csrf"]...)
	}
	for _, hv := range r.Header.Values("X-CSRF-Token") {
		if hv != "" {
			candidates = append(candidates, hv)
		}
	}

	if len(candidates) == 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing CSRF token"})
		return false
	}
	if len(candidates) != 1 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "conflicting CSRF tokens"})
		return false
	}
	// Strict shape/decode of the single candidate before any comparison.
	got, err := decodeCSRFCandidate(candidates[0])
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
		return false
	}
	// Constant-time compare of the decoded 32-byte values. No side effects.
	if subtle.ConstantTimeCompare(got, expected) != 1 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
		return false
	}
	*r = *r.WithContext(context.WithValue(r.Context(), csrfContextKey, claims.CSRF))
	return true
}

var errMalformedCSRF = errors.New("malformed CSRF value")

// decodeCSRFCandidate strictly validates a session CSRF value: it must be
// canonical lowercase hex, exactly 64 characters, decoding to exactly 32
// bytes. Uppercase, short, long, non-hex, whitespace-padded, and otherwise
// malformed values are rejected so no ambiguous or legacy claim can be
// compared. Returns the raw 32 byte key material for constant-time compare.
func decodeCSRFCandidate(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, errMalformedCSRF
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return nil, errMalformedCSRF
		}
	}
	out, err := hex.DecodeString(s)
	if err != nil || len(out) != 32 {
		return nil, errMalformedCSRF
	}
	return out, nil
}

// CSRFFromContext returns the verified CSRF value surfaced to request context
// (never to the authorization principal or policy).
func CSRFFromContext(ctx context.Context) string {
	v, _ := ctx.Value(csrfContextKey).(string)
	return v
}

// ---------------------------------------------------------------------------
// Origin validation for unauthenticated login/register forms
// ---------------------------------------------------------------------------

// checkOrigin enforces the login/register same-origin rule (ruling 1,
// unauthenticated boundary). Production requires an Origin exactly equal to the
// configured external origin; development permits an absent Origin but rejects
// an explicit mismatch when an external URL is configured. Runs before any
// credentials are touched.
func (p *securityPolicy) checkOrigin(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost || !isLoginRegisterRoute(r.URL.Path) {
		return true
	}
	origin := r.Header.Get("Origin")
	if p.production {
		if origin == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin required"})
			return false
		}
		if !constantEqual(origin, p.externalOrigin) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request rejected"})
			return false
		}
		return true
	}
	// Development: absent Origin allowed; explicit mismatch rejected when a
	// canonical external URL is configured.
	if origin == "" {
		return true
	}
	if p.externalOrigin != "" && !constantEqual(origin, p.externalOrigin) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request rejected"})
		return false
	}
	return true
}

func isLoginRegisterRoute(path string) bool {
	return path == "/api/auth/login" || path == "/api/users/register" ||
		path == "/ui/login" || path == "/ui/register" || path == "/ui/invites/accept"
}

func constantEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------------------------------------------------------------------------
// Rate-limit enforcement across routes
// ---------------------------------------------------------------------------

type routeClass string

const (
	routeNone   routeClass = ""
	routeLogin  routeClass = "login"
	routeReg    routeClass = "register"
	routeInvite routeClass = "invite"
	routeToken  routeClass = "token"
)

func classifyRoute(method string, path string) routeClass {
	switch path {
	case "/api/auth/login", "/ui/login":
		if method == http.MethodPost {
			return routeLogin
		}
	case "/api/users/register", "/ui/register", "/ui/invites/accept":
		// /ui/invites/accept can create an account (RegisterAndAcceptInvite),
		// so it always draws from the same per-IP registration bucket as
		// /ui/register and cannot bypass it by alternating routes. Even when a
		// signed-in user just accepts an invite, the registration cap still
		// applies to this account-creation-capable route.
		if method == http.MethodPost {
			return routeReg
		}
	case "/token":
		if method == http.MethodGet {
			return routeToken
		}
	}
	if strings.HasSuffix(path, "/invites") && method == http.MethodPost {
		return routeInvite
	}
	return routeNone
}

func (p *securityPolicy) principalFor(r *http.Request) string {
	if authz := r.Header.Get("Authorization"); authz != "" {
		if subject := p.verifySubject(authz); subject != "" {
			return subject
		}
	}
	if claims, ok := p.sessionClaimsFromCookie(r); ok {
		return claims.Subject
	}
	return ""
}

func (p *securityPolicy) verifySubject(authz string) string {
	bearer := strings.TrimPrefix(authz, "Bearer ")
	if bearer == authz {
		return ""
	}
	claims, err := p.verifySession(bearer)
	if err != nil {
		return ""
	}
	return claims.Subject
}

// verifiedBearer reports whether the request's Authorization header is a
// syntactically canonical Bearer whose session token the configured verifier
// successfully validates. It is the ONLY condition under which a bearer
// request is CSRF-exempt. A non-Bearer scheme, a malformed header, an
// unverifiable/forged/expired token, or an empty token all return false.
func (p *securityPolicy) verifiedBearer(r *http.Request) bool {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return false
	}
	bearer := strings.TrimPrefix(authz, "Bearer ")
	if bearer == authz {
		// Not the canonical "Bearer " scheme.
		return false
	}
	if strings.TrimSpace(bearer) == "" {
		return false
	}
	if _, err := p.verifySession(bearer); err != nil {
		return false
	}
	return true
}

func (p *securityPolicy) writeRateLimited(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.FormatInt(int64(math.Ceil(wait.Seconds())), 10))
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests, please try again later"})
}

// checkRateLimit enforces the per-route bucket before any expensive credential
// work. The route class is supplied by the caller (classified BEFORE any body
// is read) so email extraction only happens on login routes. Keys are hashed in
// memory and never stored raw.
func (p *securityPolicy) checkRateLimit(w http.ResponseWriter, r *http.Request, class routeClass, clientIP netip.Addr, email string) bool {
	if class == routeNone {
		return true
	}
	key := ""
	switch class {
	case routeLogin:
		key = hashLimiterKey(NormalizeEmail(email) + "|" + clientIP.String())
	case routeReg:
		key = hashLimiterKey(clientIP.String())
	case routeInvite:
		key = hashLimiterKey(p.principalFor(r) + "|" + clientIP.String())
	case routeToken:
		key = hashLimiterKey(clientIP.String())
	}
	limiter := p.limiterFor(class)
	allowed, wait := limiter.Allow(key)
	if !allowed {
		p.writeRateLimited(w, wait)
		return false
	}
	return true
}

func (p *securityPolicy) limiterFor(class routeClass) *Limiter {
	switch class {
	case routeLogin:
		return p.loginLimiter
	case routeReg:
		return p.registrationLimiter
	case routeInvite:
		return p.inviteLimiter
	case routeToken:
		return p.tokenLimiter
	}
	return nil
}

func hashLimiterKey(k string) string {
	sum := sha256.Sum256([]byte(k))
	var b strings.Builder
	for _, x := range sum {
		const hexdig = "0123456789abcdef"
		b.WriteByte(hexdig[x>>4])
		b.WriteByte(hexdig[x&0xf])
	}
	return b.String()
}

// loginEmail peels the email from a login/register form or JSON body without
// breaking the handler: it reads and restores the body so the handler can parse
// it again.
func loginEmail(r *http.Request) string {
	if isFormContentType(r) {
		_ = r.ParseForm()
		return r.PostFormValue("email")
	}
	body, err := readBody(r)
	if err != nil {
		return ""
	}
	var creds struct {
		Email string `json:"email"`
	}
	_ = json.Unmarshal(body, &creds)
	return creds.Email
}

// ---------------------------------------------------------------------------
// Request middleware
// ---------------------------------------------------------------------------

var clientIPContextKey = struct{}{}

// ClientIPFromContext returns the resolved client address for the request.
func ClientIPFromContext(ctx context.Context) (netip.Addr, bool) {
	a, ok := ctx.Value(clientIPContextKey).(netip.Addr)
	return a, ok
}

// requestIDContextKey carries the cryptographically random per-request ID.
var requestIDContextKey = struct{}{}

// requestIDHeader names the response header echoing the correlating request ID.
const requestIDHeader = "X-Request-Id"

// RequestIDFromContext returns the request ID generated by the security
// middleware (never trusted from an incoming header).
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDContextKey).(string)
	return v
}

// newRequestID returns a fresh cryptographically random request ID (16 bytes,
// hex-encoded). Failures to draw randomness propagate as an absent ID.
func newRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

// maxBodyBytes is the control-plane request-body cap (1 MiB). Any request
// body larger than this is rejected with a 413 before it can be buffered into
// memory at scale.
const maxBodyBytes = 1 << 20

const (
	headerCSP      = "Content-Security-Policy"
	headerNoSniff  = "X-Content-Type-Options"
	headerFrame    = "X-Frame-Options"
	headerReferrer = "Referrer-Policy"
)

// securityHeaders are applied to every response. The CSP is tuned for the
// control plane's own templates, which render a single inline <style> and
// inline <script> (no third-party assets).
func securityHeaders(h http.Header) {
	h.Set(headerCSP, "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
	h.Set(headerNoSniff, "nosniff")
	h.Set(headerFrame, "DENY")
	h.Set(headerReferrer, "strict-origin-when-cross-origin")
}

// wrap returns the security-enforcing handler around the router. Order is
// deliberate: security headers are set, the request body is bounded, a
// cryptographically random request ID is minted (never trusted inbound) and
// echoed, client IP is resolved once, the route is classified, login/register
// origin and rate limits are enforced before any credential work (only login
// routes read the body for the email key), and CSRF is enforced before any
// state-changing cookie-authenticated handler runs.
func (p *securityPolicy) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w.Header())

		// Bound the request body before anything parses it. Overflow surfaces
		// as a *http.MaxBytesError that bounded decode/parse helpers map to 413.
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

		rid := newRequestID()
		w.Header().Set(requestIDHeader, rid)
		r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey, rid))

		clientIP, err := p.resolver.ClientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"))
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid peer address"})
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), clientIPContextKey, clientIP))

		if !p.checkOrigin(w, r) {
			return
		}

		// Classify BEFORE reading any body; only login routes extract email.
		class := classifyRoute(r.Method, r.URL.Path)
		email := ""
		if class == routeLogin {
			email = loginEmail(r)
		}
		if !p.checkRateLimit(w, r, class, clientIP, email) {
			return
		}
		if !p.checkCSRF(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sessionCSRF returns the verified CSRF claim for the request's session cookie
// (empty when there is no valid cookie). UI rendering uses it to stamp every
// form with its session-bound token.
func (p *securityPolicy) sessionCSRF(r *http.Request) string {
	claims, ok := p.sessionClaimsFromCookie(r)
	if !ok {
		return ""
	}
	return claims.CSRF
}

func readBody(r *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		// On read error (a MaxBytesError from an oversized bounded body), do NOT
		// replace r.Body with a fresh reader: keeping the bounded MaxBytesReader
		// intact preserves the overflow signal so the handler's decode maps it to
		// an explicit 413 instead of a misleading 400.
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return raw, nil
}
