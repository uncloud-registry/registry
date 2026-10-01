package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Test HMAC secrets must be at least minSessionSecretBytes bytes; these
// constants keep every manager construction and raw-signing path on a strong,
// valid secret so a specific defect under test is what triggers rejection.
const (
	testSessionManagerSecret = "session-test-manager-secret-0123456789abcdef"
	testOtherSessionSecret   = "other-session-test-manager-secret-9876543210fedcba"
	testSessionRawSignSecret = "session-test-raw-sign-secret-0123456789abcdef"
)

func newTestSessionManager(t *testing.T) *SessionTokenManager {
	t.Helper()
	m, err := NewSessionTokenManager(testSessionManagerSecret, DefaultSessionIssuer, DefaultSessionAudience)
	if err != nil {
		t.Fatalf("new session manager: %v", err)
	}
	return m
}

// rawSessionSign builds a session token from the given claims, signing with
// testSessionRawSignSecret unless another secret is supplied.
func rawSessionSign(claims SessionClaims, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signing := secret
	if signing == nil {
		signing = []byte(testSessionRawSignSecret)
	}
	return token.SignedString(signing)
}

func TestSessionTokenManagerIssueAndVerify(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	raw, err := m.Issue("user:1", time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := m.Verify(raw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user:1" || claims.TokenType != SessionTokenType {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.Issuer != DefaultSessionIssuer {
		t.Fatalf("unexpected issuer %q", claims.Issuer)
	}
}

func TestSessionTokenManagerRejectsWrongSecret(t *testing.T) {
	t.Parallel()
	other, err := NewSessionTokenManager(testOtherSessionSecret, DefaultSessionIssuer, DefaultSessionAudience)
	if err != nil {
		t.Fatalf("new other manager: %v", err)
	}
	raw, err := newTestSessionManager(t).Issue("user:1", time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := other.Verify(raw); err == nil {
		t.Fatal("expected token signed with a different secret to be rejected")
	}
}

func TestSessionTokenManagerRejectsExpired(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	raw, err := m.Issue("user:1", -time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected expired session token to be rejected")
	}
}

func TestSessionTokenManagerRejectsWrongType(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	now := time.Now()
	raw, err := rawSessionSign(SessionClaims{
		TokenType: "registry",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user:1",
			Issuer:    DefaultSessionIssuer,
			Audience:  jwt.ClaimStrings{DefaultSessionAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}, []byte(testSessionRawSignSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected typ mismatch to be rejected")
	}
}

func TestSessionTokenManagerRejectsWrongAlgorithm(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	token := jwt.NewWithClaims(jwt.SigningMethodHS384, SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user:1",
			Issuer:    DefaultSessionIssuer,
			Audience:  jwt.ClaimStrings{DefaultSessionAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	raw, err := token.SignedString([]byte(testSessionRawSignSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected non-HS256 algorithm to be rejected")
	}
}

func TestSessionTokenManagerRejectsWrongIssuer(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	raw, err := rawSessionSign(SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user:1",
			Issuer:    "someone-else",
			Audience:  jwt.ClaimStrings{DefaultSessionAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}, []byte(testSessionRawSignSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected wrong issuer to be rejected")
	}
}

func TestSessionTokenManagerRejectsWrongAudience(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	raw, err := rawSessionSign(SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user:1",
			Issuer:    DefaultSessionIssuer,
			Audience:  jwt.ClaimStrings{"other-registry"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}, []byte(testSessionRawSignSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected wrong audience to be rejected")
	}
}

func TestSessionTokenManagerRejectsMultipleAudiences(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	// Exactly one audience is required: expected plus an extra is rejected.
	raw, err := rawSessionSign(SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user:1",
			Issuer:    DefaultSessionIssuer,
			Audience:  jwt.ClaimStrings{DefaultSessionAudience, "extra-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}, []byte(testSessionRawSignSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected multi-audience session token to be rejected")
	}
}

func TestSessionTokenManagerRejectsMissingSubject(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	raw, err := rawSessionSign(SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    DefaultSessionIssuer,
			Audience:  jwt.ClaimStrings{DefaultSessionAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}, []byte(testSessionRawSignSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected missing subject to be rejected")
	}
}

func TestSessionTokenManagerRejectsMissingExpiry(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	raw, err := rawSessionSign(SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "user:1",
			Issuer:   DefaultSessionIssuer,
			Audience: jwt.ClaimStrings{DefaultSessionAudience},
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, []byte(testSessionRawSignSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected missing expiry to be rejected")
	}
}

func TestSessionTokenManagerRejectsMissingIssuedAt(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	raw, err := rawSessionSign(SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user:1",
			Issuer:    DefaultSessionIssuer,
			Audience:  jwt.ClaimStrings{DefaultSessionAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}, []byte(testSessionRawSignSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected missing issued-at to be rejected")
	}
}

func TestSessionTokenManagerRejectsFutureIssuedAt(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	raw, err := rawSessionSign(SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user:1",
			Issuer:    DefaultSessionIssuer,
			Audience:  jwt.ClaimStrings{DefaultSessionAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		},
	}, []byte(testSessionRawSignSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected token issued in the future to be rejected")
	}
}

func TestNewSessionTokenManagerRejectsWeakSecret(t *testing.T) {
	t.Parallel()
	weak := []string{"", "   ", "short", "dev-secret-change-me", "0123456789abcdef" /* 16 bytes */}
	for _, secret := range weak {
		if _, err := NewSessionTokenManager(secret, DefaultSessionIssuer, DefaultSessionAudience); err == nil {
			t.Errorf("expected weak secret %q to be rejected", secret)
		}
	}
}

func TestNewSessionTokenManagerRejectsEmptyIssuerOrAudience(t *testing.T) {
	t.Parallel()
	if _, err := NewSessionTokenManager(testSessionManagerSecret, "", DefaultSessionAudience); err == nil {
		t.Fatal("expected empty issuer to be rejected")
	}
	if _, err := NewSessionTokenManager(testSessionManagerSecret, DefaultSessionIssuer, ""); err == nil {
		t.Fatal("expected empty audience to be rejected")
	}
}

func TestIssuerNamespaceDistinctness(t *testing.T) {
	t.Parallel()
	if DefaultSessionIssuer == RegistryIssuer {
		t.Fatalf("session issuer %q and registry issuer %q must be distinct", DefaultSessionIssuer, RegistryIssuer)
	}
	if DefaultSessionIssuer != "uncloud-registry/control-plane" {
		t.Fatalf("unexpected session issuer %q", DefaultSessionIssuer)
	}
	if RegistryIssuer != "uncloud-registry/registry" {
		t.Fatalf("unexpected registry issuer %q", RegistryIssuer)
	}
}

// Cross-purpose separation: a session token must be rejected by the registry
// verifier and a registry token must be rejected by the session verifier, even
// when each is otherwise well-formed.
func TestPurposeSeparationRegistryTokenRejectedBySessionVerifier(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	raw := p.issue(testSubject, testService, testRepo, []Action{ActionPush}, time.Hour)
	sess := newTestSessionManager(t)
	if _, err := sess.Verify(raw); err == nil {
		t.Fatal("expected registry token to be rejected by session verifier")
	}
}

func TestPurposeSeparationSessionTokenRejectedByRegistryVerifier(t *testing.T) {
	t.Parallel()
	sess := newTestSessionManager(t)
	raw, err := sess.Issue("user:1", time.Hour)
	if err != nil {
		t.Fatalf("issue session token: %v", err)
	}
	p := newTestRegistryPair(t)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPull); err == nil {
		t.Fatal("expected session token to be rejected by registry verifier")
	}
}

func TestSubjectResolverUsesOnlySessionTokens(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	resolver := SubjectResolver{Tokens: m}

	sessionRaw, err := m.Issue("user:7", time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if got := resolver.Subject("Bearer " + sessionRaw); got != "user:7" {
		t.Fatalf("expected subject user:7, got %q", got)
	}

	// Fail-closed: a registry (cross-purpose) token is NOT a session token and
	// must resolve to no subject — never the raw token.
	p := newTestRegistryPair(t)
	regRaw := p.issue(testSubject, testService, testRepo, []Action{ActionPush}, time.Hour)
	if got := resolver.Subject("Bearer " + regRaw); got != "" {
		t.Fatalf("registry token must not resolve to any subject, got %q", got)
	}

	// An untrusted raw bearer that mimics a privileged actor resolves to
	// nothing.
	if got := resolver.Subject("Bearer role:write"); got != "" {
		t.Fatalf("raw bearer role:write must not become a subject, got %q", got)
	}
	if got := resolver.Subject("Bearer role:read"); got != "" {
		t.Fatalf("raw bearer role:read must not become a subject, got %q", got)
	}
	// A malformed/garbage token resolves to nothing.
	if got := resolver.Subject("Bearer not.a.token"); got != "" {
		t.Fatalf("garbage bearer must not become a subject, got %q", got)
	}

	if got := resolver.Subject(""); got != "" {
		t.Fatalf("expected empty subject, got %q", got)
	}
	if got := resolver.Subject("Bearer "); got != "" {
		t.Fatalf("expected empty subject for bare bearer, got %q", got)
	}
	if got := resolver.Subject("Basic dXNlcjpwYXNz"); got != "" {
		t.Fatalf("expected empty subject for non-bearer header, got %q", got)
	}
}

func TestSubjectResolverFailsClosedWithoutManager(t *testing.T) {
	t.Parallel()
	resolver := SubjectResolver{}
	if got := resolver.Subject("Bearer role:write"); got != "" {
		t.Fatalf("no-manager resolver must not expose a raw subject, got %q", got)
	}
	if got := resolver.Subject(""); got != "" {
		t.Fatalf("expected empty subject with nil manager, got %q", got)
	}
}
