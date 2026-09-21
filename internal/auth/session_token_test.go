package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func newTestSessionManager(t *testing.T) *SessionTokenManager {
	t.Helper()
	m, err := NewSessionTokenManager("session-secret", DefaultSessionIssuer, DefaultSessionAudience)
	if err != nil {
		t.Fatalf("new session manager: %v", err)
	}
	return m
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
	other, err := NewSessionTokenManager("other-secret", DefaultSessionIssuer, DefaultSessionAudience)
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
	// Valid HMAC + issuer + audience, but typ != session.
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, SessionClaims{
		TokenType: "registry",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user:1",
			Issuer:    DefaultSessionIssuer,
			Audience:  jwt.ClaimStrings{DefaultSessionAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	})
	raw, err := token.SignedString([]byte("session-secret"))
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
		},
	})
	raw, err := token.SignedString([]byte("session-secret"))
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
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user:1",
			Issuer:    "someone-else",
			Audience:  jwt.ClaimStrings{DefaultSessionAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	raw, err := token.SignedString([]byte("session-secret"))
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
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user:1",
			Issuer:    DefaultSessionIssuer,
			Audience:  jwt.ClaimStrings{"other-registry"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	raw, err := token.SignedString([]byte("session-secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected wrong audience to be rejected")
	}
}

func TestSessionTokenManagerRejectsMissingSubject(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    DefaultSessionIssuer,
			Audience:  jwt.ClaimStrings{DefaultSessionAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	raw, err := token.SignedString([]byte("session-secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected missing subject to be rejected")
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

	// A registry token is not a session token: raw token is returned as the
	// subject fallback (registry tokens are not parseable as sessions).
	p := newTestRegistryPair(t)
	regRaw := p.issue(testSubject, testService, testRepo, []Action{ActionPush}, time.Hour)
	if got := resolver.Subject("Bearer " + regRaw); got == "user:7" {
		t.Fatalf("registry token must not be resolved as a session subject, got %q", got)
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
