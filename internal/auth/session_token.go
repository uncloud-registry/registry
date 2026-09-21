package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Purpose separation: session tokens are distinct from registry tokens. They use
// a separate HMAC key, a distinct token type, and require the exact
// control-plane issuer and audience. A registry token can never be parsed here.
const (
	// SessionTokenType marks an HMAC session token's typ claim.
	SessionTokenType = "session"
	// DefaultSessionIssuer/Audience are the control-plane claims required on
	// every session token. Peers (registry) validating session tokens must use
	// the same values. The session issuer namespace is intentionally distinct
	// from the registry issuer namespace so a token can never satisfy both
	// purposes by issuer alone.
	DefaultSessionIssuer   = "uncloud-registry/control-plane"
	DefaultSessionAudience = "uncloud-registry/control-plane"

	// minSessionSecretBytes is the smallest HS256 key width we accept. It
	// matches the minimum secret size recommended for HS256 (>= 256 bits).
	minSessionSecretBytes = 32
)

// SessionClaims is the purpose-scoped payload of a session token.
type SessionClaims struct {
	TokenType string `json:"typ"`
	jwt.RegisteredClaims
}

// SessionTokenManager issues and verifies control-plane session tokens using a
// dedicated HMAC key. It does not understand registry tokens.
type SessionTokenManager struct {
	secret   []byte
	issuer   string
	audience string
}

// NewSessionTokenManager returns a session token manager bound to an exact
// key, issuer, and audience. The key must differ from any registry key and
// must be at least minSessionSecretBytes bytes (HS256 minimum). Missing, weak,
// or default secrets are rejected so a public/guessable HMAC key can never be
// configured in a production path. Key material is never returned in errors or
// logged.
func NewSessionTokenManager(secret, issuer, audience string) (*SessionTokenManager, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("session token secret is required")
	}
	if len([]byte(secret)) < minSessionSecretBytes {
		return nil, fmt.Errorf("session token secret must be at least %d bytes", minSessionSecretBytes)
	}
	if issuer == "" || audience == "" {
		return nil, errors.New("session token issuer and audience are required")
	}
	return &SessionTokenManager{
		secret:   []byte(secret),
		issuer:   issuer,
		audience: audience,
	}, nil
}

// Issue signs a session token for the given subject with a nonzero issued-at
// and expiry.
func (m *SessionTokenManager) Issue(subject string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := SessionClaims{
		TokenType: SessionTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    m.issuer,
			Audience:  jwt.ClaimStrings{m.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

// Verify parses and fully validates a session token. It is strict: only
// HMAC-SHA256 tokens with typ=session, the exact issuer, exactly one audience
// equal to the expected audience, a subject, and non-missing issued-at and
// expiry are accepted. A token lacking an exp or iat claim is rejected
// explicitly (the underlying JWT library treats them as optional), and a token
// issued in the future is rejected by JWT validation. Tokens for any other
// purpose are rejected.
func (m *SessionTokenManager) Verify(raw string) (SessionClaims, error) {
	token := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	parsed, err := token.ParseWithClaims(raw, &SessionClaims{}, func(t *jwt.Token) (any, error) {
		return m.secret, nil
	})
	if err != nil {
		return SessionClaims{}, err
	}
	claims, ok := parsed.Claims.(*SessionClaims)
	if !ok || !parsed.Valid {
		return SessionClaims{}, errors.New("invalid session token")
	}
	if claims.TokenType != SessionTokenType {
		return SessionClaims{}, errors.New("session token type mismatch")
	}
	if claims.Issuer != m.issuer {
		return SessionClaims{}, errors.New("session token issuer mismatch")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != m.audience {
		return SessionClaims{}, errors.New("session token audience mismatch")
	}
	if claims.Subject == "" {
		return SessionClaims{}, errors.New("session token missing subject")
	}
	if claims.ExpiresAt == nil {
		return SessionClaims{}, errors.New("session token missing expiry")
	}
	if claims.IssuedAt == nil {
		return SessionClaims{}, errors.New("session token missing issued-at")
	}
	return *claims, nil
}
