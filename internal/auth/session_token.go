package auth

import (
	"errors"
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
	// the same values.
	DefaultSessionIssuer   = "uncloud-registry/control-plane"
	DefaultSessionAudience = "uncloud-registry/control-plane"
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
// key, issuer, and audience. The key must differ from any registry key.
func NewSessionTokenManager(secret, issuer, audience string) (*SessionTokenManager, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("session token secret is required")
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

// Issue signs a session token for the given subject.
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

// Verify parses and fully validates a session token. It is strict: only HMAC-SHA256
// tokens with typ=session, the exact issuer, the exact audience, and a subject are
// accepted. Expiry is enforced. tokens for any other purpose are rejected.
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
	if !hasAudience(claims.Audience, m.audience) {
		return SessionClaims{}, errors.New("session token audience mismatch")
	}
	if claims.Subject == "" {
		return SessionClaims{}, errors.New("session token missing subject")
	}
	return *claims, nil
}

func hasAudience(got jwt.ClaimStrings, want string) bool {
	for _, a := range got {
		if a == want {
			return true
		}
	}
	return false
}
