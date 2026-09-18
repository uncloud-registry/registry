package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type TokenManager struct {
	secret []byte
}

type Claims struct {
	TokenType string `json:"typ"`
	Service   string `json:"service,omitempty"`
	Scope     string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

func NewTokenManager(secret string) (*TokenManager, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("token secret is required")
	}
	return &TokenManager{secret: []byte(secret)}, nil
}

func (m *TokenManager) IssueSessionToken(subject string, ttl time.Duration) (string, error) {
	return m.issue(Claims{
		TokenType: "session",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
}

func (m *TokenManager) IssueRegistryToken(subject string, service string, scope string, ttl time.Duration) (string, error) {
	return m.issue(Claims{
		TokenType: "registry",
		Service:   service,
		Scope:     scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
}

func (m *TokenManager) Parse(token string) (Claims, error) {
	parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return Claims{}, err
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return Claims{}, errors.New("invalid token claims")
	}
	return *claims, nil
}

func (m *TokenManager) issue(claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

type SubjectResolver struct {
	Tokens *TokenManager
}

func (r SubjectResolver) Subject(authHeader string) string {
	authHeader = strings.TrimSpace(authHeader)
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return ""
	}

	if r.Tokens != nil {
		claims, err := r.Tokens.Parse(token)
		if err == nil {
			return claims.Subject
		}
	}

	return token
}
