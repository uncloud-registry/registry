package registry

import (
	"context"
	"errors"
	"strings"

	"github.com/uncloud-registry/registry/internal/auth"
)

// TokenVerifier is the narrow consumer interface for registry-token
// verification consumed by the Authenticator. *auth.RegistryTokenVerifier
// satisfies it exactly (Task 4 contract); keeping it an interface lets the
// boundary be unit-tested with in-memory key sets and fake verifiers without
// weakening the production wiring.
type TokenVerifier interface {
	Verify(raw, service, repository string, action auth.Action) (auth.Principal, error)
}

// Authenticator is the fail-closed authentication boundary. It parses the
// Authorization header exactly once, delegates ONLY the raw JWT (never a role
// literal or header fragment) to token verification, and maps every outcome
// into one of two stable categories:
//
//   - auth.ErrMissingToken: no credential was presented at all.
//   - auth.ErrInvalidToken: anything else — wrong scheme, malformed header,
//     empty bearer, unsigned role values, invalid/mismatched/expired/session
//     tokens, and scope denials.
//
// The categories never contain token, claim, or key material.
type Authenticator interface {
	Authenticate(ctx context.Context, authorization, service, repository string, action auth.Action) (auth.Principal, error)
}

// BearerAuthenticator implements Authenticator over a TokenVerifier.
type BearerAuthenticator struct {
	Tokens TokenVerifier
}

// Authenticate parses the Bearer scheme exactly once and verifies the raw JWT.
// A blank header is missing; every other header shape that is not exactly
// "Bearer <token>" is invalid. Errors from the verifier (bad signature,
// expired, wrong service/repository/action, session tokens, scope denials)
// are collapsed to ErrInvalidToken and never propagate raw messages, so the
// boundary leaks neither token bytes nor key/claim details.
func (a BearerAuthenticator) Authenticate(_ context.Context, authorization, service, repository string, action auth.Action) (auth.Principal, error) {
	var empty auth.Principal
	if strings.TrimSpace(authorization) == "" {
		return empty, auth.ErrMissingToken
	}
	scheme, raw, err := parseBearerHeader(authorization)
	if err != nil {
		return empty, auth.ErrInvalidToken
	}
	if !strings.EqualFold(scheme, "Bearer") {
		return empty, auth.ErrInvalidToken
	}
	if a.Tokens == nil {
		// A nil verifier can never accept a credential.
		return empty, auth.ErrInvalidToken
	}
	principal, err := a.Tokens.Verify(raw, service, repository, action)
	if err != nil {
		return empty, auth.ErrInvalidToken
	}
	return principal, nil
}

// parseBearerHeader splits "Authorization" into exactly two space-separated
// fields and rejects every other shape: missing or empty fields, repeated
// spaces, tabs, and multi-part values. The token part must be non-empty and
// contain no whitespace. Values are never normalized or trimmed into a
// credential, so a raw `role:write` style value cannot smuggle through.
func parseBearerHeader(authorization string) (scheme string, token string, err error) {
	parts := strings.Split(authorization, " ")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("authorization header must be exactly 'Bearer <token>'")
	}
	return parts[0], parts[1], nil
}
