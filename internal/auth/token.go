package auth

import "strings"

// SubjectResolver extracts a bearer subject from an Authorization header. It
// only understands session tokens (via SessionTokenManager); it has no generic
// parser and cannot read registry tokens. The raw token is returned as a
// fallback match when it is not a parseable session token, preserving existing
// policy matching behaviour for role/anonymous actors.
type SubjectResolver struct {
	Tokens *SessionTokenManager
}

// Subject returns the verified session subject, or the raw token when it is not
// a session token, or "" for an empty/malformed header.
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
		if claims, err := r.Tokens.Verify(token); err == nil {
			return claims.Subject
		}
	}
	return token
}
