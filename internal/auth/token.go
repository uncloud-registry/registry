package auth

import "strings"

// SubjectResolver extracts a bearer subject from an Authorization header. It
// only understands session tokens (via SessionTokenManager); it has no generic
// parser and cannot read registry tokens. It is fail-closed: an untrusted,
// unparsable, or cross-purpose token never becomes a policy subject. There is
// no raw-bearer fallback, so an attacker cannot present a literal `role:write`
// bearer value to assume a privileged actor.
type SubjectResolver struct {
	Tokens *SessionTokenManager
}

// Subject returns the verified session subject, or "" when the header is not a
// verifiable session token. An absent manager, an invalid signature, a
// cross-purpose token, or an empty/malformed header all resolve to no subject.
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

	if r.Tokens == nil {
		return ""
	}

	claims, err := r.Tokens.Verify(token)
	if err != nil {
		return ""
	}
	return claims.Subject
}
