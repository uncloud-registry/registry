package auth

import "errors"

// Action is a scoped registry operation. Only pull and push are supported.
type Action string

const (
	ActionPull Action = "pull"
	ActionPush Action = "push"

	// AnonymousSubject is the policy identity used for unauthenticated pull.
	// The registry handler constructs Principal{Subject: AnonymousSubject} ONLY
	// when the request carried no token at all (ErrMissingToken) AND the action
	// is pull. It is never minted for push and never derived from a presented
	// credential; anonymous principals can only be authorized if the auth
	// policy document explicitly lists "anonymous".
	AnonymousSubject = "anonymous"
)

// Principal is the verified identity and granted scope of a valid registry token.
type Principal struct {
	Subject    string
	TokenID    string
	Service    string
	Repository string
	Actions    map[Action]struct{}
}

// ErrScopeDenied is returned by RegistryTokenVerifier when the token is valid
// but does not grant the requested repository/action. It is distinct from
// structural/token-validation errors so callers can treat authorization
// denial separately from a malformed or untrusted token.
var ErrScopeDenied = errors.New("registry token scope denied")

// ErrMissingToken is returned by the registry Authenticator when no
// Authorization header (or only whitespace) was presented. Only the pull path
// may translate this category into the anonymous principal; on push it is a
// hard 401. It is never returned for a presented-but-invalid credential.
var ErrMissingToken = errors.New("missing registry token")

// ErrInvalidToken is the stable category for every presented-but-unacceptable
// credential: wrong scheme, malformed header, empty bearer, unsigned role
// values, invalid signature, unknown/expired/foreign tokens, session tokens,
// wrong issuer/audience/service, and scope denials. The category is fixed and
// never carries token, claim, or key material.
var ErrInvalidToken = errors.New("invalid registry token")
