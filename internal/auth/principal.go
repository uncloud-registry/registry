package auth

import "errors"

// Action is a scoped registry operation. Only pull and push are supported.
type Action string

const (
	ActionPull Action = "pull"
	ActionPush Action = "push"
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
