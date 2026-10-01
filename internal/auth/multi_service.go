package auth

import (
	"errors"
	"fmt"
	"strings"
)

// ErrServiceNotAllowed is returned when a registry token is presented at a
// service (the resolved request host) that is NOT in the configured audience
// allowlist. It fires BEFORE any token parsing or key resolution: a token
// minted for any other host can never be validated against this process, and a
// request to a host outside the allowlist fails closed immediately.
var ErrServiceNotAllowed = errors.New("registry token service not in audience allowlist")

// MultiServiceVerifier validates Ed25519 registry tokens for a registry
// process that serves several allowed hosts. Each Verify call selects the
// requested service against a strict allowlist of exact registry hosts; only a
// listed service proceeds to the shared exact-singleton-audience core, where
// the token's service claim and single audience must equal THAT service. This
// preserves the Task 4 exact-audience behavior per host while supporting at
// least two owner-map hosts in one process.
type MultiServiceVerifier struct {
	keys     PublicKeySet
	issuer   string
	services map[string]struct{}
}

// NewMultiServiceVerifier binds a verifier to a key set, the exact issuer, and
// a non-empty allowlist of exact services. Constructor inputs are preserved
// literally; whitespace-padded or blank elements are rejected so no host can
// be matched ambiguously.
func NewMultiServiceVerifier(keys PublicKeySet, issuer string, services []string) (*MultiServiceVerifier, error) {
	if keys == nil {
		return nil, errors.New("registry token verifier requires a public key set")
	}
	if strings.TrimSpace(issuer) == "" {
		return nil, errors.New("registry token issuer is required")
	}
	if len(services) == 0 {
		return nil, errors.New("registry token audience allowlist must not be empty")
	}
	set := make(map[string]struct{}, len(services))
	for _, s := range services {
		if s == "" || s != strings.TrimSpace(s) {
			return nil, fmt.Errorf("registry token audience %q must be a nonblank literal host", s)
		}
		set[s] = struct{}{}
	}
	return &MultiServiceVerifier{keys: keys, issuer: issuer, services: set}, nil
}

// Verify rejects any service outside the allowlist BEFORE token verification,
// then delegates to the shared exact-audience core for the selected service.
func (v *MultiServiceVerifier) Verify(raw, service, repository string, action Action) (Principal, error) {
	var empty Principal
	if _, ok := v.services[service]; !ok {
		return empty, ErrServiceNotAllowed
	}
	return verifyRegistryToken(v.keys, v.issuer, service, raw, repository, action)
}
