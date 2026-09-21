package registry

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
)

// testService/token constants match the handler fixture host so the same
// issuer/verifier pair works across boundary and handler tests.
const (
	boundaryService = "alice.uncloud-registry.com"
	boundaryRepo    = "backend/api"
	boundaryKeyID   = "test-key-1"
)

// memKeySet is the in-memory PublicKeySet used to inject test keys (the JWKS
// loader is tested separately in internal/auth).
type memKeySet map[string]ed25519.PublicKey

func (k memKeySet) Key(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	pk, ok := k[keyID]
	if !ok {
		return nil, errors.New("unknown kid")
	}
	return pk, nil
}

type boundaryPair struct {
	issuer   *auth.RegistryTokenIssuer
	verifier *auth.RegistryTokenVerifier
	authn    BearerAuthenticator
}

func newBoundaryPair(t *testing.T) *boundaryPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	issuer, err := auth.NewRegistryTokenIssuer(priv, auth.RegistryIssuer, boundaryKeyID)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	keys := memKeySet{boundaryKeyID: pub}
	verifier := auth.NewRegistryTokenVerifier(keys, auth.RegistryIssuer, boundaryService)
	return &boundaryPair{
		issuer:   issuer,
		verifier: verifier,
		authn:    BearerAuthenticator{Tokens: verifier},
	}
}

func (p *boundaryPair) issue(t *testing.T, subject, service, repository string, actions []auth.Action, ttl time.Duration) string {
	t.Helper()
	raw, err := p.issuer.Issue(context.Background(), auth.RegistryTokenRequest{
		Subject:    subject,
		Service:    service,
		Repository: repository,
		Actions:    actions,
		TTL:        ttl,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return raw
}

// fakeVerifier records what it is handed and returns a canned result, for
// precise category-mapping assertions.
type fakeVerifier struct {
	calledWith []string
	principal  auth.Principal
	err        error
}

func (f *fakeVerifier) Verify(raw, service, repository string, action auth.Action) (auth.Principal, error) {
	f.calledWith = append(f.calledWith, raw)
	return f.principal, f.err
}

func TestAuthenticateHeaderCategories(t *testing.T) {
	t.Parallel()

	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		fv := &fakeVerifier{err: errors.New("must not be reached")}
		a := BearerAuthenticator{Tokens: fv}
		for _, header := range []string{"", "   ", "\t\n"} {
			if _, err := a.Authenticate(context.Background(), header, boundaryService, boundaryRepo, auth.ActionPull); !errors.Is(err, auth.ErrMissingToken) {
				t.Errorf("header %q: got %v, want ErrMissingToken", header, err)
			}
		}
		if len(fv.calledWith) != 0 {
			t.Fatalf("missing headers must never reach the verifier, got %v", fv.calledWith)
		}
	})

	t.Run("malformed and wrong scheme invalid", func(t *testing.T) {
		t.Parallel()
		fv := &fakeVerifier{err: errors.New("must not be reached")}
		a := BearerAuthenticator{Tokens: fv}
		headers := []string{
			"Basic abc",           // wrong scheme
			"Digest abc",          // wrong scheme
			"Bearer",              // no token part
			"Bearer ",             // empty bearer
			"Bearer  token",       // double space
			"Bearer token extra",  // multi-part
			"Bearer\ttoken",       // tab separator
			" Bearer token",       // leading space before scheme (not exactly two fields)
			"Bearer token ",       // trailing space
			"bearer",              // scheme only
			"role:write",          // raw value, no scheme
			"Bearer role:write x", // raw value, extra part
		}
		for _, header := range headers {
			if _, err := a.Authenticate(context.Background(), header, boundaryService, boundaryRepo, auth.ActionPush); !errors.Is(err, auth.ErrInvalidToken) {
				t.Errorf("header %q: got %v, want ErrInvalidToken", header, err)
			}
		}
		if len(fv.calledWith) != 0 {
			t.Fatalf("malformed headers must never reach the verifier, got %v", fv.calledWith)
		}
	})

	t.Run("scheme case-insensitive passes raw to verifier", func(t *testing.T) {
		t.Parallel()
		for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
			fv := &fakeVerifier{principal: auth.Principal{Subject: "user:alice"}}
			a := BearerAuthenticator{Tokens: fv}
			p, err := a.Authenticate(context.Background(), scheme+" rawtoken", boundaryService, boundaryRepo, auth.ActionPull)
			if err != nil {
				t.Fatalf("scheme %q: %v", scheme, err)
			}
			if p.Subject != "user:alice" {
				t.Fatalf("scheme %q: principal %+v", scheme, p)
			}
			if len(fv.calledWith) != 1 || fv.calledWith[0] != "rawtoken" {
				t.Fatalf("scheme %q: verifier must receive exactly the raw JWT, got %v", scheme, fv.calledWith)
			}
		}
	})

	t.Run("verifier errors collapse to invalid and never leak", func(t *testing.T) {
		t.Parallel()
		secrets := []error{errors.New("signature invalid"), auth.ErrScopeDenied, errors.New("expired token")}
		for _, verr := range secrets {
			fv := &fakeVerifier{err: verr}
			a := BearerAuthenticator{Tokens: fv}
			_, err := a.Authenticate(context.Background(), "Bearer super-secret-raw", boundaryService, boundaryRepo, auth.ActionPull)
			if !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("verifier err %v: got %v, want ErrInvalidToken", verr, err)
			}
			if strings.Contains(err.Error(), "super-secret-raw") {
				t.Fatalf("boundary error leaks the raw token: %v", err)
			}
		}
	})

	t.Run("nil verifier fails closed", func(t *testing.T) {
		t.Parallel()
		a := BearerAuthenticator{}
		if _, err := a.Authenticate(context.Background(), "Bearer anything", boundaryService, boundaryRepo, auth.ActionPull); !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("nil verifier: got %v", err)
		}
	})
}

// TestAuthenticateVerifiedPrincipal exercises the full verifier path through
// the boundary: valid signed tokens honor subject and scope, and every
// credential defect lands in the invalid category.
func TestAuthenticateVerifiedPrincipal(t *testing.T) {
	t.Parallel()
	p := newBoundaryPair(t)

	t.Run("valid pull and push token", func(t *testing.T) {
		t.Parallel()
		raw := p.issue(t, "user:alice", boundaryService, boundaryRepo, []auth.Action{auth.ActionPull, auth.ActionPush}, time.Hour)
		principal, err := p.authn.Authenticate(context.Background(), "Bearer "+raw, boundaryService, boundaryRepo, auth.ActionPull)
		if err != nil {
			t.Fatalf("authenticate pull: %v", err)
		}
		if principal.Subject != "user:alice" || principal.Repository != boundaryRepo {
			t.Fatalf("unexpected principal: %+v", principal)
		}
	})

	invalid := []struct {
		name   string
		action auth.Action
		header func() string
	}{
		{"unsigned role bearer", auth.ActionPull, func() string { return "Bearer role:write" }},
		{"non-jwt garbage", auth.ActionPull, func() string { return "Bearer not-a-jwt-at-all" }},
		{"session token", auth.ActionPull, func() string {
			m, err := auth.NewSessionTokenManager("session-test-secret-0123456789abcdef", auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
			if err != nil {
				t.Fatalf("session manager: %v", err)
			}
			raw, err := m.Issue("user:alice", time.Hour)
			if err != nil {
				t.Fatalf("issue session token: %v", err)
			}
			return "Bearer " + raw
		}},
		{"expired", auth.ActionPull, func() string {
			return "Bearer " + p.issue(t, "user:alice", boundaryService, boundaryRepo, []auth.Action{auth.ActionPull}, -time.Hour)
		}},
		{"wrong service claim", auth.ActionPull, func() string {
			return "Bearer " + p.issue(t, "user:alice", "evil.example.test", boundaryRepo, []auth.Action{auth.ActionPull}, time.Hour)
		}},
		{"wrong repository", auth.ActionPull, func() string {
			return "Bearer " + p.issue(t, "user:alice", boundaryService, "other/repo", []auth.Action{auth.ActionPull}, time.Hour)
		}},
		{"pull only token on push", auth.ActionPush, func() string {
			return "Bearer " + p.issue(t, "user:alice", boundaryService, boundaryRepo, []auth.Action{auth.ActionPull}, time.Hour)
		}},
		{"request service mismatch", auth.ActionPull, func() string {
			return "Bearer " + p.issue(t, "user:alice", boundaryService, boundaryRepo, []auth.Action{auth.ActionPull}, time.Hour)
		}},
	}
	for _, tc := range invalid {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			service := boundaryService
			if tc.name == "request service mismatch" {
				service = "other-host.example.test"
			}
			_, err := p.authn.Authenticate(context.Background(), tc.header(), service, boundaryRepo, tc.action)
			if !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("%s: got %v, want ErrInvalidToken", tc.name, err)
			}
		})
	}
}
