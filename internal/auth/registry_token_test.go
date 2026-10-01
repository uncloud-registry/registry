package auth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	testIssuer  = RegistryIssuer
	testService = "alice.example.test"
	testSubject = "role:write"
	testRepo    = "backend/api"
	testKeyID   = "test-key-1"
)

type testKeySet map[string]ed25519.PublicKey

func (k testKeySet) Key(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	pk, ok := k[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown kid %q", keyID)
	}
	return pk, nil
}

type testPair struct {
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	issuer   *RegistryTokenIssuer
	verifier *RegistryTokenVerifier
	keys     testKeySet
}

func newTestRegistryPair(t *testing.T) *testPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	_ = pub
	keys := testKeySet{testKeyID: priv.Public().(ed25519.PublicKey)}
	issuer, err := NewRegistryTokenIssuer(priv, testIssuer, testKeyID)
	if err != nil {
		t.Fatalf("new registry issuer: %v", err)
	}
	verifier := NewRegistryTokenVerifier(keys, testIssuer, testService)
	return &testPair{pub: pub, priv: priv, issuer: issuer, verifier: verifier, keys: keys}
}

// issueRegistryToken issues a structured token through the issuer.
func (p *testPair) issue(subject, service, repository string, actions []Action, ttl time.Duration) string {
	t := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, RegistryClaims{
		TokenType: RegistryTokenType,
		Service:   service,
		Access:    []RegistryAccess{{Type: "repository", Name: repository, Actions: actions}},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{service},
			ExpiresAt: jwt.NewNumericDate(t.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(t),
			ID:        "jti-1",
		},
	})
	token.Header["kid"] = testKeyID
	signed, err := token.SignedString(p.priv)
	if err != nil {
		panic(err)
	}
	return signed
}

// rawSign builds a token from arbitrary claims and signs with the pair key
// (default kid and EdDSA) unless overridden via mutate.
func (p *testPair) rawSign(claims RegistryClaims, overrides *testRawOverrides) string {
	t := time.Now()
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = jwt.NewNumericDate(t.Add(time.Hour))
	}
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(t)
	}
	if claims.Issuer == "" {
		claims.Issuer = testIssuer
	}
	if claims.Audience == nil {
		claims.Audience = jwt.ClaimStrings{testService}
	}
	if claims.ID == "" {
		claims.ID = "jti-raw"
	}
	if claims.Subject == "" {
		claims.Subject = testSubject
	}
	if claims.TokenType == "" {
		claims.TokenType = RegistryTokenType
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	if overrides == nil || overrides.kid == "" {
		token.Header["kid"] = testKeyID
	}
	var secret any = p.priv
	if overrides != nil && overrides.hmacSecret != nil {
		secret = overrides.hmacSecret
	}
	signed, err := token.SignedString(secret)
	if err != nil {
		panic(err)
	}
	return signed
}

type testRawOverrides struct {
	kid        string
	hmacSecret []byte
}

// signExact signs the given claims exactly as-is without filling any defaults,
// using the pair's private key and the test kid. It is used to exercise claim
// presence/absence checks that the default-filling rawSign cannot reproduce.
func (p *testPair) signExact(claims RegistryClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = testKeyID
	signed, err := token.SignedString(p.priv)
	if err != nil {
		panic(err)
	}
	return signed
}

func TestParseDockerScope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		scope      string
		wantRepo   string
		wantActs   []Action
		wantErrSub string // empty means success
	}{
		{"repository:backend/api:pull", "backend/api", []Action{ActionPull}, ""},
		{"repository:backend/api:push", "backend/api", []Action{ActionPush}, ""},
		{"repository:backend/api:pull,push", "backend/api", []Action{ActionPull, ActionPush}, ""},
		{"repository:ns/sub/repo:pull", "ns/sub/repo", []Action{ActionPull}, ""},
		// missing fields
		{"repository:backend/api", "", nil, "expected repository:<name>:<actions>"},
		{"repository:backend/api:pull:extra", "", nil, "invalid scope"},
		{"backend/api:pull", "", nil, "invalid scope"},
		{":pain", "", nil, "invalid scope"},
		// wrong type
		{"catalog:*:pull", "", nil, "invalid scope"},
		// empty repository / action
		{"repository::pull", "", nil, "empty repository name"},
		{"repository:backend/api:", "", nil, "empty action"},
		{"repository::", "", nil, "empty repository name"},
		// duplicate / unknown actions
		{"repository:backend/api:pull,pull", "", nil, "duplicate action"},
		{"repository:backend/api:push,push", "", nil, "duplicate action"},
		{"repository:backend/api:delete", "", nil, "unknown action"},
		{"repository:backend/api:pull,delete", "", nil, "unknown action"},
		// trailing/leading space is NOT normalized silently
		{" repository:backend/api:pull", "", nil, "unsupported scope type"},
		{"repository:backend/api:pull ", "", nil, "unknown action"},
		// whitespace anywhere inside the repository component is rejected untouched
		{"repository: backend/api:pull", "", nil, "whitespace"},
		{"repository:backend/ api:pull", "", nil, "whitespace"},
		{"repository:backend/api :pull", "", nil, "whitespace"},
		{"repository: backend/api :pull,push", "", nil, "whitespace"},
		{"repository:back	end/api:pull", "", nil, "whitespace"},
	}
	for _, tc := range cases {
		repo, acts, err := ParseDockerScope(tc.scope)
		if tc.wantErrSub == "" {
			if err != nil {
				t.Errorf("ParseDockerScope(%q): unexpected error %v", tc.scope, err)
				continue
			}
			if repo != tc.wantRepo {
				t.Errorf("ParseDockerScope(%q): repo = %q, want %q", tc.scope, repo, tc.wantRepo)
			}
			if len(acts) != len(tc.wantActs) {
				t.Errorf("ParseDockerScope(%q): actions = %v, want %v", tc.scope, acts, tc.wantActs)
			} else {
				for i := range acts {
					if acts[i] != tc.wantActs[i] {
						t.Errorf("ParseDockerScope(%q): actions = %v, want %v", tc.scope, acts, tc.wantActs)
						break
					}
				}
			}
			continue
		}
		if err == nil {
			t.Errorf("ParseDockerScope(%q): expected error containing %q, got nil", tc.scope, tc.wantErrSub)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErrSub) {
			t.Errorf("ParseDockerScope(%q): error %q does not contain %q", tc.scope, err, tc.wantErrSub)
		}
	}
}

func TestRegistryTokenVerifierAcceptsPullAndPush(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)

	raw := p.issue(testSubject, testService, testRepo, []Action{ActionPull, ActionPush}, time.Hour)
	principal, err := p.verifier.Verify(raw, testService, testRepo, ActionPull)
	if err != nil {
		t.Fatalf("verify pull: %v", err)
	}
	if principal.Subject != testSubject || principal.Repository != testRepo || principal.Service != testService {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	if _, ok := principal.Actions[ActionPush]; !ok {
		t.Fatalf("expected push in granted actions, got %v", principal.Actions)
	}
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err != nil {
		t.Fatalf("verify push: %v", err)
	}
}

func TestRegistryTokenVerifierRejectsWrongRepository(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	raw := p.issue(testSubject, testService, testRepo, []Action{ActionPush}, time.Hour)
	_, err := p.verifier.Verify(raw, testService, "other/repo", ActionPush)
	if !errors.Is(err, ErrScopeDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestRegistryTokenVerifierRejectsPullOnlyForPush(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	raw := p.issue(testSubject, testService, testRepo, []Action{ActionPull}, time.Hour)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPull); err != nil {
		t.Fatalf("pull should verify: %v", err)
	}
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); !errors.Is(err, ErrScopeDenied) {
		t.Fatalf("expected scope denied, got %v", err)
	}
}

func TestRegistryTokenVerifierRejectsExpired(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	raw := p.issue(testSubject, testService, testRepo, []Action{ActionPush}, -time.Hour)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestRegistryTokenVerifierRejectsWrongKeyID(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	raw := p.rawSign(RegistryClaims{
		Service: testService,
		Access:  []RegistryAccess{{Type: "repository", Name: testRepo, Actions: []Action{ActionPush}}},
	}, &testRawOverrides{kid: "other-key"})
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected unknown kid to be rejected")
	}
}

func TestRegistryTokenVerifierRejectsMissingKeyID(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, RegistryClaims{
		Service: testService,
		Access:  []RegistryAccess{{Type: "repository", Name: testRepo, Actions: []Action{ActionPush}}},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   testSubject,
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{testService},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        "jti",
		},
	})
	raw, err := token.SignedString(p.priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected missing kid to be rejected")
	}
}

func TestRegistryTokenVerifierRejectsWrongAlgorithm(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	// HMAC-signed "registry"-looking token must be rejected (no algorithm fallback).
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, RegistryClaims{
		Service: testService,
		Access:  []RegistryAccess{{Type: "repository", Name: testRepo, Actions: []Action{ActionPush}}},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   testSubject,
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{testService},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        "jti",
		},
	})
	raw, err := token.SignedString([]byte("some-hmac-secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected non-EdDSA token to be rejected")
	}
}

func TestRegistryTokenVerifierRejectsWrongIssuer(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	raw := p.rawSign(RegistryClaims{
		Service: testService,
		Access:  []RegistryAccess{{Type: "repository", Name: testRepo, Actions: []Action{ActionPush}}},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "someone-else",
		},
	}, nil)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected wrong issuer to be rejected")
	}
}

func TestRegistryTokenVerifierRejectsWrongService(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	// Token validly signed but aimed at a different service audience.
	raw := p.issue(testSubject, "other.example.test", testRepo, []Action{ActionPush}, time.Hour)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected wrong service to be rejected")
	}
	// Token issued for the right service but requested with the wrong service.
	raw2 := p.issue(testSubject, testService, testRepo, []Action{ActionPush}, time.Hour)
	if _, err := p.verifier.Verify(raw2, "other.example.test", testRepo, ActionPush); err == nil {
		t.Fatal("expected request-side service mismatch to be rejected")
	}
}

func TestRegistryTokenVerifierRejectsSessionToken(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	sess, err := NewSessionTokenManager(testSessionManagerSecret, testIssuer, DefaultSessionAudience)
	if err != nil {
		t.Fatalf("new session manager: %v", err)
	}
	sessionRaw, err := sess.Issue("user:1", time.Hour)
	if err != nil {
		t.Fatalf("issue session token: %v", err)
	}
	// Even if the session token carries registry-looking claims via typ collision,
	// its HMAC algorithm + missing scope must fail registry verification.
	if _, err := p.verifier.Verify(sessionRaw, testService, testRepo, ActionPull); err == nil {
		t.Fatal("expected session token to be rejected by registry verifier")
	}
}

func TestRegistryTokenVerifierRejectsMalformedScope(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	claims := func(access []RegistryAccess) RegistryClaims {
		return RegistryClaims{Service: testService, Access: access}
	}

	// Unknown access type.
	raw := p.rawSign(claims([]RegistryAccess{{Type: "catalog", Name: testRepo, Actions: []Action{ActionPush}}}), nil)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected unknown access type to be rejected")
	}
	// Unknown action inside granted scope.
	raw = p.rawSign(claims([]RegistryAccess{{Type: "repository", Name: testRepo, Actions: []Action{ActionPull, "delete"}}}), nil)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPull); err == nil {
		t.Fatal("expected unknown action to be rejected")
	}
	// Duplicate action inside granted scope.
	raw = p.rawSign(claims([]RegistryAccess{{Type: "repository", Name: testRepo, Actions: []Action{ActionPull, ActionPull}}}), nil)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPull); err == nil {
		t.Fatal("expected duplicate action to be rejected")
	}
	// No access entries at all.
	raw = p.rawSign(claims(nil), nil)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPull); err == nil {
		t.Fatal("expected missing access to be rejected")
	}
	// Requested repository not in scope.
	raw = p.rawSign(claims([]RegistryAccess{{Type: "repository", Name: "other/repo", Actions: []Action{ActionPull}}}), nil)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPull); !errors.Is(err, ErrScopeDenied) {
		t.Fatalf("expected scope denied, got %v", err)
	}
}

func TestRegistryTokenVerifierRejectsMultiAccessAmbiguity(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	raw := p.rawSign(RegistryClaims{
		Service: testService,
		Access: []RegistryAccess{
			{Type: "repository", Name: testRepo, Actions: []Action{ActionPull}},
			{Type: "repository", Name: testRepo, Actions: []Action{ActionPush}},
		},
	}, nil)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected ambiguous multi-access token to be rejected")
	}
}

func TestRegistryTokenVerifierFailsClosedOnKeyErrors(t *testing.T) {
	t.Parallel()
	// nil keyset must fail closed, not panic or succeed.
	verifier := NewRegistryTokenVerifier(nil, testIssuer, testService)
	raw := (&testPair{priv: mustGeneratePrivateKey(t)}).issue(testSubject, testService, testRepo, []Action{ActionPush}, time.Hour)
	if _, err := verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected nil key set to fail closed")
	}
}

func mustGeneratePrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func TestRegistryTokenVerifierRejectsMissingExpiry(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	raw := p.signExact(RegistryClaims{
		TokenType: RegistryTokenType,
		Service:   testService,
		Access:    []RegistryAccess{{Type: "repository", Name: testRepo, Actions: []Action{ActionPush}}},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  testSubject,
			Issuer:   testIssuer,
			Audience: jwt.ClaimStrings{testService},
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ID:       "jti",
		},
	})
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected registry token with missing expiry to be rejected")
	}
}

func TestRegistryTokenVerifierRejectsMissingIssuedAt(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	raw := p.signExact(RegistryClaims{
		TokenType: RegistryTokenType,
		Service:   testService,
		Access:    []RegistryAccess{{Type: "repository", Name: testRepo, Actions: []Action{ActionPush}}},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   testSubject,
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{testService},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        "jti",
		},
	})
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected registry token with missing issued-at to be rejected")
	}
}

func TestRegistryTokenVerifierRejectsFutureIssuedAt(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	raw := p.signExact(RegistryClaims{
		TokenType: RegistryTokenType,
		Service:   testService,
		Access:    []RegistryAccess{{Type: "repository", Name: testRepo, Actions: []Action{ActionPush}}},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   testSubject,
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{testService},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			ID:        "jti",
		},
	})
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected registry token issued in the future to be rejected")
	}
}

func TestRegistryTokenVerifierRejectsMultipleAudiences(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	// Expected service plus an extra audience must be rejected, not tolerated.
	raw := p.signExact(RegistryClaims{
		TokenType: RegistryTokenType,
		Service:   testService,
		Access:    []RegistryAccess{{Type: "repository", Name: testRepo, Actions: []Action{ActionPush}}},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   testSubject,
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{testService, "extra-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "jti",
		},
	})
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected registry token with multiple audiences to be rejected")
	}
}

func TestRegistryTokenVerifierRejectsSessionIssuerNamespace(t *testing.T) {
	t.Parallel()
	p := newTestRegistryPair(t)
	// A token otherwise structurally valid but claiming the session issuer
	// namespace must be rejected: the registry verifier only trusts the registry
	// issuer.
	raw := p.rawSign(RegistryClaims{
		Service: testService,
		Access:  []RegistryAccess{{Type: "repository", Name: testRepo, Actions: []Action{ActionPush}}},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: DefaultSessionIssuer,
		},
	}, nil)
	if _, err := p.verifier.Verify(raw, testService, testRepo, ActionPush); err == nil {
		t.Fatal("expected registry token stamped with the session issuer to be rejected")
	}
}
