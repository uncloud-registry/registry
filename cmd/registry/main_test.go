package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/registry"
)

const (
	configIssuer   = "uncloud-registry/registry"
	configAudience = "alice.uncloud-registry.com"
	configKeyID    = "config-key-1"
	configSubject  = "user:alice"
	configRepo     = "backend/api"
)

// configTestKey holds a generated Ed25519 pair plus the JWKS document that
// carries its public half.
type configTestKey struct {
	priv ed25519.PrivateKey
	doc  []byte
}

func newConfigTestKey(t *testing.T) configTestKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(pub)
	doc := []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"` + configKeyID + `","x":"` + x + `"}]}`)
	return configTestKey{priv: priv, doc: doc}
}

func writeConfigJWKS(t *testing.T, key configTestKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry-keys.json")
	if err := os.WriteFile(path, key.doc, 0o644); err != nil {
		t.Fatalf("write jwks: %v", err)
	}
	return path
}

func clearRegistryAuthEnv() {
	for _, name := range []string{"REGISTRY_TOKEN_PUBLIC_KEYS_FILE", "REGISTRY_TOKEN_ISSUER", "REGISTRY_TOKEN_AUDIENCE"} {
		os.Unsetenv(name)
	}
}

// TestEnvRequired enforces the required-setting contract: a blank or
// whitespace-only value is an error, never a silent fallback.
func TestEnvRequired(t *testing.T) {
	t.Setenv("REQ_TEST_VAR", "")
	if _, err := envRequired("REQ_TEST_VAR"); err == nil {
		t.Fatal("blank value must fail")
	}
	t.Setenv("REQ_TEST_VAR", "   \t\n")
	if _, err := envRequired("REQ_TEST_VAR"); err == nil {
		t.Fatal("whitespace-only value must fail")
	}
	t.Setenv("REQ_TEST_VAR", "configured")
	v, err := envRequired("REQ_TEST_VAR")
	if err != nil || v != "configured" {
		t.Fatalf("got %q err %v", v, err)
	}
}

// TestBuildAuthenticatorFailsWhenConfigMissing pins fail-closed startup: every
// verification setting is required; absent file, issuer, or audience all fail
// construction.
func TestBuildAuthenticatorFailsWhenConfigMissing(t *testing.T) {
	clearRegistryAuthEnv()
	if _, err := buildAuthenticator(); err == nil {
		t.Fatal("no config at all must fail")
	}
	key := newConfigTestKey(t)
	jwksPath := writeConfigJWKS(t, key)

	t.Setenv("REGISTRY_TOKEN_PUBLIC_KEYS_FILE", jwksPath)
	if _, err := buildAuthenticator(); err == nil {
		t.Fatal("missing issuer must fail")
	}
	t.Setenv("REGISTRY_TOKEN_ISSUER", configIssuer)
	if _, err := buildAuthenticator(); err == nil {
		t.Fatal("missing audience must fail")
	}
	t.Setenv("REGISTRY_TOKEN_AUDIENCE", configAudience)
	if _, err := buildAuthenticator(); err != nil {
		t.Fatalf("complete config must build: %v", err)
	}
}

// TestBuildAuthenticatorRejectsInvalidKeysFile proves the strict loader is
// wired into startup: a malformed or non-Ed25519 keys file fails construction.
func TestBuildAuthenticatorRejectsInvalidKeysFile(t *testing.T) {
	t.Setenv("REGISTRY_TOKEN_ISSUER", configIssuer)
	t.Setenv("REGISTRY_TOKEN_AUDIENCE", configAudience)

	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"keys":[]}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("REGISTRY_TOKEN_PUBLIC_KEYS_FILE", bad)
	if _, err := buildAuthenticator(); err == nil {
		t.Fatal("empty key set must fail construction")
	}

	if err := os.WriteFile(bad, []byte(`{"keys":[{"kty":"RSA","kid":"r"}]}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := buildAuthenticator(); err == nil {
		t.Fatal("non-OKP key must fail construction")
	}
}

// TestBuildAuthenticatorBindsIssuerAndAudience proves the configured issuer
// and audience actually bind verification: a token signed by the configured
// key for the configured issuer+audience verifies; tokens for a different
// issuer OR audience fail, and requests against a host other than the
// configured audience fail.
func TestBuildAuthenticatorBindsIssuerAndAudience(t *testing.T) {
	key := newConfigTestKey(t)
	t.Setenv("REGISTRY_TOKEN_PUBLIC_KEYS_FILE", writeConfigJWKS(t, key))
	t.Setenv("REGISTRY_TOKEN_ISSUER", configIssuer)
	t.Setenv("REGISTRY_TOKEN_AUDIENCE", configAudience)

	authen, err := buildAuthenticator()
	if err != nil {
		t.Fatalf("buildAuthenticator: %v", err)
	}
	bearer, ok := authen.(registry.BearerAuthenticator)
	if !ok {
		t.Fatalf("unexpected authenticator type %T", authen)
	}

	issue := func(t *testing.T, issuer, service, subject, repo string, ttl time.Duration) string {
		t.Helper()
		iss, err := auth.NewRegistryTokenIssuer(key.priv, issuer, configKeyID)
		if err != nil {
			t.Fatalf("new issuer: %v", err)
		}
		raw, err := iss.Issue(context.Background(), auth.RegistryTokenRequest{
			Subject:    subject,
			Service:    service,
			Repository: repo,
			Actions:    []auth.Action{auth.ActionPull},
			TTL:        ttl,
		})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return raw
	}

	good := issue(t, configIssuer, configAudience, configSubject, configRepo, time.Hour)
	if _, err := bearer.Authenticate(context.Background(), "Bearer "+good, configAudience, configRepo, auth.ActionPull); err != nil {
		t.Fatalf("token for configured issuer/audience must verify: %v", err)
	}

	wrongIssuer := issue(t, "someone-else", configAudience, configSubject, configRepo, time.Hour)
	if _, err := bearer.Authenticate(context.Background(), "Bearer "+wrongIssuer, configAudience, configRepo, auth.ActionPull); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("wrong issuer must fail closed, got %v", err)
	}

	wrongAudience := issue(t, configIssuer, "evil.example.test", configSubject, configRepo, time.Hour)
	if _, err := bearer.Authenticate(context.Background(), "Bearer "+wrongAudience, configAudience, configRepo, auth.ActionPull); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("wrong audience must fail closed, got %v", err)
	}

	// Request-side host binding: a request against a host other than the
	// configured audience fails even with a valid token.
	if _, err := bearer.Authenticate(context.Background(), "Bearer "+good, "other-host.example.test", configRepo, auth.ActionPull); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("request host outside the configured audience must fail closed, got %v", err)
	}
}

// TestBuildMemoryHandlerRequiresVerificationConfig pins that the production
// handler cannot be built without registry token verification configuration —
// there is no optional or shared-secret fallback anymore.
func TestBuildMemoryHandlerRequiresVerificationConfig(t *testing.T) {
	clearRegistryAuthEnv()
	t.Setenv("REGISTRY_BACKEND", "memory")
	if _, err := buildHandler(); err == nil {
		t.Fatal("memory handler without verification config must fail")
	}
	key := newConfigTestKey(t)
	t.Setenv("REGISTRY_TOKEN_PUBLIC_KEYS_FILE", writeConfigJWKS(t, key))
	t.Setenv("REGISTRY_TOKEN_ISSUER", configIssuer)
	t.Setenv("REGISTRY_TOKEN_AUDIENCE", configAudience)
	if _, err := buildHandler(); err != nil {
		t.Fatalf("memory handler with full config must build: %v", err)
	}
}

// TestRegistryNoLongerUsesSharedHmacSecret proves the registry process no
// longer reads REGISTRY_TOKEN_SECRET anywhere in its config path: the shared
// HMAC registry wiring was retired in favor of verified Ed25519 principals.
func TestRegistryNoLongerUsesSharedHmacSecret(t *testing.T) {
	clearRegistryAuthEnv()
	t.Setenv("REGISTRY_BACKEND", "memory")
	t.Setenv("REGISTRY_TOKEN_SECRET", strings.Repeat("x", 32))
	if _, err := buildHandler(); err == nil {
		t.Fatal("REGISTRY_TOKEN_SECRET must not substitute for registry verification config")
	}
}

// --- Fix round 1 RED: REGISTRY_TOKEN_AUDIENCE strict allowlist ---

// TestBuildAuthenticatorRejectsMalformedAudienceList pins that
// REGISTRY_TOKEN_AUDIENCE is a strict comma-separated allowlist of exact
// registry hosts: blank elements, surrounding/interior whitespace, duplicates,
// wildcards, and malformed hosts all fail startup.
func TestBuildAuthenticatorRejectsMalformedAudienceList(t *testing.T) {
	key := newConfigTestKey(t)
	t.Setenv("REGISTRY_TOKEN_PUBLIC_KEYS_FILE", writeConfigJWKS(t, key))
	t.Setenv("REGISTRY_TOKEN_ISSUER", configIssuer)

	cases := []string{
		"a,,b",          // blank element
		" a,b",          // leading whitespace in element
		"a, b",          // trailing whitespace in element
		"a,b,a",         // duplicate
		"a,a",           // duplicate pair
		"*",             // wildcard
		"a,b:evil:8080", // malformed host (multiple colons)
		"a://evil",      // scheme-like
		"bad host",      // interior whitespace
		"Evil.Example",  // non-lowercase host
		",a",            // leading blank
		"a,",            // trailing blank
		"a, a",          // whitespace + blank mix
	}
	for _, tc := range cases {
		t.Setenv("REGISTRY_TOKEN_AUDIENCE", tc)
		if _, err := buildAuthenticator(); err == nil {
			t.Errorf("REGISTRY_TOKEN_AUDIENCE=%q must fail startup", tc)
		}
	}

	// A valid multi-host allowlist must build.
	t.Setenv("REGISTRY_TOKEN_AUDIENCE", "alice.uncloud-registry.com,bob.uncloud-registry.com")
	if _, err := buildAuthenticator(); err != nil {
		t.Fatalf("valid multi-host audience list must build: %v", err)
	}
	// Ports are legal registry hosts.
	t.Setenv("REGISTRY_TOKEN_AUDIENCE", "localhost:8080")
	if _, err := buildAuthenticator(); err != nil {
		t.Fatalf("host with port must build: %v", err)
	}
}

// TestBuildAuthenticatorServesTwoHostsWithHostSpecificTokens pins the
// multi-namespace audience contract at the production wiring layer: one
// process configured with a two-host allowlist verifies each host-specific
// signed token independently, rejects cross-host presentation, and rejects
// hosts outside the allowlist before verification.
func TestBuildAuthenticatorServesTwoHostsWithHostSpecificTokens(t *testing.T) {
	key := newConfigTestKey(t)
	t.Setenv("REGISTRY_TOKEN_PUBLIC_KEYS_FILE", writeConfigJWKS(t, key))
	t.Setenv("REGISTRY_TOKEN_ISSUER", configIssuer)
	t.Setenv("REGISTRY_TOKEN_AUDIENCE", "alice.uncloud-registry.com,bob.uncloud-registry.com")

	authen, err := buildAuthenticator()
	if err != nil {
		t.Fatalf("buildAuthenticator: %v", err)
	}
	bearer, ok := authen.(registry.BearerAuthenticator)
	if !ok {
		t.Fatalf("unexpected authenticator type %T", authen)
	}

	issue := func(service string) string {
		t.Helper()
		iss, err := auth.NewRegistryTokenIssuer(key.priv, configIssuer, configKeyID)
		if err != nil {
			t.Fatalf("new issuer: %v", err)
		}
		raw, err := iss.Issue(context.Background(), auth.RegistryTokenRequest{
			Subject:    configSubject,
			Service:    service,
			Repository: configRepo,
			Actions:    []auth.Action{auth.ActionPull},
			TTL:        time.Hour,
		})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return raw
	}

	tokenAlice := issue("alice.uncloud-registry.com")
	tokenBob := issue("bob.uncloud-registry.com")

	// Each host verifies independently with its own host-specific token.
	if _, err := bearer.Authenticate(context.Background(), "Bearer "+tokenAlice, "alice.uncloud-registry.com", configRepo, auth.ActionPull); err != nil {
		t.Fatalf("alice token at alice host must verify: %v", err)
	}
	if _, err := bearer.Authenticate(context.Background(), "Bearer "+tokenBob, "bob.uncloud-registry.com", configRepo, auth.ActionPull); err != nil {
		t.Fatalf("bob token at bob host must verify: %v", err)
	}
	// Cross-host presentation fails closed even though both hosts are configured.
	if _, err := bearer.Authenticate(context.Background(), "Bearer "+tokenAlice, "bob.uncloud-registry.com", configRepo, auth.ActionPull); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("alice token at bob host must fail closed, got %v", err)
	}
	if _, err := bearer.Authenticate(context.Background(), "Bearer "+tokenBob, "alice.uncloud-registry.com", configRepo, auth.ActionPull); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("bob token at alice host must fail closed, got %v", err)
	}
	// Host outside the allowlist fails before verification, even with a valid
	// token minted for an allowed host.
	if _, err := bearer.Authenticate(context.Background(), "Bearer "+tokenAlice, "evil.example.test", configRepo, auth.ActionPull); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("host outside the allowlist must fail closed, got %v", err)
	}
}
