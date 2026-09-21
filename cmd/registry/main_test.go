package main

import (
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
)

// INVARIANT (shared with cmd/controlplane's envRequiredSecret): whitespace is
// used only to detect a missing/all-whitespace value; any nonblank configured
// secret is preserved byte-for-byte in BOTH processes. Session secrets are
// opaque bytes (the HMAC key), not human text. The registry mirrors the
// control plane so a token issued against the shared env value verifies here.
func TestTokenManagerFromEnvPreservesSecretBytes(t *testing.T) {
	// 32+ byte secret carrying leading and trailing whitespace as a legitimate
	// part of the key bytes.
	const pad = " \t\n"
	raw := pad + strings.Repeat("x", 32) + pad
	t.Setenv("REGISTRY_TOKEN_SECRET", raw)

	registryMgr, err := tokenManagerFromEnv()
	if err != nil {
		t.Fatalf("tokenManagerFromEnv: %v", err)
	}
	if registryMgr == nil {
		t.Fatal("a nonblank secret must produce a manager, not nil")
	}

	// A control-plane issuer built from the IDENTICAL raw env value (as
	// envRequiredSecret -> NewSessionTokenManager does) must issue a token this
	// registry-side manager verifies.
	cpIssuer, err := auth.NewSessionTokenManager(raw, auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	if err != nil {
		t.Fatalf("control-plane issuer on raw secret: %v", err)
	}
	tok, err := cpIssuer.Issue("alice@example.test", time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := registryMgr.Verify(tok)
	if err != nil || claims.Subject != "alice@example.test" {
		t.Fatalf("registry manager must verify a token signed with the identical raw secret; got err=%v", err)
	}

	// A manager built from a TrimSpace'd (mutated) variant of the secret must
	// NOT verify the same token — precisely the divergence this closes.
	trimmedMgr, err := auth.NewSessionTokenManager(strings.TrimSpace(raw), auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	if err != nil {
		t.Fatalf("trimmed manager: %v", err)
	}
	if _, err := trimmedMgr.Verify(tok); err == nil {
		t.Fatal("a trimmed-secret manager must NOT verify a token signed with the padded secret")
	}
}

func TestTokenManagerFromEnvMissingTreatedAbsent(t *testing.T) {
	t.Setenv("REGISTRY_TOKEN_SECRET", "")
	mgr, err := tokenManagerFromEnv()
	if err != nil {
		t.Fatalf("missing secret must be treated as absent, got err=%v", err)
	}
	if mgr != nil {
		t.Fatal("missing secret must yield a nil manager (resolver fails closed)")
	}
}

func TestTokenManagerFromEnvAllWhitespaceTreatedAbsent(t *testing.T) {
	t.Setenv("REGISTRY_TOKEN_SECRET", " \t\n  ")
	mgr, err := tokenManagerFromEnv()
	if err != nil {
		t.Fatalf("all-whitespace secret must be treated as absent, got err=%v", err)
	}
	if mgr != nil {
		t.Fatal("all-whitespace secret must yield a nil manager (never a valid key)")
	}
}

func TestTokenManagerFromEnvWeakSecretFailsConsistently(t *testing.T) {
	// 20 raw bytes (< HS256 minimum of 32) even including whitespace padding:
	// weak under the raw-byte policy, and must fail exactly as the control
	// plane rejects the identical raw value.
	padded := "\t" + strings.Repeat("w", 16) + "\n\t"
	t.Setenv("REGISTRY_TOKEN_SECRET", padded)

	if _, err := tokenManagerFromEnv(); err == nil {
		t.Fatal("registry must reject a weak (<32 byte) secret")
	}
	if _, err := auth.NewSessionTokenManager(padded, auth.DefaultSessionIssuer, auth.DefaultSessionAudience); err == nil {
		t.Fatal("control-plane constructor must reject the same weak raw secret")
	}
}

func TestTokenManagerFromEnvPaddedCoreLengthPolicyMatchesControlPlane(t *testing.T) {
	// A 30-byte core secret padded with whitespace to 38 raw bytes. Whitespace
	// is part of the opaque key, so the raw key is >=32 bytes and MUST be
	// accepted — exactly as the control plane accepts it. The old registry code
	// TrimSpace'd this to 30 bytes and wrongly rejected it, diverging from the
	// control plane's length validation.
	core := strings.Repeat("p", 30)
	raw := "  " + core + "\t\n"
	if len([]byte(raw)) < 32 {
		t.Fatal("test precondition: raw secret must be >= 32 bytes")
	}
	t.Setenv("REGISTRY_TOKEN_SECRET", raw)

	if _, err := tokenManagerFromEnv(); err != nil {
		t.Fatalf("a >=32-byte raw secret padded with whitespace must be accepted (matching control plane), got err=%v", err)
	}
	if _, err := auth.NewSessionTokenManager(raw, auth.DefaultSessionIssuer, auth.DefaultSessionAudience); err != nil {
		t.Fatalf("control plane must accept the identical raw value: %v", err)
	}
}
