package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
)

func TestParseRegistrySeedHexDeterministic(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	seedHex := hex.EncodeToString(priv.Seed())

	rebuilt, err := parseRegistrySeedHex(seedHex)
	if err != nil {
		t.Fatalf("parse valid seed: %v", err)
	}
	if !rebuilt.Equal(priv) {
		t.Fatal("rebuilt private key must equal the source key (deterministic from seed)")
	}
	if len(rebuilt) != ed25519.PrivateKeySize {
		t.Fatalf("unexpected private key size %d", len(rebuilt))
	}
}

func TestParseRegistrySeedHexRejectsBadInputWithoutLeaking(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sampleSeed := hex.EncodeToString(priv.Seed())

	cases := []string{
		"",                                   // missing
		"   ",                                // whitespace only
		"not-hex!",                           // malformed
		"abcd",                               // too short
		hex.EncodeToString(make([]byte, 33)), // well-formed hex but 33 bytes (wrong length)
		sampleSeed + "ff",                    // 65 hex chars (odd)
		sampleSeed[:len(sampleSeed)-1],       // 63 hex chars (odd, truncated)
	}
	for _, input := range cases {
		_, err := parseRegistrySeedHex(input)
		if err == nil {
			t.Errorf("expected input %q to be rejected", input)
			continue
		}
		// Never leak the key material itself in the error.
		trimmed := strings.TrimSpace(input)
		if trimmed != "" && strings.Contains(err.Error(), trimmed) {
			t.Errorf("error for %q must not echo the input: %v", input, err)
		}
		// A real seed must never appear verbatim in any error message.
		if sampleSeed != "" && strings.Contains(err.Error(), sampleSeed) {
			t.Errorf("error must not embed the seed: %v", err)
		}
	}
}

func TestEnvRequiredSecret(t *testing.T) {
	t.Setenv("TEST_REQUIRED_SECRET_VAR", "")
	if _, err := envRequiredSecret("TEST_REQUIRED_SECRET_VAR"); err == nil {
		t.Fatal("expected missing secret to be rejected")
	}
	t.Setenv("TEST_REQUIRED_SECRET_VAR", "   ")
	if _, err := envRequiredSecret("TEST_REQUIRED_SECRET_VAR"); err == nil {
		t.Fatal("expected whitespace-only secret to be rejected")
	}
}

// INVARIANT (shared with cmd/registry's tokenManagerFromEnv): whitespace is
// used only to detect a missing/all-whitespace value; any nonblank configured
// secret is preserved byte-for-byte as the HMAC key. Whitespace is a
// legitimate part of the opaque secret bytes, not text to be trimmed.
func TestEnvRequiredSecretPreservesBytesByteForByte(t *testing.T) {
	cases := []string{
		" " + strings.Repeat("a", 32) + " ",  // padded both sides
		"	" + strings.Repeat("b", 32),        // leading tab
		strings.Repeat("c", 32) + "\n\r",     // trailing newline + CR
		"  " + strings.Repeat("d", 30) + " ", // 30-byte core padded to 34 raw
	}
	for _, v := range cases {
		t.Setenv("TEST_REQUIRED_SECRET_VAR", v)
		got, err := envRequiredSecret("TEST_REQUIRED_SECRET_VAR")
		if err != nil {
			t.Errorf("envRequiredSecret(%d-byte value): %v", len(v), err)
			continue
		}
		if got != v {
			t.Errorf("envRequiredSecret must preserve bytes byte-for-byte: got len=%d want len=%d", len(got), len(v))
		}
	}
}

func TestControlplaneSecretRoundTripsAcrossRegistryManager(t *testing.T) {
	// A token issued by the control plane on its exact-registered secret must
	// verify on a registry-side manager built from the SAME raw env value, and
	// must NOT verify on a manager built from a trimmed (mutated) value.
	raw := " 	" + strings.Repeat("e", 32) + "\n"
	issuer, err := auth.NewSessionTokenManager(raw, auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	if err != nil {
		t.Fatalf("control-plane issuer on raw secret: %v", err)
	}
	tok, err := issuer.Issue("alice@example.test", time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	registryMirror, err := auth.NewSessionTokenManager(raw, auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	if err != nil {
		t.Fatalf("registry manager on identical raw secret: %v", err)
	}
	claims, err := registryMirror.Verify(tok)
	if err != nil || claims.Subject != "alice@example.test" {
		t.Fatalf("identical raw secret must verify across processes; got err=%v", err)
	}

	trimmedMgr, err := auth.NewSessionTokenManager(strings.TrimSpace(raw), auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	if err != nil {
		t.Fatalf("trimmed manager: %v", err)
	}
	if _, err := trimmedMgr.Verify(tok); err == nil {
		t.Fatal("a trimmed-secret manager must NOT verify a token signed with the padded secret")
	}
}
