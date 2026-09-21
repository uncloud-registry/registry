package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
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
