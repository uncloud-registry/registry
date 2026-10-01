package config

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Fix round 2/5: weak predictable secrets
// ---------------------------------------------------------------------------
//
// Production must reject exact repeated patterns of ANY period up to len/2
// (including `0123456789abcdef` repeated twice), monotonic/sequential and
// other common predictable 32+ byte values, while still accepting genuinely
// strong deterministic bytes with >=16 distinct, nonperiodic, non-monotonic
// content.

func TestProductionRejectsPredictableSecretsTable(t *testing.T) {
	// Every entry must be REJECTED by validate in production. Entries span:
	// exact periods of any length up to len/2, monotonic/sequential byte
	// sequences, and common predictable literals.
	weak := []string{
		strings.Repeat("0123456789abcdef", 2),                 // hex digits x2 = 32 bytes
		strings.Repeat("deadbeefcafebabe0123456789abcdef", 2), // 64 magic words period-32
		"0123456789abcdefghijklmnopqrstuv",                    // strictly increasing ASCII run
		strings.Repeat("ab", 16),                              // period-2 (existing guard)
		strings.Repeat("0123456789", 20),                      // 10 distinct < 16 (existing guard)
		strings.Repeat("1234567890abcdef", 2),                 // period-16 alternative
	}
	for _, s := range weak {
		if len([]byte(s)) < minSessionSecretBytes {
			t.Fatalf("fixture under length minimum: %q", s)
		}
		if _, err := loadValidated(t, prodEnv(map[string]string{envSessionSecret: s})); err == nil {
			t.Errorf("predictable production secret must be rejected (len %d): %.32q…", len(s), s)
		}
	}
}

func TestProductionAcceptsStrongDeterministicSecret(t *testing.T) {
	// A deterministic 32-byte value with >=16 distinct, nonperiodic,
	// non-monotonic bytes must be accepted (random-looking bytes are never
	// falsely rejected).
	strong := "f0e1d2c3b4a596877a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9"
	strong = strong[:32]
	if len([]byte(strong)) != minSessionSecretBytes {
		t.Fatalf("fixture must be 32 bytes, got %d", len([]byte(strong)))
	}
	if _, err := loadValidated(t, prodEnv(map[string]string{envSessionSecret: strong})); err != nil {
		t.Fatalf("strong deterministic secret must be accepted: %v", err)
	}
	// The literal known-good strong production secret is also accepted.
	if _, err := loadValidated(t, prodEnv(nil)); err != nil {
		t.Fatalf("baseline strong secret must be accepted: %v", err)
	}
}

func TestWeakSessionSecretPredicateUnit(t *testing.T) {
	// Direct predicate-level coverage so a future caller can reason about
	// weakSessionSecret independent of env plumbing.
	for _, weak := range []string{
		strings.Repeat("0123456789abcdef", 2),
		"0123456789abcdefghijklmnopqrstuv", // strictly increasing
		strings.Repeat("a", 32),
		strings.Repeat("abc", 11), // 33 bytes, period-3
	} {
		if !weakSessionSecret(weak) {
			t.Errorf("weakSessionSecret(%d bytes) must be true", len([]byte(weak)))
		}
	}
	for _, strong := range []string{
		"f0e1d2c3b4a596877a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9"[:32],
		strongSecret(),
	} {
		if weakSessionSecret(strong) {
			t.Errorf("weakSessionSecret(%d bytes) must be false for strong bytes", len([]byte(strong)))
		}
	}
}

// ---------------------------------------------------------------------------
// Fix round 2/5: DNS labels / IPv6 origin
// ---------------------------------------------------------------------------

func TestRegistryDomainLabelValidation(t *testing.T) {
	valid := []string{
		"registry.example.com",
		"a-valid-label.example",
		"123.example.com",
		strings.Repeat("a", 63) + ".example.com",                // max-length single label
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63), // two 63-char labels = 127 total
	}
	for _, d := range valid {
		if _, err := loadValidated(t, prodEnv(map[string]string{envRegistryDomain: d})); err != nil {
			t.Errorf("valid registry domain %q rejected: %v", d, err)
		}
	}

	invalid := []string{
		"-leading.example.com",                   // label starts with hyphen
		"trailing-.example.com",                  // label ends with hyphen
		"-",                                      // bare hyphen
		strings.Repeat("a", 64) + ".example.com", // label over 63 chars
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63), // total > 253
		"under_score.example.com",     // underscore
		"caf\u00e9.example.com",       // unicode
		"192.168.1.1",                 // IPv4 literal
		"2001:db8::1",                 // IPv6 literal
		"registry..com",               // empty label
		"registry.example.com.",       // trailing dot
		"http://registry.example.com", // scheme
		"registry.example.com:8080",   // port
		"*.registry.example.com",      // wildcard
	}
	for _, d := range invalid {
		// IPv4/IPv6 cannot be lowercased-validated as hostnames at all; they
		// are rejected by the no-IP special case.
		if _, err := loadValidated(t, prodEnv(map[string]string{envRegistryDomain: d})); err == nil {
			t.Errorf("invalid registry domain %q must be rejected", d)
		}
	}
}

func TestExternalOriginIPv6RoundTrip(t *testing.T) {
	cases := map[string]string{
		"https://cp.example.com":         "https://cp.example.com",
		"https://cp.example.com:8443":    "https://cp.example.com:8443",
		"https://cp.example.com:443":     "https://cp.example.com",
		"http://cp.example.com:80":       "http://cp.example.com",
		"https://[2001:db8::1]":          "https://[2001:db8::1]",
		"https://[2001:db8::1]:8443":     "https://[2001:db8::1]:8443",
		"https://[2001:db8::1]:443":      "https://[2001:db8::1]",
		"http://[::1]:80":                "http://[::1]",
		"https://[::ffff:10.0.0.1]:9443": "https://[::ffff:10.0.0.1]:9443",
	}
	for raw, want := range cases {
		cfg := &ControlPlaneConfig{Mode: ModeProduction, ExternalURL: mustURL(raw)}
		if got := cfg.ExternalOrigin(); got != want {
			t.Errorf("ExternalOrigin(%q) = %q, want %q", raw, got, want)
		}
	}
}
