package config

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// validProductionSeed is a structurally valid 64-hex Ed25519 seed for tests.
const validProductionSeed = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

func strongSecret() string {
	return "prod-session-secret-0123456789abcdefghijklmnopqrstuvwxyz"
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// setEnv clears control-plane env vars and sets a minimal production set.
func setEnv(t *testing.T, m map[string]string) {
	t.Helper()
	for _, k := range []string{
		envMode, envListenAddr, envDBPath, envSessionSecret, envSessionTTL,
		envExternalURL, envRegistryDomain, envRegistryKey, envRegistryKeyID,
		envMasterKeyFile, envBeeAPIURL, envTrustedProxies, envTLSTermination,
	} {
		t.Setenv(k, "")
	}
	for k, v := range m {
		t.Setenv(k, v)
	}
}

func prodEnv(overrides map[string]string) map[string]string {
	m := map[string]string{
		envMode:           "production",
		envSessionSecret:  strongSecret(),
		envExternalURL:    "https://cp.example.com",
		envRegistryKey:    validProductionSeed,
		envMasterKeyFile:  "/run/secrets/master.key",
		envTrustedProxies: "10.0.0.0/8",
	}
	for k, v := range overrides {
		m[k] = v
	}
	return m
}

func loadValidated(t *testing.T, m map[string]string) (*ControlPlaneConfig, error) {
	t.Helper()
	setEnv(t, m)
	cfg, err := Load()
	if err != nil {
		return nil, err
	}
	return cfg, cfg.Validate()
}

func TestProductionConfigValid(t *testing.T) {
	cfg, err := loadValidated(t, prodEnv(nil))
	if err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
	if !cfg.IsProduction() {
		t.Fatal("expected production mode")
	}
	if !cfg.SecureCookie {
		t.Fatal("expected https external URL to force Secure cookies")
	}
	if cfg.ExternalOrigin() != "https://cp.example.com" {
		t.Fatalf("unexpected origin %q", cfg.ExternalOrigin())
	}
}

func TestProductionRejectsUnknownMode(t *testing.T) {
	for _, mode := range []string{"unknown", "staging", "prod", ""} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envMode: mode})); err == nil {
			t.Errorf("mode %q must be rejected", mode)
		}
	}
}

func TestProductionRejectsInsecurePlaceholderSecret(t *testing.T) {
	long := strings.Repeat("x", 40)
	cfg := prodEnv(map[string]string{envSessionSecret: long})
	if _, err := loadValidated(t, cfg); err != nil {
		t.Fatalf("strong secret rejected: %v", err)
	}
	// The literal placeholder, even padded past the length minimum, is rejected
	// in production so a drifted deployment cannot run on it.
	padded := strings.Repeat("a", 16) + "dev-secret-change-me" + strings.Repeat("z", 16)
	if _, err := loadValidated(t, prodEnv(map[string]string{envSessionSecret: padded})); err == nil {
		t.Fatal("production must reject the development placeholder secret")
	}
}

func TestRejectsWeakOrMissingSessionSecret(t *testing.T) {
	for _, secret := range []string{"", "   ", "short", "0123456789abcdef"} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envSessionSecret: secret})); err == nil {
			t.Errorf("weak secret %q must be rejected", secret)
		}
	}
}

func TestErrorNeverEchoesSecret(t *testing.T) {
	distinct := "$ecret_Not_to_echo-9f81"
	_, err := loadValidated(t, prodEnv(map[string]string{envSessionSecret: distinct[:20]}))
	if err == nil {
		t.Fatal("expected weak secret to be rejected")
	}
	if strings.Contains(err.Error(), distinct[:20]) {
		t.Fatalf("error must not echo the secret value: %v", err)
	}
}

func TestProductionRequiresExternalURL(t *testing.T) {
	if _, err := loadValidated(t, prodEnv(map[string]string{envExternalURL: ""})); err == nil {
		t.Fatal("production must require an external URL")
	}
}

func TestProductionRejectsHttpExternalURL(t *testing.T) {
	if _, err := loadValidated(t, prodEnv(map[string]string{envExternalURL: "http://cp.example.com"})); err == nil {
		t.Fatal("production must require an https external URL (insecure cookie)")
	}
}

func TestRejectsMalformedExternalURL(t *testing.T) {
	for _, u := range []string{"not a url", "://nohost", "ftp://x", "//nohost", "https://"} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envExternalURL: u})); err == nil {
			t.Errorf("malformed external URL %q must be rejected", u)
		}
	}
}

func TestProductionRequiresRegistryKey(t *testing.T) {
	if _, err := loadValidated(t, prodEnv(map[string]string{envRegistryKey: ""})); err == nil {
		t.Fatal("production must require the registry signing key")
	}
}

func TestRejectsMalformedRegistryKeyInAnyMode(t *testing.T) {
	for _, bad := range []string{"zzzz", strings.Repeat("0", 62), strings.Repeat("g", 64), validProductionSeed + "00"} {
		dev := prodEnv(map[string]string{envMode: "development", envRegistryKey: bad})
		if _, err := loadValidated(t, dev); err == nil {
			t.Errorf("malformed registry key %q must be rejected even in development", bad)
		}
	}
}

func TestProductionRequiresMasterKeyFile(t *testing.T) {
	if _, err := loadValidated(t, prodEnv(map[string]string{envMasterKeyFile: ""})); err == nil {
		t.Fatal("production must require the master-key file setting")
	}
	if _, err := loadValidated(t, prodEnv(map[string]string{envMasterKeyFile: "   "})); err == nil {
		t.Fatal("production must require a non-blank master-key file setting")
	}
}

func TestRejectsInvalidBeeURL(t *testing.T) {
	if _, err := loadValidated(t, prodEnv(map[string]string{envBeeAPIURL: "not-a-url"})); err == nil {
		t.Fatal("invalid bee url must be rejected")
	}
}

func TestTrustedProxyValidation(t *testing.T) {
	// Valid canonical list passes.
	base := prodEnv(nil)
	if _, err := loadValidated(t, base); err != nil {
		t.Fatalf("valid proxies rejected: %v", err)
	}
	// Duplicates rejected.
	dup := prodEnv(map[string]string{envTrustedProxies: "10.0.0.0/8,10.0.0.0/8"})
	if _, err := loadValidated(t, dup); err == nil {
		t.Fatal("duplicate proxy prefixes must be rejected")
	}
	// Overlaps rejected.
	ovl := prodEnv(map[string]string{envTrustedProxies: "10.0.0.0/8,10.1.0.0/16"})
	if _, err := loadValidated(t, ovl); err == nil {
		t.Fatal("overlapping proxy prefixes must be rejected")
	}
	// Non-canonical host bits rejected.
	hostbits := prodEnv(map[string]string{envTrustedProxies: "10.0.0.1/24"})
	if _, err := loadValidated(t, hostbits); err == nil {
		t.Fatal("non-canonical CIDR with host bits must be rejected")
	}
	// Unspecified /0 rejected.
	unspec := prodEnv(map[string]string{envTrustedProxies: "0.0.0.0/0"})
	if _, err := loadValidated(t, unspec); err == nil {
		t.Fatal("unspecified broad range must be rejected")
	}
	// Malformed entry rejected.
	bad := prodEnv(map[string]string{envTrustedProxies: "10.0.0.0/8,not-a-cidr"})
	if _, err := loadValidated(t, bad); err == nil {
		t.Fatal("malformed proxy entry must be rejected")
	}
}

func TestTLSTerminationValidation(t *testing.T) {
	// trusted-proxy requires proxies.
	proxy := prodEnv(map[string]string{envTLSTermination: "trusted-proxy", envTrustedProxies: ""})
	if _, err := loadValidated(t, proxy); err == nil {
		t.Fatal("trusted-proxy termination must require trusted proxies")
	}
	// Unknown termination rejected.
	unknown := prodEnv(map[string]string{envTLSTermination: "bogus"})
	if _, err := loadValidated(t, unknown); err == nil {
		t.Fatal("unknown TLS termination must be rejected")
	}
	// Valid trusted-proxy with proxies passes.
	valid := prodEnv(map[string]string{envTLSTermination: "trusted-proxy", envTrustedProxies: "10.0.0.0/8"})
	if _, err := loadValidated(t, valid); err != nil {
		t.Fatalf("valid trusted-proxy termination rejected: %v", err)
	}
}

func TestDevelopmentExplicitAndLenient(t *testing.T) {
	// Development must be explicit: it never results from a missing/unknown mode,
	// and it permits absent external URL / registry key / master key.
	dev := map[string]string{
		envMode:          "development",
		envSessionSecret: strongSecret(),
	}
	cfg, err := loadValidated(t, dev)
	if err != nil {
		t.Fatalf("valid development config rejected: %v", err)
	}
	if cfg.SecureCookie {
		t.Fatal("development with no external URL must not force Secure cookies")
	}
	// Missing mode is NOT an implicit development fallback.
	missing := map[string]string{envSessionSecret: strongSecret()}
	if _, err := loadValidated(t, missing); err == nil {
		t.Fatal("missing mode must be rejected, never silently default to development")
	}
}

func TestDevelopmentSecureCookieFromHttpsURL(t *testing.T) {
	dev := map[string]string{
		envMode:          "development",
		envSessionSecret: strongSecret(),
		envExternalURL:   "https://localhost:8443",
	}
	cfg, err := loadValidated(t, dev)
	if err != nil {
		t.Fatalf("dev https url rejected: %v", err)
	}
	if !cfg.SecureCookie {
		t.Fatal("https external URL must force Secure cookies even in development")
	}
	if cfg.ExternalOrigin() != "https://localhost:8443" {
		t.Fatalf("unexpected origin %q", cfg.ExternalOrigin())
	}
}

func TestExternalOriginDropsDefaultPort(t *testing.T) {
	cfg := &ControlPlaneConfig{Mode: ModeDevelopment}
	// https default port 443 is dropped from the origin.
	cfg.ExternalURL = mustURL("https://cp.example.com:443")
	if got := cfg.ExternalOrigin(); got != "https://cp.example.com" {
		t.Fatalf("origin %q should drop default https port", got)
	}
	cfg.ExternalURL = mustURL("https://cp.example.com:4443")
	if got := cfg.ExternalOrigin(); got != "https://cp.example.com:4443" {
		t.Fatalf("origin %q should keep non-default port", got)
	}
}

func TestSessionTTLValidation(t *testing.T) {
	if _, err := loadValidated(t, prodEnv(map[string]string{envSessionTTL: "0s"})); err == nil {
		t.Fatal("non-positive session TTL must be rejected")
	}
	if _, err := loadValidated(t, prodEnv(map[string]string{envSessionTTL: "garbage"})); err == nil {
		t.Fatal("malformed session TTL must be rejected")
	}
	cfg, err := loadValidated(t, prodEnv(map[string]string{envSessionTTL: "2h"}))
	if err != nil {
		t.Fatalf("valid TTL rejected: %v", err)
	}
	if cfg.SessionTTL != 2*time.Hour {
		t.Fatalf("unexpected TTL %v", cfg.SessionTTL)
	}
}
