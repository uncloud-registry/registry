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
		envTLSCertFile, envTLSKeyFile, envMigrateLegacy,
	} {
		t.Setenv(k, "")
	}
	for k, v := range m {
		t.Setenv(k, v)
	}
}

func prodEnv(overrides map[string]string) map[string]string {
	m := map[string]string{
		envMode:          "production",
		envSessionSecret: strongSecret(),
		envExternalURL:   "https://cp.example.com",
		envRegistryKey:   validProductionSeed,
		envMasterKeyFile: "/run/secrets/master.key",
		envTLSCertFile:   "/run/secrets/tls.crt",
		envTLSKeyFile:    "/run/secrets/tls.key",
	}
	for k, v := range overrides {
		m[k] = v
	}
	return m
}

// devBase is a validating development fixture: development must still name the
// registry signing seed, the master-key file, and (for the default direct TLS
// termination) the certificate/key paths.
func devBase(overrides map[string]string) map[string]string {
	m := map[string]string{
		envMode:          "development",
		envSessionSecret: strongSecret(),
		envRegistryKey:   validProductionSeed,
		envMasterKeyFile: "/run/secrets/master.key",
		envTLSCertFile:   "/run/secrets/tls.crt",
		envTLSKeyFile:    "/run/secrets/tls.key",
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
	// A genuinely strong secret with plenty of entropy is accepted.
	long := strongSecret() + "xyz012"
	if _, err := loadValidated(t, prodEnv(map[string]string{envSessionSecret: long})); err != nil {
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
	// Development must be explicit: it never results from a missing/unknown
	// mode. It permits an absent external URL but still requires the crypto
	// primitives the running server needs (registry seed, master key) and the
	// TLS key/cert paths for its default direct termination.
	dev := devBase(nil)
	cfg, err := loadValidated(t, dev)
	if err != nil {
		t.Fatalf("valid development config rejected: %v", err)
	}
	if cfg.SecureCookie {
		t.Fatal("development with no external URL must not force Secure cookies")
	}
	if cfg.MasterKeyFile == "" {
		t.Fatal("development must still name a master-key file")
	}
	// Missing mode is NOT an implicit development fallback.
	missing := map[string]string{envSessionSecret: strongSecret()}
	if _, err := loadValidated(t, missing); err == nil {
		t.Fatal("missing mode must be rejected, never silently default to development")
	}
}

func TestDevelopmentRequiresCryptoPrimitivesInAllModes(t *testing.T) {
	// Registry seed and master-key file are required in development too (no
	// optional mismatch with startup, which always needs both).
	noSeed := devBase(map[string]string{envRegistryKey: ""})
	if _, err := loadValidated(t, noSeed); err == nil {
		t.Fatal("development must require the registry signing seed")
	}
	noMaster := devBase(map[string]string{envMasterKeyFile: ""})
	if _, err := loadValidated(t, noMaster); err == nil {
		t.Fatal("development must require the master-key file")
	}
	// Direct termination always needs the TLS key/cert paths.
	noCert := devBase(map[string]string{envTLSCertFile: ""})
	if _, err := loadValidated(t, noCert); err == nil {
		t.Fatal("direct termination must require the TLS certificate path even in development")
	}
}

func TestDevelopmentSecureCookieFromHttpsURL(t *testing.T) {
	dev := devBase(map[string]string{envExternalURL: "https://localhost:8443"})
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

// TestControlPlaneConfigAggregate is the aggregate end-to-end config test the
// prescribed focused regex ("TestControlPlaneConfig") selects: it loads and
// validates a full production matrix and a full development matrix, confirming
// every knob composes into a usable config with the derived values populated.
func TestControlPlaneConfigAggregate(t *testing.T) {
	prod, err := loadValidated(t, prodEnv(map[string]string{
		envSessionTTL: "1h", envBeeAPIURL: "https://bee.example.com",
		envRegistryDomain: "Registry.Example.COM", envRegistryKeyID: "cp-ed25519-1",
	}))
	if err != nil {
		t.Fatalf("aggregate production config rejected: %v", err)
	}
	if !prod.IsProduction() || !prod.SecureCookie {
		t.Fatal("production aggregate must be secure")
	}
	if prod.SessionTTL != time.Hour {
		t.Fatalf("aggregate TTL not wired: %v", prod.SessionTTL)
	}
	if prod.RegistryDomain != "registry.example.com" {
		t.Fatalf("registry domain must be canonical lowercased, got %q", prod.RegistryDomain)
	}
	if prod.BeeAPIURL == nil || prod.BeeAPIURL.String() != "https://bee.example.com" {
		t.Fatalf("bee url not parsed: %v", prod.BeeAPIURL)
	}
	if prod.ExternalOrigin() != "https://cp.example.com" {
		t.Fatalf("unexpected origin %q", prod.ExternalOrigin())
	}

	dev, err := loadValidated(t, devBase(nil))
	if err != nil {
		t.Fatalf("aggregate development config rejected: %v", err)
	}
	if dev.IsProduction() || dev.SecureCookie {
		t.Fatal("development aggregate must not be secure-cookie without https")
	}
}

func TestListenAddrValidation(t *testing.T) {
	for _, addr := range []string{":8081", "127.0.0.1:8081", "[::1]:8081"} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envListenAddr: addr})); err != nil {
			t.Errorf("valid listen addr %q rejected: %v", addr, err)
		}
	}
	for _, addr := range []string{":0", ":99999", "8081", "host", ":abc"} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envListenAddr: addr})); err == nil {
			t.Errorf("invalid listen addr %q must be rejected", addr)
		}
	}
}

func TestExternalURLOriginOnlyValidation(t *testing.T) {
	for _, u := range []string{
		"https://cp.example.com/path", "https://cp.example.com?x=1",
		"https://cp.example.com#frag", "https://user:pass@cp.example.com",
		"https://cp.example.com/api",
	} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envExternalURL: u})); err == nil {
			t.Errorf("non-origin external URL %q must be rejected", u)
		}
	}
}

func TestRegistryDomainValidation(t *testing.T) {
	for _, d := range []string{"Uncloud-Registry.com", "registry.example.com"} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envRegistryDomain: d})); err != nil {
			t.Errorf("valid registry domain %q rejected: %v", d, err)
		}
	}
	for _, d := range []string{
		"http://reg.example.com", "reg.example.com:8080", "*.example.com",
		"reg.example.com.", "192.168.1.1", "reg example", "reg_example.com",
		"reg.example.com/path", "reg..com", "reg.",
	} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envRegistryDomain: d})); err == nil {
			t.Errorf("invalid registry domain %q must be rejected", d)
		}
		// Also the SQLite file-vs-host marker: a bare hyphen-only label is fine,
		// but a host-form must not slip through as an IP.
	}
}

func TestDBPathValidation(t *testing.T) {
	for _, p := range []string{"file:controlplane.db?_pragma=foreign_keys(1)", "file:db?mode=memory&cache=shared"} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envDBPath: p})); err != nil {
			t.Errorf("valid db path %q rejected: %v", p, err)
		}
	}
	for _, p := range []string{"file:", "file:db?bad=%zz"} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envDBPath: p})); err == nil {
			t.Errorf("invalid db path %q must be rejected", p)
		}
	}
	// Control characters/NUL are rejected by validateDBPath itself (they cannot
	// be injected through an env var, so test the method directly).
	if err := (&ControlPlaneConfig{DBPath: "db\x00"}).validateDBPath(); err == nil {
		t.Fatal("NUL in DB path must be rejected")
	}
	if err := (&ControlPlaneConfig{DBPath: "db\x01file"}).validateDBPath(); err == nil {
		t.Fatal("control character in DB path must be rejected")
	}
}

func TestRegistryKeyIDValidation(t *testing.T) {
	for _, id := range []string{"cp-ed25519-1", "abc123"} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envRegistryKeyID: id})); err != nil {
			t.Errorf("valid registry key id %q rejected: %v", id, err)
		}
	}
	for _, id := range []string{"-lead", "UPPER", "has space", "bad/id", "x?"} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envRegistryKeyID: id})); err == nil {
			t.Errorf("invalid registry key id %q must be rejected", id)
		}
	}
}

func TestProductionRejectsWeakSessionSecret(t *testing.T) {
	weak := []string{
		strings.Repeat("a", 32),         // one repeated byte
		strings.Repeat("ab", 16),        // repeated 2-byte period
		strings.Repeat("abab", 8),       // repeated 4-byte period
		strings.Repeat("0123456789", 4), // 10 distinct < 16
		strings.Repeat("01234567", 4),   // 8 distinct < 16
	}
	for _, s := range weak {
		if _, err := loadValidated(t, prodEnv(map[string]string{envSessionSecret: s})); err == nil {
			t.Errorf("predictable production secret must be rejected (len %d)", len(s))
		}
	}
	if _, err := loadValidated(t, prodEnv(nil)); err != nil {
		t.Fatalf("strong random-ish secret must be accepted: %v", err)
	}
}

func TestLegacyMigrationValueParsed(t *testing.T) {
	// Unset means disabled.
	if _, err := loadValidated(t, prodEnv(nil)); err != nil {
		t.Fatalf("unset migration loaded: %v", err)
	}
	// Literal "true" enables it.
	on, err := loadValidated(t, prodEnv(map[string]string{envMigrateLegacy: "true"}))
	if err != nil {
		t.Fatalf("migration true rejected: %v", err)
	}
	if !on.LegacyKeyMigration {
		t.Fatal("CONTROLPLANE_MIGRATE_LEGACY_KEYS=true must set LegacyKeyMigration")
	}
	// Any other value is rejected at Load (before side effects).
	for _, v := range []string{"false", "TRUE", "1", "yes", "ture"} {
		if _, err := loadValidated(t, prodEnv(map[string]string{envMigrateLegacy: v})); err == nil {
			t.Errorf("migration value %q must be rejected", v)
		}
	}
	// Development with migration off still fine.
	if _, err := loadValidated(t, devBase(map[string]string{envMigrateLegacy: "true"})); err != nil {
		t.Errorf("development migration true rejected: %v", err)
	}
}
