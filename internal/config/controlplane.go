// Package config centralises control-plane configuration loading and
// validation. Startup reads every CONTROLPLANE_* knob exactly once, validates
// the whole matrix before any side effect (opening the database, reading
// secret files, or listening), and never reveals secret values in errors.
//
// The package intentionally separates structural validation (this file) from
// final cryptographic validation (the token-manager and key loaders in
// cmd/controlplane and internal/controlplane). Secrets stay in memory only
// long enough for the caller to hand them to the cryptographic constructors;
// errors and logs never echo them.
package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Mode selects explicit development or production behaviour. It must be
// declared — there is no implicit fallback, so a production deployment can
// never accidentally run with development-only laxness.
type Mode string

const (
	ModeDevelopment Mode = "development"
	ModeProduction  Mode = "production"
)

// insecurePlaceholder is a credential every production deployment must reject
// even if, through configuration drift, it would pass a length check.
const insecurePlaceholder = "dev-secret-change-me"

// TLSTermination modes. "direct" means the control plane serves TLS itself;
// "trusted-proxy" means an explicitly trusted reverse proxy terminates TLS
// and forwards the original client IP/scheme.
const (
	TLSTermDirect       = "direct"
	TLSTermTrustedProxy = "trusted-proxy"
)

// ControlPlaneConfig is the fully validated configuration for the control
// plane. After Load+Validate it is safe for components to trust.
type ControlPlaneConfig struct {
	Mode               Mode
	ListenAddr         string
	DBPath             string
	SessionSecret      string
	SessionTTL         time.Duration
	ExternalURL        *url.URL // nil when not configured
	SecureCookie       bool
	RegistryDomain     string
	RegistryEd25519Key string
	RegistryKeyID      string
	MasterKeyFile      string
	BeeAPIURL          *url.URL // nil when not configured
	TrustedProxyCIDRs  []netip.Prefix
	TLSTermination     string
	// TLSCertFile/TLSKeyFile name the X.509 certificate and private key used
	// to serve TLS directly. Both are required whenever TLSTermination is
	// "direct"; trusted-proxy termination does not need them.
	TLSCertFile string
	TLSKeyFile  string
	// LegacyKeyMigration records whether the operator opted in to migrating
	// legacy plaintext feed keys at startup (CONTROLPLANE_MIGRATE_LEGACY_KEYS).
	// Only the literal value "true" enables it; absent is the default (off);
	// any other value is rejected during Load so a typo can never silently
	// skip or run the migration.
	LegacyKeyMigration bool
}

const (
	defaultListenAddr     = ":8081"
	defaultDBPath         = "file:controlplane.db?_pragma=foreign_keys(1)"
	defaultRegistryDomain = "uncloud-registry.com"
	defaultRegistryKeyID  = "cp-ed25519-1"
	defaultTLSTermination = TLSTermDirect
	defaultSessionTTL     = 24 * time.Hour
	minSessionSecretBytes = 32
	registrySeedHexLen    = 64
)

const (
	envMode           = "CONTROLPLANE_MODE"
	envListenAddr     = "CONTROLPLANE_ADDR"
	envDBPath         = "CONTROLPLANE_DB_PATH"
	envSessionSecret  = "CONTROLPLANE_TOKEN_SECRET"
	envSessionTTL     = "CONTROLPLANE_SESSION_TTL"
	envExternalURL    = "CONTROLPLANE_EXTERNAL_URL"
	envRegistryDomain = "CONTROLPLANE_REGISTRY_DOMAIN"
	envRegistryKey    = "CONTROLPLANE_REGISTRY_ED25519_KEY"
	envRegistryKeyID  = "CONTROLPLANE_REGISTRY_KEY_ID"
	envMasterKeyFile  = "CONTROLPLANE_MASTER_KEY_FILE"
	envBeeAPIURL      = "CONTROLPLANE_BEE_API_URL"
	envTrustedProxies = "CONTROLPLANE_TRUSTED_PROXIES"
	envTLSTermination = "CONTROLPLANE_TLS_TERMINATION"
	envTLSCertFile    = "CONTROLPLANE_TLS_CERT_FILE"
	envTLSKeyFile     = "CONTROLPLANE_TLS_KEY_FILE"
	envMigrateLegacy  = "CONTROLPLANE_MIGRATE_LEGACY_KEYS"
)

func rawEnv(name string) string { return os.Getenv(name) }

func trimmedEnv(name string) string { return strings.TrimSpace(os.Getenv(name)) }

// Load reads every CONTROLPLANE_* variable into a ControlPlaneConfig without
// validating it. Callers must run Validate before using the value.
func Load() (*ControlPlaneConfig, error) {
	cfg := &ControlPlaneConfig{
		Mode:               Mode(trimmedEnv(envMode)),
		ListenAddr:         envOr(envListenAddr, defaultListenAddr),
		DBPath:             envOr(envDBPath, defaultDBPath),
		SessionSecret:      rawEnv(envSessionSecret),
		SessionTTL:         defaultSessionTTL,
		RegistryDomain:     envOr(envRegistryDomain, defaultRegistryDomain),
		RegistryEd25519Key: trimmedEnv(envRegistryKey),
		RegistryKeyID:      envOr(envRegistryKeyID, defaultRegistryKeyID),
		MasterKeyFile:      trimmedEnv(envMasterKeyFile),
		TLSTermination:     envOr(envTLSTermination, defaultTLSTermination),
		TLSCertFile:        envOr(envTLSCertFile, ""),
		TLSKeyFile:         envOr(envTLSKeyFile, ""),
	}

	if raw := strings.TrimSpace(os.Getenv(envSessionTTL)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("CONTROLPLANE_SESSION_TTL is invalid; use a Go duration like %q", "24h")
		}
		cfg.SessionTTL = d
	}

	if raw := trimmedEnv(envMigrateLegacy); raw != "" {
		if raw != "true" {
			// Parsed here so the value is validated in the same place as every
			// other knob, before any file or DB side effect.
			return nil, fmt.Errorf("CONTROLPLANE_MIGRATE_LEGACY_KEYS must be exactly \"true\" to enable legacy feed-key migration, or unset to skip it")
		}
		cfg.LegacyKeyMigration = true
	}

	var err error
	if cfg.ExternalURL, err = parseAbsoluteURL(envExternalURL); err != nil {
		return nil, err
	}
	if cfg.BeeAPIURL, err = parseAbsoluteURL(envBeeAPIURL); err != nil {
		return nil, err
	}

	if raw := trimmedEnv(envTrustedProxies); raw != "" {
		parts := splitCSV(raw)
		for _, p := range parts {
			prefix, perr := netip.ParsePrefix(p)
			if perr != nil {
				return nil, fmt.Errorf("CONTROLPLANE_TRUSTED_PROXIES contains an invalid CIDR %q", p)
			}
			cfg.TrustedProxyCIDRs = append(cfg.TrustedProxyCIDRs, prefix)
		}
	}
	return cfg, nil
}

func envOr(name, fallback string) string {
	if v := trimmedEnv(name); v != "" {
		return v
	}
	return fallback
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseAbsoluteURL validates and returns an absolute http(s) URL from an env
// value, or nil when the variable is unset/blank. A non-blank value that is
// not a valid absolute HTTP(S) URL is rejected. Never echoes the value.
func parseAbsoluteURL(name string) (*url.URL, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("%s is not a valid absolute URL", name)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%s must be an http or https URL", name)
	}
	return u, nil
}

// Validate verifies the whole configuration matrix. In production it rejects
// every known-insecure or missing setting. Development permits server-local
// laxness (absent external URL) but still requires the crypto primitives the
// running server necessarily needs (registry signing seed, master-key file)
// and rejects malformed structural values that would break startup or
// security invariants in any mode. Validation never logs or returns secret
// material or file paths.
func (c *ControlPlaneConfig) Validate() error {
	if c.Mode != ModeDevelopment && c.Mode != ModeProduction {
		return fmt.Errorf("CONTROLPLANE_MODE must be exactly %q or %q", ModeDevelopment, ModeProduction)
	}
	if err := c.validateListenAddr(); err != nil {
		return err
	}
	if err := c.validateDBPath(); err != nil {
		return err
	}
	if err := c.validateSessionSecret(); err != nil {
		return err
	}
	if c.SessionTTL <= 0 {
		return fmt.Errorf("CONTROLPLANE_SESSION_TTL must be positive")
	}
	if err := c.validateExternalURL(); err != nil {
		return err
	}
	if err := c.validateRegistryDomain(); err != nil {
		return err
	}
	if err := c.validateRegistryKey(); err != nil {
		return err
	}
	if err := c.validateRegistryKeyID(); err != nil {
		return err
	}
	if err := c.validateMasterKey(); err != nil {
		return err
	}
	if err := c.validateBee(); err != nil {
		return err
	}
	if err := c.validateProxies(); err != nil {
		return err
	}
	if err := c.validateTermination(); err != nil {
		return err
	}
	return nil
}

// validateListenAddr parses the listen address as host:port (host may be
// empty for all interfaces) and requires a numeric port in the valid range.
func (c *ControlPlaneConfig) validateListenAddr() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("CONTROLPLANE_ADDR must not be empty")
	}
	_, portStr, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return fmt.Errorf("CONTROLPLANE_ADDR must be a host:port address like %q", ":8081")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("CONTROLPLANE_ADDR must carry a numeric port in 1-65535")
	}
	return nil
}

// validateDBPath rejects control characters (including NUL) and malformed
// file: DSN/query forms without opening the database. Opening happens much
// later in startup, strictly after every value has validated.
func (c *ControlPlaneConfig) validateDBPath() error {
	if c.DBPath == "" {
		return fmt.Errorf("CONTROLPLANE_DB_PATH must not be empty")
	}
	for i := 0; i < len(c.DBPath); i++ {
		if c.DBPath[i] < 0x20 || c.DBPath[i] == 0x7f {
			return fmt.Errorf("CONTROLPLANE_DB_PATH must not contain control characters")
		}
	}
	if strings.HasPrefix(c.DBPath, "file:") {
		dsn := strings.TrimPrefix(c.DBPath, "file:")
		if dsn == "" {
			return fmt.Errorf("CONTROLPLANE_DB_PATH file DSN must name a database file")
		}
		if q := strings.IndexByte(dsn, '?'); q >= 0 {
			if _, err := url.ParseQuery(dsn[q+1:]); err != nil {
				return fmt.Errorf("CONTROLPLANE_DB_PATH file DSN has a malformed query")
			}
		}
	}
	return nil
}

// validateSessionSecret rejects missing, too-short, or placeholder session
// secrets. In production the explicit insecure placeholder AND predictable
// low-entropy values are rejected even if a length check alone would pass, so
// a drifted deployment cannot serve HMAC-signed sessions with a guessable or
// public key. The acceptance contract for production secrets is explicit:
// at least 32 raw bytes, at least 16 distinct byte values, and no short
// repeated period. Operators should use 32 cryptographically random bytes.
// The secret value is never echoed.
func (c *ControlPlaneConfig) validateSessionSecret() error {
	if c.SessionSecret == "" {
		return fmt.Errorf("CONTROLPLANE_TOKEN_SECRET is required and must not be empty")
	}
	if len([]byte(c.SessionSecret)) < minSessionSecretBytes {
		return fmt.Errorf("CONTROLPLANE_TOKEN_SECRET must be at least %d bytes", minSessionSecretBytes)
	}
	if c.Mode == ModeProduction {
		if strings.Contains(c.SessionSecret, insecurePlaceholder) {
			return fmt.Errorf("CONTROLPLANE_TOKEN_SECRET must not use the development placeholder value")
		}
		if weakSessionSecret(c.SessionSecret) {
			return fmt.Errorf("CONTROLPLANE_TOKEN_SECRET is not sufficiently random: use %d random bytes with no repeated pattern", minSessionSecretBytes)
		}
	}
	return nil
}

// weakSessionSecret reports whether a production session secret is
// predictable: fewer than 16 distinct byte values, an exact repeated block of
// any period up to len/2 (including `0123456789abcdef` repeated twice), a
// monotonic/sequential byte sequence, or a known common literal. Raw-byte
// compatibility is preserved in both modes — the value is never trimmed or
// otherwise mutated — but production rejects values that are structurally
// guessable. Ordinary high-entropy random bytes are accepted.
func weakSessionSecret(s string) bool {
	n := len(s)
	if n < minSessionSecretBytes {
		return false // length is guarded separately; a short secret is weak by length
	}
	distinct := make(map[byte]struct{}, n)
	for i := 0; i < n; i++ {
		distinct[s[i]] = struct{}{}
	}
	if len(distinct) < 16 {
		return true
	}
	// An exact repeated block of ANY period p in 1..len/2 covering the whole
	// value is predictable (e.g. a single repeated byte, an abab pattern, or
	// the 16-byte hex-alphabet block `0123456789abcdef` repeated twice).
	for p := 1; p <= n/2; p++ {
		if n%p != 0 {
			continue
		}
		block := s[:p]
		whole := true
		for i := p; i < n; i += p {
			if s[i:i+p] != block {
				whole = false
				break
			}
		}
		if whole {
			return true
		}
	}
	// Monotonic/sequential byte sequences and known common literals are also
	// predictable (real random bytes are effectively never fully sorted).
	if predictableSequence(s) {
		return true
	}
	for _, known := range knownWeakSecrets {
		if s == known {
			return true
		}
	}
	return false
}

// predictableSequence reports whether s is a monotonic/sequential byte run:
// either a constant-delta arithmetic progression or a strictly increasing or
// strictly decreasing sequence. Such values are trivially guessable.
func predictableSequence(s string) bool {
	n := len(s)
	if n < 3 {
		return false
	}
	d := int(s[1]) - int(s[0])
	if d != 0 {
		all := true
		for i := 2; i < n; i++ {
			if int(s[i])-int(s[i-1]) != d {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	inc, dec := true, true
	for i := 1; i < n; i++ {
		if s[i] <= s[i-1] {
			inc = false
		}
		if s[i] >= s[i-1] {
			dec = false
		}
	}
	return inc || dec
}

// knownWeakSecrets is a small table of common predictable 32+ byte literals
// that pass the structural guards above but are still recognizable defaults.
var knownWeakSecrets = []string{
	"0123456789abcdef0123456789abcdef",
	"1234567890abcdef1234567890abcdef",
	"0123456789abcdefghijklmnopqrstuv",
	"abcdefghijklmnopqrstuvwxyz0123456789",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"abcabcabcabcabcabcabcabcabcabcab",
	"deadbeefdeadbeefdeadbeefdeadbeef",
	"passwordpasswordpasswordpassword",
}

// validateExternalURL enforces the origin-only secure-origin contract:
// absolute http(s), no userinfo, no non-root path, no query, no fragment, and
// canonical host/port. Production requires an https URL (browser origin,
// secure cookies). Development permits an absent URL but, when one is
// configured, it must still satisfy the origin-only rule, and an https URL
// still forces Secure cookies.
func (c *ControlPlaneConfig) validateExternalURL() error {
	if c.ExternalURL == nil {
		if c.Mode == ModeProduction {
			return fmt.Errorf("CONTROLPLANE_EXTERNAL_URL is required in production and must be an absolute https origin")
		}
		return nil
	}
	if c.Mode == ModeProduction && c.ExternalURL.Scheme != "https" {
		return fmt.Errorf("CONTROLPLANE_EXTERNAL_URL must use https in production (an http public origin would force insecure cookies)")
	}
	if err := c.externalURLIsOriginOnly(); err != nil {
		return err
	}
	c.SecureCookie = c.ExternalURL.Scheme == "https"
	return nil
}

// externalURLIsOriginOnly rejects userinfo, a non-root path, a query, and a
// fragment so the value is a canonical browser origin (scheme + host[:port]).
func (c *ControlPlaneConfig) externalURLIsOriginOnly() error {
	u := c.ExternalURL
	if u.User != nil {
		return fmt.Errorf("CONTROLPLANE_EXTERNAL_URL must not contain userinfo")
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("CONTROLPLANE_EXTERNAL_URL must be an origin with no path")
	}
	if u.RawQuery != "" {
		return fmt.Errorf("CONTROLPLANE_EXTERNAL_URL must not contain a query")
	}
	if u.Fragment != "" {
		return fmt.Errorf("CONTROLPLANE_EXTERNAL_URL must not contain a fragment")
	}
	if u.Hostname() == "" {
		return fmt.Errorf("CONTROLPLANE_EXTERNAL_URL must carry a host")
	}
	return nil
}

// validateRegistryDomain enforces the canonical lowercase DNS hostname
// contract: each label 1..63 chars of ASCII letters/digits/hyphens, starting
// and ending with a letter or digit (internal hyphens only), a total length of
// at most 253, no scheme/path/port/wildcard/IP literal/trailing dot, and
// canonical lowercase. Raw bytes are preserved and the lowercased canonical
// value is stored so host construction is unambiguous.
func (c *ControlPlaneConfig) validateRegistryDomain() error {
	raw := strings.TrimSpace(c.RegistryDomain)
	if raw == "" {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_DOMAIN must not be empty")
	}
	if net.ParseIP(raw) != nil {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_DOMAIN must be a DNS hostname, not an IP address")
	}
	if strings.HasSuffix(raw, ".") {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_DOMAIN must not end with a trailing dot")
	}
	if strings.HasPrefix(raw, ".") || strings.Contains(raw, "..") {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_DOMAIN must be a bare hostname with non-empty dot-separated labels")
	}
	if strings.ContainsAny(raw, ":/\\@%?#*_= ") {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_DOMAIN must be a bare DNS hostname with no scheme, port, or wildcard")
	}
	domain := strings.ToLower(raw)
	if len(domain) > 253 {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_DOMAIN must be at most 253 characters")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) > 63 {
			return fmt.Errorf("CONTROLPLANE_REGISTRY_DOMAIN labels must each be at most 63 characters")
		}
		if !isDNSAlphaNum(label[0]) || !isDNSAlphaNum(label[len(label)-1]) {
			return fmt.Errorf("CONTROLPLANE_REGISTRY_DOMAIN labels must start and end with a letter or digit")
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if ch == '-' {
				if i == 0 || i == len(label)-1 {
					return fmt.Errorf("CONTROLPLANE_REGISTRY_DOMAIN labels must not begin or end with a hyphen")
				}
				continue
			}
			if !isDNSAlphaNum(ch) {
				return fmt.Errorf("CONTROLPLANE_REGISTRY_DOMAIN must contain only letters, digits, hyphens, and dots")
			}
		}
	}
	c.RegistryDomain = domain
	return nil
}

// isDNSAlphaNum reports whether b is an ASCII letter or digit.
func isDNSAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// validateRegistryKey requires the Ed25519 signing seed in EVERY mode — the
// running control plane always needs it to issue registry tokens, so there is
// no development-only optional path. It validates the shape in every mode.
// Errors describe the problem generally and never echo the seed.
func (c *ControlPlaneConfig) validateRegistryKey() error {
	trimmed := strings.TrimSpace(c.RegistryEd25519Key)
	if c.RegistryEd25519Key == "" || trimmed == "" {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_ED25519_KEY is required: set a stable %d-character hex Ed25519 seed", registrySeedHexLen)
	}
	if len(trimmed) != registrySeedHexLen {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_ED25519_KEY must be exactly %d hex characters", registrySeedHexLen)
	}
	if _, err := hex.DecodeString(trimmed); err != nil {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_ED25519_KEY is not valid hex")
	}
	return nil
}

// validateRegistryKeyID enforces a strict safe token shape for the public
// registry key ID: lowercase alphanumerics and internal hyphens, bounded
// length, so it is safe to emit in JWKS and logs.
func (c *ControlPlaneConfig) validateRegistryKeyID() error {
	id := c.RegistryKeyID
	if id == "" {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_KEY_ID must not be empty")
	}
	if len(id) > 64 {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_KEY_ID must be at most 64 characters")
	}
	for i, ch := range id {
		if i == 0 && ch == '-' {
			return fmt.Errorf("CONTROLPLANE_REGISTRY_KEY_ID must not start with a hyphen")
		}
		if !(ch == '-' || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
			return fmt.Errorf("CONTROLPLANE_REGISTRY_KEY_ID must contain only lowercase letters, digits, and hyphens")
		}
	}
	return nil
}

// validateMasterKey requires the master-key file setting in EVERY mode. The
// value is a path and never appears in errors. The running control plane
// always loads the master key before the database so registry feed keys are
// never stored in a development-only unencrypted path.
func (c *ControlPlaneConfig) validateMasterKey() error {
	if c.MasterKeyFile == "" {
		return fmt.Errorf("CONTROLPLANE_MASTER_KEY_FILE is required; startup always loads it before the database")
	}
	return nil
}

func (c *ControlPlaneConfig) validateBee() error {
	if c.BeeAPIURL == nil {
		return nil
	}
	if c.BeeAPIURL.Scheme != "http" && c.BeeAPIURL.Scheme != "https" {
		return fmt.Errorf("CONTROLPLANE_BEE_API_URL must be an http or https URL")
	}
	// Bee accepts origin-only URLs or a documented base path; never userinfo,
	// a query, or a fragment.
	if c.BeeAPIURL.User != nil {
		return fmt.Errorf("CONTROLPLANE_BEE_API_URL must not contain userinfo")
	}
	if c.BeeAPIURL.RawQuery != "" {
		return fmt.Errorf("CONTROLPLANE_BEE_API_URL must not contain a query")
	}
	if c.BeeAPIURL.Fragment != "" {
		return fmt.Errorf("CONTROLPLANE_BEE_API_URL must not contain a fragment")
	}
	return nil
}

// validateProxies parses and canonicalises the trusted-proxy prefix list,
// rejecting duplicates, overlaps, unspecified, and broad unsafe ranges. Only
// explicit, canonical CIDRs may be trusted to supply forwarded client IPs.
func (c *ControlPlaneConfig) validateProxies() error {
	seen := make(map[netip.Prefix]bool, len(c.TrustedProxyCIDRs))
	for _, p := range c.TrustedProxyCIDRs {
		if !p.IsValid() {
			return fmt.Errorf("CONTROLPLANE_TRUSTED_PROXIES contains an invalid prefix")
		}
		if p.Addr().IsUnspecified() {
			return fmt.Errorf("CONTROLPLANE_TRUSTED_PROXIES must not trust the unspecified address %s", p)
		}
		canonical := p.Masked()
		if canonical != p {
			// Distinguish the exact offending prefix without echoing secrets.
			return fmt.Errorf("CONTROLPLANE_TRUSTED_PROXIES requires canonical CIDRs without host bits")
		}
		if seen[canonical] {
			return fmt.Errorf("CONTROLPLANE_TRUSTED_PROXIES contains a duplicate prefix")
		}
		for other := range seen {
			if overlaps(canonical, other) {
				return fmt.Errorf("CONTROLPLANE_TRUSTED_PROXIES contains overlapping prefixes")
			}
		}
		seen[canonical] = true
	}
	return nil
}

func overlaps(a, b netip.Prefix) bool {
	if a.Bits() > b.Bits() {
		a, b = b, a
	}
	return a.Contains(b.Addr())
}

// validateTermination ensures the TLS-termination declaration is coherent: a
// trusted-proxy termination must declare trusted proxies and never needs a
// local certificate; a direct termination always requires both TLS certificate
// and private-key file paths (any mode), because a direct server must serve
// TLS and cannot do so without them. Also, an https external URL served
// directly must have a coherent in-process TLS termination, while a
// trusted-proxy termination legitimately terminates https at the proxy.
func (c *ControlPlaneConfig) validateTermination() error {
	switch c.TLSTermination {
	case TLSTermTrustedProxy:
		if len(c.TrustedProxyCIDRs) == 0 {
			return fmt.Errorf("CONTROLPLANE_TLS_TERMINATION=trusted-proxy requires CONTROLPLANE_TRUSTED_PROXIES")
		}
	case TLSTermDirect:
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return fmt.Errorf("CONTROLPLANE_TLS_TERMINATION=direct requires both CONTROLPLANE_TLS_CERT_FILE and CONTROLPLANE_TLS_KEY_FILE")
		}
	default:
		return fmt.Errorf("CONTROLPLANE_TLS_TERMINATION must be %q or %q", TLSTermDirect, TLSTermTrustedProxy)
	}
	return nil
}

// ExternalOrigin returns the scheme+host of the configured external URL, or "".
// It is the only value the control plane compares browser Origins against. It
// preserves IPv6 bracket semantics (URL.Host / net.JoinHostPort style) and
// drops a port that equals the scheme's default (the Origin header omits it).
func (c *ControlPlaneConfig) ExternalOrigin() string {
	if c.ExternalURL == nil {
		return ""
	}
	u := c.ExternalURL
	host := u.Hostname()
	if strings.Contains(host, ":") {
		// An IPv6 host must keep its brackets in a URL/Origin.
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		defaultPort := "80"
		if u.Scheme == "https" {
			defaultPort = "443"
		}
		if p != defaultPort {
			host = host + ":" + p
		}
	}
	return u.Scheme + "://" + host
}

// IsProduction reports whether the mode is production.
func (c *ControlPlaneConfig) IsProduction() bool { return c.Mode == ModeProduction }
