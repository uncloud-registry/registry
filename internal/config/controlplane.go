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
	}

	if raw := strings.TrimSpace(os.Getenv(envSessionTTL)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("CONTROLPLANE_SESSION_TTL is invalid; use a Go duration like %q", "24h")
		}
		cfg.SessionTTL = d
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
// every known-insecure or missing setting; in development it rejects malformed
// crypto configuration but permits the laxness a local server needs. Validation
// never logs or returns secret material.
func (c *ControlPlaneConfig) Validate() error {
	if c.Mode != ModeDevelopment && c.Mode != ModeProduction {
		return fmt.Errorf("CONTROLPLANE_MODE must be exactly %q or %q", ModeDevelopment, ModeProduction)
	}
	if c.ListenAddr == "" {
		return fmt.Errorf("CONTROLPLANE_ADDR must not be empty")
	}
	if c.DBPath == "" {
		return fmt.Errorf("CONTROLPLANE_DB_PATH must not be empty")
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
	if c.RegistryDomain == "" {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_DOMAIN must not be empty")
	}
	if err := c.validateRegistryKey(); err != nil {
		return err
	}
	if c.RegistryKeyID == "" {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_KEY_ID must not be empty")
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

// validateSessionSecret rejects missing, too-short, or placeholder session
// secrets. In production the explicit insecure placeholder is rejected even if
// a length check would pass, so a drifted deployment cannot serve HMAC-signed
// sessions with a guessable/public key.
func (c *ControlPlaneConfig) validateSessionSecret() error {
	if c.SessionSecret == "" {
		return fmt.Errorf("CONTROLPLANE_TOKEN_SECRET is required and must not be empty")
	}
	if len([]byte(c.SessionSecret)) < minSessionSecretBytes {
		return fmt.Errorf("CONTROLPLANE_TOKEN_SECRET must be at least %d bytes", minSessionSecretBytes)
	}
	if c.Mode == ModeProduction && strings.Contains(c.SessionSecret, insecurePlaceholder) {
		return fmt.Errorf("CONTROLPLANE_TOKEN_SECRET must not use the development placeholder value")
	}
	return nil
}

// validateExternalURL enforces the secure-origin contract. Production requires
// an absolute https URL (browser origin, secure cookies). Development permits
// an absent URL but, when one is configured, it must still be absolute and
// http(s), and an https URL still forces Secure cookies.
func (c *ControlPlaneConfig) validateExternalURL() error {
	if c.ExternalURL == nil {
		if c.Mode == ModeProduction {
			return fmt.Errorf("CONTROLPLANE_EXTERNAL_URL is required in production and must be an absolute https URL")
		}
		return nil
	}
	if c.Mode == ModeProduction && c.ExternalURL.Scheme != "https" {
		return fmt.Errorf("CONTROLPLANE_EXTERNAL_URL must use https in production (an http public origin would force insecure cookies)")
	}
	c.SecureCookie = c.ExternalURL.Scheme == "https"
	return nil
}

// validateRegistryKey requires the Ed25519 signing seed in production and
// validates its shape in every mode. Errors describe the problem generally and
// never echo the seed.
func (c *ControlPlaneConfig) validateRegistryKey() error {
	if c.RegistryEd25519Key == "" {
		if c.Mode == ModeProduction {
			return fmt.Errorf("CONTROLPLANE_REGISTRY_ED25519_KEY is required in production: set a stable %d-character hex Ed25519 seed", registrySeedHexLen)
		}
		return nil
	}
	if len(c.RegistryEd25519Key) != registrySeedHexLen {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_ED25519_KEY must be exactly %d hex characters", registrySeedHexLen)
	}
	if _, err := hex.DecodeString(c.RegistryEd25519Key); err != nil {
		return fmt.Errorf("CONTROLPLANE_REGISTRY_ED25519_KEY is not valid hex")
	}
	return nil
}

// validateMasterKey requires the master-key file setting in production. The
// value is a path and never appears in errors. Development permits an absent
// master key (the control plane then refuses to store feed keys).
func (c *ControlPlaneConfig) validateMasterKey() error {
	if c.MasterKeyFile == "" && c.Mode == ModeProduction {
		return fmt.Errorf("CONTROLPLANE_MASTER_KEY_FILE is required in production")
	}
	return nil
}

func (c *ControlPlaneConfig) validateBee() error {
	if c.BeeAPIURL == nil {
		if c.Mode == ModeProduction {
			// Bee publishing is optional even in production; a control plane can
			// manage registries without a Bee object store.
			return nil
		}
		return nil
	}
	if c.BeeAPIURL.Scheme != "http" && c.BeeAPIURL.Scheme != "https" {
		return fmt.Errorf("CONTROLPLANE_BEE_API_URL must be an http or https URL")
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
// trusted-proxy termination must declare trusted proxies, and (in production)
// an https external URL must be reachable either by serving TLS directly or by
// terminating at a declared trusted proxy.
func (c *ControlPlaneConfig) validateTermination() error {
	switch c.TLSTermination {
	case TLSTermTrustedProxy:
		if len(c.TrustedProxyCIDRs) == 0 {
			return fmt.Errorf("CONTROLPLANE_TLS_TERMINATION=trusted-proxy requires CONTROLPLANE_TRUSTED_PROXIES")
		}
	case TLSTermDirect:
		// Serving TLS directly is always self-consistent.
	default:
		if c.Mode == ModeProduction {
			return fmt.Errorf("CONTROLPLANE_TLS_TERMINATION must be %q or %q", TLSTermDirect, TLSTermTrustedProxy)
		}
		return fmt.Errorf("CONTROLPLANE_TLS_TERMINATION must be %q or %q", TLSTermDirect, TLSTermTrustedProxy)
	}
	if c.Mode == ModeProduction && c.ExternalURL != nil && c.ExternalURL.Scheme == "https" {
		if c.TLSTermination != TLSTermTrustedProxy && c.TLSTermination != TLSTermDirect {
			return fmt.Errorf("CONTROLPLANE_TLS_TERMINATION must declare trusted-proxy or direct TLS to serve an https external URL")
		}
	}
	return nil
}

// ExternalOrigin returns the scheme+host of the configured external URL, or "".
// It is the only value the control plane compares browser Origins against.
func (c *ControlPlaneConfig) ExternalOrigin() string {
	if c.ExternalURL == nil {
		return ""
	}
	// Derive the origin from scheme+host, dropping a port that equals the
	// scheme's default (the Origin header omits it).
	host := c.ExternalURL.Hostname()
	if p := c.ExternalURL.Port(); p != "" {
		defaultPort := "80"
		if c.ExternalURL.Scheme == "https" {
			defaultPort = "443"
		}
		if p != defaultPort {
			host = net.JoinHostPort(host, p)
		}
	}
	return c.ExternalURL.Scheme + "://" + host
}

// IsProduction reports whether the mode is production.
func (c *ControlPlaneConfig) IsProduction() bool { return c.Mode == ModeProduction }
