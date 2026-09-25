// Registry staging configuration for the data-plane upload path (Task 16).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// RegistryConfig is the fully validated configuration for durable, bounded
// registry uploads. After Load+Validate succeeds it is safe to pass its
// values to the durable staging service (quota + stream buffer) and the
// registry handler (MaxUploadBytes copy cap) BEFORE the staging database is
// opened or any listener/client is exposed.
//
// Validation is strict and DATA-FREE: no staging path, DSN, or configured
// value is ever echoed in an error; a fixed field name and a fixed reason are
// the whole public surface, so an attacker reading a startup error learns the
// field, never the value.
type RegistryConfig struct {
	// StagingRoot is the absolute, symlink-free 0700 spool directory for
	// staged upload files (anchored per the Task 15 descriptor-relative
	// rules; the spool enforces the full component walk at construction).
	StagingRoot string
	// StagingDB is the absolute path of the dedicated staging SQLite
	// database. It must NOT be the control-plane database.
	StagingDB string
	// UploadTTL is the session lifetime.
	UploadTTL time.Duration
	// MaxUploadBytes bounds a single upload's cumulative size (a.k.a. the
	// per-session quota, enforced atomically by the staging service).
	MaxUploadBytes int64
	// MaxRepositoryBytes bounds the active+finalized staging bytes for one
	// repository across processes.
	MaxRepositoryBytes int64
	// MaxTotalStagingBytes bounds the active+finalized staging bytes across
	// every repository.
	MaxTotalStagingBytes int64
	// StreamBufferBytes is the fixed streaming-copy buffer used by bounded
	// appends (safe min/max enforced, no body-size allocation).
	StreamBufferBytes int
}

// Env-var names for the registry staging knobs.
const (
	envStagingRoot           = "REGISTRY_STAGING_ROOT"
	envStagingDB             = "REGISTRY_STAGING_DB"
	envUploadTTL             = "REGISTRY_UPLOAD_TTL"
	envMaxUploadBytes        = "REGISTRY_MAX_UPLOAD_BYTES"
	envMaxRepositoryBytes    = "REGISTRY_MAX_REPOSITORY_BYTES"
	envMaxTotalStagingBytes  = "REGISTRY_MAX_TOTAL_STAGING_BYTES"
	envStreamBufferBytes     = "REGISTRY_STREAM_BUFFER_BYTES"
	defaultStreamBufferBytes = 64 * 1024
	minStreamBufferBytes     = 4096
	maxStreamBufferBytes     = 1 << 20 // 1 MiB
)

// LoadRegistryConfig reads and validates the registry staging configuration
// from the environment in ONE pass. Every required value must be present,
// parseable, and within the bounded grammar; any failure returns a fixed,
// data-free error with zero side effects (no DB, no listener, no sidecar).
func LoadRegistryConfig() (RegistryConfig, error) {
	cfg := RegistryConfig{
		StagingRoot:       strings.TrimSpace(os.Getenv(envStagingRoot)),
		StagingDB:         strings.TrimSpace(os.Getenv(envStagingDB)),
		StreamBufferBytes: defaultStreamBufferBytes,
	}

	var ttl textDuration
	if err := ttl.set(strings.TrimSpace(os.Getenv(envUploadTTL))); err != nil {
		return RegistryConfig{}, err
	}
	cfg.UploadTTL = time.Duration(ttl)

	m, err := parsePositiveInt64(strings.TrimSpace(os.Getenv(envMaxUploadBytes)))
	if err != nil {
		return RegistryConfig{}, err
	}
	r, err := parsePositiveInt64(strings.TrimSpace(os.Getenv(envMaxRepositoryBytes)))
	if err != nil {
		return RegistryConfig{}, err
	}
	t, err := parsePositiveInt64(strings.TrimSpace(os.Getenv(envMaxTotalStagingBytes)))
	if err != nil {
		return RegistryConfig{}, err
	}
	cfg.MaxUploadBytes, cfg.MaxRepositoryBytes, cfg.MaxTotalStagingBytes = m, r, t

	if raw := strings.TrimSpace(os.Getenv(envStreamBufferBytes)); raw != "" {
		n, err := parsePositiveInt(strings.TrimSpace(os.Getenv(envStreamBufferBytes)))
		if err != nil {
			return RegistryConfig{}, err
		}
		cfg.StreamBufferBytes = n
	}

	if err := cfg.Validate(); err != nil {
		return RegistryConfig{}, err
	}
	return cfg, nil
}

// Validate enforces the cross-field invariants with fixed, data-free errors.
func (c RegistryConfig) Validate() error {
	if !isAbsolute(c.StagingRoot) {
		return fixedErr("REGISTRY_STAGING_ROOT must be an absolute path")
	}
	if !isAbsolute(c.StagingDB) {
		return fixedErr("REGISTRY_STAGING_DB must be an absolute path")
	}
	if c.StagingRoot == "" || c.StagingDB == "" {
		return fixedErr("registry staging paths are required")
	}
	if c.UploadTTL <= 0 {
		return fixedErr("REGISTRY_UPLOAD_TTL must be a positive duration")
	}
	// Positive finite limits with the monotone chain. An operator typo can
	// never create an inverted quota that silently admits an upload.
	if c.MaxUploadBytes <= 0 || c.MaxRepositoryBytes <= 0 || c.MaxTotalStagingBytes <= 0 {
		return fixedErr("registry staging byte limits must be positive")
	}
	if c.MaxUploadBytes > c.MaxRepositoryBytes || c.MaxRepositoryBytes > c.MaxTotalStagingBytes {
		return fixedErr("REGISTRY_MAX_UPLOAD_BYTES must be <= REGISTRY_MAX_REPOSITORY_BYTES <= REGISTRY_MAX_TOTAL_STAGING_BYTES")
	}
	if c.StreamBufferBytes < minStreamBufferBytes || c.StreamBufferBytes > maxStreamBufferBytes {
		return fixedErr("REGISTRY_STREAM_BUFFER_BYTES is outside the safe range")
	}
	return nil
}

// textDuration is a time.Duration parsed from a nonblank string with a fixed
// data-free parse error.
type textDuration time.Duration

func (d *textDuration) set(s string) error {
	if strings.TrimSpace(s) == "" {
		return fixedErr("REGISTRY_UPLOAD_TTL must be set")
	}
	v, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fixedErr("REGISTRY_UPLOAD_TTL is not a valid duration")
	}
	if v <= 0 {
		return fixedErr("REGISTRY_UPLOAD_TTL must be a positive duration")
	}
	*d = textDuration(v)
	return nil
}

func parsePositiveInt64(s string) (int64, error) {
	if strings.TrimSpace(s) == "" {
		return 0, fixedErr("a registry staging byte limit must be set")
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v <= 0 {
		return 0, fixedErr("a registry staging byte limit must be a positive integer")
	}
	return v, nil
}

func parsePositiveInt(s string) (int, error) {
	if strings.TrimSpace(s) == "" {
		return 0, fixedErr("a registry staging value must be set")
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 32)
	if err != nil || v <= 0 {
		return 0, fixedErr("REGISTRY_STREAM_BUFFER_BYTES must be a positive integer")
	}
	return int(v), nil
}

func isAbsolute(p string) bool {
	if p == "" {
		return false
	}
	// A leading slash (or a drive-letter-less POSIX root) is required. ".."
	// and trailing "/." are left to the spool's strict component walk.
	return strings.HasPrefix(p, "/")
}

// fixedErr returns a stable data-free error text.
func fixedErr(msg string) error { return fmt.Errorf("%s", msg) }
