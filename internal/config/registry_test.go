package config

import (
	"strings"
	"testing"
	"time"
)

// validEnv sets a fully valid registry staging environment.
func validEnv(t *testing.T) {
	t.Helper()
	t.Setenv(envStagingRoot, "/srv/registry/staging/spool")
	t.Setenv(envStagingDB, "/srv/registry/staging/staging.db")
	t.Setenv(envUploadTTL, "24h")
	t.Setenv(envMaxUploadBytes, "1073741824")       // 1 GiB
	t.Setenv(envMaxRepositoryBytes, "2147483648")   // 2 GiB
	t.Setenv(envMaxTotalStagingBytes, "4294967296") // 4 GiB
	t.Setenv(envStreamBufferBytes, "65536")
}

func TestLoadRegistryConfigValid(t *testing.T) {
	validEnv(t)
	cfg, err := LoadRegistryConfig()
	if err != nil {
		t.Fatalf("LoadRegistryConfig: %v", err)
	}
	if cfg.StagingRoot != "/srv/registry/staging/spool" || cfg.StagingDB != "/srv/registry/staging/staging.db" {
		t.Fatalf("unexpected paths: %+v", cfg)
	}
	if cfg.UploadTTL != 24*time.Hour {
		t.Fatalf("unexpected TTL: %v", cfg.UploadTTL)
	}
	if cfg.MaxUploadBytes != 1<<30 || cfg.MaxRepositoryBytes != 2<<30 || cfg.MaxTotalStagingBytes != 4<<30 {
		t.Fatalf("unexpected quota: %+v", cfg)
	}
	if cfg.StreamBufferBytes != 65536 {
		t.Fatalf("unexpected buffer: %d", cfg.StreamBufferBytes)
	}
}

func TestLoadRegistryConfigStreamBufferDefaults(t *testing.T) {
	validEnv(t)
	t.Setenv(envStreamBufferBytes, "")
	cfg, err := LoadRegistryConfig()
	if err != nil {
		t.Fatalf("LoadRegistryConfig: %v", err)
	}
	if cfg.StreamBufferBytes != defaultStreamBufferBytes {
		t.Fatalf("expected default buffer %d, got %d", defaultStreamBufferBytes, cfg.StreamBufferBytes)
	}
}

func TestLoadRegistryConfigRejectsNonAbsolutePath(t *testing.T) {
	validEnv(t)
	t.Setenv(envStagingRoot, "relative/spool")
	cfg, err := LoadRegistryConfig()
	if err == nil {
		t.Fatalf("expected non-absolute root to fail, got %+v", cfg)
	}
	if strings.Contains(err.Error(), "relative/spool") {
		t.Fatalf("error echoes the value: %v", err)
	}
}

func TestLoadRegistryConfigRejectsInvertedQuotaChain(t *testing.T) {
	validEnv(t)
	t.Setenv(envMaxRepositoryBytes, "536870912") // smaller than max-upload
	if _, err := LoadRegistryConfig(); err == nil {
		t.Fatal("expected inverted quota chain to fail")
	}
	validEnv(t)
	t.Setenv(envMaxTotalStagingBytes, "536870912") // smaller than max-repo
	if _, err := LoadRegistryConfig(); err == nil {
		t.Fatal("expected inverted total to fail")
	}
}

func TestLoadRegistryConfigRejectsInvalidTTL(t *testing.T) {
	validEnv(t)
	t.Setenv(envUploadTTL, "bogus")
	if _, err := LoadRegistryConfig(); err == nil {
		t.Fatal("expected invalid TTL to fail")
	}
	validEnv(t)
	t.Setenv(envUploadTTL, "")
	if _, err := LoadRegistryConfig(); err == nil {
		t.Fatal("expected missing TTL to fail")
	}
	t.Setenv(envUploadTTL, "-1h")
	if _, err := LoadRegistryConfig(); err == nil {
		t.Fatal("expected non-positive TTL to fail")
	}
}

func TestLoadRegistryConfigRejectsZeroOrNegativeLimit(t *testing.T) {
	for _, key := range []string{envMaxUploadBytes, envMaxRepositoryBytes, envMaxTotalStagingBytes} {
		validEnv(t)
		t.Setenv(key, "0")
		if _, err := LoadRegistryConfig(); err == nil {
			t.Fatalf("expected zero %s to fail", key)
		}
		validEnv(t)
		t.Setenv(key, "-5")
		if _, err := LoadRegistryConfig(); err == nil {
			t.Fatalf("expected negative %s to fail", key)
		}
		validEnv(t)
		t.Setenv(key, "abc")
		if _, err := LoadRegistryConfig(); err == nil {
			t.Fatalf("expected non-numeric %s to fail", key)
		}
	}
}

func TestLoadRegistryConfigRejectsBufferOutOfRange(t *testing.T) {
	validEnv(t)
	t.Setenv(envStreamBufferBytes, "128") // below min
	if _, err := LoadRegistryConfig(); err == nil {
		t.Fatal("expected under-min buffer to fail")
	}
	validEnv(t)
	t.Setenv(envStreamBufferBytes, "1073741824") // above max (1 GiB)
	if _, err := LoadRegistryConfig(); err == nil {
		t.Fatal("expected over-max buffer to fail")
	}
	validEnv(t)
	t.Setenv(envStreamBufferBytes, "abcd")
	if _, err := LoadRegistryConfig(); err == nil {
		t.Fatal("expected non-numeric buffer to fail")
	}
}

func TestLoadRegistryConfigDataFree(t *testing.T) {
	validEnv(t)
	t.Setenv(envStagingRoot, "/very/secret/private/path/with/spaces")
	t.Setenv(envMaxUploadBytes, "not-a-number")
	_, err := LoadRegistryConfig()
	if err == nil {
		t.Fatal("expected failure")
	}
	// The configured value/path must never appear in the error.
	for _, leaked := range []string{"secret", "private/path", "not-a-number"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("error leaks configured value %q: %v", leaked, err)
		}
	}
}
