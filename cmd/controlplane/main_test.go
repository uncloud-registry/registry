package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/config"
	"github.com/uncloud-registry/registry/internal/controlplane"
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

// TestMasterKeyFilePathRequired pins that the control plane requires
// CONTROLPLANE_MASTER_KEY_FILE: startup fails when it is absent or blank, and
// the configured path is preserved byte-for-byte. The error names the variable
// (not its value) so no path material ever reaches logs.
func TestMasterKeyFilePathRequired(t *testing.T) {
	t.Setenv("CONTROLPLANE_MASTER_KEY_FILE", "")
	if _, err := masterKeyFileFromEnv(); err == nil {
		t.Fatal("expected missing CONTROLPLANE_MASTER_KEY_FILE to be rejected")
	} else if !strings.Contains(err.Error(), "CONTROLPLANE_MASTER_KEY_FILE") {
		t.Fatalf("error must name the variable, never a path value: %v", err)
	}
	distinctive := " /tmp/master-key-file-9f17b2.json "
	t.Setenv("CONTROLPLANE_MASTER_KEY_FILE", distinctive)
	got, err := masterKeyFileFromEnv()
	if err != nil {
		t.Fatalf("present value must load: %v", err)
	}
	if got != distinctive {
		t.Fatalf("master key path must be preserved byte-for-byte: got %q", got)
	}
}

// INVARIANT (shared with cmd/registry's tokenManagerFromEnv): whitespace is
// used only to detect a missing/all-whitespace value; any nonblank configured
// secret is preserved byte-for-byte as the HMAC key. Whitespace is a
// legitimate part of the opaque secret bytes, not text to be trimmed.
func TestEnvRequiredSecretPreservesBytesByteForByte(t *testing.T) {
	cases := []string{
		" " + strings.Repeat("a", 32) + " ",  // padded both sides
		"\t" + strings.Repeat("b", 32),       // leading tab
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
	raw := " \t" + strings.Repeat("e", 32) + "\n"
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

// ---------------------------------------------------------------------------
// Startup assembly tests
// ---------------------------------------------------------------------------

const startSeed = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

func testCfg(mode config.Mode, termination string) *config.ControlPlaneConfig {
	return &config.ControlPlaneConfig{
		Mode:               mode,
		ListenAddr:         ":8443",
		DBPath:             "file:mem?mode=memory&cache=shared",
		SessionSecret:      "controlplane-test-session-secret-0123456789abcdef",
		SessionTTL:         time.Hour,
		RegistryDomain:     "registry.example.com",
		RegistryEd25519Key: startSeed,
		RegistryKeyID:      "cp-ed25519-1",
		MasterKeyFile:      "/run/secrets/master.key",
		TLSCertFile:        "/run/secrets/tls.crt",
		TLSKeyFile:         "/run/secrets/tls.key",
		TLSTermination:     termination,
	}
}

func fakeMasterKey(t *testing.T) func(string) (*controlplane.FeedKeyCipher, error) {
	t.Helper()
	return func(_ string) (*controlplane.FeedKeyCipher, error) {
		return controlplane.NewFeedKeyCipher(map[int][]byte{1: bytes.Repeat([]byte{0x42}, 32)}, 1)
	}
}

func TestPrepareDirectChoosesTLSAndOpensDBLast(t *testing.T) {
	cfg := testCfg(config.ModeProduction, config.TLSTermDirect)
	var tlsLoaded, storeOpened int
	deps := defaultDeps()
	deps.loadMasterKey = fakeMasterKey(t)
	deps.loadTLSKeyPair = func(_, _ string) (tls.Certificate, error) {
		tlsLoaded++
		return tls.Certificate{}, nil
	}
	deps.openStore = func(_ string) (*controlplane.Store, error) {
		storeOpened++
		return &controlplane.Store{}, nil
	}

	comps, err := prepareControlPlane(cfg, deps)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if comps.tlsCert == nil {
		t.Fatal("direct termination must select a TLS certificate")
	}
	if tlsLoaded != 1 || storeOpened != 1 {
		t.Fatalf("expected TLS then store exactly once, got tls=%d store=%d", tlsLoaded, storeOpened)
	}
}

func TestPrepareTrustedProxyServesInternalHTTP(t *testing.T) {
	cfg := testCfg(config.ModeProduction, config.TLSTermTrustedProxy)
	cfg.TrustedProxyCIDRs = nil
	var tlsLoaded, storeOpened int
	deps := defaultDeps()
	deps.loadMasterKey = fakeMasterKey(t)
	deps.loadTLSKeyPair = func(_, _ string) (tls.Certificate, error) {
		tlsLoaded++
		return tls.Certificate{}, nil
	}
	deps.openStore = func(_ string) (*controlplane.Store, error) {
		storeOpened++
		return &controlplane.Store{}, nil
	}

	comps, err := prepareControlPlane(cfg, deps)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if comps.tlsCert != nil {
		t.Fatal("trusted-proxy termination must not require or use a TLS certificate")
	}
	if tlsLoaded != 0 || storeOpened != 1 {
		t.Fatalf("expected no TLS load and one store open, got tls=%d store=%d", tlsLoaded, storeOpened)
	}
}

// TestPrepareInvalidMasterKeyZeroSideEffects proves that when the master-key
// file is invalid, NO TLS parse, DB open, or store work happens — only the
// master-key loader ran (a file read that legitimately precedes those steps).
func TestPrepareInvalidMasterKeyZeroSideEffects(t *testing.T) {
	cfg := testCfg(config.ModeProduction, config.TLSTermDirect)
	var tlsLoaded, storeOpened int
	deps := defaultDeps()
	deps.loadMasterKey = func(_ string) (*controlplane.FeedKeyCipher, error) {
		return nil, errInjected
	}
	deps.loadTLSKeyPair = func(_, _ string) (tls.Certificate, error) {
		tlsLoaded++
		return tls.Certificate{}, nil
	}
	deps.openStore = func(_ string) (*controlplane.Store, error) {
		storeOpened++
		return &controlplane.Store{}, nil
	}
	if _, err := prepareControlPlane(cfg, deps); err == nil {
		t.Fatal("expected master-key failure to abort startup")
	}
	if tlsLoaded != 0 || storeOpened != 0 {
		t.Fatalf("invalid master key must cause zero TLS/DB side effects, got tls=%d store=%d", tlsLoaded, storeOpened)
	}
}

// TestPrepareMalformedTLSFilesFailBeforeDB proves that malformed or missing
// TLS files fail before any database side effect (finding 4).
func TestPrepareMalformedTLSFilesFailBeforeDB(t *testing.T) {
	for _, tc := range []string{"missing", "malformed"} {
		t.Run(tc, func(t *testing.T) {
			cfg := testCfg(config.ModeProduction, config.TLSTermDirect)
			var storeOpened int
			deps := defaultDeps()
			deps.loadMasterKey = fakeMasterKey(t)
			deps.loadTLSKeyPair = func(_, _ string) (tls.Certificate, error) {
				return tls.Certificate{}, errInjected
			}
			deps.openStore = func(_ string) (*controlplane.Store, error) {
				storeOpened++
				return &controlplane.Store{}, nil
			}
			if _, err := prepareControlPlane(cfg, deps); err == nil {
				t.Fatal("malformed/missing TLS files must abort startup")
			}
			if storeOpened != 0 {
				t.Fatalf("TLS failure must precede DB open, got store=%d", storeOpened)
			}
		})
	}
}

func TestPrepareInvalidValuesCauseZeroFileDBListenActions(t *testing.T) {
	// A chain of injectable funcs records every file/DB reach call. An invalid
	// value at each stage must prevent every later side effect.
	t.Run("weak session secret", func(t *testing.T) {
		cfg := testCfg(config.ModeProduction, config.TLSTermDirect)
		cfg.SessionSecret = "short"
		masterRun, storeRun := 0, 0
		deps := defaultDeps()
		deps.loadMasterKey = func(_ string) (*controlplane.FeedKeyCipher, error) { masterRun++; return nil, errInjected }
		deps.openStore = func(_ string) (*controlplane.Store, error) { storeRun++; return &controlplane.Store{}, nil }
		if _, err := prepareControlPlane(cfg, deps); err == nil {
			t.Fatal("weak session secret must abort startup")
		}
		if masterRun != 0 || storeRun != 0 {
			t.Fatalf("weak secret caused side effects: master=%d store=%d", masterRun, storeRun)
		}
	})
	t.Run("invalid registry seed", func(t *testing.T) {
		cfg := testCfg(config.ModeProduction, config.TLSTermDirect)
		cfg.RegistryEd25519Key = "zz-not-hex"
		var storeRun int
		deps := defaultDeps()
		deps.loadMasterKey = fakeMasterKey(t)
		deps.openStore = func(_ string) (*controlplane.Store, error) { storeRun++; return &controlplane.Store{}, nil }
		if _, err := prepareControlPlane(cfg, deps); err == nil {
			t.Fatal("invalid registry seed must abort startup")
		}
		if storeRun != 0 {
			t.Fatalf("invalid registry seed caused a DB open: store=%d", storeRun)
		}
	})
}

// errInjected is a sentinel for spy-injected failures.
var errInjected = &injectedError{}

type injectedError struct{}

func (*injectedError) Error() string { return "injected startup failure" }
