package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/uncloud-registry/registry/internal/resolve"
)

// writeSecretFile writes a strong-enough internal credential to a scratch file.
func writeSecretFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "internal-secret")
	if err := os.WriteFile(path, []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEF"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	return path
}

// beeAuthEnv configures the minimal authenticator config used by buildBeeHandler.
func beeAuthEnv(t *testing.T) {
	t.Helper()
	key := newConfigTestKey(t)
	t.Setenv("REGISTRY_TOKEN_PUBLIC_KEYS_FILE", writeConfigJWKS(t, key))
	t.Setenv("REGISTRY_TOKEN_ISSUER", configIssuer)
	t.Setenv("REGISTRY_TOKEN_AUDIENCE", configAudience)
}

// TestBeeRegistryCannotSignLocally proves the Bee-mode registry path can ONLY
// commit repository-state feeds through the control plane: BEE_FEED_SIGNER_PRIVATE_KEY
// is no longer sufficient (or read), and the control-plane URL + the shared
// internal credential are mandatory. It fails closed before building a handler.
func TestBeeRegistryCannotSignLocally(t *testing.T) {
	t.Setenv("REGISTRY_BACKEND", "bee")
	t.Setenv("BEE_API_URL", "http://bee.test")
	t.Setenv("REGISTRY_OWNER_MAP", "registry.test=0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef")
	t.Setenv("REGISTRY_ID_MAP", "registry.test=7")
	beeAuthEnv(t)

	// Even with a feed-owner signing key present, the Bee path MUST NOT use it:
	// without the control-plane URL the handler fails closed.
	t.Setenv("BEE_FEED_SIGNER_PRIVATE_KEY", "deadbeefdeadbeefdeadbeefdeadbeef")
	t.Setenv("CONTROLPLANE_URL", "")
	t.Setenv("CONTROLPLANE_INTERNAL_SECRET_FILE", "")
	if _, err := buildBeeHandler(); err == nil {
		t.Fatal("expected Bee handler to fail closed without CONTROLPLANE_URL")
	}

	// With the URL but no shared secret file, it still fails closed.
	t.Setenv("CONTROLPLANE_URL", "http://controlplane.internal:8080")
	if _, err := buildBeeHandler(); err == nil {
		t.Fatal("expected Bee handler to fail closed without CONTROLPLANE_INTERNAL_SECRET_FILE")
	}

	// With the secret but no REGISTRY_ID_MAP, it fails closed (no unambiguous
	// host→RegistryID mapping for routing commits).
	t.Setenv("CONTROLPLANE_INTERNAL_SECRET_FILE", writeSecretFile(t))
	t.Setenv("REGISTRY_ID_MAP", "")
	if _, err := buildBeeHandler(); err == nil {
		t.Fatal("expected Bee handler to fail closed without REGISTRY_ID_MAP")
	}

	// Fully configured, the handler builds WITHOUT a feed-owner signing key:
	// the control plane signs; the registry never holds a key.
	t.Setenv("REGISTRY_ID_MAP", "registry.test=7")
	h, err := buildBeeHandler()
	if err != nil {
		t.Fatalf("fully configured Bee handler must build: %v", err)
	}
	if h == nil {
		t.Fatal("expected a non-nil handler")
	}
}

// TestRequireRegistryIDsFailClosed covers the resolver-side ID gate that routes
// Bee-mode feed commits by an unambiguous control-plane RegistryID.
func TestRequireRegistryIDsFailClosed(t *testing.T) {
	// A static resolver with a missing/zero ID is rejected.
	if err := requireRegistryIDs(resolve.StaticRegistryIdentityResolver{Hosts: map[string]resolve.RegistryIdentity{
		"a.test": {Host: "a.test", Owner: "0xaaa", RegistryID: 0},
	}}); err == nil {
		t.Fatal("expected missing registryID to fail closed")
	}
	// A non-static resolver (ENS) is rejected: it yields a feed-owner, never a
	// control-plane RegistryID.
	if err := requireRegistryIDs(resolve.RegistryResolver{}); err == nil {
		t.Fatal("expected non-static resolution to fail closed")
	}
	// A fully-mapped multi-host resolver passes.
	if err := requireRegistryIDs(resolve.StaticRegistryIdentityResolver{Hosts: map[string]resolve.RegistryIdentity{
		"a.test": {Host: "a.test", Owner: "0xaaa", RegistryID: 1},
		"b.test": {Host: "b.test", Owner: "0xbbb", RegistryID: 2},
	}}); err != nil {
		t.Fatalf("expected fully-mapped multi-host resolver to pass, got %v", err)
	}
}
