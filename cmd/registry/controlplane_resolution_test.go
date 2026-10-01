package main

import (
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
)

// TestBuildRegistryIdentityResolverControlPlane pins the controlplane mode to
// the SAME origin/credential/client the committer and binder use: the resolver
// must carry the control-plane base URL, the shared internal secret, and the
// bounded client, with no new env var of its own.
func TestBuildRegistryIdentityResolverControlPlane(t *testing.T) {
	t.Setenv("REGISTRY_RESOLUTION_MODE", "controlplane")
	t.Setenv("CONTROLPLANE_URL", "")
	t.Setenv("CONTROLPLANE_INTERNAL_SECRET_FILE", "")

	secret := []byte("shared-internal-secret")
	depClient := buildDependencyHTTPClient()
	cpClient := buildDependencyHTTPClient()

	r, err := buildRegistryIdentityResolver(depClient, "https://controlplane.internal:8089", secret, cpClient)
	if err != nil {
		t.Fatalf("build controlplane resolver: %v", err)
	}
	cp, ok := r.(publish.ControlPlaneRegistryIdentityResolver)
	if !ok {
		t.Fatalf("expected publish.ControlPlaneRegistryIdentityResolver, got %T", r)
	}
	if cp.BaseURL != "https://controlplane.internal:8089" {
		t.Fatalf("base URL: got %q", cp.BaseURL)
	}
	if string(cp.Secret) != string(secret) {
		t.Fatalf("secret: got %q", cp.Secret)
	}
	if cp.HTTPClient != cpClient {
		t.Fatal("resolver must carry the bounded control-plane client")
	}
}

// TestRequireRegistryIDsAcceptsControlPlane proves the Bee-mode ID gate accepts
// the dynamic resolver (IDs authoritative from the control plane) while still
// rejecting the static zero-ID case and every other resolver shape.
func TestRequireRegistryIDsAcceptsControlPlane(t *testing.T) {
	cp := &publish.ControlPlaneRegistryIdentityResolver{
		BaseURL: "https://controlplane.internal:8089",
		Secret:  []byte("secret"),
	}
	if err := requireRegistryIDs(cp); err != nil {
		t.Fatalf("controlplane resolver must pass, got %v", err)
	}

	if err := requireRegistryIDs(resolve.ENSRegistryIdentityResolver{}); err == nil {
		t.Fatal("ENS resolver must still be rejected")
	}
	if err := requireRegistryIDs(resolve.RegistryResolver{}); err == nil {
		t.Fatal("unknown resolver shape must be rejected")
	}
}
