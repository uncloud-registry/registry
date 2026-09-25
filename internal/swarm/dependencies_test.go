package swarm_test

// Architectural guard restored by the Task16 finalization cleanup: the swarm
// package is INFRASTRUCTURE below the registry domain, so it must never import
// the registry package (directly or via a registry subpackage). The uploader
// failure contract (resolve.ErrUploaderPreSideEffect) lives in the shared
// lower-level resolve package that both swarm and registry already depend on,
// so no swarm->registry edge is needed. This test STATICALLY parses the swarm
// package's import list and fails if a registry import regresses. On the
// pre-cleanup HEAD this test FAILS (swarm imported registry solely for the
// sentinel); after the cleanup it passes.

import (
	"go/build"
	"strings"
	"testing"
)

const registryImportPrefix = "github.com/uncloud-registry/registry/internal/registry"

// TestSwarmDoesNotImportRegistry asserts the swarm package (non-test source)
// carries no import of the registry domain package. Infrastructure must depend
// downward on neutral contracts, never upward on the domain handler.
func TestSwarmDoesNotImportRegistry(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("load swarm package: %v", err)
	}
	for _, imp := range pkg.Imports {
		if imp == registryImportPrefix || strings.HasPrefix(imp, registryImportPrefix+"/") {
			t.Fatalf("swarm must not import the registry package (%q): infrastructure cannot depend upward on the domain", imp)
		}
	}
}
