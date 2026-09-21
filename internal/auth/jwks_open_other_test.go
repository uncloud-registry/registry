//go:build !darwin && !linux

package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file is compiled only on platforms WITHOUT the secure
// single-descriptor O_NOFOLLOW open (every GOOS except darwin and linux,
// e.g. windows, freebsd, plan9). It cannot be executed on a macOS/Linux
// development host; it is validated by cross-compilation (GOOS=windows
// GOARCH=amd64 go test -c) and, where a runner exists, by execution. The
// static/source pins in jwks_open_static_test.go run everywhere.

// TestOpenJWKSFileFailsClosedNeverStatsThePath proves the unsupported
// implementation never even stats the path: with a NON-existent file a
// Lstat-based implementation would report ENOENT, while fail-closed must
// return the stable sentinel without touching the path.
func TestOpenJWKSFileFailsClosedNeverStatsThePath(t *testing.T) {
	_, err := openJWKSFile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if !errors.Is(err, ErrJWKSFileLoadingUnsupported) {
		t.Fatalf("openJWKSFile must fail closed with ErrJWKSFileLoadingUnsupported; got %v", err)
	}
}

// TestOpenJWKSFileFailsClosedDespiteValidFile proves a perfectly valid keys
// file is still refused: the file must never be opened on unsupported
// platforms, even though it would load fine on macOS/Linux.
func TestOpenJWKSFileFailsClosedDespiteValidFile(t *testing.T) {
	key := newJWKSTestKey(t, "valid-k")
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, jwksDocument(key.jwkJSON), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := openJWKSFile(path)
	if !errors.Is(err, ErrJWKSFileLoadingUnsupported) {
		t.Fatalf("expected ErrJWKSFileLoadingUnsupported, got %v", err)
	}
}

// TestLoadJWKSFromFileFailsClosedOnUnsupportedPlatform proves the whole loader
// path (open → descriptor validation → parse) fails closed, so cmd/registry
// startup (buildAuthenticator → LoadJWKSFromFile) aborts with the sentinel
// wrapped in the loader error instead of silently loading keys.
func TestLoadJWKSFromFileFailsClosedOnUnsupportedPlatform(t *testing.T) {
	key := newJWKSTestKey(t, "load-k")
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, jwksDocument(key.jwkJSON), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadJWKSFromFile(path)
	if !errors.Is(err, ErrJWKSFileLoadingUnsupported) {
		t.Fatalf("LoadJWKSFromFile must propagate ErrJWKSFileLoadingUnsupported; got %v", err)
	}
}

// assertDataFreeUnsupportedError fails the test unless err is the
// ErrJWKSFileLoadingUnsupported sentinel AND its message contains no
// caller-controlled path data: the distinctive supplied path, its directory
// or base name, or any path separator. The unsupported-platform error
// propagates unwrapped to cmd/registry startup (log.Fatal), so no part of the
// operator's REGISTRY_TOKEN_PUBLIC_KEYS_FILE value may ever reach it.
func assertDataFreeUnsupportedError(t *testing.T, err error, suppliedPath string) {
	t.Helper()
	if !errors.Is(err, ErrJWKSFileLoadingUnsupported) {
		t.Fatalf("must fail closed with ErrJWKSFileLoadingUnsupported; got %v", err)
	}
	msg := err.Error()
	for _, probe := range []string{suppliedPath, filepath.Dir(suppliedPath), filepath.Base(suppliedPath), "/", `\`} {
		if strings.Contains(msg, probe) {
			t.Fatalf("unsupported-platform error must be data-free (no supplied path, no separators); probe %q found in %q", probe, msg)
		}
	}
}

// TestOpenJWKSFileErrorCarriesNoPathData asserts the ACTUAL error returned by
// openJWKSFile on an unsupported platform: probe names are distinctive enough
// that any echo of the supplied path, its directory, its base name, or a path
// separator can only have come from the error constructing with the path.
func TestOpenJWKSFileErrorCarriesNoPathData(t *testing.T) {
	distinctive := filepath.Join(t.TempDir(), "jwks-datafree-probe-9f17b2", "distinctive-keys-3c8d4e.json")
	_, err := openJWKSFile(distinctive)
	assertDataFreeUnsupportedError(t, err, distinctive)
}

// TestLoadJWKSFromFileErrorCarriesNoPathData asserts the ACTUAL error
// propagated by LoadJWKSFromFile on an unsupported platform is data-free:
// even with a perfectly valid keys file at a distinctive path, the path must
// not appear anywhere in the propagated error (the one that reaches
// cmd/registry startup).
func TestLoadJWKSFromFileErrorCarriesNoPathData(t *testing.T) {
	key := newJWKSTestKey(t, "load-leak-k")
	distinctive := filepath.Join(t.TempDir(), "jwks-datafree-probe-9f17b2", "distinctive-keys-3c8d4e.json")
	if err := os.MkdirAll(filepath.Dir(distinctive), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(distinctive, jwksDocument(key.jwkJSON), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadJWKSFromFile(distinctive)
	assertDataFreeUnsupportedError(t, err, distinctive)
}

// TestErrJWKSFileLoadingUnsupportedIsDataFree pins that the sentinel message
// carries no path and no key material — a stable, data-free category that
// errors.Is can match anywhere in the process.
func TestErrJWKSFileLoadingUnsupportedIsDataFree(t *testing.T) {
	msg := ErrJWKSFileLoadingUnsupported.Error()
	if strings.Contains(msg, "/") || strings.Contains(msg, "\\") || strings.Contains(msg, "keys.json") {
		t.Fatalf("sentinel must be data-free (no path, no key material): %q", msg)
	}
}
