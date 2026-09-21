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

// TestErrJWKSFileLoadingUnsupportedIsDataFree pins that the sentinel message
// carries no path and no key material — a stable, data-free category that
// errors.Is can match anywhere in the process.
func TestErrJWKSFileLoadingUnsupportedIsDataFree(t *testing.T) {
	msg := ErrJWKSFileLoadingUnsupported.Error()
	if strings.Contains(msg, "/") || strings.Contains(msg, "\\") || strings.Contains(msg, "keys.json") {
		t.Fatalf("sentinel must be data-free (no path, no key material): %q", msg)
	}
}
