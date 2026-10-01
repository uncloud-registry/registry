//go:build !darwin && !linux

package controlplane

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
// static/source pins in masterkey_open_static_test.go run everywhere.

// TestOpenMasterKeyFileFailsClosedNeverStatsThePath proves the unsupported
// implementation never even stats the path: with a NON-existent file a
// Lstat-based implementation would report ENOENT, while fail-closed must
// return the stable sentinel without touching the path.
func TestOpenMasterKeyFileFailsClosedNeverStatsThePath(t *testing.T) {
	_, err := openMasterKeyFile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if !errors.Is(err, ErrMasterKeyFileLoadingUnsupported) {
		t.Fatalf("openMasterKeyFile must fail closed with ErrMasterKeyFileLoadingUnsupported; got %v", err)
	}
}

// TestOpenMasterKeyFileFailsClosedDespiteValidFile proves a perfectly valid
// master key file is still refused: the file must never be opened on
// unsupported platforms, even though it would load fine on macOS/Linux.
func TestOpenMasterKeyFileFailsClosedDespiteValidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(masterKeyDocument("1", map[string]string{"1": testMasterKeyB64(1)})), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := openMasterKeyFile(path)
	if !errors.Is(err, ErrMasterKeyFileLoadingUnsupported) {
		t.Fatalf("expected ErrMasterKeyFileLoadingUnsupported, got %v", err)
	}
}

// TestLoadMasterKeyFileFailsClosedOnUnsupportedPlatform proves the whole
// loader path (open → descriptor validation → parse) fails closed, so
// cmd/controlplane startup (LoadMasterKeyFile) aborts with the sentinel
// instead of silently loading keys.
func TestLoadMasterKeyFileFailsClosedOnUnsupportedPlatform(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(masterKeyDocument("1", map[string]string{"1": testMasterKeyB64(1)})), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadMasterKeyFile(path)
	if !errors.Is(err, ErrMasterKeyFileLoadingUnsupported) {
		t.Fatalf("LoadMasterKeyFile must propagate ErrMasterKeyFileLoadingUnsupported; got %v", err)
	}
}

// assertDataFreeMasterKeyError fails the test unless err is the
// ErrMasterKeyFileLoadingUnsupported sentinel AND its message contains no
// caller-controlled path data: the distinctive supplied path, its directory
// or base name, or any path separator. The unsupported-platform error
// propagates unwrapped to cmd/controlplane startup (log.Fatal), so no part of
// the operator's CONTROLPLANE_MASTER_KEY_FILE value may ever reach it.
func assertDataFreeMasterKeyError(t *testing.T, err error, suppliedPath string) {
	t.Helper()
	if !errors.Is(err, ErrMasterKeyFileLoadingUnsupported) {
		t.Fatalf("must fail closed with ErrMasterKeyFileLoadingUnsupported; got %v", err)
	}
	msg := err.Error()
	for _, probe := range []string{suppliedPath, filepath.Dir(suppliedPath), filepath.Base(suppliedPath), "/", `\`} {
		if strings.Contains(msg, probe) {
			t.Fatalf("unsupported-platform error must be data-free (no supplied path, no separators); probe %q found in %q", probe, msg)
		}
	}
}

// TestOpenMasterKeyFileErrorCarriesNoPathData asserts the ACTUAL error
// returned by openMasterKeyFile on an unsupported platform: probe names are
// distinctive enough that any echo of the supplied path, its directory, its
// base name, or a path separator can only have come from the error
// constructing with the path.
func TestOpenMasterKeyFileErrorCarriesNoPathData(t *testing.T) {
	distinctive := filepath.Join(t.TempDir(), "master-datafree-probe-9f17b2", "distinctive-keys-3c8d4e.json")
	_, err := openMasterKeyFile(distinctive)
	assertDataFreeMasterKeyError(t, err, distinctive)
}

// TestLoadMasterKeyFileErrorCarriesNoPathData asserts the ACTUAL error
// propagated by LoadMasterKeyFile on an unsupported platform is data-free:
// even with a perfectly valid master key file at a distinctive path, the path
// must not appear anywhere in the propagated error (the one that reaches
// cmd/controlplane startup).
func TestLoadMasterKeyFileErrorCarriesNoPathData(t *testing.T) {
	distinctive := filepath.Join(t.TempDir(), "master-datafree-probe-9f17b2", "distinctive-keys-3c8d4e.json")
	if err := os.MkdirAll(filepath.Dir(distinctive), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(distinctive, []byte(masterKeyDocument("1", map[string]string{"1": testMasterKeyB64(1)})), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadMasterKeyFile(distinctive)
	assertDataFreeMasterKeyError(t, err, distinctive)
}

// TestErrMasterKeyFileLoadingUnsupportedIsDataFree pins that the sentinel
// message carries no path and no key material — a stable, data-free category
// that errors.Is can match anywhere in the process.
func TestErrMasterKeyFileLoadingUnsupportedIsDataFree(t *testing.T) {
	msg := ErrMasterKeyFileLoadingUnsupported.Error()
	if strings.Contains(msg, "/") || strings.Contains(msg, `\`) || strings.Contains(msg, "keys.json") {
		t.Fatalf("sentinel must be data-free (no path, no key material): %q", msg)
	}
}
