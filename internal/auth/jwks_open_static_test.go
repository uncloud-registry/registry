package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// jwksSourcePath returns the absolute path of a sibling source file. Production
// build-tagged files (jwks_open_unix.go / jwks_open_other.go) are selected by
// GOOS, so tests that must pin their content cannot rely on runtime behavior
// across platforms — a static/source pin is the honest RED/GREEN gate.
func jwksSourcePath(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	return filepath.Join(filepath.Dir(thisFile), name)
}

// TestOpenJWKSFileOtherSourceHasNoRacyPathUse pins, at source level, that the
// unsupported-platform implementation never opens, Lstats, or reads the keys
// path. GOOS-tagged files cannot be EXECUTED on every platform, so absence of
// the racy Lstat-then-open path is proven structurally: the file may only
// return the fail-closed sentinel, never touch the path.
func TestOpenJWKSFileOtherSourceHasNoRacyPathUse(t *testing.T) {
	src, err := os.ReadFile(jwksSourcePath(t, "jwks_open_other.go"))
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	s := string(src)
	// These tokens would each reintroduce a path-based open/stat/read on the
	// unsupported platform and must never appear in the fail-closed file.
	for _, token := range []string{"os.Open", "os.Lstat", "os.ReadFile", "syscall.Open", "syscall.Openat", "syscall.Openat2"} {
		if strings.Contains(s, token) {
			t.Errorf("jwks_open_other.go must fail closed without opening, statting, or reading the path; found %q", token)
		}
	}
	// The fail-closed rule itself must be present: the stable sentinel error.
	if !strings.Contains(s, "ErrJWKSFileLoadingUnsupported") {
		t.Error("jwks_open_other.go must return ErrJWKSFileLoadingUnsupported on unsupported platforms")
	}
}

// TestOpenJWKSFileUnixSourceKeepsSecureSingleDescriptorOpen pins that the
// darwin/linux implementation remains the single-descriptor O_NOFOLLOW open:
// no path re-open, no Lstat-then-open, and the O_NOFOLLOW|O_NONBLOCK flags
// that close the symlink TOCTOU and prevent blocking on special files.
func TestOpenJWKSFileUnixSourceKeepsSecureSingleDescriptorOpen(t *testing.T) {
	src, err := os.ReadFile(jwksSourcePath(t, "jwks_open_unix.go"))
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	s := string(src)
	for _, token := range []string{"syscall.Open", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"} {
		if !strings.Contains(s, token) {
			t.Errorf("jwks_open_unix.go must keep the single-descriptor open with %s", token)
		}
	}
	for _, token := range []string{"os.Open", "os.Lstat", "os.ReadFile"} {
		if strings.Contains(s, token) {
			t.Errorf("jwks_open_unix.go must not reopen or re-stat the path; found %q", token)
		}
	}
}
