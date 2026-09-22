package credential

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempSecret(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "internal-secret")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	return path
}

func TestLoadSecretFileRoundTrip(t *testing.T) {
	secret := "0123456789abcdefghijABCDEFGHGIJ!@#$%"
	path := writeTempSecret(t, secret, 0o600)
	got, err := LoadSecretFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != secret {
		t.Fatalf("secret changed: got %q want %q", got, secret)
	}
}

func TestLoadSecretFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("0123456789abcdefghijklmnopqrstuv"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadSecretFile(link); err == nil {
		t.Fatal("expected symlink secret file to be rejected")
	}
}

func TestLoadSecretFileMissingOrDirectory(t *testing.T) {
	if _, err := LoadSecretFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected missing file to error")
	}
	if _, err := LoadSecretFile(t.TempDir()); err == nil {
		t.Fatal("expected directory to error")
	}
}

func TestValidateSecretRejectsEmptyAndShort(t *testing.T) {
	if err := ValidateSecret(nil); err == nil {
		t.Fatal("expected empty secret to be rejected")
	}
	if err := ValidateSecret([]byte("short")); err == nil {
		t.Fatal("expected short secret to be rejected")
	}
	if err := ValidateSecret([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatalf("expected a strong secret to validate, got %v", err)
	}
}

func TestLoadSecretFileRejectsOversized(t *testing.T) {
	// The loader requires a single-bounded read; a path to a huge file is
	// rejected as exceeding the bound.
	path := writeTempSecret(t, string(make([]byte, 1<<20+1)), 0o600)
	if _, err := LoadSecretFile(path); err == nil {
		t.Fatal("expected oversized secret file to be rejected")
	}
}
