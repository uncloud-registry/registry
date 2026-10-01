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

// strongSecret is a 32+ byte high-diversity value: multiple byte classes, no
// repeated period, no monotonic run, and not a known weak literal.
const strongSecret = "Kl9xQ2mP7vL0nB4rT8yW1uZ5cE3gH6jM"

func TestLoadSecretFileRoundTripPreservesBytes(t *testing.T) {
	path := writeTempSecret(t, strongSecret, 0o600)
	got, err := LoadSecretFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != strongSecret {
		t.Fatalf("secret changed: got %q want %q", got, strongSecret)
	}
}

func TestLoadSecretFileStripsSingleTerminalLFOnly(t *testing.T) {
	path := writeTempSecret(t, strongSecret+"\n", 0o600)
	got, err := LoadSecretFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != strongSecret {
		t.Fatalf("expected exactly one terminal LF removed, got %q", got)
	}
}

func TestLoadSecretFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte(strongSecret), 0o600); err != nil {
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

func TestLoadSecretFileRejectsGroupWorldPermissions(t *testing.T) {
	for _, perm := range []os.FileMode{0o644, 0o640, 0o664, 0o666, 0o600} {
		path := writeTempSecret(t, strongSecret, perm)
		_, err := LoadSecretFile(path)
		if perm == 0o600 {
			if err != nil {
				t.Fatalf("owner-only 0600 must be accepted, got %v", err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("expected perm %#o to be rejected (group/world bits set)", perm)
		}
	}
}

func TestLoadSecretFileRejectsOversized(t *testing.T) {
	path := writeTempSecret(t, string(make([]byte, 1<<20+1)), 0o600)
	if _, err := LoadSecretFile(path); err == nil {
		t.Fatal("expected oversized secret file to be rejected")
	}
}

func TestLoadSecretFileRejectsBadFormats(t *testing.T) {
	cases := map[string]string{
		"crlf":                strongSecret + "\r\n",
		"multiple-newlines":   strongSecret + "\n\n",
		"nonterminal-newline": strongSecret + "\nX",
		"leading-space":       " " + strongSecret,
		"trailing-space":      strongSecret + " ",
		"leading-tab":         "\t" + strongSecret,
		"trailing-tab":        strongSecret + "\t",
		"empty":               "",
		"blank-newline":       "\n",
	}
	for name, content := range cases {
		path := writeTempSecret(t, content, 0o600)
		if _, err := LoadSecretFile(path); err == nil {
			t.Fatalf("expected %q format to be rejected", name)
		}
	}
	// Interior whitespace is legitimate secret material and MUST be preserved.
	interior := "two words and 12345 ABC!?"
	path := writeTempSecret(t, interior, 0o600)
	got, err := LoadSecretFile(path)
	if err != nil {
		t.Fatalf("interior-space secret rejected: %v", err)
	}
	if string(got) != interior {
		t.Fatalf("interior-space secret changed: %q want %q", got, interior)
	}
}

func TestValidateSecretLengthAndQuality(t *testing.T) {
	if err := ValidateSecret(nil); err == nil {
		t.Fatal("expected empty secret to be rejected")
	}
	if err := ValidateSecret([]byte("short")); err == nil {
		t.Fatal("expected short secret to be rejected")
	}
	// 32 bytes of <16 distinct values, even with a terminal quality, is weak.
	if err := ValidateSecret([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); err == nil {
		t.Fatal("expected low-diversity secret to be rejected")
	}
	// 32+ bytes but a strong secret validates.
	if err := ValidateSecret([]byte(strongSecret)); err != nil {
		t.Fatalf("expected strong secret to validate, got %v", err)
	}
}

func TestValidateSecretRejectsPredictable(t *testing.T) {
	weak := []string{
		"0123456789abcdef0123456789abcdef", // exact repeated period 16
		"abcdabcdabcdabcdabcdabcdabcdabcd", // exact repeated period 4
		"abcdefghijklmnopqrstuvwxyz012345", // monotonic increasing
		"passwordpasswordpasswordpassword", // known weak literal
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // single class, low diversity
	}
	for _, s := range weak {
		if err := ValidateSecret([]byte(s)); err == nil {
			t.Fatalf("expected %q to be rejected as a predictable secret", s)
		}
	}
}

func TestValidateSecretDoesNotMutateInput(t *testing.T) {
	orig := []byte(strongSecret)
	cp := append([]byte(nil), orig...)
	if err := ValidateSecret(orig); err != nil {
		t.Fatalf("validate: %v", err)
	}
	for i := range orig {
		if orig[i] != cp[i] {
			t.Fatal("ValidateSecret must not mutate the accepted secret bytes")
		}
	}
}
