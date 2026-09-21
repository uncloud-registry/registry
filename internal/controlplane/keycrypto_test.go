package controlplane

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// testMasterKeyBytes returns a deterministic 32-byte master key whose bytes
// differ per seed so version 1 and version 2 keys are never identical.
func testMasterKeyBytes(seed byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

// testMasterKeyB64 returns the canonical unpadded base64url form of
// testMasterKeyBytes(seed).
func testMasterKeyB64(seed byte) string {
	return base64.RawURLEncoding.EncodeToString(testMasterKeyBytes(seed))
}

// newTestFeedKeyCipher builds a cipher with versions 1 and 2 loaded and
// version 1 current — the shape every rotation test needs.
func newTestFeedKeyCipher(t *testing.T) *FeedKeyCipher {
	t.Helper()
	c, err := NewFeedKeyCipher(map[int][]byte{
		1: testMasterKeyBytes(1),
		2: testMasterKeyBytes(2),
	}, 1)
	if err != nil {
		t.Fatalf("new test feed key cipher: %v", err)
	}
	return c
}

// masterKeyDocument builds a master-key file document from a literal current
// field and a literal keys map. current is written verbatim so tests can
// exercise non-canonical numbers ("1.0", "1e0", "-1", "01" via literal text).
func masterKeyDocument(current string, keys map[string]string) string {
	var buf strings.Builder
	buf.WriteString(`{"current":`)
	buf.WriteString(current)
	buf.WriteString(`,"keys":{`)
	i := 0
	for k, v := range keys {
		if i > 0 {
			buf.WriteString(",")
		}
		fmt.Fprintf(&buf, "%q:%q", k, v)
		i++
	}
	buf.WriteString(`}}`)
	return buf.String()
}

// writeMasterKeyFile writes content to a fresh 0600 file in a temp dir.
func writeMasterKeyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master-key.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write master key file: %v", err)
	}
	return path
}

func TestFeedKeyCipherRoundTrip(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	plaintext := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	enc, err := c.Encrypt(42, "0xfeed", plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc.KeyVersion != 1 {
		t.Fatalf("expected current version 1, got %d", enc.KeyVersion)
	}
	if len(enc.Nonce) == 0 || len(enc.Ciphertext) == 0 {
		t.Fatal("encrypted feed key must carry nonce and ciphertext")
	}
	got, err := c.Decrypt(42, "0xfeed", enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestFeedKeyCipherGeneratesRandomNonces(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	first, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatalf("encrypt once: %v", err)
	}
	second, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatalf("encrypt twice: %v", err)
	}
	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatal("nonces must be unique per encryption")
	}
	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatal("ciphertexts must differ across encryptions (fresh nonce)")
	}
}

func TestFeedKeyCipherRejectsTampering(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	enc, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	enc.Ciphertext[0] ^= 0xff
	if _, err := c.Decrypt(1, "0xfeed", enc); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("got %v", err)
	}
}

func TestFeedKeyCipherRejectsTamperedNonceAndEmptyCiphertext(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	enc, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	enc.Nonce[0] ^= 0xff
	if _, err := c.Decrypt(1, "0xfeed", enc); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("nonce tampering: got %v", err)
	}

	enc2, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	enc2.Ciphertext = nil
	if _, err := c.Decrypt(1, "0xfeed", enc2); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("missing ciphertext: got %v", err)
	}
}

func TestFeedKeyCipherRejectsWrongMasterKey(t *testing.T) {
	t.Parallel()
	encCipher, err := NewFeedKeyCipher(map[int][]byte{1: testMasterKeyBytes(1)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	decCipher, err := NewFeedKeyCipher(map[int][]byte{1: testMasterKeyBytes(9)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encCipher.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decCipher.Decrypt(1, "0xfeed", enc); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("wrong master key must fail authentication: got %v", err)
	}
}

func TestFeedKeyCipherRejectsUnsupportedVersion(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	// Only versions 1 and 2 are loaded.
	if _, err := c.EncryptWith(99, 1, "0xfeed", []byte("private-key")); !errors.Is(err, ErrFeedKeyVersionUnloaded) {
		t.Fatalf("encrypt with unloaded version: got %v", err)
	}
	enc, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	enc.KeyVersion = 99
	if _, err := c.Decrypt(1, "0xfeed", enc); !errors.Is(err, ErrFeedKeyVersionUnloaded) {
		t.Fatalf("decrypt with unloaded version: got %v", err)
	}
}

// TestFeedKeyCipherRejectsAADSubstitution pins the at-rest boundary: an
// encrypted feed key is bound to its own registry ID and literal owner
// address. Swapping either context must fail authentication, so a row stolen
// from another registry or owner can never be decrypted with the wrong
// context and a row cannot be silently moved between registries.
func TestFeedKeyCipherRejectsAADSubstitution(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	enc, err := c.Encrypt(7, "0xfeed0001", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}

	// Cross-registry: different registry ID, same owner.
	if _, err := c.Decrypt(8, "0xfeed0001", enc); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("cross-registry substitution: got %v", err)
	}
	// Cross-owner: same registry, different literal owner.
	if _, err := c.Decrypt(7, "0xfeed0002", enc); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("cross-owner substitution: got %v", err)
	}
	// Owner AND registry swapped.
	if _, err := c.Decrypt(8, "0xfeed0002", enc); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("cross-registry-and-owner substitution: got %v", err)
	}
	// Owner case change: the owner context is the LITERAL stored bytes; a
	// case-mutated address must not authenticate (the store always persists
	// the canonical lowercase address, so no legitimate caller changes case).
	if _, err := c.Decrypt(7, "0xFEED0001", enc); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("owner-case substitution: got %v", err)
	}
	// The true context must still decrypt.
	if _, err := c.Decrypt(7, "0xfeed0001", enc); err != nil {
		t.Fatalf("true context must decrypt: %v", err)
	}
}

func TestFeedKeyCipherRejectsEmptyContext(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	if _, err := c.Encrypt(1, "", []byte("private-key")); err == nil {
		t.Fatal("encrypt with empty owner must fail")
	}
	enc, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(1, "", enc); err == nil {
		t.Fatal("decrypt with empty owner must fail")
	}
}

func TestFeedKeyCipherEmptyPlaintextRoundTrip(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	enc, err := c.Encrypt(1, "0xfeed", []byte{})
	if err != nil {
		t.Fatalf("encrypt empty plaintext: %v", err)
	}
	got, err := c.Decrypt(1, "0xfeed", enc)
	if err != nil {
		t.Fatalf("decrypt empty plaintext: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext back, got %q", got)
	}
	// Tampering with an empty-plaintext ciphertext must still fail.
	enc.Ciphertext[0] ^= 0xff
	if _, err := c.Decrypt(1, "0xfeed", enc); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("tampered empty-plaintext ciphertext: got %v", err)
	}
}

// TestFeedKeyCipherEncryptWithTargetVersion pins that encryption can target an
// explicit loaded version (used by rotation) independent of `current`.
func TestFeedKeyCipherEncryptWithTargetVersion(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	enc, err := c.EncryptWith(2, 1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	if enc.KeyVersion != 2 {
		t.Fatalf("expected version 2, got %d", enc.KeyVersion)
	}
	got, err := c.Decrypt(1, "0xfeed", enc)
	if err != nil {
		t.Fatalf("decrypt version-2 ciphertext: %v", err)
	}
	if string(got) != "private-key" {
		t.Fatalf("round trip mismatch: %q", got)
	}
	if c.CurrentVersion() != 1 {
		t.Fatalf("current version must stay 1, got %d", c.CurrentVersion())
	}
	if !c.HasVersion(1) || !c.HasVersion(2) || c.HasVersion(99) {
		t.Fatal("HasVersion must reflect exactly the loaded versions")
	}
}

func TestNewFeedKeyCipherValidation(t *testing.T) {
	t.Parallel()
	good := map[int][]byte{1: testMasterKeyBytes(1)}
	if _, err := NewFeedKeyCipher(good, 1); err != nil {
		t.Fatalf("valid cipher: %v", err)
	}
	cases := []struct {
		name    string
		keys    map[int][]byte
		current int
	}{
		{"nil keys", nil, 1},
		{"empty keys", map[int][]byte{}, 1},
		{"current zero", good, 0},
		{"current negative", good, -1},
		{"current missing from keys", good, 2},
		{"key wrong length", map[int][]byte{1: make([]byte, 31)}, 1},
		{"key too long", map[int][]byte{1: make([]byte, 33)}, 1},
	}
	for _, tc := range cases {
		if _, err := NewFeedKeyCipher(tc.keys, tc.current); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestLoadMasterKeyFileValidDocument(t *testing.T) {
	t.Parallel()
	path := writeMasterKeyFile(t, masterKeyDocument("1", map[string]string{"1": testMasterKeyB64(1)}))
	c, err := LoadMasterKeyFile(path)
	if err != nil {
		t.Fatalf("load valid master key: %v", err)
	}
	if c.CurrentVersion() != 1 {
		t.Fatalf("expected current 1, got %d", c.CurrentVersion())
	}
	enc, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc.KeyVersion != 1 {
		t.Fatalf("expected version 1, got %d", enc.KeyVersion)
	}
	if _, err := c.Decrypt(1, "0xfeed", enc); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
}

// TestLoadMasterKeyFileSupportsRotation pins the versioned-file contract that
// rotation depends on: multiple versions stay loadable while `current` selects
// the default encryption version, and previously-encrypted rows (KeyVersion 1)
// remain decryptable after the file advances to current 2.
func TestLoadMasterKeyFileSupportsRotation(t *testing.T) {
	t.Parallel()
	path := writeMasterKeyFile(t, masterKeyDocument("2", map[string]string{
		"1": testMasterKeyB64(1),
		"2": testMasterKeyB64(2),
	}))
	c, err := LoadMasterKeyFile(path)
	if err != nil {
		t.Fatalf("load rotation master key: %v", err)
	}
	if c.CurrentVersion() != 2 {
		t.Fatalf("expected current 2, got %d", c.CurrentVersion())
	}
	// New ciphertext is produced with the current (2) version.
	enc, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	if enc.KeyVersion != 2 {
		t.Fatalf("expected version 2, got %d", enc.KeyVersion)
	}
	// Old v1 ciphertext (as produced by the previous file) still decrypts.
	oldCipher, err := NewFeedKeyCipher(map[int][]byte{1: testMasterKeyBytes(1)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	oldEnc, err := oldCipher.Encrypt(1, "0xfeed", []byte("old-key"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Decrypt(1, "0xfeed", oldEnc)
	if err != nil {
		t.Fatalf("old ciphertext must decrypt under the rotated file: %v", err)
	}
	if string(got) != "old-key" {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestLoadMasterKeyFileAcceptsWhitespaceInJSONLayoutOnly(t *testing.T) {
	t.Parallel()
	// Object-layout whitespace is JSON and must be accepted; only VALUES
	// (version strings, encodings) are strict.
	pretty := "{\n  \"current\": 1,\n  \"keys\": { \"1\": \"" + testMasterKeyB64(1) + "\" }\n}\n"
	path := writeMasterKeyFile(t, pretty)
	if _, err := LoadMasterKeyFile(path); err != nil {
		t.Fatalf("pretty-printed document must load: %v", err)
	}
}

// TestLoadMasterKeyFileRejectsMalformedDocuments covers the strict wire
// format: explicit integer current, canonical positive decimal version keys,
// strict unpadded base64url 32-byte values, no duplicates, no unknown
// members, no trailing data, no empty documents.
func TestLoadMasterKeyFileRejectsMalformedDocuments(t *testing.T) {
	t.Parallel()
	valid := testMasterKeyB64(1)
	valid2 := testMasterKeyB64(2)
	tooLong := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 33))
	tooShort := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 31))
	padded := base64.StdEncoding.EncodeToString(testMasterKeyBytes(1)) // '=' padding
	// 32 zero bytes encode to 'A'*43 — the canonical form; a non-canonical
	// variant flips pad bits by replacing the last char while decoding to the
	// same bytes.
	zeroB64 := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	nonCanonical := zeroB64[:len(zeroB64)-1] + "B"

	bigDoc := masterKeyDocument("99999999999999999999999999", map[string]string{"1": valid}) // version overflow

	cases := []struct {
		name string
		doc  string
	}{
		{"empty document", ""},
		{"null document", "null"},
		{"array document", "[]"},
		{"scalar document", "42"},
		{"missing current", `{"keys":{"1":"` + valid + `"}}`},
		{"missing keys", `{"current":1}`},
		{"empty keys object", `{"current":1,"keys":{}}`},
		{"current string", `{"current":"1","keys":{"1":"` + valid + `"}}`},
		{"current float", masterKeyDocument("1.0", map[string]string{"1": valid})},
		{"current exponent", masterKeyDocument("1e0", map[string]string{"1": valid})},
		{"current negative", masterKeyDocument("-1", map[string]string{"1": valid})},
		{"current zero", masterKeyDocument("0", map[string]string{"1": valid})},
		{"current not a loaded key", masterKeyDocument("2", map[string]string{"1": valid})},
		{"current not a loaded key, other exists", `{"current":3,"keys":{"1":"` + valid + `","2":"` + valid2 + `"}}`},
		{"non-canonical version leading zero", `{"current":1,"keys":{"01":"` + valid + `"}}`},
		{"non-canonical version zero", `{"current":1,"keys":{"0":"` + valid + `"}}`},
		{"non-canonical version negative", `{"current":1,"keys":{"-1":"` + valid + `"}}`},
		{"non-canonical version plus", `{"current":1,"keys":{"+1":"` + valid + `"}}`},
		{"non-canonical version float", `{"current":1,"keys":{"1.0":"` + valid + `"}}`},
		{"non-canonical version leading space", `{"current":1,"keys":{" 1":"` + valid + `"}}`},
		{"non-canonical version trailing space", `{"current":1,"keys":{"1 ":"` + valid + `"}}`},
		{"non-canonical version tab", "{\"current\":1,\"keys\":{\"\t1\":\"" + valid + "\"}}"},
		{"non-numeric version", `{"current":1,"keys":{"abc":"` + valid + `"}}`},
		{"version overflow", bigDoc},
		{"value too short", `{"current":1,"keys":{"1":"` + tooShort + `"}}`},
		{"value too long", `{"current":1,"keys":{"1":"` + tooLong + `"}}`},
		{"value padded", `{"current":1,"keys":{"1":"` + padded + `"}}`},
		{"value invalid base64", `{"current":1,"keys":{"1":"not-base64!!"}}`},
		{"value non-canonical pad bits", `{"current":1,"keys":{"1":"` + nonCanonical + `"}}`},
		{"value not a string", `{"current":1,"keys":{"1":123}}`},
		{"duplicate current", `{"current":1,"current":1,"keys":{"1":"` + valid + `"}}`},
		{"duplicate version key", `{"current":1,"keys":{"1":"` + valid + `","1":"` + valid + `"}}`},
		{"duplicate keys member", `{"current":1,"keys":{"1":"` + valid + `"},"keys":{"1":"` + valid + `"}}`},
		{"unknown top-level member", `{"current":1,"keys":{"1":"` + valid + `"},"extra":1}`},
		{"trailing data", masterKeyDocument("1", map[string]string{"1": valid}) + ` garbage`},
	}

	tokenRe := regexp.MustCompile(`[A-Za-z0-9_-]{16,}`)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeMasterKeyFile(t, tc.doc)
			_, err := LoadMasterKeyFile(path)
			if err == nil {
				t.Fatalf("expected %q to be rejected", tc.doc)
			}
			// No key/path material in errors: neither the base64 key values
			// embedded in the document nor the supplied path may appear.
			for _, probe := range append(tokenRe.FindAllString(tc.doc, -1), path) {
				if strings.Contains(err.Error(), probe) {
					t.Fatalf("error must not contain document/path material (probe %q): %v", probe, err)
				}
			}
		})
	}
}

// TestLoadMasterKeyFileErrorsAreDataFree pins the loader-level error contract:
// even a perfectly valid document at a distinctive path never puts the path
// into errors, and parse failures never echo key or version material.
func TestLoadMasterKeyFileErrorsAreDataFree(t *testing.T) {
	t.Parallel()
	distinctive := filepath.Join(t.TempDir(), "datafree-probe-master-46ab91", "distinctive-master-7f2c1e.json")
	if err := os.MkdirAll(filepath.Dir(distinctive), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(distinctive, []byte(masterKeyDocument("1", map[string]string{"1": testMasterKeyB64(1)})), 0o600); err != nil {
		t.Fatal(err)
	}
	// Directory (exists at a distinctive path) fails without echoing the path.
	dirProbe := filepath.Join(t.TempDir(), "datafree-dir-9a7b3c")
	if err := os.MkdirAll(dirProbe, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKeyFile(dirProbe); err == nil {
		t.Fatal("directory must be rejected")
	} else if strings.Contains(err.Error(), dirProbe) {
		t.Fatalf("directory error must not contain the path: %v", err)
	}
	if _, err := LoadMasterKeyFile(filepath.Join(t.TempDir(), "does-not-exist-master-8c1d2f.json")); err == nil {
		t.Fatal("missing file must be rejected")
	} else if strings.Contains(err.Error(), "does-not-exist-master-8c1d2f.json") {
		t.Fatalf("missing-file error must not contain the path: %v", err)
	}
	// The sentinel for unsupported platforms is data-free by construction.
	if strings.Contains(ErrMasterKeyFileLoadingUnsupported.Error(), "/") || strings.Contains(ErrMasterKeyFileLoadingUnsupported.Error(), `\`) {
		t.Fatalf("unsupported-platform sentinel must be data-free: %q", ErrMasterKeyFileLoadingUnsupported)
	}
}
