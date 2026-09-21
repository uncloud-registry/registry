package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// jwksTestKey wraps a generated Ed25519 key plus its JWKS JSON fragment.
type jwksTestKey struct {
	kid     string
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	jwkJSON string // full object entry
	xBase64 string
}

func newJWKSTestKey(t *testing.T, kid string) jwksTestKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(pub)
	return jwksTestKey{
		kid:     kid,
		pub:     pub,
		priv:    priv,
		jwkJSON: `{"kty":"OKP","crv":"Ed25519","kid":"` + kid + `","x":"` + x + `"}`,
		xBase64: x,
	}
}

func jwksDocument(entries ...string) []byte {
	return []byte(`{"keys":[` + strings.Join(entries, ",") + `]}`)
}

func mustParseJWKS(t *testing.T, doc []byte) *JWKSKeySet {
	t.Helper()
	set, err := ParseJWKS(doc)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	return set
}

func TestParseJWKSValidEd25519Set(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "key-1")
	set := mustParseJWKS(t, jwksDocument(key.jwkJSON))
	got, err := set.Key(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if len(got) != ed25519.PublicKeySize {
		t.Fatalf("key length = %d, want %d", len(got), ed25519.PublicKeySize)
	}
	if !got.Equal(key.pub) {
		t.Fatal("resolved key does not match the JWKS x coordinate")
	}
	if _, err := set.Key(context.Background(), "missing"); err == nil {
		t.Fatal("unknown kid must fail closed")
	}
}

func TestParseJWWKSRotationMultipleKids(t *testing.T) {
	t.Parallel()
	k1 := newJWKSTestKey(t, "key-rot-1")
	k2 := newJWKSTestKey(t, "key-rot-2")
	set := mustParseJWKS(t, jwksDocument(k1.jwkJSON, k2.jwkJSON))
	for _, k := range []jwksTestKey{k1, k2} {
		got, err := set.Key(context.Background(), k.kid)
		if err != nil {
			t.Fatalf("Key(%q): %v", k.kid, err)
		}
		if !got.Equal(k.pub) {
			t.Fatalf("Key(%q) mismatch", k.kid)
		}
	}
}

func TestParseJWKSRejectsMalformedSets(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "key-1")

	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"empty keys array", `{"keys":[]}`, "empty"},
		{"missing keys field", `{}`, "empty"},
		{"non-object top level", `[{"kty":"OKP"}]`, ""},
		{"trailing data", `{"keys":[]} extra`, "trailing"},
		{"rsa kty", `{"keys":[{"kty":"RSA","kid":"k"}]}`, "unsupported kty"},
		{"ec kty", `{"keys":[{"kty":"EC","crv":"P-256","kid":"k"}]}`, "unsupported kty"},
		{"okp wrong curve", `{"keys":[{"kty":"OKP","crv":"X25519","kid":"k","x":"a"}]}`, "unsupported crv"},
		{"duplicate kids", string(jwksDocument(key.jwkJSON, key.jwkJSON)), "duplicate kid"},
		{"missing kid", `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + key.xBase64 + `"}]}`, "empty or non-literal kid"},
		{"blank kid", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"  ","x":"` + key.xBase64 + `"}]}`, "empty or non-literal kid"},
		{"missing x", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k"}]}`, "missing the x coordinate"},
		{"malformed x", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"!!not-base64url!!"}]}`, "malformed x"},
		{"short x", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"YWJj"}]}`, "decodes to 3 bytes"},
		{"long x", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + key.xBase64 + key.xBase64 + `"}]}`, "decodes to 64 bytes"},
		{"private key material", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + key.xBase64 + `","d":"c2VjcmV0"}]}`, "private-key material"},
		{"unknown field use", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + key.xBase64 + `","use":"sig"}]}`, "unknown field"},
		{"unknown field alg", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + key.xBase64 + `","alg":"EdDSA"}]}`, "unknown field"},
		{"unknown field key_ops", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + key.xBase64 + `","key_ops":["verify"]}]}`, "unknown field"},
		{"unknown top-level field", `{"keys":[],"extra":1}`, "unknown field"},
		{"not json", `not-json`, ""},
	}
	for _, tc := range cases {
		if _, err := ParseJWKS([]byte(tc.doc)); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
			continue
		} else if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not contain %q", tc.name, err, tc.want)
		}
	}
}

func TestJWKSKeySetNilFailsClosed(t *testing.T) {
	t.Parallel()
	var set *JWKSKeySet
	if _, err := set.Key(context.Background(), "k"); err == nil {
		t.Fatal("nil key set must fail closed")
	}
}

func TestLoadJWKSFromFileValid(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "file-key-1")
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, jwksDocument(key.jwkJSON), 0o644); err != nil {
		t.Fatalf("write jwks: %v", err)
	}
	set, err := LoadJWKSFromFile(path)
	if err != nil {
		t.Fatalf("LoadJWKSFromFile: %v", err)
	}
	got, err := set.Key(context.Background(), "file-key-1")
	if err != nil || !got.Equal(key.pub) {
		t.Fatalf("file-loaded key mismatch: err=%v", err)
	}
}

func TestLoadJWKSFromFileRejectsUnsafePaths(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "k")

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		if _, err := LoadJWKSFromFile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Fatal("missing file must fail")
		}
	})

	t.Run("directory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if _, err := LoadJWKSFromFile(dir); err == nil {
			t.Fatal("directory must be rejected")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		target := filepath.Join(dir, "real.json")
		if err := os.WriteFile(target, jwksDocument(key.jwkJSON), 0o644); err != nil {
			t.Fatalf("write target: %v", err)
		}
		link := filepath.Join(dir, "link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks not supported on this platform: %v", err)
		}
		// NOTE (macOS/Linux): os.Lstat reports ModeSymlink identically on both
		// platforms, so the rejection below is the documented behavior on the
		// platforms this repository targets.
		if _, err := LoadJWKSFromFile(link); err == nil {
			t.Fatal("symlink must be rejected")
		}
	})

	t.Run("oversized", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "huge.json")
		if err := os.WriteFile(path, make([]byte, maxJWKSFileSize+1), 0o644); err != nil {
			t.Fatalf("write oversized file: %v", err)
		}
		if _, err := LoadJWKSFromFile(path); err == nil {
			t.Fatal("oversized file must be rejected")
		}
	})

	t.Run("invalid content", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(path, []byte(`{"keys":[]}`), 0o644); err != nil {
			t.Fatalf("write invalid jwks: %v", err)
		}
		if _, err := LoadJWKSFromFile(path); err == nil {
			t.Fatal("empty key set file must be rejected")
		}
	})
}

// TestJWKSKeyErrorsNeverLeakKeyMaterial pins the report contract: errors from
// parse and key lookup must not contain x coordinates, private bytes, or the
// raw document.
func TestJWKSKeyErrorsNeverLeakKeyMaterial(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "leak-check")
	doc := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + key.xBase64 + `","d":"` + strings.Repeat("c2VjcmV0", 4) + `"}]}`
	_, err := ParseJWKS([]byte(doc))
	if err == nil {
		t.Fatal("expected private-key rejection")
	}
	if strings.Contains(err.Error(), key.xBase64) || strings.Contains(err.Error(), "c2VjcmV0") {
		t.Fatalf("error leaks key material: %v", err)
	}
	set := mustParseJWKS(t, jwksDocument(key.jwkJSON))
	if _, err := set.Key(context.Background(), "missing-kid"); err != nil && strings.Contains(err.Error(), key.xBase64) {
		t.Fatalf("key lookup error leaks material: %v", err)
	}
}

// --- Fix round 1 RED: strict duplicate/key/encoding/file-mode validation ---

// nonCanonicalX returns a base64url string that decodes to the SAME bytes as
// xBase64 but is NOT the canonical RawURLEncoding of those bytes (nonzero pad
// bits in the final character). Go's decoder tolerates such encodings, which is
// exactly the ambiguity a strict parser must reject.
func nonCanonicalX(t *testing.T, xBase64 string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(xBase64)
	if err != nil {
		t.Fatalf("decode canonical x: %v", err)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := 0; i < len(alphabet); i++ {
		c := alphabet[i]
		if c == xBase64[len(xBase64)-1] {
			continue
		}
		mod := xBase64[:len(xBase64)-1] + string(c)
		got, err := base64.RawURLEncoding.DecodeString(mod)
		if err == nil && string(got) == string(raw) {
			return mod
		}
	}
	t.Fatal("could not construct a non-canonical encoding")
	return ""
}

// TestParseJWKSRejectsDuplicateObjectMembers pins that duplicate member names
// inside ANY JSON object are rejected at the token level, before typed
// decoding (encoding/json silently keeps only the LAST duplicate, which is
// exactly the ambiguity a hostile document exploits).
func TestParseJWKSRejectsDuplicateObjectMembers(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "dup-k1")
	keys := jwksDocument(key.jwkJSON)
	cases := []struct {
		name string
		doc  string
	}{
		{"duplicate kid member", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","kid":"b","x":"` + key.xBase64 + `"}]}`},
		{"duplicate x member", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + key.xBase64 + `","x":"` + key.xBase64 + `"}]}`},
		{"duplicate kty member", `{"keys":[{"kty":"OKP","kty":"OKP","crv":"Ed25519","kid":"k","x":"` + key.xBase64 + `"}]}`},
		{"duplicate crv member", `{"keys":[{"kty":"OKP","crv":"Ed25519","crv":"Ed25519","kid":"k","x":"` + key.xBase64 + `"}]}`},
		{"duplicate keys member", `{"keys":[` + key.jwkJSON + `],"keys":[` + key.jwkJSON + `]}`},
		{"duplicate unknown member", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","use":"sig","use":"sig","x":"` + key.xBase64 + `"}]}`},
	}
	for _, tc := range cases {
		if _, err := ParseJWKS([]byte(tc.doc)); err == nil {
			t.Errorf("%s: duplicate member names must be rejected, got nil", tc.name)
		}
	}
	_ = keys
}

// TestParseJWKSRejectsAnyPrivateKeyMember pins that ANY occurrence of a "d"
// member on any object is fatal — including empty-string occurrences and
// duplicates that would otherwise overwrite a secret value into emptiness.
func TestParseJWKSRejectsAnyPrivateKeyMember(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "dup-d")
	cases := []struct {
		name string
		doc  string
	}{
		{"single empty d", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","d":"","x":"` + key.xBase64 + `"}]}`},
		{"duplicate d with empty last value", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","d":"c2VjcmV0","d":"","x":"` + key.xBase64 + `"}]}`},
		{"duplicate d with secret last value", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","d":"c2VjcmV0","d":"c2VjcmV0Mg","x":"` + key.xBase64 + `"}]}`},
		{"whitespace d", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","d":"   ","x":"` + key.xBase64 + `"}]}`},
	}
	for _, tc := range cases {
		if _, err := ParseJWKS([]byte(tc.doc)); err == nil {
			t.Errorf("%s: any d member must be rejected, got nil", tc.name)
		}
	}
}

// TestParseJWKSRejectsPaddedOrNonCanonicalX pins the unpadded-only strict
// encoding contract: any '=' padding and any non-canonical RawURLEncoding of
// the same bytes are rejected.
func TestParseJWKSRejectsPaddedOrNonCanonicalX(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "pad-x")
	padded := key.xBase64 + strings.Repeat("=", (4-len(key.xBase64)%4)%4)
	cases := []struct {
		name string
		doc  string
	}{
		{"padded x", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + padded + `"}]}`},
		{"non-canonical x", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + nonCanonicalX(t, key.xBase64) + `"}]}`},
		{"x with interior padding char", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + key.xBase64[:10] + `=` + key.xBase64[10:] + `"}]}`},
	}
	for _, tc := range cases {
		if _, err := ParseJWKS([]byte(tc.doc)); err == nil {
			t.Errorf("%s: must be rejected, got nil", tc.name)
		}
	}
}

// TestParseJWKSRejectsNonLiteralKid pins that a kid is never whitespace
// normalized: it must be nonempty and equal to its own TrimSpace, and the
// literal value is what gets registered.
func TestParseJWKSRejectsNonLiteralKid(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "kid-k")
	cases := []struct {
		name string
		kid  string
	}{
		{"leading space", " kid-1"},
		{"trailing space", "kid-1 "},
		{"both sides", " kid-1 "},
		{"tab padded", "	kid-1	"},
		{"newline padded", "\nkid-1\n"},
	}
	for _, tc := range cases {
		doc := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"` + tc.kid + `","x":"` + key.xBase64 + `"}]}`
		if _, err := ParseJWKS([]byte(doc)); err == nil {
			t.Errorf("%s: kid %q must be rejected, got nil", tc.name, tc.kid)
		}
	}
	// A literal (unpadded) kid must still register under its exact value.
	set := mustParseJWKS(t, jwksDocument(key.jwkJSON))
	if _, err := set.Key(context.Background(), key.kid); err != nil {
		t.Fatalf("literal kid must resolve: %v", err)
	}
}

// TestLoadJWKSFromFileRejectsWritableMode pins the permission contract: a
// group- or world-writable keys file is refused (perm & 022 != 0), while an
// owner-only or owner/group-readable file loads.
func TestLoadJWKSFromFileRejectsWritableMode(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "mode-k")

	rejected := []os.FileMode{0o666, 0o660, 0o662, 0o606}
	for _, mode := range rejected {
		path := filepath.Join(t.TempDir(), "keys.json")
		if err := os.WriteFile(path, jwksDocument(key.jwkJSON), mode); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if _, err := LoadJWKSFromFile(path); err == nil {
			t.Errorf("mode %04o must be rejected", mode)
		}
	}

	accepted := []os.FileMode{0o600, 0o640, 0o604, 0o644}
	for _, mode := range accepted {
		path := filepath.Join(t.TempDir(), "keys.json")
		if err := os.WriteFile(path, jwksDocument(key.jwkJSON), mode); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if _, err := LoadJWKSFromFile(path); err != nil {
			t.Errorf("mode %04o must load: %v", mode, err)
		}
	}
}
