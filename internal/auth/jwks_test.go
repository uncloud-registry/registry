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
		{"missing kid", `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + key.xBase64 + `"}]}`, "empty or missing kid"},
		{"blank kid", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"  ","x":"` + key.xBase64 + `"}]}`, "empty or missing kid"},
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

func TestParseJWKSAcceptsPaddedBase64URL(t *testing.T) {
	t.Parallel()
	key := newJWKSTestKey(t, "padded")
	// Pad the unpadded value to a multiple of 4.
	padded := key.xBase64 + strings.Repeat("=", (4-len(key.xBase64)%4)%4)
	doc := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"padded","x":"` + padded + `"}]}`
	set, err := ParseJWKS([]byte(doc))
	if err != nil {
		t.Fatalf("padded base64url must parse: %v", err)
	}
	got, err := set.Key(context.Background(), "padded")
	if err != nil || !got.Equal(key.pub) {
		t.Fatalf("padded key mismatch: got=%v err=%v", got, err)
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
