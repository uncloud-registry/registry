package controlplane

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
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

func TestFeedKeyCipherRejectsTamperedNonce(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	enc, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	enc.Nonce[0] ^= 0xff
	// A tampered nonce of the CORRECT length is an authentication failure.
	if _, err := c.Decrypt(1, "0xfeed", enc); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("nonce tampering: got %v", err)
	}
}

// TestFeedKeyCipherRejectsMalformedEnvelopes pins the complete-envelope shape
// contract: before any GCM operation the envelope must carry a nonce of
// EXACTLY gcm.NonceSize(), a ciphertext of at least gcm.Overhead() bytes (the
// empty-plaintext minimum — every shorter ciphertext can never be authentic),
// and these checks must never panic regardless of input. A ciphertext of
// exactly Overhead() is structurally valid (empty plaintext) and therefore
// fails with ErrKeyDecrypt (authentication), not the malformed sentinel.
func TestFeedKeyCipherRejectsMalformedEnvelopes(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	valid, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(mustAESBlock(t, c, 1))
	if err != nil {
		t.Fatal(err)
	}
	shortCT := make([]byte, gcm.Overhead()-1)
	exactTagCT := make([]byte, gcm.Overhead())

	cases := []struct {
		name    string
		value   EncryptedFeedKey
		wantErr error // nil = decryption must succeed
	}{
		{"nil nonce", EncryptedFeedKey{Ciphertext: valid.Ciphertext, KeyVersion: 1}, ErrFeedKeyEnvelopeMalformed},
		{"empty nonce", EncryptedFeedKey{Ciphertext: valid.Ciphertext, Nonce: []byte{}, KeyVersion: 1}, ErrFeedKeyEnvelopeMalformed},
		{"short nonce", EncryptedFeedKey{Ciphertext: valid.Ciphertext, Nonce: valid.Nonce[:gcm.NonceSize()-1], KeyVersion: 1}, ErrFeedKeyEnvelopeMalformed},
		{"long nonce", EncryptedFeedKey{Ciphertext: valid.Ciphertext, Nonce: append(append([]byte(nil), valid.Nonce...), 0x00), KeyVersion: 1}, ErrFeedKeyEnvelopeMalformed},
		{"nil ciphertext", EncryptedFeedKey{Nonce: valid.Nonce, KeyVersion: 1}, ErrFeedKeyEnvelopeMalformed},
		{"empty ciphertext", EncryptedFeedKey{Ciphertext: []byte{}, Nonce: valid.Nonce, KeyVersion: 1}, ErrFeedKeyEnvelopeMalformed},
		{"ciphertext below GCM overhead", EncryptedFeedKey{Ciphertext: shortCT, Nonce: valid.Nonce, KeyVersion: 1}, ErrFeedKeyEnvelopeMalformed},
		{"ciphertext at GCM overhead (empty plaintext shape)", EncryptedFeedKey{Ciphertext: exactTagCT, Nonce: valid.Nonce, KeyVersion: 1}, ErrKeyDecrypt},
		{"ciphertext one past overhead", EncryptedFeedKey{Ciphertext: make([]byte, gcm.Overhead()+1), Nonce: valid.Nonce, KeyVersion: 1}, ErrKeyDecrypt},
		{"zero version", EncryptedFeedKey{Ciphertext: valid.Ciphertext, Nonce: valid.Nonce, KeyVersion: 0}, ErrFeedKeyVersionUnloaded},
		{"negative version", EncryptedFeedKey{Ciphertext: valid.Ciphertext, Nonce: valid.Nonce, KeyVersion: -1}, ErrFeedKeyVersionUnloaded},
		{"valid envelope", valid, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.Decrypt(1, "0xfeed", tc.value)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("valid envelope must decrypt: %v", err)
				}
				if !bytes.Equal(got, []byte("private-key")) {
					t.Fatalf("round trip mismatch: %q", got)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestFeedKeyCipherMalformedEnvelopesNeverPanic proves that no malformed
// stored envelope — nil/short/long nonce, nil/short/empty ciphertext, or
// non-positive version — can panic the decrypt path (gcm.Open panics on a
// wrong-size nonce unless the envelope is validated first). A recover guard
// wraps every case; a panic fails the test.
func TestFeedKeyCipherMalformedEnvelopesNeverPanic(t *testing.T) {
	t.Parallel()
	c := newTestFeedKeyCipher(t)
	valid, err := c.Encrypt(1, "0xfeed", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []EncryptedFeedKey{
		{Ciphertext: valid.Ciphertext, KeyVersion: 1},                                   // nil nonce
		{Ciphertext: valid.Ciphertext, Nonce: valid.Nonce[:7], KeyVersion: 1},           // short nonce
		{Ciphertext: valid.Ciphertext, Nonce: append(valid.Nonce, 0x00), KeyVersion: 1}, // long nonce
		{Nonce: valid.Nonce, KeyVersion: 1},                                             // nil ciphertext
		{Ciphertext: []byte{}, Nonce: valid.Nonce, KeyVersion: 1},                       // empty ciphertext
		{Ciphertext: make([]byte, 3), Nonce: valid.Nonce, KeyVersion: 1},                // short ciphertext
		{Ciphertext: valid.Ciphertext, Nonce: valid.Nonce, KeyVersion: 0},               // zero version
		{Ciphertext: valid.Ciphertext, Nonce: valid.Nonce, KeyVersion: -3},              // negative version
	}
	for i, tc := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d: decrypt panicked: %v", i, r)
				}
			}()
			_, err := c.Decrypt(1, "0xfeed", tc)
			if err == nil {
				t.Fatalf("case %d: malformed envelope must fail, got nil", i)
			}
			switch {
			case errors.Is(err, ErrFeedKeyEnvelopeMalformed),
				errors.Is(err, ErrKeyDecrypt),
				errors.Is(err, ErrFeedKeyVersionUnloaded):
			default:
				t.Fatalf("case %d: unclassified error %v", i, err)
			}
		}()
	}
}

func mustAESBlock(t *testing.T, c *FeedKeyCipher, version int) (block interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}) {
	t.Helper()
	key := c.keys[version]
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes new cipher: %v", err)
	}
	return aesBlock
}

// TestFeedKeyEnvelopeConstantsMatchAESGCM pins the persisted-envelope
// structural constants to the ACTUAL AES-256-GCM primitive used by
// FeedKeyCipher. The schema triggers and the store/runtime rules hard-code
// the same numbers (12-byte nonce, 16-byte minimum ciphertext) in different
// languages (SQL literals vs Go constants); if the cipher's NonceSize or
// Overhead ever drifted, this test fails loudly instead of letting the
// schema and runtime rules silently disagree. It also asserts the standard
// published AES-GCM values so a cipher-swap cannot quietly change the wire
// format.
func TestFeedKeyEnvelopeConstantsMatchAESGCM(t *testing.T) {
	t.Parallel()
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("aes new cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("new gcm: %v", err)
	}
	if gcm.NonceSize() != 12 {
		t.Fatalf("AES-256-GCM nonce size drifted from the standard 12 bytes: got %d", gcm.NonceSize())
	}
	if gcm.Overhead() != 16 {
		t.Fatalf("AES-256-GCM overhead drifted from the standard 16 bytes: got %d", gcm.Overhead())
	}
	if feedKeyEnvelopeNonceSize != gcm.NonceSize() {
		t.Fatalf("feedKeyEnvelopeNonceSize (%d) drifted from the live cipher nonce size (%d)", feedKeyEnvelopeNonceSize, gcm.NonceSize())
	}
	if feedKeyEnvelopeCiphertextMin != gcm.Overhead() {
		t.Fatalf("feedKeyEnvelopeCiphertextMin (%d) drifted from the live cipher overhead (%d)", feedKeyEnvelopeCiphertextMin, gcm.Overhead())
	}
	// The validators must behave identically whether invoked with a live GCM
	// (validateFeedKeyEnvelope) or the shared shape validator.
	c := newTestFeedKeyCipher(t)
	block2, err := aes.NewCipher(c.keys[1])
	if err != nil {
		t.Fatal(err)
	}
	gcm2, err := cipher.NewGCM(block2)
	if err != nil {
		t.Fatal(err)
	}
	valid := EncryptedFeedKey{Ciphertext: make([]byte, 16), Nonce: make([]byte, 12), KeyVersion: 1}
	if err := validateFeedKeyEnvelope(valid, gcm2); err != nil {
		t.Fatalf("16-byte ciphertext + 12-byte nonce must pass the live-GCM validator: %v", err)
	}
	if err := validateFeedKeyEnvelopeShape(valid); err != nil {
		t.Fatalf("16-byte ciphertext + 12-byte nonce must pass the shape validator: %v", err)
	}
	for _, value := range []EncryptedFeedKey{
		{Ciphertext: make([]byte, 16), Nonce: make([]byte, 11), KeyVersion: 1},  // short nonce
		{Ciphertext: make([]byte, 16), Nonce: make([]byte, 13), KeyVersion: 1},  // long nonce
		{Ciphertext: make([]byte, 15), Nonce: make([]byte, 12), KeyVersion: 1},  // short ciphertext
		{Ciphertext: []byte{}, Nonce: make([]byte, 12), KeyVersion: 1},          // empty ciphertext
		{Ciphertext: make([]byte, 16), Nonce: make([]byte, 12), KeyVersion: 0},  // zero version
		{Ciphertext: make([]byte, 16), Nonce: make([]byte, 12), KeyVersion: -1}, // negative version
	} {
		if err := validateFeedKeyEnvelopeShape(value); err == nil {
			t.Fatalf("malformed envelope %+v must be rejected by the shape validator", value)
		}
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
	// A non-positive registry ID is also an invalid binding context: the AAD
	// contract is canonical positive decimal ID bytes, so zero/negative IDs
	// can never be sealed under.
	if _, err := c.Encrypt(0, "0xfeed", []byte("private-key")); err == nil {
		t.Fatal("encrypt with zero registry ID must fail")
	}
	if _, err := c.Encrypt(-7, "0xfeed", []byte("private-key")); err == nil {
		t.Fatal("encrypt with negative registry ID must fail")
	}
	if _, err := c.Decrypt(0, "0xfeed", enc); err == nil {
		t.Fatal("decrypt with zero registry ID must fail")
	}
}

// TestFeedKeyAADFixedVectors pins the EXACT canonical AAD bytes: a fixed
// 32-byte domain-separator prefix ("uncloud-registry-feedkey-aad:v1" + NUL),
// an 8-byte big-endian length prefix for the canonical positive decimal
// registry-ID bytes, those bytes, an 8-byte big-endian length prefix for the
// LITERAL owner bytes, then those bytes. Both variable-length fields are
// length-prefixed, so the representation is self-delimiting no matter what the
// owner string contains. The vectors are literal hex so any accidental change
// to the wire format fails here.
func TestFeedKeyAADFixedVectors(t *testing.T) {
	t.Parallel()
	if len(feedKeyAADPrefix) != 32 {
		t.Fatalf("AAD domain prefix must be exactly 32 bytes, got %d", len(feedKeyAADPrefix))
	}
	const prefixHex = "756e636c6f75642d72656769737472792d666565646b65792d6161643a763100"

	cases := []struct {
		name    string
		id      int64
		owner   string
		wantHex string
		wantLen int
	}{
		{"id 42 owner 0xfeed", 42, "0xfeed",
			prefixHex + "0000000000000002" + "3432" + "0000000000000006" + "307866656564", 56},
		{"id 1 owner a", 1, "a",
			prefixHex + "0000000000000001" + "31" + "0000000000000001" + "61", 50},
		{"id 7 owner 0xfeed0001", 7, "0xfeed0001",
			prefixHex + "0000000000000001" + "37" + "000000000000000a" + "30786665656430303031", 59},
		{"id 999999999999 owner empty-adjacent bytes", 999999999999, "0x",
			prefixHex + "000000000000000c" + "393939393939393939393939" + "0000000000000002" + "3078", 62},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aad, err := feedKeyAAD(tc.id, tc.owner)
			if err != nil {
				t.Fatalf("feedKeyAAD: %v", err)
			}
			if got := hex.EncodeToString(aad); got != tc.wantHex {
				t.Fatalf("AAD bytes mismatch:\n got  %s\n want %s", got, tc.wantHex)
			}
			if len(aad) != tc.wantLen {
				t.Fatalf("AAD length mismatch: got %d want %d", len(aad), tc.wantLen)
			}
		})
	}

	// The length prefixes make the concatenation unambiguous: contexts whose
	// naive id||owner concatenation collides ("1"+"23" == "12"+"3") must
	// produce different AADs, and neither can authenticate the other's
	// envelope.
	ambiguousA, err := feedKeyAAD(1, "23")
	if err != nil {
		t.Fatal(err)
	}
	ambiguousB, err := feedKeyAAD(12, "3")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ambiguousA, ambiguousB) {
		t.Fatal("length-prefixed AAD must disambiguate id/owner boundary collisions")
	}
	if string(ambiguousA) == "123" || string(ambiguousB) == "123" {
		t.Fatal("AAD must never be a bare id||owner concatenation")
	}
	c := newTestFeedKeyCipher(t)
	enc, err := c.Encrypt(12, "3", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(1, "23", enc); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("boundary-collision substitution must fail authentication: %v", err)
	}
	if _, err := c.Decrypt(12, "3", enc); err != nil {
		t.Fatalf("true context must decrypt: %v", err)
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
