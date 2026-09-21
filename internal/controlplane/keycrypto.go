package controlplane

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Master-key file wire format (strict JSON):
//
//	{
//	  "current": 1,
//	  "keys": { "1": "<unpadded base64url of exactly 32 bytes>" }
//	}
//
// `current` must be an explicit JSON integer (never a float, string, or null)
// whose canonical decimal form names a member of `keys`. `keys` members are
// indexed by canonical positive decimal version strings — no leading zeros, no
// sign, no exponent, no whitespace — and every value must be strict unpadded
// base64url decoding to exactly 32 bytes (canonical round-trip, so non-zero
// padding bits are rejected). Duplicate members anywhere, unknown top-level
// members, empty documents, and trailing data are hard errors. The format is
// rotation-ready: multiple versions stay loadable while `current` selects the
// default encryption version, and previously encrypted rows (carrying their
// own KeyVersion) remain decryptable under any loaded version.

// ErrKeyDecrypt is the stable sentinel wrapping every feed-key authentication
// failure: tampered ciphertext or nonce, wrong master key, or AAD context
// substitution (different registry ID or owner than the one the row was
// encrypted under). Errors wrap this sentinel so callers can classify
// failures without parsing messages, and messages never contain key bytes.
var ErrKeyDecrypt = errors.New("feed key decryption failed")

// ErrFeedKeyVersionUnloaded is returned when an operation references a key
// version that is not present in the loaded master-key set (unsupported),
// e.g. decrypting a row stamped with a version the operator no longer loaded,
// or requesting rotation to an unloaded target version.
var ErrFeedKeyVersionUnloaded = errors.New("feed key version is not loaded")

// errFeedKeyCipherNotConfigured is the fail-closed error for any operation
// that requires AES-GCM key material (create-registry encryption, legacy
// migration, rotation, feed-key decryption) when no cipher is configured.
var errFeedKeyCipherNotConfigured = errors.New("feed key cipher is not configured")

// errFeedKeyEmptyContext is returned when AES-GCM associated-data context
// (registry ID / owner) is missing; an unbound envelope cannot be created.
var errFeedKeyEmptyContext = errors.New("feed key encryption context cannot be empty")

// errFeedKeyInvalidRegistryID is returned when the AES-GCM associated-data
// registry ID is not a positive integer (the canonical AAD carries positive
// decimal ID bytes). An envelope bound to a non-positive ID can never be
// created or opened.
var errFeedKeyInvalidRegistryID = errors.New("feed key encryption context requires a positive registry ID")

// ErrFeedKeyEnvelopeMalformed is the stable sentinel for a structurally
// invalid feed-key envelope: a nonce that is not exactly
// feedKeyEnvelopeNonceSize bytes, a ciphertext shorter than
// feedKeyEnvelopeCiphertextMin bytes (the empty-plaintext minimum — such a
// value can never be authentic), or a missing/empty field. Shape checks run
// BEFORE any GCM operation so a malformed stored envelope can never panic
// gcm.Open (which panics on wrong-size nonces) and is never handed to the
// cipher unvalidated. Store write guards reuse the same sentinel.
var ErrFeedKeyEnvelopeMalformed = errors.New("feed key envelope is malformed")

// ErrFeedKeyEnvelopeInconsistent is the stable sentinel for a registries row
// whose three feed-key columns violate the schema-level invariant (the
// columns are neither all NULL nor all present with non-empty ciphertext,
// non-empty nonce, and a strictly positive version). Scan/list, legacy
// migration, and rotation REJECT such rows with this sentinel — they are
// never silently skipped, scanned as plausible-looking values, or treated as
// "already encrypted".
var ErrFeedKeyEnvelopeInconsistent = errors.New("feed key envelope columns are inconsistent")

// ErrMasterKeyFileLoadingUnsupported is the stable, data-free sentinel
// returned by the master-key loader on every GOOS other than darwin and
// linux. The master-key security contract — open the file exactly ONCE
// without following a trailing symlink (O_NOFOLLOW) and without blocking on
// special files (O_NONBLOCK) — requires kernel support that only macOS and
// Linux provide. A Lstat-then-open fallback would still carry a symlink-swap
// TOCTOU window and could block on special files, so loading is REFUSED
// outright: the sentinel propagates through LoadMasterKeyFile to
// cmd/controlplane startup, which fails closed instead of running with weaker
// guarantees. The message carries no path and no key material.
var ErrMasterKeyFileLoadingUnsupported = errors.New("secure master key file loading is unsupported on this platform (requires macOS or Linux); refusing to fall back to an insecure open")

// maxMasterKeyFileSize bounds how large CONTROLPLANE_MASTER_KEY_FILE may be.
// The file holds a handful of 32-byte keys; 1 MiB is far beyond any
// legitimate document while still bounding hostile input before parse.
const maxMasterKeyFileSize = 1 << 20 // 1 MiB

// EncryptedFeedKey is the at-rest form of a registry feed-owner signing key:
// AES-256-GCM ciphertext, the random nonce it was sealed with, and the master
// key version that sealed it. Persisted as binary/integer columns; it must
// never be serialized into public DTOs (see dto.go).
type EncryptedFeedKey struct {
	Ciphertext []byte
	Nonce      []byte
	KeyVersion int
}

// Persisted feed-key envelope structural constants. These are the SINGLE
// source of truth for the envelope shape that every boundary enforces — the
// schema triggers and migration preflight (SQL literals), store scan and
// write validation, legacy migration, and rotation. They must stay exactly in
// sync with FeedKeyCipher's actual AES-256-GCM primitive: validateFeedKeyEnvelope
// asserts gcm.NonceSize()/Overhead() equal these constants on every cipher
// decode, and TestFeedKeyEnvelopeConstantsMatchAESGCM pins the standard values,
// so a drift can never silently split the schema rules from the runtime rules.
const (
	// feedKeyEnvelopeNonceSize is the AES-GCM standard nonce length. A nonce
	// of any other length would panic gcm.Open (wrong-size nonce), so every
	// malformed envelope must be rejected before it reaches the cipher.
	feedKeyEnvelopeNonceSize = 12
	// feedKeyEnvelopeCiphertextMin is the minimum ciphertext byte length: the
	// AES-GCM tag alone (empty plaintext + 16-byte tag) is a structurally
	// valid envelope; anything shorter can never be authentic.
	feedKeyEnvelopeCiphertextMin = 16
)

// validateFeedKeyEnvelopeShape is the structural contract shared by every
// boundary that persists or reads an EncryptedFeedKey: a COMPLETE envelope
// must have a nonce of exactly feedKeyEnvelopeNonceSize bytes, a ciphertext
// of at least feedKeyEnvelopeCiphertextMin bytes (the empty-plaintext
// minimum), and a strictly positive version. Unlike validateFeedKeyEnvelope
// it does not need a cipher.AEAD instance and can run against raw column
// values at the store/schema boundary; errors wrap ErrFeedKeyEnvelopeMalformed.
// The all-NULL (unset) state is deliberately NOT passed here — callers treat
// it as the only no-key case and reject every other column combination as
// inconsistent before structural validation applies.
func validateFeedKeyEnvelopeShape(value EncryptedFeedKey) error {
	if value.KeyVersion <= 0 {
		return fmt.Errorf("%w: version must be strictly positive, got %d", ErrFeedKeyEnvelopeMalformed, value.KeyVersion)
	}
	if len(value.Nonce) != feedKeyEnvelopeNonceSize {
		return fmt.Errorf("%w: nonce must be exactly %d bytes, got %d", ErrFeedKeyEnvelopeMalformed, feedKeyEnvelopeNonceSize, len(value.Nonce))
	}
	if len(value.Ciphertext) < feedKeyEnvelopeCiphertextMin {
		return fmt.Errorf("%w: ciphertext must be at least %d bytes (GCM tag), got %d", ErrFeedKeyEnvelopeMalformed, feedKeyEnvelopeCiphertextMin, len(value.Ciphertext))
	}
	return nil
}

// FeedKeyCipher encrypts and decrypts registry feed-owner keys with AES-256-GCM.
// Each envelope is bound (as AES-GCM associated data) to an unambiguous
// length-prefixed registry ID plus the literal feed-owner address, so a row
// copied across registries or owners can never authenticate.
//
// The cipher is immutable after construction: the key map is never mutated and
// the last-loaded versions are safe for concurrent reads. Load once at
// startup; replace the whole cipher to rotate (see LoadMasterKeyFile).
type FeedKeyCipher struct {
	keys    map[int][]byte
	current int
}

// NewFeedKeyCipher validates and wraps a versioned master-key set. keys maps
// canonical positive version numbers to exactly-32-byte AES keys; current
// must be present in keys and positive (it selects the default encryption
// version). Errors carry no key material.
func NewFeedKeyCipher(keys map[int][]byte, current int) (*FeedKeyCipher, error) {
	if len(keys) == 0 {
		return nil, errors.New("feed key cipher requires at least one master key")
	}
	if current <= 0 {
		return nil, errors.New("feed key cipher requires a positive current version")
	}
	if _, ok := keys[current]; !ok {
		return nil, errors.New("feed key cipher requires the current version to be present in the key set")
	}
	cloned := make(map[int][]byte, len(keys))
	for version, key := range keys {
		if version <= 0 {
			return nil, errors.New("feed key cipher key versions must be positive integers")
		}
		if len(key) != aes.BlockSize*2 { // 32 bytes
			return nil, errors.New("feed key cipher master keys must be exactly 32 bytes")
		}
		cloned[version] = append([]byte(nil), key...)
	}
	return &FeedKeyCipher{keys: cloned, current: current}, nil
}

// CurrentVersion returns the version used for default encryption.
func (c *FeedKeyCipher) CurrentVersion() int {
	return c.current
}

// HasVersion reports whether version is loaded in this cipher.
func (c *FeedKeyCipher) HasVersion(version int) bool {
	_, ok := c.keys[version]
	return ok
}

// Encrypt seals plaintext under the current master key, bound to the given
// registry ID and feed-owner address, with a fresh random GCM nonce.
func (c *FeedKeyCipher) Encrypt(registryID int64, owner string, plaintext []byte) (EncryptedFeedKey, error) {
	return c.EncryptWith(c.current, registryID, owner, plaintext)
}

// EncryptWith seals plaintext under an explicitly requested loaded version
// (used by rotation to target a version other than `current`). The requested
// version must be loaded.
func (c *FeedKeyCipher) EncryptWith(version int, registryID int64, owner string, plaintext []byte) (EncryptedFeedKey, error) {
	key, ok := c.keys[version]
	if !ok {
		return EncryptedFeedKey{}, fmt.Errorf("%w: %d", ErrFeedKeyVersionUnloaded, version)
	}
	aad, err := feedKeyAAD(registryID, owner)
	if err != nil {
		return EncryptedFeedKey{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedFeedKey{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedFeedKey{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedFeedKey{}, err
	}
	return EncryptedFeedKey{
		Ciphertext: gcm.Seal(nil, nonce, plaintext, aad),
		Nonce:      nonce,
		KeyVersion: version,
	}, nil
}

// Decrypt opens value under the master key named by value.KeyVersion,
// authenticating the associated data (registry ID + literal owner). The
// envelope is validated for complete shape BEFORE any GCM operation: a wrong
// nonce length would make gcm.Open panic and a ciphertext below the GCM
// overhead can never be authentic, so both fail fast with
// ErrFeedKeyEnvelopeMalformed. Any authentication failure — tampering, wrong
// key, or context substitution — returns an error wrapping ErrKeyDecrypt
// without echoing key material.
func (c *FeedKeyCipher) Decrypt(registryID int64, owner string, value EncryptedFeedKey) ([]byte, error) {
	key, ok := c.keys[value.KeyVersion]
	if !ok {
		// A version that is not loaded (including zero/negative, which can
		// never be loaded) is an unsupported-version failure, not a shape
		// failure: the caller must load the right master-key file.
		return nil, fmt.Errorf("%w: %d", ErrFeedKeyVersionUnloaded, value.KeyVersion)
	}
	aad, err := feedKeyAAD(registryID, owner)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := validateFeedKeyEnvelope(value, gcm); err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, value.Nonce, value.Ciphertext, aad)
	if err != nil {
		// The GCM error text is fixed stdlib material (never ciphertext,
		// nonce, or key bytes); wrap the stable sentinel for classification.
		return nil, fmt.Errorf("%w: %v", ErrKeyDecrypt, err)
	}
	return plaintext, nil
}

// validateFeedKeyEnvelope checks the complete-envelope shape contract: the
// nonce must be exactly gcm.NonceSize() and the ciphertext at least
// gcm.Overhead() bytes (the empty-plaintext minimum). Every malformed input
// maps to ErrFeedKeyEnvelopeMalformed. Because gcm.Open panics on a
// wrong-size nonce, this MUST run before every Open. The live cipher values
// are asserted equal to the persisted-envelope constants
// (feedKeyEnvelopeNonceSize / feedKeyEnvelopeCiphertextMin) so the schema
// triggers and store/runtime rules can never silently drift apart.
func validateFeedKeyEnvelope(value EncryptedFeedKey, gcm cipher.AEAD) error {
	if gcm.NonceSize() != feedKeyEnvelopeNonceSize || gcm.Overhead() != feedKeyEnvelopeCiphertextMin {
		return fmt.Errorf("%w: cipher primitive drifted from envelope constants: nonce %d (want %d), overhead %d (want %d)",
			ErrFeedKeyEnvelopeMalformed, gcm.NonceSize(), feedKeyEnvelopeNonceSize, gcm.Overhead(), feedKeyEnvelopeCiphertextMin)
	}
	return validateFeedKeyEnvelopeShape(value)
}

// feedKeyAADPrefix is the fixed domain-separator/version prefix of every
// feed-key envelope's associated data: the 31-byte ASCII domain string
// "uncloud-registry-feedkey-aad:v1" followed by a NUL byte (32 bytes total).
// It distinguishes feed-key AAD from any other authenticated context in the
// system and version-stamps the wire format so a future format change is
// detected, not silently mis-parsed.
const feedKeyAADPrefix = "uncloud-registry-feedkey-aad:v1\x00"

// feedKeyAAD builds the canonical AES-GCM associated data binding an envelope
// to its registry. The exact bytes are:
//
//	[0,32)    feedKeyAADPrefix (fixed domain separator/version, 32 bytes)
//	[32,40)   8-byte big-endian length of the registry-ID text bytes
//	[40,40+n) canonical positive decimal ASCII of registryID (no sign,
//	          no leading zeros — strconv.FormatInt)
//	[40+n,48+n) 8-byte big-endian length of the OWNER bytes
//	[48+n,...)   the LITERAL feed-owner address bytes (never normalized,
//	             trimmed, or case-folded)
//
// Both variable-length fields are length-prefixed, so the concatenation is
// self-delimiting no matter what the owner bytes contain — contexts whose
// naive id||owner concatenation would collide (e.g. (1,"23") vs (12,"3"))
// produce distinct AADs and cannot authenticate each other's envelopes. The
// domain prefix prevents cross-protocol confusion and fixes the format for
// any future migration. An empty owner and a non-positive registry ID are
// rejected: an envelope without a fully-bound context would be a silent
// context downgrade.
func feedKeyAAD(registryID int64, owner string) ([]byte, error) {
	if owner == "" {
		return nil, errFeedKeyEmptyContext
	}
	if registryID <= 0 {
		return nil, errFeedKeyInvalidRegistryID
	}
	idText := strconv.FormatInt(registryID, 10)
	aad := make([]byte, 0, len(feedKeyAADPrefix)+16+len(idText)+len(owner))
	aad = append(aad, feedKeyAADPrefix...)
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(idText)))
	aad = append(aad, lenBuf[:]...)
	aad = append(aad, idText...)
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(owner)))
	aad = append(aad, lenBuf[:]...)
	aad = append(aad, owner...)
	return aad, nil
}

// zeroBytes wipes a transient plaintext buffer. Used where practical after
// decryption so key material does not linger in the heap.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// LoadMasterKeyFile reads, validates, and parses the strict master-key file.
// It follows the same trust-store discipline as the registry JWKS loader
// (Task 5): the path is opened exactly once without following a trailing
// symlink (O_NOFOLLOW, macOS/Linux), the opened descriptor is validated with
// Fstat — regular file only, never group- or world-writable, never over
// maxMasterKeyFileSize — and the bytes are read through a hard size bound.
// Unsupported platforms fail closed without touching the path. Errors never
// contain the path or any key material.
func LoadMasterKeyFile(path string) (*FeedKeyCipher, error) {
	f, err := openMasterKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := readMasterKeyDescriptor(f)
	if err != nil {
		return nil, err
	}
	return parseMasterKeyDocument(data)
}

// readMasterKeyDescriptor validates the OPENED descriptor and reads its bytes
// through a hard maxMasterKeyFileSize+1 limit. Separated from the open so
// tests can prove the descriptor (not the path) is what gets read and parsed.
// Errors never include the path (data-free by design; the caller's path is an
// operator secret value).
func readMasterKeyDescriptor(f *os.File) ([]byte, error) {
	info, err := f.Stat() // Fstat: inspect the descriptor that was actually opened
	if err != nil {
		return nil, fmt.Errorf("stat master key file descriptor: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("master key file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("master key file is not a regular file")
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return nil, errors.New("master key file must not be group or world writable")
	}
	if info.Size() > maxMasterKeyFileSize {
		return nil, fmt.Errorf("master key file exceeds %d bytes", maxMasterKeyFileSize)
	}
	// Read at most maxMasterKeyFileSize+1 bytes: a file that grew after Fstat
	// (or a race that swapped content behind the descriptor) cannot blow up
	// memory and is rejected by the post-read bound.
	data, err := io.ReadAll(io.LimitReader(f, maxMasterKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read master key file: %w", err)
	}
	if len(data) > maxMasterKeyFileSize {
		return nil, fmt.Errorf("master key file exceeds %d bytes", maxMasterKeyFileSize)
	}
	return data, nil
}

// versionStringRe matches canonical positive decimal version strings: no
// leading zeros, no sign, no exponent, no whitespace, no fraction. "0" is not
// positive and is rejected.
var versionStringRe = regexp.MustCompile(`^[1-9][0-9]*$`)

// parseCanonicalVersion validates a strict canonical positive decimal version
// string and returns its integer value. Versions that are canonical decimal
// text but overflow int (or int64) are rejected.
func parseCanonicalVersion(s string) (int, bool) {
	if !versionStringRe.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || strconv.FormatInt(n, 10) != s {
		return 0, false
	}
	v := int(n)
	if int64(v) != n {
		return 0, false
	}
	return v, true
}

// parseMasterKeyDocument strict-parses a master-key document. See the
// loadMasterKeyFile doc comment for the wire contract. Errors never echo key
// bytes, version strings, or other document values.
func parseMasterKeyDocument(data []byte) (*FeedKeyCipher, error) {
	if err := rejectDuplicateJSONObjectMembers(data); err != nil {
		return nil, fmt.Errorf("parse master key document: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc struct {
		Current json.RawMessage   `json:"current"`
		Keys    map[string]string `json:"keys"`
	}
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse master key document: %w", err)
	}
	// Reject trailing content after the single top-level object.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse master key document: unexpected trailing data after top-level object")
	}

	// RawMessage (not json.Number) for `current`: encoding/json happily
	// unmarshals a JSON STRING into json.Number (it is string-kind), which
	// would let {"current":"1"} pass. Requiring the raw token to begin with a
	// digit excludes strings, null, booleans, arrays, and objects outright.
	raw := strings.TrimSpace(string(doc.Current))
	if raw == "" {
		return nil, errors.New("parse master key document: current is required and must be an integer")
	}
	if raw[0] < '0' || raw[0] > '9' {
		return nil, errors.New("parse master key document: current must be an explicit integer (not a string, null, boolean, array, or object)")
	}
	// JSON numbers that are not plain integers (fraction, exponent, sign) are
	// rejected before any typed parsing.
	for _, r := range raw {
		if r < '0' || r > '9' {
			return nil, errors.New("parse master key document: current must be an explicit integer (no fractions, exponents, or signs)")
		}
	}
	current, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || strconv.FormatInt(current, 10) != raw {
		return nil, errors.New("parse master key document: current must be canonical decimal text")
	}
	if current <= 0 {
		return nil, errors.New("parse master key document: current must be a positive integer")
	}
	cur := int(current)
	if int64(cur) != current {
		return nil, errors.New("parse master key document: current is out of range")
	}

	if len(doc.Keys) == 0 {
		return nil, errors.New("parse master key document: keys must be present and non-empty")
	}
	keys := make(map[int][]byte, len(doc.Keys))
	for versionKey, encoded := range doc.Keys {
		version, ok := parseCanonicalVersion(versionKey)
		if !ok {
			return nil, errors.New("parse master key document: every keys member must be a canonical positive decimal version string")
		}
		rawKey, err := decodeMasterKeyValue(encoded)
		if err != nil {
			return nil, err
		}
		keys[version] = rawKey
	}
	if _, ok := keys[cur]; !ok {
		return nil, errors.New("parse master key document: current key is missing from the key set")
	}
	return NewFeedKeyCipher(keys, cur)
}

// decodeMasterKeyValue decodes a master-key entry STRICTLY: no '=' padding
// anywhere, unpadded base64url, exactly 32 bytes, and a canonical round-trip
// (re-encoding the decoded bytes must reproduce the input exactly, which
// rejects non-zero padding bits Go's decoder otherwise tolerates).
func decodeMasterKeyValue(s string) ([]byte, error) {
	if strings.Contains(s, "=") {
		return nil, errors.New("parse master key document: key values must use unpadded base64url (no '=' padding)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("parse master key document: key value is not valid unpadded base64url")
	}
	if len(raw) != 32 {
		return nil, errors.New("parse master key document: key values must decode to exactly 32 bytes")
	}
	if base64.RawURLEncoding.EncodeToString(raw) != s {
		return nil, errors.New("parse master key document: key value is not canonically encoded base64url")
	}
	return raw, nil
}

// rejectDuplicateJSONObjectMembers validates the raw JSON token stream BEFORE
// any typed decoding so that duplicate member names inside ANY object are hard
// errors: encoding/json silently keeps only the LAST duplicate member, so a
// hostile document like {"current":1,"current":2} would otherwise parse with
// the second value winning. Values are never echoed into errors.
func rejectDuplicateJSONObjectMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walkJSONObjectMembers(dec)
}

func walkJSONObjectMembers(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			members := make(map[string]struct{})
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return fmt.Errorf("invalid json object member: %w", err)
				}
				key, ok := keyTok.(string)
				if !ok {
					return errors.New("invalid json object member name")
				}
				if _, dup := members[key]; dup {
					return fmt.Errorf("duplicate object member %q", key)
				}
				members[key] = struct{}{}
				if err := walkJSONObjectMembers(dec); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return fmt.Errorf("invalid json object: %w", err)
			}
		case '[':
			for dec.More() {
				if err := walkJSONObjectMembers(dec); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return fmt.Errorf("invalid json array: %w", err)
			}
		default:
			return fmt.Errorf("unexpected json delimiter %v", t)
		}
	case string, json.Number, bool, nil:
		// Scalar value; nothing further to validate.
	default:
		return fmt.Errorf("unexpected json token %T", tok)
	}
	return nil
}
