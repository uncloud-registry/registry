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
// authenticating the associated data (registry ID + literal owner). Any
// authentication failure — tampering, wrong key, or context substitution —
// returns an error wrapping ErrKeyDecrypt without echoing key material.
func (c *FeedKeyCipher) Decrypt(registryID int64, owner string, value EncryptedFeedKey) ([]byte, error) {
	key, ok := c.keys[value.KeyVersion]
	if !ok {
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
	plaintext, err := gcm.Open(nil, value.Nonce, value.Ciphertext, aad)
	if err != nil {
		// The GCM error text is fixed stdlib material (never ciphertext,
		// nonce, or key bytes); wrap the stable sentinel for classification.
		return nil, fmt.Errorf("%w: %v", ErrKeyDecrypt, err)
	}
	return plaintext, nil
}

// feedKeyAAD builds the AES-GCM associated data binding an envelope to its
// registry: an unambiguous 8-byte big-endian length prefix of the registry ID,
// a colon separator, then the LITERAL feed-owner address bytes (never
// normalized, trimmed, or case-folded — the store always persists the same
// canonical lowercase address it encrypts under, so identical bytes are used
// at both ends). The fixed-width ID prefix makes the concatenation self
// delimiting regardless of owner content. An empty owner is rejected: an
// envelope without a bound owner would be a silent context downgrade.
func feedKeyAAD(registryID int64, owner string) ([]byte, error) {
	if owner == "" {
		return nil, errFeedKeyEmptyContext
	}
	aad := make([]byte, 8+1+len(owner))
	binary.BigEndian.PutUint64(aad, uint64(registryID))
	aad[8] = ':'
	copy(aad[9:], owner)
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
