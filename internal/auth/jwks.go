package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// maxJWKSFileSize bounds how large a REGISTRY_TOKEN_PUBLIC_KEYS_FILE may be.
// JWKS files hold a handful of public keys; 1 MiB is far beyond any legitimate
// set while still bounding hostile input before parse.
const maxJWKSFileSize = 1 << 20 // 1 MiB

// jwksEntry is the ONLY accepted shape for a key entry. DisallowUnknownFields
// makes any additional JWKS field (alg, use, key_ops, e, n, y, ...) a hard
// parse error, so the loader fails closed on keys it does not fully understand
// instead of ignoring security-relevant attributes. There is deliberately no
// "d" field: token-level validation (rejectDuplicateObjectMembers) rejects ANY
// private-key member before typed decoding, so an entry never reaches this
// struct carrying secret material.
type jwksEntry struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

// JWKSKeySet is a strict, in-memory Ed25519 verification-key set loaded from a
// JWKS document. It implements PublicKeySet so RegistryTokenVerifier can
// resolve keys by kid, and it supports rotation: every unique kid in the
// document is resolvable until the set is replaced.
type JWKSKeySet struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

// Key resolves an Ed25519 verification key by its ID. Unknown kids fail
// closed; errors never contain key material.
func (s *JWKSKeySet) Key(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	if s == nil {
		return nil, errors.New("jwk key set is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown jwk key id %q", keyID)
	}
	return k, nil
}

// LoadJWKSFromFile reads and strict-parses a JWKS file. The file is opened
// exactly ONCE without following a trailing symlink (O_NOFOLLOW on macOS and
// Linux); the opened descriptor is validated with Fstat — regular file only,
// never a symlink, directory, device, FIFO, or other special type, never
// group- or world-writable (perm & 022 == 0), never over maxJWKSFileSize —
// and the bytes are read through a hard 1 MiB+1 limit rather than os.ReadFile.
// Because the same descriptor that was validated is the descriptor that is
// read and parsed, a path swap between open and read cannot redirect parsing:
// the stat→open→read TOCTOU window is closed by construction. Platform
// constraint: the secure single-descriptor open requires kernel O_NOFOLLOW and
// O_NONBLOCK, available on macOS and Linux — the supported production
// platforms for keys-file loading. On ALL other platforms secure loading is
// unsupported, so LoadJWKSFromFile fails closed with
// ErrJWKSFileLoadingUnsupported and never opens or reads the path (see
// jwks_open_other.go): there is no racy Lstat-then-open fallback on any GOOS.
// cmd/registry propagates the error so startup fails rather than running with
// weaker guarantees. The returned errors never include key bytes.
func LoadJWKSFromFile(path string) (*JWKSKeySet, error) {
	f, err := openJWKSFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := readJWKSDescriptor(f, path)
	if err != nil {
		return nil, err
	}
	return ParseJWKS(data)
}

// readJWKSDescriptor validates the OPENED descriptor and reads its bytes
// through a hard maxJWKSFileSize+1 limit. It is separated from the open so
// tests can prove the descriptor (not the path) is what gets read and parsed.
func readJWKSDescriptor(f *os.File, path string) ([]byte, error) {
	info, err := f.Stat() // Fstat: inspect the descriptor that was actually opened
	if err != nil {
		return nil, fmt.Errorf("stat registry token public keys file descriptor: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("registry token public keys file %q must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("registry token public keys file %q is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return nil, fmt.Errorf("registry token public keys file %q must not be group or world writable (mode %04o)", path, perm)
	}
	if info.Size() > maxJWKSFileSize {
		return nil, fmt.Errorf("registry token public keys file %q exceeds %d bytes", path, maxJWKSFileSize)
	}
	// Read at most maxJWKSFileSize+1 bytes: a file that grew after Fstat (or a
	// race that swapped content behind the descriptor) cannot blow up memory
	// and is rejected by the post-read bound.
	data, err := io.ReadAll(io.LimitReader(f, maxJWKSFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read registry token public keys file: %w", err)
	}
	if len(data) > maxJWKSFileSize {
		return nil, fmt.Errorf("registry token public keys file %q exceeds %d bytes", path, maxJWKSFileSize)
	}
	return data, nil
}

// ParseJWKS strict-parses a JWKS document. It accepts ONLY Ed25519 OKP
// entries: kty=OKP, crv=Ed25519, a nonempty literal kid (equal to its own
// TrimSpace — never whitespace-normalized), and an x coordinate that is
// unpadded, canonical base64url decoding to exactly 32 bytes. Token-level
// duplicate detection rejects duplicate member names inside ANY object and ANY
// occurrence of a private-key member named "d", before typed decoding, so
// hostile duplication cannot smuggle material past the struct. Unknown fields,
// missing/duplicate kids, empty key sets, non-OKP types, non-Ed25519 curves,
// private-key material, padded/non-canonical base64url, and wrong lengths are
// all rejected. Key rotation is preserved: every unique kid in the document is
// resolvable.
func ParseJWKS(data []byte) (*JWKSKeySet, error) {
	if err := rejectDuplicateObjectMembers(data); err != nil {
		return nil, fmt.Errorf("parse jwks document: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc struct {
		Keys []jwksEntry `json:"keys"`
	}
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse jwks document: %w", err)
	}
	// Reject trailing content after the single top-level object.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse jwks document: unexpected trailing data after top-level object")
	}
	if len(doc.Keys) == 0 {
		return nil, errors.New("parse jwks document: key set is empty")
	}

	keys := make(map[string]ed25519.PublicKey, len(doc.Keys))
	for i, entry := range doc.Keys {
		if entry.Kty != "OKP" {
			return nil, fmt.Errorf("parse jwks document: key %d has unsupported kty %q (only OKP accepted)", i, entry.Kty)
		}
		if entry.Crv != "Ed25519" {
			return nil, fmt.Errorf("parse jwks document: key %d has unsupported crv %q (only Ed25519 accepted)", i, entry.Crv)
		}
		// The kid must be nonempty and literal: whitespace-padded kids are
		// rejected (the value must equal its own TrimSpace) and the value is
		// never trimmed or normalized. The literal kid is what gets registered
		// for rotation lookups.
		if entry.Kid == "" || entry.Kid != strings.TrimSpace(entry.Kid) {
			return nil, fmt.Errorf("parse jwks document: key %d has an empty or non-literal kid", i)
		}
		if _, dup := keys[entry.Kid]; dup {
			return nil, fmt.Errorf("parse jwks document: duplicate kid %q", entry.Kid)
		}
		if entry.X == "" {
			return nil, fmt.Errorf("parse jwks document: key %d (kid %q) is missing the x coordinate", i, entry.Kid)
		}
		raw, err := decodeJWKSX(entry.X)
		if err != nil {
			return nil, fmt.Errorf("parse jwks document: key %d (kid %q) has malformed x encoding: %w", i, entry.Kid, err)
		}
		keys[entry.Kid] = ed25519.PublicKey(raw)
	}
	return &JWKSKeySet{keys: keys}, nil
}

// decodeJWKSX decodes an x coordinate STRICTLY: no '=' padding anywhere, pure
// base64.RawURLEncoding, and a canonical round-trip (re-encoding the decoded
// bytes must reproduce the input exactly, which rejects non-zero padding bits
// Go's decoder otherwise tolerates).
func decodeJWKSX(s string) ([]byte, error) {
	if strings.Contains(s, "=") {
		return nil, errors.New("x coordinate must use unpadded base64url (no '=' padding)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("x coordinate is not valid unpadded base64url: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("x coordinate decodes to %d bytes; want %d", len(raw), ed25519.PublicKeySize)
	}
	if base64.RawURLEncoding.EncodeToString(raw) != s {
		return nil, errors.New("x coordinate is not canonically encoded base64url")
	}
	return raw, nil
}

// rejectDuplicateObjectMembers validates the raw JSON token stream BEFORE any
// typed decoding so that duplicate member names inside ANY object — and any
// object member named "d" (private-key material) anywhere — are hard errors.
// encoding/json silently keeps only the LAST duplicate member, so a hostile
// document like {"d":"<secret>","d":""} decodes as if no private material were
// present; token-level validation closes that window. Values are never echoed
// into errors.
func rejectDuplicateObjectMembers(data []byte) error {
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
				if key == "d" {
					// Presence of the member alone is private-key material,
					// regardless of its value or of duplicate overwriting.
					return errors.New("object member \"d\" is private-key material; only public keys are accepted")
				}
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
