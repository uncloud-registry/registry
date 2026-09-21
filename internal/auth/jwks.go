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
// instead of ignoring security-relevant attributes.
type jwksEntry struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	D   string `json:"d"`
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

// LoadJWKSFromFile reads and strict-parses a JWKS file. The file must exist,
// be a regular file (not a symlink, directory, device, or other special type),
// and be at most maxJWKSFileSize bytes. On both macOS and Linux os.Lstat
// reports symlinks identically, so the rejection is portable; mode bits are
// NOT restricted because a JWKS file holds public verification material, not
// secrets. The returned errors never include key bytes.
func LoadJWKSFromFile(path string) (*JWKSKeySet, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat registry token public keys file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("registry token public keys file %q must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("registry token public keys file %q is not a regular file", path)
	}
	if info.Size() > maxJWKSFileSize {
		return nil, fmt.Errorf("registry token public keys file %q exceeds %d bytes", path, maxJWKSFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read registry token public keys file: %w", err)
	}
	// Defensive bound after read: the stat size could theoretically diverge.
	if len(data) > maxJWKSFileSize {
		return nil, fmt.Errorf("registry token public keys file %q exceeds %d bytes", path, maxJWKSFileSize)
	}
	return ParseJWKS(data)
}

// ParseJWKS strict-parses a JWKS document. It accepts ONLY Ed25519 OKP
// entries: kty=OKP, crv=Ed25519, a non-empty unique kid, and a base64url `x`
// decoding to exactly 32 bytes. Unknown fields, missing/duplicate kids, empty
// key sets, non-OKP types, non-Ed25519 curves, private-key material, and
// malformed base64url encodings are all rejected. Both padded and unpadded
// base64url are accepted for interoperability (RFC 7515 permits padding only
// in limited contexts; tolerant decoding keeps well-formed public sets from
// vendors that emit padded values while still rejecting anything non-URL-safe
// or wrong-length).
func ParseJWKS(data []byte) (*JWKSKeySet, error) {
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
		kid := strings.TrimSpace(entry.Kid)
		if kid == "" {
			return nil, fmt.Errorf("parse jwks document: key %d has an empty or missing kid", i)
		}
		if _, dup := keys[kid]; dup {
			return nil, fmt.Errorf("parse jwks document: duplicate kid %q", kid)
		}
		if strings.TrimSpace(entry.D) != "" {
			return nil, fmt.Errorf("parse jwks document: key %d carries private-key material; only public keys are accepted", i)
		}
		if entry.X == "" {
			return nil, fmt.Errorf("parse jwks document: key %d (kid %q) is missing the x coordinate", i, kid)
		}
		raw, err := decodeBase64URL(entry.X)
		if err != nil {
			return nil, fmt.Errorf("parse jwks document: key %d (kid %q) has malformed x encoding: %w", i, kid, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("parse jwks document: key %d (kid %q) x decodes to %d bytes; want %d", i, kid, len(raw), ed25519.PublicKeySize)
		}
		keys[kid] = ed25519.PublicKey(raw)
	}
	return &JWKSKeySet{keys: keys}, nil
}

// decodeBase64URL decodes a base64url value, tolerating optional padding.
func decodeBase64URL(s string) ([]byte, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	if padded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return padded, nil
	}
	return nil, errors.New("not valid base64url")
}
