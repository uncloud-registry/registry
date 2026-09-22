// Package credential loads and validates high-entropy internal service
// credentials that are mounted from secure files. It follows the same
// trust-store discipline as the master-key and JWKS loaders: the path is opened
// exactly once without following a trailing symlink (O_NOFOLLOW), the opened
// descriptor is Fstat-validated as a regular, non-group/non-world-writable file
// with bounded size, and the bytes are read through a hard bound. Unsupported
// platforms fail closed. Errors never contain the path or the credential bytes.
package credential

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// maxSecretFileSize bounds how large an internal credential file may be. A
// credential is a handful of bytes; 64 KiB is far beyond any legitimate value
// while still bounding hostile input before parse.
const maxSecretFileSize = 64 * 1024

// minSecretBytes is the minimum accepted credential length. Internal service
// credentials must be high entropy; anything shorter is rejected outright so a
// truncated mount or a placeholder value can never become the shared secret.
const minSecretBytes = 32

// ErrSecretTooShort is returned when the loaded credential is below the
// minimum entropy bound.
var ErrSecretTooShort = errors.New("internal credential is too short (must be at least 32 bytes)")

// LoadSecretFile reads and validates an internal credential file, returning
// its exact trimmed bytes. It fails closed on unsupported platforms (never a
// weaker open) and never leaks the path or material in errors.
func LoadSecretFile(path string) ([]byte, error) {
	f, err := openSecretFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat internal credential file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("internal credential file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("internal credential file is not a regular file")
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return nil, errors.New("internal credential file must not be group or world writable")
	}
	if info.Size() > maxSecretFileSize {
		return nil, fmt.Errorf("internal credential file exceeds %d bytes", maxSecretFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read internal credential file: %w", err)
	}
	if len(data) > maxSecretFileSize {
		return nil, fmt.Errorf("internal credential file exceeds %d bytes", maxSecretFileSize)
	}
	return bytes.TrimSpace(data), nil
}

// ValidateSecret enforces the high-entropy bound on a loaded internal
// credential. The exact bytes (already whitespace-trimmed) must be non-empty
// and at least minSecretBytes long, so a truncated, empty, or placeholder
// credential can never be used as the internal service secret. Asymmetric
// (raw) slices are compared by the holder with subtle.ConstantTimeCompare; this
// only gates at-load acceptability.
func ValidateSecret(secret []byte) error {
	if len(secret) < minSecretBytes {
		return ErrSecretTooShort
	}
	return nil
}
