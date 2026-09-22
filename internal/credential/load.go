// Package credential loads and validates high-entropy internal service
// credentials mounted from secure files. It follows the same trust-store
// discipline as the master-key and JWKS loaders: the path is opened exactly
// once without following a trailing symlink (O_NOFOLLOW/O_NONBLOCK), the opened
// descriptor is Fstat-validated as a regular OWNER-ONLY file (no group or world
// permission bits) with bounded size, and the bytes are read through a hard
// bound. Unsupported platforms fail closed. Errors never contain the path or
// the credential bytes.
package credential

import (
	"bytes"
	"errors"
	"io"
	"os"
)

// maxSecretFileSize bounds how large an internal credential file may be.
const maxSecretFileSize = 64 * 1024

// minSecretBytes is the minimum accepted credential length.
const minSecretBytes = 32

// ErrSecretTooShort is returned when the loaded credential is below the
// minimum entropy bound. It is data-free.
var ErrSecretTooShort = errors.New("internal credential is too short (must be at least 32 bytes)")

// ErrSecretWeak is returned when the loaded credential passes the length bound
// but is structurally predictable (low byte diversity, an exact repeated
// period, a monotonic/sequential run, or a known common literal). It is
// data-free and never echoes the value.
var ErrSecretWeak = errors.New("internal credential is not sufficiently random")

// ErrSecretFormat is returned when the credential file violates the exact
// single-terminal-newline format (CRLF, multiple newlines, a non-terminal
// newline, or remaining leading/trailing ASCII whitespace or control bytes).
var ErrSecretFormat = errors.New("internal credential file must be a single line with at most one terminal newline and no surrounding whitespace")

// LoadSecretFile reads and validates an internal credential file, returning
// its exact bytes (with at most one terminal LF removed). It fails closed on
// unsupported platforms, non-owner-only permissions, and malformed content,
// and never leaks the path or the material.
func LoadSecretFile(path string) ([]byte, error) {
	f, err := openSecretFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("stat internal credential file failed")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("internal credential file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("internal credential file is not a regular file")
	}
	// Owner-only: NO group or world permission bits may be set (mode & 0077).
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, errors.New("internal credential file must be readable/writable only by its owner (0600)")
	}
	if info.Size() > maxSecretFileSize {
		return nil, errors.New("internal credential file exceeds the size bound")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFileSize+1))
	if err != nil {
		return nil, errors.New("read internal credential file failed")
	}
	if len(data) > maxSecretFileSize {
		return nil, errors.New("internal credential file exceeds the size bound")
	}
	return parseSecretBytes(data)
}

// parseSecretBytes applies the exact file-format rule: the raw bytes are the
// secret, with AT MOST ONE terminal LF removed. CRLF, multiple newlines, a
// non-terminal newline, or any remaining leading/trailing ASCII whitespace or
// control byte is REJECTED (never silently trimmed, and never a broad
// TrimSpace which would mutate the secret). The accepted bytes are returned
// unmutated otherwise.
func parseSecretBytes(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrSecretFormat
	}
	// Any CR (CRLF or a bare carriage return) is rejected outright.
	if bytes.IndexByte(data, '\r') >= 0 {
		return nil, ErrSecretFormat
	}
	// Count newlines: more than one is multiple newlines; exactly one must be
	// the terminal byte.
	nLF := bytes.Count(data, []byte{'\n'})
	if nLF > 1 {
		return nil, ErrSecretFormat
	}
	if nLF == 1 {
		if data[len(data)-1] != '\n' {
			return nil, ErrSecretFormat
		}
		data = data[:len(data)-1]
	}
	if len(data) == 0 {
		return nil, ErrSecretFormat
	}
	// No remaining leading/trailing ASCII whitespace or control byte. Interior
	// whitespace is legitimate secret data.
	if isASCIIWhitespaceOrControl(data[0]) || isASCIIWhitespaceOrControl(data[len(data)-1]) {
		return nil, ErrSecretFormat
	}
	return data, nil
}

// isASCIIWhitespaceOrControl reports whether b is ASCII whitespace (space,
// tab, LF, CR, VT, FF) or a control byte (below space, or DEL). Interior
// whitespace is allowed; surrounding whitespace is rejected.
func isASCIIWhitespaceOrControl(b byte) bool {
	return b < 0x21 || b == 0x7f
}

// ValidateSecret enforces the high-entropy bound on a loaded internal
// credential: at least minSecretBytes of high byte diversity with no repeated
// period, no monotonic/sequential run, and no known common literal. The exact
// bytes are never mutated or echoed; asymmetric raw slices are compared by the
// holder with subtle.ConstantTimeCompare, so this only gates acceptability.
func ValidateSecret(secret []byte) error {
	if len(secret) < minSecretBytes {
		return ErrSecretTooShort
	}
	if weakSecret(secret) {
		return ErrSecretWeak
	}
	return nil
}

// weakSecret reports whether a 32+ byte secret is structurally predictable.
func weakSecret(s []byte) bool {
	n := len(s)
	distinct := make(map[byte]struct{}, n)
	for _, b := range s {
		distinct[b] = struct{}{}
	}
	if len(distinct) < 16 {
		return true
	}
	// An exact repeated block of ANY period p covering the whole value.
	for p := 1; p <= n/2; p++ {
		if n%p != 0 {
			continue
		}
		block := s[:p]
		whole := true
		for i := p; i < n; i += p {
			if !bytes.Equal(s[i:i+p], block) {
				whole = false
				break
			}
		}
		if whole {
			return true
		}
	}
	if predictableSequence(s) {
		return true
	}
	for _, known := range knownWeakSecrets {
		if string(s) == known {
			return true
		}
	}
	return false
}

// predictableSequence reports whether s is a constant-delta arithmetic
// progression or a strictly increasing/decreasing byte run.
func predictableSequence(s []byte) bool {
	n := len(s)
	if n < 3 {
		return false
	}
	d := int(s[1]) - int(s[0])
	if d != 0 {
		all := true
		for i := 2; i < n; i++ {
			if int(s[i])-int(s[i-1]) != d {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	inc, dec := true, true
	for i := 1; i < n; i++ {
		if s[i] <= s[i-1] {
			inc = false
		}
		if s[i] >= s[i-1] {
			dec = false
		}
	}
	return inc || dec
}

// knownWeakSecrets is a small table of common predictable 32+ byte literals.
var knownWeakSecrets = []string{
	"0123456789abcdef0123456789abcdef",
	"1234567890abcdef1234567890abcdef",
	"0123456789abcdefghijklmnopqrstuv",
	"abcdefghijklmnopqrstuvwxyz0123456789",
	"abcdefghijklmnopqrstuvwxyz012345",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"abcabcabcabcabcabcabcabcabcabcab",
	"deadbeefdeadbeefdeadbeefdeadbeef",
	"passwordpasswordpasswordpassword",
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
}
