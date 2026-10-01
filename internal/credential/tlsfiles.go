// Secure loading of internal TLS certificate/private-key pairs and CA bundles,
// following the same descriptor discipline as LoadSecretFile: the path is
// opened exactly once without following a trailing symlink, the opened
// descriptor is Fstat-validated, and bytes are read through a hard bound.
// Errors never contain the path or any key material.
package credential

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
)

// maxTLSFileSize bounds how large a certificate, private key, or CA bundle file
// may be. Certificates/keys are tiny; a bound defeats trivial resource abuse.
const maxTLSFileSize = 512 * 1024

// openRegularFileNoFollow opens path once for reading without following a
// trailing symlink or blocking on special files. The caller must still
// Stat-validate the returned descriptor as a regular file (and, for a private
// key, enforce owner-only permissions). The error never contains the path.
func openRegularFileNoFollow(path string) (*os.File, error) {
	f, err := openSecretFile(path)
	if err != nil {
		// openSecretFile wraps with "open internal credential file"; reuse it
		// so we keep a single, consistent, nofollow+nonblock+cloexec open path.
		return nil, err
	}
	return f, nil
}

// readRegularFileBounded opens path via the descriptor-safe nofollow path,
// validates the descriptor as a REGULAR file (rejecting symlinks, directories,
// devices, FIFOs), enforces an optional owner-only permission rule, and reads
// at most maxTLSFileSize bytes. It never returns the path or the raw error
// from opening/reading.
func readRegularFileBounded(path string, requireOwnerOnly bool) ([]byte, error) {
	f, err := openRegularFileNoFollow(path)
	if err != nil {
		return nil, errors.New("open TLS file failed")
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("stat TLS file failed")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("TLS file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("TLS file is not a regular file")
	}
	if requireOwnerOnly {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, errors.New("TLS private key file must be readable/writable only by its owner")
		}
	}
	if info.Size() > maxTLSFileSize {
		return nil, errors.New("TLS file exceeds the size bound")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTLSFileSize+1))
	if err != nil {
		return nil, errors.New("read TLS file failed")
	}
	if len(data) > maxTLSFileSize {
		return nil, errors.New("TLS file exceeds the size bound")
	}
	return data, nil
}

// LoadTLSKeyPair securely loads an internal X.509 certificate chain and its
// private key, then parses and validates them together with
// tls.X509KeyPair POOLS (in-memory, from bytes). The certificate MAY be
// world-readable (0644) but MUST be a regular file; the PRIVATE KEY must be a
// regular, OWNER-ONLY file (no group/world permission bits, mode&077==0) and is
// never symlink-followed. The loaded key bytes are wiped after parsing. Errors
// are data/path-free (this deliberately replaces the path-based
// tls.LoadX509KeyPair, which leaks paths and does no permission checks).
func LoadTLSKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	// Cert: regular file, permissions not enforced (public material).
	certPEM, err := readRegularFileBounded(certFile, false)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate: %w", err)
	}
	// Key: regular + owner-only; never path-based.
	keyPEM, err := readRegularFileBounded(keyFile, true)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("private key: %w", err)
	}
	defer wipeBytes(keyPEM)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, errors.New("invalid TLS certificate and private key pair")
	}
	return cert, nil
}

// LoadCACertPool securely loads a private/internal CA bundle from a regular
// file (world-readable 0644 is acceptable — it is PUBLIC material), building
// an x509.CertPool. A missing, empty, unparseable, or otherwise malformed pool
// fails closed (never falls back to system roots implicitly). Errors are
// data/path-free.
func LoadCACertPool(caFile string) (*x509.CertPool, error) {
	data, err := readRegularFileBounded(caFile, false)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("CA bundle is empty")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("CA bundle contains no parseable certificates")
	}
	return pool, nil
}

// wipeBytes zeroes the provided byte slice in place.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
