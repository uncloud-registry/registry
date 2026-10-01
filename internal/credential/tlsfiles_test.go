package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTempFile writes content at mode and returns the path.
func writeTempFile(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// selfSignedCA writes a self-signed CA certificate PEM plus its private key
// PEM, and returns paths plus the parsed cert + signing key (so tests can mint
// leaves that chain to the CA).
func selfSignedCA(t *testing.T) (certPath, keyPath string, ca *x509.Certificate, caPriv *ecdsa.PrivateKey) {
	t.Helper()
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-internal-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(caPriv)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return writeTempFile(t, "ca.crt", string(pemBlock), 0o644),
		writeTempFile(t, "ca.key", string(keyBlock), 0o600), ca, caPriv
}

// leafSignedByCA issues a leaf cert directly signed by the given CA key, for
// the given host SAN, and returns the leaf cert/key PEM paths. The cert chains
// to ca with no intermediate, so the CA bundle alone establishes trust.
func leafSignedByCA(t *testing.T, ca *x509.Certificate, caPriv *ecdsa.PrivateKey, host string) (certPath, keyPath string) {
	t.Helper()
	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		leafTmpl.IPAddresses = []net.IP{ip}
	} else {
		leafTmpl.DNSNames = []string{host}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafPriv)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
	return writeTempFile(t, "leaf.crt", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})), 0o644),
		writeTempFile(t, "leaf.key", string(keyPEM), 0o600)
}

func TestLoadTLSKeyPairHappyPath(t *testing.T) {
	_, _, ca, caPriv := selfSignedCA(t)
	certPath, keyPath := leafSignedByCA(t, ca, caPriv, "internal.registry.test")
	if _, err := LoadTLSKeyPair(certPath, keyPath); err != nil {
		t.Fatalf("load valid keypair: %v", err)
	}
}

func TestLoadTLSKeyPairRejectsWorldReadableKey(t *testing.T) {
	_, _, ca, caPriv := selfSignedCA(t)
	certPath, keyPath := leafSignedByCA(t, ca, caPriv, "internal.registry.test")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod key world-readable: %v", err)
	}
	if _, err := LoadTLSKeyPair(certPath, keyPath); err == nil {
		t.Fatal("expected world-readable private key to be rejected")
	}
}

func TestLoadTLSKeyPairRejectsCertSymlink(t *testing.T) {
	_, _, ca, caPriv := selfSignedCA(t)
	certPath, keyPath := leafSignedByCA(t, ca, caPriv, "internal.registry.test")
	dir := t.TempDir()
	link := filepath.Join(dir, "cert-link")
	if err := os.Symlink(certPath, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadTLSKeyPair(link, keyPath); err == nil {
		t.Fatal("expected symlinked certificate to be rejected")
	}
}

func TestLoadTLSKeyPairRejectsMalformedKey(t *testing.T) {
	_, _, ca, caPriv := selfSignedCA(t)
	certPath, _ := leafSignedByCA(t, ca, caPriv, "internal.registry.test")
	badKey := writeTempFile(t, "bad.key", "not a pem key", 0o600)
	if _, err := LoadTLSKeyPair(certPath, badKey); err == nil {
		t.Fatal("expected malformed private key to be rejected")
	}
}

func TestLoadTLSKeyPairRejectsDirectory(t *testing.T) {
	if _, err := LoadTLSKeyPair(t.TempDir(), t.TempDir()); err == nil {
		t.Fatal("expected directory certificate to be rejected")
	}
}

func TestLoadCACertPoolHappyPath(t *testing.T) {
	caPath, _, _, _ := selfSignedCA(t)
	pool, err := LoadCACertPool(caPath)
	if err != nil {
		t.Fatalf("load CA pool: %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}
}

func TestLoadCACertPoolRejectsEmpty(t *testing.T) {
	p := writeTempFile(t, "empty.crt", "  \n\t", 0o644)
	if _, err := LoadCACertPool(p); err == nil {
		t.Fatal("expected whitespace-only CA bundle to be rejected")
	}
}

func TestLoadCACertPoolRejectsMalformed(t *testing.T) {
	p := writeTempFile(t, "bad.crt", "not a certificate at all", 0o644)
	if _, err := LoadCACertPool(p); err == nil {
		t.Fatal("expected malformed CA bundle to be rejected")
	}
}

func TestLoadCACertPoolRejectsSymlink(t *testing.T) {
	caPath, _, _, _ := selfSignedCA(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "ca-link")
	if err := os.Symlink(caPath, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadCACertPool(link); err == nil {
		t.Fatal("expected symlinked CA bundle to be rejected")
	}
}
