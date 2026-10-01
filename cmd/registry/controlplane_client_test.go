package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBuildControlPlaneHTTPClientOrigin is a table test of the STARTUP origin +
// trust validation. It covers the loopback-http happy path, non-loopback http
// (must fail), both trust settings on plaintext http (must fail rather than be
// silently ignored), https with a missing trust mode (must fail), https with
// BOTH trust modes (must fail), invalid system-root boolean forms (must fail),
// and scoped/malformed origins (must fail). It also asserts the client always
// uses a DEDICATED transport clone (never the process-global transport).
func TestBuildControlPlaneHTTPClientOrigin(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		ca          string
		sysRoots    string
		wantErr     bool
		originErrOK bool // asserts the error is origin-data free (no scheme://host)
	}{
		{name: "loopback-http-happy", url: "http://127.0.0.1:8080"},
		{name: "localhost-http-happy", url: "http://localhost:8080"},
		{name: "ipv6-loopback-http-happy", url: "http://[::1]:8080"},
		{name: "loopback-http-with-ca-rejected", url: "http://127.0.0.1:8080", ca: "/nope", wantErr: true},
		{name: "loopback-http-with-system-roots-rejected", url: "http://127.0.0.1:8080", sysRoots: "1", wantErr: true},
		{name: "nonloopback-http", url: "http://cp.internal:8080", wantErr: true, originErrOK: true},
		{name: "https-missing-trust", url: "https://cp.internal:8080", wantErr: true},
		{name: "https-both-trust", url: "https://cp.internal:8080", ca: "/x", sysRoots: "1", wantErr: true},
		{name: "https-invalid-sysroots-true", url: "https://cp.internal:8080", sysRoots: "true", wantErr: true},
		{name: "https-invalid-sysroots-yes", url: "https://cp.internal:8080", sysRoots: "yes", wantErr: true},
		{name: "https-missing-ca-file", url: "https://cp.internal:8080", ca: "/nonexistent-ca.pem", wantErr: true},
		{name: "https-userinfo", url: "https://user:pass@cp.internal:8080", sysRoots: "1", wantErr: true, originErrOK: true},
		{name: "https-path", url: "https://cp.internal:8080/some/path", sysRoots: "1", wantErr: true, originErrOK: true},
		{name: "https-query", url: "https://cp.internal:8080?x=1", sysRoots: "1", wantErr: true, originErrOK: true},
		{name: "https-fragment", url: "https://cp.internal:8080#frag", sysRoots: "1", wantErr: true, originErrOK: true},
		{name: "malformed", url: "not a url", wantErr: true, originErrOK: true},
		{name: "no-scheme", url: "cp.internal:8080", wantErr: true, originErrOK: true},
		{name: "bad-scheme", url: "ftp://cp.internal", sysRoots: "1", wantErr: true, originErrOK: true},
		{name: "https-system-roots-happy", url: "https://cp.internal:8080", sysRoots: "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTROLPLANE_CA_BUNDLE_FILE", tc.ca)
			t.Setenv("CONTROLPLANE_USE_SYSTEM_ROOTS", tc.sysRoots)
			client, err := buildControlPlaneHTTPClient(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected startup validation to fail closed")
				}
				if tc.originErrOK && strings.Contains(err.Error(), "://") {
					t.Fatalf("origin-validation error must be data/path free, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client == nil || client.Transport == nil {
				t.Fatal("expected a usable client")
			}
			if client.Transport == http.DefaultTransport {
				t.Fatal("must use a DEDICATED transport clone, never the process-global transport")
			}
		})
	}
}

// --- TLS helpers (self-contained, no dependency on credential's test pkg) ---

func makeTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "uncloud-registry-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func makeLeafForHosts(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, hosts ...string) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: mustParseCert(t, der)}
}

func mustParseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestBuildControlPlaneHTTPClientTLS runs a REAL TLS handshake through the
// client built by buildControlPlaneHTTPClient, proving the chosen trust mode
// and pinned ServerName are actually enforced on the wire: CA-only happy
// path, untrusted CA (must fail), and host mismatch via ServerName pinning.
func TestBuildControlPlaneHTTPClientTLS(t *testing.T) {
	ca, caKey, caPEM := makeTestCA(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Intentionally a DIFFERENT, untrusted CA for the negative case.
	_, _, otherCAPEM := makeTestCA(t)
	otherCAFile := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(otherCAFile, otherCAPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		host string // DNS name the server cert is valid for
	}{
		{name: "ca-happy", host: "127.0.0.1"},
		{name: "host-mismatch", host: "localhost"}, // ServerName 127.0.0.1 not covered
	} {
		leaf := makeLeafForHosts(t, ca, caKey, tc.host)
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "ok")
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
		srv.StartTLS()
		t.Cleanup(srv.Close)

		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTROLPLANE_CA_BUNDLE_FILE", caFile)
			t.Setenv("CONTROLPLANE_USE_SYSTEM_ROOTS", "")
			client, err := buildControlPlaneHTTPClient(srv.URL)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			resp, err := client.Get(srv.URL)
			if tc.name == "ca-happy" {
				if err != nil {
					t.Fatalf("handshake with trusted CA must succeed: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("expected 200, got %d", resp.StatusCode)
				}
			} else {
				if err == nil {
					t.Fatal("host mismatch via ServerName pinning must fail the handshake")
				}
			}
		})
	}

	t.Run("untrusted-ca", func(t *testing.T) {
		// Drive a real handshake against a TLS server whose CA we do NOT trust.
		leaf := makeLeafForHosts(t, ca, caKey, "127.0.0.1")
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "ok")
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		t.Setenv("CONTROLPLANE_CA_BUNDLE_FILE", otherCAFile)
		t.Setenv("CONTROLPLANE_USE_SYSTEM_ROOTS", "")
		client, err := buildControlPlaneHTTPClient(srv.URL)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if _, err := client.Get(srv.URL); err == nil {
			t.Fatal("handshake against an untrusted CA must fail")
		}
	})
}

func TestBuildControlPlaneHTTPClientSystemRootsExplicit(t *testing.T) {
	t.Setenv("CONTROLPLANE_CA_BUNDLE_FILE", "")
	t.Setenv("CONTROLPLANE_USE_SYSTEM_ROOTS", "1")
	client, err := buildControlPlaneHTTPClient("https://cp.internal:8080")
	if err != nil {
		t.Fatalf("explicit system-roots construction must succeed: %v", err)
	}
	tr := client.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("system-roots mode must build an explicit root pool in the TLS config")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS minimum must be TLS1.2, got %d", tr.TLSClientConfig.MinVersion)
	}
	if tr.TLSClientConfig.ServerName != "cp.internal" {
		t.Fatalf("ServerName must be pinned to the exact origin host, got %q", tr.TLSClientConfig.ServerName)
	}
}
