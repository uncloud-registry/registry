package swarm

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func TestBeeDocumentStoreReadsBZZAndFeedReferences(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bzz/alice.eth":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":1}`))
		case "/feeds/owner/topic":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"repo":"backend/api"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	store := NewBeeDocumentStore(server.URL, server.Client())

	root, err := store.Read(context.Background(), "alice.eth")
	if err != nil {
		t.Fatalf("read bzz document: %v", err)
	}
	if string(root) != `{"version":1}` {
		t.Fatalf("unexpected root document: %s", root)
	}

	state, err := store.Read(context.Background(), "feed://owner/topic")
	if err != nil {
		t.Fatalf("read feed document: %v", err)
	}
	if string(state) != `{"repo":"backend/api"}` {
		t.Fatalf("unexpected feed document: %s", state)
	}
}

func TestBeeObjectStorePutAndGet(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/bytes":
			if got := r.Header.Get("Swarm-Postage-Batch-Id"); got != "batch-1" {
				t.Fatalf("unexpected batch id header: %s", got)
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != "hello" {
				t.Fatalf("unexpected put body: %s", body)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"reference":"swarm-ref-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/bytes/swarm-ref-1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("hello"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	store := NewBeeObjectStore(server.URL, server.Client())
	ref, err := store.Put(context.Background(), []byte("hello"), "batch-1")
	if err != nil {
		t.Fatalf("put object: %v", err)
	}
	if ref != "swarm-ref-1" {
		t.Fatalf("unexpected ref: %s", ref)
	}

	data, err := store.Get(context.Background(), ref)
	if err != nil {
		t.Fatalf("get object: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("unexpected data: %s", data)
	}
}

func TestSubdomainENSRegistryResolver(t *testing.T) {
	t.Parallel()

	resolver := SubdomainENSRegistryResolver{
		HostMap: map[string]string{"alice.uncloud-registry.com": "0xaliceowner"},
	}
	registry, err := resolver.ResolveRegistry(context.Background(), "alice.uncloud-registry.com")
	if err != nil {
		t.Fatalf("resolve registry identity: %v", err)
	}
	if registry.Owner != "0xaliceowner" {
		t.Fatalf("unexpected resolved owner: %s", registry.Owner)
	}
}

func TestBeeSequenceFeedUpdaterPublishesSOCUpdate(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])

	var gotChunkBody []byte
	var gotSOCPath string
	var gotSOCSig string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/feeds/"+owner+"/abcd":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/chunks":
			body, _ := io.ReadAll(r.Body)
			gotChunkBody = body
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
			gotSOCPath = r.URL.Path
			gotSOCSig = r.URL.Query().Get("sig")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"reference":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
	if err != nil {
		t.Fatalf("create updater: %v", err)
	}

	if err := updater.UpdateFeed(context.Background(), "feed://"+owner+"/abcd", "repo-state-ref"); err != nil {
		t.Fatalf("update feed: %v", err)
	}

	if len(gotChunkBody) == 0 {
		t.Fatal("expected chunk upload body")
	}
	if gotSOCPath == "" {
		t.Fatal("expected soc upload path")
	}
	if gotSOCSig == "" {
		t.Fatal("expected soc signature query")
	}
}

// TestNewBeeSequenceFeedUpdaterBytes pins the raw-bytes signer constructor:
// it accepts exactly the 32 private-key bytes (no hex-string intermediate)
// and rejects nil, short, and long inputs without leaking key material.
func TestNewBeeSequenceFeedUpdaterBytes(t *testing.T) {
	t.Parallel()
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	raw := ethcrypto.FromECDSA(key)
	if len(raw) != 32 {
		t.Fatalf("expected 32 raw key bytes, got %d", len(raw))
	}
	updater, err := NewBeeSequenceFeedUpdaterBytes("http://bee.invalid", nil, raw)
	if err != nil {
		t.Fatalf("bytes constructor with valid key: %v", err)
	}
	wantOwner := strings.ToLower(ethcrypto.PubkeyToAddress(key.PublicKey).Hex())
	if got := strings.ToLower(ethcrypto.PubkeyToAddress(updater.PrivateKey.PublicKey).Hex()); got != wantOwner {
		t.Fatalf("signer owner mismatch: got %s want %s", got, wantOwner)
	}

	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", raw[:31]},
		{"too long", append(append([]byte(nil), raw...), 0x00)},
	} {
		if _, err := NewBeeSequenceFeedUpdaterBytes("http://bee.invalid", nil, tc.key); err == nil {
			t.Fatalf("%s key must be rejected", tc.name)
		}
	}
}

// hex64 returns a 64-char hex reference from a deterministic repeating byte so
// tests and reconciler integration model the exact object-store output.
func hex64(b byte) string {
	buf := make([]byte, 64)
	for i := range buf {
		buf[i] = b
	}
	return string(buf)
}

// feedRef builds a canonical feed reference for a given owner.
func feedRef(owner string) string { return "feed://" + owner + "/aaaa" }

// TestBeeFeedResolverResolvesFeedBodyAsReference is the core production feed
// contract: the feed endpoint returns the raw object reference (NOT an 8-byte
// chunk prefix). It reports 200 with exactly the reference body, and the
// resolver returns its canonical (lowercased) form.
func TestBeeFeedResolverResolvesFeedBodyAsReference(t *testing.T) {
	t.Parallel()
	const owner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const ref = "AaBbCcDdEeFf00112233445566778899aabbccddeeff00112233445566778899"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/feeds/"+owner+"/aaaa" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ref))
	}))
	defer server.Close()

	resolver := NewBeeFeedResolver(server.URL, server.Client())
	got, err := resolver.ResolveFeed(context.Background(), feedRef(owner))
	if err != nil {
		t.Fatalf("resolve feed: %v", err)
	}
	if got != strings.ToLower(ref) {
		t.Fatalf("expected canonical lowercase ref %q, got %q", strings.ToLower(ref), got)
	}
}

// TestBeeFeedResolverNewConstructorNormalizesBaseURL proves the constructor
// trims trailing slashes and defaults a nil client to a usable one, and that
// resolving still works with a trailing-slash base URL.
func TestBeeFeedResolverNewConstructorNormalizesBaseURL(t *testing.T) {
	t.Parallel()
	const owner = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/feeds/"+owner+"/aaaa" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(hex64('b')))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	resolver := NewBeeFeedResolver(server.URL+"/", nil)
	got, err := resolver.ResolveFeed(context.Background(), feedRef(owner))
	if err != nil {
		t.Fatalf("resolve with trailing-slash base URL: %v", err)
	}
	if got != hex64('b') {
		t.Fatalf("unexpected resolved ref: %q", got)
	}
	// The constructor must never leave a nil client behind.
	if resolver.HTTPClient == nil {
		t.Fatal("constructor must guarantee a non-nil HTTP client")
	}
}

// TestBeeFeedResolverZeroValueFailsClosed proves a direct zero-value struct
// (no base URL) fails with an error and never panics.
func TestBeeFeedResolverZeroValueFailsClosed(t *testing.T) {
	t.Parallel()
	resolver := BeeFeedResolver{}
	if _, err := resolver.ResolveFeed(context.Background(), feedRef("owner")); err == nil {
		t.Fatal("expected a zero-value resolver (no base URL) to fail, got nil")
	}
}

// TestBeeFeedResolverEmptyBodyRejects proves an empty 200 body is not a
// reference.
func TestBeeFeedResolverEmptyBodyRejects(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("   "))
	}))
	defer server.Close()
	resolver := NewBeeFeedResolver(server.URL, server.Client())
	if _, err := resolver.ResolveFeed(context.Background(), feedRef("owner")); err == nil {
		t.Fatal("expected an empty response body to be rejected")
	}
}

// TestBeeFeedResolverMalformedBodyRejects proves a non-64-hex (or wrong-length)
// body is rejected.
func TestBeeFeedResolverMalformedBodyRejects(t *testing.T) {
	t.Parallel()
	for _, body := range []string{"short", strings.Repeat("g", 64), "not-hex!!!", hex64('a') + "extra"} {
		body := body
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			resolver := NewBeeFeedResolver(server.URL, server.Client())
			if _, err := resolver.ResolveFeed(context.Background(), feedRef("owner")); err == nil {
				t.Fatalf("expected malformed body %q to be rejected", body)
			}
		})
	}
}

// TestBeeFeedResolverOversizeBodyRejects proves a success body beyond the
// reference bound is rejected rather than silently truncated.
func TestBeeFeedResolverOversizeBodyRejects(t *testing.T) {
	t.Parallel()
	big := hex64('a') + strings.Repeat("0", beeFeedResolveMaxBody) // far over bound
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(big))
	}))
	defer server.Close()
	resolver := NewBeeFeedResolver(server.URL, server.Client())
	if _, err := resolver.ResolveFeed(context.Background(), feedRef("owner")); err == nil {
		t.Fatal("expected an oversize success body to be rejected")
	}
}

// TestBeeFeedResolverNon200ErrorIsDataFree proves a non-200 response returns an
// error WITHOUT echoing the raw Bee body, even when the body is large.
func TestBeeFeedResolverNon200ErrorIsDataFree(t *testing.T) {
	t.Parallel()
	secret := "internal-secret-" + strings.Repeat("x", 500)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(secret))
	}))
	defer server.Close()
	resolver := NewBeeFeedResolver(server.URL, server.Client())
	_, err := resolver.ResolveFeed(context.Background(), feedRef("owner"))
	if err == nil {
		t.Fatal("expected a non-200 to be an error")
	}
	if strings.Contains(err.Error(), "internal-secret") || strings.Contains(err.Error(), strings.Repeat("x", 8)) {
		t.Fatalf("error must not leak the raw Bee body: %v", err)
	}
}

// TestBeeFeedResolverRespectsCallerDeadline proves a stalled Bee node cannot
// block indefinitely: the resolver imposes (or, when the caller supplied one,
// respects) a per-request context deadline.
func TestBeeFeedResolverRespectsCallerDeadline(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release // stall until released
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(hex64('a')))
	}))
	// LIFO cleanup: release the stalled handler BEFORE the server closes, so
	// server.Close() never waits on the handler goroutine.
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	resolver := NewBeeFeedResolver(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := resolver.ResolveFeed(ctx, feedRef("owner"))
	if err == nil {
		<-started
		t.Fatal("expected a stalled request to time out")
	}
	<-started
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled request must abort near the deadline, took %v", elapsed)
	}
}

// TestBeeFeedResolverCanceledContext proves a cancelled context aborts the
// request.
func TestBeeFeedResolverCanceledContext(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	defer close(release)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(hex64('a')))
	}))
	defer server.Close()

	resolver := NewBeeFeedResolver(server.URL, server.Client())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveFeed(ctx, feedRef("owner")); err == nil {
		t.Fatal("expected a cancelled context to abort the request")
	}
}

// closingBody wraps a ReadCloser and signals once via a channel when Close is
// called, so a test can prove the resolver always closes the response body.
type closingBody struct {
	io.ReadCloser
	closed chan struct{}
	once   sync.Once
}

func (c *closingBody) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.ReadCloser.Close()
}

// bodyTrackingTransport wraps responses so their body Close is observable.
type bodyTrackingTransport struct {
	base   http.RoundTripper
	closed chan struct{}
}

func (t *bodyTrackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &closingBody{ReadCloser: resp.Body, closed: t.closed}
	return resp, nil
}

// TestBeeFeedResolverClosesBody proves the response body is always closed on
// both success and error paths.
func TestBeeFeedResolverClosesBody(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"success", http.StatusOK, hex64('a')},
		{"non-200", http.StatusBadRequest, "boom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closed := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			rt := &bodyTrackingTransport{base: &http.Transport{Proxy: http.ProxyFromEnvironment},
				closed: closed}
			client := &http.Client{Transport: rt}
			resolver := NewBeeFeedResolver(server.URL, client)
			_, _ = resolver.ResolveFeed(context.Background(), feedRef("owner"))
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("resolver must close the response body")
			}
		})
	}
}

// TestBeeFeedResolverBaseURLPathEscaping proves owner/topic are path-escaped
// so a malicious feed ref cannot smuggle a path segment.
func TestBeeFeedResolverBaseURLPathEscaping(t *testing.T) {
	t.Parallel()
	// feed://<owner>/<topic>; a topic containing '/' or spaces must be
	// path-escaped so it cannot smuggle additional path segments or query text.
	const want = "/feeds/a/b%2Fc%2Faa%2Fbb%20cc"
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(hex64('c')))
	}))
	defer server.Close()
	resolver := NewBeeFeedResolver(server.URL, server.Client())
	if _, err := resolver.ResolveFeed(context.Background(), "feed://a/b/c/aa/bb cc"); err != nil {
		t.Fatalf("resolve escaped feed: %v", err)
	}
	if gotPath != want {
		t.Fatalf("expected escaped path %q, got %q", want, gotPath)
	}
}

// TestCanonicalObjectRef pins the canonical reference normalization used by
// the reconciler: genuine 64-hex refs compare case-insensitively, symbolic and
// malformed refs pass through trimmed but otherwise unchanged.
func TestCanonicalObjectRef(t *testing.T) {
	t.Parallel()
	if got := CanonicalObjectRef(hex64('A')); got != hex64('a') {
		t.Fatalf("upper hex must lowercase, got %q", got)
	}
	if got := CanonicalObjectRef("  obj-ref-1  "); got != "obj-ref-1" {
		t.Fatalf("symbolic ref must pass through trimmed, got %q", got)
	}
	if got := CanonicalObjectRef("not-hex"); got != "not-hex" {
		t.Fatalf("malformed ref must pass through, got %q", got)
	}
	if got := CanonicalObjectRef(""); got != "" {
		t.Fatalf("empty ref must stay empty, got %q", got)
	}
}
