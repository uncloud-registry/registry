package swarm

import (
	"bytes"
	"context"
	"encoding/binary"
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

func TestBeeSequenceFeedUpdaterPublishesExplicitBatchBinarySOCUpdate(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])

	// Task 11 contract: the reference is a 64-hex immutable object ref (32
	// bytes) and the feed chunk payload is the 8-byte little-endian span (=32)
	// followed by the DECODED BINARY 32 bytes — never the 64 ASCII hex chars.
	const ref = "abababababababababababababababababababababababababababababababab"
	const batch = "cdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdef"
	refBytes, err := hex.DecodeString(ref)
	if err != nil {
		t.Fatalf("decode ref: %v", err)
	}
	// The exact wire body /chunks and /soc must receive: span = 32 (LE) then
	// the decoded 32 binary bytes. Constructed explicitly so the test does not
	// share a helper with the implementation under test.
	wantChunk := make([]byte, 8+32)
	binary.LittleEndian.PutUint64(wantChunk[:8], 32)
	copy(wantChunk[8:], refBytes)

	var gotChunkBody []byte
	var gotSOCBody []byte
	var gotSOCPath string
	var gotSOCSig string
	var gotChunkBatch, gotSOCBatch string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/feeds/"+owner+"/"+strings.Repeat("ab", 32):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/chunks":
			body, _ := io.ReadAll(r.Body)
			gotChunkBody = body
			gotChunkBatch = r.Header.Get("Swarm-Postage-Batch-Id")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
			body, _ := io.ReadAll(r.Body)
			gotSOCBody = body
			gotSOCPath = r.URL.Path
			gotSOCSig = r.URL.Query().Get("sig")
			gotSOCBatch = r.Header.Get("Swarm-Postage-Batch-Id")
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

	if err := updater.Update(context.Background(), FeedUpdate{
		Feed:      "feed://" + owner + "/" + strings.Repeat("ab", 32),
		Reference: ref,
		BatchID:   batch,
	}); err != nil {
		t.Fatalf("update feed: %v", err)
	}

	// /chunks and /soc must receive the IDENTICAL exact binary framed body:
	// 8-byte little-endian span = 32 + the decoded 32-byte reference. None of
	// the 64 ASCII hex reference bytes may appear in the payload.
	if !bytes.Equal(gotChunkBody, wantChunk) {
		t.Fatalf("chunk body must be span=32 + decoded binary reference:\n got %x\nwant %x", gotChunkBody, wantChunk)
	}
	if !bytes.Equal(gotSOCBody, wantChunk) {
		t.Fatalf("soc body must carry the same span=32 + decoded binary reference:\n got %x\nwant %x", gotSOCBody, wantChunk)
	}
	if bytes.Contains(gotChunkBody, []byte(ref)) {
		t.Fatal("chunk body must never carry the 64 ASCII hex reference bytes")
	}
	if gotSOCPath == "" {
		t.Fatal("expected soc upload path")
	}
	if !strings.HasPrefix(gotSOCPath, "/soc/"+owner+"/") {
		t.Fatalf("soc upload must target the signer-owned feed owner, path %q", gotSOCPath)
	}
	if gotSOCSig == "" {
		t.Fatal("expected soc signature query")
	}
	// Sequence index use: the feed was not found, so the updater must use a
	// zero (8-byte) next index and derive the SOC identifier from the topic +
	// that zero index. The identifier is the hex of keccak(topic || zeros).
	topicBytes, err := hex.DecodeString(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("decode topic: %v", err)
	}
	wantID := hex.EncodeToString(ethcrypto.Keccak256(append(append([]byte{}, topicBytes...), make([]byte, 8)...)))
	// The path is /soc/<owner>/<identifier>?sig=...; assert identifier prefix.
	pathID := strings.TrimPrefix(gotSOCPath, "/soc/"+owner+"/")
	pathID = strings.SplitN(pathID, "?", 2)[0]
	if pathID != wantID {
		t.Fatalf("soc identifier must derive from topic+zero next index:\n got %s\nwant %s", pathID, wantID)
	}
	// The EXPLICIT postage batch must be carried unchanged on BOTH endpoints
	// and must never be substituted with the content reference.
	if gotChunkBatch != batch {
		t.Fatalf("chunk batch id must be the explicit batch, got %q", gotChunkBatch)
	}
	if gotSOCBatch != batch {
		t.Fatalf("soc batch id must be the explicit batch, got %q", gotSOCBatch)
	}
	if gotChunkBatch == ref || gotSOCBatch == ref {
		t.Fatal("batch id must never equal the content reference")
	}
}

// TestBeeSequenceFeedUpdaterRespectsNextIndexHeader proves the updater reads
// the Swarm-Feed-Index-Next header from a non-404 feed lookup and derives the
// SOC next-index identifier from it (sequence index use), rather than always
// assuming the zero index.
func TestBeeSequenceFeedUpdaterRespectsNextIndexHeader(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	topic := strings.Repeat("ab", 32)  // 64 hex
	const nextHex = "1122334455667788" // 8 bytes, non-zero
	const ref = "abababababababababababababababababababababababababababababababab"
	const batch = "cdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdef"

	var gotSOCPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/feeds/"+owner+"/"+topic:
			w.Header().Set("Swarm-Feed-Index-Next", nextHex)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/chunks":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
			gotSOCPath = r.URL.Path
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
	if err != nil {
		t.Fatalf("create updater: %v", err)
	}
	if err := updater.Update(context.Background(), FeedUpdate{
		Feed:      "feed://" + owner + "/" + topic,
		Reference: ref,
		BatchID:   batch,
	}); err != nil {
		t.Fatalf("update feed: %v", err)
	}

	nextBytes, _ := hex.DecodeString(nextHex)
	topicBytes, _ := hex.DecodeString(topic)
	wantID := hex.EncodeToString(ethcrypto.Keccak256(append(append([]byte{}, topicBytes...), nextBytes...)))
	pathID := strings.TrimPrefix(gotSOCPath, "/soc/"+owner+"/")
	pathID = strings.SplitN(pathID, "?", 2)[0]
	if pathID != wantID {
		t.Fatalf("identifier must derive from topic+next-index header:\n got %s\nwant %s", pathID, wantID)
	}
}

// TestBeeSequenceFeedUpdaterOwnerMismatchFailsBeforeNetwork proves an
// owner/signer mismatch is rejected BEFORE any network call.
func TestBeeSequenceFeedUpdaterOwnerMismatchFailsBeforeNetwork(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	var touched bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		touched = true
		http.NotFound(w, r)
	}))
	defer server.Close()

	updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
	if err != nil {
		t.Fatalf("create updater: %v", err)
	}
	const wrongOwner = "ffffffffffffffffffffffffffffffffffffffff"
	if err := updater.Update(context.Background(), FeedUpdate{
		Feed:      "feed://" + wrongOwner + "/" + strings.Repeat("ab", 32),
		Reference: strings.Repeat("ab", 32),
		BatchID:   strings.Repeat("cd", 32),
	}); err == nil {
		t.Fatal("expected an owner/signer mismatch to fail")
	}
	if touched {
		t.Fatal("owner mismatch must fail before any network call")
	}
}

// TestBeeSequenceFeedUpdaterZeroValueFailsClosed proves a direct zero-value
// exported struct (no base URL, no signer key, nil client) returns a data-free
// error rather than panicking.
func TestBeeSequenceFeedUpdaterZeroValueFailsClosed(t *testing.T) {
	t.Parallel()
	var updater BeeSequenceFeedUpdater
	if err := updater.Update(context.Background(), FeedUpdate{
		Feed:      "feed://" + strings.Repeat("ab", 20) + "/" + strings.Repeat("ab", 32),
		Reference: strings.Repeat("ab", 32),
		BatchID:   strings.Repeat("cd", 32),
	}); err == nil {
		t.Fatal("expected a zero-value updater to fail closed")
	}
}

// TestBeeSequenceFeedUpdaterWriterErrorIsDataFree proves a non-2xx writer
// response returns a status-only error and NEVER leaks the raw Bee body.
func TestBeeSequenceFeedUpdaterWriterErrorIsDataFree(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	secret := "internal-secret-" + strings.Repeat("x", 200)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/feeds/"+owner+"/abcd":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(secret))
		case r.Method == http.MethodPost && r.URL.Path == "/chunks":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(secret))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(secret))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
	if err != nil {
		t.Fatalf("create updater: %v", err)
	}
	// feed lookup (GET) error
	if _, err := updater.nextSequenceIndex(context.Background(), owner, "abcd", false); err != nil {
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), strings.Repeat("x", 8)) {
			t.Fatalf("feed lookup error must not leak the raw body: %v", err)
		}
	}
	// chunk upload error
	if _, err := updater.uploadChunk(context.Background(), []byte("data"), "batch"); err != nil {
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), strings.Repeat("x", 8)) {
			t.Fatalf("chunk upload error must not leak the raw body: %v", err)
		}
	}
	// soc upload error
	if err := updater.uploadSOC(context.Background(), owner, []byte{1, 2}, []byte{3, 4}, []byte("data"), "batch", false); err != nil {
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), strings.Repeat("x", 8)) {
			t.Fatalf("soc upload error must not leak the raw body: %v", err)
		}
	}
}

// TestBeeSequenceFeedUpdaterWriterClosesBody proves the writer always closes the
// response body on success and error paths.
func TestBeeSequenceFeedUpdaterWriterClosesBody(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	for _, tc := range []struct {
		name string
		seed func(t *testing.T, w http.ResponseWriter, r *http.Request)
		fn   func(t *testing.T, u *BeeSequenceFeedUpdater)
	}{
		{"chunk success", func(t *testing.T, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
		}, func(t *testing.T, u *BeeSequenceFeedUpdater) {
			if _, err := u.uploadChunk(context.Background(), []byte("data"), "batch"); err != nil {
				t.Fatalf("chunk upload: %v", err)
			}
		}},
		{"chunk error", func(t *testing.T, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("boom"))
		}, func(t *testing.T, u *BeeSequenceFeedUpdater) {
			_, _ = u.uploadChunk(context.Background(), []byte("data"), "batch")
		}},
		{"lookup success", func(t *testing.T, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Swarm-Feed-Index-Next", "0000000000000000")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}, func(t *testing.T, u *BeeSequenceFeedUpdater) {
			if _, err := u.nextSequenceIndex(context.Background(), owner, "abcd", false); err != nil {
				t.Fatalf("feed lookup: %v", err)
			}
		}},
		{"lookup error", func(t *testing.T, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("boom"))
		}, func(t *testing.T, u *BeeSequenceFeedUpdater) {
			_, _ = u.nextSequenceIndex(context.Background(), owner, "abcd", false)
		}},
		{"soc success", func(t *testing.T, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		}, func(t *testing.T, u *BeeSequenceFeedUpdater) {
			if err := u.uploadSOC(context.Background(), owner, []byte{1}, []byte{2, 3, 4, 5}, []byte("data"), "batch", false); err != nil {
				t.Fatalf("soc upload: %v", err)
			}
		}},
		{"soc error", func(t *testing.T, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("boom"))
		}, func(t *testing.T, u *BeeSequenceFeedUpdater) {
			_ = u.uploadSOC(context.Background(), owner, []byte{1}, []byte{2, 3, 4, 5}, []byte("data"), "batch", false)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closed := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.seed(t, w, r)
			}))
			t.Cleanup(server.Close)
			rt := &bodyTrackingTransport{base: &http.Transport{Proxy: http.ProxyFromEnvironment}, closed: closed}
			client := &http.Client{Transport: rt}
			updater, err := NewBeeSequenceFeedUpdater(server.URL, client, hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
			if err != nil {
				t.Fatalf("create updater: %v", err)
			}
			var wg sync.WaitGroup
			wg.Add(1)
			go func() { defer wg.Done(); tc.fn(t, updater) }()
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("writer must close the response body")
			}
			wg.Wait()
		})
	}
}

// TestBeeSequenceFeedUpdaterWriterStalledRespectsDeadline proves a stalled Bee
// writer request cannot block indefinitely: the per-request context deadline
// aborts it.
func TestBeeSequenceFeedUpdaterWriterStalledRespectsDeadline(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	release := make(chan struct{})
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
	if err != nil {
		t.Fatalf("create updater: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := updater.nextSequenceIndex(ctx, owner, "abcd", false); err == nil {
		<-started
		t.Fatal("expected a stalled lookup to time out")
	}
	<-started
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled writer request must abort near the deadline, took %v", elapsed)
	}
}

// TestBeeSequenceFeedUpdaterOversizeChunkResponseRejected proves a chunk upload
// response beyond the body bound is rejected (not silently truncated) and the
// write fails closed.
func TestBeeSequenceFeedUpdaterOversizeChunkResponseRejected(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	big := `{"reference":"aaaa..."` + strings.Repeat("x", beeFeedWriteMaxBody)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(big))
	}))
	defer server.Close()
	updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
	if err != nil {
		t.Fatalf("create updater: %v", err)
	}
	if _, err := updater.uploadChunk(context.Background(), []byte("data"), "batch"); err == nil {
		t.Fatal("expected an oversized chunk response to be rejected")
	}
}

// TestBeeSequenceFeedUpdaterWriterRejectsOversizeRef proves an unbounded ref /
// batch id is rejected before any network call.
func TestBeeSequenceFeedUpdaterWriterRejectsOversizeRef(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("no request should be issued for an over-bound ref")
	}))
	defer server.Close()
	updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
	if err != nil {
		t.Fatalf("create updater: %v", err)
	}
	big := strings.Repeat("a", beeFeedWriteMaxRef+1)
	if err := updater.Update(context.Background(), FeedUpdate{
		Feed:      "feed://" + owner + "/" + strings.Repeat("ab", 32),
		Reference: big,
		BatchID:   strings.Repeat("cd", 32),
	}); err == nil {
		t.Fatal("expected an over-bound ref to be rejected")
	}
}

// TestBeeSequenceFeedUpdaterRejectsMalformedBeforeNetwork proves malformed
// reference, batch, and feed values are REJECTED before any network call: an
// empty/bad reference, a batch that is not exactly 64 hex characters, and a
// non-canonical feed all fail closed with zero requests issued to Bee.
func TestBeeSequenceFeedUpdaterRejectsMalformedBeforeNetwork(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	goodRef := strings.Repeat("ab", 32)
	goodBatch := strings.Repeat("cd", 32)

	cases := []struct {
		name  string
		feed  string
		ref   string
		batch string
	}{
		{"empty reference", "feed://" + owner + "/" + strings.Repeat("ab", 32), "", goodBatch},
		{"short reference", "feed://" + owner + "/" + strings.Repeat("ab", 32), strings.Repeat("ab", 31), goodBatch},
		{"non-hex reference", "feed://" + owner + "/" + strings.Repeat("ab", 32), strings.Repeat("zz", 32), goodBatch},
		{"empty batch", "feed://" + owner + "/" + strings.Repeat("ab", 32), goodRef, ""},
		{"short batch", "feed://" + owner + "/" + strings.Repeat("ab", 32), goodRef, strings.Repeat("cd", 31)},
		{"non-hex batch", "feed://" + owner + "/" + strings.Repeat("ab", 32), goodRef, strings.Repeat("zz", 32)},
		{"oversize batch", "feed://" + owner + "/" + strings.Repeat("ab", 32), goodRef, strings.Repeat("cd", 33)},
		{"non-canonical feed scheme", "http://" + owner + "/" + strings.Repeat("ab", 32), goodRef, goodBatch},
		{"short topic", "feed://" + owner + "/abcd", goodRef, goodBatch},
		{"uppercase owner", "feed://" + strings.ToUpper(owner) + "/" + strings.Repeat("ab", 32), goodRef, goodBatch},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var touched int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				touched++
				http.NotFound(w, r)
			}))
			defer server.Close()
			updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
			if err != nil {
				t.Fatalf("create updater: %v", err)
			}
			if err := updater.Update(context.Background(), FeedUpdate{Feed: tc.feed, Reference: tc.ref, BatchID: tc.batch}); err == nil {
				t.Fatalf("%s: expected rejection, got nil", tc.name)
			}
			if touched != 0 {
				t.Fatalf("%s: validation must fail before any network call, got %d requests", tc.name, touched)
			}
		})
	}
}

// TestBeeSequenceFeedUpdaterIndexFailuresFailClosedBeforeSOC proves the
// sequence header is STRICTLY validated: a missing (on 200), malformed,
// wrong-size, oversized, or duplicate Swarm-Feed-Index-Next header fails the
// update BEFORE any /soc upload (the chunk staging upload may already have
// happened, but the signed SOC — the value that actually advances the feed —
// must never be sent).
func TestBeeSequenceFeedUpdaterIndexFailuresFailClosedBeforeSOC(t *testing.T) {
	t.Parallel()
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	topic := strings.Repeat("ab", 32)

	cases := []struct {
		name   string
		seed   func(w http.ResponseWriter)
		reason string
	}{
		{"missing header", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}, "missing"},
		{"malformed hex", func(w http.ResponseWriter) {
			w.Header().Set("Swarm-Feed-Index-Next", "not-hex")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}, "malformed"},
		{"wrong size", func(w http.ResponseWriter) {
			w.Header().Set("Swarm-Feed-Index-Next", "00112233445566") // 7 bytes
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}, "wrong-size"},
		{"oversized header", func(w http.ResponseWriter) {
			w.Header().Set("Swarm-Feed-Index-Next", strings.Repeat("ab", beeFeedWriteMaxRef+1))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}, "oversized"},
		{"duplicate header", func(w http.ResponseWriter) {
			w.Header().Add("Swarm-Feed-Index-Next", "0000000000000001")
			w.Header().Add("Swarm-Feed-Index-Next", "0000000000000002")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}, "duplicate"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var socTouched bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/chunks":
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
				case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
					socTouched = true
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{}`))
				default:
					tc.seed(w)
				}
			}))
			defer server.Close()
			updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
			if err != nil {
				t.Fatalf("create updater: %v", err)
			}
			if err := updater.Update(context.Background(), FeedUpdate{
				Feed:      "feed://" + owner + "/" + topic,
				Reference: strings.Repeat("ab", 32),
				BatchID:   strings.Repeat("cd", 32),
			}); err == nil {
				t.Fatalf("expected %s index to fail the update", tc.reason)
			}
			if socTouched {
				t.Fatalf("%s index: SOC upload must never happen", tc.name)
			}
		})
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

// refBytes64 returns the 32 BINARY bytes a 64-hex reference decodes to — the
// exact raw payload the production feed endpoint returns (Bee GET
// /feeds/{owner}/{topic} serves the chunk payload as application/octet-stream
// with the span stripped, so a Task-11 feed body is the decoded reference).
func refBytes64(b byte) []byte {
	out, err := hex.DecodeString(hex64(b))
	if err != nil {
		panic(err)
	}
	return out
}

// feedRef builds a canonical feed reference for a given owner.
func feedRef(owner string) string { return "feed://" + owner + "/aaaa" }

// TestBeeFeedResolverResolvesFeedBodyAsReference is the core production feed
// contract: GET /feeds/{owner}/{topic} returns the RAW BINARY payload of the
// feed update (application/octet-stream, span stripped) — under Task 11 that
// is the decoded 32-byte immutable reference, NOT ASCII hex and NOT an 8-byte
// length-prefixed chunk. The resolver returns its normalized lowercase 64-hex
// form.
func TestBeeFeedResolverResolvesFeedBodyAsReference(t *testing.T) {
	t.Parallel()
	const owner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// A 64-hex ref decoded to its 32 binary bytes; mixed case proves the
	// read-back normalizes to lowercase hex.
	const ref = "AaBbCcDdEeFf00112233445566778899aabbccddeeff00112233445566778899"
	body, err := hex.DecodeString(ref)
	if err != nil {
		t.Fatalf("decode ref: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/feeds/"+owner+"/aaaa" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Swarm-Feed-Index", "0000000000000000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
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
			w.Header().Set("Swarm-Feed-Index", "0000000000000000")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(refBytes64('b'))
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

// TestBeeFeedResolverMalformedBodyRejects proves a body that is not EXACTLY 32
// binary bytes (including the OLD pre-Task-11 ASCII-hex 64-byte representation)
// is rejected: the reader must match the new binary feed payload exactly.
func TestBeeFeedResolverMalformedBodyRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body []byte
	}{
		{"short text", []byte("short")},
		{"empty", []byte("")},
		{"31 bytes", refBytes64('a')[:31]},
		{"33 bytes", append(append([]byte(nil), refBytes64('a')...), 0x00)},
		{"old ascii hex representation", []byte(hex64('a'))},
		{"ascii hex plus extra", []byte(hex64('a') + "extra")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Swarm-Feed-Index", "0000000000000000")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(tc.body)
			}))
			defer server.Close()
			resolver := NewBeeFeedResolver(server.URL, server.Client())
			if _, err := resolver.ResolveFeed(context.Background(), feedRef("owner")); err == nil {
				t.Fatalf("expected malformed body %q to be rejected", tc.body)
			}
		})
	}
}

// TestBeeFeedResolverOversizeBodyRejects proves a success body beyond the
// reference bound is rejected rather than silently truncated.
func TestBeeFeedResolverOversizeBodyRejects(t *testing.T) {
	t.Parallel()
	big := append(append([]byte(nil), refBytes64('a')...), make([]byte, beeFeedResolveMaxBody)...) // far over bound
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Swarm-Feed-Index", "0000000000000000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(big)
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
		w.Header().Set("Swarm-Feed-Index", "0000000000000000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(refBytes64('a'))
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
		w.Header().Set("Swarm-Feed-Index", "0000000000000000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(refBytes64('a'))
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
		body []byte
	}{
		{"success", http.StatusOK, refBytes64('a')},
		{"non-200", http.StatusBadRequest, []byte("boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closed := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.code == http.StatusOK {
					w.Header().Set("Swarm-Feed-Index", "0000000000000000")
				}
				w.WriteHeader(tc.code)
				_, _ = w.Write(tc.body)
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
		w.Header().Set("Swarm-Feed-Index", "0000000000000000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(refBytes64('c'))
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
