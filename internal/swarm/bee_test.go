package swarm

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
