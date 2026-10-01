package resolve

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestRegistryENSName(t *testing.T) {
	t.Parallel()

	name, err := registryENSName("alice.uncloud-registry.com", "registry.eth")
	if err != nil {
		t.Fatalf("registryENSName: %v", err)
	}
	if name != "alice.registry.eth" {
		t.Fatalf("unexpected ENS name: %s", name)
	}
}

func TestENSRegistryIdentityResolver(t *testing.T) {
	t.Parallel()

	resolverAddress := common.HexToAddress("0x1000000000000000000000000000000000000001")
	ownerAddress := common.HexToAddress("0x2000000000000000000000000000000000000002")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode rpc request: %v", err)
		}
		params := req.Params[0].(map[string]any)
		data := strings.TrimPrefix(params["data"].(string), "0x")
		switch {
		case strings.HasPrefix(data, "0178b8bf"):
			respondRPCResult(t, w, padAddress(resolverAddress))
		case strings.HasPrefix(data, "3b3b57de"):
			respondRPCResult(t, w, padAddress(ownerAddress))
		default:
			t.Fatalf("unexpected eth_call data: %s", data)
		}
	}))
	defer server.Close()

	resolver := ENSRegistryIdentityResolver{
		DomainSuffix: "registry.eth",
		RPCURL:       server.URL,
		HTTPClient:   server.Client(),
	}

	registry, err := resolver.ResolveRegistry(context.Background(), "alice.uncloud-registry.com")
	if err != nil {
		t.Fatalf("ResolveRegistry: %v", err)
	}
	if registry.Owner != ownerAddress.Hex() {
		t.Fatalf("unexpected owner: %s", registry.Owner)
	}
}

// hangingRPCServer returns an httptest server that accepts RPC requests and
// never responds until the test closes the returned channel.
func hangingRPCServer(t *testing.T) (*httptest.Server, chan struct{}) {
	t.Helper()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	t.Cleanup(func() {
		close(done)
		srv.Close()
	})
	return srv, done
}

// TestENSResolutionTimeoutPreservesDeadlineExceeded proves an ENS resolution
// against an RPC endpoint that never responds returns within the configured
// client timeout and keeps context.DeadlineExceeded intact in the error chain.
func TestENSResolutionTimeoutPreservesDeadlineExceeded(t *testing.T) {
	t.Parallel()

	hang, _ := hangingRPCServer(t)
	resolver := ENSRegistryIdentityResolver{
		DomainSuffix: "registry.eth",
		RPCURL:       hang.URL,
		HTTPClient:   &http.Client{Timeout: 200 * time.Millisecond},
	}

	start := time.Now()
	_, err := resolver.ResolveRegistry(context.Background(), "alice.uncloud-registry.com")
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("resolution error must wrap context.DeadlineExceeded, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("resolution exceeded the configured timeout: %v", elapsed)
	}
}

// TestENSDefaultClientTimeoutBounded asserts the ENS resolver never falls back
// to the bare http.DefaultClient: a nil client yields a bounded client.
func TestENSDefaultClientTimeoutBounded(t *testing.T) {
	t.Parallel()

	c := boundedENSHClient()
	if c == nil {
		t.Fatal("fallback ENS client is nil")
	}
	if c == http.DefaultClient {
		t.Fatal("fallback ENS client must not be http.DefaultClient")
	}
	if c.Timeout <= 0 {
		t.Fatalf("fallback ENS client is unbounded (Timeout=%v)", c.Timeout)
	}
}

func respondRPCResult(t *testing.T, w http.ResponseWriter, data []byte) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  "0x" + hex.EncodeToString(data),
	}); err != nil {
		t.Fatalf("encode rpc result: %v", err)
	}
}

func padAddress(addr common.Address) []byte {
	data := make([]byte, 32)
	copy(data[12:], addr.Bytes())
	return data
}
