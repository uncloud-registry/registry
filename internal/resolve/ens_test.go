package resolve

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
