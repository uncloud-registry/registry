package resolve

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

var (
	ensResolverSelector = []byte{0x01, 0x78, 0xb8, 0xbf}
	ensAddrSelector     = []byte{0x3b, 0x3b, 0x57, 0xde}
)

type ENSRegistryIdentityResolver struct {
	DomainSuffix    string
	RPCURL          string
	HTTPClient      *http.Client
	ENSRegistryAddr common.Address
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      int    `json:"id"`
}

type rpcResponse struct {
	Result string    `json:"result"`
	Error  *rpcError `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (r ENSRegistryIdentityResolver) ResolveRegistry(ctx context.Context, host string) (RegistryIdentity, error) {
	hostname := stripPort(host)
	ensName, err := registryENSName(hostname, r.DomainSuffix)
	if err != nil {
		return RegistryIdentity{}, err
	}
	owner, err := r.resolveENSAddress(ctx, ensName)
	if err != nil {
		return RegistryIdentity{}, err
	}
	return RegistryIdentity{Host: hostname, Owner: owner.Hex()}, nil
}

func registryENSName(host string, suffix string) (string, error) {
	hostname := stripPort(host)
	labels := strings.Split(hostname, ".")
	if len(labels) < 3 {
		return "", fmt.Errorf("host %q does not contain a registry subdomain", host)
	}
	subdomain := labels[0]
	suffix = strings.TrimPrefix(strings.TrimSpace(suffix), ".")
	if suffix == "" {
		return "", fmt.Errorf("domain suffix is required for ENS resolution")
	}
	return subdomain + "." + suffix, nil
}

func (r ENSRegistryIdentityResolver) resolveENSAddress(ctx context.Context, name string) (common.Address, error) {
	if strings.TrimSpace(r.RPCURL) == "" {
		return common.Address{}, fmt.Errorf("rpc url is required for ENS resolution")
	}
	registryAddr := r.ENSRegistryAddr
	if registryAddr == (common.Address{}) {
		registryAddr = common.HexToAddress("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e")
	}

	node := namehash(name)
	resolverData := append(append([]byte{}, ensResolverSelector...), node[:]...)
	resolverResp, err := r.ethCall(ctx, registryAddr, resolverData)
	if err != nil {
		return common.Address{}, fmt.Errorf("resolve ENS resolver for %q: %w", name, err)
	}
	resolverAddr := unpackAddress(resolverResp)
	if resolverAddr == (common.Address{}) {
		return common.Address{}, fmt.Errorf("ENS name %q does not have a resolver", name)
	}

	addrData := append(append([]byte{}, ensAddrSelector...), node[:]...)
	addrResp, err := r.ethCall(ctx, resolverAddr, addrData)
	if err != nil {
		return common.Address{}, fmt.Errorf("resolve ENS addr for %q: %w", name, err)
	}
	owner := unpackAddress(addrResp)
	if owner == (common.Address{}) {
		return common.Address{}, fmt.Errorf("ENS name %q does not have an address record", name)
	}
	return owner, nil
}

// ---------- bounded default HTTP client ----------
//
// The ENS resolver talks to the configured RPC endpoint, so its fallback
// client must never be the bare process-global http.DefaultClient (zero
// timeouts let a stalled RPC node block resolution forever). fallbackENSHClient
// returns a process-wide bounded client (connect/TLS-handshake/
// response-header/idle transport deadlines plus an overall per-request
// Timeout). Production binaries construct their own configured client once and
// inject it through the HTTPClient field; this fallback exists so a resolver
// with a nil client can never hang unbounded. Timeout deliberately exceeds the
// per-request horizon used by every internal context deadline so a caller's
// own deadline stays the authority when one is set.
const (
	ensDefaultConnectTimeout        = 10 * time.Second
	ensDefaultTLSHandshakeTimeout   = 10 * time.Second
	ensDefaultResponseHeaderTimeout = 30 * time.Second
	ensDefaultIdleConnTimeout       = 90 * time.Second
	ensDefaultRequestTimeout        = 60 * time.Second
)

var (
	ensBoundedClientOnce sync.Once
	ensBoundedClient     *http.Client
)

func boundedENSHClient() *http.Client {
	ensBoundedClientOnce.Do(func() {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.DialContext = (&net.Dialer{Timeout: ensDefaultConnectTimeout, KeepAlive: 30 * time.Second}).DialContext
		base.TLSHandshakeTimeout = ensDefaultTLSHandshakeTimeout
		base.ResponseHeaderTimeout = ensDefaultResponseHeaderTimeout
		base.IdleConnTimeout = ensDefaultIdleConnTimeout
		ensBoundedClient = &http.Client{Transport: base, Timeout: ensDefaultRequestTimeout}
	})
	return ensBoundedClient
}

func (r ENSRegistryIdentityResolver) ethCall(ctx context.Context, to common.Address, data []byte) ([]byte, error) {
	reqBody := rpcRequest{
		JSONRPC: "2.0",
		Method:  "eth_call",
		Params: []any{
			map[string]string{
				"to":   to.Hex(),
				"data": "0x" + hex.EncodeToString(data),
			},
			"latest",
		},
		ID: 1,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal rpc request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.RPCURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create rpc request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := r.HTTPClient
	if client == nil {
		client = boundedENSHClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rpc request failed: %w", err)
	}
	defer resp.Body.Close()

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode rpc response: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", out.Error.Code, out.Error.Message)
	}
	result := strings.TrimPrefix(strings.TrimSpace(out.Result), "0x")
	if result == "" {
		return nil, fmt.Errorf("rpc response missing result")
	}
	decoded, err := hex.DecodeString(result)
	if err != nil {
		return nil, fmt.Errorf("decode rpc result: %w", err)
	}
	return decoded, nil
}

func unpackAddress(data []byte) common.Address {
	if len(data) < 32 {
		return common.Address{}
	}
	return common.BytesToAddress(data[len(data)-20:])
}

func namehash(name string) common.Hash {
	var node common.Hash
	name = strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return node
	}
	labels := strings.Split(name, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		labelHash := ethcrypto.Keccak256([]byte(labels[i]))
		node = ethcrypto.Keccak256Hash(node.Bytes(), labelHash)
	}
	return node
}

func stripPort(host string) string {
	hostname, _, err := net.SplitHostPort(host)
	if err == nil {
		return hostname
	}
	return host
}
