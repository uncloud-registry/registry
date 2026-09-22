package swarm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/uncloud-registry/registry/internal/resolve"
)

type BeeDocumentStore struct {
	BaseURL    string
	HTTPClient *http.Client
}

type BeeObjectStore struct {
	BaseURL        string
	HTTPClient     *http.Client
	Pin            bool
	DeferredUpload bool
}

// isBeeReference reports whether s is a legitimate Swarm object reference:
// exactly 64 hex characters (a 32-byte content address), either letter case.
// This is the exact syntax the object store PUT endpoint returns and the feed
// payload carries, and it is the ONLY form the production feed resolver
// accepts on the wire. In-memory/symbolic test refs never flow through it.
func isBeeReference(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// CanonicalObjectRef returns a canonical form for byte-exact
// feed-vs-object-reference comparison: a genuine 64-hex Swarm reference is
// lowercased (so uppercase and lowercase resolve equal), while any other value
// (an in-memory symbolic test ref) is returned trimmed but otherwise unchanged
// so symbolic refs still compare exactly. The reconciler applies the SAME
// canonicalization to both the resolved feed ref and the uploaded object ref
// before comparing, so case differences on genuine hex refs never cause a
// false feed-resolution mismatch.
func CanonicalObjectRef(s string) string {
	s = strings.TrimSpace(s)
	if isBeeReference(s) {
		return strings.ToLower(s)
	}
	return s
}

type SubdomainENSRegistryResolver struct {
	HostMap map[string]string
}

type IdentityFeedResolver struct{}

type DisabledFeedUpdater struct {
	Reason string
}

type BeeSequenceFeedUpdater struct {
	BaseURL    string
	HTTPClient *http.Client
	PrivateKey *ecdsa.PrivateKey
}

// beeFeedResolveMaxBody bounds the feed resolve response body. A Swarm
// object reference is exactly 64 hex characters; 256 comfortably covers a ref
// plus incidental trailing whitespace while still rejecting any oversized or
// garbage body with a single bounded read. Success and error bodies are both
// read to this limit+1 so an oversized response is detected (not silently
// truncated) without ever buffering unbounded bytes.
const beeFeedResolveMaxBody = 256

// beeFeedResolveTimeout is the per-request deadline applied via the request
// context even when the supplied HTTP client has no Timeout configured, so a
// stalled or hung Bee node can never block reconciliation indefinitely.
const beeFeedResolveTimeout = 30 * time.Second

// BeeFeedResolver resolves a Swarm sequence feed to the object ref currently
// stored at it. It is the read-back counterpart of BeeSequenceFeedUpdater:
// GET /feeds/{owner}/{topic} returns the feed payload bytes directly — the raw
// object reference the signer wrote as the chunk payload (NOT an 8-byte
// length-prefixed chunk: the feed endpoint already unwraps the chunk, so the
// response body IS the reference). ResolveFeed therefore parses the bounded
// response body as the object reference itself, validating the exact nonempty
// bounded 64-hex reference syntax the object store outputs, and returns its
// canonical form. It never calls parseChunkData on a feed response because
// there is no 8-byte prefix to strip. A reconciler uses this to PROVE a policy
// feed points at the object it uploaded before marking a bootstrap job
// verified: a feed that was never published, points elsewhere, or was
// overwritten with a different ref will not resolve to the expected object ref.
type BeeFeedResolver struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewBeeFeedResolver returns a production BeeFeedResolver over baseURL with a
// normalized base URL and a guaranteed non-nil HTTP client (http.DefaultClient
// when none is supplied; the per-request context timeout still protects it).
// It performs no I/O. A direct zero-value struct has an empty base URL, which
// ResolveFeed rejects with an error rather than panicking.
func NewBeeFeedResolver(baseURL string, client *http.Client) *BeeFeedResolver {
	return &BeeFeedResolver{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: defaultHTTPClient(client),
	}
}

// ResolveFeed resolves a feed reference to the canonical object ref currently
// stored at it. It FAILS CLOSED on every unsafe outcome, is data-free in its
// returned error (never echoing a raw Bee body), bounds success and error
// bodies, requires exactly 200, always closes the body, and imposes a
// per-request timeout via the request context even when the supplied client
// has none. It validates the body as exactly a nonempty 64-hex reference
// (the object-store output contract) and returns its canonical (lowercased)
// form so the reconciler's comparison is case-normalized.
func (r BeeFeedResolver) ResolveFeed(ctx context.Context, feed string) (string, error) {
	if strings.TrimSpace(r.BaseURL) == "" {
		return "", errors.New("bee feed resolver: base URL is not configured")
	}
	baseURL := strings.TrimRight(r.BaseURL, "/")

	owner, topic, err := parseFeedRef(feed)
	if err != nil {
		return "", fmt.Errorf("bee feed resolver: %w", err)
	}
	// Path-escape both parts so an unusual owner/topic (or a malicious one)
	// can never smuggle a different path segment or query into the request.
	path := "/feeds/" + url.PathEscape(owner) + "/" + url.PathEscape(topic)

	client := defaultHTTPClient(r.HTTPClient)

	// Per-request timeout even when the supplied client has none configured:
	// derive a deadline sub-context unless the caller already imposed one.
	reqCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, beeFeedResolveTimeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, baseURL+path, nil)
	if err != nil {
		return "", fmt.Errorf("create bee feed resolve request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("bee feed resolve request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain a bounded amount (never the whole body) so the connection can
		// be reused, but NEVER include the raw body in the returned error.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedResolveMaxBody+1))
		return "", fmt.Errorf("bee feed resolution failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, beeFeedResolveMaxBody+1))
	if err != nil {
		return "", fmt.Errorf("read bee feed response body: %w", err)
	}
	if len(body) > beeFeedResolveMaxBody {
		return "", errors.New("bee feed resolution response exceeded the reference bound")
	}
	ref := strings.TrimSpace(string(body))
	if !isBeeReference(ref) {
		return "", errors.New("bee feed did not resolve to a valid object reference")
	}
	return CanonicalObjectRef(ref), nil
}

type beeReferenceResponse struct {
	Reference string `json:"reference"`
}

func NewBeeDocumentStore(baseURL string, client *http.Client) *BeeDocumentStore {
	return &BeeDocumentStore{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: defaultHTTPClient(client),
	}
}

func NewBeeObjectStore(baseURL string, client *http.Client) *BeeObjectStore {
	return &BeeObjectStore{
		BaseURL:        strings.TrimRight(baseURL, "/"),
		HTTPClient:     defaultHTTPClient(client),
		Pin:            true,
		DeferredUpload: false,
	}
}

func (s *BeeDocumentStore) Read(ctx context.Context, ref string) ([]byte, error) {
	switch {
	case strings.HasPrefix(ref, "feed://"):
		owner, topic, err := parseFeedRef(ref)
		if err != nil {
			return nil, err
		}
		return s.readPath(ctx, "/feeds/"+owner+"/"+topic)
	default:
		normalized := normalizeBZZReference(ref)
		return s.readPath(ctx, "/bzz/"+url.PathEscape(normalized))
	}
}

func (s *BeeDocumentStore) Get(ctx context.Context, ref string) ([]byte, error) {
	return s.Read(ctx, ref)
}

func (s *BeeDocumentStore) readPath(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("create bee read request: %w", err)
	}

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bee read request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bee read failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read bee response body: %w", err)
	}
	return data, nil
}

func (s *BeeObjectStore) Get(ctx context.Context, ref string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL+"/bytes/"+url.PathEscape(ref), nil)
	if err != nil {
		return nil, fmt.Errorf("create bee bytes get request: %w", err)
	}

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bee bytes get request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bee bytes get failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read bee bytes response body: %w", err)
	}
	return data, nil
}

func (s *BeeObjectStore) Put(ctx context.Context, data []byte, batchID string) (string, error) {
	if batchID == "" {
		return "", fmt.Errorf("missing postage batch id")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL+"/bytes", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("create bee bytes put request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Swarm-Postage-Batch-Id", batchID)
	req.Header.Set("Swarm-Pin", fmt.Sprintf("%t", s.Pin))
	req.Header.Set("Swarm-Deferred-Upload", fmt.Sprintf("%t", s.DeferredUpload))

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("bee bytes put request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("bee bytes put failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload beeReferenceResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode bee put response: %w", err)
	}
	if payload.Reference == "" {
		return "", fmt.Errorf("bee put response missing reference")
	}

	return payload.Reference, nil
}

func (r SubdomainENSRegistryResolver) ResolveRegistry(_ context.Context, host string) (resolve.RegistryIdentity, error) {
	if mapped, ok := r.HostMap[host]; ok {
		return resolve.RegistryIdentity{Host: stripPort(host), Owner: mapped}, nil
	}

	hostname := stripPort(host)
	if mapped, ok := r.HostMap[hostname]; ok {
		return resolve.RegistryIdentity{Host: hostname, Owner: mapped}, nil
	}
	return resolve.RegistryIdentity{}, fmt.Errorf("host %q is not mapped to a registry owner", host)
}

func (IdentityFeedResolver) ResolveFeed(_ context.Context, feed string) (string, error) {
	if strings.TrimSpace(feed) == "" {
		return "", fmt.Errorf("feed reference is empty")
	}
	return feed, nil
}

func (d DisabledFeedUpdater) UpdateFeed(_ context.Context, feed string, ref string) error {
	if d.Reason != "" {
		return fmt.Errorf("%s", d.Reason)
	}
	return fmt.Errorf("feed updates are not configured for feed %q -> %q", feed, ref)
}

func NewBeeSequenceFeedUpdater(baseURL string, client *http.Client, privateKeyHex string) (*BeeSequenceFeedUpdater, error) {
	privateKeyHex = strings.TrimPrefix(strings.TrimSpace(privateKeyHex), "0x")
	if privateKeyHex == "" {
		return nil, fmt.Errorf("feed signer private key is required")
	}
	raw, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("parse feed signer private key: %w", err)
	}
	return NewBeeSequenceFeedUpdaterBytes(baseURL, client, raw)
}

// NewBeeSequenceFeedUpdaterBytes builds the feed updater directly from the raw
// 32-byte private key. This is the signer constructor the control plane uses:
// decrypted feed keys never become hex strings — the bytes flow from the
// decrypt boundary straight into the signer (any intermediate hex/text copy
// would be an extra immutable plaintext the operation could not wipe).
func NewBeeSequenceFeedUpdaterBytes(baseURL string, client *http.Client, privateKeyBytes []byte) (*BeeSequenceFeedUpdater, error) {
	if len(privateKeyBytes) == 0 {
		return nil, fmt.Errorf("feed signer private key is required")
	}
	key, err := ethcrypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse feed signer private key: %w", err)
	}

	return &BeeSequenceFeedUpdater{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: defaultHTTPClient(client),
		PrivateKey: key,
	}, nil
}

func (u *BeeSequenceFeedUpdater) UpdateFeed(ctx context.Context, feed string, ref string) error {
	ownerHex, topicHex, err := parseFeedRef(feed)
	if err != nil {
		return err
	}

	expectedOwner := strings.ToLower(ethcrypto.PubkeyToAddress(u.PrivateKey.PublicKey).Hex()[2:])
	if strings.ToLower(ownerHex) != expectedOwner {
		return fmt.Errorf("feed owner %q does not match configured signer owner %q", ownerHex, expectedOwner)
	}

	topicBytes, err := hex.DecodeString(topicHex)
	if err != nil {
		return fmt.Errorf("decode feed topic: %w", err)
	}

	// The feed payload IS the raw object reference bytes ([]byte(ref)) — NOT
	// an 8-byte little-endian length-prefixed chunk. GET /feeds/{owner}/{topic}
	// returns this payload directly, so the resolver reads it as the reference
	// itself. This is the single shared contract between the signer and the
	// resolver: the chunk and SOC payloads both carry exactly the reference.
	chunkData := []byte(ref)
	chunkRef, err := u.uploadChunk(ctx, chunkData, ref)
	if err != nil {
		return err
	}

	nextIndex, err := u.nextSequenceIndex(ctx, ownerHex, topicHex)
	if err != nil {
		return err
	}

	identifier := makeFeedIdentifier(topicBytes, nextIndex)
	signature, err := signSOCIdentifier(identifier, chunkRef, u.PrivateKey)
	if err != nil {
		return err
	}

	return u.uploadSOC(ctx, ownerHex, identifier, signature, chunkData, ref)
}

func defaultHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return http.DefaultClient
}

func normalizeBZZReference(ref string) string {
	return strings.TrimPrefix(ref, "bzz://")
}

func parseFeedRef(ref string) (owner string, topic string, err error) {
	trimmed := strings.TrimPrefix(ref, "feed://")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid feed reference %q", ref)
	}
	return parts[0], parts[1], nil
}

func stripPort(host string) string {
	hostname, _, err := net.SplitHostPort(host)
	if err == nil {
		return hostname
	}
	return host
}

func (u *BeeSequenceFeedUpdater) nextSequenceIndex(ctx context.Context, owner string, topic string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.BaseURL+"/feeds/"+owner+"/"+topic, nil)
	if err != nil {
		return nil, fmt.Errorf("create feed lookup request: %w", err)
	}

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feed lookup request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return make([]byte, 8), nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("feed lookup failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	nextHex := strings.TrimSpace(resp.Header.Get("Swarm-Feed-Index-Next"))
	if nextHex == "" {
		return nil, fmt.Errorf("feed lookup response missing Swarm-Feed-Index-Next header")
	}

	nextBytes, err := hex.DecodeString(nextHex)
	if err != nil {
		return nil, fmt.Errorf("decode feed next index header: %w", err)
	}
	if len(nextBytes) != 8 {
		return nil, fmt.Errorf("unexpected feed next index length: %d", len(nextBytes))
	}
	return nextBytes, nil
}

func (u *BeeSequenceFeedUpdater) uploadChunk(ctx context.Context, chunkData []byte, batchID string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.BaseURL+"/chunks", bytes.NewReader(chunkData))
	if err != nil {
		return nil, fmt.Errorf("create chunk upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Swarm-Postage-Batch-Id", batchID)

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("chunk upload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("chunk upload failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload beeReferenceResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode chunk upload response: %w", err)
	}
	refBytes, err := hex.DecodeString(payload.Reference)
	if err != nil {
		return nil, fmt.Errorf("decode chunk reference: %w", err)
	}
	return refBytes, nil
}

func (u *BeeSequenceFeedUpdater) uploadSOC(ctx context.Context, owner string, identifier []byte, signature []byte, chunkData []byte, batchID string) error {
	endpoint := fmt.Sprintf("%s/soc/%s/%s?sig=%s", u.BaseURL, owner, hex.EncodeToString(identifier), hex.EncodeToString(signature))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(chunkData))
	if err != nil {
		return fmt.Errorf("create soc upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Swarm-Postage-Batch-Id", batchID)

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("soc upload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("soc upload failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func makeFeedIdentifier(topic []byte, index []byte) []byte {
	return ethcrypto.Keccak256(append(append([]byte{}, topic...), index...))
}

func signSOCIdentifier(identifier []byte, wrappedChunkRef []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	digest := ethcrypto.Keccak256(append(append([]byte{}, identifier...), wrappedChunkRef...))
	signature, err := ethcrypto.Sign(digest, privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign soc digest: %w", err)
	}
	return signature, nil
}
