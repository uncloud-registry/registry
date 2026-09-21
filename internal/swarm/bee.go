package swarm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

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

	chunkData := makeChunkData([]byte(ref))
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

func makeChunkData(payload []byte) []byte {
	chunk := make([]byte, 8+len(payload))
	binary.LittleEndian.PutUint64(chunk[:8], uint64(len(payload)))
	copy(chunk[8:], payload)
	return chunk
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
