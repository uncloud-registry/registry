package swarm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
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

// ResolveFeed resolves a feed reference to the canonical object ref currently
// stored at it. It is the read-back counterpart of BeeSequenceFeedUpdater:
// GET /feeds/{owner}/{topic} returns the feed payload bytes directly — under
// Task 11 the raw 32 binary bytes of the decoded immutable reference (Bee
// serves the chunk payload as application/octet-stream, span stripped; NOT an
// 8-byte length-prefixed chunk and NOT 64 ASCII hex characters). ResolveFeed
// therefore decodes the exact bounded 32-byte binary payload to its
// normalized lowercase 64-hex reference. A reconciler uses this to PROVE a
// policy feed points at the object it uploaded before marking a bootstrap job
// verified: a feed that was never published, points elsewhere, or was
// overwritten with a different ref will not resolve to the expected object
// ref. It FAILS CLOSED on every unsafe outcome, is data-free in its returned
// error, bounds success and error bodies, requires exactly 200, always closes
// the body, and imposes a per-request timeout via the request context even
// when the supplied client has none.
func (r BeeFeedResolver) ResolveFeed(ctx context.Context, feed string) (string, error) {
	value, err := r.ReadFeed(ctx, feed)
	if err != nil {
		return "", err
	}
	return value.Reference, nil
}

// BeeFeedResolver resolves a Swarm sequence feed to the object ref currently
// stored at it: GET /feeds/{owner}/{topic} returns the feed payload bytes
// directly (the raw binary chunk payload, span stripped — the decoded 32-byte
// immutable reference under Task 11). NewBeeFeedResolver is the production
// constructor.
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

func (d DisabledFeedUpdater) Update(_ context.Context, update FeedUpdate) error {
	if d.Reason != "" {
		return fmt.Errorf("%s", d.Reason)
	}
	return fmt.Errorf("feed updates are not configured for feed %q -> %q", update.Feed, update.Reference)
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

// beeFeedWriteTimeout is the per-request deadline applied via the request
// context for every outbound writer request (sequence lookup, chunk upload,
// SOC upload) even when the supplied HTTP client has no Timeout configured, so
// a stalled or hung Bee node can never block reconciliation indefinitely.
const beeFeedWriteTimeout = 30 * time.Second

// beeFeedWriteMaxBody bounds success and error response bodies for the writer
// endpoints. A chunk upload returns a small JSON wrapper around a 64-hex ref
// (plus the feed index header), so the bound comfortably covers legitimate
// output while rejecting oversized or garbage bodies with a bounded read.
const beeFeedWriteMaxBody = 512

// beeFeedWriteMaxRef bounds the object reference / batch-id / feed index values
// accepted on the writer path. A genuine Swarm ref or batch id is exactly 64
// hex chars; the bound rejects oversized or malformed values before any network
// call while still allowing the bounded in-memory/symbolic test refs.
const beeFeedWriteMaxRef = 256

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

// writerClient returns a guaranteed non-nil *http.Client for writer requests
// (http.DefaultClient when the updater's client is nil) so a zero-value or
// under-configured updater never panics on a nil receiver client.
func (u *BeeSequenceFeedUpdater) writerClient() *http.Client {
	return defaultHTTPClient(u.HTTPClient)
}

// writerBaseURL returns the normalized base URL or a data-free configuration
// error when the updater has none, so a direct exported-struct zero value
// fails closed with an error instead of building an empty-URL request.
func (u *BeeSequenceFeedUpdater) writerBaseURL() (string, error) {
	if u == nil {
		return "", errors.New("bee feed updater is not configured")
	}
	if strings.TrimSpace(u.BaseURL) == "" {
		return "", errors.New("feed updater base URL is not configured")
	}
	return strings.TrimRight(u.BaseURL, "/"), nil
}

func (u *BeeSequenceFeedUpdater) nextSequenceIndex(ctx context.Context, owner string, topic string) ([]byte, error) {
	if len(owner) > beeFeedWriteMaxRef || len(topic) > beeFeedWriteMaxRef {
		return nil, errors.New("feed owner or topic exceeds the bound")
	}
	baseURL, err := u.writerBaseURL()
	if err != nil {
		return nil, err
	}
	// Path-escape both parts so an unusual owner/topic can never smuggle a
	// different path segment or query into the request.
	path := "/feeds/" + url.PathEscape(owner) + "/" + url.PathEscape(topic)

	client := u.writerClient()
	reqCtx, cancel := writeRequestContext(ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("create feed lookup request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feed lookup request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return make([]byte, 8), nil
	}
	if resp.StatusCode != http.StatusOK {
		// Drain a bounded amount (never the whole body) so the connection can
		// be reused, but NEVER include the raw body in the returned error.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		return nil, fmt.Errorf("feed lookup failed with status %d", resp.StatusCode)
	}

	// The next sequence index is REQUIRED on a 200 and STRICTLY validated:
	// exactly one header line, bounded hex decoding to exactly 8 bytes. A
	// missing, malformed, duplicate, wrong-size, or oversized
	// Swarm-Feed-Index-Next header fails closed BEFORE any SOC upload.
	nextHex, err := feedIndexHeader(resp.Header, "Swarm-Feed-Index-Next")
	if err != nil {
		return nil, err
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
	if len(batchID) == 0 || len(batchID) > beeFeedWriteMaxRef {
		return nil, errors.New("postage batch id is empty or exceeds the bound")
	}
	baseURL, err := u.writerBaseURL()
	if err != nil {
		return nil, err
	}

	client := u.writerClient()
	reqCtx, cancel := writeRequestContext(ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/chunks", bytes.NewReader(chunkData))
	if err != nil {
		return nil, fmt.Errorf("create chunk upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Swarm-Postage-Batch-Id", batchID)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("chunk upload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		return nil, fmt.Errorf("chunk upload failed with status %d", resp.StatusCode)
	}

	var payload beeReferenceResponse
	if err := decodeBoundedJSON(resp.Body, &payload); err != nil {
		return nil, err
	}
	if len(payload.Reference) == 0 || len(payload.Reference) > beeFeedWriteMaxRef {
		return nil, errors.New("chunk upload response has an empty or oversized reference")
	}
	refBytes, err := hex.DecodeString(payload.Reference)
	if err != nil {
		return nil, fmt.Errorf("decode chunk reference: %w", err)
	}
	return refBytes, nil
}

func (u *BeeSequenceFeedUpdater) uploadSOC(ctx context.Context, owner string, identifier []byte, signature []byte, chunkData []byte, batchID string) error {
	if len(batchID) == 0 || len(batchID) > beeFeedWriteMaxRef {
		return errors.New("postage batch id is empty or exceeds the bound")
	}
	if len(owner) == 0 || len(owner) > beeFeedWriteMaxRef {
		return errors.New("feed owner is empty or exceeds the bound")
	}
	baseURL, err := u.writerBaseURL()
	if err != nil {
		return err
	}

	client := u.writerClient()
	reqCtx, cancel := writeRequestContext(ctx)
	defer cancel()

	endpoint := fmt.Sprintf("%s/soc/%s/%s?sig=%s", baseURL, url.PathEscape(owner), hex.EncodeToString(identifier), hex.EncodeToString(signature))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(chunkData))
	if err != nil {
		return fmt.Errorf("create soc upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Swarm-Postage-Batch-Id", batchID)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("soc upload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		return fmt.Errorf("soc upload failed with status %d", resp.StatusCode)
	}
	// Drain a bounded amount so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
	return nil
}

// writeRequestContext derives the per-request context for a writer call: it
// respects the caller's own deadline when one is set, otherwise imposes the
// bounded beeFeedWriteTimeout so a stalled Bee node can never block
// reconciliation indefinitely.
func writeRequestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, beeFeedWriteTimeout)
}

// decodeBoundedJSON decodes a JSON value from a bounded body read (limit+1
// detect, so an oversized response is rejected rather than silently truncated)
// and never buffers unbounded bytes.
func decodeBoundedJSON(body io.Reader, dst any) error {
	data, err := io.ReadAll(io.LimitReader(body, beeFeedWriteMaxBody+1))
	if err != nil {
		return fmt.Errorf("read bee response body: %w", err)
	}
	if len(data) > beeFeedWriteMaxBody {
		return errors.New("bee response body exceeded the bound")
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("decode bee response: %w", err)
	}
	return nil
}

// makeChunkData wraps the current payload bytes in Bee's chunk wire format: an
// 8-byte little-endian span (the payload length) followed by the payload.
// /chunks and /soc both store and accept this span-prefixed form.
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
