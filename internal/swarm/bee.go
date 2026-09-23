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
// when the supplied client has none. A nil receiver (typed nil) fails closed
// instead of panicking.
func (r *BeeFeedResolver) ResolveFeed(ctx context.Context, feed string) (string, error) {
	if r == nil {
		return "", errors.New("bee feed resolver is not configured")
	}
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

// beeReferenceResponse is the JSON wrapper the Bee object-store /bytes PUT
// success response carries ({"reference": "<64 hex>"}).
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

// sanitizeBeeTransportError converts a transport failure (request creation,
// client.Do, response body read) into a stable, DATA-FREE operation error. The
// raw error must never be wrapped or echoed: a *url.Error carries the FULL
// request URL — for the SOC upload that URL includes the signature query, and
// for feed reads/lookups the owner/topic path segments — and a malicious
// RoundTripper can smuggle arbitrary text (URLs, hostnames,
// owner/topic/batch/reference/signature values) into its error.
//
// The REQUEST CONTEXT is the sole authority for the context outcome: the safe
// internal cancellation/deadline sentinels are preserved by wrapping
// context.Canceled / context.DeadlineExceeded ONLY when the real derived
// request context (the reqCtx the HTTP request and body read actually run
// under) is done with that exact sentinel — never by trusting
// errors.Is(untrustedErr, sentinel), because a malicious transport can forge
// sentinel-wrapping errors while the request context is still live. When the
// context is live, everything collapses to an opaque fail-closed message; when
// the context is genuinely done, the returned error carries the TRUE sentinel
// even if the transport error is unrelated or forged, so callers that need to
// distinguish a genuinely cancelled or stalled request still can. A nil ctx
// should not happen (call sites always pass the derived reqCtx) and fails
// opaque. op must be a fixed internal constant, never caller data.
func sanitizeBeeTransportError(ctx context.Context, op string, err error) error {
	if ctx == nil {
		return errors.New(op + " failed")
	}
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return fmt.Errorf("%s: %w", op, context.Canceled)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("%s: %w", op, context.DeadlineExceeded)
	default:
		// Context still live (or a non-standard ctx carried an unknown
		// error): the untrusted transport error is NOT authority — neither
		// its forged sentinels nor its text may survive sanitization.
		return errors.New(op + " failed")
	}
}

func normalizeBZZReference(ref string) string {
	return strings.TrimPrefix(ref, "bzz://")
}

func parseFeedRef(ref string) (owner string, topic string, err error) {
	trimmed := strings.TrimPrefix(ref, "feed://")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		// Data-free: never echo the caller's raw feed value (it may carry
		// owner/topic markers that must not appear in logs or errors).
		return "", "", errors.New("invalid feed reference")
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
		// The parse error names the offending URL; never wrap it.
		return nil, sanitizeBeeTransportError(reqCtx, "create feed lookup request", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, sanitizeBeeTransportError(reqCtx, "feed lookup request", err)
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
		// Unreachable after feedIndexHeader validation; stay data-free.
		return nil, errors.New("decode feed next index header failed")
	}
	if len(nextBytes) != 8 {
		// Unreachable after feedIndexHeader validation; stay data-free.
		return nil, errors.New("feed response next index header is not an 8-byte sequence index")
	}
	return nextBytes, nil
}

// uploadChunk uploads the framed chunk body to /chunks and returns the
// decoded 32-byte content address of the stored chunk (the reference the SOC
// signature is computed over). The success response is parsed STRICTLY: a
// 201 must carry exactly one JSON object with exactly one "reference" member,
// a string of exactly 64 hex characters (32 bytes); duplicate reference
// members, unknown members, non-string values, missing references,
// empty/short/odd/long/non-hex references, and trailing JSON/tokens all fail
// closed with data-free errors BEFORE the sequence lookup or SOC upload can
// proceed. The body is bounded (limit+1 detect), always closed, and errors
// never echo it; transport and request-creation failures are sanitized (the
// request URL and any malicious RoundTripper text are never surfaced).
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
		// The parse error names the offending URL; never wrap it.
		return nil, sanitizeBeeTransportError(reqCtx, "create chunk upload request", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Swarm-Postage-Batch-Id", batchID)

	resp, err := client.Do(req)
	if err != nil {
		return nil, sanitizeBeeTransportError(reqCtx, "chunk upload request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		return nil, fmt.Errorf("chunk upload failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
	if err != nil {
		return nil, sanitizeBeeTransportError(reqCtx, "read chunk upload response body", err)
	}
	if len(body) > beeFeedWriteMaxBody {
		return nil, errors.New("chunk upload response exceeded the bound")
	}
	return parseChunkReferenceResponse(body)
}

// parseChunkReferenceResponse STRICTLY parses a /chunks success response body
// (already bounded by the caller): exactly one JSON object with exactly one
// member "reference", whose value is a JSON string of exactly 64 hex
// characters — the 32-byte Swarm content address of the uploaded chunk, which
// becomes the chunk ref the SOC signature is computed over. Duplicate
// "reference" members, unknown members, non-string values (numbers, booleans,
// null, objects, arrays), a missing reference, references that are not
// exactly 64 hex characters (empty, short, odd, long, non-hex), and any
// trailing JSON/tokens after the object all fail closed with data-free errors
// BEFORE the sequence lookup or SOC upload can proceed. The reference is
// decoded to its 32 binary bytes. No raw response content is ever echoed.
func parseChunkReferenceResponse(body []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return nil, errors.New("chunk upload response is not a JSON object")
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("chunk upload response is not a JSON object")
	}
	var (
		ref    string
		sawRef bool
	)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, errors.New("chunk upload response is not a JSON object")
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, errors.New("chunk upload response is not a JSON object")
		}
		if key != "reference" {
			return nil, errors.New("chunk upload response carries an unknown member")
		}
		if sawRef {
			return nil, errors.New("chunk upload response repeats the reference member")
		}
		valTok, err := dec.Token()
		if err != nil {
			return nil, errors.New("chunk upload response reference is not a string")
		}
		value, ok := valTok.(string)
		if !ok {
			return nil, errors.New("chunk upload response reference is not a string")
		}
		ref = value
		sawRef = true
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, errors.New("chunk upload response is not a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("chunk upload response has trailing data")
	}
	if !sawRef {
		return nil, errors.New("chunk upload response is missing the reference member")
	}
	if len(ref) != 64 || !isHexString(ref, 64) {
		return nil, errors.New("chunk upload response reference is not a 64-hex object reference")
	}
	raw, err := hex.DecodeString(strings.ToLower(ref))
	if err != nil {
		// Unreachable after the 64-hex check; stay data-free.
		return nil, errors.New("chunk upload response reference is not a 64-hex object reference")
	}
	return raw, nil
}

// uploadSOC uploads the signed single-owner chunk to /soc/{owner}/{id}?sig=...
// with the explicit postage batch. The SOC write completes with the 201
// itself: the feed update has already been stored, so the response body
// carries no value this flow consumes. Per the Bee contract (openapi
// /soc/{owner}/{id} 201 -> ReferenceResponse; pkg/api/soc.go
// jsonhttp.Created(w, socPostResponse{Reference: sch.Address()})) the 201 body
// is the SOC chunk's OWN address — a deterministic function of the owner,
// identifier, and payload this call constructed — not a return value the
// writer depends on, so it is intentionally drained (bounded) and ignored
// rather than validated. The body is bounded and always closed; errors never
// echo it. Transport and request-creation failures are sanitized: the request
// URL carries the SOC signature in its query, so it must NEVER surface in an
// error.
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
		// The parse error names the offending URL (which carries sig=...);
		// never wrap it.
		return sanitizeBeeTransportError(reqCtx, "create soc upload request", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Swarm-Postage-Batch-Id", batchID)

	resp, err := client.Do(req)
	if err != nil {
		return sanitizeBeeTransportError(reqCtx, "soc upload request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		return fmt.Errorf("soc upload failed with status %d", resp.StatusCode)
	}
	// Drain a bounded amount so the connection can be reused; see the SOC
	// response contract note in the doc comment above — the body is ignored.
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
