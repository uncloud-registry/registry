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
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
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

// BoundedBytesReader reads an immutable content-addressed object (GET
// /bytes/<ref>) with an EXPLICIT upper bound on the returned payload. It is
// the control-plane counterpart of resolve.Reader for ARTIFACT CONTENT — the
// /bytes object store, NOT the /bzz document path — so the feed signer can
// re-read and re-verify the operated manifest BODY without ever buffering an
// unbounded response. An object larger than the bound, a non-200 status, or a
// transport failure is a data-free error; the response body is always closed.
// Production: *BeeObjectStore (ReadBounded); in-memory fakes implement it for
// tests.
type BoundedBytesReader interface {
	ReadBounded(ctx context.Context, ref string, maxBytes int64) ([]byte, error)
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

	// createVerifyBackoff overrides beeFeedCreateVerifyBackoff for the
	// post-write effective-feed read-back retry (Round 2: tests shorten it so
	// the bounded retry loop runs fast; the documented production bound is the
	// constant). Zero keeps the production default.
	createVerifyBackoff time.Duration
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
// normalized base URL and a guaranteed non-nil HTTP client (a bounded default
// client with sane timeouts when none is supplied — never the bare
// http.DefaultClient; the per-request context deadline additionally protects
// reads). It performs no I/O. A direct zero-value struct has an empty base
// URL, which ResolveFeed rejects with an error rather than panicking.
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
		// Policy/state documents are stored as raw /bytes objects (the
		// publisher writes them with POST /bytes), which Bee serves only on
		// /bytes/<ref>; /bzz/<ref> needs a manifest and 308s. Names that are
		// not a 64-hex reference keep the /bzz path.
		if len(normalized) == 64 && isHexString(normalized, 64) {
			return s.readPath(ctx, "/bytes/"+normalized)
		}
		return s.readPath(ctx, "/bzz/"+url.PathEscape(normalized))
	}
}

func (s *BeeDocumentStore) Get(ctx context.Context, ref string) ([]byte, error) {
	return s.Read(ctx, ref)
}

// BeeDocumentReadMaxBody bounds a Bee document read's SUCCESS payload (the
// immutable /bzz document or the feed payload the registry reads as a
// repository-state document). Repository-state documents are small bounded
// JSON; the bound is deliberately generous so legitimate resolution is never
// weakened, while a hostile or broken Bee node can never make the cleanup (or
// any document reader) buffer an unbounded body in memory. The success body is
// read at bound+1 with overflow rejection (never silent truncation) and an
// oversized body is a DATA-FREE error that never echoes the payload — a
// response body may carry a SECRET that must never leak into an error or log.
const BeeDocumentReadMaxBody = 1 << 23 // 8 MiB

// beeDocumentErrorMaxBody bounds how much of a non-404 error body is drained
// (enough to let the connection be reused); the drained bytes are discarded and
// never echoed into an error or log.
const beeDocumentErrorMaxBody = 512

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
		// Drain a BOUNDED amount of the error body and discard it: the body is
		// untrusted and must never be echoed into an error or log.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeDocumentErrorMaxBody+1))
		if resp.StatusCode == http.StatusNotFound {
			// A definitive 404 is the conclusively-absent outcome (a repo
			// feed payload that has never been written, or a content chunk
			// that does not exist). Wrap the stable sentinel so the optional
			// resolver can distinguish absence from corruption/transport
			// failures; the raw Bee body is never echoed.
			return nil, fmt.Errorf("bee read failed with status %d: %w", resp.StatusCode, resolve.ErrDocumentNotFound)
		}
		// DATA-FREE: only the fixed status number, never the response body.
		return nil, fmt.Errorf("bee read failed with status %d", resp.StatusCode)
	}

	// Bounded success read with overflow rejection: read at most bound+1 bytes
	// so an oversized legitimate-looking 200 can never be buffered unbounded,
	// and DETECT (rather than silently truncate) an overflow.
	data, err := io.ReadAll(io.LimitReader(resp.Body, BeeDocumentReadMaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("read bee response body: %w", err)
	}
	if int64(len(data)) > BeeDocumentReadMaxBody {
		return nil, errors.New("bee document read exceeded the bound")
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

// ReadBounded implements BoundedBytesReader: it reads the immutable object at
// ref with overflow detection at maxBytes (reading at most maxBytes+1 bytes)
// so the caller's bound can never be exceeded by a hostile or broken Bee
// node. It FAILS CLOSED before any I/O on a nil receiver, an empty BaseURL, a
// nil HTTPClient, and a non-canonical ref (exactly 64 hex characters — a
// 32-byte Swarm content address, the only wire form the /bytes endpoint
// accepts), and rejects a negative bound and a bound at math.MaxInt64 (whose
// maxBytes+1 overflow probe would wrap negative and disable the limit). A body
// larger than maxBytes, any non-200 status, and any transport failure are
// DATA-FREE errors (the fixed status number may appear, but never the response
// body, the ref, or untrusted transport text); the response body is always
// closed; the caller's deadline is respected with the same bounded per-request
// timeout as every other Bee call.
func (s *BeeObjectStore) ReadBounded(ctx context.Context, ref string, maxBytes int64) ([]byte, error) {
	if s == nil {
		return nil, errors.New("bounded bee read requires a bee object store")
	}
	if strings.TrimSpace(s.BaseURL) == "" {
		return nil, errors.New("bounded bee read requires a configured base url")
	}
	if s.HTTPClient == nil {
		return nil, errors.New("bounded bee read requires an http client")
	}
	if !isBeeReference(ref) {
		return nil, errors.New("bounded bee read requires a 64-hex object reference")
	}
	if maxBytes < 0 {
		return nil, errors.New("bounded bee read requires a non-negative bound")
	}
	if maxBytes >= math.MaxInt64 {
		return nil, errors.New("bounded bee read bound is too large")
	}
	reqCtx, cancel := writeRequestContext(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, s.BaseURL+"/bytes/"+url.PathEscape(ref), nil)
	if err != nil {
		return nil, sanitizeBeeTransportError(reqCtx, "create bee bytes bounded read request", err)
	}
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, sanitizeBeeTransportError(reqCtx, "bee bytes bounded read request", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain a BOUNDED amount of the error body and discard it: the body
		// is untrusted and must never be echoed or retained.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		return nil, fmt.Errorf("bee bytes read failed with status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, sanitizeBeeTransportError(reqCtx, "read bee bytes response body", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("bee bytes read exceeded the bound")
	}
	return data, nil
}

// OpenObject streams the immutable object at ref (GET /bytes/<ref>) with an
// EXPLICIT upper bound enforced DURING streaming. It is the pull-integrity
// counterpart of ReadBounded: blob content is streamed into a bounded
// verification file without ever buffering the whole object in memory, so a
// hostile or broken Bee node cannot force an unbounded allocation. It FAILS
// CLOSED before any I/O on a nil receiver, an empty BaseURL, a nil
// HTTPClient, and a non-canonical ref (exactly 64 hex characters — the only
// wire form the /bytes endpoint accepts). An object LARGER than maxBytes
// fails the STREAM closed at the read past the bound (never a truncated
// payload masquerading as an in-bounds object), any non-200 status and every
// transport failure are DATA-FREE errors (the fixed status number may appear,
// never the response body or ref), the response body is always closed (the
// returned closer closes it and releases the per-request deadline), and
// maxBytes must be non-negative. A nil receiver fails closed instead of
// panicking.
func (s *BeeObjectStore) OpenObject(ctx context.Context, ref string, maxBytes int64) (io.ReadCloser, error) {
	if s == nil {
		return nil, errors.New("bee object stream requires a bee object store")
	}
	if strings.TrimSpace(s.BaseURL) == "" {
		return nil, errors.New("bee object stream requires a configured base url")
	}
	if s.HTTPClient == nil {
		return nil, errors.New("bee object stream requires an http client")
	}
	if !isBeeReference(ref) {
		return nil, errors.New("bee object stream requires a 64-hex object reference")
	}
	if maxBytes < 0 {
		return nil, errors.New("bounded bee stream requires a non-negative bound")
	}
	reqCtx, cancel := writeRequestContext(ctx)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, s.BaseURL+"/bytes/"+url.PathEscape(ref), nil)
	if err != nil {
		cancel()
		return nil, sanitizeBeeTransportError(reqCtx, "create bee bytes stream request", err)
	}
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		cancel()
		return nil, sanitizeBeeTransportError(reqCtx, "bee bytes stream request", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Drain a BOUNDED amount of the error body and discard it; the body
		// is untrusted and must never be echoed into an error or log.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		_ = resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("bee bytes stream failed with status %d", resp.StatusCode)
	}
	return &boundedObjectStream{
		body:   resp.Body,
		cancel: cancel,
		max:    maxBytes,
	}, nil
}

// boundedObjectStream is the ReadCloser OpenObject returns. It counts bytes
// as they stream and enforces maxBytes EXACTLY: after exactly maxBytes bytes
// have been read it probes the underlying body once — a further byte is
// overflow (data-free error), a real EOF is EOF. Reads never return more
// bytes than remain under the bound, so no caller can ever receive a
// truncated payload as if it were the full object. Close always closes the
// underlying response body and releases the per-request deadline.
type boundedObjectStream struct {
	body     io.ReadCloser
	cancel   context.CancelFunc
	max      int64
	read     int64
	limitHit bool
}

func (b *boundedObjectStream) Read(p []byte) (int, error) {
	if b.limitHit {
		// Exactly at the bound: probe for overflow.
		var probe [1]byte
		n, err := b.body.Read(probe[:])
		if n > 0 {
			return 0, errors.New("bee object stream exceeded the bound")
		}
		return 0, err
	}
	remaining := b.max - b.read
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := b.body.Read(p)
	b.read += int64(n)
	if b.read >= b.max {
		b.limitHit = true
	}
	return n, err
}

func (b *boundedObjectStream) Close() error {
	err := b.body.Close()
	b.cancel()
	return err
}

// Unpin removes a pinned Bee object reference via the pinned-content deletion
// endpoint DELETE /pins/{ref} — the object-store half of the eligible staged
// blob cleanup (Task 18). The cleanup calls it ONLY for expired finalized blobs
// whose ref is NOT referenced by committed repository state, so a live
// publication's content is never unpinned. A definitive 404 is IDEMPOTENT
// SUCCESS (the content was already unpinned — an expected retry outcome after
// a crash or concurrent reaper); any other non-2xx status — INCLUDING every
// direct 3xx redirect, which is disabled and treated as a fixed dependency
// failure — a malformed ref, or a transport failure fails closed with a
// data-free error. The unpin runs through a shallow per-call COPY of the
// caller-owned HTTP client with a fail-closed CheckRedirect (see unpinClient),
// so the caller's shared client is never mutated. Only genuine 64-hex Swarm
// references are accepted. The response body is bounded and always closed; the
// caller's deadline is respected with the same bounded per-request timeout as
// every other Bee call.
func (s *BeeObjectStore) Unpin(ctx context.Context, ref string) error {
	if s == nil {
		// A nil receiver must fail closed, never panic on field access.
		return errors.New("bee unpin requires a bee object store")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.HTTPClient == nil {
		return errors.New("bee unpin requires an http client")
	}
	if strings.TrimSpace(s.BaseURL) == "" {
		return errors.New("bee unpin requires a configured base url")
	}
	if !isBeeReference(ref) {
		return errors.New("bee unpin requires a 64-hex object reference")
	}
	reqCtx, cancel := writeRequestContext(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodDelete, s.BaseURL+"/pins/"+url.PathEscape(ref), nil)
	if err != nil {
		return sanitizeBeeTransportError(reqCtx, "create bee unpin request", err)
	}
	resp, err := unpinClient(s.HTTPClient).Do(req)
	if err != nil {
		return sanitizeBeeTransportError(reqCtx, "bee unpin request", err)
	}
	defer resp.Body.Close()
	// Drain a BOUNDED amount of the body (never the whole payload) so the
	// connection can be reused; the body is untrusted and never echoed.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// Pinned content successfully removed.
		return nil
	case resp.StatusCode == http.StatusNotFound:
		// The content is already unpinned: idempotent success.
		return nil
	default:
		// Classified dependency failure; the fixed status number may appear but
		// the body never survives into the error.
		return fmt.Errorf("bee unpin failed with status %d", resp.StatusCode)
	}
}

// unpinClient returns a fail-closed client for ONE DELETE /pins/{ref} request:
// a SHALLOW COPY of the caller-owned HTTP client with a CheckRedirect that
// never follows a redirect. A configured Bee DELETE that answers with any 3xx
// (301/302/303/307/308) can otherwise be steered to another endpoint — a 302
// becomes a GET, a 307/308 forwards the DELETE — and a redirected 2xx would be
// accepted as a successful unpin even though the deletion never happened.
// Returning http.ErrUseLastResponse from CheckRedirect stops the redirect
// chain and returns the direct 3xx as the response, which Unpin then
// classifies as a fixed dependency failure. The shallow copy preserves the
// caller's Transport, Timeout, Jar, and every other field (connection reuse
// and deadlines are untouched) and ONLY overrides CheckRedirect, so the
// caller-owned shared client is never mutated and concurrent Unpin calls on it
// do not race.
func unpinClient(client *http.Client) *http.Client {
	c := new(http.Client)
	*c = *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
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

// PutStream uploads an object to /bytes by streaming an io.Reader with an
// EXACT declared size and an explicit postage batch id — the registry blob
// finalization path. It never buffers the payload in memory: the request body
// is the caller's reader with Content-Length pinned to size. Errors and the
// response body are handled with the same bounded, data-free discipline as
// every other Bee writer (the response is read to a fixed bound, overflow
// fails closed, and transport failures are sanitized so no URL or body detail
// leaks). Null byte-count / negative size and an empty batch id fail closed
// before any request.
func (s *BeeObjectStore) PutStream(ctx context.Context, src io.Reader, size int64, batchID string) (string, error) {
	if src == nil {
		return "", fmt.Errorf("%w: stream source is nil", resolve.ErrUploaderPreSideEffect)
	}
	if size < 0 {
		return "", fmt.Errorf("%w: negative stream size", resolve.ErrUploaderPreSideEffect)
	}
	if len(batchID) == 0 || len(batchID) > beeFeedWriteMaxRef {
		return "", fmt.Errorf("%w: empty or oversized postage batch id", resolve.ErrUploaderPreSideEffect)
	}

	reqCtx, cancel := writeRequestContext(ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, s.BaseURL+"/bytes", src)
	if err != nil {
		// No request was ever sent: conclusively no side effect.
		return "", fmt.Errorf("%w: %v", resolve.ErrUploaderPreSideEffect, sanitizeBeeTransportError(reqCtx, "create bee bytes stream put request", err))
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Swarm-Postage-Batch-Id", batchID)
	req.Header.Set("Swarm-Pin", strconv.FormatBool(s.Pin))
	req.Header.Set("Swarm-Deferred-Upload", strconv.FormatBool(s.DeferredUpload))

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return "", sanitizeBeeTransportError(reqCtx, "bee bytes stream put request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		return "", fmt.Errorf("bee bytes put failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
	if err != nil {
		return "", sanitizeBeeTransportError(reqCtx, "read bee bytes stream put response body", err)
	}
	if len(body) > beeFeedWriteMaxBody {
		return "", errors.New("bee bytes stream put response exceeded the bound")
	}
	return parseReferenceBody(body)
}

// parseReferenceBody STRICTLY parses a single-object JSON response carrying
// exactly one "reference" member whose value is a 64-hex string — used by the
// streaming /bytes success path. Duplicate/unknown members, non-string or
// malformed references, and trailing JSON all fail closed with data-free
// errors.
func parseReferenceBody(body []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return "", errors.New("upload response is not a JSON object")
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return "", errors.New("upload response is not a JSON object")
	}
	var (
		ref    string
		sawRef bool
	)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", errors.New("upload response is not a JSON object")
		}
		key, ok := keyTok.(string)
		if !ok {
			return "", errors.New("upload response is not a JSON object")
		}
		if key != "reference" {
			return "", errors.New("upload response carries an unknown member")
		}
		if sawRef {
			return "", errors.New("upload response repeats the reference member")
		}
		valTok, err := dec.Token()
		if err != nil {
			return "", errors.New("upload response reference is not a string")
		}
		value, ok := valTok.(string)
		if !ok {
			return "", errors.New("upload response reference is not a string")
		}
		ref = value
		sawRef = true
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return "", errors.New("upload response is not a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", errors.New("upload response has trailing data")
	}
	if !sawRef {
		return "", errors.New("upload response is missing the reference member")
	}
	if !isHexString(ref, 64) {
		return "", errors.New("upload response reference is not a 64-hex object reference")
	}
	return strings.ToLower(ref), nil
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

// beeFeedCreateVerifyMaxAttempts bounds the post-write effective-feed
// read-back retries performed after a CREATE-ONLY SOC 201 (Round 2). Real Bee
// may return 201 to BOTH writers of an identical zero-index SOC (pusher
// duplicate coalescing) and may be briefly eventually consistent, so the
// create-only updater proves its payload won by reading the effective feed
// back before declaring success. A conclusive 404 (not yet visible) is the
// ONLY retried outcome; malformed/5xx/decode/transport failures are
// immediate dependency errors. Attempts x backoff stays comfortably inside
// the 30s write work context.
const beeFeedCreateVerifyMaxAttempts = 6

// beeFeedCreateVerifyBackoff is the fixed pause between effective-feed
// read-back attempts (the default when the updater's own createVerifyBackoff
// field is zero). Five pauses of 200ms bound the retry delay to ~1s above the
// per-request timeouts, and every retry is READ-ONLY: the chunk/SOC write is
// never resubmitted.
const beeFeedCreateVerifyBackoff = 200 * time.Millisecond

// beeFeedCreateZeroIndex is the exact hex sequence index a create-only feed
// MUST settle at: sequence zero. Any other index means the feed advanced —
// this update is not (and cannot become) the zero-index creation.
const beeFeedCreateZeroIndex = "0000000000000000"

// ---------- bounded default HTTP client ----------
//
// Bee interactions MUST never fall back to the bare process-global
// http.DefaultClient: its zero timeouts would let a stalled or hung Bee node
// block a request forever. defaultHTTPClient therefore substitutes a
// process-wide bounded client (connect/TLS-handshake/response-header/idle
// transport deadlines plus an overall per-request Timeout) whenever a caller
// supplies none. Production binaries construct their own configured client
// once and inject it explicitly through the constructors; this default exists
// so a zero-value or directly-constructed struct can never hang unbounded.
//
// Timeout is set LARGER than the per-request context deadlines the writer and
// bounded-reader paths already impose (beeFeedResolveTimeout /
// beeFeedWriteTimeout), so on those paths the request-context deadline fires
// first and its errors.Is(context.DeadlineExceeded) signal is preserved by the
// sanitizer; paths without an internal deadline (document/object reads) are
// bounded by the transport response-header timeout and Timeout instead.
const (
	beeDefaultConnectTimeout        = 10 * time.Second
	beeDefaultTLSHandshakeTimeout   = 10 * time.Second
	beeDefaultResponseHeaderTimeout = 30 * time.Second
	beeDefaultIdleConnTimeout       = 90 * time.Second
	beeDefaultRequestTimeout        = 60 * time.Second
)

var (
	beeBoundedClientOnce sync.Once
	beeBoundedClient     *http.Client
)

// boundedHTTPClient builds (once) the bounded default client. It clones the
// standard transport so Proxy, keep-alive, and other Go defaults are
// preserved, then applies the explicit deadlines.
func boundedHTTPClient() *http.Client {
	beeBoundedClientOnce.Do(func() {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.DialContext = (&net.Dialer{Timeout: beeDefaultConnectTimeout, KeepAlive: 30 * time.Second}).DialContext
		base.TLSHandshakeTimeout = beeDefaultTLSHandshakeTimeout
		base.ResponseHeaderTimeout = beeDefaultResponseHeaderTimeout
		base.IdleConnTimeout = beeDefaultIdleConnTimeout
		beeBoundedClient = &http.Client{Transport: base, Timeout: beeDefaultRequestTimeout}
	})
	return beeBoundedClient
}

// defaultHTTPClient returns client, or when nil the process-wide bounded
// default (never http.DefaultClient) so a zero-value store still has sane
// timeouts on every Bee call.
func defaultHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return boundedHTTPClient()
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
// (a bounded default client when the updater's client is nil — never the bare
// http.DefaultClient) so a zero-value or under-configured updater never panics
// on a nil receiver client.
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

// nextSequenceIndex reads the next sequence index for the feed. A conclusive
// 404 (never written) is the zero index; every non-404 failure is a wrapped,
// data-free dependency error. In CREATE-ONLY mode a 200 is the definitive
// already-existing outcome: the feed EXISTS, so the update must not proceed —
// the stable ErrFeedAlreadyExists sentinel is returned BEFORE any /chunks or
// /soc write (zero write side effects). Non-404 lookup failures stay
// dependency errors, never an already-exists classification.
func (u *BeeSequenceFeedUpdater) nextSequenceIndex(ctx context.Context, owner string, topic string, createOnly bool) ([]byte, error) {
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
	if createOnly && resp.StatusCode == http.StatusOK {
		// The feed EXISTS: a create-only update must never touch it. The 200
		// BEARS the feed's index headers, so drain a bounded amount and return
		// the stable sentinel — no write has happened (the lookup runs before
		// /chunks; see Update).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		return nil, fmt.Errorf("create-only feed update: %w", ErrFeedAlreadyExists)
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
	// Bee defaults to a deferred upload that pushes in the background; a
	// feed update then stays invisible for about a minute and the
	// read-after-write verification fails. Push synchronously.
	req.Header.Set("Swarm-Deferred-Upload", "false")

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
//
// CREATE-ONLY (Task 13) closes the lookup TOCTOU at the SOC layer, and Round
// 2 adds the post-write read-back. The zero-index SOC identifier is identical
// for every first writer on this feed, and Bee SOCs are IMMUTABLE — the first
// accepted write pins the address. Real Bee (ethersphere/bee master
// pkg/api/soc.go socUploadHandler; openapi Swarm.yaml) returns 201 for the
// stored writer, collapses EVERY chunk-write failure — including the
// immutable-alias conflict — to 400 "chunk write error" (no 409 in the
// current contract), AND (Round 2 root fact) may return 201 to BOTH writers
// of the identical SOC when the pusher coalesces the duplicate in-flight
// operation. So a 201 here is never treated as proof this payload won: for a
// create-only update the caller (Update) verifies the effective feed by
// bounded read-back (see verifyCreateOnlyFeed) and only then reports success.
// On a non-201 create-only response: an explicit 409 (some Bee versions /
// edge layers surface the conflict that way) is a definite
// ErrFeedAlreadyExists, and a 400 is disambiguated with the precise
// conditional probe GET /soc/{owner}/{id} (socGetHandler: 200 +
// application/octet-stream raw span-stripped 32-byte payload + strictly
// validated Swarm-Soc-Signature header when the SOC exists, 404 when
// absent): exists → ErrFeedAlreadyExists; absent or a failed/malformed
// probe → the original dependency error. A lost creation race is thus NEVER
// success and NEVER an overwrite.
func (u *BeeSequenceFeedUpdater) uploadSOC(ctx context.Context, owner string, identifier []byte, signature []byte, chunkData []byte, batchID string, createOnly bool) error {
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
	// Bee defaults to a deferred upload that pushes in the background; a
	// feed update then stays invisible for about a minute and the
	// read-after-write verification fails. Push synchronously.
	req.Header.Set("Swarm-Deferred-Upload", "false")

	resp, err := client.Do(req)
	if err != nil {
		return sanitizeBeeTransportError(reqCtx, "soc upload request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		if createOnly {
			switch resp.StatusCode {
			case http.StatusConflict:
				// Definite conflict: the immutable (owner, identifier) already
				// holds another writer's chunk, and THIS write did not apply.
				return fmt.Errorf("create-only feed update: %w", ErrFeedAlreadyExists)
			case http.StatusBadRequest:
				// Ambiguous: current Bee maps EVERY chunk-write failure —
				// including the racing creator's immutable-SOC alias conflict —
				// to 400 "chunk write error". Disambiguate with the precise
				// conditional probe: if the zero-index SOC now exists, the
				// other writer won the race; otherwise this is a genuine write
				// failure (dependency error).
				exists, perr := u.socExists(ctx, owner, identifier)
				if perr == nil && exists {
					return fmt.Errorf("create-only feed update: %w", ErrFeedAlreadyExists)
				}
			}
		}
		return fmt.Errorf("soc upload failed with status %d", resp.StatusCode)
	}
	// Drain a bounded amount so the connection can be reused; see the SOC
	// response contract note in the doc comment above — the body is ignored.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
	return nil
}

// socExists probes whether a single-owner chunk already exists at the
// immutable (owner, identifier) address — the PRECISE conditional mechanism
// the create-only 400 disambiguation uses (ethersphere/bee pkg/api/soc.go
// socGetHandler, master + v2.5.0 + v2.4.x: 200 when the SOC is present, 404
// when absent).
//
// The presence 200 is validated against the REAL Bee wire contract (Round 3
// correction — the earlier JSON-body expectation was wrong): socGetHandler
// serves the chunk payload through the download handler as
// application/octet-stream with the 8-byte span STRIPPED, plus exactly ONE
// Swarm-Soc-Signature header whose value is the hex-encoded 65-byte
// secp256k1 recoverable signature (130 hex chars). For this feed SOC the POST
// body is the 8-byte span + the 32-byte reference, so the GET body is the
// exact raw 32-byte reference payload. The body is read with a bounded
// LimitReader(33) and must be EXACTLY 32 bytes — 0/31/33/oversized bodies
// and read errors all fail closed, never silently truncated. Any 32 bytes
// are a syntactically valid immutable feed payload, so the body is
// deliberately NOT compared to the reference this write attempted: an
// existing race winner legitimately differs and still proves the conflict.
//
// The signature is NOT cryptographically re-verified in-process: doing so
// would require recomputing the chunk's Swarm content address (the BMT root
// over the span-prefixed chunk, which the digest keccak256(identifier ||
// chunkRef) binds), and this module deliberately does not reimplement BMT.
// Existence instead relies on the exact signature-shape/body contract plus
// the trust boundary of the configured Bee endpoint (the validated http(s)
// origin from BEE_API_URL, typically TLS). Nothing from the response is
// ever echoed.
//
// A 200 is existence ONLY when the content type is exactly
// application/octet-stream (one header line, mime-parseable, NO parameters —
// duplicate/absent/malformed/parameterized values fail closed), the
// signature header is exactly valid, and the body is exactly 32 bytes.
// A malformed 200, a redirect/3xx, a 5xx, a transport failure, or an
// unreadable body all fail the probe as a DEPENDENCY error — NEVER existence
// and NEVER ErrFeedAlreadyExists, because an arbitrary intermediary 200
// (captive proxy, gateway, cache) must never be mistaken for the immutable
// SOC. Only a definitive Bee 404 is absence. The body is bounded and always
// closed; errors are data-free (the requested owner/identifier and any
// injected response text never surface).
//
// VERSION NOTE: GET /soc exists on Bee master and the v2.5/v2.4 lines.
// Older releases (v2.1, v1.18) may not expose the endpoint, so their probe
// answers (404 / 405 / any other failure) stay CONSERVATIVE UNCERTAINTY —
// the original 400 write failure remains the returned dependency error, and
// a missing probe endpoint can never produce a false existence or a false
// conflict.
func (u *BeeSequenceFeedUpdater) socExists(ctx context.Context, owner string, identifier []byte) (bool, error) {
	baseURL, err := u.writerBaseURL()
	if err != nil {
		return false, err
	}
	client := u.writerClient()
	reqCtx, cancel := writeRequestContext(ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, baseURL+"/soc/"+url.PathEscape(owner)+"/"+hex.EncodeToString(identifier), nil)
	if err != nil {
		return false, sanitizeBeeTransportError(reqCtx, "create soc probe request", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, sanitizeBeeTransportError(reqCtx, "soc probe request", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		// Definitive absence: drain a bounded amount so the connection can be
		// reused; the body is never a value.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		return false, nil
	case http.StatusOK:
		// The ONE acceptable presence shape: strict content type AND strict
		// signature header AND the exact raw 32-byte payload. Anything else
		// is a dependency error.
		if err := socContentType(resp.Header); err != nil {
			return false, err
		}
		if _, err := socSignatureHeader(resp.Header); err != nil {
			return false, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 33))
		if err != nil {
			return false, sanitizeBeeTransportError(reqCtx, "read soc probe response body", err)
		}
		if len(body) != 32 {
			return false, errors.New("soc probe response body is not a 32-byte immutable reference")
		}
		return true, nil
	default:
		// 3xx/4xx-other/5xx: drain a bounded amount for connection reuse and
		// fail the probe as a dependency error, never existence.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedWriteMaxBody+1))
		return false, fmt.Errorf("soc probe failed with status %d", resp.StatusCode)
	}
}

// socContentType strictly validates the Content-Type of a GET /soc probe 200
// response: EXACTLY ONE header line must be present (duplicate lines reach
// the client as multiple values and fail closed, and a single
// comma-merged/smuggled value fails mime parsing), the value must parse with
// mime.ParseMediaType, the media type must be exactly application/octet-stream
// (case-insensitive), and it must carry NO parameters. Bee's socGetHandler
// serves the SOC chunk payload through the download handler as a bare
// application/octet-stream body, so an absent/empty value, a wrong type, a
// parameterized value, or a malformed value is a data-free dependency error,
// never existence. Errors never echo the header value.
func socContentType(h http.Header) error {
	values := h.Values("Content-Type")
	if len(values) != 1 {
		return errors.New("soc probe response must carry exactly one content type header")
	}
	v := strings.TrimSpace(values[0])
	mediaType, params, err := mime.ParseMediaType(v)
	if err != nil {
		return errors.New("soc probe response content type is malformed")
	}
	if !strings.EqualFold(mediaType, "application/octet-stream") {
		return errors.New("soc probe response content type is not application/octet-stream")
	}
	if len(params) != 0 {
		return errors.New("soc probe response content type carries unexpected parameters")
	}
	return nil
}

// socSignatureHeader strictly validates the Swarm-Soc-Signature header of a
// GET /soc probe 200 response: EXACTLY ONE header line must be present
// (duplicates fail closed, and a single comma/semicolon-joined line — a
// smuggled second value — fails closed), bounded, and hex-decode to EXACTLY
// 65 bytes (Bee's recoverable secp256k1 signature: 32-byte R, 32-byte S, 1
// recovery byte — 130 hex chars). A missing, empty, malformed, wrong-size, or
// oversized value is a data-free dependency error, never existence.
func socSignatureHeader(h http.Header) ([]byte, error) {
	values := h.Values("Swarm-Soc-Signature")
	if len(values) != 1 {
		return nil, errors.New("soc probe response must carry exactly one signature header")
	}
	v := strings.TrimSpace(values[0])
	if v == "" {
		return nil, errors.New("soc probe signature header is empty")
	}
	if len(v) > beeFeedWriteMaxRef {
		return nil, errors.New("soc probe signature header exceeds the bound")
	}
	if strings.ContainsAny(v, ",;") {
		return nil, errors.New("soc probe signature header is malformed")
	}
	if !isHexString(v, 130) {
		return nil, errors.New("soc probe signature header is not a 65-byte signature")
	}
	raw, err := hex.DecodeString(v)
	if err != nil {
		return nil, errors.New("soc probe signature header is not a 65-byte signature")
	}
	return raw, nil
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

// signSOCIdentifier signs keccak256(id||ref) the way Bee's SOC handler
// verifies it: EIP-191 personal_sign prefix over the digest, and the
// recovery byte offset by 27. A raw-digest signature is rejected by Bee
// with 401 "invalid chunk".
func signSOCIdentifier(identifier []byte, wrappedChunkRef []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	digest := ethcrypto.Keccak256(append(append([]byte{}, identifier...), wrappedChunkRef...))
	prefixed := ethcrypto.Keccak256([]byte("\x19Ethereum Signed Message:\n32"), digest)
	signature, err := ethcrypto.Sign(prefixed, privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign soc digest: %w", err)
	}
	signature[64] += 27
	return signature, nil
}
