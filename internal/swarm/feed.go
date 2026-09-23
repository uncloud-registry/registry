package swarm

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/uncloud-registry/registry/internal/resolve"
)

// FeedUpdate is the explicit, complete description of ONE sequence-feed
// update. Task 11 introduced it so the signer never has to guess which value
// is the postage batch and which is the immutable content reference: the feed
// identifier, the 64-hex object reference, and the Bee postage batch id are
// carried explicitly and validated independently BEFORE any network call.
//
// Feed must be the canonical full-feed wire form
// "feed://<40 lowercase hex owner>/<64 lowercase hex topic>"; Reference must
// be exactly 64 hex characters (32 bytes); BatchID must be exactly 64 hex
// characters (the exact Bee SwarmAddress postage-batch syntax). Anything else
// is rejected with a data-free error and ZERO requests issued to Bee.
//
// CreateOnly is the explicit creation intent (Task 13): when true, Update
// writes the feed's FIRST update ONLY — the sequence lookup must be a
// conclusive 404 (never written), the strict next-index contract is followed
// for the zero index, and any observation that the feed (or its immutable
// zero-index SOC) already exists returns the stable ErrFeedAlreadyExists
// sentinel BEFORE any /chunks or /soc write. The lookup is performed before
// the chunk upload so a create-only update against an existing feed has ZERO
// write side effects.
type FeedUpdate struct {
	Feed       string
	Reference  string
	BatchID    string
	CreateOnly bool
}

// ErrFeedAlreadyExists is the stable typed outcome of a CREATE-ONLY feed
// update that lost the creation race: the feed (or its immutable zero-index
// single-owner chunk) already exists. It is NEVER a success and NEVER an
// overwrite; the caller decides retry/conflict semantics. It carries no
// payload/URL/body data — only its identity.
var ErrFeedAlreadyExists = errors.New("feed already exists")

// FeedValue is the parsed result of reading a Bee sequence feed back:
// Reference is the normalized lowercase 64-hex immutable reference stored at
// the feed, and Index is the exact "swarm-feed-index" header value — the
// index of the found update — returned by the Bee /feeds endpoint as-is
// (hex-encoded 8-byte sequence index).
type FeedValue struct {
	Reference string
	Index     string
}

// beeFeedOwnerHexLen / beeFeedTopicHexLen mirror the canonical feed grammar
// the production contract (publish.ParseCanonicalFeed) enforces: a 40-char
// lowercase-hex owner address and a 64-char lowercase-hex topic digest.
const (
	beeFeedOwnerHexLen  = 40
	beeFeedTopicHexLen  = 64
	beeFeedCanonicalLen = len("feed://") + beeFeedOwnerHexLen + 1 + beeFeedTopicHexLen // 112
)

// isLowerHexString reports whether s is exactly n lowercase hex characters.
func isLowerHexString(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// isHexString reports whether s is exactly n hex characters of either case.
func isHexString(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// parseCanonicalFeedUpdateFeed validates that feed is EXACTLY the canonical
// full-feed wire form the production contract requires for a signed feed
// update and returns its owner and topic segments. It is deliberately strict:
// a non-canonical form (wrong length, non-hex, uppercase owner, extra slash,
// missing scheme) is rejected with a data-free error before any network call.
func parseCanonicalFeedUpdateFeed(feed string) (owner string, topic string, err error) {
	if len(feed) != beeFeedCanonicalLen || !strings.HasPrefix(feed, "feed://") {
		return "", "", errors.New("feed update feed is not a canonical feed reference (feed://<40 lowercase hex owner>/<64 lowercase hex topic>)")
	}
	rest := feed[len("feed://"):]
	if rest[beeFeedOwnerHexLen] != '/' {
		return "", "", errors.New("feed update feed is not a canonical feed reference (feed://<40 lowercase hex owner>/<64 lowercase hex topic>)")
	}
	owner = rest[:beeFeedOwnerHexLen]
	topic = rest[beeFeedOwnerHexLen+1:]
	if !isLowerHexString(owner, beeFeedOwnerHexLen) || !isLowerHexString(topic, beeFeedTopicHexLen) {
		return "", "", errors.New("feed update feed is not a canonical feed reference (feed://<40 lowercase hex owner>/<64 lowercase hex topic>)")
	}
	return owner, topic, nil
}

// Update publishes ONE sequence-feed update with the explicit postage batch.
//
// EVERY value is validated BEFORE any network call, with a data-free error:
// the feed must be the canonical full-feed wire form, the signer owner must
// equal the feed owner, the reference must be exactly 64 hex characters (32
// bytes), and the batch must be exactly 64 hex characters (the exact Bee
// SwarmAddress postage-batch syntax — symbolic values are never accepted).
// The reference is decoded to its 32 binary bytes and framed as the Bee chunk
// body: 8-byte little-endian span (=32) followed by those binary bytes.
// /chunks and /soc both receive the IDENTICAL framed bytes, and the batch id
// is carried unchanged in Swarm-Postage-Batch-Id on both — never substituted
// with the content reference. The next sequence index is consumed and STRICTLY
// validated (404 = zero index; missing on 200, malformed, duplicate, wrong
// size, or oversized headers fail closed before any SOC upload), matching the
// writer's bounded-I/O / timeout / closed-body / data-free-error contract.
//
// Task 13 (round 1): the sequence lookup runs BEFORE the chunk upload, so a
// create-only update against an existing feed (200 lookup) or an errored
// lookup NEVER triggers a write. A create-only update REQUIRES the lookup to
// be a conclusive 404; a 200 with the feed present returns the stable
// ErrFeedAlreadyExists sentinel. Create-only races that slip past the lookup
// (two writers, both 404) are closed at the SOC layer (see uploadSOC).
func (u *BeeSequenceFeedUpdater) Update(ctx context.Context, update FeedUpdate) error {
	if u == nil || u.PrivateKey == nil {
		return errors.New("feed updater signing key is not configured; refusing to sign feed updates")
	}

	// Reference: exactly 64 hex characters (32 bytes); normalize to its
	// lowercase form (the existing public contract canonicalizes genuine hex
	// refs) and decode to the binary payload.
	if len(update.Reference) == 0 {
		return errors.New("feed update reference is empty")
	}
	if len(update.Reference) > beeFeedWriteMaxRef {
		return errors.New("feed update reference exceeds the bound")
	}
	if !isHexString(update.Reference, 64) {
		return errors.New("feed update reference must be a 64-hex immutable object reference")
	}
	refBytes, err := hex.DecodeString(update.Reference)
	if err != nil {
		return errors.New("feed update reference must be a 64-hex immutable object reference")
	}

	// BatchID: exactly 64 hex characters — the exact Bee postage-batch syntax
	// (SwarmAddress ^[A-Fa-f0-9]{64}$). Empty, symbolic, or malformed batches
	// are rejected here, before any network call; the value is then passed
	// UNCHANGED to Bee.
	if len(update.BatchID) == 0 {
		return errors.New("postage batch id is empty")
	}
	if len(update.BatchID) > beeFeedWriteMaxRef {
		return errors.New("postage batch id exceeds the bound")
	}
	if !isHexString(update.BatchID, 64) {
		return errors.New("postage batch id must be exactly 64 hex characters")
	}

	ownerHex, topicHex, err := parseCanonicalFeedUpdateFeed(update.Feed)
	if err != nil {
		return err
	}

	expectedOwner := strings.ToLower(ethcrypto.PubkeyToAddress(u.PrivateKey.PublicKey).Hex()[2:])
	if ownerHex != expectedOwner {
		return fmt.Errorf("feed owner does not match the configured signer owner")
	}

	topicBytes, err := hex.DecodeString(topicHex)
	if err != nil {
		// Unreachable after parseCanonicalFeedUpdateFeed validation; stay
		// data-free rather than echoing hex-decode jargon.
		return errors.New("decode feed topic failed")
	}

	// The Bee chunk body: 8-byte little-endian span (=32) followed by the 32
	// BINARY decoded reference bytes — identical bytes for /chunks and /soc.
	// The 64 ASCII hex characters never appear in the payload.
	chunkData := makeChunkData(refBytes)

	// Sequence lookup FIRST (Task 13): the create-only contract requires the
	// lookup outcome — conclusive 404 (never written) versus 200 (exists /
	// ErrFeedAlreadyExists) — BEFORE any write side effect. For a regular
	// update this is the same strict next-index lookup as before, just
	// reordered ahead of the chunk upload (which cannot race it: the SOC is
	// still written only after /chunks succeeds).
	nextIndex, err := u.nextSequenceIndex(ctx, ownerHex, topicHex, update.CreateOnly)
	if err != nil {
		return err
	}

	chunkRef, err := u.uploadChunk(ctx, chunkData, update.BatchID)
	if err != nil {
		return err
	}

	identifier := makeFeedIdentifier(topicBytes, nextIndex)
	signature, err := signSOCIdentifier(identifier, chunkRef, u.PrivateKey)
	if err != nil {
		return err
	}

	// createOnly is forwarded so a lost race at the immutable SOC layer
	// (identical zero-index SOC identifier; Bee accepts the first writer and
	// conflict-fails the second) maps to ErrFeedAlreadyExists, never to a
	// silent overwrite and never to a success.
	return u.uploadSOC(ctx, ownerHex, identifier, signature, chunkData, update.BatchID, update.CreateOnly)
}

// ReadFeed reads a Bee sequence feed back: GET /feeds/{owner}/{topic} serves
// the RAW BINARY chunk payload (application/octet-stream, span stripped) with
// the required hex index headers, so ReadFeed decodes the exact bounded
// 32-byte payload to a normalized lowercase 64-hex reference and returns the
// found update's index ("swarm-feed-index" header) with it. It FAILS CLOSED on
// every unsafe outcome: non-200 (data-free), body not exactly 32 bytes
// (including the old ASCII-hex form and any oversized body), missing /
// malformed / duplicated / wrong-size / oversized index header, unreadable
// body, and a stalled request (per-request context deadline). Bodies are
// bounded and always closed; errors never echo raw Bee bytes, the request URL
// (which names the owner/topic path segments), or the caller's feed value.
// Transport, request-creation, and body-read failures are sanitized to stable
// data-free messages; only the safe internal context cancellation/deadline
// outcomes keep their errors.Is signal (the sentinel is wrapped, never the
// transport error text). A nil receiver (typed nil) fails closed instead of
// panicking.
func (r *BeeFeedResolver) ReadFeed(ctx context.Context, feed string) (FeedValue, error) {
	if r == nil {
		return FeedValue{}, errors.New("bee feed resolver is not configured")
	}
	if strings.TrimSpace(r.BaseURL) == "" {
		return FeedValue{}, errors.New("bee feed resolver: base URL is not configured")
	}
	baseURL := strings.TrimRight(r.BaseURL, "/")

	owner, topic, err := parseFeedRef(feed)
	if err != nil {
		// Data-free: never quote the caller's raw feed value.
		return FeedValue{}, errors.New("bee feed resolver: invalid feed reference")
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
		// The parse error names the offending URL; never wrap it. The
		// derived request context stays the sentinel authority even on
		// pre-HTTP request-construction failure.
		return FeedValue{}, sanitizeBeeTransportError(reqCtx, "create bee feed read request", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return FeedValue{}, sanitizeBeeTransportError(reqCtx, "bee feed read request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain a bounded amount (never the whole body) so the connection can
		// be reused, but NEVER include the raw body in the returned error.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, beeFeedResolveMaxBody+1))
		if resp.StatusCode == http.StatusNotFound {
			// A definitive 404 means the feed has never been written. Wrap the
			// stable sentinel so the caller can distinguish a conclusively
			// absent feed (generation-zero creation) from every other failure.
			return FeedValue{}, fmt.Errorf("bee feed resolution failed with status %d: %w", resp.StatusCode, resolve.ErrFeedNotFound)
		}
		return FeedValue{}, fmt.Errorf("bee feed resolution failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, beeFeedResolveMaxBody+1))
	if err != nil {
		return FeedValue{}, sanitizeBeeTransportError(reqCtx, "read bee feed response body", err)
	}
	if len(body) > beeFeedResolveMaxBody {
		return FeedValue{}, errors.New("bee feed response exceeded the reference bound")
	}
	// The Task 11 feed payload is exactly the 32 binary decoded reference
	// bytes. Anything else — empty, short, long, or the old 64-byte ASCII hex
	// representation — is a malformed response.
	if len(body) != 32 {
		return FeedValue{}, errors.New("bee feed payload is not a 32-byte binary reference")
	}

	// The current feed index is REQUIRED: the reader must know exactly which
	// update it found the payload at. Header values are strictly validated
	// (exactly one, exactly 8 bytes after hex decoding, bounded).
	index, err := feedIndexHeader(resp.Header, "Swarm-Feed-Index")
	if err != nil {
		return FeedValue{}, err
	}

	return FeedValue{Reference: hex.EncodeToString(body), Index: index}, nil
}

// feedIndexHeader strictly parses a feed response's hex sequence-index header:
// exactly ONE header line must be present (duplicates fail closed), the value
// must be bounded, hex-decodable, and decode to EXACTLY 8 bytes (a Bee
// uint64 sequence index). It returns the canonical lowercase hex form.
func feedIndexHeader(h http.Header, name string) (string, error) {
	values := h.Values(name)
	if len(values) != 1 {
		return "", errors.New("feed response must carry exactly one index header")
	}
	v := strings.ToLower(strings.TrimSpace(values[0]))
	if v == "" {
		return "", errors.New("feed response index header is empty")
	}
	if len(v) > beeFeedWriteMaxRef {
		return "", errors.New("feed response index header exceeds the bound")
	}
	raw, err := hex.DecodeString(v)
	if err != nil {
		return "", errors.New("feed response index header is not valid hex")
	}
	if len(raw) != 8 {
		return "", errors.New("feed response index header is not an 8-byte sequence index")
	}
	return v, nil
}
