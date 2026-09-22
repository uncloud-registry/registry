package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

// InternalFeedUpdatePath is the exact internal feed-update endpoint path. The
// internal feed-signing server accepts ONLY this path on POST; nothing else is
// served, so a caller cannot discover or reach unrelated control-plane routes
// through the internal credential.
const InternalFeedUpdatePath = "/internal/v1/feed-updates"

// InternalAuthHeader is the dedicated credential header the registry data
// plane sends on every internal feed-commit request. It is distinct from the
// public Authorization header so an internal request can never be confused
// with (or benefit from) a browser/session credential, and it never carries a
// user session, registry token, or feed-owner key.
const InternalAuthHeader = "X-Uncloud-Internal-Auth"

// FeedCommitRequest is the exact request the registry data plane sends to the
// control-plane internal feed signer. Field/JSON names are the fixed contract
// from the Task 10 interface. Topic is the FULL deterministic repository-state
// feed reference (feed://<owner>/<topichex>).
type FeedCommitRequest struct {
	OperationID        string `json:"operationID"`
	RegistryID         int64  `json:"registryID"`
	Owner              string `json:"owner"`
	Topic              string `json:"topic"`
	Reference          string `json:"reference"`
	BatchID            string `json:"batchID"`
	ExpectedGeneration int64  `json:"expectedGeneration"`
}

// FeedCommitResult is the exact response a successful feed commit returns.
type FeedCommitResult struct {
	OperationID string `json:"operationID"`
	Feed        string `json:"feed"`
	Reference   string `json:"reference"`
}

// Stable sentinel errors mapping the internal service's coarse statuses. They
// carry no internal error text, secrets, or topology, and every raw transport/
// decode/build detail is REDUCED to one of them before it can cross a caller
// boundary.
var (
	// ErrCommitUnauthorized is returned when the control plane rejects the
	// internal credential (401).
	ErrCommitUnauthorized = errors.New("internal feed signing rejected the credential")
	// ErrCommitMalformed is returned when the control plane rejects the
	// request as malformed (400) or when the client cannot build/send a valid
	// request.
	ErrCommitMalformed = errors.New("invalid feed commit request rejected")
	// ErrCommitUnknownRegistry is returned when the registry ID does not exist
	// or the caller's owner does not belong to it (404).
	ErrCommitUnknownRegistry = errors.New("registry is unknown to the feed signing service")
	// ErrCommitConflict is returned when reusing an operation ID with different
	// input, or when the repository generation advanced elsewhere (409).
	ErrCommitConflict = errors.New("feed commit operation conflict")
	// ErrCommitBackend is a retryable control-plane/Bee/dependency failure (503).
	// It is also the class to which every raw network, dial, timeout, URL,
	// TLS, decode, and validation-of-response failure collapses, so no host/
	// port/path/topology or response body ever reaches err.Error().
	ErrCommitBackend = errors.New("feed signing service is temporarily unavailable")
)

// CommitResponseMaxBody bounds the internal feed-commit response body.
const CommitResponseMaxBody = 4096

// CommitRequestMaxBody bounds the internal feed-commit request body.
const CommitRequestMaxBody = 16384

// Bounded string-length contract for every request field.
const (
	operationIDMaxLen = 128
	ownerMaxLen       = 128
	topicMaxLen       = 256
	batchIDMaxLen     = 128
)

// commitRequestTimeout is the per-request deadline applied via the request
// context even when the supplied HTTP client has no Timeout configured.
const commitRequestTimeout = 30 * time.Second

// ControlPlaneCommitter commits an immutable repository-state reference through
// the control plane's internal feed-signing service. It carries NO key
// material. The internal credential (Secret) authenticates the registry data
// plane and is mounted from a secret file.
type ControlPlaneCommitter struct {
	// BaseURL is the control-plane internal feed-signing origin, validated and
	// canonicalized by Commit: absolute http(s), host required, no userinfo,
	// path (beyond empty or "/"), query, or fragment. Plaintext http is
	// accepted ONLY for a loopback host; any non-loopback origin must use
	// https.
	BaseURL string
	// Secret is the internal service credential bytes loaded from a secret
	// file. It is never echoed.
	Secret []byte
	// HTTPClient is the transport; a nil client uses http.DefaultClient.
	HTTPClient *http.Client
	// Logger, when set, records the raw transport/diagnostic detail that is
	// deliberately NOT propagated in returned errors (data-free to callers).
	Logger *slog.Logger
}

func (c ControlPlaneCommitter) logf(msg string, args ...any) {
	if c.Logger != nil {
		c.Logger.Warn(msg, args...)
	}
}

// Commit sends one authenticated, bounded feed-commit request, strictly decodes
// and canonically VERIFIES the result against the request, and returns only a
// fixed sentinel class on any failure. A successful result is never returned
// unless its OperationID/Feed/Reference EXACTLY match the (canonicalized)
// request; a mismatched, malformed, or duplicated response is a fail-closed
// backend error, never an accepted success. Every raw network/URL/decode error
// collapses to ErrCommitBackend so no URL/host/port/dial/body leaks through
// err.Error(). There is no retry loop here: safe retries use the same
// OperationID idempotency contract the caller owns.
func (c ControlPlaneCommitter) Commit(ctx context.Context, req FeedCommitRequest) (FeedCommitResult, error) {
	baseURL, err := parseCommitBaseURL(c.BaseURL)
	if err != nil {
		c.logf("internal commit: invalid base URL", "err", err.Error())
		return FeedCommitResult{}, ErrCommitBackend
	}
	if len(c.Secret) == 0 {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if err := validateCommitRequestShape(req); err != nil {
		return FeedCommitResult{}, ErrCommitMalformed
	}

	body, err := json.Marshal(req)
	if err != nil {
		return FeedCommitResult{}, ErrCommitMalformed
	}
	if len(body) > CommitRequestMaxBody {
		return FeedCommitResult{}, ErrCommitMalformed
	}

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	reqCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, commitRequestTimeout)
		defer cancel()
	}

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+InternalFeedUpdatePath, bytes.NewReader(body))
	if err != nil {
		return FeedCommitResult{}, ErrCommitMalformed
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(InternalAuthHeader, string(c.Secret))

	resp, err := client.Do(httpReq)
	if err != nil {
		// Raw dial/TLS/timeout detail is correlated locally, never returned.
		c.logf("internal commit: transport failure")
		return FeedCommitResult{}, ErrCommitBackend
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, CommitResponseMaxBody+1))
	if err != nil {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if len(respBody) > CommitResponseMaxBody {
		return FeedCommitResult{}, ErrCommitBackend
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return decodeCommitResult(respBody, req)
	case http.StatusUnauthorized:
		return FeedCommitResult{}, ErrCommitUnauthorized
	case http.StatusBadRequest:
		return FeedCommitResult{}, ErrCommitMalformed
	case http.StatusNotFound:
		return FeedCommitResult{}, ErrCommitUnknownRegistry
	case http.StatusConflict:
		return FeedCommitResult{}, ErrCommitConflict
	default:
		// 503 and anything else on the backend side is retryable/dependency.
		return FeedCommitResult{}, ErrCommitBackend
	}
}

// parseCommitBaseURL validates and canonicalizes the internal feed-signing
// origin: absolute http(s), host required, no userinfo, no path beyond empty
// or "/", no query, no fragment. Plaintext http is allowed ONLY for a loopback
// host (127.0.0.0/8, ::1, or localhost); any other host must use https. The
// returned value is the canonical scheme://host[:port] origin.
func parseCommitBaseURL(raw string) (string, error) {
	raw = strings.TrimRight(raw, "/")
	if raw == "" {
		return "", errors.New("control plane URL is not configured")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("control plane URL is not an absolute origin")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("control plane URL must be http or https")
	}
	if u.User != nil {
		return "", errors.New("control plane URL must not contain userinfo")
	}
	if u.RawQuery != "" {
		return "", errors.New("control plane URL must not contain a query")
	}
	if u.Fragment != "" {
		return "", errors.New("control plane URL must not contain a fragment")
	}
	if p := u.EscapedPath(); p != "" && p != "/" {
		return "", errors.New("control plane URL must be an origin with no path")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return "", errors.New("control plane URL uses plaintext http for a non-loopback host")
	}
	return u.Scheme + "://" + u.Host, nil
}

func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	// Strip IPv6 brackets before parsing.
	h := host
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return false // a DNS name is not provably loopback
	}
	return addr.IsLoopback()
}

// decodeCommitResult STRICTLY decodes a bounded successful response: duplicate
// members anywhere, unknown top-level fields, trailing content, malformed or
// unbounded field values, and a result that does not canonically match the
// request are all rejected. Only a fully validated, request-equal result is
// returned as success.
func decodeCommitResult(data []byte, req FeedCommitRequest) (FeedCommitResult, error) {
	if err := rejectDuplicateJSONMembers(data); err != nil {
		return FeedCommitResult{}, ErrCommitBackend
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var result FeedCommitResult
	if err := dec.Decode(&result); err != nil {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if err := ValidateCommitResult(result); err != nil {
		return FeedCommitResult{}, ErrCommitBackend
	}
	// Canonical constant/normal comparison of every result field to the
	// request before success; the publisher must never accept an unrelated
	// result.
	if result.OperationID != req.OperationID {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if result.Feed != CanonicalTopic(req.Topic) {
		return FeedCommitResult{}, ErrCommitBackend
	}
	if result.Reference != CanonicalReference(req.Reference) {
		return FeedCommitResult{}, ErrCommitBackend
	}
	return result, nil
}

// validateCommitRequestShape applies the client-side bounded syntax contract.
func validateCommitRequestShape(req FeedCommitRequest) error {
	if req.OperationID == "" || len(req.OperationID) > operationIDMaxLen {
		return errors.New("operationID must be non-empty and bounded")
	}
	if req.RegistryID <= 0 {
		return errors.New("registryID must be positive")
	}
	if req.Owner == "" || len(req.Owner) > ownerMaxLen {
		return errors.New("owner must be non-empty and bounded")
	}
	if req.Topic == "" || len(req.Topic) > topicMaxLen {
		return errors.New("topic must be non-empty and bounded")
	}
	if !IsHexReference(req.Reference) {
		return errors.New("reference must be a 64-hex immutable object reference")
	}
	if req.BatchID == "" || len(req.BatchID) > batchIDMaxLen {
		return errors.New("batchID must be non-empty and bounded")
	}
	if req.ExpectedGeneration < 0 {
		return errors.New("expectedGeneration must be non-negative")
	}
	return nil
}

// ValidateCommitRequest applies the bounded client-side syntax contract so the
// control-plane feed signer and the data-plane client share exactly the same
// acceptance rules.
func ValidateCommitRequest(req FeedCommitRequest) error {
	return validateCommitRequestShape(req)
}

// IsHexReference reports whether s is a 64-character lowercase or uppercase
// hexadecimal immutable object reference.
func IsHexReference(s string) bool {
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

// CanonicalTopic returns the canonical deterministic form of a repository
// state feed reference: feed://<normalized-owner>/<lowercase topic hex>. It is
// the shared canonical form the client, signer, and stored result all compare
// against, so a casing/whitespace difference can never fabricate a mismatch.
func CanonicalTopic(topic string) string {
	const prefix = "feed://"
	if !strings.HasPrefix(topic, prefix) {
		return strings.ToLower(topic)
	}
	rest := topic[len(prefix):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return prefix + spec.NormalizeOwner(rest[:i]) + "/" + strings.ToLower(rest[i+1:])
	}
	return prefix + spec.NormalizeOwner(rest)
}

// CanonicalReference returns the canonical lowercase form of a 64-hex object
// reference.
func CanonicalReference(ref string) string {
	return strings.ToLower(ref)
}

// ValidateCommitResult enforces the bounded, canonical field contract on a
// FeedCommitResult (used on both the wire response and the stored result).
func ValidateCommitResult(result FeedCommitResult) error {
	if result.OperationID == "" || len(result.OperationID) > operationIDMaxLen {
		return errors.New("result operationID must be non-empty and bounded")
	}
	if result.Feed == "" || len(result.Feed) > topicMaxLen || result.Feed != CanonicalTopic(result.Feed) {
		return errors.New("result feed must be a canonical feed reference")
	}
	if !IsHexReference(result.Reference) || result.Reference != CanonicalReference(result.Reference) {
		return errors.New("result reference must be a canonical 64-hex value")
	}
	return nil
}

// rejectDuplicateJSONMembers rejects duplicate member names anywhere in a JSON
// object so encoding/json's last-wins behavior cannot silently accept a
// duplicated control-plane result field.
func rejectDuplicateJSONMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walkJSON(dec)
}

func walkJSON(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			members := make(map[string]struct{})
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyTok.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if _, dup := members[key]; dup {
					return fmt.Errorf("duplicate object member %q", key)
				}
				members[key] = struct{}{}
				if err := walkJSON(dec); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walkJSON(dec); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		default:
			return errors.New("unexpected delimiter")
		}
	case string, json.Number, bool, nil:
		return nil
	default:
		return errors.New("unexpected token")
	}
}

// ComputeOperationID derives a stable, deterministic, PROVISIONAL operation ID
// for a logical repository publication from its immutable identity: registry,
// owner, repository, tag, the manifest content digest, and the expected
// (current) generation. It canonicalizes the owner (via NormalizeOwner) and
// encodes every typed field with binary fixed-width (int64) or length-prefixed
// (string) framing so no NUL/separator byte inside a value can create a field
// boundary collision. Because it is a pure function of the immutable logical
// publication, retrying the SAME publication computes the same OperationID.
//
// NOTE: Task 14 owns the FINAL stable-operation-ID and read-after-write retry
// semantics at the manifest-PUT caller boundary. This provisional form keeps
// the current caller wiring buildable and durable-idempotent for a supplied
// OperationID, but does NOT itself solve Task 14's public retry contract.
func ComputeOperationID(registryID int64, owner string, repo string, tag string, manifestDigest string, expectedGeneration int64) string {
	h := sha256.New()
	h.Write([]byte("uncloud-registry-feed-commit-op:v1\x00"))
	writeInt64Field(h, registryID)
	writeStringField(h, spec.NormalizeOwner(owner))
	writeStringField(h, repo)
	writeStringField(h, tag)
	writeStringField(h, manifestDigest)
	writeInt64Field(h, expectedGeneration)
	return hex.EncodeToString(h.Sum(nil))
}

func writeStringField(h io.Writer, s string) {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(s)))
	h.Write(lb[:])
	h.Write([]byte(s))
}

func writeInt64Field(h io.Writer, v int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	h.Write(b[:])
}
