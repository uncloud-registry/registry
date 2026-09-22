package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
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
// carry no internal error text, secrets, or topology.
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
	ErrCommitBackend = errors.New("feed signing service is temporarily unavailable")
)

// CommitResponseMaxBody bounds the internal feed-commit response body. A
// successful result is a tiny JSON object; 4 KiB is far beyond it while still
// bounding hostile output before a single decode.
const CommitResponseMaxBody = 4096

// CommitRequestMaxBody bounds the internal feed-commit request body. The
// request is a handful of bounded strings; 16 KiB is far beyond it.
const CommitRequestMaxBody = 16384

// Bounded string-length contract for every request field. The control plane
// enforces the same (or stricter) bounds server-side; these are the shared
// upper limits so the client and server can never disagree about what is
// legitimately bounded.
const (
	operationIDMaxLen = 128
	ownerMaxLen       = 128
	topicMaxLen       = 256
	batchIDMaxLen     = 128
)

// commitRequestTimeout is the per-request deadline applied via the request
// context even when the supplied HTTP client has no Timeout configured, so a
// stalled or hung control plane can never block a push indefinitely.
const commitRequestTimeout = 30 * time.Second

// ControlPlaneCommitter commits an immutable repository-state reference through
// the control plane's internal feed-signing service. It carries NO key
// material: the feed-owner signing key never leaves the control plane. The
// internal credential (Secret) authenticates the registry data plane and is
// mounted from a secret file; it is never a feed key.
type ControlPlaneCommitter struct {
	// BaseURL is the control-plane internal feed-signing origin (scheme+host
	// [+port]); the request path is always InternalFeedUpdatePath.
	BaseURL string
	// Secret is the internal service credential bytes loaded from a secret
	// file by the caller. It must be non-empty.
	Secret []byte
	// HTTPClient is the transport; a nil client uses http.DefaultClient, and
	// every request still gets a per-request context deadline.
	HTTPClient *http.Client
}

// Commit sends one authenticated, bounded feed-commit request and decodes the
// stable result. It returns one of the package sentinels mapped from the
// control plane's coarse status code, so a caller can classify failures
// without parsing text. There is deliberately NO retry loop here: retries that
// could double-advance a feed are only safe under the same OperationID
// idempotency contract, which the caller (not the transport) owns.
func (c ControlPlaneCommitter) Commit(ctx context.Context, req FeedCommitRequest) (FeedCommitResult, error) {
	baseURL := strings.TrimRight(c.BaseURL, "/")
	if baseURL == "" {
		return FeedCommitResult{}, fmt.Errorf("%w: control plane URL is not configured", ErrCommitBackend)
	}
	if len(c.Secret) == 0 {
		return FeedCommitResult{}, fmt.Errorf("%w: internal service credential is not configured", ErrCommitBackend)
	}
	if err := validateCommitRequestShape(req); err != nil {
		return FeedCommitResult{}, fmt.Errorf("%w: %v", ErrCommitMalformed, err)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return FeedCommitResult{}, fmt.Errorf("%w: encode request: %v", ErrCommitMalformed, err)
	}
	if len(body) > CommitRequestMaxBody {
		return FeedCommitResult{}, fmt.Errorf("%w: request exceeds the bound", ErrCommitMalformed)
	}

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	// Per-request timeout even when the supplied client has none: derive a
	// deadline sub-context unless the caller already imposed one, and always
	// propagate the caller's cancellation.
	reqCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, commitRequestTimeout)
		defer cancel()
	}

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+InternalFeedUpdatePath, bytes.NewReader(body))
	if err != nil {
		return FeedCommitResult{}, fmt.Errorf("%w: create request: %v", ErrCommitMalformed, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(InternalAuthHeader, string(c.Secret))

	resp, err := client.Do(httpReq)
	if err != nil {
		return FeedCommitResult{}, fmt.Errorf("%w: %v", ErrCommitBackend, err)
	}
	defer resp.Body.Close()

	// Drain a bounded amount on every path so the connection can be reused.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, CommitResponseMaxBody+1))
	if err != nil {
		return FeedCommitResult{}, fmt.Errorf("%w: read response: %v", ErrCommitBackend, err)
	}
	if len(respBody) > CommitResponseMaxBody {
		return FeedCommitResult{}, fmt.Errorf("%w: response exceeded the bound", ErrCommitBackend)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return decodeCommitResult(respBody)
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
		return FeedCommitResult{}, fmt.Errorf("%w: control plane returned status %d", ErrCommitBackend, resp.StatusCode)
	}
}

// decodeCommitResult strictly decodes a bounded successful response: unknown
// top-level fields are rejected and trailing content after the single JSON
// value is rejected.
func decodeCommitResult(data []byte) (FeedCommitResult, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var result FeedCommitResult
	if err := dec.Decode(&result); err != nil {
		return FeedCommitResult{}, fmt.Errorf("%w: decode result: %v", ErrCommitBackend, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return FeedCommitResult{}, fmt.Errorf("%w: trailing response content", ErrCommitBackend)
	}
	return result, nil
}

// validateCommitRequestShape applies the client-side bounded syntax contract so
// a malformed request is rejected before the network. The control plane applies
// the SAME (and stronger) validation server-side; this only fails the client
// fast.
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
	if !isHexReference(req.Reference) {
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
// acceptance rules for the fixed FeedCommitRequest shape.
func ValidateCommitRequest(req FeedCommitRequest) error {
	return validateCommitRequestShape(req)
}

func isHexReference(s string) bool {
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

// ComputeOperationID derives a stable, deterministic operation ID for a logical
// repository publication from its immutable identity: registry, owner,
// repository, tag, the manifest content digest, and the expected (current)
// generation. Because it is a pure function of the immutable logical
// publication, retrying the SAME publication computes the same OperationID and
// the same FeedCommitRequest, so the control plane's durable idempotency
// returns the stored result without advancing the feed twice. The returned
// value is domain-separated so it cannot collide with any other ID domain.
func ComputeOperationID(registryID int64, owner string, repo string, tag string, manifestDigest string, expectedGeneration int64) string {
	h := sha256.New()
	h.Write([]byte("uncloud-registry-feed-commit-op:v1\x00"))
	h.Write([]byte(strconv.FormatInt(registryID, 10)))
	h.Write([]byte{0})
	h.Write([]byte(owner))
	h.Write([]byte{0})
	h.Write([]byte(repo))
	h.Write([]byte{0})
	h.Write([]byte(tag))
	h.Write([]byte{0})
	h.Write([]byte(manifestDigest))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(expectedGeneration, 10)))
	return hex.EncodeToString(h.Sum(nil))
}
