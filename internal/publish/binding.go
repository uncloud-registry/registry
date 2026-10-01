package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
)

// InternalOperationBindingPath is the exact internal endpoint path for
// preflight operation-key binding. The internal server accepts ONLY this and
// InternalFeedUpdatePathV2 on POST; the retired v1 feed-update path is not a
// route. Nothing else is served, so a caller cannot discover or reach
// unrelated control-plane routes through the internal credential.
const InternalOperationBindingPath = "/internal/v1/operation-bindings"

// BindingRequestMaxBody bounds the internal operation-binding request body.
// An OperationBindingRequest carries six bounded strings/ints; 16 KiB is far
// beyond it even after JSON encoding.
const BindingRequestMaxBody = 16384

// BindingResponseMaxBody bounds the internal operation-binding response body.
const BindingResponseMaxBody = 4096

// OperationBindingRequest is the exact request the registry data plane sends
// to the control plane BEFORE any immutable object write. It carries the
// caller-supplied operation key plus the FIVE immutable fields the key is
// bound to: registry, owner, repository, tag, and the manifest content
// digest. Field/JSON names are the fixed contract of the internal binding
// endpoint. The fields are NEVER persisted raw — the control plane derives a
// bounded domain-separated hash and stores only that.
type OperationBindingRequest struct {
	OperationID    string `json:"operationID"`
	RegistryID     int64  `json:"registryID"`
	Owner          string `json:"owner"`
	Repo           string `json:"repo"`
	Tag            string `json:"tag"`
	ManifestDigest string `json:"manifestDigest"`
}

// OperationBinder durably binds an explicit caller operation key to exactly
// ONE logical publication payload — registry + owner + repository + tag +
// manifest digest — BEFORE any immutable object upload, feed write, or
// staging consumption. The binding is persistent (never an in-memory map):
// a retried identical request passes, a reused key with a different payload
// is a hard conflict, and both decisions survive process restarts. It
// returns ErrCommitConflict for a conflicting reuse and the backend class
// (ErrCommitBackend etc.) for any unavailable/malformed control-plane
// outcome, so the shared publication classifier maps them unchanged.
type OperationBinder interface {
	Bind(ctx context.Context, req OperationBindingRequest) error
}

// BindingResponse is the exact success body of the internal binding endpoint.
type BindingResponse struct {
	Status string `json:"status"`
}

// repoNameMaxLen / manifestTagMaxLen are the preflight bounds on the
// repository name and tag. They are deliberately GENEROUS (pathological
// values far beyond any real client, and beyond no legitimate repository
// push): the publication path — not the preflight — remains the authority on
// OCI repo/tag grammar, so the preflight never rejects a value the commit
// path would accept. The operation-ID grammar is the strict one; repo and
// tag only need to be bounded to keep the derived binding-hash input bounded.
const (
	repoNameMaxLen    = 4096
	manifestTagMaxLen = 4096
)

// IsManifestContentDigest reports whether s is the EXACT content digest form
// the handler computes for a manifest body: "sha256:" followed by 64
// lowercase hex characters.
func IsManifestContentDigest(s string) bool {
	if len(s) != len("sha256:")+64 || !bytes.HasPrefix([]byte(s), []byte("sha256:")) {
		return false
	}
	for i := len("sha256:"); i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ValidatePublicationBindingRequest is the SINGLE shared bounded syntax
// contract for an OperationBindingRequest, applied by BOTH the data-plane
// client (before any network call) and the control-plane internal server
// (before any durable write), so the two sides can never drift. The strict
// member is the operation ID (exact Task 10 grammar); repo/tag are bounded
// non-empty values (the publication path remains the grammar authority);
// the manifest digest must be the exact canonical form.
func ValidatePublicationBindingRequest(req OperationBindingRequest) error {
	if err := ValidateOperationID(req.OperationID); err != nil {
		return errors.New("operationID must be non-empty, bounded, and a JSON-safe printable-ASCII identifier")
	}
	if req.RegistryID <= 0 {
		return errors.New("registryID must be positive")
	}
	if req.Owner == "" || len(req.Owner) > ownerMaxLen {
		return errors.New("owner must be non-empty and bounded")
	}
	if req.Repo == "" || len(req.Repo) > repoNameMaxLen {
		return errors.New("repo must be non-empty and bounded")
	}
	if req.Tag == "" || len(req.Tag) > manifestTagMaxLen {
		return errors.New("tag must be non-empty and bounded")
	}
	if !IsManifestContentDigest(req.ManifestDigest) {
		return errors.New("manifestDigest must be the exact canonical form sha256:<64 lowercase hex>")
	}
	return nil
}

// ControlPlaneOperationBinder implements OperationBinder through the control
// plane's authenticated internal operation-binding endpoint. It carries NO
// key material. The internal credential (Secret) authenticates the registry
// data plane and is mounted from a secret file; transport, URL, and response
// handling mirror ControlPlaneCommitter exactly (same origin policy, same
// credential header, same bounded strict decode, same fail-closed status
// mapping).
type ControlPlaneOperationBinder struct {
	// BaseURL is the control-plane internal origin, validated and
	// canonicalized per request (see ControlPlaneCommitter).
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

func (c ControlPlaneOperationBinder) logf(msg string, args ...any) {
	if c.Logger != nil {
		c.Logger.Warn(msg, args...)
	}
}

// Bind sends one authenticated, bounded operation-binding request and returns
// a fixed sentinel class on any failure. A 200 returns nil only when the
// response body is EXACTLY the fixed success object (strictly decoded); a 409
// returns ErrCommitConflict; every other status and every transport/decode
// failure collapses to the backend class so no URL/host/body content leaks
// through err.Error().
func (c ControlPlaneOperationBinder) Bind(ctx context.Context, req OperationBindingRequest) error {
	baseURL, err := parseCommitBaseURL(c.BaseURL)
	if err != nil {
		c.logf("internal binding: invalid base URL", "err", err.Error())
		return ErrCommitBackend
	}
	if len(c.Secret) == 0 {
		return ErrCommitBackend
	}
	if err := ValidatePublicationBindingRequest(req); err != nil {
		return ErrCommitMalformed
	}

	body, err := json.Marshal(req)
	if err != nil {
		return ErrCommitMalformed
	}
	if len(body) > BindingRequestMaxBody {
		return ErrCommitMalformed
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

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+InternalOperationBindingPath, bytes.NewReader(body))
	if err != nil {
		return ErrCommitMalformed
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(InternalAuthHeader, string(c.Secret))

	resp, err := client.Do(httpReq)
	if err != nil {
		// Raw dial/TLS/timeout detail is correlated locally, never returned.
		c.logf("internal binding: transport failure")
		return ErrCommitBackend
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, BindingResponseMaxBody+1))
	if err != nil {
		return ErrCommitBackend
	}
	if len(respBody) > BindingResponseMaxBody {
		return ErrCommitBackend
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return decodeBindingResponse(respBody)
	case http.StatusUnauthorized:
		return ErrCommitUnauthorized
	case http.StatusBadRequest:
		return ErrCommitMalformed
	case http.StatusNotFound:
		return ErrCommitUnknownRegistry
	case http.StatusConflict:
		return ErrCommitConflict
	default:
		// 503 and anything else on the backend side is retryable/dependency.
		return ErrCommitBackend
	}
}

// decodeBindingResponse STRICTLY decodes a bounded successful binding
// response: duplicate members, unknown top-level fields, trailing content,
// and any status other than the exact fixed "reserved" value are all
// rejected as a fail-closed backend error.
func decodeBindingResponse(data []byte) error {
	if err := rejectDuplicateJSONMembers(data); err != nil {
		return ErrCommitBackend
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var result BindingResponse
	if err := dec.Decode(&result); err != nil {
		return ErrCommitBackend
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrCommitBackend
	}
	if result.Status != "reserved" {
		return ErrCommitBackend
	}
	return nil
}
