package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/staging"
)

// handleUploadV1 is the strict, bounded upload path. Every upload request is
// authenticated/authorized before any staging access; ownership is bound to
// repo+actor and never reveals whether an ID belongs to another tenant.
// Request bodies are STREAMED through staging.Append with a fixed buffer and
// a real limit+1 boundary — never io.ReadAll. Content-Range is parsed with one
// strict grammar; stale/future offsets make zero durable change and answer a
// documented 416 with the accurate current Range. Digest is verified by a
// streaming hash BEFORE any Bee write; finalization streams the staged bytes
// to the object uploader with an exact size and the explicit postage batch.
func (h *Handler) handleUploadV1(w http.ResponseWriter, r *http.Request, registryIdentity resolve.RegistryIdentity, repo string, uploadID string, principal auth.Principal) {
	actor := principal.Subject

	batchID, authorized, err := h.PushAuthorizer.Authorize(r.Context(), registryIdentity, repo, principal)
	if err != nil {
		status, code, message := classifyRequestBoundaryError(err)
		writeError(w, status, code, message)
		return
	}
	if !authorized {
		w.Header().Set("WWW-Authenticate", bearerChallenge(h.AuthRealm, registryIdentity.Host, repo, "push"))
		writeError(w, http.StatusForbidden, ErrorCodeDenied, "push access denied")
		return
	}

	if uploadID == "" {
		// POST /v2/<repo>/blobs/uploads/ — start a session.
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		session, err := h.Staging.Create(r.Context(), repo, actor, h.SessionTTL)
		if err != nil {
			status, code, message := classifyUploadError(err)
			writeError(w, status, code, message)
			return
		}
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, session.ID))
		w.Header().Set("Docker-Upload-UUID", session.ID)
		w.Header().Set("Range", uploadRange(session.Offset))
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Load the durable session: absent, foreign, or expired answers the same
	// fixed 404 (never an existence oracle for other tenants' uploads).
	session, err := h.Staging.Status(r.Context(), uploadID, repo, actor)
	if err != nil {
		status, code, message := classifyUploadError(err)
		writeError(w, status, code, message)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeUploadStatus(w, repo, session)
	case http.MethodPatch:
		h.uploadPatch(w, r, repo, uploadID, actor, session, batchID)
	case http.MethodPut:
		h.uploadPut(w, r, repo, uploadID, actor, session, batchID)
	case http.MethodDelete:
		if err := h.Staging.Delete(r.Context(), uploadID, repo, actor); err != nil {
			status, code, message := classifyUploadError(err)
			writeError(w, status, code, message)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PATCH, PUT, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// uploadMaxBytes returns the bounded copy cap: the configured per-upload limit
// when set, otherwise a bounded default. Append still validates the offset
// atomically and the durable service enforces the per-upload quota.
func (h *Handler) uploadMaxBytes() int64 {
	if h.MaxUploadBytes > 0 {
		return h.MaxUploadBytes
	}
	return defaultUploadMaxBytes
}

func (h *Handler) uploadPatch(w http.ResponseWriter, r *http.Request, repo, uploadID, actor string, session staging.Session, batchID string) {
	start, end, present, perr := parseContentRangeHeader(r.Header)
	if perr != nil {
		writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageRangeInvalid)
		return
	}

	expected := session.Offset
	var maxBytes int64
	if present {
		span, ok := rangeSpan(start, end)
		if !ok {
			writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageRangeInvalid)
			return
		}
		if start != session.Offset {
			// Noncontiguous start: 416 with the accurate current Range.
			h.respondRangeNotSatisfiable(w, repo, uploadID, actor)
			return
		}
		if r.ContentLength >= 0 && r.ContentLength != span {
			// Conflicting Content-Length/Content-Range length: reject BEFORE
			// any side effect.
			writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageRangeInvalid)
			return
		}
		expected = start
		maxBytes = span
	} else {
		maxBytes = h.uploadMaxBytes()
	}

	updated, err := h.Staging.Append(r.Context(), uploadID, repo, actor, expected, r.Body, maxBytes)
	if err != nil {
		h.classifyAppendError(w, r, repo, uploadID, actor, err)
		return
	}
	if present && updated.Offset != end+1 {
		// The body did not fill the declared range (shorter than span).
		writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageRangeInvalid)
		return
	}
	writeUploadAccepted(w, repo, updated)
}

// uploadPut finalizes an upload. It may carry a final chunk, subject to the
// same range/offset/quota rules. The staged digest is verified by a streaming
// hash BEFORE any Bee write; a mismatch makes zero Bee writes and retains
// staging. On success the staged bytes are streamed (reader + exact size +
// explicit postage) to the object uploader, then the durable finalized
// metadata is recorded.
func (h *Handler) uploadPut(w http.ResponseWriter, r *http.Request, repo, uploadID, actor string, session staging.Session, batchID string) {
	digest := r.URL.Query().Get("digest")
	if !isValidDigest(digest) {
		writeError(w, http.StatusBadRequest, "DIGEST_INVALID", "the digest parameter is missing or invalid")
		return
	}

	// Optional final chunk, subject to the same strict range/offset rules.
	if r.ContentLength != 0 {
		start, end, present, perr := parseContentRangeHeader(r.Header)
		if perr != nil {
			writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageRangeInvalid)
			return
		}
		expected := session.Offset
		maxBytes := h.uploadMaxBytes()
		if present {
			span, ok := rangeSpan(start, end)
			if !ok {
				writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageRangeInvalid)
				return
			}
			if start != session.Offset {
				h.respondRangeNotSatisfiable(w, repo, uploadID, actor)
				return
			}
			if r.ContentLength >= 0 && r.ContentLength != span {
				writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageRangeInvalid)
				return
			}
			expected = start
			maxBytes = span
		} else if r.ContentLength >= 0 && int64(r.ContentLength) > h.uploadMaxBytes() {
			// Oversized final body rejected before any side effect.
			writeError(w, http.StatusRequestEntityTooLarge, "BLOB_UPLOAD_INVALID", messageUploadTooLarge)
			return
		}
		updated, err := h.Staging.Append(r.Context(), uploadID, repo, actor, expected, r.Body, maxBytes)
		if err != nil {
			h.classifyAppendError(w, r, repo, uploadID, actor, err)
			return
		}
		if present && updated.Offset != end+1 {
			writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageRangeInvalid)
			return
		}
		session = updated
	}

	// Streaming digest verification: hash the staged bytes, compare the
	// canonical digest BEFORE any Bee write.
	rc, _, err := h.Staging.Open(r.Context(), uploadID, repo, actor)
	if err != nil {
		status, code, message := classifyUploadError(err)
		writeError(w, status, code, message)
		return
	}
	sum, n, herr := hashStaged(rc)
	rc.Close()
	if herr != nil {
		status, code, message := classifyUploadError(herr)
		writeError(w, status, code, message)
		return
	}
	digest = computeDigestOf(sum, n)
	if digest != r.URL.Query().Get("digest") {
		// Zero Bee writes; staging retained for a corrected retry.
		writeError(w, http.StatusBadRequest, "DIGEST_INVALID", "the staged content does not match the requested digest")
		return
	}

	// Reopen and stream to the object uploader with an exact size and the
	// explicit postage batch id.
	rc2, _, err := h.Staging.Open(r.Context(), uploadID, repo, actor)
	if err != nil {
		status, code, message := classifyUploadError(err)
		writeError(w, status, code, message)
		return
	}
	ref, err := h.Uploader.PutStream(r.Context(), rc2, n, batchID)
	rc2.Close()
	if err != nil {
		status, code, message := classifyUploadError(err)
		writeError(w, status, code, message)
		return
	}

	mediaType := r.Header.Get("Content-Type")
	if mediaType == "" {
		// A blob without an explicit media type is stored as octet-stream. A
		// NON-EMPTY (possibly adversarial) value is retained exactly as
		// uploaded: the durable service enforces its media-type grammar at
		// finalization, and publication-time media/descriptor validation
		// rejects malformed stored media with a 400 that never echoes it.
		mediaType = "application/octet-stream"
	}
	if err := h.Staging.MarkFinalized(r.Context(), uploadID, repo, actor, digest, ref, mediaType, n); err != nil {
		status, code, message := classifyUploadError(err)
		writeError(w, status, code, message)
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, digest))
	w.WriteHeader(http.StatusCreated)
}

// classifyAppendError maps a durable Append failure to the HTTP surface. A
// stale/future offset is answered as 416 with the accurate current Range.
func (h *Handler) classifyAppendError(w http.ResponseWriter, r *http.Request, repo, uploadID, actor string, err error) {
	if errors.Is(err, staging.ErrOffsetMismatch) {
		h.respondRangeNotSatisfiable(w, repo, uploadID, actor)
		return
	}
	if errors.Is(err, staging.ErrTooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "BLOB_UPLOAD_INVALID", messageUploadTooLarge)
		return
	}
	status, code, message := classifyUploadError(err)
	writeError(w, status, code, message)
}

// respondRangeNotSatisfiable answers 416 with the accurate current Range by
// reloading the durable session.
func (h *Handler) respondRangeNotSatisfiable(w http.ResponseWriter, repo, uploadID, actor string) {
	if cur, err := h.Staging.Status(context.Background(), uploadID, repo, actor); err == nil {
		w.Header().Set("Range", uploadRange(cur.Offset))
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uploadID))
		w.Header().Set("Docker-Upload-UUID", uploadID)
	}
	writeError(w, http.StatusRequestedRangeNotSatisfiable, "RANGE_NOT_SATISFIABLE", "the upload offset does not match the reported range")
}

// classifyUploadError is the single fixed, DATA-FREE mapper from durable
// staging sentinels to the upload HTTP surface. Raw error text — which can
// carry paths, DSNs, IDs, digests, or offsets — never crosses the boundary.
func classifyUploadError(err error) (int, string, string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return http.StatusServiceUnavailable, ErrorCodeDependencyUnavailable, messageDependencyUnavailable
	case errors.Is(err, staging.ErrNotFound), errors.Is(err, staging.ErrExpired):
		return http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "upload session not found"
	case errors.Is(err, staging.ErrInvalidState):
		return http.StatusConflict, "BLOB_UPLOAD_INVALID", "the upload state does not permit this operation"
	case errors.Is(err, staging.ErrFinalizeConflict):
		return http.StatusConflict, "BLOB_UPLOAD_INVALID", "the upload was already finalized"
	case errors.Is(err, staging.ErrSourceRead):
		return http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageUploadBodyRead
	case errors.Is(err, staging.ErrInvalidInput):
		return http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageUploadInvalid
	case errors.Is(err, staging.ErrOffsetMismatch):
		return http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageRangeInvalid
	case errors.Is(err, staging.ErrTooLarge):
		return http.StatusRequestEntityTooLarge, "BLOB_UPLOAD_INVALID", messageUploadTooLarge
	case errors.Is(err, staging.ErrDependency):
		return http.StatusBadGateway, "BLOB_UPLOAD_INVALID", messageBlobUploadFailed
	default:
		return http.StatusInternalServerError, ErrorCodeInternal, messageUnknown
	}
}

// hashStaged streams rc through SHA-256, returning the digest bytes (as a
// hex string WITHOUT the "sha256:" prefix) and the exact byte count. It never
// buffers the payload.
func hashStaged(rc io.Reader) ([]byte, int64, error) {
	hasher := sha256.New()
	n, err := io.Copy(hasher, rc)
	if err != nil {
		return nil, 0, fmt.Errorf("stream staged content hash: %w", err)
	}
	return hasher.Sum(nil), n, nil
}

func computeDigestOf(sum []byte, _ int64) string {
	return "sha256:" + hex.EncodeToString(sum)
}

// parseContentRangeHeader parses the strict single Content-Range "start-end".
// present=false with no error when the header is absent and the request is an
// implicit contiguous append. Any malformed or multiple value yields a
// non-nil error: whitespace, signs, alternate units, extra separators,
// non-digit text, an unparseable/overflowing bound, or end-before-start.
func parseContentRangeHeader(h http.Header) (start, end int64, present bool, err error) {
	vals := h.Values("Content-Range")
	switch len(vals) {
	case 0:
		return 0, 0, false, nil
	case 1:
		// fall through
	default:
		return 0, 0, true, errors.New("multiple Content-Range values")
	}
	v := vals[0]
	start, end, ok := parseContentRange(v)
	if !ok {
		return 0, 0, true, errors.New("malformed Content-Range")
	}
	return start, end, true, nil
}

// parseContentRange enforces the single bounded grammar: exactly one '-' with
// non-empty digit-only start and end on either side, no whitespace, no signs,
// no alternate units or separators, int64-representable (overflow fails via
// ParseInt), and end >= start. A units prefix such as "bytes 0-99", a signed
// value, a comma-separated multi-range, or trailing data all fail.
func parseContentRange(v string) (start, end int64, ok bool) {
	if v == "" {
		return 0, 0, false
	}
	dash := 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			// digit
		case c == '-':
			dash++
			if dash > 1 {
				return 0, 0, false
			}
		default:
			return 0, 0, false // whitespace, sign, '.', ',', ';', '=', letters, etc.
		}
	}
	if dash != 1 {
		return 0, 0, false
	}
	idx := strings.IndexByte(v, '-')
	if idx == 0 || idx == len(v)-1 {
		return 0, 0, false
	}
	var e1, e2 error
	start, e1 = strconv.ParseInt(v[:idx], 10, 64)
	end, e2 = strconv.ParseInt(v[idx+1:], 10, 64)
	if e1 != nil || e2 != nil {
		return 0, 0, false // overflow or unrepresentable
	}
	if end < start {
		return 0, 0, false
	}
	return start, end, true
}

// rangeSpan returns the inclusive span length end-start+1 without int64
// overflow. ok=false when the span would overflow (end == MaxInt64).
func rangeSpan(start, end int64) (int64, bool) {
	if start > end {
		return 0, false
	}
	delta := end - start
	if delta == math.MaxInt64 {
		return 0, false
	}
	return delta + 1, true
}

func writeUploadStatus(w http.ResponseWriter, repo string, session staging.Session) {
	w.Header().Set("Docker-Upload-UUID", session.ID)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, session.ID))
	w.Header().Set("Range", uploadRange(session.Offset))
	w.WriteHeader(http.StatusNoContent)
}

func writeUploadAccepted(w http.ResponseWriter, repo string, session staging.Session) {
	w.Header().Set("Docker-Upload-UUID", session.ID)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, session.ID))
	w.Header().Set("Range", uploadRange(session.Offset))
	w.WriteHeader(http.StatusAccepted)
}

func uploadRange(offset int64) string {
	if offset <= 0 {
		return "0-0"
	}
	return fmt.Sprintf("0-%d", offset-1)
}

// isValidDigest reports the canonical lowercase "sha256:<64hex>" grammar.
func isValidDigest(s string) bool {
	const prefix = "sha256:"
	if len(s) != len(prefix)+64 || !strings.HasPrefix(s, prefix) {
		return false
	}
	for i := len(prefix); i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

const (
	defaultUploadMaxBytes = 1 << 30 // 1 GiB handler copy bound when unconfigured
	messageRangeInvalid   = "the upload range or offset is invalid"
	messageUploadTooLarge = "the upload exceeds the configured size limit"
	messageUploadInvalid  = "the upload request is invalid"
)
