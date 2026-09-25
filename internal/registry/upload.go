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
// documented 416 with the accurate current Range. A declared range whose
// chunked body is short or over-long is rejected BEFORE the durable offset
// advances (the exact-span reader makes Append roll back its tail). Digest is
// verified by a streaming hash BEFORE any Bee write; finalization streams the
// staged bytes to the object uploader with an exact size and the explicit
// postage batch. A finalize retried on an already-finalized session with the
// matching canonical digest and no body is answered idempotently with ZERO
// uploader calls.
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
			// Noncontiguous start: 416 with the accurate current Range
			// (refetched under the REQUEST context, never a detached read).
			h.respondRangeNotSatisfiable(w, r.Context(), repo, uploadID, actor)
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

	body := io.Reader(r.Body)
	var exact *exactSpanReader
	if present && r.ContentLength < 0 {
		// A chunked/unknown-length body with a declared range: enforce the
		// EXACT span so a short body fails the append BEFORE the durable
		// offset advances (Task 15 rolls back the tail), and an over-long
		// body trips the bounded overflow probe.
		exact = newExactSpanReader(r.Body, maxBytes)
		body = exact
	}

	// A declared Content-Range span is the EXACT number of bytes this request
	// will write, so the durable append may preflight-reject it when the span
	// exceeds the available quota allowance BEFORE reading any payload (zero
	// bytes consumed, no spool write) — while an implicit stream is instead
	// bounded at the allowance and probed.
	appendCtx := r.Context()
	if present {
		appendCtx = staging.WithDeclaredSpan(appendCtx)
	}

	updated, err := h.Staging.Append(appendCtx, uploadID, repo, actor, expected, body, maxBytes)
	if err != nil {
		if exact != nil && (exact.short || exact.long) {
			// The chunked body did NOT fill the declared span exactly —
			// either short of it or over it. Both are framing/range
			// mismatches: a fixed range-invalid error with ZERO durable
			// change, never a quota-limit overflow.
			writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageRangeInvalid)
			return
		}
		h.classifyAppendError(w, r, repo, uploadID, actor, err)
		return
	}
	// Defensive invariant: with the exact-span reader (chunked) or the
	// pre-validated Content-Length, the committed offset always fills the
	// declared span. The check is retained as a fail-closed guard.
	if present && updated.Offset != end+1 {
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

	// A finalized session is immutable. A retry that replays the SAME
	// canonical digest with NO body and NO Content-Range is answered
	// idempotently as 201 with the exact stored digest/location and ZERO
	// object-uploader calls and ZERO staging mutation (the decision uses only
	// the DURABLE finalized metadata, so it survives handler recreation and
	// service restart). Any body, any Content-Range, or a differing digest on
	// a finalized session is a fixed 409 invalid-state with zero uploader
	// calls and zero staging mutation.
	if session.State == staging.StateFinalized {
		_, _, rangePresent, _ := parseContentRangeHeader(r.Header)
		hasBody := r.ContentLength != 0
		if rangePresent || hasBody || session.Digest != digest {
			writeError(w, http.StatusConflict, "BLOB_UPLOAD_INVALID", messageAlreadyFinalized)
			return
		}
		w.Header().Set("Docker-Content-Digest", session.Digest)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, digest))
		w.WriteHeader(http.StatusCreated)
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
				h.respondRangeNotSatisfiable(w, r.Context(), repo, uploadID, actor)
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
		body := io.Reader(r.Body)
		var exact *exactSpanReader
		if present && r.ContentLength < 0 {
			exact = newExactSpanReader(r.Body, maxBytes)
			body = exact
		}
		// Declared span => eligible for quota preflight rejection before any
		// payload read (see uploadPatch).
		appendCtx := r.Context()
		if present {
			appendCtx = staging.WithDeclaredSpan(appendCtx)
		}
		updated, err := h.Staging.Append(appendCtx, uploadID, repo, actor, expected, body, maxBytes)
		if err != nil {
			if exact != nil && (exact.short || exact.long) {
				writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", messageRangeInvalid)
				return
			}
			h.classifyAppendError(w, r, repo, uploadID, actor, err)
			return
		}
		// Defensive invariant (see uploadPatch): in reachable states the
		// committed offset always fills the declared span.
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
		h.respondRangeNotSatisfiable(w, r.Context(), repo, uploadID, actor)
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
// reloading the durable session. The refetch runs under the REQUEST context —
// never a detached context.Background read — so cancellation propagates and
// can never start a detached database read. When the authoritative status is
// unavailable (refetch failed or cancelled), the fixed data-free 416 is still
// answered but without an authoritative Range header; nothing leaks or hangs.
func (h *Handler) respondRangeNotSatisfiable(w http.ResponseWriter, ctx context.Context, repo, uploadID, actor string) {
	if cur, err := h.Staging.Status(ctx, uploadID, repo, actor); err == nil {
		w.Header().Set("Range", uploadRange(cur.Offset))
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uploadID))
		w.Header().Set("Docker-Upload-UUID", uploadID)
	}
	writeError(w, http.StatusRequestedRangeNotSatisfiable, "RANGE_NOT_SATISFIABLE", "the upload offset does not match the reported range")
}

// errRangeTruncated is the fixed, data-free sentinel the exact-span reader
// yields when a chunked/unknown-length request body reaches EOF before filling
// the declared Content-Range span. errRangeExceeded is the matching sentinel
// for a body LARGER than the declared span: a frame/range mismatch, distinct
// from a broken quota-limit so an over-long body is never misclassified as an
// upload-quota overflow. Both are distinct from io.ErrUnexpectedEOF and the
// underlying source error so genuine transport-level truncation/faults are not
// conflated with a misstated declared range.
var (
	errRangeTruncated = errors.New("upload body shorter than declared range")
	errRangeExceeded  = errors.New("upload body longer than declared range")
)

// exactSpanReader wraps a chunked/unknown-length request body to enforce an
// EXACT declared Content-Range span while streaming with bounded memory and
// WITHOUT buffering (it owns only two counters and two flags; the payload is
// never held, reads delegate to the underlying body so request cancellation
// propagates identically). It returns errRangeTruncated (and sets short) the
// moment the underlying body hits EOF before the span fills, so the durable
// Append sees a reader fault and rolls back its tail and offset BEFORE any
// commit — a short body never advances the durable offset. It returns
// errRangeExceeded (and sets long) the moment the underlying body yields a byte
// BEYOND the span, so an over-long body is a framing/range mismatch that rolls
// back too — never a quota-limit overflow. A body that exactly fills the span
// ends on EOF and is accepted.
type exactSpanReader struct {
	src   io.Reader
	want  int64
	count int64
	short bool // body reached EOF before the declared span
	long  bool // body exceeded the declared span
}

// newExactSpanReader wraps src to require exactly want bytes (want >= 1).
func newExactSpanReader(src io.Reader, want int64) *exactSpanReader {
	return &exactSpanReader{src: src, want: want}
}

func (e *exactSpanReader) Read(p []byte) (int, error) {
	if e.count >= e.want {
		// The declared span is already served. Probe the underlying body to
		// tell an EXACTLY-span body (EOF) from an OVER-LONG one (a yielded
		// byte is a framing violation), without buffering anything.
		n, err := e.src.Read(p)
		if n > 0 {
			e.long = true
			return n, errRangeExceeded
		}
		return n, err
	}
	// Only ever claim the remaining bytes of the declared span from the
	// underlying body; anything past the span is caught by the probe above.
	remaining := e.want - e.count
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := e.src.Read(p)
	e.count += int64(n)
	if err == io.EOF && e.count < e.want {
		// Body exhausted before the declared span: flag it and surface a
		// fixed source error so the append fails and rolls back before any
		// durable commit.
		e.short = true
		return n, errRangeTruncated
	}
	return n, err
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
	defaultUploadMaxBytes   = 1 << 30 // 1 GiB handler copy bound when unconfigured
	messageRangeInvalid     = "the upload range or offset is invalid"
	messageUploadTooLarge   = "the upload exceeds the configured size limit"
	messageUploadInvalid    = "the upload request is invalid"
	messageAlreadyFinalized = "the upload is already finalized and cannot be modified"
)
