package controlplane

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/uncloud-registry/registry/internal/publish"
)

// internalFeedBodyLimit bounds the internal feed-commit request body. A
// FeedCommitRequest is a handful of bounded strings; 64 KiB is far beyond it
// even after JSON encoding, while still rejecting oversized hostile input before
// any decode.
const internalFeedBodyLimit = 65536

// InternalFeedServer serves the control plane's constrained internal feed-
// signing endpoint. It is intended to be mounted on a SEPARATE internal
// listener (not the public router), so it can never inherit the public browser
// CSRF/session assumptions. It accepts exactly one route: POST
// /internal/v1/feed-updates. It authenticates with a dedicated credential
// header compared in constant time, decodes a bounded strict-JSON request, and
// returns only generic coarse statuses — never internal error text, secrets,
// keys, or topology.
type InternalFeedServer struct {
	Signer *FeedSigner
	Secret []byte
	Logger *slog.Logger
}

// NewInternalFeedServer returns the internal feed server, failing closed on a
// missing signer or empty secret.
func NewInternalFeedServer(signer *FeedSigner, secret []byte, logger *slog.Logger) (*InternalFeedServer, error) {
	if isNilDependency(signer) {
		return nil, errors.New("internal feed server requires a signer")
	}
	if len(secret) == 0 {
		return nil, errors.New("internal feed server requires the internal service credential")
	}
	return &InternalFeedServer{Signer: signer, Secret: append([]byte(nil), secret...), Logger: logger}, nil
}

func (s *InternalFeedServer) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// ServeHTTP handles the single allowed route. Any other path or method is a
// generic 404; a non-POST method on the route is 405.
func (s *InternalFeedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != publish.InternalFeedUpdatePath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Authenticate with the dedicated credential header. Only exactly ONE
	// non-blank value is accepted; duplicates (even identical) or a blank value
	// are rejected. Comparison is constant-time and length-safe.
	if !s.checkCredential(r) {
		s.logger().Warn("internal credential rejected", "component", "controlplane-internal", "path", publish.InternalFeedUpdatePath)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Bound the body before any parse (known-length fast reject included).
	if r.ContentLength > internalFeedBodyLimit {
		_ = r.Body.Close()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, internalFeedBodyLimit+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}

	var req publish.FeedCommitRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}

	result, err := s.Signer.Commit(r.Context(), req)
	if err != nil {
		status := mapFeedSignerError(err)
		if status == http.StatusServiceUnavailable {
			s.logger().Warn("internal feed commit backend failure", "component", "controlplane-internal", "class", "backend")
		}
		writeJSON(w, status, map[string]string{"error": genericFeedSingErrorFor(status)})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// checkCredential verifies the request's dedicated internal credential header
// against the server secret. Exactly one non-blank header value is required;
// duplicates, blank values, or mismatches fail authentication without revealing
// anything.
func (s *InternalFeedServer) checkCredential(r *http.Request) bool {
	vals := r.Header.Values(publish.InternalAuthHeader)
	if len(vals) != 1 {
		return false
	}
	// EXACT byte comparison, never trimmed: the internal credential is the
	// exact secret-file bytes, and a header value that differs by even one
	// byte (including surrounding whitespace) is rejected. TrimSpace here
	// would silently mutate the effective credential and defeat the exact
	// comparison.
	got := vals[0]
	if got == "" {
		return false
	}
	// Length-safe constant-time compare: unequal length returns 0 without
	// leaking how far the prefix agreed; duplicate-header values were already
	// rejected above.
	if len(got) != len(s.Secret) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), s.Secret) == 1
}

// decodeStrictJSON decodes a bounded request body strictly: duplicate members
// anywhere, unknown top-level fields, and trailing content after the single
// JSON value are all rejected. Returns a boolean-typed error wrapper so the
// handler emits only the generic malformed status.
func decodeStrictJSON(data []byte, dst any) error {
	if err := rejectDuplicateJSONObjectMembers(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing content after JSON body")
	}
	return nil
}

// mapFeedSignerError maps the signer's stable sentinels to the generic coarse
// internal statuses.
func mapFeedSignerError(err error) int {
	switch {
	case errors.Is(err, errFeedSignerMalformed):
		return http.StatusBadRequest
	case errors.Is(err, errFeedSignerRegistryNotFound), errors.Is(err, errFeedSignerNotReady):
		return http.StatusNotFound
	case errors.Is(err, errFeedSignerGenerationConflict), errors.Is(err, errFeedSignerConflict):
		return http.StatusConflict
	default: // errFeedSignerBackend and anything unrecognized
		return http.StatusServiceUnavailable
	}
}

// genericFeedSingErrorFor returns the fixed generic body for an internal feed-
// signer error status; it never carries internal text, secrets, or keys.
func genericFeedSingErrorFor(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid request"
	case http.StatusNotFound:
		return "registry not found"
	case http.StatusConflict:
		return "operation conflict"
	default:
		return "temporary service failure"
	}
}
