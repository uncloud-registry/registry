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

// InternalFeedServer serves the control plane's constrained internal
// feed-signing endpoints. It is intended to be mounted on a SEPARATE internal
// listener (not the public router), so it can never inherit the public browser
// CSRF/session assumptions. It accepts exactly two routes on POST:
// /internal/v1/feed-updates (the feed signer) and /internal/v1/operation-bindings
// (the preflight operation-key binder). It authenticates with a dedicated
// credential header compared in constant time, decodes bounded strict-JSON
// requests, and returns only generic coarse statuses — never internal error
// text, secrets, keys, or topology.
type InternalFeedServer struct {
	Signer *FeedSigner
	Binder *PublicationBinder
	Secret []byte
	Logger *slog.Logger
}

// NewInternalFeedServer returns the internal feed server, failing closed on a
// missing signer, binder, or empty secret.
func NewInternalFeedServer(signer *FeedSigner, binder *PublicationBinder, secret []byte, logger *slog.Logger) (*InternalFeedServer, error) {
	if isNilDependency(signer) {
		return nil, errors.New("internal feed server requires a signer")
	}
	if isNilDependency(binder) {
		return nil, errors.New("internal feed server requires the publication binder")
	}
	if len(secret) == 0 {
		return nil, errors.New("internal feed server requires the internal service credential")
	}
	return &InternalFeedServer{Signer: signer, Binder: binder, Secret: append([]byte(nil), secret...), Logger: logger}, nil
}

func (s *InternalFeedServer) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// ServeHTTP handles the two allowed routes. Any other path or method is a
// generic 404; a non-POST method on a route is 405.
func (s *InternalFeedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		switch r.URL.Path {
		case publish.InternalFeedUpdatePath, publish.InternalOperationBindingPath:
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.NotFound(w, r)
		return
	}
	switch r.URL.Path {
	case publish.InternalFeedUpdatePath:
		s.handleFeedUpdate(w, r)
	case publish.InternalOperationBindingPath:
		s.handleOperationBinding(w, r)
	default:
		http.NotFound(w, r)
	}
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

// handleFeedUpdate serves POST /internal/v1/feed-updates.
func (s *InternalFeedServer) handleFeedUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.checkCredential(r) {
		s.logger().Warn("internal credential rejected", "component", "controlplane-internal", "path", publish.InternalFeedUpdatePath)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	data, ok := s.readBoundedBody(w, r)
	if !ok {
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
		writeJSON(w, status, map[string]string{"error": genericFeedSignerErrorFor(status)})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleOperationBinding serves POST /internal/v1/operation-bindings: the
// authenticated preflight reservation of an explicit caller operation key for
// exactly one logical payload, decided BEFORE the data plane writes any
// immutable object. A fresh or identical binding is 200; a reused key with a
// different payload is 409; every failure maps to the same coarse statuses as
// feed commits.
func (s *InternalFeedServer) handleOperationBinding(w http.ResponseWriter, r *http.Request) {
	if !s.checkCredential(r) {
		s.logger().Warn("internal credential rejected", "component", "controlplane-internal", "path", publish.InternalOperationBindingPath)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	data, ok := s.readBoundedBody(w, r)
	if !ok {
		return
	}

	var req publish.OperationBindingRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}

	if err := s.Binder.Bind(r.Context(), req); err != nil {
		status := mapFeedSignerError(err)
		if status == http.StatusServiceUnavailable {
			s.logger().Warn("internal operation binding backend failure", "component", "controlplane-internal", "class", "backend")
		}
		writeJSON(w, status, map[string]string{"error": genericFeedSignerErrorFor(status)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reserved"})
}

// readBoundedBody enforces the shared internal request-body bound (known-length
// fast reject included) before any parse.
func (s *InternalFeedServer) readBoundedBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.ContentLength > internalFeedBodyLimit {
		_ = r.Body.Close()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, internalFeedBodyLimit+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return nil, false
	}
	return data, true
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
// internal statuses. The two conflict classes carry DISTINCT, fixed,
// data-free statuses so the data-plane client can tell them apart WITHOUT any
// response body content: errFeedSignerGenerationConflict (recoverable — the
// repository generation advanced elsewhere) maps to 412, so
// ControlPlaneCommitter.Commit can surface publish.ErrCommitGenerationConflict
// and the publisher's one-time rebuild triggers; errFeedSignerConflict
// (permanent — a reused operation/publication identity with different input)
// stays 409 and must never be rebuilt.
func mapFeedSignerError(err error) int {
	switch {
	case errors.Is(err, errFeedSignerMalformed):
		return http.StatusBadRequest
	case errors.Is(err, errFeedSignerRegistryNotFound), errors.Is(err, errFeedSignerNotReady):
		return http.StatusNotFound
	case errors.Is(err, errFeedSignerGenerationConflict):
		return http.StatusPreconditionFailed
	case errors.Is(err, errFeedSignerConflict):
		return http.StatusConflict
	default: // errFeedSignerBackend and anything unrecognized
		return http.StatusServiceUnavailable
	}
}

// genericFeedSignerErrorFor returns the fixed generic body for an internal
// feed-signer error status; it never carries internal text, secrets, or keys.
func genericFeedSignerErrorFor(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid request"
	case http.StatusNotFound:
		return "registry not found"
	case http.StatusPreconditionFailed:
		return "generation conflict"
	case http.StatusConflict:
		return "operation conflict"
	default:
		return "temporary service failure"
	}
}
