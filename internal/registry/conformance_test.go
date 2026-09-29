package registry

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
)

// This file is the machine-readable Distribution conformance matrix for the
// v1 compatibility contract published in docs/compatibility.md. Every row
// drives a REAL request through httptest against the production handler built
// by newTestHandler — no mocks, no stubbed routes — and asserts the exact wire
// contract: status, Distribution error code, Allow header, WWW-Authenticate
// challenge, and the documented success headers (digest, location, range,
// upload UUID, content type, content length). Any route/method change that
// violates the documented contract fails here, and any new route MUST be added
// to this table before it can be called supported.
//
// The matrix covers:
//   - every supported route/method and its success status
//   - the auth requirement per route (anonymous pull vs bearer push/pull)
//   - unsupported methods on supported routes (405 UNSUPPORTED + Allow)
//   - the deferred catalog, delete, and mount operations (data-free 405s
//     answered before identity resolution or authentication)
//   - the fixed Distribution error codes for the 4xx/5xx surfaces
//
// Deferred-operation rows deliberately send NO credential: they must answer
// 405 UNSUPPORTED regardless of authentication state, proving the deferral
// short-circuits before any challenge and can never act as an existence
// oracle.

// zeroDigest is a syntactically valid sha256 digest that no fixture ever
// commits, used for unknown-manifest/blob and mount rows.
var zeroDigest = "sha256:" + strings.Repeat("0", 64)

// conformanceState holds the values injected into the table's templates.
// Digest/size fields are fixed for the test; uploadID/configDigest are filled
// by the seeds that run before a row (each row's seeds create a fresh upload
// session, so rows never interfere).
type conformanceState struct {
	manifestDigest string
	manifestSize   string
	blobDigest     string
	blobSize       string
	configSize     string

	uploadURL    string
	uploadID     string
	configDigest string
}

// conformanceCase is one row of the matrix.
type conformanceCase struct {
	name        string
	method      string
	path        string // placeholders: {zero} {manifest} {manifestSize} {blob} {blobSize} {upload} {configDigest} {configSize} {config}
	auth        string // "" (no credential), pull, push, pull-other, push-other
	seeds       []string
	body        string // request body template; "" = no body
	contentType string

	wantStatus    int
	wantCode      string // expected Distribution error code (JSON envelope); "" for success
	wantAllow     string
	wantHeaders   map[string]string
	wantBody      string // exact expected response body; "" = not asserted
	wantNoBody    bool
	wantChallenge string // substring required in WWW-Authenticate
	// Upload-finalize / manifest-put digest hooks (the digest is computed from
	// the actual body, so the table stays declarative).
	wantDigestOfConfig bool
	wantDigestOfBody   bool
	wantLocation       string
	wantOperationID    bool
	// captureUploadID records the session ID the RESPONSE ITself created
	// (the upload-start row) so its own Location/UUID assertions can resolve
	// {upload} after the fact.
	captureUploadID bool
}

var conformanceMatrix = []conformanceCase{
	// --- base ping ---
	{name: "ping", method: http.MethodGet, path: "/v2", wantStatus: http.StatusOK,
		wantHeaders: map[string]string{"Docker-Distribution-API-Version": "registry/2.0"}, wantNoBody: true},
	{name: "ping slash", method: http.MethodGet, path: "/v2/", wantStatus: http.StatusOK,
		wantHeaders: map[string]string{"Docker-Distribution-API-Version": "registry/2.0"}, wantNoBody: true},
	{name: "ping unsupported method", method: http.MethodPost, path: "/v2",
		wantStatus: http.StatusMethodNotAllowed, wantCode: ErrorCodeUnsupported, wantAllow: allowPing},

	// --- unknown path ---
	{name: "unknown path", method: http.MethodGet, path: "/v2/not/a/route",
		wantStatus: http.StatusNotFound, wantCode: ErrorCodeNameUnknown},

	// --- deferred operations (answered before authentication) ---
	{name: "catalog deferred", method: http.MethodGet, path: "/v2/_catalog",
		wantStatus: http.StatusMethodNotAllowed, wantCode: ErrorCodeUnsupported, wantAllow: allowPing},
	{name: "catalog deferred slash", method: http.MethodGet, path: "/v2/_catalog/",
		wantStatus: http.StatusMethodNotAllowed, wantCode: ErrorCodeUnsupported, wantAllow: allowPing},
	{name: "manifest delete deferred", method: http.MethodDelete, path: "/v2/backend/api/manifests/latest",
		wantStatus: http.StatusMethodNotAllowed, wantCode: ErrorCodeUnsupported, wantAllow: allowManifests},
	{name: "blob delete deferred", method: http.MethodDelete, path: "/v2/backend/api/blobs/{zero}",
		wantStatus: http.StatusMethodNotAllowed, wantCode: ErrorCodeUnsupported, wantAllow: allowBlobs},
	{name: "mount deferred", method: http.MethodPost, path: "/v2/backend/api/blobs/uploads/?mount={zero}&from=backend/other",
		wantStatus: http.StatusMethodNotAllowed, wantCode: ErrorCodeUnsupported, wantAllow: allowUploadStart},

	// --- manifests: pull ---
	{name: "manifest get anonymous", method: http.MethodGet, path: "/v2/backend/api/manifests/latest",
		wantStatus: http.StatusOK,
		wantHeaders: map[string]string{
			"Docker-Content-Digest": "{manifest}",
			"Content-Type":          publish.MediaTypeOCIManifest,
			"Content-Length":        "{manifestSize}",
			"Vary":                  "Accept",
		},
		wantBody: `{"schemaVersion":2}`},
	{name: "manifest get by digest", method: http.MethodGet, path: "/v2/backend/api/manifests/{manifest}",
		auth: "pull", wantStatus: http.StatusOK,
		wantHeaders: map[string]string{"Docker-Content-Digest": "{manifest}", "Content-Type": publish.MediaTypeOCIManifest, "Content-Length": "{manifestSize}"},
		wantBody:    `{"schemaVersion":2}`},
	{name: "manifest head", method: http.MethodHead, path: "/v2/backend/api/manifests/latest",
		wantStatus: http.StatusOK, wantNoBody: true,
		wantHeaders: map[string]string{"Docker-Content-Digest": "{manifest}", "Content-Type": publish.MediaTypeOCIManifest, "Content-Length": "{manifestSize}"}},
	{name: "manifest tag unknown", method: http.MethodGet, path: "/v2/backend/api/manifests/nope",
		wantStatus: http.StatusNotFound, wantCode: "MANIFEST_UNKNOWN"},
	{name: "manifest pull requires credential", method: http.MethodGet, path: "/v2/backend/other/manifests/latest",
		wantStatus: http.StatusUnauthorized, wantCode: "UNAUTHORIZED", wantChallenge: "repository:backend/other:pull"},
	{name: "manifest pull authenticated but denied", method: http.MethodGet, path: "/v2/backend/other/manifests/latest",
		auth: "pull-other", wantStatus: http.StatusUnauthorized, wantCode: "UNAUTHORIZED", wantChallenge: "repository:backend/other:pull"},

	// --- manifests: unsupported methods / publish ---
	{name: "manifest unsupported method", method: http.MethodPost, path: "/v2/backend/api/manifests/latest",
		wantStatus: http.StatusMethodNotAllowed, wantCode: ErrorCodeUnsupported, wantAllow: allowManifests},
	{name: "manifest put by digest unsupported", method: http.MethodPut, path: "/v2/backend/api/manifests/{zero}",
		auth: "push", contentType: publish.MediaTypeOCIManifest, body: `{}`,
		wantStatus: http.StatusBadRequest, wantCode: "MANIFEST_INVALID"},
	{name: "manifest put", method: http.MethodPut, path: "/v2/backend/api/manifests/latest",
		auth: "push", seeds: []string{"start-upload", "append-config", "finalize-config"},
		contentType:      publish.MediaTypeOCIManifest,
		body:             `{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":{configSize},"digest":"{configDigest}"},"layers":[]}`,
		wantStatus:       http.StatusCreated,
		wantLocation:     "/v2/backend/api/manifests/latest",
		wantDigestOfBody: true, wantOperationID: true},

	// --- blobs: pull ---
	{name: "blob get", method: http.MethodGet, path: "/v2/backend/api/blobs/{blob}",
		wantStatus: http.StatusOK, wantBody: "blob-bytes",
		wantHeaders: map[string]string{
			"Docker-Content-Digest": "{blob}",
			"Content-Length":        "{blobSize}",
			"Content-Type":          "application/vnd.oci.image.layer.v1.tar+gzip",
		}},
	{name: "blob head", method: http.MethodHead, path: "/v2/backend/api/blobs/{blob}",
		wantStatus: http.StatusOK, wantNoBody: true,
		wantHeaders: map[string]string{"Docker-Content-Digest": "{blob}", "Content-Length": "{blobSize}"}},
	{name: "blob unknown", method: http.MethodGet, path: "/v2/backend/api/blobs/{zero}",
		wantStatus: http.StatusNotFound, wantCode: "BLOB_UNKNOWN"},
	{name: "blob unsupported method", method: http.MethodPut, path: "/v2/backend/api/blobs/{blob}",
		wantStatus: http.StatusMethodNotAllowed, wantCode: ErrorCodeUnsupported, wantAllow: allowBlobs},

	// --- uploads ---
	{name: "upload start requires credential", method: http.MethodPost, path: "/v2/backend/api/blobs/uploads/",
		wantStatus: http.StatusUnauthorized, wantCode: "UNAUTHORIZED", wantChallenge: "repository:backend/api:push"},
	{name: "push denied by policy", method: http.MethodPost, path: "/v2/backend/other/blobs/uploads/",
		auth: "push-other", wantStatus: http.StatusForbidden, wantCode: "DENIED"},
	{name: "upload start", method: http.MethodPost, path: "/v2/backend/api/blobs/uploads/",
		auth: "push", wantStatus: http.StatusAccepted,
		wantHeaders:     map[string]string{"Range": "0-0", "Docker-Upload-UUID": "{upload}"},
		wantLocation:    "/v2/backend/api/blobs/uploads/{upload}",
		captureUploadID: true},
	{name: "upload root unsupported method", method: http.MethodGet, path: "/v2/backend/api/blobs/uploads/",
		auth: "push", wantStatus: http.StatusMethodNotAllowed, wantCode: ErrorCodeUnsupported, wantAllow: allowUploadStart},
	{name: "upload status", method: http.MethodGet, path: "/v2/backend/api/blobs/uploads/{upload}",
		auth: "push", seeds: []string{"start-upload"},
		wantStatus: http.StatusNoContent, wantNoBody: true,
		wantHeaders:  map[string]string{"Range": "0-0", "Docker-Upload-UUID": "{upload}"},
		wantLocation: "/v2/backend/api/blobs/uploads/{upload}"},
	{name: "upload append", method: http.MethodPatch, path: "/v2/backend/api/blobs/uploads/{upload}",
		auth: "push", seeds: []string{"start-upload"}, body: "{config}",
		wantStatus:   http.StatusAccepted,
		wantHeaders:  map[string]string{"Docker-Upload-UUID": "{upload}"},
		wantLocation: "/v2/backend/api/blobs/uploads/{upload}"},
	{name: "upload finalize", method: http.MethodPut, path: "/v2/backend/api/blobs/uploads/{upload}?digest={configDigest}",
		auth: "push", seeds: []string{"start-upload", "append-config"},
		contentType:        "application/vnd.oci.image.config.v1+json",
		wantStatus:         http.StatusCreated,
		wantDigestOfConfig: true,
		wantLocation:       "/v2/backend/api/blobs/{configDigest}"},
	{name: "upload cancel", method: http.MethodDelete, path: "/v2/backend/api/blobs/uploads/{upload}",
		auth: "push", seeds: []string{"start-upload"},
		wantStatus: http.StatusNoContent, wantNoBody: true},
	{name: "upload unsupported method", method: http.MethodOptions, path: "/v2/backend/api/blobs/uploads/{upload}",
		auth: "push", seeds: []string{"start-upload"},
		wantStatus: http.StatusMethodNotAllowed, wantCode: ErrorCodeUnsupported, wantAllow: allowUploads},
}

// TestDistributionConformanceMatrix executes the full matrix against the real
// handler over httptest (no mocks): every row exercises the production
// ServeHTTP/auth/staging/publish paths and asserts the documented wire
// contract. Rows run sequentially; each row's seeds create its own upload
// session so no row depends on another's side effects.
func TestDistributionConformanceMatrix(t *testing.T) {
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, issuer := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	configBytes := []byte(`{"architecture":"amd64"}`)
	manifestBody := []byte(`{"schemaVersion":2}`)
	blobBody := []byte("blob-bytes")

	state := &conformanceState{
		manifestDigest: publish.ComputeDigest(manifestBody),
		manifestSize:   strconv.Itoa(len(manifestBody)),
		blobDigest:     publish.ComputeDigest(blobBody),
		blobSize:       strconv.Itoa(len(blobBody)),
		configSize:     strconv.Itoa(len(configBytes)),
	}

	for _, tc := range conformanceMatrix {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runConformanceCase(t, server, issuer, state, configBytes, tc)
		})
	}
}

func runConformanceCase(t *testing.T, server *httptest.Server, issuer *auth.RegistryTokenIssuer, state *conformanceState, config []byte, tc conformanceCase) {
	t.Helper()
	for _, seed := range tc.seeds {
		runConformanceSeed(t, server, issuer, state, config, seed)
	}

	var body io.Reader
	if tc.body != "" {
		body = strings.NewReader(conformanceResolve(tc.body, state))
	}
	req, err := http.NewRequest(tc.method, server.URL+conformanceResolve(tc.path, state), body)
	if err != nil {
		t.Fatalf("%s: build request: %v", tc.name, err)
	}
	req.Host = testServiceHost
	if hdr := conformanceAuthHeader(t, issuer, tc.auth); hdr != "" {
		req.Header.Set("Authorization", hdr)
	}
	if tc.contentType != "" {
		req.Header.Set("Content-Type", tc.contentType)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: request failed: %v", tc.name, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	// Rows whose own response creates the session (upload start) capture the
	// created upload ID before the header assertions resolve {upload}.
	if tc.captureUploadID {
		loc := resp.Header.Get("Location")
		const prefix = "/v2/backend/api/blobs/uploads/"
		if !strings.HasPrefix(loc, prefix) {
			t.Errorf("%s: captured upload Location %q does not start with %q", tc.name, loc, prefix)
		} else {
			state.uploadID = strings.TrimPrefix(loc, prefix)
		}
	}

	if resp.StatusCode != tc.wantStatus {
		t.Errorf("%s: status %d, want %d (body %s)", tc.name, resp.StatusCode, tc.wantStatus, raw)
		return
	}
	if tc.wantNoBody && len(raw) != 0 {
		t.Errorf("%s: expected empty body, got %d bytes: %s", tc.name, len(raw), raw)
	}
	if tc.wantBody != "" {
		if want := conformanceResolve(tc.wantBody, state); string(raw) != want {
			t.Errorf("%s: body %q, want %q", tc.name, raw, want)
		}
	}
	if tc.wantCode != "" {
		code, _ := decodeErrorPayload(t, raw)
		if code != tc.wantCode {
			t.Errorf("%s: error code %q, want %q (body %s)", tc.name, code, tc.wantCode, raw)
		}
	}
	if tc.wantAllow != "" {
		if got := resp.Header.Get("Allow"); got != tc.wantAllow {
			t.Errorf("%s: Allow %q, want %q", tc.name, got, tc.wantAllow)
		}
	}
	for hdr, wantVal := range tc.wantHeaders {
		if got := resp.Header.Get(hdr); got != conformanceResolve(wantVal, state) {
			t.Errorf("%s: header %s = %q, want %q", tc.name, hdr, got, wantVal)
		}
	}
	if tc.wantChallenge != "" {
		if ch := resp.Header.Get("WWW-Authenticate"); !strings.Contains(ch, tc.wantChallenge) {
			t.Errorf("%s: WWW-Authenticate %q does not contain %q", tc.name, ch, tc.wantChallenge)
		}
	}
	if tc.wantLocation != "" {
		if got := resp.Header.Get("Location"); got != conformanceResolve(tc.wantLocation, state) {
			t.Errorf("%s: Location %q, want %q", tc.name, got, tc.wantLocation)
		}
	}
	if tc.wantDigestOfConfig {
		digest := publish.ComputeDigest(config)
		if got := resp.Header.Get("Docker-Content-Digest"); got != digest {
			t.Errorf("%s: Docker-Content-Digest %q, want %q", tc.name, got, digest)
		}
	}
	if tc.wantDigestOfBody {
		digest := publish.ComputeDigest([]byte(conformanceResolve(tc.body, state)))
		if got := resp.Header.Get("Docker-Content-Digest"); got != digest {
			t.Errorf("%s: Docker-Content-Digest %q, want %q", tc.name, got, digest)
		}
	}
	if tc.wantOperationID && resp.Header.Get(OperationIDHeader) == "" {
		t.Errorf("%s: missing %s header on the verified 201", tc.name, OperationIDHeader)
	}
}

// runConformanceSeed performs the prerequisite real-HTTP operations a row's
// request depends on, asserting their own conformance contract as it goes.
func runConformanceSeed(t *testing.T, server *httptest.Server, issuer *auth.RegistryTokenIssuer, state *conformanceState, config []byte, seed string) {
	t.Helper()
	push := conformanceAuthHeader(t, issuer, "push")
	do := func(req *http.Request) (*http.Response, []byte) {
		t.Helper()
		req.Host = testServiceHost
		if push != "" {
			req.Header.Set("Authorization", push)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("seed %s: request failed: %v", seed, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, body
	}

	switch seed {
	case "start-upload":
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v2/backend/api/blobs/uploads/", nil)
		if err != nil {
			t.Fatalf("seed start-upload: build request: %v", err)
		}
		resp, body := do(req)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("seed start-upload: status %d, want 202 (body %s)", resp.StatusCode, body)
		}
		loc, uuid := resp.Header.Get("Location"), resp.Header.Get("Docker-Upload-UUID")
		if loc == "" || uuid == "" {
			t.Fatalf("seed start-upload: missing Location/Docker-Upload-UUID (Location %q UUID %q)", loc, uuid)
		}
		if got := resp.Header.Get("Range"); got != "0-0" {
			t.Fatalf("seed start-upload: Range %q, want 0-0", got)
		}
		state.uploadURL = server.URL + loc
		state.uploadID = uuid
	case "append-config":
		if state.uploadURL == "" {
			t.Fatal("seed append-config: no active upload session")
		}
		req, err := http.NewRequest(http.MethodPatch, state.uploadURL, bytes.NewReader(config))
		if err != nil {
			t.Fatalf("seed append-config: build request: %v", err)
		}
		resp, body := do(req)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("seed append-config: status %d, want 202 (body %s)", resp.StatusCode, body)
		}
		if got := resp.Header.Get("Range"); got != uploadRange(int64(len(config))) {
			t.Fatalf("seed append-config: Range %q, want %q", got, uploadRange(int64(len(config))))
		}
		if got := resp.Header.Get("Docker-Upload-UUID"); got != state.uploadID {
			t.Fatalf("seed append-config: Docker-Upload-UUID %q, want %q", got, state.uploadID)
		}
	case "finalize-config":
		if state.uploadURL == "" {
			t.Fatal("seed finalize-config: no active upload session")
		}
		digest := publish.ComputeDigest(config)
		req, err := http.NewRequest(http.MethodPut, state.uploadURL+"?digest="+digest, nil)
		if err != nil {
			t.Fatalf("seed finalize-config: build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/vnd.oci.image.config.v1+json")
		resp, body := do(req)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("seed finalize-config: status %d, want 201 (body %s)", resp.StatusCode, body)
		}
		if got := resp.Header.Get("Docker-Content-Digest"); got != digest {
			t.Fatalf("seed finalize-config: Docker-Content-Digest %q, want %q", got, digest)
		}
		if got := resp.Header.Get("Location"); got != "/v2/backend/api/blobs/"+digest {
			t.Fatalf("seed finalize-config: Location %q, want %q", got, "/v2/backend/api/blobs/"+digest)
		}
		state.configDigest = digest
	default:
		t.Fatalf("unknown conformance seed %q", seed)
	}
}

// conformanceAuthHeader returns the Authorization header value for a row's
// auth kind. Pull/push tokens are scoped to backend/api (the repository the
// policy grants), *-other tokens to backend/other (which the policy denies).
func conformanceAuthHeader(t *testing.T, issuer *auth.RegistryTokenIssuer, kind string) string {
	t.Helper()
	switch kind {
	case "", "anonymous":
		return ""
	case "pull":
		return registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour)
	case "push":
		return registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPush}, time.Hour)
	case "pull-other":
		return registryBearer(t, issuer, "user:alice", testServiceHost, "backend/other", []auth.Action{auth.ActionPull}, time.Hour)
	case "push-other":
		return registryBearer(t, issuer, "user:alice", testServiceHost, "backend/other", []auth.Action{auth.ActionPush}, time.Hour)
	}
	t.Fatalf("unknown conformance auth kind %q", kind)
	return ""
}

// conformanceResolve substitutes the table's value placeholders.
func conformanceResolve(s string, st *conformanceState) string {
	repl := map[string]string{
		"{zero}":         zeroDigest,
		"{manifest}":     st.manifestDigest,
		"{manifestSize}": st.manifestSize,
		"{blob}":         st.blobDigest,
		"{blobSize}":     st.blobSize,
		"{upload}":       st.uploadID,
		"{configDigest}": st.configDigest,
		"{configSize}":   st.configSize,
	}
	for k, v := range repl {
		s = strings.ReplaceAll(s, k, v)
	}
	return s
}
