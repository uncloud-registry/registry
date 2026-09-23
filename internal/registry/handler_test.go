package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/policy"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/staging"
)

// testServiceHost is the canonical registry host the test handler serves and
// the audience every valid test token is issued for.
const testServiceHost = "alice.uncloud-registry.com"

// testKeyID is the kid shared by the test key pairs.
const testKeyID = "test-key-1"

// testKeySet is an in-memory PublicKeySet (the strict JWKS loader is exercised
// separately in internal/auth and cmd/registry).
type testKeySet map[string]ed25519.PublicKey

func (k testKeySet) Key(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	pk, ok := k[keyID]
	if !ok {
		return nil, errors.New("unknown kid")
	}
	return pk, nil
}

func TestManifestAndBlobPullViaRepoState(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)
	docs.Documents["manifest-ref"] = []byte(`{"schemaVersion":2}`)
	docs.Documents["blob-ref"] = []byte("blob-bytes")

	handler, _ := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	manifestReq, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create manifest request: %v", err)
	}
	manifestReq.Host = testServiceHost

	manifestResp, err := http.DefaultClient.Do(manifestReq)
	if err != nil {
		t.Fatalf("manifest request failed: %v", err)
	}
	defer manifestResp.Body.Close()

	if manifestResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected manifest status: %d", manifestResp.StatusCode)
	}

	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(manifestResp.Body); err != nil {
		t.Fatalf("read manifest body: %v", err)
	}
	if got := body.String(); got != `{"schemaVersion":2}` {
		t.Fatalf("unexpected manifest body: %s", got)
	}

	blobReq, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/blobs/sha256:blob1", nil)
	if err != nil {
		t.Fatalf("create blob request: %v", err)
	}
	blobReq.Host = testServiceHost

	blobResp, err := http.DefaultClient.Do(blobReq)
	if err != nil {
		t.Fatalf("blob request failed: %v", err)
	}
	defer blobResp.Body.Close()

	if blobResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected blob status: %d", blobResp.StatusCode)
	}
}

func TestPullRequiresAuthWhenAnonymousNotAllowed(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)
	docs.Documents["auth-policy-ref"] = []byte(`{
		"version":1,
		"defaultAccess":"deny",
		"repos":{"backend/api":{"pull":["user:alice"],"push":["user:alice"]}}
	}`)

	handler, _ := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = testServiceHost

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	if challenge := resp.Header.Get("WWW-Authenticate"); challenge == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestAuthenticatedPullAllowedByPolicy(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, issuer := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = testServiceHost
	req.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
}

// TestAnonymousPullIsEvaluatedByPolicy captures the principal handed to the
// pull policy when no token is presented: it must be the anonymous subject,
// and the policy (not the auth layer) makes the allow decision.
func TestAnonymousPullIsEvaluatedByPolicy(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, _ := newTestHandler(t, docs, feeds)
	handler.(*Handler).PullAuthorizer = &capturingPullAuthorizer{
		allowed:  true,
		onCall:   func(p auth.Principal) { t.Logf("policy saw principal %+v", p) },
		recorded: &[]auth.Principal{},
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = testServiceHost

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous pull on public repo must be allowed, status=%d", resp.StatusCode)
	}
	// The auth layer must hand policy exactly the anonymous subject.
	got := *handler.(*Handler).PullAuthorizer.(*capturingPullAuthorizer).recorded
	if len(got) != 1 || got[0].Subject != auth.AnonymousSubject {
		t.Fatalf("policy must be consulted with the anonymous principal, got %+v", got)
	}
}

// TestPullRejectsInvalidCredentialsOnPublicRepo pins the never-downgrade rule:
// on a repo whose policy explicitly allows anonymous pull, ANY presented but
// invalid credential is still a hard 401 — invalid credentials are never
// reclassified as anonymous on public repos.
func TestPullRejectsInvalidCredentialsOnPublicRepo(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, issuer := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	headers := map[string]string{
		"non-jwt garbage":         "Bearer not-a-jwt",
		"unsigned role bearer":    "Bearer role:read",
		"wrong scheme":            "Basic dXNlcjpwYXNz",
		"missing token part":      "Bearer",
		"empty bearer":            "Bearer ",
		"double space":            "Bearer  xyz",
		"expired token":           "Bearer " + registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, -time.Hour),
		"wrong service claim":     "Bearer " + registryBearer(t, issuer, "user:alice", "evil.example.test", "backend/api", []auth.Action{auth.ActionPull}, time.Hour),
		"wrong repository":        "Bearer " + registryBearer(t, issuer, "user:alice", testServiceHost, "other/repo", []auth.Action{auth.ActionPull}, time.Hour),
		"push-only token on pull": "Bearer " + registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPush}, time.Hour),
		"session token":           sessionBearerText(t, "user:alice"),
		"invalid signature":       "Bearer " + registryBearerFromOtherKey(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour),
	}

	for name, header := range headers {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
		if err != nil {
			t.Fatalf("%s: create request: %v", name, err)
		}
		req.Host = testServiceHost
		req.Header.Set("Authorization", header)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: request failed: %v", name, err)
		}
		code := resp.StatusCode
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()

		if code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401 on a public repo, got %d", name, code)
		}
		if challenge == "" {
			t.Errorf("%s: expected WWW-Authenticate challenge", name)
		}
	}
}

// TestPushRejectsInvalidCredentials covers every invalid push credential
// shape: no header, wrong scheme, malformed, unsigned, expired, wrong
// service/repository, pull-only scope, session tokens, and forgeries.
func TestPushRejectsInvalidCredentials(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, issuer := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	headers := map[string]string{
		"no header":            "",
		"non-jwt garbage":      "Bearer not-a-jwt",
		"unsigned role bearer": "Bearer role:write",
		"wrong scheme":         "Basic dXNlcjpwYXNz",
		"missing token part":   "Bearer",
		"empty bearer":         "Bearer ",
		"double space":         "Bearer  xyz",
		"expired token":        "Bearer " + registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPush}, -time.Hour),
		"wrong service claim":  "Bearer " + registryBearer(t, issuer, "user:alice", "evil.example.test", "backend/api", []auth.Action{auth.ActionPush}, time.Hour),
		"wrong repository":     "Bearer " + registryBearer(t, issuer, "user:alice", testServiceHost, "other/repo", []auth.Action{auth.ActionPush}, time.Hour),
		"pull-only token":      "Bearer " + registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour),
		"session token":        sessionBearerText(t, "user:alice"),
		"invalid signature":    "Bearer " + registryBearerFromOtherKey(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPush}, time.Hour),
	}

	for name, header := range headers {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v2/backend/api/blobs/uploads/", nil)
		if err != nil {
			t.Fatalf("%s: create request: %v", name, err)
		}
		req.Host = testServiceHost
		if header != "" {
			req.Header.Set("Authorization", header)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: request failed: %v", name, err)
		}
		code := resp.StatusCode
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()

		if code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %d", name, code)
		}
		if challenge == "" {
			t.Errorf("%s: expected WWW-Authenticate challenge", name)
		}
	}
}

// TestPushRejectsTokenAtUnconfiguredRequestHost proves the request-side
// service binding: a valid token for the configured audience presented at a
// host that resolves to a DIFFERENT registry identity still fails closed.
func TestPushRejectsTokenAtUnconfiguredRequestHost(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, issuer := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/v2/backend/api/blobs/uploads/", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = "evil.example.test" // resolves in the test identity map
	req.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPush}, time.Hour))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token for another service host must be rejected, status=%d", resp.StatusCode)
	}
}

func TestPushRejectsUnsignedRoleBearer(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, _ := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/v2/backend/api/blobs/uploads/", nil)
	if err != nil {
		t.Fatalf("create start upload request: %v", err)
	}
	req.Host = testServiceHost
	req.Header.Set("Authorization", "Bearer role:write")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("start upload request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned role bearer must be rejected, status=%d", resp.StatusCode)
	}
}

func TestPullRejectsSessionTokenEvenOnPublicRepo(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, _ := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = testServiceHost
	req.Header.Set("Authorization", sessionBearerText(t, "user:alice"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session token must not authorize or downgrade pull on a public repo, status=%d", resp.StatusCode)
	}
}

func TestPushRejectsSessionToken(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, _ := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/v2/backend/api/blobs/uploads/", nil)
	if err != nil {
		t.Fatalf("create start upload request: %v", err)
	}
	req.Host = testServiceHost
	req.Header.Set("Authorization", sessionBearerText(t, "user:alice"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("start upload request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session token must never start a push, status=%d", resp.StatusCode)
	}
}

func TestPushBlobAndPublishManifest(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, issuer := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	pushAuth := func(req *http.Request) {
		req.Host = testServiceHost
		req.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPush}, time.Hour))
	}

	startReq, err := http.NewRequest(http.MethodPost, server.URL+"/v2/backend/api/blobs/uploads/", nil)
	if err != nil {
		t.Fatalf("create start upload request: %v", err)
	}
	pushAuth(startReq)

	startResp, err := http.DefaultClient.Do(startReq)
	if err != nil {
		t.Fatalf("start upload request failed: %v", err)
	}
	defer startResp.Body.Close()

	if startResp.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected start upload status: %d", startResp.StatusCode)
	}

	uploadURL := server.URL + startResp.Header.Get("Location")
	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := publish.ComputeDigest(configBytes)

	patchReq, err := http.NewRequest(http.MethodPatch, uploadURL, bytes.NewReader(configBytes))
	if err != nil {
		t.Fatalf("create patch request: %v", err)
	}
	pushAuth(patchReq)

	patchResp, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("patch request failed: %v", err)
	}
	defer patchResp.Body.Close()

	if patchResp.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected patch status: %d", patchResp.StatusCode)
	}

	finalizeReq, err := http.NewRequest(http.MethodPut, uploadURL+"?digest="+configDigest, nil)
	if err != nil {
		t.Fatalf("create finalize request: %v", err)
	}
	pushAuth(finalizeReq)
	finalizeReq.Header.Set("Content-Type", "application/vnd.oci.image.config.v1+json")

	finalizeResp, err := http.DefaultClient.Do(finalizeReq)
	if err != nil {
		t.Fatalf("finalize request failed: %v", err)
	}
	defer finalizeResp.Body.Close()

	if finalizeResp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected finalize status: %d", finalizeResp.StatusCode)
	}

	manifestBody := []byte(`{
		"schemaVersion":2,
		"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":24,"digest":"` + configDigest + `"},
		"layers":[]
	}`)

	manifestReq, err := http.NewRequest(http.MethodPut, server.URL+"/v2/backend/api/manifests/latest", bytes.NewReader(manifestBody))
	if err != nil {
		t.Fatalf("create manifest request: %v", err)
	}
	pushAuth(manifestReq)
	manifestReq.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")

	manifestResp, err := http.DefaultClient.Do(manifestReq)
	if err != nil {
		t.Fatalf("manifest publish request failed: %v", err)
	}
	defer manifestResp.Body.Close()

	if manifestResp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected manifest publish status: %d", manifestResp.StatusCode)
	}

	// Signed pull with the same principal works too.
	getReq, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create get manifest request: %v", err)
	}
	getReq.Host = testServiceHost
	getReq.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour))

	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get manifest request failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected get manifest status: %d", getResp.StatusCode)
	}
}

// TestInvalidPushCredentialsProduceNoSideEffects proves verification happens
// BEFORE policy, staging, and publish: every blocked attempt leaves zero
// staging sessions, zero policy consultations, and the repo-state feed
// untouched.
func TestInvalidPushCredentialsProduceNoSideEffects(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, issuer := newTestHandler(t, docs, feeds)
	h := handler.(*Handler)
	stage := &countingStaging{Store: staging.NewMemoryStore()}
	h.Staging = stage
	pushAuthz := &recordingPushAuthorizer{allowed: true, batchID: "batch-repo"}
	h.PushAuthorizer = pushAuthz
	server := httptest.NewServer(h)
	defer server.Close()

	attempts := map[string]string{
		"no header":            "",
		"unsigned role bearer": "Bearer role:write",
		"expired token":        "Bearer " + registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPush}, -time.Hour),
		"session token":        sessionBearerText(t, "user:alice"),
		"wrong repository":     "Bearer " + registryBearer(t, issuer, "user:alice", testServiceHost, "other/repo", []auth.Action{auth.ActionPush}, time.Hour),
	}
	for name, header := range attempts {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v2/backend/api/blobs/uploads/", nil)
		if err != nil {
			t.Fatalf("%s: create request: %v", name, err)
		}
		req.Host = testServiceHost
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: request failed: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d", name, resp.StatusCode)
		}
	}

	if stage.created != 0 {
		t.Fatalf("blocked pushes created %d staging sessions", stage.created)
	}
	if pushAuthz.calls != 0 {
		t.Fatalf("blocked pushes consulted the push policy %d times", pushAuthz.calls)
	}
	// Manifest path never ran, so the repo-state feed must still point at the
	// seeded document.
	if got := feeds.Feeds[spec.RepoStateFeedRef("0xaliceowner", "backend/api")]; got != "repo-state-ref" {
		t.Fatalf("repo-state feed changed to %q after blocked pushes", got)
	}
}

// TestInvalidPullCredentialsProduceNoSideEffects proves blocked pulls never
// reach the pull policy, the repo-state resolution, or the object store —
// even on a public repo where anonymous would have been allowed.
func TestInvalidPullCredentialsProduceNoSideEffects(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, _ := newTestHandler(t, docs, feeds)
	h := handler.(*Handler)
	objects := &countingObjects{ObjectStore: docs}
	h.Objects = objects
	pullAuthz := &recordingPullAuthorizer{allowed: true}
	h.PullAuthorizer = pullAuthz
	server := httptest.NewServer(h)
	defer server.Close()

	for name, header := range map[string]string{
		"non-jwt garbage": "Bearer garbage",
		"wrong scheme":    "Basic dXNlcjpwYXNz",
	} {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
		if err != nil {
			t.Fatalf("%s: create request: %v", name, err)
		}
		req.Host = testServiceHost
		req.Header.Set("Authorization", header)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: request failed: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d", name, resp.StatusCode)
		}
	}

	if pullAuthz.calls != 0 {
		t.Fatalf("blocked pulls consulted the pull policy %d times", pullAuthz.calls)
	}
	if objects.gets != 0 {
		t.Fatalf("blocked pulls fetched %d objects", objects.gets)
	}
}

func TestMemoryDocumentStoreRoundTrip(t *testing.T) {
	t.Parallel()

	store := resolve.NewMemoryDocumentStore()
	ref, err := store.Put(context.Background(), []byte("hello"), "batch")
	if err != nil {
		t.Fatalf("put failed: %v", err)
	}
	got, err := store.Get(context.Background(), ref)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("unexpected stored data: %q", got)
	}
}

// --- fixtures and helpers ---

// newTestHandler builds a handler wired to a freshly generated Ed25519 test
// key pair. The verifier is bound to the test issuer and the testServiceHost
// audience. It returns the handler plus the issuer used to sign fixtures.
func newTestHandler(t *testing.T, docs *resolve.MemoryDocumentStore, feeds *resolve.MemoryFeedStore) (http.Handler, *auth.RegistryTokenIssuer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keys := testKeySet{testKeyID: pub}
	issuer, err := auth.NewRegistryTokenIssuer(priv, auth.RegistryIssuer, testKeyID)
	if err != nil {
		t.Fatalf("new registry token issuer: %v", err)
	}
	verifier := auth.NewRegistryTokenVerifier(keys, auth.RegistryIssuer, testServiceHost)
	stageStore := staging.NewMemoryStore()
	handler := NewHandler(
		resolve.RegistryResolver{
			Registries: resolve.StaticRegistryIdentityResolver{
				Hosts: map[string]resolve.RegistryIdentity{
					testServiceHost: {
						Host:  testServiceHost,
						Owner: "0xaliceowner",
					},
					"evil.example.test": {
						Host:  "evil.example.test",
						Owner: "0xevilowner",
					},
				},
			},
			Docs:  docs,
			Feeds: feeds,
		},
		docs,
		docs,
		policy.PullAuthorizer{Policies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}},
		policy.PushAuthorizer{
			AuthPolicies:  policy.AuthPolicyResolver{Docs: docs, Feeds: feeds},
			StampPolicies: policy.StampPolicyResolver{Docs: docs, Feeds: feeds},
		},
		BearerAuthenticator{Tokens: verifier},
		stageStore,
		publish.Publisher{
			Builder: publish.DefaultBuilder{},
			Objects: docs,
			Feeds:   feeds,
		},
		nil,
		"https://auth.uncloud-registry.com/token",
	)
	return handler, issuer
}

// registryBearer issues a signed registry token through the given issuer and
// returns the full `Bearer <token>` header value.
func registryBearer(t *testing.T, issuer *auth.RegistryTokenIssuer, subject, service, repository string, actions []auth.Action, ttl time.Duration) string {
	t.Helper()
	raw, err := issuer.Issue(context.Background(), auth.RegistryTokenRequest{
		Subject:    subject,
		Service:    service,
		Repository: repository,
		Actions:    actions,
		TTL:        ttl,
	})
	if err != nil {
		t.Fatalf("issue registry token: %v", err)
	}
	return "Bearer " + raw
}

// registryBearerFromOtherKey signs a structurally identical token with a
// DIFFERENT private key under the same kid, producing a forged signature.
func registryBearerFromOtherKey(t *testing.T, _ *auth.RegistryTokenIssuer, subject, service, repository string, actions []auth.Action, ttl time.Duration) string {
	t.Helper()
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	forger, err := auth.NewRegistryTokenIssuer(otherPriv, auth.RegistryIssuer, testKeyID)
	if err != nil {
		t.Fatalf("new forger issuer: %v", err)
	}
	raw, err := forger.Issue(context.Background(), auth.RegistryTokenRequest{
		Subject:    subject,
		Service:    service,
		Repository: repository,
		Actions:    actions,
		TTL:        ttl,
	})
	if err != nil {
		t.Fatalf("forge token: %v", err)
	}
	return raw
}

// sessionBearerText issues a control-plane session token (HMAC, a different
// purpose) and returns the full `Bearer <token>` header value. Such tokens
// are NOT registry credentials and must be rejected everywhere.
func sessionBearerText(t *testing.T, subject string) string {
	t.Helper()
	m, err := auth.NewSessionTokenManager("handler-test-session-secret-0123456789abcdef", auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	if err != nil {
		t.Fatalf("new session manager: %v", err)
	}
	raw, err := m.Issue(subject, time.Hour)
	if err != nil {
		t.Fatalf("issue session token: %v", err)
	}
	return "Bearer " + raw
}

func seedRegistryDocuments(t *testing.T, docs *resolve.MemoryDocumentStore, feeds *resolve.MemoryFeedStore) {
	t.Helper()

	docs.Documents["repo-state-ref"] = []byte(`{
		"version":1,
		"repo":"backend/api",
		"generation":3,
		"updatedAt":"2026-04-05T12:00:00Z",
		"tags":{"latest":"sha256:manifest1"},
		"manifests":{
			"sha256:manifest1":{"swarmRef":"manifest-ref","mediaType":"application/vnd.oci.image.manifest.v1+json","size":19}
		},
		"blobs":{
			"sha256:blob1":{"swarmRef":"blob-ref","size":10,"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip"}
		}
	}`)
	docs.Documents["auth-policy-ref"] = []byte(`{
		"version":1,
		"defaultAccess":"deny",
		"repos":{"backend/api":{"pull":["anonymous","user:alice"],"push":["user:alice"]}}
	}`)
	docs.Documents["stamp-policy-ref"] = []byte(`{
		"version":1,
		"defaultPolicy":{"batchID":"batch-default","allowPushFor":["user:alice"]},
		"repos":{"backend/api":{"batchID":"batch-repo","allowPushFor":["user:alice"]}}
	}`)
	docs.Documents["manifest-ref"] = []byte(`{"schemaVersion":2}`)
	docs.Documents["blob-ref"] = []byte("blob-bytes")
	feeds.Feeds[spec.RepoStateFeedRef("0xaliceowner", "backend/api")] = "repo-state-ref"
	feeds.Feeds[spec.AuthPolicyFeedRef("0xaliceowner")] = "auth-policy-ref"
	feeds.Feeds[spec.StampPolicyFeedRef("0xaliceowner")] = "stamp-policy-ref"
}

// --- side-effect instrumentation ---

type capturingPullAuthorizer struct {
	allowed  bool
	recorded *[]auth.Principal
	onCall   func(auth.Principal)
}

func (c *capturingPullAuthorizer) Authorize(_ context.Context, _ resolve.RegistryIdentity, _ string, p auth.Principal) (bool, error) {
	if c.recorded != nil {
		*c.recorded = append(*c.recorded, p)
	}
	if c.onCall != nil {
		c.onCall(p)
	}
	return c.allowed, nil
}

type recordingPullAuthorizer struct {
	calls   int
	allowed bool
	err     error
}

func (r *recordingPullAuthorizer) Authorize(_ context.Context, _ resolve.RegistryIdentity, _ string, _ auth.Principal) (bool, error) {
	r.calls++
	return r.allowed, r.err
}

type recordingPushAuthorizer struct {
	calls   int
	batchID string
	allowed bool
}

func (r *recordingPushAuthorizer) Authorize(_ context.Context, _ resolve.RegistryIdentity, _ string, _ auth.Principal) (string, bool, error) {
	r.calls++
	return r.batchID, r.allowed, nil
}

type countingStaging struct {
	staging.Store
	created int
}

func (c *countingStaging) CreateSession(ctx context.Context, repo string, actor string, ttl time.Duration) (spec.UploadSession, error) {
	c.created++
	return c.Store.CreateSession(ctx, repo, actor, ttl)
}

type countingObjects struct {
	ObjectStore
	gets int
}

func (c *countingObjects) Get(ctx context.Context, ref string) ([]byte, error) {
	c.gets++
	return c.ObjectStore.Get(ctx, ref)
}

// TestAnonymousPullDeniedWhenDefaultAllowOnly pins the handler-visible
// behavior of the anonymous rule: an auth policy whose only grant is
// DefaultAccess "allow" (no repo entry, no DefaultRepo, no "anonymous"
// anywhere) must reject an anonymous manifest pull with 401 — default-allow
// must never implicitly turn a repo public.
func TestAnonymousPullDeniedWhenDefaultAllowOnly(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)
	// Overwrite the seeded policy: no entry for backend/api, defaultAccess
	// allow, and no anonymous listing anywhere.
	docs.Documents["auth-policy-ref"] = []byte(`{
		"version":1,
		"defaultAccess":"allow",
		"repos":{}
	}`)

	handler, _ := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = testServiceHost

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous pull with default-allow only must be 401, got %d", resp.StatusCode)
	}
	if challenge := resp.Header.Get("WWW-Authenticate"); challenge == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

// TestHandlerServesTwoHostsWithHostSpecificTokens pins the multi-namespace
// audience behavior at the HTTP boundary: one handler process serving two
// owner-map hosts verifies each host's token independently (200), rejects a
// host A token presented at host B (401), and rejects any host outside the
// configured allowlist (401) before policy is consulted.
func TestHandlerServesTwoHostsWithHostSpecificTokens(t *testing.T) {
	t.Parallel()

	const hostB = "bob.uncloud-registry.com"

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keys := testKeySet{testKeyID: pub}
	issuer, err := auth.NewRegistryTokenIssuer(priv, auth.RegistryIssuer, testKeyID)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	verifier, err := auth.NewMultiServiceVerifier(keys, auth.RegistryIssuer, []string{testServiceHost, hostB})
	if err != nil {
		t.Fatalf("new multi verifier: %v", err)
	}
	handler := NewHandler(
		resolve.RegistryResolver{
			Registries: resolve.StaticRegistryIdentityResolver{
				Hosts: map[string]resolve.RegistryIdentity{
					testServiceHost:     {Host: testServiceHost, Owner: "0xaliceowner"},
					hostB:               {Host: hostB, Owner: "0xaliceowner"},
					"evil.example.test": {Host: "evil.example.test", Owner: "0xevilowner"},
				},
			},
			Docs:  docs,
			Feeds: feeds,
		},
		docs,
		docs,
		policy.PullAuthorizer{Policies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}},
		policy.PushAuthorizer{
			AuthPolicies:  policy.AuthPolicyResolver{Docs: docs, Feeds: feeds},
			StampPolicies: policy.StampPolicyResolver{Docs: docs, Feeds: feeds},
		},
		BearerAuthenticator{Tokens: verifier},
		staging.NewMemoryStore(),
		publish.Publisher{
			Builder: publish.DefaultBuilder{},
			Objects: docs,
			Feeds:   feeds,
		},
		nil,
		"https://auth.uncloud-registry.com/token",
	)
	server := httptest.NewServer(handler)
	defer server.Close()

	getManifest := func(host, bearer string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		req.Host = host
		if bearer != "" {
			req.Header.Set("Authorization", bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	tokenA := registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour)
	tokenB := registryBearer(t, issuer, "user:alice", hostB, "backend/api", []auth.Action{auth.ActionPull}, time.Hour)

	if got := getManifest(testServiceHost, tokenA); got != http.StatusOK {
		t.Fatalf("host A token at host A: status %d, want 200", got)
	}
	if got := getManifest(hostB, tokenB); got != http.StatusOK {
		t.Fatalf("host B token at host B: status %d, want 200", got)
	}
	if got := getManifest(hostB, tokenA); got != http.StatusUnauthorized {
		t.Fatalf("host A token at host B: status %d, want 401", got)
	}
	if got := getManifest(testServiceHost, tokenB); got != http.StatusUnauthorized {
		t.Fatalf("host B token at host A: status %d, want 401", got)
	}
	if got := getManifest("evil.example.test", tokenA); got != http.StatusUnauthorized {
		t.Fatalf("valid token at a host outside the allowlist: status %d, want 401", got)
	}
}

// TestManifestPutRejectsAttackerStoredMediaWithoutEcho drives a real
// handleManifestPut where the staged blob's stored media type is attacker
// controlled and malformed/conflicting. The 400 MANIFEST_INVALID response must
// NOT echo the attacker marker anywhere (ValidationError.Error is data-free),
// and the manifest body itself must be rejected before any manifest state is
// recorded — the upload of the blob is the only side effect.
func TestManifestPutRejectsAttackerStoredMediaWithoutEcho(t *testing.T) {
	t.Parallel()

	const marker = "EVILSTOREDMEDIATYPE_ATTACKER_7f3a"

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)

	handler, issuer := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	pushAuth := func(req *http.Request) {
		req.Host = testServiceHost
		req.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPush}, time.Hour))
	}

	do := func(req *http.Request) (*http.Response, []byte) {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, body
	}

	// Stage a config blob whose stored media type is the attacker marker.
	startReq, _ := http.NewRequest(http.MethodPost, server.URL+"/v2/backend/api/blobs/uploads/", nil)
	pushAuth(startReq)
	startResp, _ := do(startReq)
	if startResp.StatusCode != http.StatusAccepted {
		t.Fatalf("start upload status %d", startResp.StatusCode)
	}
	uploadURL := server.URL + startResp.Header.Get("Location")

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := publish.ComputeDigest(configBytes)

	patchReq, _ := http.NewRequest(http.MethodPatch, uploadURL, bytes.NewReader(configBytes))
	pushAuth(patchReq)
	patchResp, _ := do(patchReq)
	if patchResp.StatusCode != http.StatusAccepted {
		t.Fatalf("patch upload status %d", patchResp.StatusCode)
	}

	finalizeReq, _ := http.NewRequest(http.MethodPut, uploadURL+"?digest="+configDigest, nil)
	pushAuth(finalizeReq)
	finalizeReq.Header.Set("Content-Type", marker) // attacker-controlled stored media type
	finalizeResp, _ := do(finalizeReq)
	if finalizeResp.StatusCode != http.StatusCreated {
		t.Fatalf("finalize upload status %d", finalizeResp.StatusCode)
	}

	// Publish a manifest that references the staged blob with a VALID
	// descriptor. The stored media type (marker) is malformed, so reference
	// coherence must reject with a data-free 400 and zero manifest state.
	manifestBody := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":` + fmt.Sprintf("%d", len(configBytes)) + `,"digest":"` + configDigest + `"},"layers":[]}`)
	manifestReq, _ := http.NewRequest(http.MethodPut, server.URL+"/v2/backend/api/manifests/latest", bytes.NewReader(manifestBody))
	pushAuth(manifestReq)
	manifestReq.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	manifestResp, manifestBodyBytes := do(manifestReq)

	if manifestResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("manifest put status %d, want 400 (body: %s)", manifestResp.StatusCode, manifestBodyBytes)
	}
	if strings.Contains(string(manifestBodyBytes), marker) {
		t.Fatalf("MANIFEST_INVALID response echoes attacker stored media marker %q: %s", marker, manifestBodyBytes)
	}
}
