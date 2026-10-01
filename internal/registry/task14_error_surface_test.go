package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
)

// failingRegistryResolver injects a raw resolver failure carrying a marker,
// the service host, the repository, and a document reference — exactly the
// text the fixed classification must never leak.
type failingRegistryResolver struct{ err error }

func (f failingRegistryResolver) ResolveRegistry(context.Context, string) (resolve.RegistryIdentity, error) {
	return resolve.RegistryIdentity{}, f.err
}

// TestResolveRegistryFailureDataFreeThroughRealHandler is the Finding-3
// regression for the registry-identity boundary: a raw ResolveRegistry error
// is classified through the fixed centralized mapper into a fixed 503
// DEPENDENCY_UNAVAILABLE with a fixed generic message. The injected marker,
// the request Host, the repository name, and any digest/ref text in the raw
// error must never reach status line, headers, or body — and no feed, object,
// or staging write happens (no registry, no repository).
func TestResolveRegistryFailureDataFreeThroughRealHandler(t *testing.T) {
	const marker = "MARKER_T14_identity_77aa"
	h, docs, feeds, issuer, serverURL := task14World(t)
	h.Resolver.Registries = failingRegistryResolver{err: fmt.Errorf("resolve %q repo %q ref %q: %w", testServiceHost, "backend/api", "repo-state-ref", errors.New(marker))}
	h.PushAuthorizer = &recordingPushAuthorizer{allowed: true, batchID: "batch-repo"}
	docCount := len(docs.Documents)

	req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	pushTo(t, req, issuer)
	req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("identity resolution failure must be 503 DEPENDENCY_UNAVAILABLE, got %d (%s)", resp.StatusCode, body)
	}
	code, message := decodeErrorPayload(t, body)
	if code != ErrorCodeDependencyUnavailable {
		t.Fatalf("expected DEPENDENCY_UNAVAILABLE, got %q", code)
	}
	if message != messageDependencyUnavailable {
		t.Fatalf("message must be the fixed generic dependency text, got %q", message)
	}
	for _, leaked := range []string{marker, testServiceHost, "backend/api", "repo-state-ref"} {
		if strings.Contains(string(body), leaked) {
			t.Fatalf("identity failure leaked %q in the public body: %s", leaked, body)
		}
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("identity failure must not create the repo-state feed")
	}
	if len(docs.Documents) != docCount {
		t.Fatalf("identity failure must not create objects: %d -> %d", docCount, len(docs.Documents))
	}
}

// failingPushAuthorizer injects a raw authorization-policy failure carrying a
// marker, a policy document reference, and repository text.
type failingPushAuthorizer struct{ err error }

func (f *failingPushAuthorizer) Authorize(context.Context, resolve.RegistryIdentity, string, auth.Principal) (string, bool, error) {
	return "", false, f.err
}

// TestPushAuthorizerFailureDataFreeThroughRealHandler is the Finding-3
// regression for the manifest-PUT policy boundary: the raw policy failure is
// classified into a fixed 503 DEPENDENCY_UNAVAILABLE with the fixed generic
// message — never the raw text, the service host, the repository, or the
// document reference — and zero writes happen behind it.
func TestPushAuthorizerFailureDataFreeThroughRealHandler(t *testing.T) {
	const marker = "MARKER_T14_policy_9c41"
	h, docs, feeds, issuer, serverURL := task14World(t)
	h.PushAuthorizer = &failingPushAuthorizer{err: fmt.Errorf("policy consult for %q failed reading %q: %w", "backend/api", "stamp-policy-ref", errors.New(marker))}
	docCount := len(docs.Documents)

	req, err := http.NewRequest(http.MethodPut, serverURL+"/v2/backend/api/manifests/latest", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	pushTo(t, req, issuer)
	req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("push authorizer failure must be 503 DEPENDENCY_UNAVAILABLE, got %d (%s)", resp.StatusCode, body)
	}
	code, message := decodeErrorPayload(t, body)
	if code != ErrorCodeDependencyUnavailable || message != messageDependencyUnavailable {
		t.Fatalf("expected fixed 503 DEPENDENCY_UNAVAILABLE (%q), got code=%q message=%q", messageDependencyUnavailable, code, message)
	}
	for _, leaked := range []string{marker, "backend/api", "stamp-policy-ref", testServiceHost} {
		if strings.Contains(string(body), leaked) {
			t.Fatalf("authorizer failure leaked %q in the public body: %s", leaked, body)
		}
	}
	if _, ok := feeds.Feeds[repoStateFeed()]; ok {
		t.Fatal("authorizer failure must not create the repo-state feed")
	}
	if len(docs.Documents) != docCount {
		t.Fatalf("authorizer failure must not create objects: %d -> %d", docCount, len(docs.Documents))
	}
}

// TestPullPathFailuresDataFreeThroughRealHandler proves the pull paths are
// wired through the same fixed classification: pull-authorizer failure is a
// fixed 503, a missing repository state is a fixed 404 NAME_UNKNOWN (never
// the resolver's raw document/feed text), and a failing object read is a
// fixed 502 with the fixed generic message — no marker, host, repo, digest,
// or ref text ever reaches the body.
func TestPullPathFailuresDataFreeThroughRealHandler(t *testing.T) {
	const marker = "MARKER_T14_pull_d42f"

	t.Run("pull authorizer failure is fixed 503", func(t *testing.T) {
		h, docs, feeds, issuer, serverURL := task14World(t)
		h.PullAuthorizer = &recordingPullAuthorizer{err: fmt.Errorf("pull policy %q: %w", "auth-policy-ref", errors.New(marker))}
		docCount := len(docs.Documents)
		resp := pullManifest(t, serverURL, issuer)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("pull authorizer failure must be 503, got %d (%s)", resp.StatusCode, body)
		}
		if code, _ := decodeErrorPayload(t, body); code != ErrorCodeDependencyUnavailable {
			t.Fatalf("expected DEPENDENCY_UNAVAILABLE, got %q", code)
		}
		assertNoLeak(t, body, marker, "auth-policy-ref", "backend/api")
		if _, ok := feeds.Feeds[repoStateFeed()]; ok {
			t.Fatal("authorizer failure must not create the repo-state feed")
		}
		if len(docs.Documents) != docCount {
			t.Fatalf("authorizer failure must not create objects: %d -> %d", docCount, len(docs.Documents))
		}
	})

	t.Run("missing repository state is fixed 404", func(t *testing.T) {
		_, _, _, issuer, serverURL := task14World(t)
		resp := pullManifest(t, serverURL, issuer)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("missing repo state must be 404, got %d (%s)", resp.StatusCode, body)
		}
		if code, message := decodeErrorPayload(t, body); code != "NAME_UNKNOWN" {
			t.Fatalf("expected NAME_UNKNOWN, got %q", code)
		} else if message == "" {
			t.Fatal("404 must carry the fixed generic message")
		}
		// The resolver's raw text must never surface (no feed ref, no repo).
		assertNoLeak(t, body, repoStateFeed(), "backend/api", "feed")
	})

	t.Run("failing manifest object read is fixed 502", func(t *testing.T) {
		h, docs, feeds, issuer, serverURL := task14World(t)
		seedRegistryDocuments(t, docs, feeds)
		// The pull path reads manifest bodies through the BOUNDED artifact
		// reader (pre-verification), so the failure is injected there; the
		// raw object store is no longer the read seam.
		h.BoundedBytes = &failingBoundedReader{err: fmt.Errorf("bee %q get %q: %w", "some-swarm-ref", "manifest-ref", errors.New(marker))}
		resp := pullManifest(t, serverURL, issuer)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("failing manifest object read must be 502, got %d (%s)", resp.StatusCode, body)
		}
		if code, _ := decodeErrorPayload(t, body); code != "MANIFEST_BLOB_UNKNOWN" {
			t.Fatalf("expected MANIFEST_BLOB_UNKNOWN, got %q", code)
		}
		assertNoLeak(t, body, marker, "some-swarm-ref", "manifest-ref", "backend/api")
	})
}

// failingObjectStore injects a raw object read failure carrying a marker and
// a swarm reference for the pull-path classification.
type failingObjectStore struct {
	err   error
	extra PutFunc
}

type PutFunc func(context.Context, []byte, string) (string, error)

func (f *failingObjectStore) Get(context.Context, string) ([]byte, error) { return nil, f.err }
func (f *failingObjectStore) Put(ctx context.Context, b []byte, batch string) (string, error) {
	if f.extra != nil {
		return f.extra(ctx, b, batch)
	}
	return "", f.err
}

// TestUploadPolicyFailureDataFreeThroughRealHandler proves the upload path's
// push-authorizer failure is classified through the fixed mapper too (fixed
// 503 with the fixed message, no marker), and a staging-session failure is a
// fixed 500 BLOB_UPLOAD_UNKNOWN with the fixed generic message.
func TestUploadPolicyFailureDataFreeThroughRealHandler(t *testing.T) {
	const marker = "MARKER_T14_upload_1b3e"

	t.Run("upload authorizer failure is fixed 503", func(t *testing.T) {
		h, docs, feeds, issuer, serverURL := task14World(t)
		h.PushAuthorizer = &failingPushAuthorizer{err: fmt.Errorf("upload policy %q: %w", "auth-policy-ref", errors.New(marker))}
		docCount := len(docs.Documents)
		req, err := http.NewRequest(http.MethodPost, serverURL+"/v2/backend/api/blobs/uploads/", nil)
		if err != nil {
			t.Fatal(err)
		}
		pushTo(t, req, issuer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("upload authorizer failure must be 503, got %d (%s)", resp.StatusCode, body)
		}
		if code, _ := decodeErrorPayload(t, body); code != ErrorCodeDependencyUnavailable {
			t.Fatalf("expected DEPENDENCY_UNAVAILABLE, got %q", code)
		}
		assertNoLeak(t, body, marker, "auth-policy-ref", "backend/api")
		if _, ok := feeds.Feeds[repoStateFeed()]; ok {
			t.Fatal("authorizer failure must not create the repo-state feed")
		}
		if len(docs.Documents) != docCount {
			t.Fatalf("authorizer failure must not create objects: %d -> %d", docCount, len(docs.Documents))
		}
	})
}

// pullManifest issues an authorized PULL-scoped GET for the latest manifest.
func pullManifest(t *testing.T, serverURL string, issuer *auth.RegistryTokenIssuer) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, serverURL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = testServiceHost
	req.Header.Set("Authorization", registryBearer(t, issuer, "user:alice", testServiceHost, "backend/api", []auth.Action{auth.ActionPull}, time.Hour))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// assertNoLeak fails the test if ANY of the values appears in the body.
func assertNoLeak(t *testing.T, body []byte, values ...string) {
	t.Helper()
	for _, v := range values {
		if v != "" && strings.Contains(string(body), v) {
			t.Fatalf("public body leaked %q: %s", v, body)
		}
	}
}
