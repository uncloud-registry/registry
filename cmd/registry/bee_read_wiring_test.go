package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/registry"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/swarm"
)

const (
	beeWiringOwner = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
	beeWiringHost  = "registry.test"
)

// binaryRef builds a 64-hex reference from a raw byte pattern (0..31), so the
// raw feed payload bytes are NOT valid UTF-8/JSON: any code path that tried to
// JSON-decode the feed body would fail, proving binary-only decoding.
func binaryRef(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return hex.EncodeToString(raw)
}

func binaryBytes(ref string) []byte {
	raw, _ := hex.DecodeString(ref)
	return raw
}

// beeReadFixture is the fake Bee for the production read-layering test. It
// serves the REAL read surface: GET /feeds/<owner>/<topic> (raw 32 binary
// payload + Swarm-Feed-Index), GET /bzz/<ref> (immutable documents), and
// GET /bytes/<ref> (objects). Request accounting proves exactly which layering
// each read took.
type beeReadFixture struct {
	mu        sync.Mutex
	feeds     map[string][]byte
	indexes   map[string]string
	payloads  map[string][]byte
	feedHits  map[string]int
	bzzHits   map[string]int
	bytesHits map[string]int
}

func newBeeReadFixture(t *testing.T) *beeReadFixture {
	t.Helper()
	f := &beeReadFixture{
		feeds:     map[string][]byte{},
		indexes:   map[string]string{},
		payloads:  map[string][]byte{},
		feedHits:  map[string]int{},
		bzzHits:   map[string]int{},
		bytesHits: map[string]int{},
	}

	// Immutable documents: repo state (generation 5), auth policy.
	repoStateRef := binaryRef(0x10)
	authPolicyRef := binaryRef(0x20)
	manifestRef := binaryRef(0x30)
	manifestBody := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":20,"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000001"},"layers":[]}`)
	manifestDigest := publish.ComputeDigest(manifestBody)

	repoStateDoc := fmt.Sprintf(`{
		"version":1,
		"repo":"backend/api",
		"generation":5,
		"tags":{"latest":%q},
		"manifests":{%q:{"swarmRef":%q,"mediaType":"application/vnd.oci.image.manifest.v1+json","size":%d}},
		"blobs":{}
	}`, manifestDigest, manifestDigest, manifestRef, len(manifestBody))
	f.payloads[repoStateRef] = []byte(repoStateDoc)
	f.payloads[authPolicyRef] = []byte(`{
		"version":1,
		"defaultAccess":"deny",
		"repos":{"backend/api":{"pull":["anonymous","user:alice"],"push":["user:alice"]}}
	}`)
	f.payloads[manifestRef] = manifestBody

	// Feed payloads: the raw 32 binary reference bytes (never JSON).
	repoTopic := strings.TrimPrefix(spec.RepoStateFeedRef("0x"+beeWiringOwner, "backend/api"), "feed://")
	authTopic := strings.TrimPrefix(spec.AuthPolicyFeedRef("0x"+beeWiringOwner), "feed://")
	f.feeds["/feeds/"+repoTopic] = binaryBytes(repoStateRef)
	f.indexes["/feeds/"+repoTopic] = "0000000000000005"
	f.feeds["/feeds/"+authTopic] = binaryBytes(authPolicyRef)
	f.indexes["/feeds/"+authTopic] = "0000000000000003"
	return f
}

func (f *beeReadFixture) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/feeds/"):
			f.mu.Lock()
			payload, ok := f.feeds[r.URL.Path]
			idx := f.indexes[r.URL.Path]
			f.feedHits[r.URL.Path]++
			f.mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Swarm-Feed-Index", idx)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/bzz/"):
			ref := strings.TrimPrefix(r.URL.Path, "/bzz/")
			f.mu.Lock()
			payload, ok := f.payloads[ref]
			f.bzzHits[ref]++
			f.mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/bytes/"):
			ref := strings.TrimPrefix(r.URL.Path, "/bytes/")
			f.mu.Lock()
			payload, ok := f.payloads[ref]
			f.bytesHits[ref]++
			f.mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	})
}

func (f *beeReadFixture) counts() (feeds map[string]int, bzz map[string]int, bytes map[string]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	feeds = map[string]int{}
	for k, v := range f.feedHits {
		feeds[k] = v
	}
	bzz = map[string]int{}
	for k, v := range f.bzzHits {
		bzz[k] = v
	}
	bytes = map[string]int{}
	for k, v := range f.bytesHits {
		bytes[k] = v
	}
	return
}

// buildWiredBeeHandler assembles a production Bee-mode handler with the given
// fake Bee and returns it plus the fixture and the token issuer key.
func buildWiredBeeHandler(t *testing.T, fixture *beeReadFixture) (*registry.Handler, *beeReadFixture, *auth.RegistryTokenIssuer) {
	t.Helper()
	server := httptest.NewServer(fixture.handler())
	t.Cleanup(server.Close)

	key := newConfigTestKey(t)
	t.Setenv("REGISTRY_BACKEND", "bee")
	t.Setenv("BEE_API_URL", server.URL)
	t.Setenv("REGISTRY_OWNER_MAP", beeWiringHost+"=0x"+beeWiringOwner)
	t.Setenv("REGISTRY_ID_MAP", beeWiringHost+"=7")
	t.Setenv("CONTROLPLANE_URL", "http://127.0.0.1:1")
	t.Setenv("CONTROLPLANE_INTERNAL_SECRET_FILE", writeSecretFile(t))
	// The resolver audience MUST equal the served host for request clipping.
	t.Setenv("REGISTRY_TOKEN_PUBLIC_KEYS_FILE", writeConfigJWKS(t, key))
	t.Setenv("REGISTRY_TOKEN_ISSUER", configIssuer)
	t.Setenv("REGISTRY_TOKEN_AUDIENCE", beeWiringHost)
	setupRegistryStagingEnv(t)

	h, err := buildBeeHandler()
	if err != nil {
		t.Fatalf("build wired bee handler: %v", err)
	}
	// Release the durable staging service (spool + SQLite) when the test ends
	// so the handle is not leaked across tests in this process.
	hr, ok := h.(*registry.Handler)
	if !ok {
		t.Fatalf("unexpected handler type %T", h)
	}
	t.Cleanup(func() { _ = hr.Close() })
	issuer, err := auth.NewRegistryTokenIssuer(key.priv, configIssuer, configKeyID)
	if err != nil {
		t.Fatalf("test token issuer: %v", err)
	}
	return hr, fixture, issuer
}

// TestBeeHandlerProductionReadLayering proves the production Bee read path:
// RegistryResolver.Feeds is the BeeFeedResolver (binary payload → canonical
// immutable 64-hex ref), the BeeDocumentStore is used ONLY for immutable
// /bzz document reads, IdentityFeedResolver is NEVER used, and the feed binary
// bytes are never decoded as JSON.
func TestBeeHandlerProductionReadLayering(t *testing.T) {
	// No t.Parallel: buildWiredBeeHandler mutates the environment (t.Setenv).
	hr, fixture, issuer := buildWiredBeeHandler(t, newBeeReadFixture(t))

	// The wiring itself: Feeds must be the Bee resolver (binary feed payloads),
	// Docs the Bee document store, Objects the Bee object store.
	if _, ok := hr.Resolver.Feeds.(*swarm.BeeFeedResolver); !ok {
		t.Fatalf("Bee mode must wire the BeeFeedResolver as RegistryResolver.Feeds, got %T", hr.Resolver.Feeds)
	}
	if _, ok := hr.Resolver.Docs.(*swarm.BeeDocumentStore); !ok {
		t.Fatalf("Bee mode must wire the BeeDocumentStore for immutable document reads, got %T", hr.Resolver.Docs)
	}
	if _, ok := hr.Objects.(*swarm.BeeObjectStore); !ok {
		t.Fatalf("Bee mode must wire the BeeObjectStore as the object store, got %T", hr.Objects)
	}

	ctx := context.Background()
	identity := resolve.RegistryIdentity{Host: beeWiringHost, Owner: "0x" + beeWiringOwner, RegistryID: 7}

	// Direct resolver read: repo feed → binary → hex ref → /bzz document.
	doc, err := hr.Resolver.ResolveRepoState(ctx, identity, "backend/api")
	if err != nil {
		t.Fatalf("ResolveRepoState: %v", err)
	}
	if doc.Generation != 5 || doc.Repo != "backend/api" {
		t.Fatalf("unexpected resolved repo state: %+v", doc)
	}
	repoTopicPath := "/feeds/" + strings.TrimPrefix(spec.RepoStateFeedRef("0x"+beeWiringOwner, "backend/api"), "feed://")
	feeds, bzz, _ := fixture.counts()
	if feeds[repoTopicPath] != 1 {
		t.Fatalf("repo feed must be read exactly once via /feeds, got %d", feeds[repoTopicPath])
	}
	if len(bzz) != 1 || bzz[binaryRef(0x10)] != 1 {
		t.Fatalf("the resolved document must come from exactly one /bzz read of the decoded hex ref, got %v", bzz)
	}
	// The feed body bytes are NOT JSON-valid; a JSON decode would have failed.
	if json.Valid(fixture.feeds[repoTopicPath]) {
		t.Fatal("fixture feed payload must be JSON-invalid to prove binary decode")
	}

	// HTTP pull: auth policy via feeds, repo state via feeds, manifest object
	// via /bytes; then assert the full layering accounting.
	raw, err := issuer.Issue(ctx, auth.RegistryTokenRequest{
		Subject:    "user:alice",
		Service:    beeWiringHost,
		Repository: "backend/api",
		Actions:    []auth.Action{auth.ActionPull},
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	server := httptest.NewServer(hr)
	defer server.Close()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create pull request: %v", err)
	}
	req.Host = beeWiringHost
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pull request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read pull body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("manifest pull must be 200, got %d: %s", resp.StatusCode, body)
	}
	authTopicPath := "/feeds/" + strings.TrimPrefix(spec.AuthPolicyFeedRef("0x"+beeWiringOwner), "feed://")
	feeds, bzz, bytes := fixture.counts()
	if feeds[repoTopicPath] != 2 || feeds[authTopicPath] != 1 {
		t.Fatalf("read layering violated: repo path hits=%d (want 2: resolve+pull), auth policy hits=%d (want 1)", feeds[repoTopicPath], feeds[authTopicPath])
	}
	if bzz[binaryRef(0x10)] != 2 || bzz[binaryRef(0x20)] != 1 {
		t.Fatalf("/bzz reads must be exactly the state+policy documents, got %v", bzz)
	}
	if bytes[binaryRef(0x30)] != 1 {
		t.Fatalf("the manifest object must come from /bytes, got %v", bytes)
	}
}

// TestBeeHandlerOptionalResolutionDistinguishesAbsenceFromCorruption proves the
// unresolved-state semantics in Bee production mode: a missing feed (404) is
// OPTIONAL ABSENT, while a resolvable feed whose target /bzz document is
// missing is CORRUPTION — an error, never absence.
func TestBeeHandlerOptionalResolutionDistinguishesAbsenceFromCorruption(t *testing.T) {
	// No t.Parallel: the fixtures mutate the environment (t.Setenv).

	ctx := context.Background()
	identity := resolve.RegistryIdentity{Host: beeWiringHost, Owner: "0x" + beeWiringOwner, RegistryID: 7}

	t.Run("missing feed is optional absent", func(t *testing.T) {
		fixture := newBeeReadFixture(t)
		delete(fixture.feeds, "/feeds/"+strings.TrimPrefix(spec.RepoStateFeedRef("0x"+beeWiringOwner, "backend/api"), "feed://"))
		hr, _, _ := buildWiredBeeHandler(t, fixture)
		doc, found, err := hr.Resolver.ResolveRepoStateOptional(ctx, identity, "backend/api")
		if err != nil {
			t.Fatalf("missing feed must resolve as optional absent, got error: %v", err)
		}
		if found {
			t.Fatal("missing feed must NOT be found")
		}
		if doc.Generation != 0 || doc.Repo != "" {
			t.Fatalf("absent resolution must leave a zero document, got %+v", doc)
		}
	})

	t.Run("missing target document is corruption, not absent", func(t *testing.T) {
		fixture := newBeeReadFixture(t)
		// Feed resolves to a hex ref that has NO /bzz document behind it.
		corruptRef := binaryRef(0x40)
		repoTopicPath := "/feeds/" + strings.TrimPrefix(spec.RepoStateFeedRef("0x"+beeWiringOwner, "backend/api"), "feed://")
		fixture.feeds[repoTopicPath] = binaryBytes(corruptRef)
		fixture.indexes[repoTopicPath] = "0000000000000005"
		hr, _, _ := buildWiredBeeHandler(t, fixture)

		doc, found, err := hr.Resolver.ResolveRepoStateOptional(ctx, identity, "backend/api")
		if err == nil {
			t.Fatal("feed resolving to a missing /bzz document must be a corruption ERROR, never absence")
		}
		if found {
			t.Fatal("corruption must not report found")
		}
		if errors.Is(err, resolve.ErrFeedNotFound) {
			t.Fatalf("corruption must NOT be classified as a missing feed (it is an error, not absence): %v", err)
		}
		if strings.Contains(err.Error(), "resolve repo state feed") {
			t.Fatalf("corruption must fail at the DOCUMENT read, not the feed resolution: %v", err)
		}
		_ = doc
	})
}

// TestBeeHandlerRejectsMalformedBeeURL proves the BEE_API_URL config validation
// fails closed BEFORE any listener/client is built: malformed schemes, missing
// hosts, and non-origin forms (path, query, userinfo) are rejected.
func TestBeeHandlerRejectsMalformedBeeURL(t *testing.T) {
	// No t.Parallel: the sub-tests mutate the environment with t.Setenv.
	for _, tc := range []struct {
		name    string
		url     string
		wantErr string
	}{
		{name: "empty", url: "", wantErr: "BEE_API_URL is required"},
		{name: "relative", url: "bee:1234", wantErr: "BEE_API_URL"},
		{name: "no host", url: "http://", wantErr: "BEE_API_URL"},
		{name: "wrong scheme", url: "ftp://bee.invalid", wantErr: "BEE_API_URL"},
		{name: "path", url: "http://bee.invalid/v1", wantErr: "BEE_API_URL"},
		{name: "query", url: "http://bee.invalid?x=1", wantErr: "BEE_API_URL"},
		{name: "userinfo", url: "http://user@bee.invalid", wantErr: "BEE_API_URL"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REGISTRY_BACKEND", "bee")
			t.Setenv("BEE_API_URL", tc.url)
			t.Setenv("REGISTRY_OWNER_MAP", beeWiringHost+"=0x"+beeWiringOwner)
			t.Setenv("REGISTRY_ID_MAP", beeWiringHost+"=7")
			t.Setenv("REGISTRY_TOKEN_PUBLIC_KEYS_FILE", writeConfigJWKS(t, newConfigTestKey(t)))
			t.Setenv("REGISTRY_TOKEN_ISSUER", configIssuer)
			t.Setenv("REGISTRY_TOKEN_AUDIENCE", beeWiringHost)
			t.Setenv("CONTROLPLANE_URL", "http://127.0.0.1:1")
			t.Setenv("CONTROLPLANE_INTERNAL_SECRET_FILE", writeSecretFile(t))
			if _, err := buildBeeHandler(); err == nil {
				t.Fatalf("BEE_API_URL %q must fail closed", tc.url)
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q must mention %q", err, tc.wantErr)
			}
		})
	}
}
