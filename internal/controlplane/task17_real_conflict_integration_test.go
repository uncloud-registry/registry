package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/policy"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/registry"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/staging"
	"github.com/uncloud-registry/registry/internal/swarm"
)

// --- shared plumbing bridging the registry data plane to a REAL FeedSigner ---

// realIntegrationFeedUpdater adapts the shared resolve.MemoryFeedStore (the
// registry data plane's own feed truth) into controlplane.RegistryFeedUpdater
// so the REAL FeedSigner signs updates into the EXACT SAME feed map the
// registry handlers resolve against — never a separate/parallel feed store.
type realIntegrationFeedUpdater struct {
	feeds *resolve.MemoryFeedStore
}

func (u realIntegrationFeedUpdater) UpdateRegistryFeed(ctx context.Context, _ Registry, feed string, ref string, _ string, createOnly bool) error {
	if createOnly {
		if _, err := u.feeds.ResolveFeed(ctx, feed); err == nil {
			return fmt.Errorf("create-only feed update: %w", swarm.ErrFeedAlreadyExists)
		}
	}
	return u.feeds.UpdateFeed(ctx, feed, ref)
}

// realIntegrationDocs is a thread-safe content-addressed immutable object
// store whose Put returns a BARE lowercase-64-hex SHA-256 digest — the exact
// wire-reference shape production Bee/Swarm content addresses use, and the
// shape publish.IsHexReference strictly requires of every FeedCommitRequest
// Reference. resolve.MemoryDocumentStore (used elsewhere in this package)
// instead prefixes its references with "mem-ref-" for test readability; every
// OTHER test double in this package that wraps it feeds a SCRIPTED committer
// that never validates reference shape, but this file routes through the
// REAL ControlPlaneCommitter, which fails the strict shape check on that
// prefix before ever issuing the HTTP request. This store fills both the
// registry data plane's object store and the control plane's document/bytes
// readers, so both sides prove the SAME reference against the SAME bytes.
type realIntegrationDocs struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newRealIntegrationDocs() *realIntegrationDocs {
	return &realIntegrationDocs{data: map[string][]byte{}}
}

// seed installs a fixed, non-content-addressed reference (used for the
// auth/stamp policy documents this world wires by hand). Policy document
// references are never passed through the strict FeedCommitRequest hex
// contract, so an arbitrary key is fine here.
func (d *realIntegrationDocs) seed(ref string, data []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data[ref] = data
}

func (d *realIntegrationDocs) Read(_ context.Context, ref string) ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	data, ok := d.data[ref]
	if !ok {
		return nil, fmt.Errorf("document %q not found: %w", ref, resolve.ErrDocumentNotFound)
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func (d *realIntegrationDocs) Get(ctx context.Context, ref string) ([]byte, error) {
	return d.Read(ctx, ref)
}

func (d *realIntegrationDocs) Put(_ context.Context, data []byte, _ string) (string, error) {
	sum := sha256.Sum256(data)
	ref := hex.EncodeToString(sum[:])
	out := make([]byte, len(data))
	copy(out, data)
	d.mu.Lock()
	d.data[ref] = out
	d.mu.Unlock()
	return ref, nil
}

func (d *realIntegrationDocs) PutStream(ctx context.Context, src io.Reader, size int64, batchID string) (string, error) {
	if size < 0 {
		return "", fmt.Errorf("streamed put requires a non-negative size")
	}
	if src == nil {
		return "", fmt.Errorf("streamed put requires a source reader")
	}
	data, err := io.ReadAll(io.LimitReader(src, size+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > size {
		return "", fmt.Errorf("streamed put payload exceeds the declared size")
	}
	return d.Put(ctx, data, batchID)
}

// ReadBounded implements swarm.BoundedBytesReader so the REAL FeedSigner
// independently proves the operated manifest body from the EXACT SAME
// immutable object store the registry data plane uploads into.
func (d *realIntegrationDocs) ReadBounded(ctx context.Context, ref string, maxBytes int64) ([]byte, error) {
	data, err := d.Read(ctx, ref)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("object at %q exceeds the bounded read limit", ref)
	}
	return data, nil
}

// gatingTransport delays the FIRST outgoing HTTP request whose path matches
// path until the test releases gate, then forwards every request (including
// the gated one) to inner unchanged. It is how this test forces ONE
// registry handler's feed-commit attempt to be held at the WIRE boundary —
// BEFORE it ever reaches the control plane's claim/processing machinery —
// while an independent handler's request is free to run the full real
// FeedSigner path to completion and advance the authoritative generation.
// Gating inside the signer itself would hold the (registry,topic) processing
// claim the whole time and spuriously bounce the other handler's request;
// gating the wire request models a genuinely independent, not-yet-dispatched
// commit attempt instead.
//
// The gate is DISARMED until arm() is called: the sequential seed publication
// (which reuses this same client/transport before the racy phase begins)
// must complete uncontended, so gating only takes effect once the test has
// explicitly armed it for the race.
type gatingTransport struct {
	inner     http.RoundTripper
	path      string
	gate      chan struct{}
	armed     atomic.Bool
	blockSeen atomic.Bool
	blocked   chan struct{}
}

func (g *gatingTransport) arm() { g.armed.Store(true) }

func (g *gatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if g.armed.Load() && req.URL.Path == g.path && g.blockSeen.CompareAndSwap(false, true) {
		close(g.blocked)
		<-g.gate
	}
	return g.inner.RoundTrip(req)
}

// staticKeySet is a minimal auth.PublicKeySet over one key id.
type staticKeySet map[string]ed25519.PublicKey

func (s staticKeySet) Key(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	k, ok := s[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown key id %q", keyID)
	}
	return k, nil
}

const (
	integrationServiceHost = "task17-integration.test"
	integrationOwnerHex    = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	integrationRepo        = "backend/api"
	integrationBatchID     = "batch-integration-1"
	integrationKeyID       = "task17-key-1"
)

// realConflictWorld assembles the FULL production composition: a real durable
// controlplane.Store (SQLite), a real controlplane.FeedSigner served over a
// real controlplane.InternalFeedServer HTTP boundary, and TWO independent
// registry.Handler instances (separate RepositoryLockers, separate staging
// pools) — h1 and h2 — that both route their manifest publications through
// publish.ControlPlaneCommitter / publish.ControlPlaneOperationBinder to that
// ONE shared control plane, exactly the cross-process topology the
// authoritative generation comparison exists to police.
type realConflictWorld struct {
	store       *Store
	docs        *realIntegrationDocs
	feeds       *resolve.MemoryFeedStore
	registryRow Registry
	issuer      *auth.RegistryTokenIssuer
	h1, h2      *registry.Handler
	s1, s2      *httptest.Server
	gate        chan struct{}
	blocked     chan struct{}
	commitGate  *gatingTransport
}

// armRace arms the wire-boundary gate on h1's feed-commit transport so its
// FIRST subsequent feed-commit request blocks at the wire until the test
// closes w.gate. Call this only AFTER any sequential (non-racy) setup
// publications through h1 have completed.
func (w *realConflictWorld) armRace() { w.commitGate.arm() }

func newRealConflictWorld(t *testing.T) *realConflictWorld {
	t.Helper()
	store := newFileBackedProvisioningStore(t)
	owner := seedProvisioningOwner(t, store)
	ctx := context.Background()

	reg, err := store.CreateProvisionedRegistry(ctx, Registry{
		Slug: "t17r2", Host: integrationServiceHost, ENSName: "",
		OwnerUserID: owner.ID, FeedOwnerAddress: integrationOwnerHex, DefaultStampBatchID: integrationBatchID,
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create provisioned registry: %v", err)
	}
	if err := store.MarkRegistryReady(ctx, reg.ID); err != nil {
		t.Fatalf("mark registry ready: %v", err)
	}

	docs := newRealIntegrationDocs()
	feeds := resolve.NewMemoryFeedStore()
	authDoc := []byte(`{"version":1,"defaultAccess":"deny","repos":{"` + integrationRepo + `":{"pull":["anonymous","user:alice"],"push":["user:alice"]}}}`)
	stampDoc := []byte(`{"version":1,"defaultPolicy":{"batchID":"` + integrationBatchID + `","allowPushFor":["user:alice"]},"repos":{}}`)
	docs.seed("auth-policy-ref", authDoc)
	docs.seed("stamp-policy-ref", stampDoc)
	feeds.Feeds[spec.AuthPolicyFeedRef(integrationOwnerHex)] = "auth-policy-ref"
	feeds.Feeds[spec.StampPolicyFeedRef(integrationOwnerHex)] = "stamp-policy-ref"

	signer := &FeedSigner{
		Store:        store,
		Feeds:        realIntegrationFeedUpdater{feeds: feeds},
		ResolveFeeds: feeds,
		Docs:         docs,
		Bytes:        docs,
	}
	binder := &PublicationBinder{Store: store}
	internalSecret := []byte("integration-internal-secret-0123456789")
	internalSrv, err := NewInternalFeedServer(signer, binder, internalSecret, nil)
	if err != nil {
		t.Fatalf("new internal feed server: %v", err)
	}
	internalHTTP := httptest.NewServer(internalSrv)
	t.Cleanup(internalHTTP.Close)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tokenIssuer, err := auth.NewRegistryTokenIssuer(priv, auth.RegistryIssuer, integrationKeyID)
	if err != nil {
		t.Fatalf("new registry token issuer: %v", err)
	}
	verifier := auth.NewRegistryTokenVerifier(staticKeySet{integrationKeyID: pub}, auth.RegistryIssuer, integrationServiceHost)

	gate := make(chan struct{})
	blocked := make(chan struct{})
	gatedTransport := &gatingTransport{inner: http.DefaultTransport, path: publish.InternalFeedUpdatePath, gate: gate, blocked: blocked}

	buildHandler := func(commitClient *http.Client) *registry.Handler {
		resolver := resolve.RegistryResolver{
			Registries: resolve.StaticRegistryIdentityResolver{Hosts: map[string]resolve.RegistryIdentity{
				integrationServiceHost: {Host: integrationServiceHost, Owner: integrationOwnerHex, RegistryID: reg.ID},
			}},
			Docs:  docs,
			Feeds: feeds,
		}
		h := registry.NewHandler(
			resolver,
			docs,
			docs,
			policy.PullAuthorizer{Policies: policy.AuthPolicyResolver{Docs: docs, Feeds: feeds}},
			policy.PushAuthorizer{
				AuthPolicies:  policy.AuthPolicyResolver{Docs: docs, Feeds: feeds},
				StampPolicies: policy.StampPolicyResolver{Docs: docs, Feeds: feeds},
			},
			registry.BearerAuthenticator{Tokens: verifier},
			staging.NewMemoryStore(),
			publish.Publisher{
				Builder: publish.DefaultBuilder{},
				Objects: docs,
				Feeds:   feeds,
				Commits: publish.ControlPlaneCommitter{BaseURL: internalHTTP.URL, Secret: internalSecret, HTTPClient: commitClient},
			},
			publish.ControlPlaneOperationBinder{BaseURL: internalHTTP.URL, Secret: internalSecret, HTTPClient: &http.Client{Transport: &gatingTransport{inner: http.DefaultTransport, path: "__never__", gate: make(chan struct{}), blocked: make(chan struct{})}}},
			"https://auth.uncloud-registry.test/token",
		)
		return h.(*registry.Handler)
	}

	h1 := buildHandler(&http.Client{Transport: gatedTransport})
	h2 := buildHandler(internalHTTP.Client())

	s1 := httptest.NewServer(h1)
	s2 := httptest.NewServer(h2)
	t.Cleanup(s1.Close)
	t.Cleanup(s2.Close)

	return &realConflictWorld{
		store: store, docs: docs, feeds: feeds, registryRow: reg, issuer: tokenIssuer,
		h1: h1, h2: h2, s1: s1, s2: s2, gate: gate, blocked: blocked, commitGate: gatedTransport,
	}
}

func (w *realConflictWorld) bearer(t *testing.T) string {
	t.Helper()
	raw, err := w.issuer.Issue(context.Background(), auth.RegistryTokenRequest{
		Subject: "user:alice", Service: integrationServiceHost, Repository: integrationRepo,
		Actions: []auth.Action{auth.ActionPush}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return "Bearer " + raw
}

func (w *realConflictWorld) stageBlob(t *testing.T, serverURL string, body []byte) string {
	t.Helper()
	digest := publish.ComputeDigest(body)
	startReq, _ := http.NewRequest(http.MethodPost, serverURL+"/v2/"+integrationRepo+"/blobs/uploads/", nil)
	startReq.Host = integrationServiceHost
	startReq.Header.Set("Authorization", w.bearer(t))
	startResp, err := http.DefaultClient.Do(startReq)
	if err != nil {
		t.Fatalf("start upload: %v", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(startResp.Body)
		t.Fatalf("start upload status %d: %s", startResp.StatusCode, body)
	}
	uploadURL := serverURL + startResp.Header.Get("Location")

	patchReq, _ := http.NewRequest(http.MethodPatch, uploadURL, bytes.NewReader(body))
	patchReq.Host = integrationServiceHost
	patchReq.Header.Set("Authorization", w.bearer(t))
	patchResp, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("patch upload: %v", err)
	}
	patchResp.Body.Close()
	if patchResp.StatusCode != http.StatusAccepted {
		t.Fatalf("patch upload status %d", patchResp.StatusCode)
	}

	finalizeReq, _ := http.NewRequest(http.MethodPut, uploadURL+"?digest="+digest, nil)
	finalizeReq.Host = integrationServiceHost
	finalizeReq.Header.Set("Authorization", w.bearer(t))
	finalizeReq.Header.Set("Content-Type", "application/vnd.oci.image.config.v1+json")
	finalizeResp, err := http.DefaultClient.Do(finalizeReq)
	if err != nil {
		t.Fatalf("finalize upload: %v", err)
	}
	defer finalizeResp.Body.Close()
	if finalizeResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(finalizeResp.Body)
		t.Fatalf("finalize upload status %d: %s", finalizeResp.StatusCode, body)
	}
	return digest
}

func integrationManifest(configDigest string, configSize int) []byte {
	return []byte(fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":%d,"digest":%q},"layers":[]}`, configSize, configDigest))
}

func (w *realConflictWorld) putManifest(t *testing.T, serverURL, tag string, body []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, serverURL+"/v2/"+integrationRepo+"/manifests/"+tag, bytes.NewReader(body))
	req.Host = integrationServiceHost
	req.Header.Set("Authorization", w.bearer(t))
	req.Header.Set("Content-Type", publish.MediaTypeOCIManifest)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("manifest publish request: %v", err)
	}
	return resp
}

func (w *realConflictWorld) currentRepoState(t *testing.T) spec.RepoStateDocument {
	t.Helper()
	ref, err := w.feeds.ResolveFeed(context.Background(), spec.RepoStateFeedRef(integrationOwnerHex, integrationRepo))
	if err != nil {
		t.Fatalf("resolve repo-state feed: %v", err)
	}
	data, err := w.docs.Read(context.Background(), ref)
	if err != nil {
		t.Fatalf("read repo-state document: %v", err)
	}
	doc, err := spec.DecodeRepoStateDocument(data)
	if err != nil {
		t.Fatalf("decode repo-state document: %v", err)
	}
	return doc
}

func (w *realConflictWorld) feedSignerOperationCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := w.store.DB.QueryRowContext(context.Background(),
		`select count(*) from feed_signer_operations where registry_id = ?`, w.registryRow.ID).Scan(&n); err != nil {
		t.Fatalf("count feed_signer_operations: %v", err)
	}
	return n
}

// TestRealFeedSignerCrossHandlerGenerationConflictSingleRebuild is the
// MANDATORY production-composition acceptance proof for Task 17 round 2: two
// independent registry.Handler instances (separate RepositoryLockers,
// separate staging pools) publish DIFFERENT tags to the SAME repository
// concurrently through the REAL controlplane FeedSigner / durable Store /
// InternalFeedServer HTTP boundary / ControlPlaneCommitter. The FIRST
// handler's feed-commit HTTP request is held at the wire boundary so the
// SECOND handler's publication runs the full authentic path and advances the
// authoritative generation first; releasing the first then forces it to
// discover a genuine 412 generation conflict and perform exactly ONE
// re-resolution + rebuild with a FRESH per-attempt identity, never a fake
// committer.
func TestRealFeedSignerCrossHandlerGenerationConflictSingleRebuild(t *testing.T) {
	w := newRealConflictWorld(t)

	// Seed the repository sequentially (no race) so the racy phase below
	// starts from a known, already-created generation-1 repository.
	seedConfig := []byte(`{"seed":true}`)
	seedConfigDigest := w.stageBlob(t, w.s1.URL, seedConfig)
	seedManifestBytes := integrationManifest(seedConfigDigest, len(seedConfig))
	seedManifestDigest := publish.ComputeDigest(seedManifestBytes)
	seedResp := w.putManifest(t, w.s1.URL, "seed", seedManifestBytes)
	seedBody, _ := io.ReadAll(seedResp.Body)
	seedResp.Body.Close()
	if seedResp.StatusCode != http.StatusCreated {
		t.Fatalf("seed push status %d: %s", seedResp.StatusCode, seedBody)
	}
	if got := w.currentRepoState(t).Generation; got != 1 {
		t.Fatalf("expected generation 1 after seed, got %d", got)
	}
	opsBeforeRace := w.feedSignerOperationCount(t)

	// Arm the wire gate only NOW: the seed publication above reused h1's
	// commit transport uncontended, and only the racy phase below needs its
	// first feed-commit request held at the wire.
	w.armRace()

	configAmd := []byte(`{"architecture":"amd64"}`)
	amdConfigDigest := w.stageBlob(t, w.s1.URL, configAmd)
	manifestAmd := integrationManifest(amdConfigDigest, len(configAmd))
	amdManifestDigest := publish.ComputeDigest(manifestAmd)
	configArm := []byte(`{"architecture":"arm64"}`)
	armConfigDigest := w.stageBlob(t, w.s2.URL, configArm)
	manifestArm := integrationManifest(armConfigDigest, len(configArm))
	armManifestDigest := publish.ComputeDigest(manifestArm)

	type result struct {
		status int
		opID   string
		body   string
	}
	results := make(chan result, 2)

	go func() {
		resp := w.putManifest(t, w.s1.URL, "amd-tag", manifestAmd)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		results <- result{resp.StatusCode, resp.Header.Get(registry.OperationIDHeader), string(body)}
	}()

	select {
	case <-w.blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("h1's feed-commit request never reached the wire gate")
	}

	// h2's publication (a DISTINCT tag) now runs the ENTIRE real FeedSigner
	// path uncontended and must succeed, advancing the feed to generation 2.
	armResp := w.putManifest(t, w.s2.URL, "arm-tag", manifestArm)
	armBody, _ := io.ReadAll(armResp.Body)
	armResp.Body.Close()
	if armResp.StatusCode != http.StatusCreated {
		t.Fatalf("h2 (arm-tag) push status %d: %s", armResp.StatusCode, armBody)
	}
	if got := w.currentRepoState(t).Generation; got != 2 {
		t.Fatalf("expected generation 2 after h2's un-gated push, got %d", got)
	}

	// Release h1's held request: it now discovers the REAL 412 generation
	// conflict against the live control plane and must rebuild exactly once.
	close(w.gate)

	var amdResult result
	select {
	case amdResult = <-results:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for h1's conflict-rebuilt push")
	}
	if amdResult.status != http.StatusCreated {
		t.Fatalf("h1 (amd-tag) conflict-rebuilt push status %d: %s", amdResult.status, amdResult.body)
	}
	if amdResult.opID == "" {
		t.Fatal("h1's rebuilt success must carry its stable operation identity")
	}

	final := w.currentRepoState(t)
	if final.Generation != 3 {
		t.Fatalf("expected generation 3 (seed=1, arm-tag=2, rebuilt amd-tag=3), got %d", final.Generation)
	}
	if final.Tags["arm-tag"] != armManifestDigest {
		t.Fatalf("arm-tag must survive at its digest, got %+v", final.Tags)
	}
	if final.Tags["amd-tag"] != amdManifestDigest {
		t.Fatalf("amd-tag must survive at its (rebuilt) digest, got %+v", final.Tags)
	}
	if final.Tags["seed"] != seedManifestDigest {
		t.Fatalf("unrelated seeded tag must be preserved, got %+v", final.Tags)
	}

	armPub, ok := final.TagPublications["arm-tag"]
	if !ok || armPub.Generation != 2 {
		t.Fatalf("arm-tag provenance must record generation 2: %+v", armPub)
	}
	amdPub, ok := final.TagPublications["amd-tag"]
	if !ok || amdPub.Generation != 3 {
		t.Fatalf("amd-tag provenance must record the REBUILT generation 3: %+v", amdPub)
	}
	if amdResult.opID != amdPub.OperationID {
		t.Fatalf("h1's public operation id %q must equal its STABLE publication id recorded in provenance %q", amdResult.opID, amdPub.OperationID)
	}

	// The amd-tag publication's STABLE identity was computed at the ORIGINAL
	// (pre-conflict) generation 1 — it must have been durably bound before
	// the conflicted attempt, and that SAME binding must still authenticate
	// the rebuilt attempt at generation 2->3 (the recomputed generated-form
	// check no longer matches at the fresh generation, so authentication can
	// only have succeeded through the durable preflight binding surviving the
	// conflict — proof the round-2 fix actually closed the original defect).
	stablePubID := publish.ComputeOperationID(w.registryRow.ID, integrationOwnerHex, integrationRepo, "amd-tag", amdManifestDigest, 1)
	if stablePubID != amdPub.OperationID {
		t.Fatalf("amd-tag's stable publication id must be the generated form at its ORIGINAL generation 1, got %q want %q", amdPub.OperationID, stablePubID)
	}
	binding, err := w.store.GetPublicationBinding(context.Background(), stablePubID)
	if err != nil {
		t.Fatalf("durable publication binding for the stable id must exist: %v", err)
	}
	wantHash := NormalizePublicationBindingHash(w.registryRow.ID, integrationOwnerHex, integrationRepo, "amd-tag", amdManifestDigest)
	if binding.BindingHash != wantHash {
		t.Fatalf("durable publication binding hash mismatch: got %x want %x", binding.BindingHash, wantHash)
	}

	// Exactly THREE new durable feed_signer_operations rows were created
	// during the race: h2's single successful attempt, plus h1's conflicted
	// attempt AND its distinct rebuilt attempt (two DISTINCT per-attempt
	// identities for the SAME stable publication).
	opsAfterRace := w.feedSignerOperationCount(t)
	if delta := opsAfterRace - opsBeforeRace; delta != 3 {
		t.Fatalf("expected exactly 3 new durable feed-signer operation rows (1 for arm-tag + 2 for amd-tag's conflicted+rebuilt attempts), got %d", delta)
	}

	// A lost-response-style retry of the SAME (already-published) amd-tag
	// manifest must be recognized and answered WITHOUT any further feed
	// advancement or a fourth operation row.
	retryResp := w.putManifest(t, w.s1.URL, "amd-tag", manifestAmd)
	retryBody, _ := io.ReadAll(retryResp.Body)
	retryResp.Body.Close()
	if retryResp.StatusCode != http.StatusCreated {
		t.Fatalf("retry of the published amd-tag manifest status %d: %s", retryResp.StatusCode, retryBody)
	}
	if got := w.currentRepoState(t).Generation; got != 3 {
		t.Fatalf("retry must NOT advance the feed again, got generation %d", got)
	}
	if n := w.feedSignerOperationCount(t); n != opsAfterRace {
		t.Fatalf("retry must NOT create a new durable operation row, count changed from %d to %d", opsAfterRace, n)
	}
}
