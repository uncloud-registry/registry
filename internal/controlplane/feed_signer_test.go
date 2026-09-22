package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// refHex returns a 64-hex reference composed of a single hex character.
func refHex(c byte) string {
	return strings.Repeat(string(c), 64)
}

// testRepo is the repository name used by every feed-signer fixture document.
const testRepo = "repo1"

// feedTestWorld assembles a FeedSigner against in-memory stores, seeding a
// ready registry, a current repo feed, the repos' immutable documents, and the
// stamp policy feed. FeedSigner.Commit mutates feedStore.Feeds[repoTopic] on a
// successful signed update so tests can assert whether the feed advanced.
type feedTestWorld struct {
	signer    *FeedSigner
	store     *Store
	feedStore *MemoryRegistryFeedStore
	docs      *resolve.MemoryDocumentStore
	registry  Registry
	repoTopic string
	stampFeed string
	// batchAllowed is the default stamp-policy batch.
	batchAllowed string
}

type feedDocSet struct {
	currentRef string
	currentGen int64
	targetRef  string
	targetGen  int64
	stampRef   string
}

// newFeedTestWorld builds the fixture and a FeedSigner. req sets the request;
// the world's registry owner and repo topic are derived from it so callers can
// modify the request before asserting a decided outcome.
func newFeedTestWorld(t *testing.T, req publish.FeedCommitRequest, dst feedDocSet) *feedTestWorld {
	t.Helper()
	ctx := context.Background()
	store := newProvisioningStore(t)
	owner := seedProvisioningOwner(t, store)

	feedOwner := "0xabcDEF1234"
	newReg, err := store.CreateProvisionedRegistry(ctx, Registry{
		Slug: "feedsigreg", Host: "feedsigreg.test", ENSName: "",
		OwnerUserID: owner.ID, FeedOwnerAddress: feedOwner, DefaultStampBatchID: dst.stampRef,
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create provisioned registry: %v", err)
	}
	if err := store.MarkRegistryReady(ctx, newReg.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}

	repoTopic := spec.RepoStateFeedRef(feedOwner, testRepo)
	stampFeed := spec.StampPolicyFeedRef(feedOwner)

	feedStore := &MemoryRegistryFeedStore{Feeds: map[string]string{
		repoTopic: dst.currentRef,
		stampFeed: dst.stampRef,
	}}
	docs := resolve.NewMemoryDocumentStore()
	docs.Documents = map[string][]byte{
		dst.currentRef: mustRepoDoc(t, testRepo, dst.currentGen),
		dst.targetRef:  mustRepoDoc(t, testRepo, dst.targetGen),
		dst.stampRef:   mustStampDoc(t, req.BatchID),
	}

	signer := &FeedSigner{Store: store, Feeds: feedStore, ResolveFeeds: feedStore, Docs: docs}
	return &feedTestWorld{
		signer: signer, store: store, feedStore: feedStore, docs: docs,
		registry: newReg, repoTopic: repoTopic, stampFeed: stampFeed, batchAllowed: req.BatchID,
	}
}

func mustRepoDoc(t *testing.T, repo string, gen int64) []byte {
	t.Helper()
	doc := spec.RepoStateDocument{
		Version:    1,
		Repo:       repo,
		Generation: gen,
		Tags:       map[string]string{},
		Manifests:  map[string]spec.ManifestDescriptor{},
		Blobs:      map[string]spec.BlobDescriptor{},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal repo doc: %v", err)
	}
	return data
}

func mustStampDoc(t *testing.T, batch string) []byte {
	t.Helper()
	doc := spec.StampPolicyDocument{
		Version: 1,
		DefaultPolicy: spec.StampAccessPolicy{
			BatchID:      batch,
			AllowPushFor: []string{"role:write"},
		},
		Repos: map[string]spec.StampAccessPolicy{},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal stamp doc: %v", err)
	}
	return data
}

func validCommitReq(registryID int64, batch string) publish.FeedCommitRequest {
	return publish.FeedCommitRequest{
		OperationID:        "op-1",
		RegistryID:         registryID,
		Owner:              "0xabcDEF1234",
		Topic:              "",
		Reference:          refHex('a'),
		BatchID:            batch,
		ExpectedGeneration: 0,
	}
}

// fillTopic sets the request Topic to the world's deterministic repo feed ref.
func (w *feedTestWorld) fillTopic(req *publish.FeedCommitRequest) {
	req.Topic = w.repoTopic
	// Ensure the target document generation matches expected+1.
	req.ExpectedGeneration = 0
}

func TestFeedSignerValidCommit(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0,
		targetRef: refHex('a'), targetGen: 1,
		stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 0
	target := refHex('a')

	result, err := w.signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if result.Feed != req.Topic || result.Reference != target || result.OperationID != req.OperationID {
		t.Fatalf("unexpected result: %+v", result)
	}
	// The feed was advanced to the target.
	if got := w.feedStore.Feeds[w.repoTopic]; got != target {
		t.Fatalf("repo feed not advanced: got %q want %q", got, target)
	}
}

func TestFeedSignerUnknownRegistry(t *testing.T) {
	req := validCommitReq(923131, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	w.fillTopic(&req)
	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerRegistryNotFound) {
		t.Fatalf("expected registry not found, got %v", err)
	}
}

func TestFeedSignerRegistryNotReady(t *testing.T) {
	ctx := context.Background()
	// Fresh provisioning registry that is deliberately NOT marked ready.
	store := newProvisioningStore(t)
	owner := seedProvisioningOwner(t, store)
	provisioning, err := store.CreateProvisionedRegistry(ctx, Registry{
		Slug: "notready", Host: "notready.test", ENSName: "",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xabcDEF1234", DefaultStampBatchID: "batch-1",
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create provisioned registry: %v", err)
	}
	repoTopic := spec.RepoStateFeedRef("0xabcDEF1234", testRepo)
	stampFeed := spec.StampPolicyFeedRef("0xabcDEF1234")
	feedStore := &MemoryRegistryFeedStore{Feeds: map[string]string{
		repoTopic: refHex('b'),
		stampFeed: refHex('c'),
	}}
	docs := resolve.NewMemoryDocumentStore()
	docs.Documents = map[string][]byte{
		refHex('b'): mustRepoDoc(t, testRepo, 0),
		refHex('a'): mustRepoDoc(t, testRepo, 1),
		refHex('c'): mustStampDoc(t, "batch-1"),
	}
	signer := &FeedSigner{Store: store, Feeds: feedStore, ResolveFeeds: feedStore, Docs: docs}

	req := validCommitReq(provisioning.ID, "batch-1")
	req.Topic = repoTopic
	req.Reference = refHex('a')
	req.ExpectedGeneration = 0

	_, err = signer.Commit(ctx, req)
	if !errors.Is(err, errFeedSignerNotReady) {
		t.Fatalf("expected not ready, got %v", err)
	}
	if got := feedStore.Feeds[repoTopic]; got != refHex('b') {
		t.Fatalf("feed advanced despite registry not ready: %q", got)
	}
}

func TestFeedSignerOwnerMismatchBeforeKeyOrNetwork(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	req.Owner = "0xffffffffffffffffffffffffffffffffffffffff" // different owner
	w.fillTopic(&req)
	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerRegistryNotFound) {
		t.Fatalf("expected owner-mismatch rejection, got %v", err)
	}
	// The feed must NOT have been advanced: the owner check runs before the key
	// is touched or any network update.
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed advanced despite owner mismatch: %q", got)
	}
}

func TestFeedSignerNonDeterministicTopic(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	req.Topic = "feed://" + strings.Repeat("0", 40) + "/deadbeef" // arbitrary, non-deterministic
	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("expected malformed topic rejection, got %v", err)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed advanced despite wrong topic: %q", got)
	}
}

func TestFeedSignerAuthPolicyTopicRejected(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	req.Topic = spec.AuthPolicyFeedRef(w.registry.FeedOwnerAddress)
	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("expected auth-policy topic rejection, got %v", err)
	}
}

func TestFeedSignerTargetGenerationMismatch(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 3, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerGenerationConflict) {
		t.Fatalf("expected generation conflict on target mismatch, got %v", err)
	}
}

func TestFeedSignerCurrentGenerationMismatch(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 5, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerGenerationConflict) {
		t.Fatalf("expected generation conflict on current mismatch, got %v", err)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed advanced despite current-gen mismatch: %q", got)
	}
}

func TestFeedSignerOverflowGenerationRejected(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	req.ExpectedGeneration = math.MaxInt64
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	req.Topic = w.repoTopic // deliberately NOT calling fillTopic (it would reset the generation)
	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerGenerationConflict) {
		t.Fatalf("expected generation conflict on overflow, got %v", err)
	}
}

func TestFeedSignerDisallowedBatch(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	req.BatchID = "not-the-policy-batch"
	w.fillTopic(&req)
	req.BatchID = "not-the-policy-batch"
	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("expected batch rejection, got %v", err)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed advanced despite disallowed batch: %q", got)
	}
}

func TestFeedSignerStampRepoOverrideBatch(t *testing.T) {
	req := validCommitReq(1, "overridden-batch")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	// The default policy batch is "batch-1"; add a repo override that permits
	// "overridden-batch" for the target repo.
	override := spec.StampPolicyDocument{
		Version:       1,
		DefaultPolicy: spec.StampAccessPolicy{BatchID: "batch-1", AllowPushFor: []string{"role:write"}},
		Repos: map[string]spec.StampAccessPolicy{
			"repo1": {BatchID: "overridden-batch", AllowPushFor: []string{"role:write"}},
		},
	}
	data, _ := json.Marshal(override)
	w.docs.Documents[refHex('c')] = data
	req.RegistryID = w.registry.ID
	req.BatchID = "overridden-batch"
	w.fillTopic(&req)
	req.BatchID = "overridden-batch"
	if _, err := w.signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("commit with repo override batch: %v", err)
	}
}

func TestFeedSignerIdempotentIdenticalRequest(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	if _, err := w.signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	first := w.feedStore.Feeds[w.repoTopic]

	// Identical retry returns the stored result WITHOUT a second advancement.
	result, err := w.signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if result.Reference != req.Reference || result.OperationID != req.OperationID {
		t.Fatalf("unexpected idempotent result: %+v", result)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != first {
		t.Fatalf("feed advanced twice on identical idempotent retry: %q -> %q", first, got)
	}
}

func TestFeedSignerOperationConflict(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.OperationID = "shared-op"
	if _, err := w.signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	// Reuse the same operation ID with DIFFERENT input (different batch).
	req.BatchID = "different-batch"
	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("expected operation conflict, got %v", err)
	}
}

func TestFeedSignerInvalidReferenceSyntax(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	req.Reference = "not-a-64-hex-ref"
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("expected malformed reference, got %v", err)
	}
}

func TestFeedSignerNonPositiveRegistryIDRejected(t *testing.T) {
	req := validCommitReq(0, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	w.fillTopic(&req)
	if _, err := w.signer.Commit(context.Background(), req); !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("expected malformed for non-positive registryID, got %v", err)
	}
}

func TestFeedSignerTypedNilDependenciesFailClosed(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	var nilUpdater *MemoryRegistryFeedStore // typed nil
	signer := &FeedSigner{Store: w.store, Feeds: nilUpdater, ResolveFeeds: w.feedStore, Docs: w.docs}
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("expected backend failure for typed-nil updater, got %v", err)
	}
}

// TestFeedSignerUncertainResponseRecovery simulates a crash after the network
// feed update succeeded but before the result was persisted: a pending
// operation row exists and the feed already points at the target. Commit must
// recover by validating the target and persisting the result WITHOUT advancing
// the feed a second time.
func TestFeedSignerUncertainResponseRecovery(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('a'), currentGen: 1, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	// The current feed already resolves to the exact target reference.
	w.feedStore.Feeds[w.repoTopic] = refHex('a')

	// Pre-reserve a pending operation the way a crashed first attempt left it.
	hash := NormalizeFeedCommitHash(req)
	if _, _, err := w.store.ReserveFeedSignerOperation(context.Background(), req.OperationID, hash); err != nil {
		t.Fatalf("pre-reserve: %v", err)
	}

	result, err := w.signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if result.OperationID != req.OperationID || result.Reference != req.Reference {
		t.Fatalf("unexpected recovery result: %+v", result)
	}
	// The feed must NOT have been advanced a second time.
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('a') {
		t.Fatalf("feed advanced during recovery: %q", got)
	}
	// The operation must now be terminal succeeded.
	op, err := w.store.GetFeedSignerOperation(context.Background(), req.OperationID)
	if err != nil {
		t.Fatalf("get op: %v", err)
	}
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("expected op recovered to succeeded, got %q", op.State)
	}
}

// TestFeedSignerPersistsAcrossDBRestart proves durable idempotency survives a
// process/Database restart: a succeeded operation loaded from a reopened
// file-backed database returns the stored result without touching the feed.
func TestFeedSignerPersistsAcrossDBRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controlplane-test.db")
	open := func() *Store {
		store, err := OpenSQLite(dbPath)
		if err != nil {
			t.Fatalf("open file store: %v", err)
		}
		return store
	}
	store := open()
	asd, err := store.CreateUser(context.Background(), "persist@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	newReg, err := store.CreateProvisionedRegistry(context.Background(), Registry{
		Slug: "persist", Host: "persist.test", ENSName: "",
		OwnerUserID: asd.ID, FeedOwnerAddress: "0xpersist", DefaultStampBatchID: "batch-1",
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	if err := store.MarkRegistryReady(context.Background(), newReg.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}

	repoTopic := spec.RepoStateFeedRef("0xpersist", testRepo)
	stampFeed := spec.StampPolicyFeedRef("0xpersist")
	feedStore := &MemoryRegistryFeedStore{Feeds: map[string]string{repoTopic: refHex('b'), stampFeed: refHex('c')}}
	docs := resolve.NewMemoryDocumentStore()
	docs.Documents = map[string][]byte{
		refHex('b'): mustRepoDoc(t, testRepo, 0),
		refHex('a'): mustRepoDoc(t, testRepo, 1),
		refHex('c'): mustStampDoc(t, "batch-1"),
	}
	signer := &FeedSigner{Store: store, Feeds: feedStore, ResolveFeeds: feedStore, Docs: docs}

	req := validCommitReq(newReg.ID, "batch-1")
	req.Owner = "0xpersist"
	req.Topic = repoTopic
	if _, err := signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	_ = store.DB.Close()

	// Reopen and commit the identical request through a fresh signer: the
	// stored succeeded result is returned without advancing the feed.
	store2 := open()
	docs2 := resolve.NewMemoryDocumentStore()
	docs2.Documents = docs.Documents
	signer2 := &FeedSigner{Store: store2, Feeds: feedStore, ResolveFeeds: feedStore, Docs: docs2}
	result, err := signer2.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("reopen commit: %v", err)
	}
	if result.OperationID != req.OperationID || result.Reference != req.Reference {
		t.Fatalf("unexpected persisted result: %+v", result)
	}
	if got := feedStore.Feeds[repoTopic]; got != refHex('a') {
		t.Fatalf("feed advanced on reopen idempotent retry: %q", got)
	}
	_ = store2.DB.Close()
}

// TestFeedSignerConcurrentIdenticalRequests proves concurrent identical requests
// cause exactly one logical commit: all callers succeed, and regardless of
// interleaving the feed is advanced exactly once to the target.
func TestFeedSignerConcurrentIdenticalRequests(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	results := make([]publish.FeedCommitResult, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = w.signer.Commit(context.Background(), req)
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if results[i].OperationID != req.OperationID || results[i].Reference != req.Reference {
			t.Fatalf("goroutine %d unexpected result: %+v", i, results[i])
		}
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != req.Reference {
		t.Fatalf("expected feed advanced once to target, got %q", got)
	}
	op, err := w.store.GetFeedSignerOperation(context.Background(), req.OperationID)
	if err != nil || op.State != FeedSignerOpSucceeded {
		t.Fatalf("operation must be terminal succeeded (err=%v state=%q)", err, op.State)
	}
}

// TestFeedSignerDifferentOperationIDsSameTarget advances the feed once, then a
// SECOND distinct operation (different content → different target reference)
// that expects the PRE-advance generation on the same feed is rejected: the
// durable generation guard prevents a stale commit.
func TestFeedSignerDifferentOperationIDsSameTarget(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	if _, err := w.signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("first commit: %v", err)
	}

	// A second operation with different content publishes a different target
	// reference on the same feed at the now-stale expected generation 0. The
	// current generation is already 1, so it must conflict.
	staleRef := refHex('d')
	w.docs.Documents[staleRef] = mustRepoDoc(t, testRepo, 1) // target would be gen 1
	stale := req
	stale.OperationID = "op-stale"
	stale.Reference = staleRef
	stale.ExpectedGeneration = 0
	_, err := w.signer.Commit(context.Background(), stale)
	if !errors.Is(err, errFeedSignerGenerationConflict) {
		t.Fatalf("expected stale-generation conflict, got %v", err)
	}
}
