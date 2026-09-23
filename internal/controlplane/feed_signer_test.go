package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// refHex returns a 64-hex reference composed of a single hex character.
func refHex(c byte) string {
	return strings.Repeat(string(c), 64)
}

// testFeedOwner is a canonical 40-lowercase-hex feed-owner address used by
// the signer/store fixtures, so the deterministic feed references derived from
// it parse as EXACTLY canonical full-feed wire form
// (feed://<40 lowercase hex owner>/<64 lowercase hex topic>) under the strict
// validator.
const testFeedOwner = "abababababababababababababababababababab"

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

	feedOwner := testFeedOwner
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
		Owner:              "0x" + testFeedOwner,
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
		OwnerUserID: owner.ID, FeedOwnerAddress: testFeedOwner, DefaultStampBatchID: "batch-1",
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create provisioned registry: %v", err)
	}
	repoTopic := spec.RepoStateFeedRef(testFeedOwner, testRepo)
	stampFeed := spec.StampPolicyFeedRef(testFeedOwner)
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
	if _, err := w.store.ReserveFeedSignerOperation(context.Background(), req.OperationID, w.registry.ID, w.repoTopic, hash); err != nil {
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
		OwnerUserID: asd.ID, FeedOwnerAddress: testFeedOwner, DefaultStampBatchID: "batch-1",
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	if err := store.MarkRegistryReady(context.Background(), newReg.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}

	repoTopic := spec.RepoStateFeedRef(testFeedOwner, testRepo)
	stampFeed := spec.StampPolicyFeedRef(testFeedOwner)
	feedStore := &MemoryRegistryFeedStore{Feeds: map[string]string{repoTopic: refHex('b'), stampFeed: refHex('c')}}
	docs := resolve.NewMemoryDocumentStore()
	docs.Documents = map[string][]byte{
		refHex('b'): mustRepoDoc(t, testRepo, 0),
		refHex('a'): mustRepoDoc(t, testRepo, 1),
		refHex('c'): mustStampDoc(t, "batch-1"),
	}
	signer := &FeedSigner{Store: store, Feeds: feedStore, ResolveFeeds: feedStore, Docs: docs}

	req := validCommitReq(newReg.ID, "batch-1")
	req.Owner = "0x" + testFeedOwner
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

// TestNormalizeFeedCommitHashCanonicalizesAndSeparates proves the request hash
// normalizes typed fields before hashing (owner case, reference case, topic
// case) and uses length-prefixed/domain-separated framing so no field or NUL
// boundary can collide, and so the OperationID is bound into the hash.
func TestNormalizeFeedCommitHashCanonicalizesAndSeparates(t *testing.T) {
	base := publish.FeedCommitRequest{
		OperationID:        "op-hash",
		RegistryID:         7,
		Owner:              "0xABCdef",
		Topic:              "feed://0xABCdef/" + strings.Repeat("AB", 32),
		Reference:          strings.Repeat("AB", 32),
		BatchID:            "batch",
		ExpectedGeneration: 3,
	}
	hBase := NormalizeFeedCommitHash(base)

	canonical := base
	canonical.Owner = "0xabcdef"
	canonical.Topic = "feed://0xabcdef/" + strings.Repeat("ab", 32)
	canonical.Reference = strings.Repeat("ab", 32)
	if got := NormalizeFeedCommitHash(canonical); got != hBase {
		t.Fatal("expected case-only differences to hash identically (canonicalization)")
	}

	mutations := map[string]func(*publish.FeedCommitRequest){
		"batch":              func(r *publish.FeedCommitRequest) { r.BatchID = "batch2" },
		"batch-with-nul":     func(r *publish.FeedCommitRequest) { r.BatchID = "batch\x00" },
		"reference":          func(r *publish.FeedCommitRequest) { r.Reference = strings.Repeat("cd", 32) },
		"registry":           func(r *publish.FeedCommitRequest) { r.RegistryID = 8 },
		"generation":         func(r *publish.FeedCommitRequest) { r.ExpectedGeneration = 4 },
		"operation-id":       func(r *publish.FeedCommitRequest) { r.OperationID = "op-hash2" },
		"owner":              func(r *publish.FeedCommitRequest) { r.Owner = "0xfeed" },
		"topic":              func(r *publish.FeedCommitRequest) { r.Topic = "feed://0xabcdef/" + strings.Repeat("cd", 32) },
		"reference-nul-tail": func(r *publish.FeedCommitRequest) { r.Reference = strings.Repeat("ab", 32) + "\x00" },
	}
	for name, mutate := range mutations {
		m := base
		mutate(&m)
		if got := NormalizeFeedCommitHash(m); got == hBase {
			t.Fatalf("expected %q mutation to change the request hash", name)
		}
	}
}

// TestDecodeStoredResultStrictUnit drives the stored-result decoder directly
// against duplicate members, unknown fields, trailing content, and
// non-canonical field values.
func TestDecodeStoredResultStrictUnit(t *testing.T) {
	topic := "feed://" + strings.Repeat("ab", 20) + "/" + strings.Repeat("cd", 32)
	ref := strings.Repeat("ab", 32)
	good := `{"operationID":"op-x","feed":"` + topic + `","reference":"` + ref + `"}`
	if _, err := decodeStoredResult([]byte(good)); err != nil {
		t.Fatalf("well-formed stored result rejected: %v", err)
	}
	cases := map[string]string{
		"duplicate-member":    `{"operationID":"op-x","feed":"` + topic + `","reference":"` + ref + `","operationID":"op-x"}`,
		"unknown-field":       `{"operationID":"op-x","feed":"` + topic + `","reference":"` + ref + `","extra":1}`,
		"trailing-content":    good + `{}`,
		"blank":               ``,
		"uppercase-reference": `{"operationID":"op-x","feed":"` + topic + `","reference":"` + strings.ToUpper(ref) + `"}`,
		"noncanonical-feed":   `{"operationID":"op-x","feed":"` + strings.ToUpper(topic) + `","reference":"` + ref + `"}`,
		"short-reference":     `{"operationID":"op-x","feed":"` + topic + `","reference":"abcd"}`,
	}
	for name, data := range cases {
		if _, err := decodeStoredResult([]byte(data)); err == nil {
			t.Fatalf("expected strict stored-result rejection for %s", name)
		}
	}
}

// TestFeedSignerStoredResultStrictDecodeFailClosed proves the signer refuses a
// stored succeeded row whose result JSON violates the strict decoder contract,
// failing closed with a data-free backend error rather than fabricating success.
// Rows that violate the DB-level result-integrity contract can no longer enter
// the database at all (the migration-11 triggers reject them), so this test
// also asserts that direct-SQL write is refused; the remaining case — a result
// that is structurally canonical but semantically mismatched to the request —
// is caught by the strict Go decoder.
func TestFeedSignerStoredResultStrictDecodeFailClosed(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	ctx := context.Background()
	hash := NormalizeFeedCommitHash(req)
	if _, err := w.store.ReserveFeedSignerOperation(ctx, req.OperationID, w.registry.ID, w.repoTopic, hash); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	// These results also violate the DB result-integrity triggers, so the
	// direct-SQL write is itself refused (the strongest protection).
	triggerRejected := map[string]string{
		"duplicate-member": `{"operationID":"` + req.OperationID + `","feed":"` + w.repoTopic + `","reference":"` + refHex('a') + `","operationID":"` + req.OperationID + `"}`,
		"unknown-field":    `{"operationID":"` + req.OperationID + `","feed":"` + w.repoTopic + `","reference":"` + refHex('a') + `","extra":true}`,
		"wrong-feed":       `{"operationID":"` + req.OperationID + `","feed":"feed://other/` + strings.Repeat("ab", 32) + `","reference":"` + refHex('a') + `"}`,
		"uppercase-feed":   `{"operationID":"` + req.OperationID + `","feed":"` + strings.ToUpper(w.repoTopic) + `","reference":"` + refHex('a') + `"}`,
	}
	for name, resultJSON := range triggerRejected {
		if _, err := w.store.DB.ExecContext(ctx, `update feed_signer_operations
			set state='succeeded', result_json=?, claim_token=null, lease_until=null
			where operation_id=?`, resultJSON, req.OperationID); err == nil {
			t.Fatalf("%s: expected DB result-integrity trigger to reject the write, got nil", name)
		}
		// Reset to pending so the next case re-drives the same path.
		if _, err := w.store.DB.ExecContext(ctx, `update feed_signer_operations
			set state='pending', result_json=null where operation_id=?`, req.OperationID); err != nil {
			t.Fatalf("%s: reset row: %v", name, err)
		}
	}

	// Structurally canonical (passes the DB triggers) but semantically wrong for
	// the request: caught by the strict Go decoder, fail closed.
	decoderRejected := `{"operationID":"` + req.OperationID + `","feed":"` + w.repoTopic + `","reference":"` + refHex('d') + `"}`
	if _, err := w.store.DB.ExecContext(ctx, `update feed_signer_operations
		set state='succeeded', result_json=?, claim_token=null, lease_until=null
		where operation_id=?`, decoderRejected, req.OperationID); err != nil {
		t.Fatalf("seed semantically-wrong succeeded row: %v", err)
	}
	_, err := w.signer.Commit(ctx, req)
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("expected fail-closed backend error for semantically-wrong result, got %v", err)
	}
}

// countingFeedUpdater wraps a RegistryFeedUpdater and counts how many times the
// network/key update path is actually exercised, across every signer/Store that
// shares it.
type countingFeedUpdater struct {
	inner RegistryFeedUpdater
	mu    sync.Mutex
	calls int
}

func (c *countingFeedUpdater) UpdateRegistryFeed(ctx context.Context, reg Registry, topic, ref string) error {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.inner.UpdateRegistryFeed(ctx, reg, topic, ref)
}

func (c *countingFeedUpdater) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// sharedFeedWorld opens N independent Stores over one shared on-disk database
// and assembles N signers sharing one counting updater, one feed store, and one
// document store, with a single ready registry.
type sharedFeedWorld struct {
	stores  []*Store
	signers []*FeedSigner
	updater *countingFeedUpdater
	feeds   *MemoryRegistryFeedStore
	docs    *resolve.MemoryDocumentStore
	reg     Registry
	topic   string
}

func newSharedFeedWorld(t *testing.T, n int, feedRefs map[string]string, docs map[string][]byte) *sharedFeedWorld {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "shared-feed.db")
	stores := make([]*Store, n)
	for i := range stores {
		s, err := OpenSQLite(dbPath)
		if err != nil {
			t.Fatalf("open store %d: %v", i, err)
		}
		// Wait out brief write locks across the independent pools instead of
		// surfacing a spurious SQLITE_BUSY as a backend failure.
		if _, err := s.DB.ExecContext(ctx, `pragma busy_timeout = 10000`); err != nil {
			t.Fatalf("busy_timeout: %v", err)
		}
		stores[i] = s
	}
	owner, err := stores[0].CreateUser(ctx, "sharedfeed@example.com", "hash")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	reg, err := stores[0].CreateProvisionedRegistry(ctx, Registry{
		Slug: "sharedfeed", Host: "sharedfeed.test", ENSName: "",
		OwnerUserID: owner.ID, FeedOwnerAddress: testFeedOwner, DefaultStampBatchID: "batch-1",
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	if err := stores[0].MarkRegistryReady(ctx, reg.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	feeds := &MemoryRegistryFeedStore{Feeds: feedRefs}
	docsStore := resolve.NewMemoryDocumentStore()
	docsStore.Documents = docs
	updater := &countingFeedUpdater{inner: feeds}
	signers := make([]*FeedSigner, n)
	for i := range signers {
		signers[i] = &FeedSigner{Store: stores[i], Feeds: updater, ResolveFeeds: feeds, Docs: docsStore}
	}
	return &sharedFeedWorld{
		stores: stores, signers: signers, updater: updater, feeds: feeds, docs: docsStore,
		reg: reg, topic: spec.RepoStateFeedRef(testFeedOwner, testRepo),
	}
}

// TestFeedSignerTwoStoresIdenticalOpOneUpdate uses TWO independent Store
// instances over one database and a counting updater to force an identical
// concurrent interleaving: all callers succeed, but exactly ONE external update
// happens. This is the cross-process/Store safety proof.
func TestFeedSignerTwoStoresIdenticalOpOneUpdate(t *testing.T) {
	w := newSharedFeedWorld(t, 2,
		map[string]string{spec.RepoStateFeedRef(testFeedOwner, testRepo): refHex('b'), spec.StampPolicyFeedRef(testFeedOwner): refHex('c')},
		map[string][]byte{
			refHex('b'): mustRepoDoc(t, testRepo, 0),
			refHex('a'): mustRepoDoc(t, testRepo, 1),
			refHex('c'): mustStampDoc(t, "batch-1"),
		})

	req := validCommitReq(w.reg.ID, "batch-1")
	req.Owner = "0x" + testFeedOwner
	req.Topic = w.topic
	req.ExpectedGeneration = 0

	const n = 2
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			_, errs[i] = w.signers[i].Commit(context.Background(), req)
		}(i)
	}
	start.Done()
	done.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("signer %d commit: %v", i, errs[i])
		}
	}
	if got := w.updater.count(); got != 1 {
		t.Fatalf("expected exactly 1 external feed update across two Stores, got %d", got)
	}
	if got := w.feeds.Feeds[w.topic]; got != refHex('a') {
		t.Fatalf("expected feed advanced once to target, got %q", got)
	}
	op, err := w.stores[0].GetFeedSignerOperation(context.Background(), req.OperationID)
	if err != nil || op.State != FeedSignerOpSucceeded {
		t.Fatalf("operation must be terminal succeeded (err=%v state=%q)", err, op.State)
	}
}

// TestFeedSignerTwoStoresDistinctOpsOneUpdate uses TWO independent Store
// instances and a counting updater with two DISTINCT operation IDs on the SAME
// registry+topic: the durable (registry,topic) claim gate and the generation
// guard together guarantee exactly ONE external update, and the loser never
// updates the feed.
func TestFeedSignerTwoStoresDistinctOpsOneUpdate(t *testing.T) {
	w := newSharedFeedWorld(t, 2,
		map[string]string{spec.RepoStateFeedRef(testFeedOwner, testRepo): refHex('b'), spec.StampPolicyFeedRef(testFeedOwner): refHex('c')},
		map[string][]byte{
			refHex('b'): mustRepoDoc(t, testRepo, 0),
			refHex('a'): mustRepoDoc(t, testRepo, 1),
			refHex('c'): mustStampDoc(t, "batch-1"),
		})

	reqA := validCommitReq(w.reg.ID, "batch-1")
	reqA.OperationID = "shared-op-A"
	reqA.Owner = "0x" + testFeedOwner
	reqA.Topic = w.topic
	reqA.Reference = refHex('a')
	reqA.ExpectedGeneration = 0

	reqB := reqA
	reqB.OperationID = "shared-op-B"
	reqB.Reference = refHex('d')
	w.docs.Documents[refHex('d')] = mustRepoDoc(t, testRepo, 1)

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(2)
	var mu sync.Mutex
	successes := 0
	var firstErr error
	run := func(signer *FeedSigner, req publish.FeedCommitRequest) {
		defer done.Done()
		start.Wait()
		if _, err := signer.Commit(context.Background(), req); err == nil {
			mu.Lock()
			successes++
			mu.Unlock()
		} else if firstErr == nil {
			mu.Lock()
			firstErr = err
			mu.Unlock()
		}
	}
	go run(w.signers[0], reqA)
	go run(w.signers[1], reqB)
	start.Done()
	done.Wait()

	if got := w.updater.count(); got != 1 {
		t.Fatalf("expected exactly 1 external feed update across two distinct ops, got %d", got)
	}
	if successes != 1 {
		t.Fatalf("expected exactly one distinct-op commit to succeed, got %d (first err %v)", successes, firstErr)
	}
}

// TestFeedSignerExpiredLeaseCrashRecovery proves crash recovery through the
// durable claim: a processing row left by a crashed attempt (expired lease,
// feed ALREADY advanced) is taken over by an identical request, which resolves
// the target and completes WITHOUT a second external update.
func TestFeedSignerExpiredLeaseCrashRecovery(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('a'), currentGen: 1, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	ctx := context.Background()

	hash := NormalizeFeedCommitHash(req)
	if _, err := w.store.ReserveFeedSignerOperation(ctx, req.OperationID, w.registry.ID, w.repoTopic, hash); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// Simulate the crashed attempt: it claimed with an already-expired lease and
	// completed the network update (feed is at target) but never persisted.
	if won, err := w.store.ClaimFeedSignerOperation(ctx, req.OperationID, hash, testClaimToken(t), time.Now().UTC().Add(-time.Minute)); err != nil || !won {
		t.Fatalf("seed crashed claim: won=%v err=%v", won, err)
	}

	updater := &countingFeedUpdater{inner: w.feedStore}
	signer := &FeedSigner{Store: w.store, Feeds: updater, ResolveFeeds: w.feedStore, Docs: w.docs}
	result, err := signer.Commit(ctx, req)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if result.OperationID != req.OperationID || result.Reference != req.Reference {
		t.Fatalf("unexpected recovery result: %+v", result)
	}
	if got := updater.count(); got != 0 {
		t.Fatalf("recovery must not re-run the external update, got %d", got)
	}
	op, _ := w.store.GetFeedSignerOperation(ctx, req.OperationID)
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("expected operation recovered to succeeded, got %q", op.State)
	}
}

// m9HistoricalRequestHash independently reproduces the EXACT migration-9
// (1e91614) delimiter-framed request hash from the RAW request fields, using
// the historical algorithm directly (never the production legacyFeedCommitHash)
// so the test pins the production function to the true historical bytes.
func m9HistoricalRequestHash(req publish.FeedCommitRequest) [32]byte {
	h := sha256.New()
	h.Write([]byte("uncloud-registry-feed-commit-req:v1\x00"))
	h.Write([]byte(req.OperationID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(req.RegistryID, 10)))
	h.Write([]byte{0})
	h.Write([]byte(req.Owner))
	h.Write([]byte{0})
	h.Write([]byte(req.Topic))
	h.Write([]byte{0})
	h.Write([]byte(req.Reference))
	h.Write([]byte{0})
	h.Write([]byte(req.BatchID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(req.ExpectedGeneration, 10)))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// TestLegacyFeedCommitHashReproducesM9Bytes pins legacyFeedCommitHash to the
// byte-exact migration-9 request hash: raw fields, historical order, 0x00
// delimiter framing, decimal integers. Any divergence from the historical
// algorithm would leave logically-identical migration-9 rows permanently
// quarantined.
func TestLegacyFeedCommitHashReproducesM9Bytes(t *testing.T) {
	req := publish.FeedCommitRequest{
		OperationID:        "op-m9",
		RegistryID:         7,
		Owner:              "0x" + testFeedOwner,
		Topic:              "feed://" + strings.Repeat("ab", 20) + "/" + strings.Repeat("cd", 32),
		Reference:          strings.Repeat("ef", 32),
		BatchID:            "batch-1",
		ExpectedGeneration: 3,
	}
	if got := legacyFeedCommitHash(req); got != m9HistoricalRequestHash(req) {
		t.Fatalf("legacyFeedCommitHash diverged from historical m9 bytes:\n got %x\nwant %x", got, m9HistoricalRequestHash(req))
	}
	// The legacy hash must also DIFFER from the forward canonical hash when the
	// historical framing / raw fields differ (owner normalization, topic
	// canonicalization, reference lowercasing, length-prefix framing). This is
	// the root cause of the round-2 finding: m9 rows cannot match the new hash.
	if Modern := NormalizeFeedCommitHash(req); Modern == legacyFeedCommitHash(req) {
		t.Fatal("legacy and modern hashes must differ for a raw request with unnormalized fields")
	}
}

// TestFeedSignerAdoptsLegacyM9HashRow proves a quarantined migration-9
// SUCCEEDED row whose stored request_hash was produced by the historical m9
// delimiter-framed algorithm ADOPTS on the same logical request: the stored
// canonical result is returned idempotently, the network/key update is NOT
// re-run, and the quarantine row is deleted. This is the exact failure the
// round-2 finding flagged (the old hash could not match the new request hash).
func TestFeedSignerAdoptsLegacyM9HashRow(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	target := refHex('a')
	ctx := context.Background()

	// The stored m9 hash is the HISTORICAL delimiter-framed hash, not the modern one.
	m9hash := m9HistoricalRequestHash(req)
	if m9hash == NormalizeFeedCommitHash(req) {
		t.Fatal("test requires the m9 hash to differ from the modern hash")
	}
	result := `{"operationID":"` + req.OperationID + `","feed":"` + w.repoTopic + `","reference":"` + target + `"}`
	nowNs := timeToNanos(time.Now().UTC())
	if _, err := w.store.DB.ExecContext(ctx, `insert into feed_signer_operations_legacy
		(operation_id, request_hash, state, result_json, created_at, updated_at)
		values (?, ?, 'succeeded', ?, ?, ?)`, req.OperationID, m9hash[:], result, nowNs, nowNs); err != nil {
		t.Fatalf("seed m9 succeeded row: %v", err)
	}

	updater := &countingFeedUpdater{inner: w.feedStore}
	signer := &FeedSigner{Store: w.store, Feeds: updater, ResolveFeeds: w.feedStore, Docs: w.docs}
	res, err := signer.Commit(ctx, req)
	if err != nil {
		t.Fatalf("adopt+idempotent commit: %v", err)
	}
	if res.Feed != w.repoTopic || res.Reference != target || res.OperationID != req.OperationID {
		t.Fatalf("adopted result mismatch: %+v", res)
	}
	// No second advancement: the stored succeeded result is returned directly.
	if gotFeed := w.feedStore.Feeds[w.repoTopic]; gotFeed != refHex('b') {
		t.Fatalf("feed must not be re-advanced on adoption, got %q", gotFeed)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("adoption must not call the external updater, got %d calls", n)
	}
	// The quarantine row is deleted; the active row carries the stored bytes.
	if legacyCount(t, w.store, req.OperationID) != 0 {
		t.Fatal("quarantine row must be deleted after successful adoption")
	}
	op, err := w.store.GetFeedSignerOperation(ctx, req.OperationID)
	if err != nil || op.State != FeedSignerOpSucceeded || string(op.ResultJSON) != result {
		t.Fatalf("adopted active row malformed: state=%q result=%s err=%v", op.State, op.ResultJSON, err)
	}
}

// TestFeedSignerAdoptsLegacyM9HashPendingRow proves a quarantined PENDING m9
// row (historical hash) once adopted becomes an active pending row and the
// request proceeds through the normal sign path exactly once.
func TestFeedSignerAdoptsLegacyM9HashPendingRow(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	target := refHex('a')
	ctx := context.Background()

	m9hash := m9HistoricalRequestHash(req)
	nowNs := timeToNanos(time.Now().UTC())
	if _, err := w.store.DB.ExecContext(ctx, `insert into feed_signer_operations_legacy
		(operation_id, request_hash, state, result_json, created_at, updated_at)
		values (?, ?, 'pending', null, ?, ?)`, req.OperationID, m9hash[:], nowNs, nowNs); err != nil {
		t.Fatalf("seed m9 pending row: %v", err)
	}

	updater := &countingFeedUpdater{inner: w.feedStore}
	signer := &FeedSigner{Store: w.store, Feeds: updater, ResolveFeeds: w.feedStore, Docs: w.docs}
	res, err := signer.Commit(ctx, req)
	if err != nil {
		t.Fatalf("adopt pending + sign: %v", err)
	}
	if res.Feed != w.repoTopic || res.Reference != target {
		t.Fatalf("unexpected sign result: %+v", res)
	}
	if gotFeed := w.feedStore.Feeds[w.repoTopic]; gotFeed != target {
		t.Fatalf("pending-adopt must sign once and advance the feed, got %q", gotFeed)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("pending-adopt must sign exactly once, got %d", n)
	}
	if legacyCount(t, w.store, req.OperationID) != 0 {
		t.Fatal("quarantine row must be deleted after successful pending adoption")
	}
	op, _ := w.store.GetFeedSignerOperation(ctx, req.OperationID)
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("pending-adopt should complete to succeeded, got %q", op.State)
	}
}

// TestFeedSignerLegacyRowAdversarialNonMatch proves a quarantined row whose
// stored hash matches NEITHER the current canonical hash NOR the exact m9 hash
// is a hard CONFLICT and stays quarantined (never adopted, never deleted).
func TestFeedSignerLegacyRowAdversarialNonMatch(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	ctx := context.Background()

	// A hash that is neither the modern nor the m9 hash of this request.
	adversarial := feedSignerTestHash("adversarial-nonmatch")
	if adversarial == NormalizeFeedCommitHash(req) || adversarial == m9HistoricalRequestHash(req) {
		t.Fatal("test fixture must be a non-matching hash")
	}
	nowNs := timeToNanos(time.Now().UTC())
	if _, err := w.store.DB.ExecContext(ctx, `insert into feed_signer_operations_legacy
		(operation_id, request_hash, state, result_json, created_at, updated_at)
		values (?, ?, 'succeeded', ?, ?, ?)`, req.OperationID, adversarial[:],
		`{"operationID":"`+req.OperationID+`","feed":"`+w.repoTopic+`","reference":"`+refHex('a')+`"}`, nowNs, nowNs); err != nil {
		t.Fatalf("seed adversarial row: %v", err)
	}

	_, err := w.signer.Commit(ctx, req)
	if !errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("expected conflict for a non-matching legacy row, got %v", err)
	}
	if legacyCount(t, w.store, req.OperationID) != 1 {
		t.Fatal("adversarial non-matching row must remain quarantined")
	}
	if n := w.feedStore.Feeds[w.repoTopic]; n != refHex('b') {
		t.Fatalf("feed must not advance on conflict, got %q", n)
	}
}
