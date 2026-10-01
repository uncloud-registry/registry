package controlplane

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// newFileBackedProvisioningStore opens a REAL durable file-backed SQLite store
// under a fresh t.TempDir() unique to this invocation. Unlike
// newProvisioningStore's shared-cache in-memory database (whose name is
// keyed only on t.Name(), and therefore collides across repeated runs of the
// SAME test under `go test -count=N`), a per-invocation temp file can never
// alias a prior run's rows, so it is the only store construction Task 17's
// mandatory real cross-process integration test may use to back its claim of
// a REAL durable Store.
func newFileBackedProvisioningStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "task17.sqlite")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open file-backed sqlite: %v", err)
	}
	t.Cleanup(func() { store.DB.Close() })
	return store
}

// newFileBackedFeedTestWorld builds the exact same fixture as
// newFeedTestWorld (feed_signer_test.go), but backs it with
// newFileBackedProvisioningStore instead of newProvisioningStore's shared-cache
// in-memory database, so Task 17 tests that run under `go test -count=N` never
// collide on a repeated t.Name()-derived database identity.
func newFileBackedFeedTestWorld(t *testing.T, req publish.FeedCommitRequest, dst feedDocSet) *feedTestWorld {
	t.Helper()
	ctx := context.Background()
	store := newFileBackedProvisioningStore(t)
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
	targetDoc := mustRepoDoc(t, testRepo, dst.targetGen)
	if len(dst.targetTags) > 0 {
		targetDoc = mustRepoDocWithTags(t, testRepo, dst.targetGen, dst.targetTags)
	}
	if len(dst.targetTags) == 1 {
		var tag, digest string
		for tg, dg := range dst.targetTags {
			tag, digest = tg, dg
		}
		if dst.artifact != nil {
			fx := dst.artifact
			digest = fx.digest
			targetDoc = transitionDoc(t, testRepo, dst.targetGen,
				map[string]string{tag: fx.digest},
				map[string]spec.TagPublication{tag: {OperationID: req.OperationID, Generation: dst.targetGen, Digest: fx.digest}},
				map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
				fx.blobDescs)
		} else {
			targetDoc = mustRepoDocWithPubs(t, testRepo, dst.targetGen, dst.targetTags,
				map[string]spec.TagPublication{tag: {OperationID: req.OperationID, Generation: dst.targetGen, Digest: digest}})
		}
		if _, err := store.ReservePublicationBinding(ctx, req.OperationID, newReg.ID,
			NormalizePublicationBindingHash(newReg.ID, req.Owner, testRepo, tag, digest)); err != nil {
			t.Fatalf("seed publication binding: %v", err)
		}
	}
	docs := resolve.NewMemoryDocumentStore()
	bytes := newMemoryBytesReader()
	if dst.artifact != nil {
		bytes.serve(dst.artifact.manifest.SwarmRef, dst.artifact.body)
	}
	docs.Documents = map[string][]byte{
		dst.currentRef: mustRepoDoc(t, testRepo, dst.currentGen),
		dst.targetRef:  targetDoc,
		dst.stampRef:   mustStampDoc(t, req.BatchID),
	}
	operated := (*artifactFixture)(nil)
	if dst.artifact != nil {
		operated = dst.artifact
	}

	signer := &FeedSigner{Store: store, Feeds: feedStore, ResolveFeeds: feedStore, Docs: docs, Bytes: bytes}
	return &feedTestWorld{
		signer: signer, store: store, feedStore: feedStore, docs: docs, bytes: bytes,
		registry: newReg, repoTopic: repoTopic, stampFeed: stampFeed, batchAllowed: req.BatchID,
		operatedArtifact: operated,
	}
}
