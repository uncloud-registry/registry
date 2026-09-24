package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
)

// Round 4/5 adversarial suites for the complete-publication-transition
// validation (finding 1) and the fail-closed binding precedence over the
// generated-ID fallback (finding 2). Every rejected case asserts ZERO external
// updater calls, the feed untouched, and a data-free malformed/conflict error;
// every accepted case asserts EXACTLY ONE external update.

const manifestFixtureMediaType = "application/vnd.oci.image.manifest.v1+json"

func fixtureManifestDescriptor(size int64) spec.ManifestDescriptor {
	return spec.ManifestDescriptor{SwarmRef: refHex('e'), MediaType: manifestFixtureMediaType, Size: size}
}

func fixtureBlobDescriptor(size int64) spec.BlobDescriptor {
	return spec.BlobDescriptor{SwarmRef: refHex('f'), Size: size, MediaType: "application/octet-stream"}
}

// transitionDoc marshals a repo-state document with EXPLICIT manifests and
// blobs so tests can model the EXACT DefaultBuilder transition shapes:
// retained entries preserved verbatim, the operated digest added/updated,
// referenced blobs added. It self-validates so a malformed fixture fails the
// test immediately instead of silently exercising the wrong path.
func transitionDoc(t *testing.T, repo string, gen int64, tags map[string]string, pubs map[string]spec.TagPublication, manifests map[string]spec.ManifestDescriptor, blobs map[string]spec.BlobDescriptor) []byte {
	t.Helper()
	doc := spec.RepoStateDocument{
		Version:         1,
		Repo:            repo,
		Generation:      gen,
		Tags:            tags,
		Manifests:       manifests,
		Blobs:           blobs,
		TagPublications: pubs,
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("fixture document is invalid: %v", err)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal transition doc: %v", err)
	}
	return data
}

// manifestsForTags derives a DefaultBuilder-consistent manifest map: one
// descriptor per tag digest (document resolution) plus any caller-retained
// extras (existing entries the builder clones verbatim).
func manifestsForTags(tags map[string]string, extras map[string]spec.ManifestDescriptor) map[string]spec.ManifestDescriptor {
	out := map[string]spec.ManifestDescriptor{}
	for _, d := range tags {
		out[d] = fixtureManifestDescriptor(42)
	}
	for d, desc := range extras {
		out[d] = desc
	}
	return out
}

// --- Finding 1: the transition union must be SYMMETRIC over current+target ---

// TestFeedSignerRejectsUnrelatedTagDeletionWithProvenanceDeletion proves a
// target that deletes an unrelated CURRENT tag AND its provenance entry while
// operating one tag is rejected: the deletion is a current-only entry the
// target-side-only union used to miss, exactly-one transition must fail
// closed with zero updater calls.
func TestFeedSignerRejectsUnrelatedTagDeletionWithProvenanceDeletion(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestC, digestD := digestRef('a'), digestRef('c'), digestRef('d')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestC, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA, "old": digestD},
		map[string]spec.TagPublication{
			"latest": {OperationID: "op-cur-latest", Generation: 1, Digest: digestA},
			"old":    {OperationID: "op-cur-old", Generation: 1, Digest: digestD},
		},
		manifestsForTags(map[string]string{"latest": digestA, "old": digestD}, nil),
		map[string]spec.BlobDescriptor{})
	// "old" is deleted wholesale (mapping AND provenance); manifests retain
	// all existing descriptors exactly as DefaultBuilder would.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"latest": digestC},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 2, Digest: digestC}},
		manifestsForTags(map[string]string{"latest": digestC},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42), digestD: fixtureManifestDescriptor(42)}),
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("unrelated tag+provenance deletion must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("must cause ZERO external updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance, got %q", got)
	}
}

// TestFeedSignerRejectsUnrelatedTagOnlyDeletion proves a target that DELETES
// an unrelated current tag that carried NO provenance entry (a legacy tag) is
// still a current-only mapping change and is rejected.
func TestFeedSignerRejectsUnrelatedTagOnlyDeletion(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestC, digestD := digestRef('a'), digestRef('c'), digestRef('d')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestC, req.ExpectedGeneration)
	req.OperationID = generated
	// "legacy-old" is a LEGACY tag: mapped, but carries no provenance entry.
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA, "legacy-old": digestD},
		map[string]spec.TagPublication{
			"latest": {OperationID: "op-cur-latest", Generation: 1, Digest: digestA},
		},
		manifestsForTags(map[string]string{"latest": digestA, "legacy-old": digestD}, nil),
		map[string]spec.BlobDescriptor{})
	// The unrelated legacy tag mapping is deleted; manifests stay retained.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"latest": digestC},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 2, Digest: digestC}},
		manifestsForTags(map[string]string{"latest": digestC},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42), digestD: fixtureManifestDescriptor(42)}),
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("unrelated tag-only deletion must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsUnrelatedProvenanceOnlyDeletion proves a target that
// deletes an unrelated tag's PROVENANCE ENTRY while retaining the tag mapping
// is a current-only provenance change and is rejected.
func TestFeedSignerRejectsUnrelatedProvenanceOnlyDeletion(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestB, digestC := digestRef('a'), digestRef('b'), digestRef('c')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestC, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA, "stable": digestB},
		map[string]spec.TagPublication{
			"latest": {OperationID: "op-cur-latest", Generation: 1, Digest: digestA},
			"stable": {OperationID: "op-stable-orig", Generation: 1, Digest: digestB},
		},
		manifestsForTags(map[string]string{"latest": digestA, "stable": digestB}, nil),
		map[string]spec.BlobDescriptor{})
	// "stable" RETAINS its mapping but its provenance entry is silently
	// deleted; all manifests retained.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"latest": digestC, "stable": digestB},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 2, Digest: digestC}},
		manifestsForTags(map[string]string{"latest": digestC, "stable": digestB},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42)}),
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("unrelated provenance-only deletion must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("must cause ZERO external updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance, got %q", got)
	}
}

// TestFeedSignerRejectsUnrelatedManifestDeletion proves the same root class
// across the MANIFESTS map: removing a current manifest entry that no current
// tag points at any more — while the operated transition itself is valid —
// is an unrelated semantic change and fails closed.
func TestFeedSignerRejectsUnrelatedManifestDeletion(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestC := digestRef('a'), digestRef('c')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestC, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: "op-cur-latest", Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{"latest": digestA}, nil),
		map[string]spec.BlobDescriptor{})
	// The operated tag moves cleanly to C with its provenance, but the OLD
	// manifest descriptor for digest A is deleted from the target — a shape
	// DefaultBuilder never produces (it clones every existing entry).
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"latest": digestC},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 2, Digest: digestC}},
		manifestsForTags(map[string]string{"latest": digestC}, nil),
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("unrelated manifest deletion must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsUnrelatedManifestMutation proves mutating the
// descriptor of a RETAINED manifest (one the operated transition does not
// touch) is rejected: existing manifest entries must be preserved exactly.
func TestFeedSignerRejectsUnrelatedManifestMutation(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestB, digestC := digestRef('a'), digestRef('b'), digestRef('c')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestC, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA, "stable": digestB},
		map[string]spec.TagPublication{
			"latest": {OperationID: "op-cur-latest", Generation: 1, Digest: digestA},
			"stable": {OperationID: "op-stable-orig", Generation: 1, Digest: digestB},
		},
		manifestsForTags(map[string]string{"latest": digestA, "stable": digestB}, nil),
		map[string]spec.BlobDescriptor{})
	// The retained "stable" manifest's descriptor is REWRITTEN (size changed)
	// while the operated tag moves to C.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"latest": digestC, "stable": digestB},
		map[string]spec.TagPublication{
			"latest": {OperationID: generated, Generation: 2, Digest: digestC},
			"stable": {OperationID: "op-stable-orig", Generation: 1, Digest: digestB},
		},
		map[string]spec.ManifestDescriptor{
			digestA: fixtureManifestDescriptor(42),
			digestB: fixtureManifestDescriptor(999), // mutated retained descriptor
			digestC: fixtureManifestDescriptor(42),
		},
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("unrelated manifest descriptor mutation must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsUnrelatedManifestAddition proves ADDING a manifest
// descriptor at a digest the operated tag does not map to (an unrelated
// semantic change) is rejected while the operated transition stays intact.
func TestFeedSignerRejectsUnrelatedManifestAddition(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestC, digestX := digestRef('a'), digestRef('c'), digestRef('x')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestC, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: "op-cur-latest", Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{"latest": digestA}, nil),
		map[string]spec.BlobDescriptor{})
	// The target carries an EXTRA manifest at digest X — referenced by no tag
	// (document-valid) — hidden alongside the operated transition.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"latest": digestC},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 2, Digest: digestC}},
		map[string]spec.ManifestDescriptor{
			digestA: fixtureManifestDescriptor(42),
			digestC: fixtureManifestDescriptor(42),
			digestX: fixtureManifestDescriptor(7),
		},
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("unrelated manifest addition must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerAcceptsOperatedManifestUpdateAtOperatedDigest proves replacing
// the descriptor AT THE OPERATED DIGEST (the exact DefaultBuilder
// `next.Manifests[input.ManifestDigest] = input.Manifest` shape) is accepted —
// the manifest validation must not over-reject the operated update.
func TestFeedSignerAcceptsOperatedManifestUpdateAtOperatedDigest(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA := digestRef('a')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestA, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: "op-cur-latest", Generation: 1, Digest: digestA}},
		map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42)},
		map[string]spec.BlobDescriptor{})
	// Same digest republished: the operated digest's descriptor is UPDATED and
	// the provenance entry replaced — both permitted (operated transition only).
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 2, Digest: digestA}},
		map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(43)},
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	if _, err := signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("operated-manifest descriptor update at the operated digest must succeed: %v", err)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
}

// TestFeedSignerRejectsBlobDeletion proves a current-only blob record DELETED
// from the target is rejected: existing blob entries must be preserved.
func TestFeedSignerRejectsBlobDeletion(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestC := digestRef('a'), digestRef('c')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestC, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: "op-cur-latest", Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{"latest": digestA}, nil),
		map[string]spec.BlobDescriptor{"sha256:" + refHex('1'): fixtureBlobDescriptor(100)})
	// The operated transition is valid; the existing blob record is dropped.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"latest": digestC},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 2, Digest: digestC}},
		manifestsForTags(map[string]string{"latest": digestC},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42)}),
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("blob deletion must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsBlobMutation proves rewriting a RETAINED blob record's
// descriptor is rejected; only the data plane's staged-reference copy may add
// NEW blob records, never change existing state.
func TestFeedSignerRejectsBlobMutation(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestC := digestRef('a'), digestRef('c')
	blobDigest := "sha256:" + refHex('1')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestC, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: "op-cur-latest", Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{"latest": digestA}, nil),
		map[string]spec.BlobDescriptor{blobDigest: fixtureBlobDescriptor(100)})
	// The retained blob record's SIZE is rewritten while the tag moves.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"latest": digestC},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 2, Digest: digestC}},
		manifestsForTags(map[string]string{"latest": digestC},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42)}),
		map[string]spec.BlobDescriptor{blobDigest: fixtureBlobDescriptor(999)})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("blob descriptor mutation must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerAcceptsBlobAddition proves ADDING a NEW blob record alongside
// the operated transition is accepted: DefaultBuilder copies referenced staged
// blobs into the next state, and the signer cannot re-derive the artifact's
// reference set — a new record never deletes or rewrites existing state.
func TestFeedSignerAcceptsBlobAddition(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestC := digestRef('a'), digestRef('c')
	blobDigest := "sha256:" + refHex('2')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestC, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: "op-cur-latest", Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{"latest": digestA}, nil),
		map[string]spec.BlobDescriptor{})
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"latest": digestC},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 2, Digest: digestC}},
		manifestsForTags(map[string]string{"latest": digestC},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42)}),
		map[string]spec.BlobDescriptor{blobDigest: fixtureBlobDescriptor(100)})

	signer, updater := w.countingSigner()
	if _, err := signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("blob addition alongside the operated transition must succeed: %v", err)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
}

// TestFeedSignerAcceptsLegitimateRetainedEntriesAcrossMaps proves the
// legitimate multi-tag advance that RETAINS unrelated entries in every map —
// tag mappings, provenance, manifests, and blobs — is accepted (exactly one
// transition, one update).
func TestFeedSignerAcceptsLegitimateRetainedEntriesAcrossMaps(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestB, digestC, digestD := digestRef('a'), digestRef('b'), digestRef('c'), digestRef('d')
	blobDigest := "sha256:" + refHex('3')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestC, req.ExpectedGeneration)
	req.OperationID = generated
	curManifests := manifestsForTags(map[string]string{"latest": digestA, "stable": digestB, "legacy": digestD}, nil)
	curBlobs := map[string]spec.BlobDescriptor{blobDigest: fixtureBlobDescriptor(100)}
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA, "stable": digestB, "legacy": digestD},
		map[string]spec.TagPublication{
			"latest": {OperationID: "op-cur-latest", Generation: 1, Digest: digestA},
			"stable": {OperationID: "op-stable-orig", Generation: 1, Digest: digestB},
			// "legacy" intentionally carries no provenance entry.
		},
		curManifests,
		curBlobs)
	// Target: latest moves to C with new provenance; stable's entry and the
	// legacy tag are retained verbatim; every manifest and blob is retained
	// exactly; only the operated manifest digest C is added.
	targetManifests := map[string]spec.ManifestDescriptor{}
	for d, desc := range curManifests {
		targetManifests[d] = desc
	}
	targetManifests[digestC] = fixtureManifestDescriptor(42)
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"latest": digestC, "stable": digestB, "legacy": digestD},
		map[string]spec.TagPublication{
			"latest": {OperationID: generated, Generation: 2, Digest: digestC},
			"stable": {OperationID: "op-stable-orig", Generation: 1, Digest: digestB},
		},
		targetManifests,
		curBlobs)

	signer, updater := w.countingSigner()
	if _, err := signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("legitimate retained multi-map advance must succeed: %v", err)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
}

// TestFeedSignerCreatePathRejectsUnrelatedManifestAddition proves the
// generation-zero (nil current) path applies the SAME manifest rule: a first
// document that adds a manifest at a digest the operated tag does not map to
// fails closed with the feed left absent.
func TestFeedSignerCreatePathRejectsUnrelatedManifestAddition(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestX := digestRef('a'), digestRef('x')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestA, req.ExpectedGeneration)
	req.OperationID = generated
	delete(w.feedStore.Feeds, w.repoTopic)
	// First document: the operated tag maps to A, but an EXTRA manifest at X
	// (referenced by no tag) is hidden in the creation.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 1, Digest: digestA}},
		map[string]spec.ManifestDescriptor{
			digestA: fixtureManifestDescriptor(42),
			digestX: fixtureManifestDescriptor(7),
		},
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("create path with an unrelated manifest addition must fail closed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("must cause ZERO external updates, got %d", n)
	}
	if _, ok := w.feedStore.Feeds[w.repoTopic]; ok {
		t.Fatal("feed must remain absent after the rejected creation")
	}
}

// TestFeedSignerCreatePathAcceptsBlobAdditions proves the nil-current
// generation-zero path ACCEPTS blob records in the first document (the data
// plane commits the artifact's referenced staged blobs).
func TestFeedSignerCreatePathAcceptsBlobAdditions(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA := digestRef('a')
	blobDigest := "sha256:" + refHex('4')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestA, req.ExpectedGeneration)
	req.OperationID = generated
	delete(w.feedStore.Feeds, w.repoTopic)
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{"latest": digestA}, nil),
		map[string]spec.BlobDescriptor{blobDigest: fixtureBlobDescriptor(100)})

	signer, updater := w.countingSigner()
	if _, err := signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("create path with blob records must succeed: %v", err)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != req.Reference {
		t.Fatalf("feed must be created at target, got %q", got)
	}
}

// --- Finding 2: permanent bindings hold precedence over the generated form ---

// TestFeedSignerGeneratedLookingIDWithMatchingBindingAccepted proves a
// generated-looking operation identity that ALSO has a permanent binding row
// matching the exact payload still authenticates (row first, hash matched).
func TestFeedSignerGeneratedLookingIDWithMatchingBindingAccepted(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA := digestRef('a')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	key := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestA, req.ExpectedGeneration)
	req.OperationID = key
	// The identity was ALSO durably bound (preflight) to the exact payload.
	if _, err := w.store.ReservePublicationBinding(context.Background(), key, w.registry.ID,
		NormalizePublicationBindingHash(w.registry.ID, req.Owner, testRepo, "latest", digestA)); err != nil {
		t.Fatalf("seed matching binding: %v", err)
	}
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: key, Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{"latest": digestA}, nil),
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	if _, err := signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("generated-looking identity with a MATCHING binding must succeed: %v", err)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
}

// TestFeedSignerGeneratedLookingIDWithConflictingBindingRejected proves the
// binding-precedence fix: an identity equal to the deterministic generated
// form whose PERMANENT binding records a DIFFERENT payload must be REJECTED as
// a conflict with zero updater calls — the binding row is never bypassed by
// the generated-form check.
func TestFeedSignerGeneratedLookingIDWithConflictingBindingRejected(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA := digestRef('a')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	key := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestA, req.ExpectedGeneration)
	req.OperationID = key
	// The permanent binding for this generated-looking identity is bound to a
	// DIFFERENT digest — a conflicting payload the generated-form check must
	// never bypass.
	if _, err := w.store.ReservePublicationBinding(context.Background(), key, w.registry.ID,
		NormalizePublicationBindingHash(w.registry.ID, req.Owner, testRepo, "latest", digestRef('9'))); err != nil {
		t.Fatalf("seed conflicting binding: %v", err)
	}
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: key, Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{"latest": digestA}, nil),
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("conflicting permanent binding must fail closed as a conflict, got %v", err)
	}
	if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), digestA) {
		t.Fatalf("conflict error must be data-free: %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("conflicting binding must cause ZERO external updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance, got %q", got)
	}
}

// TestFeedSignerGeneratedLookingIDWithForeignRegistryBindingRejected proves a
// generated-looking identity durably bound to ANOTHER registry is a conflict
// (never accepted via the generated form).
func TestFeedSignerGeneratedLookingIDWithForeignRegistryBindingRejected(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA := digestRef('a')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	key := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestA, req.ExpectedGeneration)
	req.OperationID = key
	// A SECOND registry exists; the key is durably bound there.
	ctx := context.Background()
	otherOwner, err := w.store.CreateUser(ctx, "other-registry@example.com", "hash")
	if err != nil {
		t.Fatalf("create other owner: %v", err)
	}
	otherReg, err := w.store.CreateProvisionedRegistry(ctx, Registry{
		Slug: "otherreg", Host: "otherreg.test", ENSName: "",
		OwnerUserID: otherOwner.ID, FeedOwnerAddress: testFeedOwner, DefaultStampBatchID: req.BatchID,
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create other registry: %v", err)
	}
	if err := w.store.MarkRegistryReady(ctx, otherReg.ID); err != nil {
		t.Fatalf("mark other ready: %v", err)
	}
	if _, err := w.store.ReservePublicationBinding(ctx, key, otherReg.ID,
		NormalizePublicationBindingHash(otherReg.ID, req.Owner, testRepo, "latest", digestA)); err != nil {
		t.Fatalf("seed foreign binding: %v", err)
	}
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: key, Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{"latest": digestA}, nil),
		map[string]spec.BlobDescriptor{})

	signer, updater := w.countingSigner()
	_, err = signer.Commit(ctx, req)
	if !errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("foreign-registry binding must fail closed as a conflict, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("foreign-registry binding must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerBindingQueryFailureNeverFallsBack proves a DB/query failure on
// the binding read is a BACKEND/uncertain error — even for an identity that
// equals the generated form — and never falls back to the deterministic
// recomputation. The failure is data-free (no request values) with zero
// updates.
func TestFeedSignerBindingQueryFailureNeverFallsBack(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA := digestRef('a')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "latest", digestA, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: generated, Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{"latest": digestA}, nil),
		map[string]spec.BlobDescriptor{})
	// Break the binding table AFTER the world is fully set up: the signer's
	// binding read now fails exactly where the precedence decision is made.
	if _, err := w.store.DB.ExecContext(context.Background(), `drop table publication_bindings`); err != nil {
		t.Fatalf("drop binding table: %v", err)
	}

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("binding query failure must be a backend error (never the generated-ID fallback), got %v", err)
	}
	if strings.Contains(err.Error(), generated) || strings.Contains(err.Error(), digestA) || strings.Contains(err.Error(), "latest") {
		t.Fatalf("query-failure error must carry no request values: %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("query failure must cause ZERO external updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance after the query failure, got %q", got)
	}
}

// TestFeedSignerTwoStoresBindingPrecedenceConflictZeroUpdates proves the
// conflicting permanent binding for a generated-looking identity is enforced
// across INDEPENDENT Store instances over one database (process model): the
// row seeded through store 0 is consulted through store 1, and neither
// request can advance the feed — exactly zero external updates.
func TestFeedSignerTwoStoresBindingPrecedenceConflictZeroUpdates(t *testing.T) {
	digestA := digestRef('a')
	w := newSharedFeedWorld(t, 2,
		map[string]string{spec.RepoStateFeedRef(testFeedOwner, testRepo): refHex('b'), spec.StampPolicyFeedRef(testFeedOwner): refHex('c')},
		map[string][]byte{
			refHex('b'): mustRepoDoc(t, testRepo, 0),
			refHex('a'): transitionDoc(t, testRepo, 1,
				map[string]string{"latest": digestA},
				map[string]spec.TagPublication{},
				manifestsForTags(map[string]string{"latest": digestA}, nil),
				map[string]spec.BlobDescriptor{}),
			refHex('c'): mustStampDoc(t, "batch-1"),
		})
	key := publish.ComputeOperationID(w.reg.ID, "0x"+testFeedOwner, testRepo, "latest", digestA, 0)
	// Seed the CONFLICTING binding through store 0; both signers must honor it.
	if _, err := w.stores[0].ReservePublicationBinding(context.Background(), key, w.reg.ID,
		NormalizePublicationBindingHash(w.reg.ID, "0x"+testFeedOwner, testRepo, "latest", digestRef('9'))); err != nil {
		t.Fatalf("seed conflicting binding: %v", err)
	}
	// The docs' provenance entry is filled AFTER deriving the key (the helper
	// requires decode-valid documents).
	w.docs.Documents[refHex('a')] = transitionDoc(t, testRepo, 1,
		map[string]string{"latest": digestA},
		map[string]spec.TagPublication{"latest": {OperationID: key, Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{"latest": digestA}, nil),
		map[string]spec.BlobDescriptor{})

	req := validCommitReq(w.reg.ID, "batch-1")
	req.OperationID = key
	req.Owner = "0x" + testFeedOwner
	req.Topic = w.topic
	req.Reference = refHex('a')
	req.ExpectedGeneration = 0

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(2)
	successes := 0
	var mu sync.Mutex
	var firstErr error
	run := func(signer *FeedSigner) {
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
	go run(w.signers[0])
	go run(w.signers[1])
	start.Done()
	done.Wait()

	if successes != 0 {
		t.Fatalf("no conflicting-binding request may succeed, got %d", successes)
	}
	if firstErr == nil || !errors.Is(firstErr, errFeedSignerConflict) {
		t.Fatalf("both requests must conflict against the binding, first err %v", firstErr)
	}
	if n := w.updater.count(); n != 0 {
		t.Fatalf("conflicting binding across two stores must cause ZERO external updates, got %d", n)
	}
	if got := w.feeds.Feeds[w.topic]; got != refHex('b') {
		t.Fatalf("feed must stay untouched, got %q", got)
	}
}

// TestStoreGetPublicationBindingDistinguishesNotFoundFromFailure pins the
// store API contract the signer's precedence relies on: an authoritative
// not-found is the plain sql.ErrNoRows sentinel (no row/table data), while a
// broken store surfaces a REAL failure that is never mistaken for not-found.
func TestStoreGetPublicationBindingDistinguishesNotFoundFromFailure(t *testing.T) {
	store := newProvisioningStore(t)
	ctx := context.Background()

	_, err := store.GetPublicationBinding(ctx, "never-bound-operation")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing binding must be an authoritative sql.ErrNoRows not-found, got %v", err)
	}
	if strings.Contains(err.Error(), "publication_bindings") || strings.Contains(err.Error(), "never-bound-operation") {
		t.Fatalf("not-found must stay the plain sentinel, leaking nothing: %v", err)
	}

	if err := store.DB.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	_, err = store.GetPublicationBinding(ctx, "never-bound-operation")
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("a broken store must surface a REAL failure, never an authoritative not-found: %v", err)
	}
}
