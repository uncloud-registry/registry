package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
)

// digestRef returns a canonical sha256 manifest content digest ("sha256:" +
// 64 identical hex chars) for a fixture.
func digestRef(c byte) string { return "sha256:" + refHex(c) }

// provenanceRepoDoc marshals a repo-state document with an EXPLICIT per-tag
// publication-provenance map. A nil pubs yields the legacy shape (the field is
// omitted by the struct's omitempty), exactly like mustRepoDocWithTags.
func provenanceRepoDoc(t *testing.T, repo string, gen int64, tags map[string]string, pubs map[string]spec.TagPublication) []byte {
	t.Helper()
	manifests := map[string]spec.ManifestDescriptor{}
	for _, digest := range tags {
		manifests[digest] = spec.ManifestDescriptor{SwarmRef: refHex('e'), MediaType: "application/vnd.oci.image.manifest.v1+json", Size: 42}
	}
	doc := spec.RepoStateDocument{
		Version:         1,
		Repo:            repo,
		Generation:      gen,
		Tags:            tags,
		Manifests:       manifests,
		Blobs:           map[string]spec.BlobDescriptor{},
		TagPublications: pubs,
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal provenance repo doc: %v", err)
	}
	return data
}

// provenanceWorld builds the standard signer fixture and then REPLACES the
// current and target repo-state documents with the caller's exact bytes (full
// control over the provenance shape under test). curDoc nil keeps the world's
// default generation-only current document.
func provenanceWorld(t *testing.T, req publish.FeedCommitRequest, curGen int64, curDoc, targetDoc []byte) *feedTestWorld {
	t.Helper()
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: curGen,
		targetRef: refHex('a'), targetGen: curGen + 1,
		stampRef: refHex('c'),
	})
	if curDoc != nil {
		w.docs.Documents[refHex('b')] = curDoc
	}
	if targetDoc != nil {
		w.docs.Documents[refHex('a')] = targetDoc
	}
	return w
}

// countingSigner re-points the world signer at a counting updater and returns
// the signer (convenience so tests can assert EXACT updater-call counts).
func (w *feedTestWorld) countingSigner() (*FeedSigner, *countingFeedUpdater) {
	updater := &countingFeedUpdater{inner: w.feedStore}
	w.signer.Feeds = updater
	return w.signer, updater
}

// TestFeedSignerAuthenticatesGeneratedOperationIdentity proves the normal
// success path with a GENERATED operation identity (the deterministic
// ComputeOperationID domain over registry/owner/repo/operated tag/digest/
// expected generation): the signer recomputes the identity from the immutable
// transition and accepts WITHOUT any durable binding, advancing the feed once.
func TestFeedSignerAuthenticatesGeneratedOperationIdentity(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	targetDigest := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, targetDigest, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: targetDigest}},
		operatedManifests(manifestsForTags(map[string]string{tag: targetDigest}, nil), fx),
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("commit with generated identity: %v", err)
	}
	if result.OperationID != generated || result.Reference != req.Reference {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != req.Reference {
		t.Fatalf("feed must advance to the authenticated target, got %q", got)
	}
	// The generated identity's OWN permanent binding row IS the atomically
	// reserved serialization point: it exists, matches the exact payload
	// hash and operated registry, and remains after the commit (permanence).
	var regID int64
	var raw []byte
	if err := w.store.DB.QueryRowContext(context.Background(),
		`select registry_id, binding_hash from publication_bindings where operation_id = ?`, generated).Scan(&regID, &raw); err != nil {
		t.Fatalf("generated identity must have reserved its binding row: %v", err)
	}
	if regID != w.registry.ID {
		t.Fatalf("generated binding must be bound to the operated registry, got %d want %d", regID, w.registry.ID)
	}
	var want [32]byte
	copy(want[:], raw)
	if got := NormalizePublicationBindingHash(w.registry.ID, req.Owner, testRepo, tag, targetDigest); got != want {
		t.Fatalf("generated binding hash mismatch: stored %x want %x", want, got)
	}
}

// TestFeedSignerRejectsForgedProvenanceOperationID is the core finding-1
// regression: a target document whose operated-tag provenance entry records a
// DIFFERENT (valid-grammar) operation ID — a shape/coherence-valid document
// the retry handler would later trust — is REJECTED by the signer as malformed
// BEFORE any external feed update, with zero updater calls and the feed
// untouched, and the forged identity never leaks through the error.
func TestFeedSignerRejectsForgedProvenanceOperationID(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	targetDigest := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, targetDigest, req.ExpectedGeneration)
	req.OperationID = generated
	forged := "attacker-chosen-valid-grammar-id"
	// The document itself is FULLY valid (a REAL artifact, proven blob
	// state, provenance coherent with the tag mapping); only its
	// provenance identity is forged.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest},
		map[string]spec.TagPublication{tag: {OperationID: forged, Generation: 1, Digest: targetDigest}},
		operatedManifests(manifestsForTags(map[string]string{tag: targetDigest}, nil), fx),
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("forged provenance identity must fail closed as malformed, got %v", err)
	}
	if strings.Contains(err.Error(), forged) {
		t.Fatalf("error must never echo the forged operation identity: %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("forged provenance must cause ZERO external updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance on forged provenance, got %q", got)
	}
}

// TestFeedSignerRejectsUnboundExplicitOperationID proves an EXPLICIT operation
// identity that was never durably bound to this logical payload is rejected
// before any external update: an arbitrary internal request can never pair a
// chosen request ID with a chosen document ID.
func TestFeedSignerRejectsUnboundExplicitOperationID(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	targetDigest := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.OperationID = "explicit-key-never-bound"
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest},
		map[string]spec.TagPublication{tag: {OperationID: req.OperationID, Generation: 1, Digest: targetDigest}},
		operatedManifests(manifestsForTags(map[string]string{tag: targetDigest}, nil), fx),
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("unbound explicit identity must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("unbound explicit identity must cause ZERO external updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance, got %q", got)
	}
	// The signer must NEVER auto-reserve an absent EXPLICIT key: explicit
	// identities come only from a data-plane preflight that ran BEFORE the
	// object write (preflight-before-object-write contract).
	var bound int
	if err := w.store.DB.QueryRowContext(context.Background(),
		`select count(*) from publication_bindings where operation_id = ?`, req.OperationID).Scan(&bound); err != nil {
		t.Fatalf("binding count: %v", err)
	}
	if bound != 0 {
		t.Fatalf("signer must not auto-reserve arbitrary explicit identities, got %d binding rows", bound)
	}
}

// TestFeedSignerAcceptsBoundExplicitOperationID proves an explicit operation
// key that IS durably bound to exactly the committed payload authenticates and
// advances the feed exactly once.
func TestFeedSignerAcceptsBoundExplicitOperationID(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	targetDigest := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.OperationID = "explicit-key-bound-ok"
	if _, err := w.store.ReservePublicationBinding(context.Background(), req.OperationID, w.registry.ID,
		NormalizePublicationBindingHash(w.registry.ID, req.Owner, testRepo, tag, targetDigest)); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest},
		map[string]spec.TagPublication{tag: {OperationID: req.OperationID, Generation: 1, Digest: targetDigest}},
		operatedManifests(manifestsForTags(map[string]string{tag: targetDigest}, nil), fx),
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("commit with bound explicit identity: %v", err)
	}
	if result.OperationID != req.OperationID {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
}

// TestFeedSignerRejectsConflictingExplicitBinding proves an explicit key that
// is durably bound to a DIFFERENT payload conflicts BEFORE any external update
// (zero updater calls, feed untouched).
func TestFeedSignerRejectsConflictingExplicitBinding(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	targetDigest := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.OperationID = "explicit-key-conflicting"
	// Bound to a DIFFERENT digest than the committed document records.
	if _, err := w.store.ReservePublicationBinding(context.Background(), req.OperationID, w.registry.ID,
		NormalizePublicationBindingHash(w.registry.ID, req.Owner, testRepo, tag, digestRef('9'))); err != nil {
		t.Fatalf("seed conflicting binding: %v", err)
	}
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest},
		map[string]spec.TagPublication{tag: {OperationID: req.OperationID, Generation: 1, Digest: targetDigest}},
		operatedManifests(manifestsForTags(map[string]string{tag: targetDigest}, nil), fx),
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("conflicting explicit binding must fail closed as a conflict, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("conflicting binding must cause ZERO external updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance, got %q", got)
	}
}

// TestFeedSignerRejectsZeroProvenanceMutation proves a target document that
// moves a tag WITHOUT recording ANY provenance transition is rejected: the
// signer cannot authenticate what operation produced the mapping.
func TestFeedSignerRejectsZeroProvenanceMutation(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	targetDigest := digestRef('a')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, targetDigest, req.ExpectedGeneration)
	req.OperationID = generated
	// Target carries the tag mapping but NO provenance entry (legacy shape).
	w.docs.Documents[req.Reference] = provenanceRepoDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest}, nil)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("zero provenance mutation must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("zero provenance mutation must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsMultipleProvenanceMutations proves a target document
// whose transition mutates TWO tags' provenance entries (two publications in
// one document) is rejected — the signer authenticates EXACTLY ONE
// tag-publication transition per operation.
func TestFeedSignerRejectsMultipleProvenanceMutations(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	w.docs.Documents[req.Reference] = provenanceRepoDoc(t, testRepo, 1,
		map[string]string{"a": digestRef('a'), "b": digestRef('b')},
		map[string]spec.TagPublication{
			"a": {OperationID: "multi-op-a", Generation: 1, Digest: digestRef('a')},
			"b": {OperationID: "multi-op-b", Generation: 1, Digest: digestRef('b')},
		})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("multiple provenance mutations must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("multiple provenance mutations must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerAcceptsUnrelatedTagAdvanceRetainingEntries proves an operation
// on ONE tag that advances a MULTI-TAG document retains the unrelated tags'
// provenance entries verbatim and is accepted (exactly one transition).
func TestFeedSignerAcceptsUnrelatedTagAdvanceRetainingEntries(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestB := digestRef('a'), digestRef('b')
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	digestC := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	operated := "a"
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, operated, digestC, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = provenanceRepoDoc(t, testRepo, 1,
		map[string]string{"a": digestA, "b": digestB},
		map[string]spec.TagPublication{
			"a": {OperationID: "op-a-prev", Generation: 1, Digest: digestA},
			"b": {OperationID: "op-b-kept", Generation: 1, Digest: digestB},
		})
	// The target is DefaultBuilder-faithful: the operated manifest digest C
	// (a REAL artifact) is ADDED while EVERY existing manifest descriptor
	// (A, B) is retained verbatim; the blob records are exactly the
	// artifact's own references.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{"a": digestC, "b": digestB},
		map[string]spec.TagPublication{
			"a": {OperationID: generated, Generation: 2, Digest: digestC},
			"b": {OperationID: "op-b-kept", Generation: 1, Digest: digestB},
		},
		operatedManifests(manifestsForTags(map[string]string{"a": digestC, "b": digestB},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42)}), fx),
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("unrelated-tag advance with retained entries must succeed: %v", err)
	}
	if result.OperationID != generated || result.Reference != req.Reference {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
}

// TestFeedSignerRejectsUnrelatedTagMappingMutation proves a target document
// that ALSO moves an unrelated tag's mapping (without a provenance entry for
// it) is rejected: TWO tag mappings changed in one transition.
func TestFeedSignerRejectsUnrelatedTagMappingMutation(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	digestA, digestB, digestC, digestD := digestRef('a'), digestRef('b'), digestRef('c'), digestRef('d')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, "a", digestC, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = provenanceRepoDoc(t, testRepo, 1,
		map[string]string{"a": digestA, "b": digestB},
		map[string]spec.TagPublication{
			"a": {OperationID: "op-a-prev", Generation: 1, Digest: digestA},
		})
	// "b" MOVES to digestD with no provenance record while "a" is operated.
	w.docs.Documents[req.Reference] = provenanceRepoDoc(t, testRepo, 2,
		map[string]string{"a": digestC, "b": digestD},
		map[string]spec.TagPublication{
			"a": {OperationID: generated, Generation: 2, Digest: digestC},
		})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("two tag mappings changed in one transition must fail closed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerLegacyCurrentFirstProvenanceAccepted proves a LEGACY current
// document (tags but no provenance) can be advanced by an operation that
// records provenance for the first time: exactly one transition, accepted.
func TestFeedSignerLegacyCurrentFirstProvenanceAccepted(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	digestA := digestRef('a')
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	digestC := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, digestC, req.ExpectedGeneration)
	req.OperationID = generated
	// Legacy current: tag mapping, NO provenance section.
	w.docs.Documents[refHex('b')] = provenanceRepoDoc(t, testRepo, 1,
		map[string]string{tag: digestA}, nil)
	// DefaultBuilder-faithful target: the old manifest descriptor for digestA
	// is RETAINED verbatim and the operated digest C (a REAL artifact) is
	// added with its exact reference blob records.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{tag: digestC},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 2, Digest: digestC}},
		operatedManifests(manifestsForTags(map[string]string{tag: digestC},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42)}), fx),
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	if _, err := signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("first provenance on a legacy document must succeed: %v", err)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
}

// TestFeedSignerCreatePathAuthenticatesProvenance proves the generation-zero
// creation path authenticates the single tag-publication transition of the
// first document against the generated identity.
func TestFeedSignerCreatePathAuthenticatesProvenance(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	targetDigest := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, targetDigest, req.ExpectedGeneration)
	req.OperationID = generated
	delete(w.feedStore.Feeds, w.repoTopic)
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: targetDigest}},
		operatedManifests(manifestsForTags(map[string]string{tag: targetDigest}, nil), fx),
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("generation-zero creation with authenticated provenance: %v", err)
	}
	if result.OperationID != generated || result.Reference != req.Reference {
		t.Fatalf("unexpected creation result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("creation must update exactly once, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != req.Reference {
		t.Fatalf("feed not created at target, got %q", got)
	}
}

// TestFeedSignerCreatePathZeroProvenanceRejected proves a generation-zero
// creation whose first document records NO provenance is rejected with zero
// updater calls and the feed left absent.
func TestFeedSignerCreatePathZeroProvenanceRejected(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	targetDigest := digestRef('a')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, targetDigest, req.ExpectedGeneration)
	req.OperationID = generated
	delete(w.feedStore.Feeds, w.repoTopic)
	w.docs.Documents[req.Reference] = provenanceRepoDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest}, nil)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("zero-provenance creation must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("zero-provenance creation must cause ZERO external updates, got %d", n)
	}
	if _, ok := w.feedStore.Feeds[w.repoTopic]; ok {
		t.Fatal("feed must remain absent after a rejected creation")
	}
}

// TestFeedSignerDoneRecoveryAuthenticatesProvenance proves the already-advanced
// (uncertain-response recovery) path authenticates the committed document's
// single provenance entry for the requesting operation and completes WITH zero
// updater calls.
func TestFeedSignerDoneRecoveryAuthenticatesProvenance(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	targetDigest := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('a'), currentGen: 1, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, targetDigest, req.ExpectedGeneration)
	req.OperationID = generated
	w.feedStore.Feeds[w.repoTopic] = refHex('a')
	w.docs.Documents[refHex('a')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: targetDigest}},
		operatedManifests(manifestsForTags(map[string]string{tag: targetDigest}, nil), fx),
		fx.blobDescs)
	w.serveArtifact(fx)
	hash := NormalizeFeedCommitHash(req)
	if _, err := w.store.ReserveFeedSignerOperation(context.Background(), req.OperationID, w.registry.ID, w.repoTopic, hash); err != nil {
		t.Fatalf("pre-reserve: %v", err)
	}

	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("done-path recovery: %v", err)
	}
	if result.OperationID != req.OperationID || result.Reference != req.Reference {
		t.Fatalf("unexpected recovery result: %+v", result)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("recovery must not re-run the external update, got %d", n)
	}
	op, err := w.store.GetFeedSignerOperation(context.Background(), req.OperationID)
	if err != nil || op.State != FeedSignerOpSucceeded {
		t.Fatalf("operation must be terminal succeeded (err=%v state=%q)", err, op.State)
	}
}

// TestFeedSignerDoneRecoveryForgedProvenanceRejected proves the
// already-advanced recovery path REJECTS a document whose provenance identity
// does not match the request (the finding's forged-document scenario) with
// zero updater calls even when the feed already points at it.
func TestFeedSignerDoneRecoveryForgedProvenanceRejected(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	targetDigest := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('a'), currentGen: 1, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, targetDigest, req.ExpectedGeneration)
	req.OperationID = generated
	forged := "attacker-done-forged-id"
	w.feedStore.Feeds[w.repoTopic] = refHex('a')
	w.docs.Documents[refHex('a')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest},
		map[string]spec.TagPublication{tag: {OperationID: forged, Generation: 1, Digest: targetDigest}},
		operatedManifests(manifestsForTags(map[string]string{tag: targetDigest}, nil), fx),
		fx.blobDescs)
	w.serveArtifact(fx)
	hash := NormalizeFeedCommitHash(req)
	if _, err := w.store.ReserveFeedSignerOperation(context.Background(), req.OperationID, w.registry.ID, w.repoTopic, hash); err != nil {
		t.Fatalf("pre-reserve: %v", err)
	}

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("done-path forged provenance must fail closed as malformed, got %v", err)
	}
	if strings.Contains(err.Error(), forged) {
		t.Fatalf("error must never echo the forged identity: %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("done-path forged provenance must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerDoneRecoveryLegacyDocFailsClosed proves the already-advanced
// path fails closed on a legacy document with no provenance record: no
// identity can be authenticated, zero updater calls.
func TestFeedSignerDoneRecoveryLegacyDocFailsClosed(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('a'), currentGen: 1, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, digestRef('a'), req.ExpectedGeneration)
	req.OperationID = generated
	w.feedStore.Feeds[w.repoTopic] = refHex('a')
	w.docs.Documents[refHex('a')] = provenanceRepoDoc(t, testRepo, 1,
		map[string]string{tag: digestRef('a')}, nil)
	hash := NormalizeFeedCommitHash(req)
	if _, err := w.store.ReserveFeedSignerOperation(context.Background(), req.OperationID, w.registry.ID, w.repoTopic, hash); err != nil {
		t.Fatalf("pre-reserve: %v", err)
	}

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("done-path legacy document must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("legacy done-path must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerSameDigestNewExplicitOperation proves a new explicit operation
// that REPUBLISHES the identical digest (tag mapping unchanged, provenance
// entry replaced) authenticates: exactly one transition (the entry), bound
// identity, one feed advance.
func TestFeedSignerSameDigestNewExplicitOperation(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	digestA := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	req.OperationID = "explicit-same-digest-republish"
	if _, err := w.store.ReservePublicationBinding(context.Background(), req.OperationID, w.registry.ID,
		NormalizePublicationBindingHash(w.registry.ID, req.Owner, testRepo, tag, digestA)); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: digestA},
		map[string]spec.TagPublication{tag: {OperationID: "op-original", Generation: 1, Digest: digestA}},
		operatedManifests(manifestsForTags(map[string]string{tag: digestA}, nil), fx),
		fx.blobDescs)
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{tag: digestA},
		map[string]spec.TagPublication{tag: {OperationID: req.OperationID, Generation: 2, Digest: digestA}},
		operatedManifests(manifestsForTags(map[string]string{tag: digestA}, nil), fx),
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("same-digest explicit republish must succeed: %v", err)
	}
	if result.OperationID != req.OperationID {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
}

// TestFeedSignerRejectsStaleCopiedProvenanceEntry proves a target document
// whose operated-tag entry was COPIED from the current entry and only its
// digest updated (stale operation ID and generation) is rejected: the recorded
// identity does not equal the request's, even though the document is
// shape/coherence-valid.
func TestFeedSignerRejectsStaleCopiedProvenanceEntry(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	digestA := digestRef('a')
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	digestC := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, digestC, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = provenanceRepoDoc(t, testRepo, 1,
		map[string]string{tag: digestA},
		map[string]spec.TagPublication{tag: {OperationID: "op-stale-origin", Generation: 1, Digest: digestA}})
	// Stale/copied: same operation ID and OLD generation, digest updated to the
	// new mapping so the document itself remains fully valid (a REAL artifact,
	// manifests retain the old descriptor exactly as DefaultBuilder would).
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{tag: digestC},
		map[string]spec.TagPublication{tag: {OperationID: "op-stale-origin", Generation: 1, Digest: digestC}},
		operatedManifests(manifestsForTags(map[string]string{tag: digestC},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42)}), fx),
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("stale/copied provenance entry must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("stale/copied entry must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerTwoStoresForgedProvenanceZeroUpdates proves the forged-provenance
// rejection across INDEPENDENT Store instances over one database (process
// model): neither request can advance the feed — exactly zero external updates,
// feed untouched.
func TestFeedSignerTwoStoresForgedProvenanceZeroUpdates(t *testing.T) {
	fxA := simpleArtifact(t, '1', '2', '3', 100, 100)
	fxB := simpleArtifact(t, '4', '5', '6', 200, 200)
	w := newSharedFeedWorld(t, 2,
		map[string]string{spec.RepoStateFeedRef(testFeedOwner, testRepo): refHex('b'), spec.StampPolicyFeedRef(testFeedOwner): refHex('c')},
		map[string][]byte{
			refHex('b'): mustRepoDoc(t, testRepo, 0),
			refHex('a'): transitionDoc(t, testRepo, 1,
				map[string]string{"latest": fxA.digest},
				map[string]spec.TagPublication{"latest": {OperationID: "forged-op-a", Generation: 1, Digest: fxA.digest}},
				operatedManifests(manifestsForTags(map[string]string{"latest": fxA.digest}, nil), fxA),
				fxA.blobDescs),
			refHex('d'): transitionDoc(t, testRepo, 1,
				map[string]string{"latest": fxB.digest},
				map[string]spec.TagPublication{"latest": {OperationID: "forged-op-b", Generation: 1, Digest: fxB.digest}},
				operatedManifests(manifestsForTags(map[string]string{"latest": fxB.digest}, nil), fxB),
				fxB.blobDescs),
			refHex('c'): mustStampDoc(t, "batch-1"),
		})
	w.serve(fxA)
	w.serve(fxB)

	reqA := validCommitReq(w.reg.ID, "batch-1")
	reqA.OperationID = "proc-A"
	reqA.Owner = "0x" + testFeedOwner
	reqA.Topic = w.topic
	reqA.Reference = refHex('a')
	reqA.ExpectedGeneration = 0
	reqB := reqA
	reqB.OperationID = "proc-B"
	reqB.Reference = refHex('d')

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(2)
	successes := 0
	var mu sync.Mutex
	var firstErr error
	run := func(signer *FeedSigner, req publish.FeedCommitRequest) {
		defer done.Done()
		start.Wait()
		// The commit result and the first-error capture share ONE critical
		// section: firstErr must never be read or written outside the mutex
		// (the race detector flags mixed access under -race).
		_, commitErr := signer.Commit(context.Background(), req)
		mu.Lock()
		if commitErr == nil {
			successes++
		} else if firstErr == nil {
			firstErr = commitErr
		}
		mu.Unlock()
	}
	go run(w.signers[0], reqA)
	go run(w.signers[1], reqB)
	start.Done()
	done.Wait()

	if successes != 0 {
		t.Fatalf("no forged-provenance request may succeed, got %d", successes)
	}
	if firstErr == nil {
		t.Fatal("at least one request must fail")
	}
	if n := w.updater.count(); n != 0 {
		t.Fatalf("forged provenance across two stores must cause ZERO external updates, got %d", n)
	}
	if got := w.feeds.Feeds[w.topic]; got != refHex('b') {
		t.Fatalf("feed must stay untouched, got %q", got)
	}
}

// TestFeedSignerMissingBindingStoreRowIsDistinct proves an explicit identity
// with NO binding row fails as malformed while a GENERATED identity for the
// SAME document passes — the two identity classes are decided without attacker
// ambiguity (no private/db error text ever escapes).
func TestFeedSignerMissingBindingStoreRowIsDistinct(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	targetDigest := fx.digest
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, targetDigest, req.ExpectedGeneration)

	// No binding row exists for either identity class.
	var bound int
	if err := w.store.DB.QueryRowContext(context.Background(),
		`select count(*) from publication_bindings where operation_id in (?, ?)`, generated, "explicit-unbound-x").Scan(&bound); err != nil {
		t.Fatalf("binding count: %v", err)
	}
	if bound != 0 {
		t.Fatalf("fixture must start with no bindings, got %d", bound)
	}

	// A MISSING binding is a data-free malformed failure — never a raw sql
	// error string.
	doc := transitionDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest},
		map[string]spec.TagPublication{tag: {OperationID: "explicit-unbound-x", Generation: 1, Digest: targetDigest}},
		operatedManifests(manifestsForTags(map[string]string{tag: targetDigest}, nil), fx),
		fx.blobDescs)
	w.docs.Documents[refHex('a')] = doc
	w.serveArtifact(fx)
	explicitReq := req
	explicitReq.OperationID = "explicit-unbound-x"
	explicitReq.Reference = refHex('a')
	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), explicitReq)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("missing binding must fail closed as malformed, got %v", err)
	}
	if strings.Contains(err.Error(), "no rows") || strings.Contains(err.Error(), "publication_bindings") {
		t.Fatalf("missing-binding failure must be data-free: %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("missing binding must cause ZERO external updates, got %d", n)
	}

	// The GENERATED identity for the same document passes via its OWN
	// atomically reserved binding row (insert-or-read serializes against any
	// concurrent explicit preflight; there was none, so the signer won).
	w.docs.Documents[refHex('a')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: targetDigest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: targetDigest}},
		operatedManifests(manifestsForTags(map[string]string{tag: targetDigest}, nil), fx),
		fx.blobDescs)
	genReq := req
	genReq.OperationID = generated
	genReq.Reference = refHex('a')
	if _, err := signer.Commit(context.Background(), genReq); err != nil {
		t.Fatalf("generated identity for the same document must pass: %v", err)
	}
	var regID int64
	var raw []byte
	if err := w.store.DB.QueryRowContext(context.Background(),
		`select registry_id, binding_hash from publication_bindings where operation_id = ?`, generated).Scan(&regID, &raw); err != nil {
		t.Fatalf("generated identity must have reserved its binding row: %v", err)
	}
	var want [32]byte
	copy(want[:], raw)
	if got := NormalizePublicationBindingHash(w.registry.ID, req.Owner, testRepo, tag, targetDigest); got != want {
		t.Fatalf("generated binding hash mismatch: stored %x want %x", want, got)
	}
}

// TestFeedSignerRejectsDuplicateOperationAttribution proves a target document
// attributing TWO tags to the SAME operation identity (a stale/copy-fabricated
// duplicate) fails closed on every path shape where the signer commits.
func TestFeedSignerRejectsDuplicateOperationAttribution(t *testing.T) {
	const dupOp = "dup-op-id"
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	w.docs.Documents[req.Reference] = provenanceRepoDoc(t, testRepo, 1,
		map[string]string{"a": digestRef('a'), "b": digestRef('b')},
		map[string]spec.TagPublication{
			"a": {OperationID: dupOp, Generation: 1, Digest: digestRef('a')},
			"b": {OperationID: dupOp, Generation: 1, Digest: digestRef('b')},
		})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("duplicate operation attribution must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("duplicate attribution must cause ZERO external updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance, got %q", got)
	}
}
