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

// fixtureBlobMediaType is the unspecified transport placeholder (the type a
// real staged blob upload carries): transparent under the media-type
// normalization contract, like an empty stored type.
const fixtureBlobMediaType = "application/octet-stream"

// Round 5: artifact-proven blob transitions (finding 1) and the atomic
// generated-operation-ID reserve (finding 2).
//
// Finding 1: the signer can no longer accept an unproven blob addition — it
// INDEPENDENTLY reads the operated manifest's immutable BODY through the
// separately-wired bounded /bytes reader (never the docs path, never
// unbounded), parses it with the strict Task-12 artifact parser under the
// operated descriptor's media type, verifies its digest/size/media against
// the descriptor, rejects index publication (the Task 19 gate), and requires
// the target's blob-record additions to be EXACTLY the artifact's derived
// reference set while every existing record is preserved byte-identically.
//
// Finding 2: the generated-operation-ID identity decision can no longer be
// made on a stale absence — the signer ATOMICALLY RESERVES its own binding
// row (insert-or-read) for the exact deterministic generated ID, serializing
// with any concurrent explicit preflight: one permanent winner, the loser
// conflicts before the updater. Explicit caller keys still require their
// pre-existing preflight row (never auto-reserved by the signer).

// --- bounded /bytes reader fixture ---------------------------------------------

// memoryBytesReader is the in-memory bounded immutable-object reader for
// signer fixtures. It models the SAME overflow contract as
// swarm.BeeObjectStore.ReadBounded: an object larger than the requested bound
// is a data-free error, and a missing object is a data-free error — the
// signer must never receive unbounded data or attacker-controlled details.
type memoryBytesReader struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newMemoryBytesReader() *memoryBytesReader {
	return &memoryBytesReader{objects: map[string][]byte{}}
}

func (m *memoryBytesReader) ReadBounded(_ context.Context, ref string, maxBytes int64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[ref]
	if !ok {
		return nil, errors.New("bounded object read: object not found")
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("bounded object read exceeded the bound")
	}
	return data, nil
}

func (m *memoryBytesReader) serve(ref string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[ref] = data
}

// --- real DefaultBuilder artifact fixtures ---------------------------------------

// artifactFixture bundles a REAL strict OCI manifest body and the exact state
// descriptors the DefaultBuilder data plane would record for it: the manifest
// content digest (sha256 of the body), the manifest descriptor (SwarmRef
// / media type / size matching the body), one blob record per referenced
// digest, and the parsed reference set.
type artifactFixture struct {
	body       []byte
	digest     string
	manifest   spec.ManifestDescriptor
	blobDescs  map[string]spec.BlobDescriptor
	references []publish.Descriptor
}

func fixtureRef(c byte) string { return "sha256:" + refHex(c) }

const (
	fixtureConfigMediaType = "application/vnd.oci.image.config.v1+json"
	fixtureLayerMediaType  = "application/vnd.oci.image.layer.v1.tar+gzip"
	fixtureIndexMediaType  = "application/vnd.oci.image.index.v1+json"
)

type manifestRef struct {
	digestByte byte
	size       int64
	mediaType  string
}

func (b manifestRef) descriptor() publish.Descriptor {
	return publish.Descriptor{MediaType: b.mediaType, Digest: fixtureRef(b.digestByte), Size: b.size}
}

// buildArtifact constructs the REAL manifest body and the exact descriptors
// the data plane would record: the body is served at a SwarmRef of 64×
// swarmRefByte; referenced digests are the canonical fixture digests; the
// stored blob records use the unspecified octet-stream placeholder (the
// transport's transparent type, like a real staged upload).
func buildArtifact(t *testing.T, swarmRefByte byte, config manifestRef, layers ...manifestRef) artifactFixture {
	t.Helper()
	configDesc := config.descriptor()
	layerDescs := make([]publish.Descriptor, 0, len(layers))
	for _, l := range layers {
		layerDescs = append(layerDescs, l.descriptor())
	}
	body := fixtureManifestBody(t, configDesc, layerDescs...)
	fx := artifactFixture{
		body:       body,
		digest:     publish.ComputeDigest(body),
		manifest:   spec.ManifestDescriptor{SwarmRef: refHex(swarmRefByte), MediaType: manifestFixtureMediaType, Size: int64(len(body))},
		blobDescs:  map[string]spec.BlobDescriptor{},
		references: []publish.Descriptor{configDesc},
	}
	fx.references = append(fx.references, layerDescs...)
	for _, ref := range fx.references {
		fx.blobDescs[ref.Digest] = spec.BlobDescriptor{SwarmRef: refHex(ref.Digest[7]), Size: ref.Size, MediaType: fixtureBlobMediaType}
	}
	return fx
}

func fixtureManifestBody(t *testing.T, config publish.Descriptor, layers ...publish.Descriptor) []byte {
	t.Helper()
	layerJSON := make([]map[string]any, 0, len(layers))
	for _, l := range layers {
		layerJSON = append(layerJSON, map[string]any{"mediaType": l.MediaType, "digest": l.Digest, "size": l.Size})
	}
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     manifestFixtureMediaType,
		"config":        map[string]any{"mediaType": config.MediaType, "digest": config.Digest, "size": config.Size},
		"layers":        layerJSON,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal fixture manifest: %v", err)
	}
	return data
}

// simpleArtifact builds a config+single-layer artifact.
func simpleArtifact(t *testing.T, swarmRefByte, cfgByte, layerByte byte, cfgSize, layerSize int64) artifactFixture {
	t.Helper()
	return buildArtifact(t, swarmRefByte,
		manifestRef{digestByte: cfgByte, size: cfgSize, mediaType: fixtureConfigMediaType},
		manifestRef{digestByte: layerByte, size: layerSize, mediaType: fixtureLayerMediaType})
}

// configOnlyArtifact builds a zero-layer artifact: valid OCI, referencing
// exactly the config blob.
func configOnlyArtifact(t *testing.T, swarmRefByte, cfgByte byte, cfgSize int64) artifactFixture {
	t.Helper()
	return buildArtifact(t, swarmRefByte, manifestRef{digestByte: cfgByte, size: cfgSize, mediaType: fixtureConfigMediaType})
}

// fixtureEmptyIndexBody builds a REAL but ZERO-reference OCI image index body
// (manifests: [] — explicitly permitted by both the OCI image-index and the
// Docker manifest-list specs) so the Task-19 gate can be exercised.
func fixtureEmptyIndexBody(t *testing.T) []byte {
	t.Helper()
	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     fixtureIndexMediaType,
		"manifests":     []map[string]any{},
	}
	data, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal fixture index: %v", err)
	}
	return data
}

// operatedManifests returns the caller's manifest map with the synthetic
// descriptor at the operated digest REPLACED by the artifact's real one.
func operatedManifests(base map[string]spec.ManifestDescriptor, fx artifactFixture) map[string]spec.ManifestDescriptor {
	out := map[string]spec.ManifestDescriptor{}
	for d, desc := range base {
		out[d] = desc
	}
	out[fx.digest] = fx.manifest
	return out
}

// withBlobs returns the caller's blob map PLUS the artifact's referenced blob
// records (existing records are preserved byte-identically).
func withBlobs(base map[string]spec.BlobDescriptor, fx artifactFixture) map[string]spec.BlobDescriptor {
	out := map[string]spec.BlobDescriptor{}
	for d, b := range base {
		out[d] = b
	}
	for d, b := range fx.blobDescs {
		out[d] = b
	}
	return out
}

// serveArtifact registers the operated manifest's REAL body with the world's
// bounded /bytes reader at the exact SwarmRef the document records.
func (w *feedTestWorld) serveArtifact(fx artifactFixture) {
	w.bytes.serve(fx.manifest.SwarmRef, fx.body)
}

// bindingRow loads the durable binding row for one operation key.
func bindingRow(t *testing.T, store *Store, operationID string) (registryID int64, hash [32]byte) {
	t.Helper()
	var raw []byte
	if err := store.DB.QueryRowContext(context.Background(),
		`select registry_id, binding_hash from publication_bindings where operation_id = ?`, operationID).Scan(&registryID, &raw); err != nil {
		t.Fatalf("load binding row for %q: %v", operationID, err)
	}
	if len(raw) != len(hash) {
		t.Fatalf("binding hash for %q has %d bytes, want %d", operationID, len(raw), len(hash))
	}
	copy(hash[:], raw)
	return registryID, hash
}

func bindingRowCount(t *testing.T, store *Store, operationID string) int {
	t.Helper()
	var n int
	if err := store.DB.QueryRowContext(context.Background(),
		`select count(*) from publication_bindings where operation_id = ?`, operationID).Scan(&n); err != nil {
		t.Fatalf("binding count for %q: %v", operationID, err)
	}
	return n
}

// --- Finding 1: the signer independently proves the operated artifact ------------

// TestFeedSignerAcceptsVerifiedArtifactCreateTransition proves the
// generation-zero creation path accepts a transition whose blob additions are
// EXACTLY the verified artifact's references — every referenced digest present
// with coherent size/media, nothing extra — with exactly one feed update.
func TestFeedSignerAcceptsVerifiedArtifactCreateTransition(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		fx.blobDescs)
	w.serveArtifact(fx)
	delete(w.feedStore.Feeds, w.repoTopic)

	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("verified artifact creation must succeed: %v", err)
	}
	if result.OperationID != generated || result.Reference != req.Reference {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != req.Reference {
		t.Fatalf("feed must be created at the target, got %q", got)
	}
}

// TestFeedSignerAcceptsExistingReferencedBlobsNoNewRecords proves an existing
// publication whose artifact references blobs ALREADY recorded (no new blob
// records) plus an unrelated retained blob is accepted: the transition needs
// no additions at all, and the reference set must still resolve.
func TestFeedSignerAcceptsExistingReferencedBlobsNoNewRecords(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	digestA := digestRef('a')
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	unrelated := fixtureRef('9')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	curBlobs := withBlobs(map[string]spec.BlobDescriptor{
		unrelated: {SwarmRef: refHex('9'), Size: 7, MediaType: fixtureBlobMediaType},
	}, fx)
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: digestA},
		map[string]spec.TagPublication{tag: {OperationID: "op-cur", Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{tag: digestA}, nil),
		curBlobs)
	// The operated digest is ADDED; every blob record (referenced and
	// unrelated) stays byte-identical — the unrelated retained blob is not
	// new, so it needs no reference.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 2, Digest: fx.digest}},
		operatedManifests(manifestsForTags(map[string]string{tag: fx.digest},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42)}), fx),
		curBlobs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	if _, err := signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("existing referenced blobs + unrelated retained blob must succeed: %v", err)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
}

// TestFeedSignerRejectsUnreferencedNewBlobRecord is the CORE finding-1
// regression: a target that adds a NEW blob record the operated artifact does
// NOT reference is rejected as malformed with ZERO external updates — a blob
// mapping can no longer be smuggled into the committed state.
func TestFeedSignerRejectsUnreferencedNewBlobRecord(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	digestA := digestRef('a')
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	extra := fixtureRef('9')
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: digestA},
		map[string]spec.TagPublication{tag: {OperationID: "op-cur", Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{tag: digestA}, nil),
		map[string]spec.BlobDescriptor{})
	targetBlobs := withBlobs(map[string]spec.BlobDescriptor{
		extra: {SwarmRef: refHex('9'), Size: 7, MediaType: fixtureBlobMediaType},
	}, fx)
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 2, Digest: fx.digest}},
		operatedManifests(manifestsForTags(map[string]string{tag: fx.digest},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42)}), fx),
		targetBlobs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("unreferenced NEW blob record must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("unreferenced blob must cause ZERO external updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance, got %q", got)
	}
}

// TestFeedSignerRejectsWrongManifestBytesAtOperatedRef proves the signer
// verifies the operated manifest BODY by content digest: bytes at the
// descriptor's SwarmRef that hash to a DIFFERENT digest are malformed with
// zero updates — the feed can no longer be pointed at a document whose
// manifest object does not match its recorded digest.
func TestFeedSignerRejectsWrongManifestBytesAtOperatedRef(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	digestA := digestRef('a')
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: digestA},
		map[string]spec.TagPublication{tag: {OperationID: "op-cur", Generation: 1, Digest: digestA}},
		manifestsForTags(map[string]string{tag: digestA}, nil),
		map[string]spec.BlobDescriptor{})
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 2, Digest: fx.digest}},
		operatedManifests(manifestsForTags(map[string]string{tag: fx.digest},
			map[string]spec.ManifestDescriptor{digestA: fixtureManifestDescriptor(42)}), fx),
		fx.blobDescs)
	// Serve DIFFERENT well-formed manifest bytes at the operated SwarmRef.
	w.serveArtifact(simpleArtifact(t, '1', '4', '5', 200, 200))

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("wrong manifest bytes must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("wrong bytes must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsManifestSizeMismatch proves the operated descriptor's
// size must equal the ACTUAL read body size.
func TestFeedSignerRejectsManifestSizeMismatch(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	desc := fx.manifest
	desc.Size = fx.manifest.Size + 1 // descriptor lies about the body size
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: desc},
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("manifest size mismatch must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("size mismatch must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsUnsupportedManifestMediaType proves an operated
// manifest whose descriptor media type is not one of the four supported
// artifact types is rejected before any update.
func TestFeedSignerRejectsUnsupportedManifestMediaType(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	desc := fx.manifest
	desc.MediaType = "text/plain"
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: desc},
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("unsupported manifest media type must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("unsupported media type must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsIndexPublicationUntilTask19 proves the operated
// manifest object may NOT be an image index: index publication is rejected
// (the Task 19 gate) as malformed with zero updates, even for a fully valid
// zero-reference index whose content digest and descriptor sizes match.
func TestFeedSignerRejectsIndexPublicationUntilTask19(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	body := fixtureEmptyIndexBody(t)
	digest := publish.ComputeDigest(body)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, digest, req.ExpectedGeneration)
	req.OperationID = generated
	swarmRef := refHex('7')
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: digest}},
		map[string]spec.ManifestDescriptor{digest: {SwarmRef: swarmRef, MediaType: fixtureIndexMediaType, Size: int64(len(body))}},
		map[string]spec.BlobDescriptor{})
	w.serveArtifact(artifactFixture{body: body, digest: digest, manifest: spec.ManifestDescriptor{SwarmRef: swarmRef, MediaType: fixtureIndexMediaType, Size: int64(len(body))}})

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("index publication must fail closed as malformed (Task 19 gate), got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("index publication must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsReferencedBlobMissingFromTarget proves every digest
// the verified artifact references must exist in the target blob records.
func TestFeedSignerRejectsReferencedBlobMissingFromTarget(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	// The layer record is recorded; the CONFIG record is silently dropped.
	blobs := map[string]spec.BlobDescriptor{}
	for d, b := range fx.blobDescs {
		if d == fx.references[0].Digest {
			continue
		}
		blobs[d] = b
	}
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		blobs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("missing referenced blob must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("missing referenced blob must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsReferencedBlobSizeMismatch proves a referenced blob
// record whose SIZE disagrees with the artifact's descriptor fails closed.
func TestFeedSignerRejectsReferencedBlobSizeMismatch(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	blobs := map[string]spec.BlobDescriptor{}
	for d, b := range fx.blobDescs {
		if d == fx.references[0].Digest {
			b = spec.BlobDescriptor{SwarmRef: b.SwarmRef, Size: b.Size + 1, MediaType: b.MediaType}
		}
		blobs[d] = b
	}
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		blobs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("referenced blob size mismatch must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("size mismatch must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsReferencedBlobMediaMismatch proves a referenced blob
// record whose CONCRETE media type conflicts with the artifact descriptor's
// (under the exact normalization contract the data plane enforces) fails
// closed; only empty/octet-stream stored placeholders are transparent.
func TestFeedSignerRejectsReferencedBlobMediaMismatch(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	blobs := map[string]spec.BlobDescriptor{}
	for d, b := range fx.blobDescs {
		if d == fx.references[0].Digest {
			b = spec.BlobDescriptor{SwarmRef: b.SwarmRef, Size: b.Size, MediaType: "text/plain"}
		}
		blobs[d] = b
	}
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		blobs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("referenced blob media conflict must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("media conflict must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsOversizedManifestRead proves the signer's bounded read
// NEVER touches an object beyond publish.MaxArtifactBodyBytes: the reader's
// overflow signal is a data-free BACKEND error with zero updates (the
// signer's own body bound is already enforced by the parser; the reader's
// bound protects the signer from unbounded buffering).
func TestFeedSignerRejectsOversizedManifestRead(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		fx.blobDescs)
	w.bytes.serve(fx.manifest.SwarmRef, make([]byte, publish.MaxArtifactBodyBytes+1))

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("oversized manifest body must fail closed as backend, got %v", err)
	}
	if strings.Contains(err.Error(), fx.manifest.SwarmRef) {
		t.Fatalf("oversize error must be data-free: %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("oversized read must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsManifestReadFailure proves an unreadable operated
// manifest object (missing/transport failure — the reader's data-free error)
// is a backend condition with zero updates: the signer never signs a
// transition whose manifest content it could not independently read.
func TestFeedSignerRejectsManifestReadFailure(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		fx.blobDescs)
	// The object is deliberately NOT served.

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("unreadable manifest object must fail closed as backend, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("read failure must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerNilBytesReaderFailsClosed proves an unconfigured bounded
// /bytes reader (or any typed nil) fails closed as a backend error before any
// work — the production wiring must always provide it.
func TestFeedSignerNilBytesReaderFailsClosed(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)

	var nilBytes *memoryBytesReader
	signer := &FeedSigner{Store: w.store, Feeds: w.feedStore, ResolveFeeds: w.feedStore, Docs: w.docs, Bytes: nilBytes}
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("signer without a bounded bytes reader must fail closed as backend, got %v", err)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance with an unconfigured bytes reader, got %q", got)
	}
}

// TestFeedSignerSameDigestCoherentRepublishAccepted proves the same-digest
// republish shape: the operated descriptor is the REAL artifact's (identical
// digest/ref/size/media), the provenance entry is replaced, existing blob
// records are retained — exactly one transition, one update.
func TestFeedSignerSameDigestCoherentRepublishAccepted(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: "op-cur", Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fixtureManifestDescriptor(42)},
		fx.blobDescs)
	// Same digest republished: descriptor now the REAL one (content-addressed
	// identity CANNOT change its bytes), provenance entry replaced, blob
	// records byte-identical.
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 2,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 2, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	if _, err := signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("coherent same-digest republish must succeed: %v", err)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
}

// TestFeedSignerDonePathVerifiesOperatedArtifact proves the already-advanced
// (done) recovery path ALSO runs the independent artifact proof: a document
// whose operated manifest object bytes do not match the recorded digest fails
// closed as malformed with zero updates and the claim released.
func TestFeedSignerDonePathVerifiesOperatedArtifact(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('a'), currentGen: 1, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.feedStore.Feeds[w.repoTopic] = refHex('a')
	w.docs.Documents[refHex('a')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		fx.blobDescs)
	w.serveArtifact(simpleArtifact(t, '1', '6', '7', 300, 300)) // WRONG bytes at the ref
	hash := NormalizeFeedCommitHash(req)
	if _, err := w.store.ReserveFeedSignerOperation(context.Background(), req.OperationID, w.registry.ID, w.repoTopic, hash); err != nil {
		t.Fatalf("pre-reserve: %v", err)
	}

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("done path with wrong manifest bytes must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("done-path artifact failure must cause ZERO external updates, got %d", n)
	}
	op, err := w.store.GetFeedSignerOperation(context.Background(), req.OperationID)
	if err != nil {
		t.Fatalf("load operation: %v", err)
	}
	if op.State != FeedSignerOpPending {
		t.Fatalf("definite done-path failure must release the claim to pending, got %q", op.State)
	}
}

// --- Finding 2: atomic generated-operation-ID reserve ----------------------------

// TestFeedSignerGeneratedCommitAtomicallyReservesBinding proves the signer's
// generated path does NOT decide on a stale absence: the commit ATOMICALLY
// RESERVES its own permanent binding row (insert-or-read) for the exact
// deterministic generated ID. After the commit the row exists with the exact
// registry+hash (row permanence), and a CONCURRENT conflicting explicit
// preflight for the same key — signer-reserve-first ordering — reads the
// signer's row and LOSES (no bypass), never overwriting it.
func TestFeedSignerGeneratedCommitAtomicallyReservesBinding(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("generated commit must succeed: %v", err)
	}
	if result.OperationID != generated {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
	wantHash := NormalizePublicationBindingHash(req.RegistryID, req.Owner, testRepo, tag, fx.digest)
	regID, stored := bindingRow(t, w.store, generated)
	if regID != req.RegistryID || stored != wantHash {
		t.Fatalf("generated commit must reserve its OWN permanent binding row (reg=%d want %d, hash match=%v)", regID, req.RegistryID, stored == wantHash)
	}

	// A conflicting explicit preflight racing the SAME key now reads the
	// signer's row: it must NOT win (the insert-or-read serialization point
	// already decided). Reserve returns the signer's row; the caller-side
	// hash check rejects the conflict.
	conflicting := NormalizePublicationBindingHash(req.RegistryID, req.Owner, testRepo, tag, fx.digest+"x")
	if conflicting == wantHash {
		t.Fatal("fixture conflict hash must differ")
	}
	got, err := w.store.ReservePublicationBinding(context.Background(), generated, req.RegistryID, conflicting)
	if err != nil {
		t.Fatalf("conflicting preflight after the signer: %v", err)
	}
	if got.RegistryID != req.RegistryID || got.BindingHash != wantHash {
		t.Fatalf("conflicting preflight must observe the signer's winning row (hash match=%v)", got.BindingHash == wantHash)
	}
	if n := bindingRowCount(t, w.store, generated); n != 1 {
		t.Fatalf("exactly one binding row must ever exist for the generated ID, got %d", n)
	}

	// The row is PERMANENT: still the signer's after the losing preflight.
	regID, stored = bindingRow(t, w.store, generated)
	if stored != wantHash {
		t.Fatal("the generated identity's binding row must remain the signer's own")
	}
}

// TestFeedSignerPreflightFirstGeneratedCommitZeroUpdates proves the
// preflight-conflicting-first ordering: a permanent preflight binding for the
// generated-looking key over a DIFFERENT payload makes the signer's commit
// conflict BEFORE the updater — zero updates, feed untouched, claim released
// to pending, the preflight's row permanent across a retry.
func TestFeedSignerPreflightFirstGeneratedCommitZeroUpdates(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	// The preflight reserved the generated-looking key for a DIFFERENT digest.
	conflicting := NormalizePublicationBindingHash(req.RegistryID, req.Owner, testRepo, tag, digestRef('9'))
	if _, err := w.store.ReservePublicationBinding(context.Background(), generated, req.RegistryID, conflicting); err != nil {
		t.Fatalf("seed preflight binding: %v", err)
	}
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		fx.blobDescs)
	w.serveArtifact(fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("preflight-first conflicting binding must fail closed as a conflict, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("conflict must cause ZERO external updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance, got %q", got)
	}
	// Definite pre-update failure: the claim is released for a later retry.
	op, err := w.store.GetFeedSignerOperation(context.Background(), req.OperationID)
	if err != nil {
		t.Fatalf("load operation: %v", err)
	}
	if op.State != FeedSignerOpPending {
		t.Fatalf("definite conflict must release the claim to pending, got %q", op.State)
	}
	// The preflight's row is PERMANENT: an identical retry conflicts again
	// with zero updates.
	if _, err := signer.Commit(context.Background(), req); !errors.Is(err, errFeedSignerConflict) {
		t.Fatalf("retry must conflict again against the permanent preflight row, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("retry must cause ZERO external updates, got %d", n)
	}
	regID, stored := bindingRow(t, w.store, generated)
	if regID != req.RegistryID || stored != conflicting {
		t.Fatal("the preflight's permanent row must remain authoritative")
	}
}

// TestFeedSignerExplicitUnboundKeyNeverAutoReserved proves the signer NEVER
// auto-reserves an arbitrary EXPLICIT caller key: an explicit ID with no
// preflight row fails as malformed AND leaves zero binding rows behind — only
// the exact deterministic generated identity may be reserved by the signer.
func TestFeedSignerExplicitUnboundKeyNeverAutoReserved(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.OperationID = "arbitrary-explicit-key"
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: req.OperationID, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
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
	if n := bindingRowCount(t, w.store, req.OperationID); n != 0 {
		t.Fatalf("the signer must NEVER reserve an arbitrary explicit identity, got %d rows", n)
	}
}

// TestFeedSignerMatchingConcurrentGeneratedCommitsOneUpdate proves the
// matching-concurrency ordering across INDEPENDENT Store instances over one
// database: two identical generated-ID commits both succeed (their atomic
// reserves serialize on ONE matching row — no deadlock, no duplicate rows),
// exactly one external update happens, the feed advances once, and the
// operation is terminal.
func TestFeedSignerMatchingConcurrentGeneratedCommitsOneUpdate(t *testing.T) {
	const tag = "latest"
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)

	// The provenance entry needs the registry ID, which the shared world
	// creates — so the doc is built with an EMPTY provenance map first and
	// the operated entry is filled in below (same pattern as the round-4
	// two-store tests).
	w := newSharedFeedWorld(t, 2,
		map[string]string{spec.RepoStateFeedRef(testFeedOwner, testRepo): refHex('b'), spec.StampPolicyFeedRef(testFeedOwner): refHex('c')},
		map[string][]byte{
			refHex('b'): mustRepoDoc(t, testRepo, 0),
			refHex('a'): transitionDoc(t, testRepo, 1,
				map[string]string{tag: fx.digest},
				nil,
				map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
				fx.blobDescs),
			refHex('c'): mustStampDoc(t, "batch-1"),
		})
	w.serve(fx)

	req := validCommitReq(w.reg.ID, "batch-1")
	req.Owner = "0x" + testFeedOwner
	req.Topic = w.topic
	req.Reference = refHex('a')
	req.ExpectedGeneration = 0
	key := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = key
	w.docs.Documents[refHex('a')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: key, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		fx.blobDescs)

	const n = 2
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	errs := make([]error, n)
	results := make([]publish.FeedCommitResult, n)
	for i := 0; i < n; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			results[i], errs[i] = w.signers[i].Commit(context.Background(), req)
		}(i)
	}
	start.Done()
	done.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("signer %d: matching concurrent generated commit must succeed, got %v", i, errs[i])
		}
		if results[i].OperationID != key || results[i].Reference != refHex('a') {
			t.Fatalf("signer %d: unexpected result: %+v", i, results[i])
		}
	}
	if got := w.updater.count(); got != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", got)
	}
	if n := bindingRowCount(t, w.stores[0], key); n != 1 {
		t.Fatalf("matching concurrent reserves must yield exactly ONE binding row, got %d", n)
	}
	wantHash := NormalizePublicationBindingHash(w.reg.ID, req.Owner, testRepo, tag, fx.digest)
	regID, stored := bindingRow(t, w.stores[0], key)
	if regID != w.reg.ID || stored != wantHash {
		t.Fatalf("the single binding row must match the exact payload (row hash match=%v)", stored == wantHash)
	}
	op, err := w.stores[0].GetFeedSignerOperation(context.Background(), req.OperationID)
	if err != nil || op.State != FeedSignerOpSucceeded {
		t.Fatalf("operation must be terminal succeeded (err=%v state=%q)", err, op.State)
	}
}

// TestStoreReservePublicationBindingSerializesTwoOrderings pins the store
// serialization point itself across INDEPENDENT Store instances over one
// database, for BOTH deterministic orderings: the first committed reserve
// wins, the second observes the very same row (never a stale absence, never a
// duplicate), and identical-hash contenders all pass through the same row.
func TestStoreReservePublicationBindingSerializesTwoOrderings(t *testing.T) {
	const dsn = "file:bindserial_round5?mode=memory&cache=shared"
	storeA, errA := OpenSQLite(dsn)
	if errA != nil {
		t.Fatal(errA)
	}
	defer storeA.DB.Close()
	storeB, errB := OpenSQLite(dsn)
	if errB != nil {
		t.Fatal(errB)
	}
	defer storeB.DB.Close()
	reg, _ := seedBindingRegistry(t, storeA)
	ctx := context.Background()

	const key = "op-round5-serialization"
	hashA := NormalizePublicationBindingHash(reg.ID, testFeedOwner, "repo1", "latest", digestRef('a'))
	hashB := NormalizePublicationBindingHash(reg.ID, testFeedOwner, "repo1", "latest", digestRef('b'))

	// Ordering 1: storeA reserves hashA first; storeB's conflicting reserve
	// reads the SAME row (hashA) — one winner, no bypass.
	first, err := storeA.ReservePublicationBinding(ctx, key, reg.ID, hashA)
	if err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	second, err := storeB.ReservePublicationBinding(ctx, key, reg.ID, hashB)
	if err != nil {
		t.Fatalf("second reserve: %v", err)
	}
	if first.BindingHash != hashA || second.BindingHash != hashA || second != first {
		t.Fatalf("conflicting reserve must observe the FIRST committed row, got %v and %v", first, second)
	}
	if n := bindingRowCount(t, storeA, key); n != 1 {
		t.Fatalf("exactly one row must exist, got %d", n)
	}

	// Ordering 2 (fresh key, reverse order on stores): storeB commits first,
	// storeA observes it.
	const key2 = "op-round5-serialization-reverse"
	first2, err := storeB.ReservePublicationBinding(ctx, key2, reg.ID, hashB)
	if err != nil {
		t.Fatalf("reverse first reserve: %v", err)
	}
	second2, err := storeA.ReservePublicationBinding(ctx, key2, reg.ID, hashA)
	if err != nil {
		t.Fatalf("reverse second reserve: %v", err)
	}
	if first2.BindingHash != hashB || second2.BindingHash != hashB || second2 != first2 {
		t.Fatalf("reverse ordering must still decide one winner, got %v and %v", first2, second2)
	}

	// Identical-hash CONCURRENT contenders across both stores: all pass
	// through the one row, no deadlock, no duplicate.
	const key3 = "op-round5-serialization-matching"
	const contenders = 12
	var wg sync.WaitGroup
	seen := make([][32]byte, contenders)
	errs := make([]error, contenders)
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var store *Store
			if i%2 == 0 {
				store = storeA
			} else {
				store = storeB
			}
			b, err := store.ReservePublicationBinding(ctx, key3, reg.ID, hashA)
			seen[i] = b.BindingHash
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("matching contender %d: %v", i, errs[i])
		}
		if seen[i] != hashA {
			t.Fatalf("matching contender %d must read the common row, got a different hash", i)
		}
	}
	if n := bindingRowCount(t, storeA, key3); n != 1 {
		t.Fatalf("matching concurrent reserves must yield exactly ONE row, got %d", n)
	}
}

// TestFeedSignerGeneratedReserveDBFailureIsBackend proves a reserve/DB
// failure on the generated path is a backend (uncertain) error — zero
// updates, data-free — and NEVER falls back to accepting without a binding.
func TestFeedSignerGeneratedReserveDBFailureIsBackend(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[req.Reference] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		fx.blobDescs)
	w.serveArtifact(fx)
	// Break the binding table where the atomic reserve is made.
	if _, err := w.store.DB.ExecContext(context.Background(), `drop table publication_bindings`); err != nil {
		t.Fatalf("drop binding table: %v", err)
	}

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("reserve failure must be a backend error (never accepted without a binding), got %v", err)
	}
	if strings.Contains(err.Error(), generated) || strings.Contains(err.Error(), fx.digest) || strings.Contains(err.Error(), "latest") {
		t.Fatalf("reserve-failure error must carry no request values: %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("reserve failure must cause ZERO external updates, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('b') {
		t.Fatalf("feed must not advance, got %q", got)
	}
}

// TestFeedSignerDoneRecoveryGeneratedReservesBinding proves the done path for
// a generated identity ALSO atomically reserves/commits its own binding row
// (self-healing recovery: a pre-fix publication with no row acquires it; an
// existing row must match), with zero updater calls.
func TestFeedSignerDoneRecoveryGeneratedReservesBinding(t *testing.T) {
	const tag = "latest"
	req := validCommitReq(1, "batch-1")
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('a'), currentGen: 1, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.feedStore.Feeds[w.repoTopic] = refHex('a')
	w.docs.Documents[refHex('a')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		fx.blobDescs)
	w.serveArtifact(fx)
	hash := NormalizeFeedCommitHash(req)
	if _, err := w.store.ReserveFeedSignerOperation(context.Background(), req.OperationID, w.registry.ID, w.repoTopic, hash); err != nil {
		t.Fatalf("pre-reserve: %v", err)
	}

	signer, updater := w.countingSigner()
	if _, err := signer.Commit(context.Background(), req); err != nil {
		t.Fatalf("done-path generated recovery must succeed: %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("done-path recovery must not re-run the external update, got %d", n)
	}
	wantHash := NormalizePublicationBindingHash(req.RegistryID, req.Owner, testRepo, tag, fx.digest)
	regID, stored := bindingRow(t, w.store, generated)
	if regID != req.RegistryID || stored != wantHash {
		t.Fatalf("done path must reserve its own permanent binding row (hash match=%v)", stored == wantHash)
	}
}

// TestFeedSignerCrossStoreReserveThenAdoptionConflict pinpoints that the
// binding-reserve serialization is visible across independent Store instances
// AND takes precedence over adoption-driven candidate derivation: the signer
// with the conflicting preflight row conflicts with zero updates even when a
// migration-9 quarantine row is present and untouched.
func TestFeedSignerCrossStoreReserveThenAdoptionConflict(t *testing.T) {
	const tag = "latest"
	fx := simpleArtifact(t, '1', '2', '3', 100, 100)

	w := newSharedFeedWorld(t, 2,
		map[string]string{spec.RepoStateFeedRef(testFeedOwner, testRepo): refHex('b'), spec.StampPolicyFeedRef(testFeedOwner): refHex('c')},
		map[string][]byte{
			refHex('b'): mustRepoDoc(t, testRepo, 0),
			refHex('a'): transitionDoc(t, testRepo, 1,
				map[string]string{tag: fx.digest},
				nil,
				map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
				fx.blobDescs),
			refHex('c'): mustStampDoc(t, "batch-1"),
		})
	w.serve(fx)

	req := validCommitReq(w.reg.ID, "batch-1")
	req.Owner = "0x" + testFeedOwner
	req.Topic = w.topic
	req.Reference = refHex('a')
	req.ExpectedGeneration = 0
	key := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = key
	w.docs.Documents[refHex('a')] = transitionDoc(t, testRepo, 1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: key, Generation: 1, Digest: fx.digest}},
		map[string]spec.ManifestDescriptor{fx.digest: fx.manifest},
		fx.blobDescs)

	conflicting := NormalizePublicationBindingHash(w.reg.ID, req.Owner, testRepo, tag, digestRef('9'))
	if _, err := w.stores[1].ReservePublicationBinding(context.Background(), key, w.reg.ID, conflicting); err != nil {
		t.Fatalf("seed conflicting preflight through store 1: %v", err)
	}

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(2)
	successes := 0
	var firstErr error
	var mu sync.Mutex
	run := func(signer *FeedSigner) {
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
	go run(w.signers[0])
	go run(w.signers[1])
	start.Done()
	done.Wait()

	if successes != 0 {
		t.Fatalf("no request may succeed against the conflicting preflight, got %d", successes)
	}
	if firstErr == nil || !errors.Is(firstErr, errFeedSignerConflict) {
		t.Fatalf("both stores must conflict against the preflight row, first err %v", firstErr)
	}
	if n := w.updater.count(); n != 0 {
		t.Fatalf("must cause ZERO external updates, got %d", n)
	}
	if n := bindingRowCount(t, w.stores[0], key); n != 1 {
		t.Fatalf("exactly one permanent preflight row, got %d", n)
	}
	regID, stored := bindingRow(t, w.stores[0], key)
	if regID != w.reg.ID || stored != conflicting {
		t.Fatal("the preflight's permanent row must remain authoritative")
	}
}
