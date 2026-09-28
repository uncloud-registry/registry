package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
)

// Index fixture helpers for the Task-19 round-1 signer proof: a real committed
// single-platform child manifest and a real OCI image index referencing it.

// indexChildFixture is a committed single-platform child manifest an index
// references: the REAL body, its digest, the exact committed record, and the
// index's reference descriptor (matching the committed bytes).
type indexChildFixture struct {
	body     []byte
	digest   string
	manifest spec.ManifestDescriptor
	ref      publish.Descriptor
}

// makeChild builds a REAL config-only single-platform manifest fixture (the
// same DefaultBuilder artifact the data plane commits for a child manifest).
func makeChild(t *testing.T, swarmByte, cfgByte byte, cfgSize int64) indexChildFixture {
	t.Helper()
	fx := buildArtifact(t, swarmByte, manifestRef{digestByte: cfgByte, size: cfgSize, mediaType: fixtureConfigMediaType})
	ref := publish.Descriptor{MediaType: fx.manifest.MediaType, Digest: fx.digest, Size: fx.manifest.Size}
	return indexChildFixture{body: fx.body, digest: fx.digest, manifest: fx.manifest, ref: ref}
}

// indexFixture is an OCI image index whose children are the given committed
// single-platform manifests.
type indexFixture struct {
	body     []byte
	digest   string
	manifest spec.ManifestDescriptor
	children []indexChildFixture
}

// buildIndex assembles a REAL OCI image index body referencing the given
// children with exact digests/sizes/media types. arch is a per-child
// disambiguator only; the signer does not re-enforce builder platform rules.
func buildIndex(t *testing.T, arch string, children ...indexChildFixture) indexFixture {
	t.Helper()
	childJSON := make([]map[string]any, 0, len(children))
	for _, c := range children {
		childJSON = append(childJSON, map[string]any{
			"mediaType": c.ref.MediaType,
			"digest":    c.ref.Digest,
			"size":      c.ref.Size,
			"platform":  map[string]any{"architecture": arch, "os": "linux"},
		})
	}
	idx := map[string]any{"schemaVersion": 2, "mediaType": fixtureIndexMediaType, "manifests": childJSON}
	body, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal index fixture: %v", err)
	}
	return indexFixture{
		body:     body,
		digest:   publish.ComputeDigest(body),
		manifest: spec.ManifestDescriptor{SwarmRef: refHex('9'), MediaType: fixtureIndexMediaType, Size: int64(len(body))},
		children: children,
	}
}

// indexWorld seeds an index signer fixture where the CURRENT state already has
// the given children committed and returns the world plus the request to
// commit. The operated index fixture is served through the bounded /bytes
// reader. The tag transition uses the generated identity for fx.digest at the
// given generation.
func indexWorld(t *testing.T, tag string, curGen int64, children []indexChildFixture, fx indexFixture) (*feedTestWorld, publish.FeedCommitRequest) {
	t.Helper()
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorldFile(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: curGen,
		targetRef: refHex('a'), targetGen: curGen + 1,
		stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = curGen
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated

	// Current state: children committed verbatim.
	curManifests := map[string]spec.ManifestDescriptor{}
	for _, c := range children {
		curManifests[c.digest] = c.manifest
	}
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, curGen,
		map[string]string{}, map[string]spec.TagPublication{}, curManifests, map[string]spec.BlobDescriptor{})

	// Target state: children preserved + the operated index descriptor.
	opfx := artifactFixture{body: fx.body, digest: fx.digest, manifest: fx.manifest}
	targetManifests := operatedManifests(curManifests, opfx)
	w.docs.Documents[refHex('a')] = transitionDoc(t, testRepo, curGen+1,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: curGen + 1, Digest: fx.digest}},
		targetManifests,
		map[string]spec.BlobDescriptor{})

	// Serve the operated index body AND every committed child body through the
	// bounded /bytes reader at the exact SwarmRefs the document records.
	w.bytes.serve(fx.manifest.SwarmRef, fx.body)
	for _, c := range children {
		w.bytes.serve(c.manifest.SwarmRef, c.body)
	}
	return w, req
}

// TestFeedSignerAcceptsIndexTransitionWithCommittedChildren proves the
// production signer now accepts a valid image-index feed transition (Task 19
// gate lifted): the operated index is independently parsed, every child is
// verified against the committed manifest map (supported type, exact size and
// media, bounded body read with digest AND byte-length proof, not a nested
// index), the blob map is preserved byte-identically, and exactly one feed
// update happens.
func TestFeedSignerAcceptsIndexTransitionWithCommittedChildren(t *testing.T) {
	const tag = "latest"
	c1 := makeChild(t, '1', 'a', 100)
	c2 := makeChild(t, '2', 'b', 101)
	fx := buildIndex(t, "amd64", c1, c2)
	w, req := indexWorld(t, tag, 1, []indexChildFixture{c1, c2}, fx)

	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("valid index transition must be accepted by the signer: %v", err)
	}
	if result.Feed != w.repoTopic || result.Reference != refHex('a') {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != refHex('a') {
		t.Fatalf("feed must advance to the index target, got %q", got)
	}
}

// TestFeedSignerRejectsIndexChildSizeMismatch isolates the child-size proof: a
// child whose committed record's size disagrees with the index reference is
// malformed with ZERO external updates.
func TestFeedSignerRejectsIndexChildSizeMismatch(t *testing.T) {
	const tag = "latest"
	c1 := makeChild(t, '1', 'a', 100)
	c2 := makeChild(t, '2', 'b', 101)
	// Declare c2 with a size differing from its committed record.
	fx := buildIndex(t, "amd64", c1, indexChildFixture{
		body: c2.body, digest: c2.digest, manifest: c2.manifest,
		ref: publish.Descriptor{MediaType: c2.ref.MediaType, Digest: c2.ref.Digest, Size: c2.ref.Size + 1},
	})
	w, req := indexWorld(t, tag, 1, []indexChildFixture{c1, c2}, fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("child size mismatch must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("child size mismatch must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsIndexChildUnsupportedMediaType isolates the supported-
// child-media-type proof: an index reference whose media type is not a
// supported single-platform child manifest (here a nesting index type) is
// malformed with zero updates.
func TestFeedSignerRejectsIndexChildUnsupportedMediaType(t *testing.T) {
	const tag = "latest"
	c1 := makeChild(t, '1', 'a', 100)
	c2 := makeChild(t, '2', 'b', 101)
	fx := buildIndex(t, "amd64", c1, indexChildFixture{
		body: c2.body, digest: c2.digest, manifest: c2.manifest,
		ref: publish.Descriptor{MediaType: fixtureIndexMediaType, Digest: c2.ref.Digest, Size: c2.ref.Size},
	})
	w, req := indexWorld(t, tag, 1, []indexChildFixture{c1, c2}, fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("unsupported/nested child media type must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("unsupported/nested child media type must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsNestedIndexChildBody proves the signer independently
// parses each child under its declared media type and rejects a child whose
// BODY is itself an index (recursive nested index), zero updates.
func TestFeedSignerRejectsNestedIndexChildBody(t *testing.T) {
	const tag = "latest"
	c1 := makeChild(t, '1', 'a', 100)
	// A child whose committed BODY is itself an empty image index.
	nestedBody := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	nestedDigest := publish.ComputeDigest(nestedBody)
	nestedManifest := spec.ManifestDescriptor{SwarmRef: refHex('4'), MediaType: fixtureIndexMediaType, Size: int64(len(nestedBody))}
	nested := indexChildFixture{body: nestedBody, digest: nestedDigest, manifest: nestedManifest,
		ref: publish.Descriptor{MediaType: fixtureIndexMediaType, Digest: nestedDigest, Size: int64(len(nestedBody))}}
	fx := buildIndex(t, "amd64", c1, nested)
	w, req := indexWorld(t, tag, 1, []indexChildFixture{c1, nested}, fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("nested-index child body must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("nested-index child body must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsIndexChildByteLengthMismatch isolates the byte-length
// proof: a child whose ACTUAL served body length disagrees with the declared
// size (even when the recorded descriptor and the index reference agree on
// that size, and the digest matches) is malformed with zero updates.
func TestFeedSignerRejectsIndexChildByteLengthMismatch(t *testing.T) {
	const tag = "latest"
	c1 := makeChild(t, '1', 'a', 100)
	c2 := makeChild(t, '2', 'b', 101)
	// Both the committed record and the index reference claim size wrong
	// (larger than the real body); the real body is served so its digest
	// matches but its byte length does not.
	wrong := int64(len(c2.body)) + 7
	childRec := spec.ManifestDescriptor{SwarmRef: c2.manifest.SwarmRef, MediaType: c2.manifest.MediaType, Size: wrong}
	c2wrong := indexChildFixture{body: c2.body, digest: c2.digest, manifest: c2.manifest,
		ref: publish.Descriptor{MediaType: c2.ref.MediaType, Digest: c2.ref.Digest, Size: wrong}}
	fx := buildIndex(t, "amd64", c1, c2wrong)
	// Override the committed child record size to the SAME wrong value so the
	// size-vs-size checks pass; only the byte-length proof can catch it.
	curManifests := map[string]spec.ManifestDescriptor{c1.digest: c1.manifest, c2.digest: childRec}

	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorldFile(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1, map[string]string{}, map[string]spec.TagPublication{}, curManifests, map[string]spec.BlobDescriptor{})
	targetManifests := operatedManifests(curManifests, artifactFixture{body: fx.body, digest: fx.digest, manifest: fx.manifest})
	w.docs.Documents[refHex('a')] = transitionDoc(t, testRepo, 2,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 2, Digest: fx.digest}},
		targetManifests, map[string]spec.BlobDescriptor{})
	w.bytes.serve(fx.manifest.SwarmRef, fx.body)
	w.bytes.serve(c1.manifest.SwarmRef, c1.body)
	w.bytes.serve(c2.manifest.SwarmRef, c2.body)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("child byte-length mismatch must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("child byte-length mismatch must cause ZERO external updates, got %d", n)
	}
}
