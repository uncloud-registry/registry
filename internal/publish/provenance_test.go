package publish

import (
	"context"
	"testing"

	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// TestLegacyPublishMovesProvenanceTagSucceeds proves the legacy Publish path
// (no operation identity) can MOVE a tag that already carries durable
// publication provenance end-to-end: the stale provenance entry is REMOVED for
// the operated tag (never retained with the old digest — retaining it would
// make the derived document violate its own digest-coherence validation AFTER
// the manifest object was uploaded), unrelated tags' entries are retained
// verbatim, and the committed document still decodes and validates.
func TestLegacyPublishMovesProvenanceTagSucceeds(t *testing.T) {
	current := spec.RepoStateDocument{
		Version:    1,
		Repo:       "backend/api",
		Generation: 2,
		Tags:       map[string]string{"latest": dig('1'), "stable": dig('2')},
		Manifests: map[string]spec.ManifestDescriptor{
			dig('1'): {SwarmRef: "r-old", MediaType: ociManifestMT, Size: 10},
			dig('2'): {SwarmRef: "r-stable", MediaType: ociManifestMT, Size: 11},
		},
		Blobs: map[string]spec.BlobDescriptor{},
		TagPublications: map[string]spec.TagPublication{
			"latest": {OperationID: "op-prev-latest", Generation: 2, Digest: dig('1')},
			"stable": {OperationID: "op-stable", Generation: 1, Digest: dig('2')},
		},
	}
	if err := current.Validate(); err != nil {
		t.Fatalf("fixture current state must validate: %v", err)
	}

	input := validBuildInput(t)
	input.Manifest.SwarmRef = "swarm-ref-manifest-new"
	// input.OperationID deliberately left empty: the legacy publication path.

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	p := Publisher{Builder: DefaultBuilder{}, Objects: docs, Feeds: feeds}
	feed := spec.RepoStateFeedRef("0xaliceowner", "backend/api")

	if _, err := p.Publish(context.Background(), feed, current, input, "batch-1"); err != nil {
		t.Fatalf("legacy publish moving a provenance-bearing tag must succeed: %v", err)
	}

	// The committed document decodes, validates, and carries the moved tag
	// mapping WITHOUT the stale entry; the unrelated entry survives.
	stateRef := feeds.Feeds[feed]
	data, err := docs.Read(context.Background(), stateRef)
	if err != nil {
		t.Fatalf("read committed state: %v", err)
	}
	doc, err := spec.DecodeRepoStateDocument(data)
	if err != nil {
		t.Fatalf("decode committed state: %v", err)
	}
	if doc.Tags[input.Tag] != input.ManifestDigest {
		t.Fatalf("moved tag must point at the new digest: %+v", doc.Tags)
	}
	if _, ok := doc.TagPublications[input.Tag]; ok {
		t.Fatalf("legacy publish must REMOVE the operated tag's stale provenance entry, got %+v", doc.TagPublications[input.Tag])
	}
	if got := doc.TagPublications["stable"]; got != current.TagPublications["stable"] {
		t.Fatalf("unrelated tag provenance must be retained verbatim: %+v", got)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("committed legacy-moved state must validate: %v", err)
	}
}

// TestBuildNextRecordsPublicationProvenance proves DefaultBuilder persists
// the durable per-tag publication provenance entry (operation ID + applied
// generation + digest) for the published tag when the input carries an
// operation identity — the exact record the retry recognition reads back.
func TestBuildNextRecordsPublicationProvenance(t *testing.T) {
	input := validBuildInput(t)
	input.Manifest.SwarmRef = "swarm-ref-manifest"
	input.OperationID = "op-record-1"

	next, err := (DefaultBuilder{}).BuildNext(spec.RepoStateDocument{}, input)
	if err != nil {
		t.Fatalf("build next: %v", err)
	}
	pub, ok := next.TagPublications[input.Tag]
	if !ok {
		t.Fatalf("builder must record publication provenance for %q: %+v", input.Tag, next.TagPublications)
	}
	if pub.OperationID != "op-record-1" || pub.Generation != 1 || pub.Digest != input.ManifestDigest {
		t.Fatalf("provenance entry must be the exact (operationID, applied generation, digest): %+v", pub)
	}
	if next.Tags[input.Tag] != input.ManifestDigest {
		t.Fatalf("tag must point at the published digest: %+v", next.Tags)
	}
	if err := next.Validate(); err != nil {
		t.Fatalf("built state with provenance must validate: %v", err)
	}
}

// TestBuildNextRetainsUnrelatedProvenanceAndReplacesMovedTag proves the
// provenance is per-tag and bounded: an unrelated tag's entry survives the
// next publication, while re-pointing a tag REPLACES its entry — never an
// unbounded history, never an aliased map.
func TestBuildNextRetainsUnrelatedProvenanceAndReplacesMovedTag(t *testing.T) {
	config := spec.BlobDescriptor{SwarmRef: "s-c", Size: 24, MediaType: ociConfigMT}
	layer := spec.BlobDescriptor{SwarmRef: "s-a", Size: 1024, MediaType: ociLayerMT}
	current := spec.RepoStateDocument{
		Generation: 2,
		Tags:       map[string]string{"stable": "sha256:old"},
		Manifests: map[string]spec.ManifestDescriptor{
			"sha256:old": {SwarmRef: "r-old", MediaType: ociManifestMT, Size: 10},
		},
		Blobs: map[string]spec.BlobDescriptor{
			dig('c'): config,
			dig('a'): layer,
		},
		TagPublications: map[string]spec.TagPublication{
			"stable": {OperationID: "op-stable", Generation: 1, Digest: "sha256:old"},
		},
	}

	input := validBuildInput(t)
	input.Manifest.SwarmRef = "swarm-ref-manifest"
	input.OperationID = "op-new"

	next, err := (DefaultBuilder{}).BuildNext(current, input)
	if err != nil {
		t.Fatalf("build next: %v", err)
	}
	// Unrelated tag's provenance is retained verbatim.
	if got := next.TagPublications["stable"]; got != current.TagPublications["stable"] {
		t.Fatalf("unrelated tag provenance must be retained: %+v", got)
	}
	// The moved tag's entry is REPLACED with the new operation at the new
	// applied generation — no history is kept.
	if got := next.TagPublications[input.Tag]; got.OperationID != "op-new" || got.Generation != 3 || got.Digest != input.ManifestDigest {
		t.Fatalf("moved tag provenance must be replaced: %+v", got)
	}
	if len(next.TagPublications) != 2 {
		t.Fatalf("provenance must stay bounded to the current tag set, got %+v", next.TagPublications)
	}
	// The derived document validates BEFORE any test-only tampering below.
	if err := next.Validate(); err != nil {
		t.Fatalf("built state must validate: %v", err)
	}
	// No map aliasing: mutating the derived state must not mutate current.
	next.TagPublications["stable"] = spec.TagPublication{OperationID: "tampered", Generation: 9, Digest: "sha256:x"}
	if cur := current.TagPublications["stable"]; cur != (spec.TagPublication{OperationID: "op-stable", Generation: 1, Digest: "sha256:old"}) {
		t.Fatalf("builder output must not alias the current provenance map: %+v", cur)
	}
}

// TestBuildNextWithoutOperationIDWritesNoProvenance proves the legacy
// builder path (no operation identity) produces a valid document with NO
// provenance entry — the backward-compatible shape.
func TestBuildNextWithoutOperationIDWritesNoProvenance(t *testing.T) {
	input := validBuildInput(t)
	input.Manifest.SwarmRef = "swarm-ref-manifest"
	// input.OperationID left empty.

	next, err := (DefaultBuilder{}).BuildNext(spec.RepoStateDocument{}, input)
	if err != nil {
		t.Fatalf("build next: %v", err)
	}
	if next.TagPublications == nil {
		t.Fatal("derived state must carry a non-nil (possibly empty) provenance map")
	}
	if _, ok := next.TagPublications[input.Tag]; ok {
		t.Fatalf("no operation identity must not record provenance: %+v", next.TagPublications)
	}
	if err := next.Validate(); err != nil {
		t.Fatalf("built state without provenance must validate: %v", err)
	}
}

// TestPublishCommitRecordsProvenanceReadBack proves the full PublishCommit
// path persists the provenance entry into the committed state document, and
// the legacy Publish path (no operation identity) does not — the exact
// read-back the retry recognition and verification gate consume.
func TestPublishCommitRecordsProvenanceReadBack(t *testing.T) {
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	p := Publisher{Builder: DefaultBuilder{}, Objects: docs, Feeds: feeds}
	feed := spec.RepoStateFeedRef("0xaliceowner", "backend/api")

	input := validBuildInput(t)
	input.UpdatedAt = DeterministicUpdatedAt("op-t14r2-prov-1")

	receipt, err := p.PublishCommit(context.Background(), feed, spec.RepoStateDocument{}, input, "batch-1", 7, "0xaliceowner", "op-t14r2-prov-1")
	if err != nil {
		t.Fatalf("publish commit: %v", err)
	}
	stateRef := feeds.Feeds[feed]
	if stateRef != receipt.StateRef {
		t.Fatalf("feed target %q must equal the committed state ref %q", stateRef, receipt.StateRef)
	}
	data, err := docs.Read(context.Background(), stateRef)
	if err != nil {
		t.Fatalf("read committed state: %v", err)
	}
	doc, err := spec.DecodeRepoStateDocument(data)
	if err != nil {
		t.Fatalf("decode committed state: %v", err)
	}
	pub, ok := doc.TagPublications[input.Tag]
	if !ok || pub.OperationID != "op-t14r2-prov-1" || pub.Generation != 1 || pub.Digest != input.ManifestDigest {
		t.Fatalf("committed state must carry the exact provenance entry: %+v", doc.TagPublications)
	}

	// Legacy Publish path: no operation identity → no provenance entry.
	feeds2 := resolve.NewMemoryFeedStore()
	p2 := Publisher{Builder: DefaultBuilder{}, Objects: docs, Feeds: feeds2}
	if _, err := p2.Publish(context.Background(), feed, spec.RepoStateDocument{}, input, "batch-1"); err != nil {
		t.Fatalf("legacy publish: %v", err)
	}
	data2, err := docs.Read(context.Background(), feeds2.Feeds[feed])
	if err != nil {
		t.Fatalf("read legacy committed state: %v", err)
	}
	doc2, err := spec.DecodeRepoStateDocument(data2)
	if err != nil {
		t.Fatalf("decode legacy committed state: %v", err)
	}
	if _, ok := doc2.TagPublications[input.Tag]; ok {
		t.Fatalf("legacy publish must not record provenance: %+v", doc2.TagPublications)
	}
}
