package publish

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/spec"
)

// childSpec describes one index child manifest descriptor used to assemble an
// index body in tests.
type childSpec struct {
	mediaType string
	digest    string
	size      int64
	arch      string
	os        string
}

// makeIndex assembles an OCI image index (or Docker manifest list) body with
// the given top-level media type and child descriptors, returning the body.
func makeIndex(t *testing.T, mediaType string, children ...childSpec) []byte {
	t.Helper()
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[`, mediaType))
	for i, c := range children {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"mediaType":%q,"size":%d,"digest":%q`, c.mediaType, c.size, c.digest)
		if c.arch != "" || c.os != "" {
			fmt.Fprintf(&b, `,"platform":{"architecture":%q,"os":%q}`, c.arch, c.os)
		}
		b.WriteString("}")
	}
	b.WriteString("]}")
	return []byte(b.String())
}

// currentWithChildren returns repository state whose Manifests map already
// contains the two canonical single-platform child manifests with EXACT
// committed media type and size.
func currentWithChildren() spec.RepoStateDocument {
	return spec.RepoStateDocument{
		Version:    1,
		Generation: 2,
		Tags:       map[string]string{},
		Manifests: map[string]spec.ManifestDescriptor{
			dig('b'): {SwarmRef: "child-amd64-ref", MediaType: ociManifestMT, Size: 512},
			dig('d'): {SwarmRef: "child-arm64-ref", MediaType: ociManifestMT, Size: 513},
		},
		Blobs: map[string]spec.BlobDescriptor{},
	}
}

// indexInput builds a BuildInput whose manifest body is an OCI image index
// with the exact two-child shape of `ociIndex()` referencing the children
// committed by currentWithChildren.
func indexInput(t *testing.T) (BuildInput, []byte) {
	t.Helper()
	body := makeIndex(t, ociIndexMT,
		childSpec{mediaType: ociManifestMT, digest: dig('b'), size: 512, arch: "amd64", os: "linux"},
		childSpec{mediaType: ociManifestMT, digest: dig('d'), size: 513, arch: "arm64", os: "linux"},
	)
	return BuildInput{
		Repo:           "backend/api",
		Tag:            "multi",
		ManifestDigest: ComputeDigest(body),
		ManifestJSON:   body,
		Manifest:       spec.ManifestDescriptor{SwarmRef: "index-swarm-ref", MediaType: ociIndexMT, Size: int64(len(body))},
		StagedBlobs:    map[string]spec.BlobDescriptor{},
	}, body
}

// TestBuildNextIndexPublicationValid proves a two-platform OCI image index
// whose children are ALL committed in current state builds successfully: the
// index itself is recorded under its digest in the manifests map, the tag
// maps to it, the committed children are retained, and no blob records are
// fabricated for child manifests (they are manifests, not blobs).
func TestBuildNextIndexPublicationValid(t *testing.T) {
	input, _ := indexInput(t)
	next, err := (DefaultBuilder{}).BuildNext(currentWithChildren(), input)
	if err != nil {
		t.Fatalf("BuildNext of a valid index must succeed: %v", err)
	}
	if next.Generation != 3 {
		t.Fatalf("expected generation 3, got %d", next.Generation)
	}
	if next.Tags["multi"] != input.ManifestDigest {
		t.Fatalf("tag did not map to the index digest: %+v", next.Tags)
	}
	idx, ok := next.Manifests[input.ManifestDigest]
	if !ok || idx.MediaType != ociIndexMT || idx.Size != int64(len(input.ManifestJSON)) {
		t.Fatalf("index descriptor not recorded exactly: %+v", next.Manifests)
	}
	// Both committed children must be retained with their exact records.
	if got := next.Manifests[dig('b')]; got.SwarmRef != "child-amd64-ref" || got.Size != 512 {
		t.Fatalf("child amd64 not retained: %+v", got)
	}
	if got := next.Manifests[dig('d')]; got.SwarmRef != "child-arm64-ref" || got.Size != 513 {
		t.Fatalf("child arm64 not retained: %+v", got)
	}
	// Child manifests are not blobs; the blobs map must not contain them.
	if _, isBlob := next.Blobs[dig('b')]; isBlob {
		t.Fatalf("index child must not be recorded as a blob record: %+v", next.Blobs)
	}
}

// TestPublishIndexValidWritesAndFeedsOnce proves the end-to-end publish path
// for a valid index: exactly two object writes (index bytes + repo state) and
// one feed update.
func TestPublishIndexValidWritesAndFeedsOnce(t *testing.T) {
	input, _ := indexInput(t)
	objs := &countingObjects{}
	feeds := &countingFeeds{}
	p := Publisher{Builder: DefaultBuilder{}, Objects: objs, Feeds: feeds}
	next, err := p.Publish(context.Background(), "feed://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", currentWithChildren(), input, "batch-1")
	if err != nil {
		t.Fatalf("publish valid index: %v", err)
	}
	if objs.puts != 2 {
		t.Fatalf("expected 2 object writes, got %d", objs.puts)
	}
	if feeds.updates != 1 {
		t.Fatalf("expected 1 feed update, got %d", feeds.updates)
	}
	if next.Tags["multi"] != input.ManifestDigest {
		t.Fatalf("tag did not map to the index: %+v", next.Tags)
	}
}

// TestBuildNextIndexMissingChildZeroWrites proves an index referencing a child
// digest that is NOT committed in current state fails typed as a missing
// reference and derives no state.
func TestBuildNextIndexMissingChildZeroWrites(t *testing.T) {
	input, _ := indexInput(t)
	// Reference a child (`dig('e')`) that is missing from the committed set.
	input.ManifestJSON = makeIndex(t, ociIndexMT,
		childSpec{mediaType: ociManifestMT, digest: dig('e'), size: 512, arch: "amd64", os: "linux"})
	input.ManifestDigest = ComputeDigest(input.ManifestJSON)
	input.Manifest.Size = int64(len(input.ManifestJSON))

	current := currentWithChildren()
	objs := &countingObjects{}
	feeds := &countingFeeds{}
	p := Publisher{Builder: DefaultBuilder{}, Objects: objs, Feeds: feeds}
	_, err := p.Publish(context.Background(), "feed://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", current, input, "batch-1")
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Kind != ErrKindMissingReference {
		t.Fatalf("expected missing_reference, got %v", err)
	}
	if objs.puts != 0 || feeds.updates != 0 {
		t.Fatalf("missing child caused %d puts / %d feed updates, want 0/0", objs.puts, feeds.updates)
	}
}

// TestBuildNextIndexChildSizeMismatch rejects a child descriptor whose size
// disagrees with the committed child manifest record.
func TestBuildNextIndexChildSizeMismatch(t *testing.T) {
	input, _ := indexInput(t)
	input.ManifestJSON = makeIndex(t, ociIndexMT,
		childSpec{mediaType: ociManifestMT, digest: dig('b'), size: 9999, arch: "amd64", os: "linux"})
	input.ManifestDigest = ComputeDigest(input.ManifestJSON)
	input.Manifest.Size = int64(len(input.ManifestJSON))

	_, err := (DefaultBuilder{}).BuildNext(currentWithChildren(), input)
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Kind != ErrKindSizeMismatch {
		t.Fatalf("expected size_mismatch, got %v", err)
	}
}

// TestBuildNextIndexChildMediaTypeMismatch rejects a child descriptor whose
// media type disagrees with the committed child manifest record.
func TestBuildNextIndexChildMediaTypeMismatch(t *testing.T) {
	input, _ := indexInput(t)
	input.ManifestJSON = makeIndex(t, ociIndexMT,
		childSpec{mediaType: dockerManMT, digest: dig('b'), size: 512, arch: "amd64", os: "linux"})
	input.ManifestDigest = ComputeDigest(input.ManifestJSON)
	input.Manifest.Size = int64(len(input.ManifestJSON))

	_, err := (DefaultBuilder{}).BuildNext(currentWithChildren(), input)
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Kind != ErrKindMediaTypeMismatch {
		t.Fatalf("expected media_type_mismatch, got %v", err)
	}
}

// TestBuildNextIndexUnsupportedNestedMediaType rejects an index child whose
// media type is itself an index (OCI image index / Docker manifest list):
// recursive nested indexes are NOT supported in v1 and must fail before any
// write.
func TestBuildNextIndexUnsupportedNestedMediaType(t *testing.T) {
	for _, nestedMT := range []string{ociIndexMT, dockerListMT} {
		input, _ := indexInput(t)
		input.ManifestJSON = makeIndex(t, ociIndexMT,
			childSpec{mediaType: nestedMT, digest: dig('b'), size: 512, arch: "amd64", os: "linux"})
		input.ManifestDigest = ComputeDigest(input.ManifestJSON)
		input.Manifest.Size = int64(len(input.ManifestJSON))

		_, err := (DefaultBuilder{}).BuildNext(currentWithChildren(), input)
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Kind != ErrKindUnsupportedNestedMediaType {
			t.Fatalf("nested index %q: expected unsupported_nested_media_type, got %v", nestedMT, err)
		}
	}
}

// TestBuildNextIndexUnsupportedChildMediaType rejects a child descriptor with
// a media type that is neither a single-platform manifest nor an index (e.g. a
// bare octet-stream): a child MUST be a supported manifest media type.
func TestBuildNextIndexUnsupportedChildMediaType(t *testing.T) {
	input, _ := indexInput(t)
	input.ManifestJSON = makeIndex(t, ociIndexMT,
		childSpec{mediaType: "application/octet-stream", digest: dig('b'), size: 512, arch: "amd64", os: "linux"})
	input.ManifestDigest = ComputeDigest(input.ManifestJSON)
	input.Manifest.Size = int64(len(input.ManifestJSON))

	_, err := (DefaultBuilder{}).BuildNext(currentWithChildren(), input)
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Kind != ErrKindUnsupportedNestedMediaType {
		t.Fatalf("expected unsupported_nested_media_type, got %v", err)
	}
}

// TestBuildNextEmptyIndexPublicationValid proves an EMPTY index (manifests
// array of length zero — permitted by both the OCI and Docker specs) publishes
// successfully with no child references to prove.
func TestBuildNextEmptyIndexPublicationValid(t *testing.T) {
	input, _ := indexInput(t)
	input.ManifestJSON = []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[]}`, ociIndexMT))
	input.ManifestDigest = ComputeDigest(input.ManifestJSON)
	input.Manifest.Size = int64(len(input.ManifestJSON))

	next, err := (DefaultBuilder{}).BuildNext(currentWithChildren(), input)
	if err != nil {
		t.Fatalf("empty index must publish: %v", err)
	}
	idx, ok := next.Manifests[input.ManifestDigest]
	if !ok || idx.MediaType != ociIndexMT || next.Tags["multi"] != input.ManifestDigest {
		t.Fatalf("empty index not recorded: %+v", next.Manifests)
	}
}

// TestBuildNextIndexDuplicatePlatformAccepted proves an index with TWO
// children carrying the SAME resolved platform is ACCEPTED and published.
// Neither the OCI image-index spec nor the Docker manifest-list spec requires
// child platforms to be unique: the OCI spec resolves a tie on a client or
// runtime as "the first matching entry SHOULD be used" (descriptor order),
// so a duplicate is never rejected and the second child is never shadowed.
// Both committed children are retained exactly. (Children without a platform
// are likewise all valid and not compared to one another.)
func TestBuildNextIndexDuplicatePlatformAccepted(t *testing.T) {
	input, _ := indexInput(t)
	// Both children declare the SAME platform (amd64/linux); they reference
	// the two canonical committed children and must both be validated.
	input.ManifestJSON = makeIndex(t, ociIndexMT,
		childSpec{mediaType: ociManifestMT, digest: dig('b'), size: 512, arch: "amd64", os: "linux"},
		childSpec{mediaType: ociManifestMT, digest: dig('d'), size: 513, arch: "amd64", os: "linux"},
	)
	input.ManifestDigest = ComputeDigest(input.ManifestJSON)
	input.Manifest.Size = int64(len(input.ManifestJSON))

	next, err := (DefaultBuilder{}).BuildNext(currentWithChildren(), input)
	if err != nil {
		t.Fatalf("same-platform children must publish: %v", err)
	}
	if next.Tags["multi"] != input.ManifestDigest {
		t.Fatalf("tag did not map to the index: %+v", next.Tags)
	}
	// Both committed children are retained exactly (neither is shadowed).
	if got := next.Manifests[dig('b')]; got.SwarmRef != "child-amd64-ref" || got.Size != 512 {
		t.Fatalf("child b not retained: %+v", got)
	}
	if got := next.Manifests[dig('d')]; got.SwarmRef != "child-arm64-ref" || got.Size != 513 {
		t.Fatalf("child d not retained: %+v", got)
	}
}

// TestBuildNextIndexDistinctFeatureSetAccepted proves two children whose
// platforms differ ONLY in where a comma falls inside their os.features
// arrays are two independent, accepted platforms (["a,b","c"] vs
// ["a","b,c"]). With no duplicate-platform detector, both are trivially
// accepted and the index publishes; this pins that a naive/lossy slicing
// cannot conflate them into one rejected kid.
func TestBuildNextIndexDistinctFeatureSetAccepted(t *testing.T) {
	body := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[`+
		`{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux","os.features":["a,b","c"]}},`+
		`{"mediaType":%q,"size":513,"digest":%q,"platform":{"architecture":"amd64","os":"linux","os.features":["a","b,c"]}}]}`,
		ociIndexMT, ociManifestMT, dig('b'), ociManifestMT, dig('d')))
	input, _ := indexInput(t)
	input.ManifestJSON = body
	input.ManifestDigest = ComputeDigest(body)
	input.Manifest.Size = int64(len(body))

	next, err := (DefaultBuilder{}).BuildNext(currentWithChildren(), input)
	if err != nil {
		t.Fatalf("distinct feature platforms must not be conflated as duplicates: %v", err)
	}
	if next.Tags["multi"] != input.ManifestDigest {
		t.Fatalf("tag did not map to the index: %+v", next.Tags)
	}
}

// TestBuildNextIndexDockerManifestListValid proves a Docker manifest list with
// a single Docker schema-2 child publishes successfully.
func TestBuildNextIndexDockerManifestListValid(t *testing.T) {
	body := makeIndex(t, dockerListMT,
		childSpec{mediaType: dockerManMT, digest: dig('b'), size: 512, arch: "amd64", os: "linux"})
	input, _ := indexInput(t)
	input.ManifestJSON = body
	input.ManifestDigest = ComputeDigest(body)
	input.Manifest.MediaType = dockerListMT
	input.Manifest.Size = int64(len(body))

	current := spec.RepoStateDocument{
		Version:    1,
		Generation: 2,
		Tags:       map[string]string{},
		Manifests: map[string]spec.ManifestDescriptor{
			dig('b'): {SwarmRef: "child-ref", MediaType: dockerManMT, Size: 512},
		},
		Blobs: map[string]spec.BlobDescriptor{},
	}
	next, err := (DefaultBuilder{}).BuildNext(current, input)
	if err != nil {
		t.Fatalf("docker manifest list must publish: %v", err)
	}
	if got := next.Manifests[input.ManifestDigest]; got.MediaType != dockerListMT {
		t.Fatalf("manifest list not recorded exactly: %+v", got)
	}
}

// NOTE on cycles / self-reference: a publication cycle is NOT representable in
// this model. An index's content digest is a fixed function of its own bytes
// (X = H(X) is impossible), so an index cannot reference itself; and a
// committed child can never reference an index that does not yet exist at
// availability time, so a mutual cycle is also unreachable. The closest
// representable cycle-family failure — an index referencing a digest that is
// neither committed nor staged — is covered by
// TestBuildNextIndexMissingChildZeroWrites (missing_reference).
