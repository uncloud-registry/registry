package publish

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/uncloud-registry/registry/internal/spec"
)

// Round-3 OCI optional-property, media-specific-strictness, index-bound, and
// kind-aware-builder tests for the artifact parser and builder.

// dataDescriptorFor returns an OCI descriptor body with embedded `data` (the
// base64 of content) whose digest/size are exactly coherent with that content.
func dataDescriptorFor(t *testing.T, content []byte, extra string) string {
	t.Helper()
	return fmt.Sprintf(`{"mediaType":%q,"size":%d,"digest":%q,"data":%q%s}`,
		ociConfigMT, len(content), ComputeDigest(content), base64.StdEncoding.EncodeToString(content), extra)
}

// TestParseArtifactAcceptsOCIOptionalManifestProperties proves the OCI 1.1
// optional top-level manifest members (artifactType, subject, annotations) and
// the optional descriptor members (urls, annotations, data) are ACCEPTED on an
// OCI image manifest and reflected on the validated Artifact.
func TestParseArtifactAcceptsOCIOptionalManifestProperties(t *testing.T) {
	configData := []byte(`{"architecture":"amd64"}`)
	body := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"artifactType":%q,`+
		`"subject":%s,`+
		`"annotations":{"com.example.k":"v"},"config":%s,`+
		`"layers":[{"mediaType":%q,"size":24,"digest":%q,"urls":["https://example.com/layer.tar.gz"],"annotations":{"com.example.l":"1"}}]}`,
		ociManifestMT, "application/vnd.example.sbom.v1",
		dataDescriptorFor(t, []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","size":24,"digest":"`+dig('c')+`"}`), ``),
		dataDescriptorFor(t, configData, ``),
		ociLayerMT, dig('a'))

	a, err := ParseArtifact(ociManifestMT, []byte(body))
	if err != nil {
		t.Fatalf("parse OCI optional-property manifest: %v", err)
	}
	if a.Kind != ArtifactKindManifest {
		t.Fatalf("expected manifest kind, got %v", a.Kind)
	}
	if a.ArtifactType != "application/vnd.example.sbom.v1" {
		t.Fatalf("artifactType not preserved: %q", a.ArtifactType)
	}
	if a.Subject == nil {
		t.Fatal("subject not preserved")
	}
	if a.Subject.URLs != nil || a.Subject.Annotations != nil {
		t.Fatalf("subject optional members not preserved: %+v", a.Subject)
	}
	if a.Annotations["com.example.k"] != "v" {
		t.Fatalf("top-level annotations not preserved: %+v", a.Annotations)
	}
	if a.Config == nil || a.Config.Data == nil || string(a.Config.Data) != string(configData) {
		t.Fatalf("config data not preserved: %+v", a.Config)
	}
	if len(a.Layers) != 1 || len(a.Layers[0].URLs) != 1 || a.Layers[0].URLs[0] != "https://example.com/layer.tar.gz" {
		t.Fatalf("layer urls not preserved: %+v", a.Layers)
	}
	if a.Layers[0].Annotations["com.example.l"] != "1" {
		t.Fatalf("layer annotations not preserved: %+v", a.Layers[0].Annotations)
	}
}

// TestParseArtifactAcceptsOCIIndexOptionalProperties proves the OCI 1.1
// optional index members are accepted and byte-identical body retention is
// implicitly guaranteed (parsing is validation, never transcoding).
func TestParseArtifactAcceptsOCIIndexOptionalProperties(t *testing.T) {
	body := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"artifactType":%q,`+
		`"subject":{"mediaType":%q,"size":24,"digest":%q},`+
		`"annotations":{"com.example":"1"},`+
		`"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux"},"annotations":{"com.example.c":"x"}}]}`,
		ociIndexMT, "application/vnd.example.sbom.index.v1",
		ociManifestMT, dig('b'),
		ociManifestMT, dig('b'))
	a, err := ParseArtifact(ociIndexMT, []byte(body))
	if err != nil {
		t.Fatalf("parse OCI optional-property index: %v", err)
	}
	if a.ArtifactType != "application/vnd.example.sbom.index.v1" {
		t.Fatalf("index artifactType not preserved: %q", a.ArtifactType)
	}
	if a.Subject == nil || a.Subject.Digest != dig('b') {
		t.Fatalf("index subject not preserved: %+v", a.Subject)
	}
	if a.Annotations["com.example"] != "1" {
		t.Fatalf("index annotations not preserved: %+v", a.Annotations)
	}
	if len(a.Manifests) != 1 || a.Manifests[0].Annotations["com.example.c"] != "x" || a.Manifests[0].Platform == nil {
		t.Fatalf("index child optional members not preserved: %+v", a.Manifests)
	}
}

// TestParseArtifactDescriptorDataCoherence proves the `data` descriptor member
// must base64-decode to bytes whose length equals size and whose SHA-256 equals
// digest; any incoherence or invalid base64 is rejected.
func TestParseArtifactDescriptorDataCoherence(t *testing.T) {
	content := []byte("embedded-config-content")
	valid := dataDescriptorFor(t, content, ``)

	cases := []struct {
		name        string
		body        string
		wantErrKind ValidationErrorKind
	}{
		{"coherent data accepted", fmt.Sprintf(`{"schemaVersion":2,"config":%s,"layers":[]}`, valid), ""},
		{"wrong size rejected", fmt.Sprintf(`{"schemaVersion":2,"config":%s,"layers":[]}`,
			fmt.Sprintf(`{"mediaType":%q,"size":%d,"digest":%q,"data":%q}`, ociConfigMT, len(content)+1, ComputeDigest(content), base64.StdEncoding.EncodeToString(content))), ErrKindInvalidSize},
		{"wrong digest rejected", fmt.Sprintf(`{"schemaVersion":2,"config":%s,"layers":[]}`,
			fmt.Sprintf(`{"mediaType":%q,"size":%d,"digest":%q,"data":%q}`, ociConfigMT, len(content), dig('c'), base64.StdEncoding.EncodeToString(content))), ErrKindInvalidDigest},
		{"invalid base64 rejected", fmt.Sprintf(`{"schemaVersion":2,"config":%s,"layers":[]}`,
			fmt.Sprintf(`{"mediaType":%q,"size":%d,"digest":%q,"data":%q}`, ociConfigMT, len(content), ComputeDigest(content), "!!!not-base64!!!")), ErrKindInvalidSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseArtifact(ociManifestMT, []byte(tc.body))
			if tc.wantErrKind == "" {
				if err != nil {
					t.Fatalf("expected parse success, got %v", err)
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) || ve.Kind != tc.wantErrKind {
				t.Fatalf("expected kind %q, got %v", tc.wantErrKind, err)
			}
		})
	}
}

// TestParseArtifactDockerManifestListChildRequiresPlatform proves the
// media-specific strictness rule: a Docker manifest-list child MUST include a
// valid platform object, while an OCI image-index child keeps platform
// OPTIONAL.
func TestParseArtifactDockerManifestListChildRequiresPlatform(t *testing.T) {
	// Docker manifest list child without platform -> rejected.
	dockerMissing := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q}]}`,
		dockerListMT, dockerManMT, dig('b'))
	if _, err := ParseArtifact(dockerListMT, []byte(dockerMissing)); err == nil {
		t.Fatal("Docker manifest-list child must require a platform")
	}
	// With platform -> accepted.
	dockerWith := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}]}`,
		dockerListMT, dockerManMT, dig('b'))
	if _, err := ParseArtifact(dockerListMT, []byte(dockerWith)); err != nil {
		t.Fatalf("Docker manifest-list child with platform must parse: %v", err)
	}
	// OCI image-index child without platform is still OPTIONAL.
	ociWithout := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q}]}`,
		ociIndexMT, ociManifestMT, dig('b'))
	if _, err := ParseArtifact(ociIndexMT, []byte(ociWithout)); err != nil {
		t.Fatalf("OCI index child without platform must stay optional: %v", err)
	}
}

// TestParseArtifactPresentEmptyMediaTypeRejected proves a PRESENT top-level
// mediaType member whose value is the empty string is rejected (never equated
// with an absent member).
func TestParseArtifactPresentEmptyMediaTypeRejected(t *testing.T) {
	body := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"","config":{"mediaType":%q,"size":24,"digest":%q},"layers":[]}`,
		ociConfigMT, dig('c'))
	_, err := ParseArtifact(ociManifestMT, []byte(body))
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Kind != ErrKindMediaTypeMismatch {
		t.Fatalf("present empty embedded mediaType must be rejected, got %v", err)
	}
}

// TestParseArtifactDockerDescriptorRejectsOCIOnlyMembers proves Docker
// descriptors never accept the OCI-only urls/annotations/data members.
func TestParseArtifactDockerDescriptorRejectsOCIOnlyMembers(t *testing.T) {
	reject := []struct {
		name string
		body string
		mt   string
	}{
		{"docker config urls", fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q,"urls":["https://x"]},"layers":[]}`, dockerConfigMT, dig('c')), dockerManMT},
		{"docker config data", fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q,"data":"aGk="},"layers":[]}`, dockerConfigMT, dig('c')), dockerManMT},
		{"docker layer annotations", fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":24,"digest":%q,"annotations":{"k":"v"}}]}`, dockerConfigMT, dig('c'), dockerLayerMT, dig('a')), dockerManMT},
		{"docker layer data", fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":24,"digest":%q,"data":"aGk="}]}`, dockerConfigMT, dig('c'), dockerLayerMT, dig('a')), dockerManMT},
		{"docker manifest-list child annotations", fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux"},"annotations":{"k":"v"}}]}`, dockerListMT, dockerManMT, dig('b')), dockerListMT},
		{"docker manifest-list child urls", fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux"},"urls":["https://x"]}]}`, dockerListMT, dockerManMT, dig('b')), dockerListMT},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseArtifact(tc.mt, []byte(tc.body)); err == nil {
				t.Fatalf("%s must be rejected as an unknown OCI-only member", tc.name)
			}
		})
	}
	// Docker LAYER descriptors DO allow urls (per the Docker Distribution
	// manifest-v2-2 descriptor).
	dockerLayerURL := fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":%q,"size":24,"digest":%q},"layers":[{"mediaType":%q,"size":24,"digest":%q,"urls":["https://x"]}]}`,
		dockerConfigMT, dig('c'), dockerLayerMT, dig('a'))
	if _, err := ParseArtifact(dockerManMT, []byte(dockerLayerURL)); err != nil {
		t.Fatalf("Docker layer descriptor must accept urls: %v", err)
	}
}

// TestValidateIndexAggregateBounds proves the shared index-size policy: total
// descriptor count, distinct child count, and aggregate declared bytes are each
// bounded; duplicates are counted once for distinct/byte sums; and the checks
// are overflow-safe.
func TestValidateIndexAggregateBounds(t *testing.T) {
	if err := ValidateIndexAggregateBounds(nil); err != nil {
		t.Fatalf("empty index must be accepted: %v", err)
	}
	// Duplicate descriptors: each digest counted once for distinct/byte sums.
	dup := []Descriptor{
		{Digest: dig('a'), Size: 100},
		{Digest: dig('a'), Size: 100},
		{Digest: dig('b'), Size: 50},
	}
	if err := ValidateIndexAggregateBounds(dup); err != nil {
		t.Fatalf("small duplicate index must be accepted: %v", err)
	}
	if u, err := UniqueIndexChildren(dup); err != nil || len(u) != 2 {
		t.Fatalf("unique children must dedupe duplicate digests to 2, got %d err %v", len(u), err)
	}
	// Total descriptor count bound.
	tooMany := make([]Descriptor, MaxIndexChildDescriptors+1)
	for i := range tooMany {
		tooMany[i] = Descriptor{Digest: fmt.Sprintf("sha256:%x", []byte{byte(i)}), Size: 1}
	}
	if err := ValidateIndexAggregateBounds(tooMany); err == nil {
		t.Fatal("exceeding MaxIndexChildDescriptors must be rejected")
	}
	// Distinct child count bound (sizes tiny so byte bound won't trigger). Each
	// digest is a real sha256 of a distinct label, so all 4097 are distinct.
	var distinctTooMany []Descriptor
	for i := 0; i < MaxUniqueIndexChildManifests+1; i++ {
		distinctTooMany = append(distinctTooMany, Descriptor{Digest: ComputeDigest([]byte(fmt.Sprintf("child-%d", i))), Size: 1})
	}
	if err := ValidateIndexAggregateBounds(distinctTooMany); err == nil {
		t.Fatal("exceeding MaxUniqueIndexChildManifests must be rejected")
	}
	// Aggregate declared byte bound.
	aggTooHigh := []Descriptor{
		{Digest: dig('a'), Size: MaxAggregateIndexChildBytes + 1},
	}
	if err := ValidateIndexAggregateBounds(aggTooHigh); err == nil {
		t.Fatal("single child exceeding the aggregate byte bound must be rejected")
	}
	aggSum := []Descriptor{
		{Digest: dig('a'), Size: MaxAggregateIndexChildBytes / 2},
		{Digest: dig('b'), Size: MaxAggregateIndexChildBytes/2 + 1},
	}
	if err := ValidateIndexAggregateBounds(aggSum); err == nil {
		t.Fatal("aggregate sum exceeding the byte bound must be rejected")
	}
}

// TestBuildNextIndexDoesNotCopyCollidingStagedBlob proves DefaultBuilder.
// BuildNext is KIND-AWARE: a DIRECT caller's StagedBlobs map containing a blob
// whose digest collides with an index child manifest digest is NEVER copied
// into next.Blobs (no fabricated blob record for a manifest digest, and hence
// no orphan-upload source), because an index references child MANIFESTS, never
// blobs.
func TestBuildNextIndexDoesNotCopyCollidingStagedBlob(t *testing.T) {
	current := currentWithChildren()
	input, body := indexInput(t)
	// A staged blob whose digest collides with the committed amd64 child digest
	// (dig('b')) is present in the direct caller's staged set.
	childDigest := dig('b')
	input.StagedBlobs = map[string]spec.BlobDescriptor{
		childDigest: {SwarmRef: "staged-collision", Size: 512, MediaType: "application/octet-stream"},
	}
	next, err := (DefaultBuilder{}).BuildNext(current, input)
	if err != nil {
		t.Fatalf("BuildNext of a valid index must succeed: %v", err)
	}
	if _, isBlob := next.Blobs[childDigest]; isBlob {
		t.Fatalf("a staged blob colliding with an index child-manifest digest must never be copied into next.Blobs: %+v", next.Blobs)
	}
	// The child manifest record stays in the manifests map (not degraded and
	// not duplicated as a blob).
	if got := next.Manifests[childDigest]; got.SwarmRef != "child-amd64-ref" {
		t.Fatalf("child manifest record degraded: %+v", got)
	}
	_ = body
}

// TestPublishIndexRejectsOversizedChildSetBeforeAnyWrite proves an index whose
// child descriptor set exceeds a shared bound is rejected at PARSE time with
// zero object writes and zero feed updates.
func TestPublishIndexRejectsOversizedChildSetBeforeAnyWrite(t *testing.T) {
	// A single child whose declared size exceeds the aggregate bound.
	body := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":%d,"digest":%q}]}`,
		ociIndexMT, ociManifestMT, MaxAggregateIndexChildBytes+1, dig('b'))
	input := BuildInput{
		Repo:           "backend/api",
		Tag:            "multi",
		ManifestDigest: ComputeDigest([]byte(body)),
		ManifestJSON:   []byte(body),
		Manifest:       spec.ManifestDescriptor{MediaType: ociIndexMT, Size: int64(len(body))},
		StagedBlobs:    map[string]spec.BlobDescriptor{},
	}
	objs := &countingObjects{}
	feeds := &countingFeeds{}
	p := Publisher{Builder: DefaultBuilder{}, Objects: objs, Feeds: feeds}
	_, err := p.Publish(context.Background(), "feed://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", currentWithChildren(), input, "batch-1")
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Kind != ErrKindIndexTooLarge {
		t.Fatalf("expected index_too_large, got %v", err)
	}
	if objs.puts != 0 || feeds.updates != 0 {
		t.Fatalf("oversized child set caused %d puts / %d feed updates, want 0/0", objs.puts, feeds.updates)
	}
}
