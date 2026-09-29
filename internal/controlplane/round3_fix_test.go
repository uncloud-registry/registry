package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
)

// countingBytesReader wraps the world's bounded object reader and counts every
// ReadBounded call, so a test can prove duplicate index descriptors cause ONE
// child read rather than N reads.
type countingBytesReader struct {
	inner *memoryBytesReader
	reads atomic.Int64
}

func (c *countingBytesReader) ReadBounded(ctx context.Context, ref string, maxBytes int64) ([]byte, error) {
	c.reads.Add(1)
	return c.inner.ReadBounded(ctx, ref, maxBytes)
}

// buildAnnotatedIndex assembles a REAL OCI image index that carries the OCI
// 1.1 optional top-level members (artifactType, subject, annotations) and
// optional descriptor members (annotations, urls) on its children, referencing
// real committed children.
func buildAnnotatedIndex(t *testing.T, children ...indexChildFixture) indexFixture {
	t.Helper()
	type descriptor struct {
		MediaType   string            `json:"mediaType"`
		Digest      string            `json:"digest"`
		Size        int64             `json:"size"`
		Platform    map[string]string `json:"platform,omitempty"`
		Annotations map[string]string `json:"annotations,omitempty"`
		URLs        []string          `json:"urls,omitempty"`
	}
	childJSON := make([]descriptor, 0, len(children))
	for _, c := range children {
		childJSON = append(childJSON, descriptor{
			MediaType:   c.ref.MediaType,
			Digest:      c.ref.Digest,
			Size:        c.ref.Size,
			Platform:    map[string]string{"architecture": "amd64", "os": "linux"},
			Annotations: map[string]string{"com.example.child": "x"},
			URLs:        []string{"https://example.com/child"},
		})
	}
	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     fixtureIndexMediaType,
		"artifactType":  "application/vnd.example.sbom.index.v1",
		"subject": map[string]any{
			"mediaType": fixtureIndexMediaType,
			"digest":    children[0].ref.Digest,
			"size":      children[0].ref.Size,
		},
		"annotations": map[string]any{"com.example": "1"},
		"manifests":   childJSON,
	}
	body, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal annotated index fixture: %v", err)
	}
	return indexFixture{
		body:     body,
		digest:   publish.ComputeDigest(body),
		manifest: spec.ManifestDescriptor{SwarmRef: refHex('9'), MediaType: fixtureIndexMediaType, Size: int64(len(body))},
		children: children,
	}
}

// buildRawIndex assembles an index body from raw JSON map (allows handcrafted
// mediaType, duplicate descriptors, and oversized declared sizes).
func buildRawIndex(t *testing.T, idx map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal raw index fixture: %v", err)
	}
	return body
}

// TestFeedSignerAcceptsAnnotatedOCIIndexOptionalProperties proves the real
// signer accepts an OCI image index carrying the OCI 1.1 optional top-level and
// descriptor members end to end: the operated body parses under its declared
// OCI media type, the committed child is verified, and exactly one feed update
// advances the repository.
func TestFeedSignerAcceptsAnnotatedOCIIndexOptionalProperties(t *testing.T) {
	const tag = "latest"
	c1 := makeChild(t, '1', 'a', 100)
	fx := buildAnnotatedIndex(t, c1)
	w, req := indexWorld(t, tag, 1, []indexChildFixture{c1}, fx)

	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("annotated OCI index must be accepted by the signer: %v", err)
	}
	if result.Feed != w.repoTopic || result.Reference != refHex('a') {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
}

// TestFeedSignerDeduplicatesDuplicateChildDescriptorReads proves the
// production-path read-amplification fix: an index that lists the SAME child
// digest twice still reads the child body exactly ONCE (plus the single index
// body read), never twice.
func TestFeedSignerDeduplicatesDuplicateChildDescriptorReads(t *testing.T) {
	const tag = "latest"
	c1 := makeChild(t, '1', 'a', 100)
	// The index body lists c1 TWICE (identical descriptor, same digest).
	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     fixtureIndexMediaType,
		"manifests": []map[string]any{
			{"mediaType": c1.ref.MediaType, "digest": c1.ref.Digest, "size": c1.ref.Size, "platform": map[string]any{"architecture": "amd64", "os": "linux"}},
			{"mediaType": c1.ref.MediaType, "digest": c1.ref.Digest, "size": c1.ref.Size, "platform": map[string]any{"architecture": "amd64", "os": "linux"}},
		},
	}
	body := buildRawIndex(t, idx)
	fx := indexFixture{
		body: body, digest: publish.ComputeDigest(body),
		manifest: spec.ManifestDescriptor{SwarmRef: refHex('9'), MediaType: fixtureIndexMediaType, Size: int64(len(body))},
		children: []indexChildFixture{c1},
	}
	w, req := indexWorld(t, tag, 1, []indexChildFixture{c1}, fx)

	counting := &countingBytesReader{inner: w.bytes}
	w.signer.Bytes = counting
	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("duplicate-descriptor index must be accepted: %v", err)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
	// Exactly 2 reads: the index body once + the single DISTINCT child once.
	if reads := counting.reads.Load(); reads != 2 {
		t.Fatalf("duplicate child descriptors must cause exactly 2 reads (1 body + 1 deduped child), got %d", reads)
	}
	_ = result
}

// TestFeedSignerRejectsIndexDeclaredAggregateTooLarge proves an index whose
// child descriptor set violates the shared aggregate byte bound fails CLOSED
// with ZERO external feed updates.
func TestFeedSignerRejectsIndexDeclaredAggregateTooLarge(t *testing.T) {
	const tag = "latest"
	c1 := makeChild(t, '1', 'a', 100)
	// A single child whose declared size alone exceeds the aggregate bound.
	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     fixtureIndexMediaType,
		"manifests": []map[string]any{
			{"mediaType": c1.ref.MediaType, "digest": c1.ref.Digest, "size": publish.MaxAggregateIndexChildBytes + 1, "platform": map[string]any{"architecture": "amd64", "os": "linux"}},
		},
	}
	body := buildRawIndex(t, idx)
	fx := indexFixture{
		body: body, digest: publish.ComputeDigest(body),
		manifest: spec.ManifestDescriptor{SwarmRef: refHex('9'), MediaType: fixtureIndexMediaType, Size: int64(len(body))},
		children: []indexChildFixture{c1},
	}
	w, req := indexWorld(t, tag, 1, []indexChildFixture{c1}, fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("oversized declared child set must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("oversized child set must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerRejectsDockerManifestListChildWithoutPlatform proves the
// media-specific strictness rule on the production signer path: a Docker
// schema2 manifest list whose child lacks the REQUIRED platform object is
// malformed with zero updates.
func TestFeedSignerRejectsDockerManifestListChildWithoutPlatform(t *testing.T) {
	const tag = "latest"
	child := makeDockerChild(t)
	// Docker list body with a child that has NO platform.
	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     publish.MediaTypeDockerManifestList,
		"manifests": []map[string]any{
			{"mediaType": child.ref.MediaType, "digest": child.ref.Digest, "size": child.ref.Size},
		},
	}
	body := buildRawIndex(t, idx)
	fx := indexFixture{
		body: body, digest: publish.ComputeDigest(body),
		manifest: spec.ManifestDescriptor{SwarmRef: refHex('9'), MediaType: publish.MediaTypeDockerManifestList, Size: int64(len(body))},
		children: []indexChildFixture{child},
	}
	w, req := indexWorld(t, tag, 1, []indexChildFixture{child}, fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("Docker manifest-list child without platform must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("Docker manifest-list child without platform must cause ZERO external updates, got %d", n)
	}
}

// TestFeedSignerAcceptsOCIIndexChildWithoutPlatform proves the OCI image-index
// keeps the platform OPTIONAL on the production signer path (unlike Docker).
func TestFeedSignerAcceptsOCIIndexChildWithoutPlatform(t *testing.T) {
	const tag = "latest"
	c1 := makeChild(t, '1', 'a', 100)
	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     fixtureIndexMediaType,
		"manifests": []map[string]any{
			{"mediaType": c1.ref.MediaType, "digest": c1.ref.Digest, "size": c1.ref.Size},
		},
	}
	body := buildRawIndex(t, idx)
	fx := indexFixture{
		body: body, digest: publish.ComputeDigest(body),
		manifest: spec.ManifestDescriptor{SwarmRef: refHex('9'), MediaType: fixtureIndexMediaType, Size: int64(len(body))},
		children: []indexChildFixture{c1},
	}
	w, req := indexWorld(t, tag, 1, []indexChildFixture{c1}, fx)

	signer, updater := w.countingSigner()
	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("OCI index child without platform must be accepted, got %v", err)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}
	_ = result
}

// TestFeedSignerRejectsPresentEmptyEmbeddedMediaType proves the completed fix
// on the production signer path: a PRESENT top-level mediaType member whose
// value is the empty string is rejected (never equated with an absent member).
func TestFeedSignerRejectsPresentEmptyEmbeddedMediaType(t *testing.T) {
	const tag = "latest"
	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "",
		"manifests":     []map[string]any{},
	}
	body := buildRawIndex(t, idx)
	fx := indexFixture{
		body: body, digest: publish.ComputeDigest(body),
		manifest: spec.ManifestDescriptor{SwarmRef: refHex('9'), MediaType: fixtureIndexMediaType, Size: int64(len(body))},
		children: nil,
	}
	w, req := indexWorld(t, tag, 1, nil, fx)

	signer, updater := w.countingSigner()
	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("present empty embedded mediaType must fail closed as malformed, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("present empty embedded mediaType must cause ZERO external updates, got %d", n)
	}
}
