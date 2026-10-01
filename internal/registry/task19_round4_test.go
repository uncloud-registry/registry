package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// recordingBoundedReader is a bounded artifact-byte reader that RECORDS the
// exact maxBytes bound and ref of every read, so the publication verification's
// per-read bounds and aggregate accounting are directly observable.
type recordingBoundedReader struct {
	mu      sync.Mutex
	objects map[string][]byte
	refs    []string
	bounds  []int64
}

func newRecordingBoundedReader() *recordingBoundedReader {
	return &recordingBoundedReader{objects: map[string][]byte{}}
}

func (r *recordingBoundedReader) serve(ref string, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.objects[ref] = data
}

func (r *recordingBoundedReader) ReadBounded(_ context.Context, ref string, maxBytes int64) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refs = append(r.refs, ref)
	r.bounds = append(r.bounds, maxBytes)
	data, ok := r.objects[ref]
	if !ok {
		return nil, errors.New("bounded object read: object not found")
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("bounded object read exceeded the bound")
	}
	return data, nil
}

func (r *recordingBoundedReader) snapshot() (refs []string, bounds []int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	refs = append([]string(nil), r.refs...)
	bounds = append([]int64(nil), r.bounds...)
	return refs, bounds
}

// TestIndexDescriptorArtifactTypePublishPullByteIdentical proves an OCI image
// index whose CHILD descriptor carries the OCI 1.1 artifactType AND a valid
// RFC 3986 urls entry publishes 201 and pulls BYTE-IDENTICALLY through the
// production handler (parser + builder + handler + verification), with no
// unintended staging consumption.
func TestIndexDescriptorArtifactTypePublishPullByteIdentical(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	counter := &countingObjectUploader{inner: h.Publisher.Objects}
	h.Publisher.Objects = counter
	server := httptest.NewServer(h)
	defer server.Close()

	tag := "multi"
	body := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[`+
		`{"mediaType":%q,"size":%d,"digest":%q,"artifactType":%q,"urls":["https://example.com/amd64","relative/m"]}`+
		`]}`,
		indexTestMT, indexTestManMT, len(indexChildAmd64), publish.ComputeDigest(indexChildAmd64),
		"application/vnd.example.sbom.v1"))

	before, err := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged before: %v", err)
	}
	resp := putIndex(t, server.URL, issuer, tag, indexTestMT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("index with descriptor artifactType must publish 201, got %d (body %s)", resp.StatusCode, b)
	}
	if counter.puts != 2 {
		t.Fatalf("expected exactly 2 object writes (index + state), got %d", counter.puts)
	}

	// Byte-identical pull by digest.
	indexDigest := publish.ComputeDigest(body)
	p := indexPullManifest(t, server.URL, issuer, indexDigest, indexTestMT)
	defer p.Body.Close()
	pb, _ := io.ReadAll(p.Body)
	if p.StatusCode != http.StatusOK || string(pb) != string(body) {
		t.Fatalf("index with artifactType must pull byte-identically, status=%d", p.StatusCode)
	}

	// Zero unintended staging consumption (no blobs are referenced by an index).
	after, err := h.Staging.ListStagedBlobs(context.Background(), "backend/api", "user:alice")
	if err != nil {
		t.Fatalf("list staged after: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("index publication must not consume staged blob rows: before=%d after=%d", len(before), len(after))
	}
}

// TestPublicationRejectsInvalidDescriptorMediaTypeZeroWrites proves a manifest
// whose descriptor mediaType is not a valid RFC 6838 media type is a 400 with
// ZERO object writes and unchanged state.
func TestPublicationRejectsInvalidDescriptorMediaTypeZeroWrites(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	counter := &countingObjectUploader{inner: h.Publisher.Objects}
	h.Publisher.Objects = counter
	server := httptest.NewServer(h)
	defer server.Close()

	// Index child with a malformed descriptor mediaType (interior space).
	body := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":"application/oci manifest","size":%d,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}]}`,
		indexTestMT, len(indexChildAmd64), publish.ComputeDigest(indexChildAmd64)))
	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("malformed descriptor mediaType must be 400, got %d (body %s)", resp.StatusCode, b)
	}
	if counter.puts != 0 {
		t.Fatalf("malformed descriptor mediaType caused %d object writes, want 0", counter.puts)
	}
}

// TestPublicationRejectsInvalidDescriptorURLZeroWrites proves an OCI descriptor
// urls entry that is not a valid RFC 3986 URI reference is a 400 with zero
// object writes.
func TestPublicationRejectsInvalidDescriptorURLZeroWrites(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	counter := &countingObjectUploader{inner: h.Publisher.Objects}
	h.Publisher.Objects = counter
	server := httptest.NewServer(h)
	defer server.Close()

	// Index child with an absolute http url whose authority is empty.
	body := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":%d,"digest":%q,"urls":["http:///broken"]}]}`,
		indexTestMT, indexTestManMT, len(indexChildAmd64), publish.ComputeDigest(indexChildAmd64)))
	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("invalid descriptor url must be 400, got %d (body %s)", resp.StatusCode, b)
	}
	if counter.puts != 0 {
		t.Fatalf("invalid descriptor url caused %d object writes, want 0", counter.puts)
	}
}

// TestPublicationRejectsInvalidDescriptorArtifactTypeZeroWrites proves an
// OCI descriptor artifactType that is not a valid RFC 6838 media type is a 400
// with zero object writes and a data-free message.
func TestPublicationRejectsInvalidDescriptorArtifactTypeZeroWrites(t *testing.T) {
	t.Parallel()
	h, _, _, issuer := newIndexWorld(t)
	counter := &countingObjectUploader{inner: h.Publisher.Objects}
	h.Publisher.Objects = counter
	server := httptest.NewServer(h)
	defer server.Close()

	body := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":%d,"digest":%q,"artifactType":"not-a media-type"}]}`,
		indexTestMT, indexTestManMT, len(indexChildAmd64), publish.ComputeDigest(indexChildAmd64)))
	resp := putIndex(t, server.URL, issuer, "multi", indexTestMT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("invalid descriptor artifactType must be 400, got %d (body %s)", resp.StatusCode, b)
	}
	// The public 400 must NOT echo the rejected artifactType value.
	rb, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(rb), "not-a media-type") {
		t.Fatalf("public error leaks the rejected artifactType: %s", rb)
	}
	if counter.puts != 0 {
		t.Fatalf("invalid descriptor artifactType caused %d object writes, want 0", counter.puts)
	}
}

// TestVerifyIndexBoundedReadAccounting proves the read-after-write verification
// reads each DISTINCT child body exactly once THROUGH the bounded byte reader,
// bounding each read to min(MaxArtifactBodyBytes, remaining aggregate budget,
// declared size + 1) and ACCOUNTING the read toward the aggregate budget.
func TestVerifyIndexBoundedReadAccounting(t *testing.T) {
	childA := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":11,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[]}`)
	childB := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":17,"digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"layers":[]}`)
	digA := publish.ComputeDigest(childA)
	digB := publish.ComputeDigest(childB)
	indexBody := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":%d,"digest":%q},{"mediaType":%q,"size":%d,"digest":%q},{"mediaType":%q,"size":%d,"digest":%q}]}`,
		indexTestMT, indexTestManMT, len(childA), digA, indexTestManMT, len(childB), digB, indexTestManMT, len(childA), digA))
	indexDigest := publish.ComputeDigest(indexBody)

	doc := spec.RepoStateDocument{
		Version: 1, Repo: "backend/api", Generation: 3,
		Tags: map[string]string{"multi": indexDigest},
		Manifests: map[string]spec.ManifestDescriptor{
			indexDigest: {SwarmRef: "index-ref", MediaType: indexTestMT, Size: int64(len(indexBody))},
			digA:        {SwarmRef: "child-a-ref", MediaType: indexTestManMT, Size: int64(len(childA))},
			digB:        {SwarmRef: "child-b-ref", MediaType: indexTestManMT, Size: int64(len(childB))},
		},
		Blobs: map[string]spec.BlobDescriptor{},
	}
	// The index references childA TWICE (identical duplicate) and childB once.
	artifact := publish.Artifact{Kind: publish.ArtifactKindIndex, MediaType: indexTestMT,
		Manifests: []publish.Descriptor{
			{MediaType: indexTestManMT, Digest: digA, Size: int64(len(childA))},
			{MediaType: indexTestManMT, Digest: digB, Size: int64(len(childB))},
			{MediaType: indexTestManMT, Digest: digA, Size: int64(len(childA))},
		}}

	bounded := newRecordingBoundedReader()
	bounded.serve("child-a-ref", childA)
	bounded.serve("child-b-ref", childB)
	bounded.serve("index-ref", indexBody)

	err := verifyPublicationCoherence(context.Background(), resolve.NewMemoryDocumentStore(), bounded, doc,
		"backend/api", "multi", indexDigest,
		spec.ManifestDescriptor{MediaType: indexTestMT, Size: int64(len(indexBody))}, artifact)
	if err != nil {
		t.Fatalf("coherent index must verify: %v", err)
	}

	refs, bounds := bounded.snapshot()
	// Reads: the top-level manifest body, then childA once, childB once
	// (the duplicate childA digest is NEVER read twice).
	if len(refs) != 3 {
		t.Fatalf("expected exactly 3 bounded reads (1 index + 2 distinct children), got %d: %v", len(refs), refs)
	}
	if refs[0] != "index-ref" {
		t.Fatalf("first read must be the index body (declared + 1 bound), got %q", refs[0])
	}
	if bounds[0] != int64(len(indexBody))+1 {
		t.Fatalf("index body read bound = %d, want declared+1 = %d", bounds[0], len(indexBody)+1)
	}
	// Children: each bound = min(MaxArtifactBodyBytes, remaining, size+1).
	// remaining stays huge (256MiB), so the binding term is size+1.
	if bounds[1] != int64(len(childA))+1 || bounds[2] != int64(len(childB))+1 {
		t.Fatalf("child read bounds = %v, want [%d %d]", bounds[1:], len(childA)+1, len(childB)+1)
	}
}

// TestVerifyFailsClosedWithoutBoundedReader proves the publication verification
// NEVER silently falls back to an unbounded read: with no bounded reader wired,
// an artifact body read FAILS CLOSED as an integrity violation.
func TestVerifyFailsClosedWithoutBoundedReader(t *testing.T) {
	childBody := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":11,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[]}`)
	indexBody := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":%d,"digest":%q}]}`, indexTestMT, indexTestManMT, len(childBody), publish.ComputeDigest(childBody)))
	indexDigest := publish.ComputeDigest(indexBody)
	doc := spec.RepoStateDocument{
		Version: 1, Repo: "backend/api", Generation: 3,
		Tags: map[string]string{"multi": indexDigest},
		Manifests: map[string]spec.ManifestDescriptor{
			indexDigest: {SwarmRef: "index-ref", MediaType: indexTestMT, Size: int64(len(indexBody))},
		},
		Blobs: map[string]spec.BlobDescriptor{},
	}
	artifact := publish.Artifact{Kind: publish.ArtifactKindIndex, MediaType: indexTestMT, Manifests: []publish.Descriptor{}}
	err := verifyPublicationCoherence(context.Background(), resolve.NewMemoryDocumentStore(), nil, doc,
		"backend/api", "multi", indexDigest,
		spec.ManifestDescriptor{MediaType: indexTestMT, Size: int64(len(indexBody))}, artifact)
	var ie *IntegrityError
	if !errors.As(err, &ie) {
		t.Fatalf("missing bounded reader must fail closed as IntegrityError, got %T: %v", err, err)
	}
}

// TestVerifyOversizedChildBodyFailsClosedBounded proves a child body larger
// than the per-read bound fails closed BEFORE full allocation: the in-memory
// bounded reader refuses to return it, so verification never buffers the
// oversized object.
func TestVerifyOversizedChildBodyFailsClosedBounded(t *testing.T) {
	// A child whose served body is larger than the declared size + 1 the
	// verification allows.
	childBody := []byte(strings.Repeat("x", 4096))
	dig := publish.ComputeDigest(childBody)
	indexBody := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":%d,"digest":%q}]}`, indexTestMT, indexTestManMT, len(childBody), dig))
	indexDigest := publish.ComputeDigest(indexBody)
	doc := spec.RepoStateDocument{
		Version: 1, Repo: "backend/api", Generation: 3,
		Tags: map[string]string{"multi": indexDigest},
		Manifests: map[string]spec.ManifestDescriptor{
			indexDigest: {SwarmRef: "index-ref", MediaType: indexTestMT, Size: int64(len(indexBody))},
			dig:         {SwarmRef: "child-ref", MediaType: indexTestManMT, Size: int64(len(childBody))},
		},
		Blobs: map[string]spec.BlobDescriptor{},
	}
	artifact := publish.Artifact{Kind: publish.ArtifactKindIndex, MediaType: indexTestMT,
		Manifests: []publish.Descriptor{{MediaType: indexTestManMT, Digest: dig, Size: int64(len(childBody))}}}

	// The bounded reader is size-bounded: serve a body CLEARLY larger than the
	// per-read bound (declared+1), so the bounded reader itself refuses to
	// return it — proving the read is bounded BEFORE any oversized allocation.
	bounded := newRecordingBoundedReader()
	bounded.serve("index-ref", indexBody)
	bounded.serve("child-ref", append(append([]byte(nil), childBody...), 'y', 'x')) // declared+2 > declared+1 bound

	err := verifyPublicationCoherence(context.Background(), resolve.NewMemoryDocumentStore(), bounded, doc,
		"backend/api", "multi", indexDigest,
		spec.ManifestDescriptor{MediaType: indexTestMT, Size: int64(len(indexBody))}, artifact)
	if err == nil {
		t.Fatal("verify must fail closed when a child body exceeds the per-read bound")
	}
	// The failed read recorded the bounded max (size+1), proving the read was
	// bounded before any oversized allocation.
	_, bounds := bounded.snapshot()
	if bounds[len(bounds)-1] != int64(len(childBody))+1 {
		t.Fatalf("oversized child read bound = %d, want declared+1 = %d", bounds[len(bounds)-1], len(childBody)+1)
	}
}

// TestArtifactReadBound pins the shared per-read bound function: the result is
// min(MaxArtifactBodyBytes, remaining, declared+1), never negative, and
// overflow-safe.
func TestArtifactReadBound(t *testing.T) {
	const maxBody = int64(publish.MaxArtifactBodyBytes)
	cases := []struct {
		declared, remaining int64
		want                int64
	}{
		{declared: 100, remaining: 0, want: 101},           // mismatch term binds
		{declared: 0, remaining: 0, want: 1},               // empty child → read 1 byte just in case
		{declared: maxBody, remaining: 0, want: maxBody},   // declared == cap → read at cap
		{declared: 1 << 40, remaining: 0, want: maxBody},   // huge declared capped at MaxArtifactBodyBytes
		{declared: 200, remaining: 150, want: 150},         // remaining binds (smaller than declared+1)
		{declared: 10, remaining: 5, want: 5},              // remaining binds
		{declared: 1<<63 - 1, remaining: 0, want: maxBody}, // overflow-safe huge declared
		{declared: 100, remaining: -500, want: 101},        // negative remaining treated as no-constraint
		{declared: 10, remaining: maxBody, want: 11},       // remaining huge, mismatch binds
	}
	for _, tc := range cases {
		got := artifactReadBound(tc.declared, tc.remaining)
		if got != tc.want {
			t.Fatalf("artifactReadBound(%d, %d) = %d, want %d", tc.declared, tc.remaining, got, tc.want)
		}
		if got < 0 {
			t.Fatalf("artifactReadBound(%d, %d) = %d must never be negative", tc.declared, tc.remaining, got)
		}
	}
}

// TestHandlerWiresBoundedByteReaderInMemory proves NewHandler wires the in-memory
// object store (which implements the bounded reader) so the production
// verification path always has a bounded artifact-byte reader.
func TestHandlerWiresBoundedByteReaderInMemory(t *testing.T) {
	h, _, _, _ := newIndexWorld(t)
	if h.BoundedBytes == nil {
		t.Fatal("in-memory handler must wire a bounded artifact byte reader")
	}
	if _, ok := h.Resolver.Docs.(*resolve.MemoryDocumentStore); !ok {
		t.Fatalf("fixture docs must be a MemoryDocumentStore, got %T", h.Resolver.Docs)
	}
}
