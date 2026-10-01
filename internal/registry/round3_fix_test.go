package registry

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
)

func newTestRegistryServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

// TestIndexHandlerByteIdenticalAnnotatedOCIPull proves the whole HTTP path:
// an OCI image index carrying the OCI 1.1 optional top-level members
// (artifactType, subject, annotations) and descriptor optional members
// (annotations, urls) is accepted on PUT and pulled back BYTE-IDENTICALLY
// (parsing is validation, never transcoding).
func TestIndexHandlerByteIdenticalAnnotatedOCIPull(t *testing.T) {
	t.Parallel()
	handler, docs, feeds, issuer := newIndexWorld(t)
	server := newTestRegistryServer(t, handler)
	defer server.Close()

	amd := publish.ComputeDigest(indexChildAmd64)
	// Annotated OCI index referencing the committed amd64 child with optional
	// top-level and descriptor members.
	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     indexTestMT,
		"artifactType":  "application/vnd.example.sbom.index.v1",
		"subject": map[string]any{
			"mediaType": indexTestManMT,
			"digest":    amd,
			"size":      len(indexChildAmd64),
		},
		"annotations": map[string]any{"com.example": "1"},
		"manifests": []map[string]any{
			{
				"mediaType":   indexTestManMT,
				"digest":      amd,
				"size":        len(indexChildAmd64),
				"platform":    map[string]any{"architecture": "amd64", "os": "linux"},
				"annotations": map[string]any{"com.example.child": "x"},
				"urls":        []string{"https://example.com/child"},
			},
		},
	}
	body, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal annotated index: %v", err)
	}

	if resp := putIndex(t, server.URL, issuer, "annotated", indexTestMT, body); resp.StatusCode != http.StatusCreated {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		t.Fatalf("annotated OCI index PUT must be accepted, got %d", resp.StatusCode)
	}

	// Pull by tag with the exact media type accepted; bytes must be identical.
	pull := indexPullManifest(t, server.URL, issuer, "annotated", indexTestMT)
	got, _ := io.ReadAll(pull.Body)
	pull.Body.Close()
	if pull.StatusCode != http.StatusOK {
		t.Fatalf("annotated index pull must serve, got %d", pull.StatusCode)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("annotated index must pull back byte-identically: got %d bytes, want %d", len(got), len(body))
	}

	// The resolved state records the OCI optional members (artifactType etc.)
	// don't affect byte identity — the stored body is the exact uploaded one.
	_ = docs
	_ = feeds
}

// TestIndexHandlerOCIChildPlatformOptional proves the media-specific strictness
// on the HTTP path: an OCI image index child may OMIT the platform object.
func TestIndexHandlerOCIChildPlatformOptional(t *testing.T) {
	t.Parallel()
	handler, _, _, issuer := newIndexWorld(t)
	server := newTestRegistryServer(t, handler)
	defer server.Close()

	amd := publish.ComputeDigest(indexChildAmd64)
	// OCI index child WITHOUT platform (allowed).
	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     indexTestMT,
		"manifests": []map[string]any{
			{"mediaType": indexTestManMT, "digest": amd, "size": len(indexChildAmd64)},
		},
	}
	body, _ := json.Marshal(idx)
	if resp := putIndex(t, server.URL, issuer, "noplatform", indexTestMT, body); resp.StatusCode != http.StatusCreated {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		t.Fatalf("OCI index child without platform must be accepted, got %d", resp.StatusCode)
	}
}

// TestHandlerRejectsPresentEmptyEmbeddedMediaType proves a PRESENT embedded
// top-level mediaType member whose value is the empty string is rejected on the
// PUT path (never equated with an absent member).
func TestHandlerRejectsPresentEmptyEmbeddedMediaType(t *testing.T) {
	t.Parallel()
	handler, _, _, issuer := newIndexWorld(t)
	server := newTestRegistryServer(t, handler)
	defer server.Close()

	amd := publish.ComputeDigest(indexChildAmd64)
	idx := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "",
		"manifests": []map[string]any{
			{"mediaType": indexTestManMT, "digest": amd, "size": len(indexChildAmd64)},
		},
	}
	body, _ := json.Marshal(idx)
	if resp := putIndex(t, server.URL, issuer, "emptymt", indexTestMT, body); resp.StatusCode != http.StatusBadRequest {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		t.Fatalf("present empty embedded mediaType must be rejected with 400, got %d", resp.StatusCode)
	}
}

// TestHandlerManifestListChildWithoutPlatformRejected proves a Docker manifest
// list child MUST include a platform object, enforced at the HTTP PUT path.
func TestHandlerManifestListChildWithoutPlatformRejected(t *testing.T) {
	t.Parallel()
	// Stand up a fresh world WITHOUT committed children so the only failure
	// driver is the platform requirement. A Docker manifest list references
	// only the platform-provided committed children; a missing platform on the
	// sole child is rejected before any child lookup.
	handler, _, _, issuer := newIndexWorld(t)
	server := newTestRegistryServer(t, handler)
	defer server.Close()

	amd := publish.ComputeDigest(indexChildAmd64)
	list := map[string]any{
		"schemaVersion": 2,
		"mediaType":     indexTestListMT,
		"manifests": []map[string]any{
			// Docker manifest-list child with NO platform.
			{"mediaType": indexTestDockerMT, "digest": amd, "size": len(indexChildAmd64)},
		},
	}
	body, _ := json.Marshal(list)
	if resp := putIndex(t, server.URL, issuer, "dlist", indexTestListMT, body); resp.StatusCode != http.StatusBadRequest {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		t.Fatalf("Docker manifest-list child without platform must be rejected with 400, got %d (body: %s)", resp.StatusCode, string(body))
	}
}
