package controlplane

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
)

// putIndexAs publishes an OCI image index body to a tag through the given
// registry instance with the index media type.
func (w *realConflictWorld) putIndexAs(t *testing.T, serverURL, tag string, body []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, serverURL+"/v2/"+integrationRepo+"/manifests/"+tag, bytes.NewReader(body))
	req.Host = integrationServiceHost
	req.Header.Set("Authorization", w.bearer(t))
	req.Header.Set("Content-Type", publish.MediaTypeOCIIndex)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("index publish request: %v", err)
	}
	return resp
}

// TestRealFeedSignerPublishesIndexThroughProductionPath is the MANDATORY
// end-to-end production proof for Task-19 round 1: an OCI image index is
// published through the REAL durable composition — a file-backed
// controlplane.Store, the REAL controlplane.FeedSigner (now kind-aware: it
// independently validates every index child against the committed manifest map,
// including a bounded child-body read with digest AND byte-length proof, and
// rejects nested indexes), the REAL InternalFeedServer HTTP boundary, and the
// production publish.ControlPlaneCommitter, wired to TWO independent
// registry.Handler instances. On each handler the commit completes once, the
// committed children remain preserved as manifests (never blobs), and an
// idempotent retry of the SAME index is recognized WITHOUT a second feed
// advance or a new durable operation row.
func TestRealFeedSignerPublishesIndexThroughProductionPath(t *testing.T) {
	w := newRealConflictWorld(t)

	// Publish two committed single-platform child manifests (generation 1, 2).
	configAmd := []byte(`{"architecture":"amd64"}`)
	amdConfigDigest := w.stageBlob(t, w.s1.URL, configAmd)
	manifestAmd := integrationManifest(amdConfigDigest, len(configAmd))
	amdManifestDigest := publish.ComputeDigest(manifestAmd)
	amdResp := w.putManifest(t, w.s1.URL, "child-amd", manifestAmd)
	amdBody, _ := io.ReadAll(amdResp.Body)
	amdResp.Body.Close()
	if amdResp.StatusCode != http.StatusCreated {
		t.Fatalf("child-amd publish status %d: %s", amdResp.StatusCode, amdBody)
	}

	configArm := []byte(`{"architecture":"arm64"}`)
	armConfigDigest := w.stageBlob(t, w.s1.URL, configArm)
	manifestArm := integrationManifest(armConfigDigest, len(configArm))
	armManifestDigest := publish.ComputeDigest(manifestArm)
	armResp := w.putManifest(t, w.s1.URL, "child-arm", manifestArm)
	armBody, _ := io.ReadAll(armResp.Body)
	armResp.Body.Close()
	if armResp.StatusCode != http.StatusCreated {
		t.Fatalf("child-arm publish status %d: %s", armResp.StatusCode, armBody)
	}

	// Build the image index referencing the two committed children.
	indexBody := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[`+
		`{"mediaType":%q,"size":%d,"digest":%q,"platform":{"architecture":"amd64","os":"linux"}},`+
		`{"mediaType":%q,"size":%d,"digest":%q,"platform":{"architecture":"arm64","os":"linux"}}]}`,
		publish.MediaTypeOCIIndex, publish.MediaTypeOCIManifest, len(manifestAmd), amdManifestDigest,
		publish.MediaTypeOCIManifest, len(manifestArm), armManifestDigest))
	indexDigest := publish.ComputeDigest(indexBody)

	opsBefore := w.feedSignerOperationCount(t)

	// Publish the index through the INDEPENDENT handler h2 → the REAL committer
	// → the REAL kind-aware FeedSigner.
	idxResp := w.putIndexAs(t, w.s2.URL, "multi", indexBody)
	idxBody, _ := io.ReadAll(idxResp.Body)
	idxResp.Body.Close()
	if idxResp.StatusCode != http.StatusCreated {
		t.Fatalf("index publish through the production path status %d: %s", idxResp.StatusCode, idxBody)
	}

	state := w.currentRepoState(t)
	if state.Generation != 3 {
		t.Fatalf("expected generation 3 (child-amd=1, child-arm=2, index=3), got %d", state.Generation)
	}
	if state.Tags["multi"] != indexDigest {
		t.Fatalf("multi tag must map to the index digest: %+v", state.Tags)
	}
	// The committed children are preserved in the MANIFEST namespace, never
	// re-recorded as blobs.
	if _, ok := state.Manifests[amdManifestDigest]; !ok {
		t.Fatalf("amd child manifest must be preserved in the manifest map")
	}
	if _, ok := state.Manifests[armManifestDigest]; !ok {
		t.Fatalf("arm child manifest must be preserved in the manifest map")
	}
	if _, isBlob := state.Blobs[amdManifestDigest]; isBlob {
		t.Fatalf("a child manifest must never be recorded as a blob record")
	}
	// Exactly ONE new durable feed-signer operation row for the index (the two
	// children's rows were already counted in opsBefore).
	if delta := w.feedSignerOperationCount(t) - opsBefore; delta != 1 {
		t.Fatalf("expected exactly 1 new durable operation row for the index, got %d", delta)
	}

	// Idempotent retry of the SAME index: recognized via the production
	// read-after-write retry path — 201, NO second feed advance, NO new
	// durable operation row, NO staging consumption for a child digest.
	retryResp := w.putIndexAs(t, w.s1.URL, "multi", indexBody)
	retryBody, _ := io.ReadAll(retryResp.Body)
	retryResp.Body.Close()
	if retryResp.StatusCode != http.StatusCreated {
		t.Fatalf("index retry status %d: %s", retryResp.StatusCode, retryBody)
	}
	if got := w.currentRepoState(t).Generation; got != 3 {
		t.Fatalf("index retry must NOT advance the feed again, got generation %d", got)
	}
	if n := w.feedSignerOperationCount(t); n != opsBefore+1 {
		t.Fatalf("index retry must NOT create a new durable operation row, count %d want %d", n, opsBefore+1)
	}
}
