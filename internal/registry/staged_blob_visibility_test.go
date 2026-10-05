package registry

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
)

// Docker re-checks a blob (HEAD) right after uploading it, before any
// manifest commit. The uploader must see its own finalized staged blob;
// another actor must not.
func TestStagedBlobVisibleOnlyToUploaderBeforeCommit(t *testing.T) {
	t.Parallel()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)
	handler, issuer := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	bearer := func(user string, actions ...auth.Action) string {
		return registryBearer(t, issuer, user, testServiceHost, "backend/api", actions, time.Hour)
	}
	do := func(method, url string, body []byte, token string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, url, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = testServiceHost
		req.Header.Set("Authorization", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	push := bearer("user:alice", auth.ActionPush)
	start := do(http.MethodPost, server.URL+"/v2/backend/api/blobs/uploads/", nil, push)
	if start.StatusCode != http.StatusAccepted {
		t.Fatalf("start = %d", start.StatusCode)
	}
	uploadURL := server.URL + start.Header.Get("Location")
	data := []byte(`{"staged":"blob"}`)
	digest := publish.ComputeDigest(data)
	if r := do(http.MethodPut, uploadURL+"?digest="+digest, data, push); r.StatusCode != http.StatusCreated {
		t.Fatalf("finalize = %d", r.StatusCode)
	}

	blobURL := server.URL + "/v2/backend/api/blobs/" + digest
	if r := do(http.MethodHead, blobURL, nil, bearer("user:alice", auth.ActionPull)); r.StatusCode != http.StatusOK {
		t.Fatalf("uploader HEAD staged blob = %d, want 200", r.StatusCode)
	}
	// The fixture's pull policy may reject bob outright (401) or let him
	// through to a 404; either way he must never see the staged blob.
	if r := do(http.MethodHead, blobURL, nil, bearer("user:bob", auth.ActionPull)); r.StatusCode == http.StatusOK {
		t.Fatalf("other actor HEAD staged blob = %d, must not be 200", r.StatusCode)
	}
}
