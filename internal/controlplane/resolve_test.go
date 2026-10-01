package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
)

// newResolveServer builds an InternalFeedServer whose signer carries a store
// seeded with one registry, so the dynamic-resolution route can be exercised.
func newResolveServer(t *testing.T, host, owner string) (*InternalFeedServer, Registry) {
	t.Helper()
	store := newProvisioningStore(t)
	user := seedProvisioningOwner(t, store)
	registry, err := store.CreateRegistry(context.Background(), Registry{
		Slug: "resolve", Host: host, ENSName: "",
		OwnerUserID: user.ID, FeedOwnerAddress: owner, DefaultStampBatchID: "batch-1",
		AnonymousPull: true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	srv, err := NewInternalFeedServer(&FeedSigner{Store: store}, &PublicationBinder{Store: store}, []byte(testInternalSecret), nil)
	if err != nil {
		t.Fatalf("new internal feed server: %v", err)
	}
	return srv, registry
}

func getResolve(t *testing.T, srv http.Handler, path, secret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if secret != "" {
		req.Header.Set(publish.InternalAuthHeader, secret)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestInternalResolveReturnsOwnerAndRegistryID(t *testing.T) {
	srv, registry := newResolveServer(t, "resolve.test", "0xabc123")

	rec := getResolve(t, srv, publish.InternalResolvePath+"resolve.test", testInternalSecret)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp publish.ResolveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Owner != "0xabc123" {
		t.Fatalf("owner: got %q want 0xabc123", resp.Owner)
	}
	if resp.RegistryID != registry.ID {
		t.Fatalf("registryID: got %d want %d", resp.RegistryID, registry.ID)
	}
}

func TestInternalResolveRejectsMissingAndWrongCredential(t *testing.T) {
	srv, _ := newResolveServer(t, "resolve.test", "0xabc123")

	if rec := getResolve(t, srv, publish.InternalResolvePath+"resolve.test", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing credential: got %d want 401", rec.Code)
	}
	if rec := getResolve(t, srv, publish.InternalResolvePath+"resolve.test", "wrong-secret"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong credential: got %d want 401", rec.Code)
	}
}

func TestInternalResolveUnknownHostIs404(t *testing.T) {
	srv, _ := newResolveServer(t, "resolve.test", "0xabc123")

	if rec := getResolve(t, srv, publish.InternalResolvePath+"other.test", testInternalSecret); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host: got %d want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestInternalResolveEmptyHostIs400(t *testing.T) {
	srv, _ := newResolveServer(t, "resolve.test", "0xabc123")

	if rec := getResolve(t, srv, publish.InternalResolvePath, testInternalSecret); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty host: got %d want 400", rec.Code)
	}
}

func TestInternalResolveRejectsNonGetMethod(t *testing.T) {
	srv, _ := newResolveServer(t, "resolve.test", "0xabc123")

	req := httptest.NewRequest(http.MethodPost, publish.InternalResolvePath+"resolve.test", nil)
	req.Header.Set(publish.InternalAuthHeader, testInternalSecret)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST on resolve: got %d want 405", rec.Code)
	}
}
