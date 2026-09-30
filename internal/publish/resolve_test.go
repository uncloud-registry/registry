package publish

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uncloud-registry/registry/internal/resolve"
)

func resolveServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, ControlPlaneRegistryIdentityResolver) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, ControlPlaneRegistryIdentityResolver{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
}

func TestControlPlaneResolverResolvesIdentity(t *testing.T) {
	srv, r := resolveServer(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			t.Fatalf("method: got %s want GET", req.Method)
		}
		if got := req.URL.Path; got != InternalResolvePath+"alice.test" {
			t.Fatalf("path: got %q want %q", got, InternalResolvePath+"alice.test")
		}
		if got := req.Header.Get(InternalAuthHeader); got != commitSecret {
			t.Fatalf("credential header: got %q want %q", got, commitSecret)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"owner":"0xabc123","registryID":7}`))
	})

	identity, err := r.ResolveRegistry(context.Background(), "alice.test:5000")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if identity.Host != "alice.test" {
		t.Fatalf("host: got %q want alice.test (port stripped)", identity.Host)
	}
	if identity.Owner != "0xabc123" {
		t.Fatalf("owner: got %q", identity.Owner)
	}
	if identity.RegistryID != 7 {
		t.Fatalf("registryID: got %d", identity.RegistryID)
	}
	_ = srv
}

func TestControlPlaneResolverMapsNotFound(t *testing.T) {
	_, r := resolveServer(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if _, err := r.ResolveRegistry(context.Background(), "ghost.test"); err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestControlPlaneResolverMapsUnauthorized(t *testing.T) {
	_, r := resolveServer(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	if _, err := r.ResolveRegistry(context.Background(), "alice.test"); err == nil {
		t.Fatal("expected error for 401")
	}
}

func TestControlPlaneResolverRejectsMalformedBody(t *testing.T) {
	cases := []string{
		`{"owner":"","registryID":7}`,                // empty owner
		`{"owner":"0xabc","registryID":0}`,           // non-positive registryID
		`{"owner":"0xabc","registryID":7,"extra":1}`, // unknown field
		`{"owner":"0xabc","registryID":7} trailing`,  // trailing content
		`{"owner":"0xabc"}`,                          // missing registryID
	}
	for _, body := range cases {
		_, r := resolveServer(t, func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
		if _, err := r.ResolveRegistry(context.Background(), "alice.test"); err == nil {
			t.Fatalf("expected error for malformed body %q", body)
		}
	}
}

func TestControlPlaneResolverRequiresCredentialAndURL(t *testing.T) {
	empty := ControlPlaneRegistryIdentityResolver{}
	if _, err := empty.ResolveRegistry(context.Background(), "alice.test"); err == nil {
		t.Fatal("expected error when base URL and secret are empty")
	}
	if _, err := (ControlPlaneRegistryIdentityResolver{BaseURL: "not-a-url"}).ResolveRegistry(context.Background(), "alice.test"); err == nil {
		t.Fatal("expected error when base URL is malformed")
	}
}

func TestControlPlaneResolverImplementsInterface(t *testing.T) {
	var _ resolve.RegistryIdentityResolver = ControlPlaneRegistryIdentityResolver{}
}
