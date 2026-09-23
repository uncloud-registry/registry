package controlplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/uncloud-registry/registry/internal/swarm"
)

// beeIntegrationServer is a minimal in-memory Bee HTTP surface used to prove
// the REAL reconcile path end-to-end: POST /bytes returns a deterministic
// 64-hex ref for the uploaded payload, GET /bytes/<ref> returns the payload
// back, and GET /feeds/<owner>/<topic> returns the RAW BINARY payload
// currently stored at that feed (the Task 11 wire contract: the decoded
// 32-byte reference, no ASCII hex, no 8-byte chunk prefix) plus the required
// Swarm-Feed-Index header. This is the endpoint model the production
// resolver relies on.
type beeIntegrationServer struct {
	mu       sync.Mutex
	payloads map[string][]byte
	feeds    map[string][]byte
	seq      int
}

func newBeeIntegrationServer() *beeIntegrationServer {
	return &beeIntegrationServer{payloads: map[string][]byte{}, feeds: map[string][]byte{}}
}

// pathForFeedRef maps a feed://owner/topic reference to the /feeds/owner/topic
// endpoint path that both the updater and the resolver use.
func pathForFeedRef(feed string) string {
	trimmed := strings.TrimPrefix(feed, "feed://")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	return "/feeds/" + parts[0] + "/" + parts[1]
}

func (s *beeIntegrationServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/bytes":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.seq++
			ref := fmt.Sprintf("%064x", s.seq) // deterministic 64 lowercase hex
			s.payloads[ref] = body
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"reference":"%s"}`, ref)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/bytes/"):
			ref := strings.TrimPrefix(r.URL.Path, "/bytes/")
			payload, ok := s.payloads[ref]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/feeds/"):
			// The feed endpoint returns the raw BINARY payload: the 32 decoded
			// reference bytes (Bee serves the chunk payload as
			// application/octet-stream with the span stripped), plus the
			// required index headers.
			payload, ok := s.feeds[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Swarm-Feed-Index", "0000000000000000")
			w.Header().Set("Swarm-Feed-Index-Next", "0000000000000001")
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	})
}

// beeIntegrationFeeds writes a feed update into the SAME authoritative feed map
// the HTTP server resolves from, so the updater's write is exactly what the
// real resolver reads back over the wire. The 64-hex reference is stored
// DECODED (the binary 32-byte payload the Task 11 resolver reads).
type beeIntegrationFeeds struct {
	server *beeIntegrationServer
}

func (b *beeIntegrationFeeds) UpdateRegistryFeed(_ context.Context, _ Registry, feed string, ref string, _ string) error {
	raw, err := hex.DecodeString(ref)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("integration feed ref must be a 64-hex reference")
	}
	b.server.mu.Lock()
	defer b.server.mu.Unlock()
	b.server.feeds[pathForFeedRef(feed)] = raw
	return nil
}

// TestProvisioningRealBeeFeedMappingCompletes proves the REAL production
// resolver + object store participate in reconciliation: the reconciler uploads
// the policy via the Bee object store, the feed updater writes the object ref,
// and the real BeeFeedResolver reads the feed body (the raw reference) back and
// resolves it to exactly the uploaded ref — only then is a registry marked
// 'ready'.
func TestProvisioningRealBeeFeedMappingCompletes(t *testing.T) {
	beesrv := newBeeIntegrationServer()
	srv := httptest.NewServer(beesrv.handler())
	defer srv.Close()

	store := mustOpenFileStore(t, t.TempDir()+"/bee_map.db")
	service := &Service{
		Store:          store,
		Tokens:         newTestSessionManager(t),
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
		Publisher: &Publisher{
			Documents:   swarm.NewBeeObjectStore(srv.URL, srv.Client()),
			Feeds:       &beeIntegrationFeeds{server: beesrv},
			FeedsReader: swarm.NewBeeFeedResolver(srv.URL, srv.Client()),
		},
	}
	owner, _, err := service.RegisterUser(context.Background(), "bee-owner@example.com", "password123")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	created, err := service.CreateRegistry(context.Background(), owner.ID, "beereg", "beereg.eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	rec, err := service.NewReconciler()
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if err := rec.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once: %v", err)
	}
	reg, err := store.FindRegistryByID(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if reg.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("expected ready after real Bee feed mapping, got %q", reg.ProvisioningState)
	}
	jobs, err := store.listJobsForRegistry(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("expected two jobs, got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.State != PublicationStateSucceeded {
			t.Fatalf("job %s must succeed, got %s", j.Kind, j.State)
		}
		if j.ObjectRef == "" || j.FeedRef == "" {
			t.Fatalf("succeeded job must carry refs, got %+v", j)
		}
		// The uploaded object must be the exact policy bytes — read back via
		// the real object store.
		got, err := service.Publisher.Documents.Get(context.Background(), j.ObjectRef)
		if err != nil {
			t.Fatalf("read back object: %v", err)
		}
		if !bytes.Equal(got, j.PayloadJSON) {
			t.Fatalf("object read-back must equal the payload")
		}
	}
}

// TestProvisioningRealBeeResolverCatchesMisdirectedFeed proves the REAL
// resolver refuses to complete when the feed resolves to a wrong ref (a
// mis-directed / overwritten feed), leaving the registry provisioning and the
// job retryable with the coarse "feed resolution mismatch" class.
func TestProvisioningRealBeeResolverCatchesMisdirectedFeed(t *testing.T) {
	beesrv := newBeeIntegrationServer()
	srv := httptest.NewServer(beesrv.handler())
	defer srv.Close()

	resolver := swarm.NewBeeFeedResolver(srv.URL, srv.Client())

	store := mustOpenFileStore(t, t.TempDir()+"/bee_misdirect.db")
	service := &Service{
		Store:          store,
		Tokens:         newTestSessionManager(t),
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
		Publisher: &Publisher{
			Documents:   swarm.NewBeeObjectStore(srv.URL, srv.Client()),
			Feeds:       noopFeedUpdater{},
			FeedsReader: resolver,
		},
	}
	owner, _, err := service.RegisterUser(context.Background(), "bee-misdirect@example.com", "password123")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	created, err := service.CreateRegistry(context.Background(), owner.ID, "beemisdr", "beemisdr.eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	// Pre-seed the feeds the resolver reads with a WRONG (but valid 64-hex)
	// ref, simulating a mis-directed feed. The no-op updater never overwrites.
	beesrv.mu.Lock()
	for _, kind := range []string{PublicationKindAuth, PublicationKindStamp} {
		var feed string
		if kind == PublicationKindAuth {
			feed = authPolicyFeedRef(created.Registry)
		} else {
			feed = stampPolicyFeedRef(created.Registry)
		}
		// Seed a WRONG (but valid) binary reference, simulating a mis-directed
		// feed: the resolver reads raw binary, so the 64-hex ref must be
		// decoded to its 32 bytes exactly as a real Task-11 feed payload.
		wrong := fmt.Sprintf("%064x", 999_999)
		raw, derr := hex.DecodeString(wrong)
		if derr != nil {
			t.Fatalf("decode seeded ref: %v", derr)
		}
		beesrv.feeds[pathForFeedRef(feed)] = raw
	}
	beesrv.mu.Unlock()

	rec, err := service.NewReconciler()
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if err := rec.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once: %v", err)
	}
	jobs, err := store.listJobsForRegistry(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	for _, j := range jobs {
		if j.State == PublicationStateSucceeded {
			t.Fatalf("a mis-directed feed must never succeed a job, got %+v", j)
		}
		if j.LastError != "feed resolution mismatch" {
			t.Fatalf("expected coarse feed resolution mismatch, got %q", j.LastError)
		}
	}
	reg, err := store.FindRegistryByID(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if reg.ProvisioningState == ProvisioningStateReady {
		t.Fatal("a mis-directed feed must never mark the registry ready")
	}
}
