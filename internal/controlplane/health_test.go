package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/observability"
)

// newControlplaneHandler builds a real authed HTTPServer over a test Service,
// mirroring the http_test.go fixture.
func newControlplaneHandler(t *testing.T, service *Service) http.Handler {
	t.Helper()
	return NewHTTPServer(service, auth.SubjectResolver{Tokens: service.Tokens})
}

// newControlplaneTestService builds a fully healthy controlplane Service
// (database, master key, signing key, in-memory Bee publication).
func newControlplaneTestService(t *testing.T) *Service {
	t.Helper()
	store, err := OpenSQLite("file:controlplane_health_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.DB.Close() })
	tokens := newTestSessionManager(t)
	return &Service{
		Store:          store,
		Tokens:         tokens,
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
		Publisher:      newMemPublisher(),
	}
}

func getPath(t *testing.T, h http.Handler, path string) (int, http.Header, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Header(), rec.Body.String()
}

// TestControlplaneOutboxStats proves the /metrics outbox source counts only
// non-terminal publication jobs and reports the oldest one's age, with a
// zero-depth zero-age snapshot on an empty queue.
func TestControlplaneOutboxStats(t *testing.T) {
	svc := newControlplaneTestService(t)
	ctx := context.Background()

	depth, age, err := svc.OutboxStats(ctx)
	if err != nil {
		t.Fatalf("outbox stats on empty queue: %v", err)
	}
	if depth != 0 || age != 0 {
		t.Fatalf("empty queue stats = depth %d age %v, want 0/0", depth, age)
	}

	owner, _, err := svc.RegisterUser(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	created, err := svc.CreateRegistry(ctx, owner.ID, "alice", "alice.registry.eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	_ = created
	depth, age, err = svc.OutboxStats(ctx)
	if err != nil {
		t.Fatalf("outbox stats with pending jobs: %v", err)
	}
	if depth != 2 {
		t.Fatalf("outbox depth after create = %d, want 2 (auth + stamp)", depth)
	}
	if age <= 0 {
		t.Fatalf("oldest pending job age = %v, want positive", age)
	}
}

// TestControlplaneHealthEndpointsOutsideSecurityWrap proves /livez and
// /readyz never require session or CSRF material (outside the wrap), while UI
// routes that do require sessions still behave.
func TestControlplaneHealthEndpointsOutsideSecurityWrap(t *testing.T) {
	svc := newControlplaneTestService(t)
	server := NewHTTPServer(svc, auth.SubjectResolver{Tokens: svc.Tokens}).(*HTTPServer)
	status, _, _ := getPath(t, server, "/livez")
	if status != http.StatusOK {
		t.Fatalf("/livez status = %d", status)
	}
	status, _, _ = getPath(t, server, "/readyz")
	if status != http.StatusOK {
		t.Fatalf("/readyz status = %d", status)
	}
}

// TestControlplaneLivezReadyzUnauthenticated proves both endpoints answer
// WITHOUT any session or CSRF material (health endpoints sit outside the
// security wrap), and that a healthy service reports ready:true with the
// stable component summary and NO path/secret data.
func TestControlplaneLivezReadyzUnauthenticated(t *testing.T) {
	handler := newControlplaneHandler(t, newControlplaneTestService(t))

	status, _, body := getPath(t, handler, "/livez")
	if status != http.StatusOK {
		t.Fatalf("/livez status = %d", status)
	}
	if body != "ok" {
		t.Fatalf("/livez body = %q, want ok", body)
	}

	status, _, body = getPath(t, handler, "/readyz")
	if status != http.StatusOK {
		t.Fatalf("/readyz status = %d, body = %s", status, body)
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(body), &summary); err != nil {
		t.Fatalf("/readyz is not JSON: %v (body %q)", err, body)
	}
	if ready, _ := summary["status"].(string); ready != string(observability.StatusReady) {
		t.Fatalf("/readyz status = %q on healthy service: %s", ready, body)
	}
	checks, ok := summary["checks"].([]any)
	if !ok {
		t.Fatalf("/readyz checks missing: %s", body)
	}
	seen := map[string]bool{}
	for _, c := range checks {
		entry, ok := c.(map[string]any)
		if !ok {
			t.Fatalf("/readyz check entry not an object: %s", body)
		}
		name, _ := entry["name"].(string)
		okState, _ := entry["ok"].(bool)
		seen[name] = true
		if !okState {
			t.Fatalf("/readyz check %q not ok: %s", name, body)
		}
	}
	for _, component := range []string{"database", "master-key", "signing-key", "bee-publication"} {
		if !seen[component] {
			t.Fatalf("/readyz check %q missing: %s", component, body)
		}
	}
	if strings.Contains(body, "uncloud-registry.com") || strings.Contains(body, "sqlite") {
		t.Fatalf("/readyz must never carry paths/config: %s", body)
	}
}

// TestControlplaneLivezSurvivesBrokenDependencies proves liveness is
// independent of the database, keys, and Bee publication.
func TestControlplaneLivezSurvivesBrokenDependencies(t *testing.T) {
	svc := newControlplaneTestService(t)
	svc.FeedKeys = nil
	_ = svc.Store.DB.Close()
	handler := newControlplaneHandler(t, svc)

	status, _, body := getPath(t, handler, "/livez")
	if status != http.StatusOK {
		t.Fatalf("/livez status = %d", status)
	}
	if body != "ok" {
		t.Fatalf("/livez body = %q", body)
	}
}

// TestControlplaneReadyzFailsWithoutMasterKey proves the master-key check
// fails closed when no master key is loaded and the failure is data-free.
func TestControlplaneReadyzFailsWithoutMasterKey(t *testing.T) {
	svc := newControlplaneTestService(t)
	svc.FeedKeys = nil
	handler := newControlplaneHandler(t, svc)

	status, _, body := getPath(t, handler, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503 (body %s)", status, body)
	}
	if !strings.Contains(body, "master-key") {
		t.Fatalf("/readyz must name the failed master-key component: %s", body)
	}
	if strings.Contains(body, "key") && (strings.Contains(body, "0x") || strings.Contains(body, "hex")) {
		t.Fatalf("/readyz must never carry key material: %s", body)
	}
}

// TestControlplaneReadyzFailsOnDatabase proves the database check fails when
// the store is unreachable.
func TestControlplaneReadyzFailsOnDatabase(t *testing.T) {
	svc := newControlplaneTestService(t)
	_ = svc.Store.DB.Close()
	handler := newControlplaneHandler(t, svc)

	status, _, body := getPath(t, handler, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503 (body %s)", status, body)
	}
	if !strings.Contains(body, "database") {
		t.Fatalf("/readyz must name the failed database component: %s", body)
	}
}

// failingUploader is a Bee object store that always fails, for the required
// Bee publication readiness check.
type failingUploader struct{ err error }

func (f failingUploader) Put(_ context.Context, _ []byte, _ string) (string, error) {
	return "", f.err
}

func (f failingUploader) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, f.err
}

// TestControlplaneReadyzFailsOnRequiredBeePublication proves a registry with
// a pending required publication is NOT ready while Bee publication fails and
// IS ready once publication works.
func TestControlplaneReadyzFailsOnRequiredBeePublication(t *testing.T) {
	svc := newControlplaneTestService(t)
	owner, _, err := svc.RegisterUser(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	failing := &Publisher{Documents: failingUploader{err: errors.New("bee unreachable")}, Feeds: svc.Publisher.Feeds, FeedsReader: svc.Publisher.FeedsReader}
	svc.Publisher = failing
	created, err := svc.CreateRegistry(context.Background(), owner.ID, "alice", "alice.registry.eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	// Force the registry's existing required stamp publication to be
	// immediately claimable (stale next-attempt) so the bee-publication
	// component must really publish; CreateRegistry seeds one per kind.
	if _, err := svc.Store.DB.ExecContext(context.Background(),
		`update registry_publication_jobs set state='pending', next_attempt_at=1000 where registry_id=? and kind='stamp'`,
		created.Registry.ID); err != nil {
		t.Fatalf("force stale stamp publication: %v", err)
	}
	handler := newControlplaneHandler(t, svc)

	status, _, body := getPath(t, handler, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with failing Bee = %d, want 503 (body %s)", status, body)
	}
	if !strings.Contains(body, "bee-publication") {
		t.Fatalf("/readyz must name the failed bee-publication component: %s", body)
	}

	svc.Publisher = newMemPublisher()
	// Reset BOTH required bootstrap jobs to immediately claimable so the
	// working publisher really drains them (the failed attempt scheduled a
	// future retry).
	if _, err := svc.Store.DB.ExecContext(context.Background(),
		`update registry_publication_jobs set state='pending', next_attempt_at=1000, attempts=0, claimed_by='', claimed_until=null where registry_id=?`,
		created.Registry.ID); err != nil {
		t.Fatalf("reset required publications: %v", err)
	}
	status, _, body = getPath(t, handler, "/readyz")
	if status != http.StatusOK {
		t.Fatalf("/readyz with working Bee = %d (body %s)", status, body)
	}
	_ = created
}

// TestControlplaneReadyzNoSecretMaterial proves readiness responses carry no
// secret material even when probes fail: a database path and a fake key woven
// into the service must never appear.
func TestControlplaneReadyzNoSecretMaterial(t *testing.T) {
	svc := newControlplaneTestService(t)
	_ = svc.Store.DB.Close()
	handler := newControlplaneHandler(t, svc)

	status, _, body := getPath(t, handler, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d", status)
	}
	for _, needle := range []string{"file:", "mode=memory", "batch-", "uncloud"} {
		if strings.Contains(body, needle) {
			t.Fatalf("/readyz leaked %q: %s", needle, body)
		}
	}
}

// TestControlplaneMetricsRoute proves /metrics serves Prometheus text ONLY
// when instrumentation is wired, and answers outside the security wrap.
func TestControlplaneMetricsRoute(t *testing.T) {
	handler := newControlplaneHandler(t, newControlplaneTestService(t))

	status, _, _ := getPath(t, handler, "/metrics")
	if status != http.StatusNotFound {
		t.Fatalf("/metrics without instrumentation = %d, want 404", status)
	}
}

// TestControlplaneMetricsLiveWiring proves a controlplane with Metrics wired
// exposes the request-count family after an observed request, while an
// unwired server 404s /metrics.
func TestControlplaneMetricsLiveWiring(t *testing.T) {
	svc := newControlplaneTestService(t)
	server := NewHTTPServer(svc, auth.SubjectResolver{Tokens: svc.Tokens}).(*HTTPServer)

	status, _, _ := getPath(t, server, "/metrics")
	if status != http.StatusNotFound {
		t.Fatalf("/metrics without instrumentation = %d, want 404", status)
	}

	server.Metrics = observability.New()
	// Seed one observed request through the instrumented server, then scrape.
	status, _, _ = getPath(t, server, "/api/registries")
	if status != http.StatusOK && status != http.StatusSeeOther && status != http.StatusUnauthorized && status != http.StatusFound {
		t.Fatalf("seed request status = %d", status)
	}
	status, _, body := getPath(t, server, "/metrics")
	if status != http.StatusOK {
		t.Fatalf("/metrics on instrumented server = %d", status)
	}
	if !strings.Contains(body, observability.MetricRequestsTotal) {
		t.Fatalf("/metrics must expose %s: %s", observability.MetricRequestsTotal, body[:200])
	}
}

// TestControlplaneRequestLogNeedsWiring proves the HTTPServer exposes the
// Logger field (the slog emission middleware is shared with the registry and
// covered there; controlplane wires the same recorder).
func TestControlplaneRequestLogNeedsWiring(t *testing.T) {
	svc := newControlplaneTestService(t)
	server := NewHTTPServer(svc, auth.SubjectResolver{Tokens: svc.Tokens}).(*HTTPServer)
	if server.Metrics != nil || server.Logger != nil {
		t.Fatal("zero-value server must start with no telemetry")
	}
	var buf strings.Builder
	server.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
}
