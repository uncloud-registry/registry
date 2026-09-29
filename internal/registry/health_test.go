package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/observability"
	"github.com/uncloud-registry/registry/internal/staging"
)

// ---------------------------------------------------------------------------
// Task 23: /livez and /readyz on the registry data plane.
// ---------------------------------------------------------------------------

// requestOps performs a request on path and returns status and body text.
func requestOps(t *testing.T, h http.Handler, method, path string, host string) (int, string, http.Header) {
	t.Helper()
	var body io.Reader
	if method != http.MethodGet && method != http.MethodHead {
		body = strings.NewReader("{}")
	}
	req := httptest.NewRequest(method, path, body)
	if host != "" {
		req.Host = host
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec.Header()
}

// TestLivezIsIndependentOfDependencies proves /livez answers 200 even when
// every readiness dependency is broken (staging root gone, Bee down, missing
// keys): liveness must never consult external state.
func TestLivezIsIndependentOfDependencies(t *testing.T) {
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)
	handler.Authenticator = nil
	handler.BeeProbe = func(context.Context) error { return context.DeadlineExceeded }
	svc, root := durableTestStaging(t)
	handler.Staging = svc
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("remove staging root: %v", err)
	}

	status, body, _ := requestOps(t, handler, http.MethodGet, "/livez", "")
	if status != http.StatusOK {
		t.Fatalf("/livez status = %d, want 200 (liveness must be dependency-independent)", status)
	}
	if !strings.Contains(body, `"live"`) || !strings.Contains(body, `"status"`) {
		t.Fatalf("/livez body = %q, want a fixed status payload", body)
	}
}

// TestLivezReadyzUnauthenticated proves the ops endpoints answer WITHOUT any
// Authorization (standard unauthenticated health surface) and carry no
// challenge or secret material.
func TestLivezReadyzUnauthenticated(t *testing.T) {
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)
	handler.BeeProbe = func(context.Context) error { return nil }
	for _, path := range []string{"/livez", "/readyz"} {
		status, body, _ := requestOps(t, handler, http.MethodGet, path, "")
		if status != http.StatusOK {
			t.Fatalf("%s status = %d (no credentials), want 200", path, status)
		}
		for _, leak := range []string{"WWW-Authenticate", "Bearer", "token", "challenge"} {
			if strings.Contains(body, leak) {
				t.Fatalf("%s body must not carry %q: %s", path, leak, body)
			}
		}
	}
}

// durableTestStaging wires a durable staging service (real spool + SQLite)
// over a private temp dir. The returned root can be made inaccessible. The
// strict service requires a private 0700 directory with symlink-free path
// components (the staging test helper's contract), replicated here.
func durableTestStaging(t *testing.T) (staging.RegistryStore, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod staging dir: %v", err)
	}
	dir = symlinkFreeBase(dir)
	root := filepath.Join(dir, "spool")
	svc, err := staging.NewService(context.Background(), root, filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("new staging service: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc, root
}

// symlinkFreeBase rewrites the OS-standard /var and /tmp symlink prefixes to
// their real directories so the strict component walk never trips on them
// (same contract as the staging package's own test helper).
func symlinkFreeBase(p string) string {
	if !strings.HasPrefix(p, "/var/") && !strings.HasPrefix(p, "/tmp/") && p != "/var" && p != "/tmp" {
		return p
	}
	return "/private" + p
}

// TestReadyzFailsOnInaccessibleStagingRoot proves an inaccessible staging
// root fails the staged readiness component with the fixed classification.
func TestReadyzFailsOnInaccessibleStagingRoot(t *testing.T) {
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)
	svc, root := durableTestStaging(t)
	handler.Staging = svc
	handler.Authenticator = healthyAuthenticator(t)
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("remove staging root: %v", err)
	}

	status, body, _ := requestOps(t, handler, http.MethodGet, "/readyz", "")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503", status)
	}
	if !strings.Contains(body, observability.ComponentStaging) || !strings.Contains(body, `"ok":false`) {
		t.Fatalf("/readyz body must report the staging component down: %s", body)
	}
}

// TestReadyzFailsOnMissingVerificationKeys proves a handler without token
// verification key material is not ready.
func TestReadyzFailsOnMissingVerificationKeys(t *testing.T) {
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)
	handler.Authenticator = nil

	status, body, _ := requestOps(t, handler, http.MethodGet, "/readyz", "")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503", status)
	}
	if !strings.Contains(body, observability.ComponentVerification) {
		t.Fatalf("/readyz body must name the verification-keys component: %s", body)
	}

	// A BearerAuthenticator with nil verifier is equally not ready.
	handler.Authenticator = BearerAuthenticator{}
	status, _, _ = requestOps(t, handler, http.MethodGet, "/readyz", "")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status with nil verifier = %d, want 503", status)
	}

	handler.Authenticator = healthyAuthenticator(t)
	status, body, _ = requestOps(t, handler, http.MethodGet, "/readyz", "")
	if status != http.StatusOK {
		t.Fatalf("/readyz status with keys = %d, want 200: %s", status, body)
	}
}

// healthyAuthenticator builds a BearerAuthenticator with a real verifier from
// a fresh test handler.
func healthyAuthenticator(t *testing.T) Authenticator {
	t.Helper()
	h, _ := newTestHandlerWithKeys(t, nil, nil, nil, nil)
	return h.Authenticator
}

// TestReadyzFailsOnBeeProbeDown proves a failed Bee probe fails readiness and
// a healthy probe passes it.
func TestReadyzFailsOnBeeProbeDown(t *testing.T) {
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)
	handler.BeeProbe = func(context.Context) error { return io.EOF }

	status, body, _ := requestOps(t, handler, http.MethodGet, "/readyz", "")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503", status)
	}
	if !strings.Contains(body, observability.ComponentBee) {
		t.Fatalf("/readyz body must name the bee component: %s", body)
	}

	handler.BeeProbe = func(context.Context) error { return nil }
	status, body, _ = requestOps(t, handler, http.MethodGet, "/readyz", "")
	if status != http.StatusOK {
		t.Fatalf("/readyz status with healthy bee = %d, want 200: %s", status, body)
	}
}

// TestReadyzHealthyComponentSummary proves a healthy handler reports the
// applicable components (verification-keys; staging only with a durable
// store) as ok, and a nil Bee probe omits the bee component entirely
// (memory/dev mode has no Bee).
func TestReadyzHealthyComponentSummary(t *testing.T) {
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)

	status, body, _ := requestOps(t, handler, http.MethodGet, "/readyz", "")
	if status != http.StatusOK {
		t.Fatalf("/readyz status = %d, want 200: %s", status, body)
	}
	var summary observability.Readiness
	if err := json.Unmarshal([]byte(body), &summary); err != nil {
		t.Fatalf("readyz body must be structured JSON: %v", err)
	}
	if summary.Status != observability.StatusReady {
		t.Fatalf("summary status = %q, want %q", summary.Status, observability.StatusReady)
	}
	names := map[string]bool{}
	for _, check := range summary.Checks {
		names[check.Name] = true
		if !check.OK {
			t.Fatalf("component %q reported down on a healthy handler", check.Name)
		}
	}
	if !names[observability.ComponentVerification] {
		t.Fatalf("healthy summary must include verification-keys, got %v", names)
	}
	if names[observability.ComponentBee] {
		t.Fatalf("a nil Bee probe must OMIT the bee component, got %v", names)
	}
}

// TestReadyzNeverLeaksProbeDetail proves probe error text — which can carry
// paths, hosts, or tokens — never reaches the /readyz response, even when a
// probe fails with detail-bearing errors.
func TestReadyzNeverLeaksProbeDetail(t *testing.T) {
	const secret = "s3cr3t-master-key-918273645"
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)
	handler.BeeProbe = func(context.Context) error {
		return &detailError{detail: "bee down at https://bee.internal:1633 " + secret}
	}

	status, body, _ := requestOps(t, handler, http.MethodGet, "/readyz", "")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503", status)
	}
	for _, leak := range []string{secret, "bee.internal", "1633", "down at"} {
		if strings.Contains(body, leak) {
			t.Fatalf("/readyz body leaked probe detail %q: %s", leak, body)
		}
	}
}

type detailError struct{ detail string }

func (e *detailError) Error() string { return "component down: " + e.detail }

// TestOpsEndpointsOutsideRegistryParsing proves /livez /readyz /metrics are
// answered BEFORE registry API path parsing: they work without any /v2
// prefix, and the /v2 base ping still works alongside them.
func TestOpsEndpointsOutsideRegistryParsing(t *testing.T) {
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)

	status, _, _ := requestOps(t, handler, http.MethodGet, "/livez", "")
	if status != http.StatusOK {
		t.Fatalf("/livez status = %d, want 200", status)
	}
	status, _, _ = requestOps(t, handler, http.MethodGet, "/v2", "")
	if status != http.StatusOK {
		t.Fatalf("/v2 ping status = %d, want 200 (health routes must not shadow the API)", status)
	}
	status, _, _ = requestOps(t, handler, http.MethodGet, "/not-a-registry-path", "")
	if status != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404 (health routes are the ONLY additions)", status)
	}
}

// TestMetricsRouteServesPrometheus proves /metrics serves the instrumentation
// registry's exposition format and answers 404 when no instrumentation is
// wired.
func TestMetricsRouteServesPrometheus(t *testing.T) {
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)
	status, _, _ := requestOps(t, handler, http.MethodGet, "/metrics", "")
	if status != http.StatusNotFound {
		t.Fatalf("/metrics without instrumentation = %d, want 404", status)
	}

	obs := observability.New()
	handler.Metrics = obs
	// Observe a ping so the family exists in the exposition (a fresh
	// registry is otherwise empty).
	status, _, _ = requestOps(t, handler, http.MethodGet, "/v2", testServiceHost)
	if status != http.StatusOK {
		t.Fatalf("seed ping status = %d", status)
	}
	status, body, _ := requestOps(t, handler, http.MethodGet, "/metrics", "")
	if status != http.StatusOK {
		t.Fatalf("/metrics with instrumentation = %d, want 200", status)
	}
	if !strings.Contains(body, observability.MetricRequestsTotal) {
		t.Fatalf("/metrics body must expose %s: %s", observability.MetricRequestsTotal, body[:clamp(len(body), 0, 200)])
	}
}

// TestHandlerMetricsRequestCounting proves the request middleware records
// count/latency/error class with the bounded (registry, operation, result)
// triple after a real request.
func TestHandlerMetricsRequestCounting(t *testing.T) {
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)
	obs := observability.New()
	handler.Metrics = obs

	status, _, _ := requestOps(t, handler, http.MethodGet, "/v2", testServiceHost)
	if status != http.StatusOK {
		t.Fatalf("ping status = %d", status)
	}

	mfs, err := obs.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() != observability.MetricRequestsTotal {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels[observability.LabelOperation] == observability.OperationPing &&
				labels[observability.LabelResult] == observability.ResultSuccess &&
				labels[observability.LabelRegistry] == testServiceHost {
				if m.GetCounter().GetValue() != 1 {
					t.Fatalf("ping series count = %v, want 1", m.GetCounter().GetValue())
				}
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no requests_total{registry,operation=ping,result=success} series recorded")
	}
}

// ---------------------------------------------------------------------------
// Task 23: structured request logging (log/slog JSON, secrets never logged).
// ---------------------------------------------------------------------------

// jsonBufferLogger returns a slog logger writing JSON lines into buf.
func jsonBufferLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// parsedLogLines decodes every line of the JSON log buffer.
func parsedLogLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line is not valid JSON: %v (%q)", err, line)
		}
		lines = append(lines, entry)
	}
	return lines
}

// TestRequestLogStructuredAndExcludesSecrets proves the structured request
// log carries the required fields and that secrets appearing in the request
// (Authorization token, digest-bearing path) are ABSENT from the emitted
// JSON.
func TestRequestLogStructuredAndExcludesSecrets(t *testing.T) {
	const secretToken = "eyJsecrets-token-value-9876543210"
	h, _, _, _ := newFirstPushWorld(t)
	handler := h
	var buf bytes.Buffer
	handler.Logger = jsonBufferLogger(&buf)
	server := httptest.NewServer(handler)
	defer server.Close()

	pingReq, err := http.NewRequest(http.MethodGet, server.URL+"/v2", nil)
	if err != nil {
		t.Fatalf("create ping request: %v", err)
	}
	pingReq.Host = testServiceHost
	pingReq.Header.Set("Authorization", "Bearer "+secretToken)
	pingResp, err := http.DefaultClient.Do(pingReq)
	if err != nil {
		t.Fatalf("ping request failed: %v", err)
	}
	pingResp.Body.Close()
	if pingResp.StatusCode != http.StatusOK {
		t.Fatalf("ping status = %d", pingResp.StatusCode)
	}

	// A 404 on a digest-bearing path of a known repository: the digest must
	// never appear in the log.
	const digestPath = "/v2/backend/api/blobs/sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	blobReq, err := http.NewRequest(http.MethodGet, server.URL+digestPath, nil)
	if err != nil {
		t.Fatalf("create blob request: %v", err)
	}
	blobReq.Host = testServiceHost
	blobResp, err := http.DefaultClient.Do(blobReq)
	if err != nil {
		t.Fatalf("blob request failed: %v", err)
	}
	blobResp.Body.Close()
	if blobResp.StatusCode != http.StatusNotFound {
		t.Fatalf("blob digest path status = %d, want 404", blobResp.StatusCode)
	}

	lines := parsedLogLines(t, &buf)
	if len(lines) == 0 {
		t.Fatal("no request log lines emitted")
	}
	variables := []string{"component", "request_id", "registry", "repository", "action", "duration", "status", "result"}
	for _, entry := range lines {
		for _, secret := range []string{secretToken, "Bearer", "deadbeefdeadbeef", "sha256:deadbeef"} {
			raw, _ := json.Marshal(entry)
			if strings.Contains(string(raw), secret) {
				t.Fatalf("request log leaked %q: %s", secret, raw)
			}
		}
		for _, v := range variables {
			if _, ok := entry[v]; !ok {
				t.Errorf("request log line missing field %q: %v", v, entry)
			}
		}
		if entry["component"] != "registry" {
			t.Errorf("component = %v, want %q", entry["component"], "registry")
		}
	}
	var foundClientError bool
	for _, entry := range lines {
		if entry["status"] == float64(404) {
			foundClientError = true
			if entry["result"] != observability.ResultClientError {
				t.Errorf("404 log result = %v, want %q", entry["result"], observability.ResultClientError)
			}
			if entry["repository"] != "backend/api" {
				t.Errorf("404 log repository = %v, want %q", entry["repository"], "backend/api")
			}
		}
	}
	if !foundClientError {
		t.Fatal("no 404 request was logged")
	}
}

// TestRequestLogCarriesOperationIDOnPublish proves a successful publication
// log line includes the durable operation identity from the response header
// (never a fabricated value).
func TestRequestLogCarriesOperationIDOnPublish(t *testing.T) {
	h, _, _, issuer, serverURL := task14World(t)
	handler := h
	var buf bytes.Buffer
	handler.Logger = jsonBufferLogger(&buf)

	configBytes := []byte(`{"architecture":"amd64"}`)
	configDigest := stageBlob(t, serverURL, issuer, configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))
	resp := putManifest(t, serverURL, issuer, manifestBody)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("publish status = %d, want 201", resp.StatusCode)
	}
	operationID := resp.Header.Get(OperationIDHeader)

	lines := parsedLogLines(t, &buf)
	var found bool
	for _, entry := range lines {
		if entry["action"] == observability.OperationPushManifest && entry["status"] == float64(201) {
			found = true
			got, _ := entry["operation_id"].(string)
			if got == "" {
				t.Fatal("201 log line must carry the durable operation_id")
			}
			if got != operationID {
				t.Fatalf("log operation_id = %q, want the response header %q", got, operationID)
			}
		}
	}
	if !found {
		t.Fatal("no 201 push-manifest log line emitted")
	}
}

// TestRequestIDIsBoundedSanitized proves a caller-supplied X-Request-ID is
// sanitized to the bounded safe alphabet (log-injection safe) and absent
// values fall back to a generated ID.
func TestRequestIDIsBoundedSanitized(t *testing.T) {
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)
	var buf bytes.Buffer
	handler.Logger = jsonBufferLogger(&buf)

	req := httptest.NewRequest(http.MethodGet, "/v2", nil)
	req.Header.Set("X-Request-ID", "abc-123_xyz;rm -rf /win"+strings.Repeat("a", 200))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	lines := parsedLogLines(t, &buf)
	if len(lines) == 0 {
		t.Fatal("no log lines")
	}
	rid, _ := lines[0]["request_id"].(string)
	if rid == "" {
		t.Fatal("request_id must never be empty")
	}
	if len(rid) > 64 {
		t.Fatalf("request_id must be bounded, got %d chars", len(rid))
	}
	for _, c := range rid {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			t.Fatalf("request_id carries a character outside the safe alphabet: %q", rid)
		}
	}
	// The unsafe input substrings must be gone entirely.
	for _, bad := range []string{";", " ", "/", "rm "} {
		if strings.Contains(rid, bad) {
			t.Fatalf("request_id is not sanitized: %q", rid)
		}
	}
}

// TestOpsEndpointsSkippedByTelemetry proves health/metrics requests are NOT
// recorded as registry API requests (no log line, no request metrics).
func TestOpsEndpointsSkippedByTelemetry(t *testing.T) {
	h, _ := newTestHandler(t, nil, nil)
	handler := h.(*Handler)
	obs := observability.New()
	handler.Metrics = obs
	var buf bytes.Buffer
	handler.Logger = jsonBufferLogger(&buf)

	status, _, _ := requestOps(t, handler, http.MethodGet, "/livez", "")
	if status != http.StatusOK {
		t.Fatalf("/livez status = %d", status)
	}

	lines := parsedLogLines(t, &buf)
	if len(lines) != 0 {
		t.Fatalf("ops endpoints must not emit request log lines: %v", lines)
	}

	mfs, _ := obs.Registry.Gather()
	for _, mf := range mfs {
		if mf.GetName() != observability.MetricRequestsTotal {
			continue
		}
		for _, m := range mf.GetMetric() {
			if m.GetCounter().GetValue() != 0 {
				t.Fatalf("ops endpoints must not advance request metrics: %v", m)
			}
		}
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
