package registry

import (
	"context"
	"errors"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/uncloud-registry/registry/internal/observability"
)

// ---------------------------------------------------------------------------
// Task 23: operational endpoints (/livez, /readyz, /metrics).
//
// All three endpoints sit OUTSIDE the registry API parsing: they are
// dispatched before any path parsing, identity resolution, or authentication,
// and answer without credentials (standard unauthenticated health surface).
// Their responses are FIXED and data-free: component names and the fixed
// failure classification only — never probe error text, paths, hosts, refs,
// or key material. /metrics serves the instrumentation registry's exposition
// format (also unauthenticated; operators gate the listener with the same
// deployment controls as the health endpoints).
// ---------------------------------------------------------------------------

// Handler additions for Task 23 telemetry (see handler.go for the field
// declarations): Metrics *observability.Instrumentation, Logger *slog.Logger,
// and BeeProbe observability.Probe.

// livezBody is the fixed /livez payload. Liveness answers "the process is up"
// and must NEVER consult staging, Bee, keys, or the database.
const livezBody = `{"status":"live"}`

// handleLivez answers 200 with the fixed liveness payload, independent of
// every external dependency.
func (h *Handler) handleLivez(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(livezBody))
}

// handleMetrics serves the Prometheus exposition of the instrumentation
// registry. Without wired instrumentation the route is a fixed 404 (outside
// API parsing); with it, the route is the standard promhttp handler.
func (h *Handler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if h.Metrics == nil || h.Metrics.Registry == nil {
		http.NotFound(w, r)
		return
	}
	promhttp.HandlerFor(h.Metrics.Registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	}).ServeHTTP(w, r)
}

// handleReadyz runs every applicable readiness component under the short
// per-probe deadline and answers 200 (ready) or 503 (not ready) with the
// structured, non-secret component summary.
func (h *Handler) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	res := observability.RunReadiness(r.Context(), h.readinessComponents())
	status := http.StatusOK
	if res.Status != observability.StatusReady {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(res.JSON()))
}

// readinessComponents assembles the applicable readiness components for this
// process. A component whose probe is nil is NOT applicable and is omitted:
//
//   - staging: only the durable staging service (with a real spool root)
//     runs the accessibility check; the in-memory store has no root to check.
//   - verification-keys: the token-verification key material must be present.
//   - bee: only when a Bee dependency is wired (BeeProbe non-nil).
func (h *Handler) readinessComponents() []observability.Component {
	comps := []observability.Component{
		{Name: observability.ComponentVerification, Probe: h.probeVerificationKeys},
	}
	if root, ok := h.Staging.(stagingRootAccessChecker); ok {
		comps = append(comps, observability.Component{Name: observability.ComponentStaging, Probe: root.CheckStagingRootAccess})
	}
	if h.BeeProbe != nil {
		comps = append(comps, observability.Component{Name: observability.ComponentBee, Probe: h.BeeProbe})
	}
	return comps
}

// stagingRootAccessChecker is implemented by the durable staging service
// (memory/dev stores have no filesystem root and are omitted). Structural:
// the service needs no import of this package.
type stagingRootAccessChecker interface {
	// CheckStagingRootAccess verifies the spool root is present and is a
	// directory. Failures must be data-free (never echo the path).
	CheckStagingRootAccess(ctx context.Context) error
}

// errVerificationKeysMissing is the fixed data-free failure for a handler
// without token-verification key material.
var errVerificationKeysMissing = errors.New("registry token verification keys are not configured")

// probeVerificationKeys reports whether the handler can verify registry
// tokens: the authenticator must be present and, for the production bearer
// authenticator, the verifier must be non-nil.
func (h *Handler) probeVerificationKeys(context.Context) error {
	if h.Authenticator == nil {
		return errVerificationKeysMissing
	}
	if ba, ok := h.Authenticator.(BearerAuthenticator); ok && ba.Tokens == nil {
		return errVerificationKeysMissing
	}
	return nil
}

// CheckStagingRootAccess is the registry-side check for the durable staging
// service: documented on the service itself (stagingRootAccessChecker wiring),
// the service owns the check's data-free error contract.
