package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/uncloud-registry/registry/internal/observability"
)

// ---------------------------------------------------------------------------
// Task 23: operational endpoints (/livez, /readyz, /metrics).
//
// All three sit OUTSIDE the security wrap: they answer without session, CSRF,
// rate-limit, or origin material (standard unauthenticated health surface).
// Responses are FIXED and data-free: component names and the fixed failure
// classification only — never probe error text, paths, hostnames, or key
// material. /metrics serves the instrumentation registry's exposition.
// ---------------------------------------------------------------------------

// handleLivez answers 200 with a fixed liveness body, independent of the
// database, keys, and Bee publication.
func (s *HTTPServer) handleLivez(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleMetrics serves the Prometheus exposition. Without wired
// instrumentation the route is a fixed 404.
func (s *HTTPServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.Metrics == nil || s.Metrics.Registry == nil {
		http.NotFound(w, r)
		return
	}
	promhttp.HandlerFor(s.Metrics.Registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	}).ServeHTTP(w, r)
}

// handleReadyz runs the controlplane readiness components under the short
// per-probe deadline and answers 200 (ready) or 503 (not ready) with the
// structured, non-secret component summary. Each probe is bounded by
// RunReadiness's per-probe deadline (ReadinessProbeTimeout); there is no
// outer whole-run wrapper, matching the registry data plane (health.go), so
// both binaries rely only on per-probe timeouts.
func (s *HTTPServer) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	res := observability.RunReadiness(r.Context(), []observability.Component{
		{Name: observability.ComponentDatabase, Probe: s.Service.CheckDatabase},
		{Name: observability.ComponentMasterKey, Probe: s.Service.CheckMasterKey},
		{Name: observability.ComponentSigningKey, Probe: s.Service.CheckSigningKey},
		{Name: observability.ComponentBeePublication, Probe: s.Service.CheckRequiredBeePublication},
	})
	status := http.StatusOK
	if res.Status != observability.StatusReady {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(res.JSON()))
}

// ---------------------------------------------------------------------------
// Service-level readiness checks. Every check returns a FIXED, data-free
// error; the probe error text (which can carry DSNs, paths, hostnames, or
// key-version detail) never crosses the /readyz boundary.
// ---------------------------------------------------------------------------

var (
	errControlplaneDatabaseUnavailable       = errors.New("database is not accessible")
	errControlplaneMasterKeyUnavailable      = errors.New("master key is not loaded")
	errControlplaneSigningKeyUnavailable     = errors.New("feed signing key is not loaded")
	errControlplaneBeePublicationUnavailable = errors.New("required bee publication failed")
)

// OutboxStats returns the bounded /metrics snapshot of the publication queue
// (Task 23): the depth of non-terminal jobs (pending or claimed) and the age
// of the OLDEST non-terminal job (zero when the queue is empty). It is a pure
// read under a single context and never leaks job payload, ref, or registry
// data.
func (s *Service) OutboxStats(ctx context.Context) (int, time.Duration, error) {
	if s == nil || s.Store == nil || s.Store.DB == nil {
		return 0, 0, errControlplaneDatabaseUnavailable
	}
	var depth int
	var oldestNanos int64
	row := s.Store.DB.QueryRowContext(ctx, `select
		count(*),
		coalesce(min(created_at), 0)
		from registry_publication_jobs
		where state in ('pending','claimed')`)
	if err := row.Scan(&depth, &oldestNanos); err != nil {
		return 0, 0, errControlplaneDatabaseUnavailable
	}
	if depth == 0 || oldestNanos <= 0 {
		return 0, 0, nil
	}
	age := time.Since(time.Unix(0, oldestNanos))
	if age < 0 {
		age = 0
	}
	return depth, age, nil
}

// CheckDatabase pings the controlplane store.
func (s *Service) CheckDatabase(ctx context.Context) error {
	if s == nil || s.Store == nil || s.Store.DB == nil {
		return errControlplaneDatabaseUnavailable
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := s.Store.DB.PingContext(ctx); err != nil {
		return errControlplaneDatabaseUnavailable
	}
	return nil
}

// CheckMasterKey fails closed unless the master key material is loaded (the
// cipher holding the master-key set, always constructed from the master-key
// file at startup).
func (s *Service) CheckMasterKey(ctx context.Context) error {
	if s == nil || s.FeedKeys == nil {
		return errControlplaneMasterKeyUnavailable
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return nil
}

// CheckSigningKey fails closed unless the feed-owner signing key material is
// derivable: the signing key derives deterministically from the loaded master
// key, so a cipher holding at least one current key version satisfies it.
func (s *Service) CheckSigningKey(ctx context.Context) error {
	if s == nil || s.FeedKeys == nil || s.FeedKeys.CurrentVersion() <= 0 {
		return errControlplaneSigningKeyUnavailable
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return nil
}

// CheckRequiredBeePublication drains the required publication queue: one
// reconciliation batch is attempted and, after it, ANY outstanding (pending
// or claimed) publication job makes the component not-ready — a registry
// whose bootstrap policy cannot be delivered (or awaits a retry) means the
// controlplane is not ready. With nothing outstanding the check passes. The
// drain is transactional (lease-based claim) so a readiness probe can never
// corrupt worker state; the whole run is bounded by the probe context.
//
// DELIBERATE DESIGN (Task 23 round 1): the probe deliberately keeps the real
// drain. It is the only way to prove the publication pipeline (Bee upload,
// feed update, verified read-back) is actually live, and it doubles as an
// additional bounded progress pump alongside the background reconciler loop.
// A read-only outstanding-count query would report false not-ready for jobs
// the background worker is about to deliver, and an age-thresholded variant
// would gate readiness on time rather than on true pipeline state — both
// weaken the required-publication signal. The drain costs nothing at steady
// state (the outbox is empty: one claim query, zero publication work), is
// bounded per pass (default batch 50) and by the probe deadline, and is
// lease-guarded so concurrent probes cannot double-complete or corrupt jobs.
func (s *Service) CheckRequiredBeePublication(ctx context.Context) error {
	if s == nil || s.Publisher == nil {
		return errControlplaneBeePublicationUnavailable
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	rec, err := s.NewReconciler()
	if err != nil {
		return errControlplaneBeePublicationUnavailable
	}
	if err := rec.RunOnce(ctx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return err
		}
		return errControlplaneBeePublicationUnavailable
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	// A retryable failure schedules a future attempt rather than failing the
	// drain, so outstanding non-terminal work after the drain is the honest
	// "required publication not delivered" signal.
	var outstanding int64
	if err := s.Store.DB.QueryRowContext(ctx,
		`select count(*) from registry_publication_jobs where state in ('pending','claimed')`,
	).Scan(&outstanding); err != nil {
		return errControlplaneBeePublicationUnavailable
	}
	if outstanding > 0 {
		return errControlplaneBeePublicationUnavailable
	}
	return nil
}
