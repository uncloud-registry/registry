// Package observability owns the operational telemetry surface of both
// binaries: Prometheus instruments (count/latency/error-class request
// series, staged bytes/sessions, publication conflicts/retries, dependency
// and integrity failures, outbox depth/age, cleanup results), the shared
// readiness summary used by /readyz, and the response-recording helpers used
// by the structured request loggers.
//
// BOUNDED-CARDINALITY CONTRACT: every instrument label is LIMITED to the
// fixed vocabulary {registry, operation, result, dependency}. No instrument
// may carry email, token, digest, upload-ID, or unbounded repository/ref
// labels, and label VALUES must come from the fixed constant sets in this
// package (plus, for the registry label, the canonical registry identity —
// a static host in the data plane or a control-plane registry ID — never a
// per-request, per-upload, or per-artifact value). Every instrumentation
// method is nil-safe so call sites need no nil guards.
package observability

import (
	"context"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/uncloud-registry/registry/internal/publish"
)

// Bounded label names. These are the ONLY label names any instrument in this
// package may carry.
const (
	LabelRegistry   = "registry"
	LabelOperation  = "operation"
	LabelResult     = "result"
	LabelDependency = "dependency"
)

// Request result classes (the "error class" of a request). Fixed vocabulary.
const (
	ResultSuccess     = "success"
	ResultClientError = "client_error"
	ResultServerError = "server_error"
)

// Operation vocabulary (fixed, bounded). The data plane classifies registry
// routes; the control plane classifies its UI/API surface.
const (
	OperationPing         = "ping"
	OperationCatalog      = "catalog"
	OperationPullManifest = "pull-manifest"
	OperationPushManifest = "push-manifest"
	OperationPullBlob     = "pull-blob"
	OperationUpload       = "upload"
	OperationUI           = "ui"
	OperationAPI          = "api"
	OperationToken        = "token"
	OperationRoot         = "root"
	OperationUnknown      = "unknown"
)

// Dependency vocabulary (fixed, bounded). Best-effort fixed classification at
// the call site — never derived from request data.
const (
	DependencyIdentity     = "registry-identity"
	DependencyPolicy       = "policy"
	DependencyControlPlane = "controlplane"
	DependencyBee          = "bee"
	DependencyStaging      = "staging"
	DependencyDatabase     = "database"
	DependencyExternal     = "external" // fixed log classification only
	DependencyNone         = "none"     // fixed log classification only
)

// SystemRegistry is the fixed registry label value for process-wide series
// (control-plane request metrics, system reconciliation) that have no single
// registry identity. It is a constant, so cardinality stays exactly one.
const SystemRegistry = "-"

// Cleanup item result classes for the cleanup_items_total series (the
// per-item outcome reported by a bounded cleanup pass).
const (
	CleanupExamined = "examined"
	CleanupExpired  = "expired"
	CleanupRemoved  = "removed"
	CleanupUnpinned = "unpinned"
	CleanupFailed   = "failed"
)

// Cleanup pass outcome classes for the cleanup_passes_total series.
const (
	CleanupPassOK      = "ok"
	CleanupPassAborted = "aborted"
)

// Metric names. The uncloud_ prefix keeps the surface namespaced.
const (
	MetricRequestsTotal        = "uncloud_requests_total"
	MetricRequestDuration      = "uncloud_request_duration_seconds"
	MetricDependencyFailures   = "uncloud_dependency_failures_total"
	MetricIntegrityFailures    = "uncloud_integrity_failures_total"
	MetricPublicationConflicts = "uncloud_publication_conflicts_total"
	MetricPublicationRetries   = "uncloud_publication_retries_total"
	MetricStagingBytes         = "uncloud_staging_bytes"
	MetricStagingSessions      = "uncloud_staging_sessions"
	MetricOutboxDepth          = "uncloud_outbox_pending_jobs"
	MetricOutboxOldestAge      = "uncloud_outbox_oldest_job_age_seconds"
	MetricCleanupPasses        = "uncloud_cleanup_passes_total"
	MetricCleanupItems         = "uncloud_cleanup_items_total"
)

// Instrumentation is ONE self-contained set of instruments owning its own
// Prometheus registry. Constructing a fresh Instrumentation NEVER touches a
// global registerer, so re-initialization (handler rebuilds, multiple test
// fixtures, both binaries in one process) can never panic with a
// duplicate-registration error; /metrics serves promhttp.HandlerFor(in.Registry).
type Instrumentation struct {
	// Registry is the instance's own registry; /metrics serves it directly.
	Registry *prometheus.Registry

	// RequestsTotal counts every observed request by
	// (registry, operation, result) — the request error class is the result
	// label.
	RequestsTotal *prometheus.CounterVec
	// RequestDuration seconds (registry, operation, result).
	RequestDuration *prometheus.HistogramVec
	// DependencyFailures counts dependency-class failures by
	// (registry, dependency). Dependency values are the fixed vocabulary.
	DependencyFailures *prometheus.CounterVec
	// IntegrityFailures counts pull/publication content-integrity failures by
	// (registry, operation).
	IntegrityFailures *prometheus.CounterVec
	// PublicationConflicts counts authoritative commit conflicts by
	// (registry) where registry is the control-plane registry ID.
	PublicationConflicts *prometheus.CounterVec
	// PublicationRetries counts one-time conflict rebuilds by (registry).
	PublicationRetries *prometheus.CounterVec
	// CleanupPasses counts bounded cleanup passes by (result: ok|aborted).
	CleanupPasses *prometheus.CounterVec
	// CleanupItems counts per-item cleanup outcomes by (result).
	CleanupItems *prometheus.CounterVec

	staging *refreshGaugePair
	outbox  *refreshGaugePair
}

// New returns an Instrumentation with every family registered on its own
// registry. Safe to call any number of times in one process.
func New() *Instrumentation {
	in := &Instrumentation{
		Registry: prometheus.NewRegistry(),
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: MetricRequestsTotal,
			Help: "Registry requests by registry, operation, and result class.",
		}, []string{LabelRegistry, LabelOperation, LabelResult}),
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    MetricRequestDuration,
			Help:    "Registry request latency in seconds by registry, operation, and result class.",
			Buckets: prometheus.DefBuckets,
		}, []string{LabelRegistry, LabelOperation, LabelResult}),
		DependencyFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: MetricDependencyFailures,
			Help: "Dependency-class request failures by registry and fixed dependency classification.",
		}, []string{LabelRegistry, LabelDependency}),
		IntegrityFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: MetricIntegrityFailures,
			Help: "Content-integrity verification failures by registry and operation.",
		}, []string{LabelRegistry, LabelOperation}),
		PublicationConflicts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: MetricPublicationConflicts,
			Help: "Authoritative publication commit conflicts by control-plane registry ID.",
		}, []string{LabelRegistry}),
		PublicationRetries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: MetricPublicationRetries,
			Help: "One-time conflict-rebuild retries by control-plane registry ID.",
		}, []string{LabelRegistry}),
		CleanupPasses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: MetricCleanupPasses,
			Help: "Bounded staging cleanup passes by outcome (ok|aborted).",
		}, []string{LabelResult}),
		CleanupItems: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: MetricCleanupItems,
			Help: "Staging cleanup item outcomes by fixed class (examined|expired|removed|unpinned|failed).",
		}, []string{LabelResult}),
	}
	in.Registry.MustRegister(
		in.RequestsTotal,
		in.RequestDuration,
		in.DependencyFailures,
		in.IntegrityFailures,
		in.PublicationConflicts,
		in.PublicationRetries,
		in.CleanupPasses,
		in.CleanupItems,
	)
	return in
}

// ObserveRequest records one request's count, latency, and error class. All
// arguments must be bounded: registry is the canonical identity or
// SystemRegistry; operation and result come from the fixed vocabularies.
func (in *Instrumentation) ObserveRequest(registry, operation, result string, duration time.Duration) {
	if in == nil {
		return
	}
	labels := prometheus.Labels{LabelRegistry: registry, LabelOperation: operation, LabelResult: result}
	in.RequestsTotal.With(labels).Inc()
	in.RequestDuration.With(labels).Observe(duration.Seconds())
}

// ObserveDependencyFailure records a dependency-class failure with the fixed
// dependency classification (see Dependency* constants).
func (in *Instrumentation) ObserveDependencyFailure(registry, dependency string) {
	if in == nil {
		return
	}
	in.DependencyFailures.WithLabelValues(registry, dependency).Inc()
}

// ObserveIntegrityFailure records a content-integrity verification failure
// (pull pre-verification or publication read-after-write verification).
func (in *Instrumentation) ObserveIntegrityFailure(registry, operation string) {
	if in == nil {
		return
	}
	in.IntegrityFailures.WithLabelValues(registry, operation).Inc()
}

// ObserveCleanupPass records one bounded cleanup pass outcome.
func (in *Instrumentation) ObserveCleanupPass(ok bool) {
	if in == nil {
		return
	}
	result := CleanupPassAborted
	if ok {
		result = CleanupPassOK
	}
	in.CleanupPasses.WithLabelValues(result).Inc()
}

// ObserveCleanupResult records one cleanup pass's per-item outcome counts.
func (in *Instrumentation) ObserveCleanupResult(examined, expired, removed, unpinned, failed int) {
	if in == nil {
		return
	}
	for _, pair := range []struct {
		class string
		n     int
	}{
		{CleanupExamined, examined},
		{CleanupExpired, expired},
		{CleanupRemoved, removed},
		{CleanupUnpinned, unpinned},
		{CleanupFailed, failed},
	} {
		if pair.n > 0 {
			in.CleanupItems.WithLabelValues(pair.class).Add(float64(pair.n))
		}
	}
}

// ObservePublicationConflict records an authoritative commit conflict for the
// bounded registry label value (the control-plane registry ID as text, or a
// fixed placeholder). The label value must come from a bounded identity —
// never a per-request or per-artifact value.
func (in *Instrumentation) ObservePublicationConflict(registryID string) {
	if in == nil {
		return
	}
	in.PublicationConflicts.WithLabelValues(registryID).Inc()
}

// ObservePublicationRetry records a one-time conflict rebuild for the bounded
// registry label value.
func (in *Instrumentation) ObservePublicationRetry(registryID string) {
	if in == nil {
		return
	}
	in.PublicationRetries.WithLabelValues(registryID).Inc()
}

// publishObserver adapts Instrumentation to publish.PublicationObserver so
// the conflict-safe commit path can report conflicts/rebuilds. The registry
// label is the control-plane registry ID (bounded).
type publishObserver struct {
	in *Instrumentation
}

func (o publishObserver) ObservePublicationConflict(registryID int64) {
	o.in.ObservePublicationConflict(strconv.FormatInt(registryID, 10))
}

func (o publishObserver) ObservePublicationRebuild(registryID int64) {
	o.in.ObservePublicationRetry(strconv.FormatInt(registryID, 10))
}

// PublisherObserver returns the publish.PublicationObserver adapter wired to
// this Instrumentation. Safe to call when in is nil (returns a no-op).
func (in *Instrumentation) PublisherObserver() publish.PublicationObserver {
	if in == nil {
		return publishObserver{}
	}
	return publishObserver{in: in}
}

// StagingStatsSource is implemented by durable staging services (and the
// in-memory store) to report the bounded staged-bytes/sessions snapshot for
// /metrics. Structural: implementations never need to import this package.
type StagingStatsSource interface {
	// StagingStats returns the total byte-bearing staged bytes and the total
	// number of byte-bearing staged sessions (active/finalizing/finalized/
	// deleting/expiring/claimed), or an error that fails the scrape closed.
	StagingStats(ctx context.Context) (bytes int64, sessions int64, err error)
}

// OutboxStatsSource is implemented by the control-plane store to report the
// provisioning outbox depth and oldest pending/claimed job age for /metrics.
type OutboxStatsSource interface {
	// OutboxStats returns the number of pending/claimed publication jobs and
	// the age of the OLDEST of them (zero when the outbox is empty).
	OutboxStats(ctx context.Context) (depth int, oldestAge time.Duration, err error)
}
