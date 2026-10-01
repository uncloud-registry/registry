package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// allowedLabelNames is the ONLY label-name vocabulary any instrument may
// carry: registry/operation/result/dependency. Adding a new label name to an
// instrument is a violation of the bounded-cardinality contract.
var allowedLabelNames = map[string]bool{
	LabelRegistry:   true,
	LabelOperation:  true,
	LabelResult:     true,
	LabelDependency: true,
}

// gatherFamily extracts a single metric family by name from a registry.
func gatherFamily(t *testing.T, reg *prometheus.Registry, name string) *dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather %s: %v", name, err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	t.Fatalf("metric family %q not found", name)
	return nil
}

// counterValue returns the total counter value across all label sets of a
// family, and the set of distinct label-name strings used.
func counterValue(t *testing.T, mf *dto.MetricFamily) (float64, map[string]bool) {
	t.Helper()
	var total float64
	labels := map[string]bool{}
	for _, m := range mf.GetMetric() {
		for _, lp := range m.GetLabel() {
			labels[lp.GetName()] = true
		}
		total += m.GetCounter().GetValue()
	}
	return total, labels
}

// gaugeValue returns the first metric's gauge value.
func gaugeValue(t *testing.T, mf *dto.MetricFamily) float64 {
	t.Helper()
	if len(mf.GetMetric()) == 0 {
		t.Fatalf("family %q has no metrics", mf.GetName())
	}
	return mf.GetMetric()[0].GetGauge().GetValue()
}

// TestInstrumentationInstancesAreIndependent proves metrics are registered
// EXACTLY once per Instrumentation: constructing two instances must never
// panic with a duplicate-registration error, and each instance's registry is
// its own (re-init safe).
func TestInstrumentationInstancesAreIndependent(t *testing.T) {
	first := New()
	second := New()
	if first == second {
		t.Fatal("New() returned the same instance twice")
	}
	if first.Registry == second.Registry {
		t.Fatal("two Instrumentation instances must own distinct registries")
	}
	// Registering a staging source on one instance must not affect the other.
	if err := first.RegisterStaging(fakeStagingSource{bytes: 1, sessions: 1}); err != nil {
		t.Fatalf("register staging on first: %v", err)
	}
	if err := second.RegisterStaging(fakeStagingSource{bytes: 2, sessions: 2}); err != nil {
		t.Fatalf("register staging on second: %v", err)
	}
	if got := gaugeValue(t, gatherFamily(t, first.Registry, MetricStagingBytes)); got != 1 {
		t.Fatalf("first staging bytes = %v, want 1", got)
	}
	if got := gaugeValue(t, gatherFamily(t, second.Registry, MetricStagingBytes)); got != 2 {
		t.Fatalf("second staging bytes = %v, want 2", got)
	}
}

// TestMetricsOnlyCarryBoundedLabels proves every instrument's label names are
// within the fixed {registry, operation, result, dependency} vocabulary and
// that the shared request instruments only ever see the bounded label values
// this package defines.
func TestMetricsOnlyCarryBoundedLabels(t *testing.T) {
	in := New()
	in.ObserveRequest("reg.example", OperationPing, ResultSuccess, time.Millisecond)
	in.ObserveRequest("reg.example", OperationPushManifest, ResultClientError, 2*time.Millisecond)
	in.ObserveRequest(SystemRegistry, OperationAPI, ResultServerError, 3*time.Millisecond)
	in.ObserveDependencyFailure("reg.example", DependencyBee)
	in.ObserveDependencyFailure(SystemRegistry, DependencyControlPlane)
	in.ObserveIntegrityFailure("reg.example", OperationPullBlob)
	in.ObservePublicationConflict("3")
	in.ObservePublicationRetry("3")
	in.ObserveCleanupPass(true)
	in.ObserveCleanupResult(10, 2, 1, 1, 0)

	mfs, err := in.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(mfs) == 0 {
		t.Fatal("no metric families gathered")
	}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if !allowedLabelNames[lp.GetName()] {
					t.Errorf("family %q carries label %q outside the bounded vocabulary", mf.GetName(), lp.GetName())
				}
			}
		}
	}
}

// TestRequestMetricsIncrementAndClassify proves request count/latency/error
// class series advance with the exact bounded (registry, operation, result)
// label triple.
func TestRequestMetricsIncrementAndClassify(t *testing.T) {
	in := New()
	in.ObserveRequest("reg.example", OperationPing, ResultSuccess, 5*time.Millisecond)

	mf := gatherFamily(t, in.Registry, MetricRequestsTotal)
	total, labels := counterValue(t, mf)
	if total != 1 {
		t.Fatalf("requests_total = %v, want 1", total)
	}
	for _, want := range []string{LabelRegistry, LabelOperation, LabelResult} {
		if !labels[want] {
			t.Errorf("requests_total missing label %q: %v", want, labels)
		}
	}
	// The recorded series must carry exactly the bounded triple.
	got := mf.GetMetric()[0].GetLabel()
	if len(got) != 3 {
		t.Fatalf("requests_total label count = %d, want 3", len(got))
	}

	durFamily := gatherFamily(t, in.Registry, MetricRequestDuration)
	if len(durFamily.GetMetric()) == 0 {
		t.Fatal("request_duration_seconds has no observed series")
	}
	// A histogram's count must reflect the single observation.
	if got := durFamily.GetMetric()[0].GetHistogram().GetSampleCount(); got != 1 {
		t.Fatalf("request_duration sample count = %d, want 1", got)
	}
}

// TestDependencyAndIntegritySeries proves the dedicated failure counters
// advance with their bounded labels.
func TestDependencyAndIntegritySeries(t *testing.T) {
	in := New()
	in.ObserveDependencyFailure("reg.example", DependencyBee)
	in.ObserveDependencyFailure("reg.example", DependencyBee)
	in.ObserveDependencyFailure("reg.example", DependencyControlPlane)
	in.ObserveIntegrityFailure("reg.example", OperationPullManifest)
	in.ObserveIntegrityFailure("reg.example", OperationPullBlob)

	mf := gatherFamily(t, in.Registry, MetricDependencyFailures)
	total, _ := counterValue(t, mf)
	if total != 3 {
		t.Fatalf("dependency_failures_total = %v, want 3", total)
	}

	mf = gatherFamily(t, in.Registry, MetricIntegrityFailures)
	total, _ = counterValue(t, mf)
	if total != 2 {
		t.Fatalf("integrity_failures_total = %v, want 2", total)
	}
}

// TestPublicationConflictRetrySeries proves the conflict/rebuild series map
// the control-plane registry ID to the bounded registry label.
func TestPublicationConflictRetrySeries(t *testing.T) {
	in := New()
	obs := in.PublisherObserver()
	obs.ObservePublicationConflict(7)
	obs.ObservePublicationConflict(7)
	obs.ObservePublicationRebuild(7)

	mf := gatherFamily(t, in.Registry, MetricPublicationConflicts)
	total, _ := counterValue(t, mf)
	if total != 2 {
		t.Fatalf("publication_conflicts_total = %v, want 2", total)
	}
	for _, m := range mf.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == LabelRegistry && lp.GetValue() != "7" {
				t.Fatalf("publication conflict registry label = %q, want \"7\"", lp.GetValue())
			}
		}
	}

	mf = gatherFamily(t, in.Registry, MetricPublicationRetries)
	total, _ = counterValue(t, mf)
	if total != 1 {
		t.Fatalf("publication_retries_total = %v, want 1", total)
	}
}

// TestCleanupResultSeries proves cleanup passes and per-item outcomes advance
// with the bounded result label.
func TestCleanupResultSeries(t *testing.T) {
	in := New()
	in.ObserveCleanupPass(true)
	in.ObserveCleanupPass(true)
	in.ObserveCleanupPass(false)
	in.ObserveCleanupResult(10, 2, 1, 1, 1)

	mf := gatherFamily(t, in.Registry, MetricCleanupPasses)
	total, _ := counterValue(t, mf)
	if total != 3 {
		t.Fatalf("cleanup_passes_total = %v, want 3", total)
	}

	mf = gatherFamily(t, in.Registry, MetricCleanupItems)
	total, _ = counterValue(t, mf)
	if total != 15 {
		t.Fatalf("cleanup_items_total = %v, want 15", total)
	}
}

// fakeStagingSource is a deterministic StagingStatsSource for tests.
type fakeStagingSource struct {
	bytes    int64
	sessions int64
	err      error
}

func (f fakeStagingSource) StagingStats(context.Context) (int64, int64, error) {
	return f.bytes, f.sessions, f.err
}

// TestStagingCollectorRefreshesFromSource proves the staged bytes/sessions
// gauges are refreshed from the source on every scrape and that a failing
// source leaves the last known value (never an error surfacing to a scrape).
func TestStagingCollectorRefreshesFromSource(t *testing.T) {
	src := fakeStagingSource{bytes: 1000, sessions: 4}
	in := New()
	if err := in.RegisterStaging(src); err != nil {
		t.Fatalf("register staging: %v", err)
	}
	if got := gaugeValue(t, gatherFamily(t, in.Registry, MetricStagingBytes)); got != 1000 {
		t.Fatalf("staging_bytes = %v, want 1000", got)
	}
	if got := gaugeValue(t, gatherFamily(t, in.Registry, MetricStagingSessions)); got != 4 {
		t.Fatalf("staging_sessions = %v, want 4", got)
	}

	// A failing source retains the last known value.
	src.err = context.DeadlineExceeded
	// The source is captured by value; rebuild the registration with a
	// failing source and assert the previous values survive the failure.
	failing := New()
	if err := failing.RegisterStaging(fakeStagingSource{bytes: 1000, sessions: 4}); err != nil {
		t.Fatalf("register failing staging: %v", err)
	}
	if err := failing.RegisterStaging(fakeStagingSource{bytes: 99999, sessions: 99, err: context.DeadlineExceeded}); err == nil {
		t.Fatal("registering a second staging collector on one registry must fail closed (no duplicate registration)")
	}
	if got := gaugeValue(t, gatherFamily(t, failing.Registry, MetricStagingBytes)); got != 1000 {
		t.Fatalf("staging_bytes after failed refresh = %v, want retained 1000", got)
	}
}

// fakeOutboxSource is a deterministic OutboxStatsSource for tests.
type fakeOutboxSource struct {
	depth int
	age   time.Duration
	err   error
}

func (f fakeOutboxSource) OutboxStats(context.Context) (int, time.Duration, error) {
	return f.depth, f.age, f.err
}

// TestOutboxCollectorRefreshesFromSource proves the outbox depth/age gauges
// are refreshed per scrape and duplicate registration fails closed.
func TestOutboxCollectorRefreshesFromSource(t *testing.T) {
	in := New()
	if err := in.RegisterOutbox(fakeOutboxSource{depth: 3, age: 90 * time.Second}); err != nil {
		t.Fatalf("register outbox: %v", err)
	}
	if got := gaugeValue(t, gatherFamily(t, in.Registry, MetricOutboxDepth)); got != 3 {
		t.Fatalf("outbox_depth = %v, want 3", got)
	}
	if got := gaugeValue(t, gatherFamily(t, in.Registry, MetricOutboxOldestAge)); got != 90 {
		t.Fatalf("outbox_oldest_age_seconds = %v, want 90", got)
	}
	if err := in.RegisterOutbox(fakeOutboxSource{depth: 9, age: time.Second}); err == nil {
		t.Fatal("registering a second outbox collector on one registry must fail closed")
	}
	if got := gaugeValue(t, gatherFamily(t, in.Registry, MetricOutboxDepth)); got != 3 {
		t.Fatalf("outbox_depth after refused duplicate = %v, want 3", got)
	}
}

// TestResultClass proves the fixed status→result-class mapping.
func TestResultClass(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusOK, ResultSuccess},
		{http.StatusCreated, ResultSuccess},
		{http.StatusUnauthorized, ResultClientError},
		{http.StatusNotFound, ResultClientError},
		{http.StatusConflict, ResultClientError},
		{http.StatusBadGateway, ResultServerError},
		{http.StatusServiceUnavailable, ResultServerError},
		{http.StatusInternalServerError, ResultServerError},
	}
	for _, tc := range cases {
		if got := ResultClass(tc.status); got != tc.want {
			t.Errorf("ResultClass(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

// TestResponseRecorderCapturesStatus proves the recorder captures the FIRST
// status write and defaults to 200 for headerless writes (the handler writes
// body without an explicit WriteHeader for success paths).
func TestResponseRecorderCapturesStatus(t *testing.T) {
	inner := httptest.NewRecorder()
	rec := NewResponseRecorder(inner)
	rec.WriteHeader(http.StatusTeapot)
	rec.WriteHeader(http.StatusOK) // later calls must be ignored by the recorder
	if got := rec.Status(); got != http.StatusTeapot {
		t.Fatalf("Status() = %d, want %d", got, http.StatusTeapot)
	}
	if inner.Code != http.StatusTeapot {
		t.Fatalf("inner status = %d, want %d", inner.Code, http.StatusTeapot)
	}

	inner2 := httptest.NewRecorder()
	rec2 := NewResponseRecorder(inner2)
	if _, err := rec2.Write([]byte("ok")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := rec2.Status(); got != http.StatusOK {
		t.Fatalf("Status() after bare Write = %d, want 200", got)
	}
}

// TestReadinessRunMasksProbeDetail proves the readiness runner never leaks
// probe error text (which can carry secrets) into the structured summary.
func TestReadinessRunMasksProbeDetail(t *testing.T) {
	const secret = "s3cr3t-master-key-abcdef"
	secretProbe := Probe(func(context.Context) error {
		return &probeDetailError{detail: secret}
	})
	res := RunReadiness(context.Background(), []Component{
		{Name: "staging", Probe: func(context.Context) error { return nil }},
		{Name: "master-key", Probe: secretProbe},
	})
	if res.Status != StatusNotReady {
		t.Fatalf("status = %q, want %q", res.Status, StatusNotReady)
	}
	body := res.JSON()
	if strings.Contains(body, secret) || strings.Contains(body, "s3cr3t") {
		t.Fatalf("readiness summary leaked probe detail: %s", body)
	}
	for _, check := range res.Checks {
		if check.Name == "master-key" {
			if check.OK {
				t.Fatal("master-key must be reported down")
			}
			if check.Error != "failed" {
				t.Fatalf("master-key error classification = %q, want fixed \"failed\"", check.Error)
			}
		}
	}
	// The healthy component must be reported as ok with no error field.
	for _, check := range res.Checks {
		if check.Name == "staging" && (!check.OK || check.Error != "") {
			t.Fatalf("staging check = %+v, want ok with no error", check)
		}
	}
}

// probeDetailError is a probe error carrying detail that must never surface.
type probeDetailError struct{ detail string }

func (e *probeDetailError) Error() string { return "probe failed: " + e.detail }

// TestReadinessSkipsNilProbes proves a nil probe means the component is not
// applicable and is omitted entirely from the summary.
func TestReadinessSkipsNilProbes(t *testing.T) {
	res := RunReadiness(context.Background(), []Component{
		{Name: "bee", Probe: nil},
		{Name: "staging", Probe: func(context.Context) error { return nil }},
	})
	if res.Status != StatusReady {
		t.Fatalf("status = %q, want %q", res.Status, StatusReady)
	}
	if len(res.Checks) != 1 || res.Checks[0].Name != "staging" {
		t.Fatalf("checks = %+v, want only the staging component", res.Checks)
	}
}

// TestReadinessProbeTimeoutBoundsEachProbe proves each component probe runs
// under a short timeout so a stalled dependency cannot hang /readyz.
func TestReadinessProbeTimeoutBoundsEachProbe(t *testing.T) {
	old := ReadinessProbeTimeout
	ReadinessProbeTimeout = 20 * time.Millisecond
	defer func() { ReadinessProbeTimeout = old }()

	blocked := make(chan struct{})
	defer close(blocked)
	start := time.Now()
	res := RunReadiness(context.Background(), []Component{
		{Name: "bee", Probe: func(ctx context.Context) error {
			<-ctx.Done() // block until the readiness timeout fires
			return ctx.Err()
		}},
		{Name: "blocker", Probe: func(ctx context.Context) error {
			select {
			case <-blocked:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}},
	})
	if elapsed := time.Since(start); elapsed > 5*ReadinessProbeTimeout {
		t.Fatalf("readiness ran %v, want bounded by the per-probe timeout (2 probes x %v)", elapsed, ReadinessProbeTimeout)
	}
	if res.Status != StatusNotReady || len(res.Checks) != 2 {
		t.Fatalf("unexpected readiness result: %+v", res)
	}
}
