package observability

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// refreshGaugePair is a prometheus.Collector exposing TWO gauges whose values
// are refreshed from a data source on every scrape. A failing source read
// leaves the previous values in place (the scrape never fails and never
// surfaces the raw error), and the collector can be registered exactly once
// per registry — a duplicate registration fails closed with an error instead
// of panicking. It is the shared mechanism behind the staging and outbox
// gauges.
type refreshGaugePair struct {
	firstDesc  *prometheus.Desc
	secondDesc *prometheus.Desc
	refresh    func(ctx context.Context) (first float64, second float64, err error)

	mu       sync.Mutex
	first    float64
	second   float64
	observed bool
}

// newStagingPair builds the staging_bytes / staging_sessions gauge pair
// refreshed from a StagingStatsSource.
func newStagingPair(source StagingStatsSource) *refreshGaugePair {
	bytesDesc := prometheus.NewDesc(MetricStagingBytes, "Total byte-bearing staged upload bytes (active/finalizing/finalized/deleting/expiring/claimed).", nil, nil)
	sessionsDesc := prometheus.NewDesc(MetricStagingSessions, "Total number of byte-bearing staged upload sessions.", nil, nil)
	return &refreshGaugePair{
		firstDesc:  bytesDesc,
		secondDesc: sessionsDesc,
		refresh: func(ctx context.Context) (float64, float64, error) {
			bytes, sessions, err := source.StagingStats(ctx)
			return float64(bytes), float64(sessions), err
		},
	}
}

// newOutboxPair builds the outbox_pending_jobs / outbox_oldest_job_age_seconds
// gauge pair refreshed from an OutboxStatsSource.
func newOutboxPair(source OutboxStatsSource) *refreshGaugePair {
	depthDesc := prometheus.NewDesc(MetricOutboxDepth, "Number of pending/claimed registry publication jobs in the provisioning outbox.", nil, nil)
	ageDesc := prometheus.NewDesc(MetricOutboxOldestAge, "Age in seconds of the OLDEST pending/claimed registry publication job (0 when the outbox is empty).", nil, nil)
	return &refreshGaugePair{
		firstDesc:  depthDesc,
		secondDesc: ageDesc,
		refresh: func(ctx context.Context) (float64, float64, error) {
			depth, age, err := source.OutboxStats(ctx)
			return float64(depth), age.Seconds(), err
		},
	}
}

// Describe implements prometheus.Collector.
func (p *refreshGaugePair) Describe(ch chan<- *prometheus.Desc) {
	ch <- p.firstDesc
	ch <- p.secondDesc
}

// Collect implements prometheus.Collector: it refreshes the pair from the
// source and emits either the fresh or the last-known values. A failed
// refresh is never surfaced to the scrape.
func (p *refreshGaugePair) Collect(ch chan<- prometheus.Metric) {
	p.mu.Lock()
	defer p.mu.Unlock()
	first, second, err := p.refresh(context.Background())
	if err == nil {
		p.first, p.second, p.observed = first, second, true
	}
	if !p.observed {
		return
	}
	ch <- prometheus.MustNewConstMetric(p.firstDesc, prometheus.GaugeValue, p.first)
	ch <- prometheus.MustNewConstMetric(p.secondDesc, prometheus.GaugeValue, p.second)
}

// errSourceAlreadyRegistered is the fixed data-free error for registering a
// second single-source collector (staging or outbox) on one Instrumentation.
var errSourceAlreadyRegistered = errors.New("observability: collector is already registered for this instrumentation")

// RegisterStaging registers the staged bytes/sessions gauges, refreshed from
// source on every scrape. It FAILS CLOSED when the pair is already registered
// on this Instrumentation (each instance supports exactly one staging source).
func (in *Instrumentation) RegisterStaging(source StagingStatsSource) error {
	if in == nil {
		return nil
	}
	if in.staging != nil {
		return errSourceAlreadyRegistered
	}
	pair := newStagingPair(source)
	if err := in.Registry.Register(pair); err != nil {
		return fmt.Errorf("observability: register staging gauges: %w", err)
	}
	in.staging = pair
	return nil
}

// RegisterOutbox registers the outbox depth/age gauges, refreshed from source
// on every scrape. It FAILS CLOSED when already registered.
func (in *Instrumentation) RegisterOutbox(source OutboxStatsSource) error {
	if in == nil {
		return nil
	}
	if in.outbox != nil {
		return errSourceAlreadyRegistered
	}
	pair := newOutboxPair(source)
	if err := in.Registry.Register(pair); err != nil {
		return fmt.Errorf("observability: register outbox gauges: %w", err)
	}
	in.outbox = pair
	return nil
}
