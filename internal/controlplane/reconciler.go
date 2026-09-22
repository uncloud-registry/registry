package controlplane

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

// Reconciler drives the transactional provisioning outbox: it claims durable
// bootstrap jobs, performs each logical publication stage (upload → feed update
// → verified read-back), persists progress between stages so retries resume
// without duplicating completed work, and transitions a registry to 'ready'
// only once BOTH jobs complete verified read-back. Terminal policy failure is
// reached only through the explicit bounded-attempts rule.
//
// Claiming is concurrency-safe (guarded conditional UPDATE), bounded, and
// short-transaction — no SQL transaction is ever held during a network call.
// RunOnce is deterministic and self-contained for tests; Run wraps it in a
// bounded loop with context cancellation and graceful join.
type Reconciler struct {
	Store     *Store
	Documents ObjectStore
	Feeds     RegistryFeedUpdater
	// ResolveFeeds is the feed resolution/read contract: it independently
	// resolves a policy feed to the ref currently stored at it, so the
	// reconciler proves the feed the updater claims it wrote really points at
	// the uploaded object (a no-op/wrong/overwritten updater never completes).
	ResolveFeeds FeedResolver

	// Lease is how long one worker's claim holds a job before another worker
	// may reclaim it (stale-claim reclamation).
	Lease time.Duration
	// BatchSize bounds how many jobs a single claim pass processes.
	BatchSize int
	// MaxAttempts is the bounded rule for terminal failure: a job whose
	// attempts reach this value is marked failed and its registry 'failed'.
	MaxAttempts int
	// BackoffBase/BackoffMax bound the exponential retry schedule.
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// Interval is the idle delay between passes in the Run loop.
	Interval time.Duration

	// now is an injectable clock for determinism in tests. Zero means
	// time.Now().UTC().
	now func() time.Time
}

// Default reconciler tuning (bounded, worker-friendly, crash-safe).
const (
	defaultClaimLease   = 30 * time.Second
	defaultBatchSize    = 50
	defaultMaxAttempts  = 8
	defaultBackoffBase  = time.Second
	defaultBackoffMax   = 5 * time.Minute
	defaultLoopInterval = 2 * time.Second
)

// NewReconciler returns a Reconciler over an already-open store, a
// writable/readable object store, a feed updater, and a feed resolver. It
// FAILS CLOSED on any missing dependency (store, documents, feeds updater, or
// feed resolver) rather than constructing a reconciler that could silently
// skip a stage or complete an unverified job. It performs no I/O here; it is
// safe to construct after config and key material are validated.
func NewReconciler(store *Store, documents ObjectStore, feeds RegistryFeedUpdater, resolveFeeds FeedResolver) (*Reconciler, error) {
	if store == nil || documents == nil || feeds == nil {
		return nil, errReconcilerNotConfigured
	}
	if resolveFeeds == nil {
		// Without feed resolution/read-back the reconciler cannot prove a
		// feed points at the uploaded object, so it must fail closed.
		return nil, errReconcilerNotConfigured
	}
	return &Reconciler{
		Store:        store,
		Documents:    documents,
		Feeds:        feeds,
		ResolveFeeds: resolveFeeds,
		Lease:        defaultClaimLease,
		BatchSize:    defaultBatchSize,
		MaxAttempts:  defaultMaxAttempts,
		BackoffBase:  defaultBackoffBase,
		BackoffMax:   defaultBackoffMax,
		Interval:     defaultLoopInterval,
	}, nil
}

// validate returns a data-free configuration error (never panics) when any
// dependency the reconciler needs to publish and verify a job is missing. It
// guards RunOnce even for an externally-constructed zero-value Reconciler.
func (r *Reconciler) validate() error {
	if r == nil {
		return errReconcilerNotConfigured
	}
	if r.Store == nil || r.Documents == nil || r.Feeds == nil || r.ResolveFeeds == nil {
		return errReconcilerNotConfigured
	}
	return nil
}

func (r *Reconciler) nowUTC() time.Time {
	if r.now != nil {
		return r.now().UTC()
	}
	return time.Now().UTC()
}

// RunOnce performs one deterministic reconciliation pass: claim a bounded
// batch of due/stale jobs and process each through its logical stages. It
// returns nil after a normal pass (retryable external failures are persisted
// as backoff, not returned); it returns an error only for fatal conditions
// (missing configuration, datastore, or lost-claim on persist). A missing
// dependency returns the data-free errReconcilerNotConfigured, never a panic.
// Test-injectable via reconciler.now and the store's clock where relevant.
func (r *Reconciler) RunOnce(ctx context.Context) error {
	if err := r.validate(); err != nil {
		return err
	}
	now := r.nowUTC()
	jobs, worker, err := r.Store.ClaimStalePublicationJobs(ctx, now, r.Lease, r.BatchSize)
	if err != nil {
		return fmt.Errorf("reconcile: claim: %w", err)
	}
	for i := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.reconcileJob(ctx, jobs[i], worker, now); err != nil {
			return err
		}
	}
	return nil
}

// Run is the bounded worker loop. It runs passes indefinitely until ctx is
// cancelled, idling Interval between passes and backing off on fatal errors. It
// returns when the context is done (nil, graceful), so an owner can start it in
// a goroutine and WaitGroup-join it after cancelling the context.
func (r *Reconciler) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return nil // graceful join on cancellation
		}
		if err := r.RunOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if err := waitFor(ctx, r.Interval); err != nil {
				return nil
			}
			continue
		}
		if err := waitFor(ctx, r.Interval); err != nil {
			return nil
		}
	}
}

// waitFor sleeps d respecting ctx cancellation; it returns ctx.Err() when the
// context is done first.
func waitFor(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// reconcileJob advances one claimed job through its persisted stages. Each
// network stage is followed by a persist of the resulting ref BEFORE the next
// stage, so a crash or failure between stages resumes without repeating a
// completed logical operation. All external workers fail retryably (persisted
// backoff); only datastore/persist failures are returned as fatal.
func (r *Reconciler) reconcileJob(ctx context.Context, job PublicationJob, worker string, now time.Time) error {
	reg, err := r.Store.FindRegistryByID(ctx, job.RegistryID)
	if err != nil {
		return fmt.Errorf("reconcile: load registry %d: %w", job.RegistryID, err)
	}

	// Stage 1 — upload the deterministic canonical payload. Skip when the
	// object ref is already persisted (upload completed on a prior attempt).
	if job.ObjectRef == "" {
		ref, err := r.Documents.Put(ctx, job.PayloadJSON, reg.DefaultStampBatchID)
		if err != nil {
			return r.failRetryable(ctx, job, worker, now, "upload failed")
		}
		if err := r.Store.SetPublicationObjectRef(ctx, job.ID, worker, ref); err != nil {
			return fmt.Errorf("reconcile: persist object ref: %w", err)
		}
		job.ObjectRef = ref
	}

	// Stage 2 — publish the feed pointing at the uploaded object. Skip when
	// the feed ref is already persisted.
	if job.FeedRef == "" {
		feed := r.feedRefForJob(reg, job.Kind)
		if err := r.Feeds.UpdateRegistryFeed(ctx, reg, feed, job.ObjectRef); err != nil {
			return r.failRetryable(ctx, job, worker, now, "feed update failed")
		}
		if err := r.Store.SetPublicationFeedRef(ctx, job.ID, worker, feed); err != nil {
			return fmt.Errorf("reconcile: persist feed ref: %w", err)
		}
		job.FeedRef = feed
	}

	// Stage 3 — verified feed resolution: the feed MUST independently resolve
	// to exactly the object ref the job uploaded. This is the explicit
	// feed read-back that closes the no-op/wrong/overwritten-updater gap:
	// persisting the feed_ref identifier is not proof. A feed that was never
	// published, points at a different ref, or was overwritten is retryable
	// (never a false completion).
	feed := r.feedRefForJob(reg, job.Kind)
	resolved, err := r.ResolveFeeds.ResolveFeed(ctx, feed)
	if err != nil || resolved != job.ObjectRef {
		return r.failRetryable(ctx, job, worker, now, "feed resolution mismatch")
	}

	// Stage 4 — verified object read-back: the uploaded object must return
	// exactly the expected policy bytes. A mismatch (or read failure) is
	// retryable, so a partially satisfying object store never falsely
	// completes a job.
	got, err := r.Documents.Get(ctx, job.ObjectRef)
	if err != nil || !bytes.Equal(got, job.PayloadJSON) {
		return r.failRetryable(ctx, job, worker, now, "read-back mismatch")
	}

	if err := r.Store.CompletePublicationJob(ctx, job.ID, worker, now); err != nil {
		return fmt.Errorf("reconcile: complete job: %w", err)
	}

	// A registry is 'ready' only when BOTH bootstrap jobs are succeeded.
	done, err := r.Store.RegistryProvisioningJobsComplete(ctx, job.RegistryID)
	if err != nil {
		return fmt.Errorf("reconcile: check provisioning complete: %w", err)
	}
	if done {
		if err := r.Store.MarkRegistryReady(ctx, job.RegistryID); err != nil {
			return err
		}
	}
	return nil
}

// failRetryable records a retryable failure with a sanitized LastError (a
// fixed coarse class, never payload/secret/internal response body), applies the
// bounded backoff, and marks the registry 'failed' only when the bounded
// attempts rule is hit. It returns nil so a retryable failure is not a fatal
// reconciler error.
func (r *Reconciler) failRetryable(ctx context.Context, job PublicationJob, worker string, now time.Time, class string) error {
	safe := sanitizeFailureClass(class)
	terminal, err := r.Store.FailPublicationJob(ctx, job.ID, worker, now, r.MaxAttempts, r.BackoffBase, r.BackoffMax, safe)
	if err != nil {
		return fmt.Errorf("reconcile: persist failure: %w", err)
	}
	if terminal {
		if err := r.Store.MarkRegistryFailed(ctx, job.RegistryID); err != nil {
			return err
		}
	}
	return nil
}

// sanitizeFailureClass reduces a coarse class string to exactly what is safe to
// persist. It never propagates raw external error text.
func sanitizeFailureClass(class string) string {
	switch class {
	case "upload failed", "feed update failed", "feed resolution mismatch", "read-back mismatch":
		return class
	default:
		return fmt.Sprintf("publication failed (%s)", truncate(class, 40))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// feedRefForJob returns the deterministic feed reference for a job kind.
func (r *Reconciler) feedRefForJob(reg Registry, kind string) string {
	if kind == PublicationKindAuth {
		return authPolicyFeedRef(reg)
	}
	return stampPolicyFeedRef(reg)
}
