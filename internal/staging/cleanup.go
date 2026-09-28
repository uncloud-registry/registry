package staging

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Task 18: bounded, crash-safe cleanup of expired staging sessions and blobs
// with eligible Bee unpinning.
//
// Cleanup reaps expired staging in deterministic, bounded batches. Every
// expired ACTIVE session is removed (its staged file and metadata); every
// expired FINALIZED blob is removed AND its pinned Bee content is unpinned
// through the object store — but ONLY when the blob is eligible, i.e. its Bee
// ref is NOT referenced by committed repository state. A blob still referenced
// by a committed publication (the crash window between a verified feed commit
// and its staging consumption) is NEVER unpinned and NEVER removed: deleting
// its pinned content would corrupt a live, verifiable publication.
//
// Crash safety and retry: before any irreversible side effect (the Bee unpin),
// the row is durably transitioned through the deleting tombstone — the explicit
// pre-side-effect marker. Tombstoning excludes the blob from every live read
// (publication listing, pull, finalization) while RETAINING its metadata (the
// staged_blobs row, and thus the bee_ref, survives until the tombstone row is
// finally removed). A crash or an unpin failure therefore NEVER loses the
// bee_ref: the row stays tombstoned with its metadata intact, and a later pass
// re-runs the (idempotent) unpin and finishes the removal. Only after the unpin
// succeeds is the file durably unlinked via the existing authenticated
// quarantine protocol and the metadata row removed.
// ---------------------------------------------------------------------------

// Unpinner removes a pinned Bee object reference so its content can be
// garbage-collected. Production: *swarm.BeeObjectStore; tests inject fakes.
type Unpinner interface {
	Unpin(ctx context.Context, ref string) error
}

// CommittedRefs reports the Bee refs currently referenced by committed (live)
// repository state for a repo. The cleanup REFUSES to unpin or remove any
// expired staged blob whose ref is reported here — a blob still referenced by a
// committed publication must never lose its pinned content. It is OPTIONAL
// (nil means no committed state is consulted and every expired blob is
// eligible); production wiring supplies an authoritative committed-state
// source so cleanup never races a just-committed publication.
type CommittedRefs interface {
	// CommittedRefs returns the refs of every blob referenced by repo's current
	// committed repository state. Refs must be in the canonical (lowercase)
	// form the cleanup compares.
	CommittedRefs(ctx context.Context, repo string) (map[string]struct{}, error)
}

// Cleanup reaps expired staging in bounded batches over a durable
// staging service.
type Cleanup struct {
	svc       *service
	unpin     Unpinner
	committed CommittedRefs
	now       func() time.Time
}

// CleanupResult is the observable count of one RunOnce pass.
type CleanupResult struct {
	// Examined is the number of expired candidate rows selected by the bounded
	// batch query.
	Examined int
	// Expired is the number of candidates that were actually eligible for
	// cleanup (a committed-referenced blob is examined but not expired).
	Expired int
	// Removed is the number of fully removed sessions/blobs.
	Removed int
	// Unpinned is the number of Bee refs this pass unpinned.
	Unpinned int
	// Failed is the number of candidates that errored (tombstone, unpin, or
	// file-removal failure); their metadata is retained for a later pass.
	Failed int
}

// NewCleanup builds a cleanup over the durable staging service held behind a
// RegistryStore. An in-memory MemoryStore has nothing to reap and is rejected.
// unpin is required; committed is optional (nil makes every expired blob
// eligible).
func NewCleanup(store RegistryStore, unpin Unpinner, committed CommittedRefs) (*Cleanup, error) {
	svc, ok := store.(*service)
	if !ok {
		return nil, errors.New("staging cleanup requires the durable staging service")
	}
	if unpin == nil {
		return nil, errors.New("staging cleanup requires an unpinner")
	}
	return &Cleanup{svc: svc, unpin: unpin, committed: committed, now: time.Now}, nil
}

// RunOnce performs ONE bounded cleanup pass over the expired rows at now. It
// returns the per-class counts. It runs and returns even when per-row
// failures occurred (they are counted in Failed and retried by a later pass);
// it returns a non-nil error only for a canceled/deadlined context or when an
// authoritative committed-state provider fails — in which case it fails closed
// and refuses to unpin anything.
func (c *Cleanup) RunOnce(ctx context.Context, now time.Time, limit int) (CleanupResult, error) {
	var res CleanupResult
	if limit <= 0 {
		return res, ErrInvalidInput
	}
	nowNanos := now.UTC().UnixNano()
	if err := ctx.Err(); err != nil {
		return res, err
	}

	// Select the limit oldest-expiring cleanable rows in deterministic order.
	// finalizing rows are deliberately excluded (retained fail-closed for an
	// explicit reconciliation path) and expired creating rows are the startup
	// reconciler's job, never the background reaper's.
	conn, err := c.svc.pool.acquire(ctx)
	if err != nil {
		return res, ctxOr(err, ctx)
	}
	rows, err := conn.QueryContext(ctx,
		`select id from upload_sessions
		 where expires_at <= ? and state in ('active','finalized','deleting')
		 order by expires_at, id limit ?`, nowNanos, limit)
	if err != nil {
		c.svc.pool.release(conn)
		return res, depErr(err, ctx)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			c.svc.pool.release(conn)
			return res, depErr(err, ctx)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		c.svc.pool.release(conn)
		return res, depErr(err, ctx)
	}
	rows.Close()
	c.svc.pool.release(conn)
	res.Examined = len(ids)

	// Per-repo committed-refs cache so one pass never re-resolves the same
	// repo's committed state for every blob in the batch.
	committedCache := map[string]map[string]struct{}{}
	committedRefs := func(ctx context.Context, repo string) (map[string]struct{}, error) {
		if c.committed == nil {
			return nil, nil
		}
		if m, ok := committedCache[repo]; ok {
			return m, nil
		}
		m, err := c.committed.CommittedRefs(ctx, repo)
		if err != nil {
			return nil, err
		}
		if m == nil {
			m = map[string]struct{}{}
		}
		committedCache[repo] = m
		return m, nil
	}

	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		cand, err := c.svc.cleanupTombstone(ctx, id, committedRefs)
		if err != nil {
			// A committed-state failure fails the whole pass closed (an
			// unpin without authoritative committed knowledge is unsafe); any
			// other dependency failure is counted and retried next pass.
			res.Failed++
			if errors.Is(err, errCleanupCommittedRefs) {
				return res, err
			}
			continue
		}
		if !cand.found || !cand.eligible || !cand.proceed {
			// Vanished, mid-finalization, or committed-referenced: examined
			// only, never touched.
			continue
		}
		res.Expired++
		if cand.beeRef != "" {
			// The row is already durably tombstoned (its bee_ref retained in
			// staged_blobs), so an interrupted or failed unpin never loses the
			// ref; Unpin is idempotent and a later pass retries it.
			if err := c.unpin.Unpin(ctx, cand.beeRef); err != nil {
				res.Failed++
				continue
			}
			res.Unpinned++
		}
		// Remove the file (authenticated quarantine, missing-tolerant) and the
		// tombstone row, which cascades the staged_blobs metadata.
		_, err = c.svc.finishDeletion(ctx, id, cand.auth)
		if err != nil {
			res.Failed++
			continue
		}
		res.Removed++
	}
	return res, nil
}

// errCleanupCommittedRefs wraps a committed-state provider failure so RunOnce
// can fail the pass closed instead of unpinning without authoritative
// knowledge. It is never surfaced to a caller-visible error.
var errCleanupCommittedRefs = errors.New("staging cleanup cannot verify committed references")

// cleanupCandidate is the outcome of one candidate's eligibility + tombstone
// decision.
type cleanupCandidate struct {
	found    bool // a row was present and cleanable-state at capture
	eligible bool // not referenced by committed state
	proceed  bool // a durable tombstone is in place, removal may proceed
	repo     string
	beeRef   string
	auth     deleteAuth
}

// cleanupTombstone decides eligibility and, when eligible, durably transitions
// a live active/finalized row to the deleting tombstone (the explicit
// pre-side-effect marker) capturing the transition provenance; for a leftover
// deleting row it re-captures provenance so the removal can be finished. It
// runs the committed-eligibility check on the read-only snapshot BEFORE any
// write or side effect, then re-reads under the serialized lock so a row
// concurrently finalized (or a concurrent delete) is never mis-handled.
func (s *service) cleanupTombstone(ctx context.Context, id string, committedRefs func(ctx context.Context, repo string) (map[string]struct{}, error)) (cleanupCandidate, error) {
	var cand cleanupCandidate
	if err := ctx.Err(); err != nil {
		return cand, err
	}
	// Phase 1 (read-only): capture the current row and decide eligibility.
	conn, err := s.pool.acquire(ctx)
	if err != nil {
		return cand, ctxOr(err, ctx)
	}
	row, found, err := fetchSession(ctx, conn, id)
	s.pool.release(conn)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cand, cerr
		}
		return cand, typed(ErrDependency, err)
	}
	if !found {
		return cand, nil // vanished: examined, nothing to clean
	}
	cand.repo = row.repo
	cand.beeRef = row.beeRef.String
	cand.found = true
	if row.state == string(StateFinalizing) {
		// Never clean a mid-finalization session (bytes may have reached the
		// object store with no recorded receipt).
		return cand, nil
	}
	// Eligibility only ever gates a live active/finalized row. A leftover
	// deleting tombstone was already eligible when it was created and is
	// always finished (a stuck deleting row must never become permanent).
	if (row.state == string(StateActive) || row.state == string(StateFinalized)) &&
		cand.beeRef != "" && committedRefs != nil {
		refs, err := committedRefs(ctx, cand.repo)
		if err != nil {
			// Fail closed: refuse to unpin without authoritative committed
			// state.
			return cand, fmt.Errorf("%w: %v", errCleanupCommittedRefs, err)
		}
		if _, committed := refs[cand.beeRef]; committed {
			cand.eligible = false
			return cand, nil // NEVER unpin/remove a committed-referenced blob
		}
	}
	cand.eligible = true

	// Phase 2 (serialized): tombstone a live row and/or re-capture provenance,
	// mirroring the ordinary Delete/Expire transition protocol.
	if row.state == string(StateActive) || row.state == string(StateFinalized) || row.state == string(StateDeleting) {
		cand.proceed = true
		if err := s.withTx(ctx, func(tc *sql.Conn) error {
			cur, f, err := fetchSession(ctx, tc, id)
			if err != nil {
				return err
			}
			if !f || cur.state == string(StateFinalizing) {
				// Vanished, or a concurrent finalize won between the read-only
				// capture and the lock: never clean it.
				cand.proceed = false
				return nil
			}
			cand.repo = cur.repo
			cand.beeRef = cur.beeRef.String
			var a deleteAuth
			if cur.state != string(StateDeleting) {
				// Capture the byte-authenticating token and copy it onto the
				// tombstone as cleanup_token (a crash leaves a restart able to
				// authenticate the sidecar).
				switch {
				case cur.state == string(StateCreating):
					a.creating = true
					a.tokenBytes, _ = hex.DecodeString(cur.createToken.String)
					a.tokenBytesKnown = a.tokenBytes != nil && len(a.tokenBytes) == creatingTokenLen
				case cur.cleanupToken.Valid:
					a.tokenBytes, _ = hex.DecodeString(cur.cleanupToken.String)
					a.tokenBytesKnown = a.tokenBytes != nil && len(a.tokenBytes) == creatingTokenLen
				}
				newCleanup := deletingTransitionToken(cur)
				if _, err := tc.ExecContext(ctx,
					`update upload_sessions set state = 'deleting', create_token = null, cleanup_token = ? where id = ? and state <> 'deleting'`, newCleanup, id); err != nil {
					return typed(ErrDependency, err)
				}
				cand.proceed = true
			}
			if fi, _, err := s.spool.nameInfo(id); err != nil {
				return typed(ErrDependency, err)
			} else {
				a.canonical = fi
			}
			cand.auth = a
			return nil
		}); err != nil {
			return cand, err
		}
	}
	return cand, nil
}
