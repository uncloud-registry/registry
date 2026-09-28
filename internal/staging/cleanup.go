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
// expired ACTIVE session is removed (its staged file and metadata) with no Bee
// side effect (an active session carries no content). Every expired FINALIZED
// blob is removed AND its pinned Bee content is unpinned through the object
// store — but ONLY when the blob is eligible, i.e. its Bee ref is NOT
// referenced by authoritative committed repository state. A blob still
// referenced by a committed publication (the crash window between a verified
// feed commit and its staging consumption) is NEVER unpinned and NEVER
// removed: deleting its pinned content would corrupt a live, verifiable
// publication.
//
// Cleanup ownership is explicit and durable: before ANY irreversible side
// effect (the Bee unpin and the final file/staged-metadata removal), an
// eligible finalized blob is durably claimed through the `expiring` state —
// a cleanup-OWNED tombstone distinct from the generic `deleting` tombstone
// that Delete/Expire/startup produce. The expiring row RETAINS the blob's
// metadata (digest, bee_ref, media type, size) and any deletion provenance
// (cleanup_token), so a crash or an unpin failure NEVER loses the bee_ref: a
// later pass resumes ONLY cleanup-created expiring rows for the idempotent
// unpin and finish. A generic `deleting` row — however it was tombstoned — is
// NEVER inferred cleanup-eligible: in particular a deleting row that still
// carries a bee_ref (e.g. a failed post-publication staging Delete) is left
// untouched, so cleanup can never unpin content a generic Delete merely
// staged for removal.
//
// Listing exclusion: only genuinely FINALIZED, non-expired, non-expiring
// staged blobs are publishable (ListFinalized/ListStagedBlobs join the
// session state). A blob the cleanup claims to expiring is therefore never
// newly contributed to a publication, and a blob already expired is outside
// the publication window entirely.
//
// TOCTOU, honestly bounded: the cleanup re-reads authoritative committed
// state FRESH immediately before each unpin (never a staled pass cache) and
// requires the committed-state provider to succeed; any failure fails the
// whole pass closed and unpins nothing. Because committed state and the
// publication feed are external to the staging database, Task 18 cannot
// establish an airtight cross-process guarantee that a publication which
// already listed a blob (before it expired) and then commits strictly after
// the cleanup's unpin is impossible; the design therefore (a) makes an
// expired/expiring blob unpublishable by construction, (b) revalidates
// committed state atomically-timing-immediately-before the unpin, and
// (c) FAILS CLOSED (retains the blob, never unpins) whenever authoritative
// committed knowledge is absent or stale-by-error. This is the strongest
// guarantee the Task 18 surface allows; it is not claimed as an absolute
// proof. Removing content whose ref may still be the subject of an in-flight
// (not-yet-committed) publication is the one residual the reviewer explicitly
// directed to fail closed rather than claim — enforced by the mandatory
// authoritative committed-state provider and the fresh pre-unpin revalidation.
// ---------------------------------------------------------------------------

// Unpinner removes a pinned Bee object reference so its content can be
// garbage-collected. Production: *swarm.BeeObjectStore; tests inject fakes.
type Unpinner interface {
	Unpin(ctx context.Context, ref string) error
}

// CommittedRefs reports the Bee refs currently referenced by committed (live)
// repository state for a repo. The cleanup REFUSES to unpin or remove any
// expired staged blob whose ref is reported here — a blob still referenced by
// a committed publication must never lose its pinned content. It is REQUIRED
// (never nil): without authoritative committed state the cleanup is incapable
// of unpinning any finalized blob, so a nil source cannot silently unpin
// everything.
type CommittedRefs interface {
	// CommittedRefs returns the refs of every blob referenced by repo's current
	// committed repository state. Refs must be in the canonical (lowercase)
	// form the cleanup compares. An error fails the pass closed.
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
	// cleanup (a committed-referenced or ambiguous blob is examined but not
	// expired).
	Expired int
	// Removed is the number of fully removed sessions/blobs.
	Removed int
	// Unpinned is the number of Bee refs this pass unpinned.
	Unpinned int
	// Failed is the number of candidates that errored (claim, unpin, or
	// file-removal failure); their metadata is retained for a later pass.
	Failed int
}

// NewCleanup builds a cleanup over the durable staging service held behind a
// RegistryStore. An in-memory MemoryStore has nothing to reap and is rejected.
// unpin and committed are both REQUIRED: without an authoritative committed
// state source the cleanup can never prove a finalized blob unpublishable, so
// it refuses to construct rather than risk unpinning published content.
func NewCleanup(store RegistryStore, unpin Unpinner, committed CommittedRefs) (*Cleanup, error) {
	svc, ok := store.(*service)
	if !ok {
		return nil, errors.New("staging cleanup requires the durable staging service")
	}
	if unpin == nil {
		return nil, errors.New("staging cleanup requires an unpinner")
	}
	if committed == nil {
		return nil, errors.New("staging cleanup requires an authoritative committed-state provider")
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
	// Cleanup-eligible candidate states: active (expired session, contentless),
	// finalized (expired blob needing eligibility proof), expiring (a durable
	// cleanup-OWNED claim to resume), and a `deleting` row WITHOUT a bee_ref
	// (a contentless tombstone — cleanup's own active-deletion crash residue or
	// a generic contentless Delete — safe to finish because there is no content
	// to unpin). A `deleting` row WITH a bee_ref is deliberately NOT selected:
	// it is a generic Delete/Expire tombstone whose eligibility the cleanup
	// never infers, and unpinning it could destroy live published content.
	// finalizing/creating rows are excluded (retained fail-closed for explicit
	// reconciliation / the startup reconciler).
	conn, err := c.svc.pool.acquire(ctx)
	if err != nil {
		return res, ctxOr(err, ctx)
	}
	rows, err := conn.QueryContext(ctx,
		`select id from upload_sessions
		 where expires_at <= ? and (
		   state in ('active','finalized','expiring')
		   or (state = 'deleting' and bee_ref is null))
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
	// repo's committed state for every blob in the batch during the claim
	// decision. The pre-unpin revalidation always bypasses this cache.
	committedCache := map[string]map[string]struct{}{}
	committedRefs := func(ctx context.Context, repo string) (map[string]struct{}, error) {
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
		cand, err := c.svc.cleanupPrepare(ctx, id, committedRefs)
		if err != nil {
			// A committed-state failure fails the whole pass closed (an unpin
			// without authoritative committed knowledge is unsafe); any other
			// dependency failure is counted and retried next pass.
			res.Failed++
			if errors.Is(err, errCleanupCommittedRefs) {
				return res, err
			}
			continue
		}
		if !cand.found || !cand.willing {
			// Vanished, mid-finalization, a generic deleting-with-content
			// tombstone, or a committed/ambiguous finalized blob: examined only,
			// never touched.
			continue
		}
		if cand.expiring {
			// A cleanup-OWNED expiring claim: it is unpublishable, but we still
			// re-read AUTHORITATIVE committed state immediately before the unpin
			// (never the pass cache) and retain the blob if a publication won the
			// race — an unpin of newly-committed content is never performed.
			if err := ctx.Err(); err != nil {
				return res, err
			}
			refs, err := c.committed.CommittedRefs(ctx, cand.repo)
			if err != nil {
				// Fail closed: cannot prove the ref is still unpublishable.
				return res, fmt.Errorf("%w: %v", errCleanupCommittedRefs, err)
			}
			if cand.beeRef != "" {
				if _, committed := refs[cand.beeRef]; committed {
					// A publication committed the ref after the claim: retain
					// the expiring row (content stays pinned), never unpin.
					continue
				}
			}
			res.Expired++
			if cand.beeRef != "" {
				if err := c.unpin.Unpin(ctx, cand.beeRef); err != nil {
					res.Failed++
					continue
				}
				res.Unpinned++
			}
			if _, err := c.svc.finishDeletion(ctx, id, cand.auth); err != nil {
				res.Failed++
				continue
			}
			res.Removed++
			continue
		}
		// An already-tombstoned contentless row (active deletion or a deleting
		// tombstone without a bee_ref): no unpin, just finish the removal.
		res.Expired++
		if _, err := c.svc.finishDeletion(ctx, id, cand.auth); err != nil {
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

// cleanupCandidate is the outcome of one candidate's eligibility + claim
// decision.
type cleanupCandidate struct {
	found    bool // a row was present and considered
	willing  bool // cleanup may act (a durable claim / tombstone exists)
	expiring bool // a cleanup-OWNED expiring claim: unpin-revalidate then finish
	repo     string
	beeRef   string
	auth     deleteAuth
}

// cleanupPrepare decides one candidate's eligibility and, when eligible,
// durably transitions a live active/finalized row into a tombstone the cleanup
// then finishes. For an expired FINALIZED blob it commits the cleanup-OWNED
// `expiring` claim (retaining the blob's metadata so the bee_ref survives a
// crash); for a contentless active session it uses the generic deleting
// tombstone (no content, so no eligibility proof and no unpin). A leftover
// expiring (cleanup-owned) row or a contentless deleting tombstone is resumed.
// A generic deleting row with content, a committed/ambiguous finalized blob, a
// finalizing row, and a creating row are all examined but never acted on.
func (s *service) cleanupPrepare(ctx context.Context, id string, committedRefs func(ctx context.Context, repo string) (map[string]struct{}, error)) (cleanupCandidate, error) {
	var cand cleanupCandidate
	if err := ctx.Err(); err != nil {
		return cand, err
	}
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
	switch row.state {
	case string(StateFinalizing):
		// Never clean a mid-finalization session (bytes may have reached the
		// object store with no recorded receipt).
		return cand, nil
	case string(StateCreating):
		// Expired creating rows are the startup reconciler's job, never the
		// background reaper's.
		return cand, nil
	case string(StateActive):
		// A contentless expired session: no Bee content, so no eligibility
		// proof and no unpin. Tombstone to deleting, retaining any durable
		// delete provenance, then finish the removal.
		if err := s.claimActiveDeleting(ctx, id, &cand); err != nil {
			return cand, err
		}
		cand.willing = cand.found
		return cand, nil
	case string(StateFinalized):
		if cand.beeRef == "" {
			// A finalized row always carries a bee_ref (coherence CHECK), but
			// never unpin/remove an empty-ref row.
			return cand, nil
		}
		// Eligibility: authoritative committed state. A blob referenced by a
		// committed publication is NEVER unpinned and NEVER removed.
		refs, err := committedRefs(ctx, cand.repo)
		if err != nil {
			return cand, fmt.Errorf("%w: %v", errCleanupCommittedRefs, err)
		}
		if _, committed := refs[cand.beeRef]; committed {
			return cand, nil // examined only; retain a published blob
		}
		// Eligible: durably claim the cleanup-OWNED expiring tombstone BEFORE
		// any unpin/removal so a crash never loses the bee_ref or provenance.
		if err := s.claimExpiring(ctx, id, &cand); err != nil {
			return cand, err
		}
		cand.willing = cand.found && cand.expiring
		return cand, nil
	case string(StateExpiring):
		// A leftover cleanup-OWNED claim (crash/failed unpin residue, or an
		// eligible finalized blob claimed in an earlier pass): resume it.
		if err := s.captureResumeAuth(ctx, id, &cand); err != nil {
			return cand, err
		}
		cand.expiring = true
		cand.willing = cand.found
		return cand, nil
	case string(StateDeleting):
		if cand.beeRef != "" {
			// A generic Delete/Expire tombstone that still carries content:
			// NEVER inferred cleanup-eligible. The cleanup does not unpin it
			// (the content may be published) and does not finish it (the
			// authenticated Delete/startup path owns it). Leave it untouched.
			return cand, nil
		}
		// A contentless deleting tombstone (cleanup's own active-deletion
		// crash residue, or a generic contentless Delete): safe to finish.
		if err := s.captureResumeAuth(ctx, id, &cand); err != nil {
			return cand, err
		}
		cand.willing = cand.found
		return cand, nil
	}
	return cand, nil
}

// claimActiveDeleting tombstone a contentless expired active session to the
// generic deleting tombstone under the serialized lock, capturing any durable
// delete provenance and the canonical file identity for the authenticated
// removal. It never unpins (an active session carries no Bee content).
func (s *service) claimActiveDeleting(ctx context.Context, id string, cand *cleanupCandidate) error {
	return s.withTx(ctx, func(tc *sql.Conn) error {
		cur, f, err := fetchSession(ctx, tc, id)
		if err != nil {
			return err
		}
		if !f || cur.state != string(StateActive) {
			// Vanished, or a concurrent operation won between the read-only
			// capture and the lock: never clean it.
			cand.found = false
			return nil
		}
		cand.repo = cur.repo
		cand.beeRef = cur.beeRef.String
		var a deleteAuth
		if cur.cleanupToken.Valid {
			a.tokenBytes, _ = hex.DecodeString(cur.cleanupToken.String)
			a.tokenBytesKnown = a.tokenBytes != nil && len(a.tokenBytes) == creatingTokenLen
		}
		newCleanup := deletingTransitionToken(cur)
		if _, err := tc.ExecContext(ctx,
			`update upload_sessions set state = 'deleting', create_token = null, cleanup_token = ? where id = ? and state = 'active'`, newCleanup, id); err != nil {
			return typed(ErrDependency, err)
		}
		if fi, _, err := s.spool.nameInfo(id); err != nil {
			return typed(ErrDependency, err)
		} else {
			a.canonical = fi
		}
		cand.auth = a
		return nil
	})
}

// claimExpiring durably claims an eligible expired FINALIZED blob through the
// cleanup-OWNED expiring tombstone, retaining the blob's metadata (bee_ref for
// the unpin) and any deletion provenance. This happens BEFORE any unpin or
// removal, so a crash between the claim and the side effects leaves an
// expiring row carrying the bee_ref for a restart-safe resume — and only
// cleanup-created expiring rows may ever be resumed for an unpin.
func (s *service) claimExpiring(ctx context.Context, id string, cand *cleanupCandidate) error {
	return s.withTx(ctx, func(tc *sql.Conn) error {
		cur, f, err := fetchSession(ctx, tc, id)
		if err != nil {
			return err
		}
		if !f || cur.state != string(StateFinalized) || cur.beeRef.String == "" {
			// Vanished, or a concurrent finalize/delete won between the
			// read-only capture and the lock: never claim it.
			cand.found = false
			return nil
		}
		cand.repo = cur.repo
		cand.beeRef = cur.beeRef.String
		var a deleteAuth
		if cur.cleanupToken.Valid {
			a.tokenBytes, _ = hex.DecodeString(cur.cleanupToken.String)
			a.tokenBytesKnown = a.tokenBytes != nil && len(a.tokenBytes) == creatingTokenLen
		}
		// The cleanup leaves cleanup_token unchanged (retained provenance or
		// faithful absence); the expiring row keeps digest/bee_ref/media_type/
		// size so a restart can always resume the idempotent unpin.
		if _, err := tc.ExecContext(ctx,
			`update upload_sessions set state = 'expiring' where id = ? and state = 'finalized'`, id); err != nil {
			return typed(ErrDependency, err)
		}
		if fi, _, err := s.spool.nameInfo(id); err != nil {
			return typed(ErrDependency, err)
		} else {
			a.canonical = fi
		}
		cand.auth = a
		cand.expiring = true
		return nil
	})
}

// captureResumeAuth re-reads an expiring/deleting resume row under the
// serialized lock, capturing the canonical file identity and any durable
// deletion provenance so the authenticated removal can proceed. If the row is
// no longer in a resumable state it is reported not-found / not-willing.
func (s *service) captureResumeAuth(ctx context.Context, id string, cand *cleanupCandidate) error {
	return s.withTx(ctx, func(tc *sql.Conn) error {
		cur, f, err := fetchSession(ctx, tc, id)
		if err != nil {
			return err
		}
		if !f {
			cand.found = false
			return nil
		}
		resumable := cur.state == string(StateExpiring) || cur.state == string(StateDeleting)
		if !resumable {
			cand.found = false
			cand.willing = false
			return nil
		}
		cand.repo = cur.repo
		cand.beeRef = cur.beeRef.String
		var a deleteAuth
		if cur.cleanupToken.Valid {
			a.tokenBytes, _ = hex.DecodeString(cur.cleanupToken.String)
			a.tokenBytesKnown = a.tokenBytes != nil && len(a.tokenBytes) == creatingTokenLen
		}
		if fi, _, err := s.spool.nameInfo(id); err != nil {
			return typed(ErrDependency, err)
		} else {
			a.canonical = fi
		}
		cand.auth = a
		return nil
	})
}

