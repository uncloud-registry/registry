package staging

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

// ---------------------------------------------------------------------------
// Task 18 close: the durable publication-claim fence.
//
// Publication and cleanup operate on the SAME SQLite staging database under
// serialized write transactions, so the cross-process publication-versus-unpin
// TOCTOU is closed at the DB level, not by read ordering. ClaimStagedForPublish
// atomically frees the exact finalized staged upload rows a logical publication
// depends on into the publication-owned `claimed` state under its stable
// operation_id — BEFORE any immutable object or feed write. Because the claim
// re-reads authoritative row state inside one BEGIN IMMEDIATE write
// transaction, a publication whose candidate row cleanup won between listing
// and commit (row already moved to expiring and its content unpinned/removed)
// fails its claim closed (ErrClaimConflict) and makes ZERO external writes;
// it can never commit a manifest referencing content cleanup just unpinned.
// Symmetrically, a claimed row is never selected by cleanup's candidate query,
// never moved to expiring (the state-transition trigger requires expiring only
// from a live active/finalized row), and is never user-deleted/expired, so a
// publication that won its claim provably races cleanup to zero unpins.
//
// Fail-closed retention: on ANY error or ambiguity after a claim succeeds, the
// durable claim is RETAINED for the exact-operation retry and never restored
// to finalized when an external commit may have happened. Startup preserves
// every valid claim; its bytes keep charging quota. A same-operation retry
// idempotently reacquires its existing claims and completes/consumes them.
// ---------------------------------------------------------------------------

// operationIDMaxLen-bounded OperationID (also enforced by validateOperationID).

// ClaimStagedForPublish implements the durable publication claim. See the
// RegistryStore doc-comment for the contract.
func (s *service) ClaimStagedForPublish(ctx context.Context, repo, actor, operationID string, digests []string) ([]spec.StagedBlob, error) {
	if err := validateRepo(repo); err != nil {
		return nil, err
	}
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	if err := validateOperationID(operationID); err != nil {
		return nil, err
	}
	if len(digests) == 0 {
		return nil, ErrInvalidInput
	}
	// Deterministic, de-duplicated digest order.
	set := make(map[string]struct{}, len(digests))
	for _, d := range digests {
		if err := validateDigest(d); err != nil {
			return nil, err
		}
		set[d] = struct{}{}
	}
	wanted := make([]string, 0, len(set))
	for d := range set {
		wanted = append(wanted, d)
	}
	sort.Strings(wanted)

	nowNanos := s.now().UTC().UnixNano()
	var claimed []spec.StagedBlob
	err := s.withTx(ctx, func(tc *sql.Conn) error {
		for _, digest := range wanted {
			rows, err := s.claimableDigestRows(ctx, tc, repo, actor, digest)
			if err != nil {
				return err
			}
			// Decide this digest across its candidate rows:
			//   - a row already claimed by THIS operation => idempotent
			//     reacquisition (keep its descriptor, no new claim needed);
			//   - a row claimed by a DIFFERENT operation => fail the WHOLE
			//     claim closed (we must never latch onto a foreign claim);
			//   - a live finalized non-expired row => a claim candidate
			//     (claim exactly one per digest, the earliest).
			haveOwned := false
			firstFinalized := -1
			for i := range rows {
				r := &rows[i]
				switch r.state {
				case string(StateClaimed):
					if !r.operationID.Valid || r.operationID.String != operationID {
						return typed(ErrClaimConflict, errors.New("staged row claimed by another operation"))
					}
					if !haveOwned {
						claimed = append(claimed, r.blob)
						haveOwned = true
					}
				case string(StateFinalized):
					if r.expiresNanos <= nowNanos {
						// The row expired before the claim: it is outside the
						// publication window (cleanup/expiry could have taken
						// it). If no other row satisfies this digest, fail
						// closed; an owned claim / a live row still wins.
						continue
					}
					if firstFinalized < 0 {
						firstFinalized = i
					}
				default:
					// expiring (cleanup won), deleting (generic delete won),
					// etc.: never claimable.
					continue
				}
			}
			if haveOwned {
				continue
			}
			if firstFinalized < 0 {
				// No finalized non-expired row and no owned claim for this
				// digest: missing / expired / cleanup-won / foreign-claimed —
				// fail the ENTIRE claim closed (zero rows claimed, zero
				// external writes).
				return typed(ErrClaimConflict, errors.New("no claimable staged row for a referenced digest"))
			}
			// Atomically claim the earliest eligible finalized row under the
			// serialized write lock; the guarded UPDATE re-checks
			// state/expiry/ownership, so a concurrent cleanup or foreign claim
			// that landed between the read and here fails the update (0 rows
			// affected) and fails the whole claim closed.
			r := &rows[firstFinalized]
			res, err := tc.ExecContext(ctx,
				`update upload_sessions set state = 'claimed', operation_id = ? where id = ? and repo = ? and actor = ? and state = 'finalized' and expires_at > ?`,
				operationID, r.id, repo, actor, nowNanos)
			if err != nil {
				return typed(ErrDependency, err)
			}
			if n, err := res.RowsAffected(); err != nil {
				return typed(ErrDependency, err)
			} else if n == 0 {
				return typed(ErrClaimConflict, errors.New("staged row claimed by a concurrent operation"))
			}
			claimed = append(claimed, r.blob)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

// claimableDigestRows returns the finalized or already-claimed session/blob
// rows for one repo/actor/digest, with the descriptor and the session state and
// operation ownership so the claim decision can act on authoritative read data.
type claimableRow struct {
	id           string
	state        string
	expiresNanos int64
	operationID  sql.NullString
	blob         spec.StagedBlob
}

func (s *service) claimableDigestRows(ctx context.Context, tc *sql.Conn, repo, actor, digest string) ([]claimableRow, error) {
	rows, err := tc.QueryContext(ctx,
		`select u.id, u.state, u.expires_at, u.operation_id, b.digest, b.bee_ref, b.size, b.media_type, b.created_at, b.expires_at
		   from staged_blobs b join upload_sessions u on u.id = b.upload_id
		  where b.repo = ? and b.actor = ? and b.digest = ? and u.state in ('finalized','claimed')`,
		repo, actor, digest)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, typed(ErrDependency, err)
	}
	defer rows.Close()
	var out []claimableRow
	for rows.Next() {
		var r claimableRow
		var bDigest, ref, media string
		var size int64
		var created, expires int64
		if err := rows.Scan(&r.id, &r.state, &r.expiresNanos, &r.operationID,
			&bDigest, &ref, &size, &media, &created, &expires); err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			return nil, typed(ErrDependency, err)
		}
		r.blob = spec.StagedBlob{
			UploadID:  r.id,
			Repo:      repo,
			Actor:     actor,
			Digest:    bDigest,
			SwarmRef:  ref,
			Size:      size,
			MediaType: media,
			CreatedAt: time.Unix(0, created).UTC().Format(time.RFC3339),
			ExpiresAt: time.Unix(0, expires).UTC().Format(time.RFC3339),
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, typed(ErrDependency, err)
	}
	return out, nil
}

// ClaimedDigests returns the digests the caller's repo/actor has claimed under
// operationID.
func (s *service) ClaimedDigests(ctx context.Context, repo, actor, operationID string) (map[string]struct{}, error) {
	if err := validateRepo(repo); err != nil {
		return nil, err
	}
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	if err := validateOperationID(operationID); err != nil {
		return nil, err
	}
	conn, err := s.pool.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer s.pool.release(conn)
	rows, err := conn.QueryContext(ctx,
		`select distinct b.digest from staged_blobs b join upload_sessions u on u.id = b.upload_id
		  where b.repo = ? and b.actor = ? and u.state = 'claimed' and u.operation_id = ?`,
		repo, actor, operationID)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, typed(ErrDependency, err)
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			return nil, typed(ErrDependency, err)
		}
		out[d] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, typed(ErrDependency, err)
	}
	return out, nil
}

// ConsumeStagedForPublish removes (WITHOUT unpinning) ONLY the staged upload
// rows claimed by operationID whose digests are in digests, after a verified
// publication of that operation. Rows claimed by a different operation, rows
// not in the claimed state, and rows whose digest is not referenced are never
// touched.
//
// The consume is scoped by the AUTHORITATIVE (global) operation identity —
// repo + operationID + referenced digests — never by the calling actor. The
// caller is a principal ALREADY authorized for the repo (that authorization
// happens upstream), and the durable operation binding (repo + globally unique
// operationID) is what actually owns the claim, so a VERIFIED retry by ANY
// authorized actor for the repo SAFELY finishes a claim a prior authorized
// actor created and committed but crashed before consuming. Because operationID
// is globally unique per publication, scoping by it (plus repo and referenced
// digests) can never clear a DIFFERENT operation's claim, and the actor of the
// original claim is irrelevant. The `actor` argument is retained in the
// signature only for interface stability; it does not restrict consumption.
func (s *service) ConsumeStagedForPublish(ctx context.Context, repo, actor, operationID string, digests []string) error {
	if err := validateRepo(repo); err != nil {
		return err
	}
	if err := validateActor(actor); err != nil {
		return err
	}
	if err := validateOperationID(operationID); err != nil {
		return err
	}
	if len(digests) == 0 {
		return nil
	}
	wanted := make(map[string]struct{}, len(digests))
	for _, d := range digests {
		if err := validateDigest(d); err != nil {
			return err
		}
		wanted[d] = struct{}{}
	}

	var ids []string
	conn, err := s.pool.acquire(ctx)
	if err != nil {
		return err
	}
	rows, err := conn.QueryContext(ctx,
		`select u.id from staged_blobs b join upload_sessions u on u.id = b.upload_id
		  where b.repo = ? and b.digest in (select value from json_each(?)) and u.state = 'claimed' and u.operation_id = ?`,
		repo, digestJSON(wanted), operationID)
	if err != nil {
		s.pool.release(conn)
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return typed(ErrDependency, err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			s.pool.release(conn)
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return typed(ErrDependency, err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		s.pool.release(conn)
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return typed(ErrDependency, err)
	}
	rows.Close()
	s.pool.release(conn)

	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		done, err := s.consumeClaimed(ctx, id, repo, operationID)
		if err != nil {
			return err
		}
		if !done {
			// The row was concurrently consumed or no longer owned by this
			// operation (a foreign consume raced us): idempotent skip.
			continue
		}
	}
	return nil
}

// consumeClaimed tombstone + atomically quarantine-removes ONE claimed-by-op
// staged upload row WITHOUT unpinning. It reports whether THIS call performed
// the final metadata removal (so concurrent instances converge on count 1).
func (s *service) consumeClaimed(ctx context.Context, id, repo, operationID string) (bool, error) {
	var a deleteAuth
	proceed := false
	err := s.withTx(ctx, func(conn *sql.Conn) error {
		row, found, err := fetchSession(ctx, conn, id)
		if err != nil {
			return err
		}
		if !found || row.repo != repo {
			return nil
		}
		if row.state != string(StateClaimed) {
			// Not claimed (finalized/active/deleting/etc.): only claimed rows
			// belonging to THIS operation may be consumed here.
			return nil
		}
		if !row.operationID.Valid || row.operationID.String != operationID {
			// A row claimed by a DIFFERENT operation is NEVER consumed by us
			// (another operation's claim is never cleared).
			return nil
		}
		// Capture the authenticating token (a claimed row may still carry the
		// post-activation cleanup_token sidecar provenance) onto the deleting
		// tombstone, then transition claimed -> deleting and clear the
		// operation_id (the coherence CHECK requires operation_id null on a
		// deleting row). A crash at any point leaves a deleting tombstone that
		// startup/retry finishes idempotently.
		if row.cleanupToken.Valid {
			a.tokenBytes, _ = hex.DecodeString(row.cleanupToken.String)
			a.tokenBytesKnown = a.tokenBytes != nil && len(a.tokenBytes) == creatingTokenLen
		}
		newCleanup := deletingTransitionToken(row)
		res, err := conn.ExecContext(ctx,
			`update upload_sessions set state = 'deleting', operation_id = null, create_token = null, cleanup_token = ?
			  where id = ? and state = 'claimed' and operation_id = ?`,
			newCleanup, id, operationID)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return typed(ErrDependency, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			// A concurrent consume or foreign claim cleared it first: skip.
			return nil
		}
		if fi, _, err := s.spool.nameInfo(id); err != nil {
			return typed(ErrDependency, err)
		} else {
			a.canonical = fi
		}
		proceed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	if !proceed {
		return false, nil
	}
	return s.finishDeletion(ctx, id, a)
}

// digestJSON renders a validated digest set as a JSON text (for SQLite
// json_each). The digests are canonical validated lowercase-hex forms, so the
// JSON is always well-formed and never controllable by a caller.
func digestJSON(set map[string]struct{}) string {
	keys := make([]string, 0, len(set))
	sorted := make([]string, 0, len(set))
	for k := range set {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		keys = append(keys, fmt.Sprintf("%q", k))
	}
	out := "["
	for i, k := range keys {
		if i > 0 {
			out += ","
		}
		out += k
	}
	return out + "]"
}
