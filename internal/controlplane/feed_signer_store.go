package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Feed signer operation states. A row progresses pending -> processing ->
// succeeded (durable idempotency), or processing -> pending (a definite
// pre-update failure released the claim for a later retry).
const (
	FeedSignerOpPending    = "pending"
	FeedSignerOpProcessing = "processing"
	FeedSignerOpSucceeded  = "succeeded"
)

// claimTokenBytes is the size of the unpredictable per-claim token. A client
// only ever completes or releases its own claim by presenting the exact token
// the claim wrote (constant-time compare); a stale or stolen token can never
// complete or release the operation. 32 cryptorandom bytes, hex-encoded.
const claimTokenBytes = 32

// feedSignerLeaseDuration is how long a claim owns the network/key work before
// the lease expires and an identical retry may take it over (crash recovery).
const feedSignerLeaseDuration = 60 * time.Second

// feedSignerClaimMaxAttempts bounds how long a caller waits (polling) for a
// concurrent owner to finish before returning a retryable backend error. It is
// deliberately small so a same-operation concurrent caller never blocks a push
// indefinitely, and never performs the network/key work itself.
const feedSignerClaimMaxAttempts = 100

// feedSignerClaimPollInterval is the sleep between bounded polls for a
// concurrent claim to complete.
const feedSignerClaimPollInterval = 10 * time.Millisecond

// feedSignerOperationTableSQLM9 is the migration-9 schema body, preserved
// verbatim so migration 9 (which MUST NOT be edited) still installs the
// original table that migration 10 then rebuilds when it is empty.
const feedSignerOperationTableSQLM9 = `CREATE TABLE feed_signer_operations (
	operation_id text primary key
		check (typeof(operation_id) = 'text' and length(operation_id) between 1 and 128),
	request_hash blob not null
		check (typeof(request_hash) = 'blob' and length(request_hash) = 32),
	state text not null
		check (typeof(state) = 'text' and state in ('pending','succeeded')),
	result_json text
		check (result_json is null or (typeof(result_json) = 'text' and length(result_json) between 2 and 4096)),
	created_at integer not null check (typeof(created_at) = 'integer'),
	updated_at integer not null check (typeof(updated_at) = 'integer'),
	check (state <> 'succeeded' or result_json is not null)
)`

// installFeedSignerOperationStore is migration 9's body (unchanged): it
// creates the durable feed-signer idempotency table that migration 10
// rebuilds. It is preserved verbatim so an already-migrated database reaches
// version 9 with exactly the schema migration 9 has always written.
func installFeedSignerOperationStore(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, feedSignerOperationTableSQLM9); err != nil {
		return err
	}
	return nil
}

// feedSignerOperationTableSQLV10 is the SINGLE SOURCE OF TRUTH for the
// migration-10 feed_signer_operations schema. It hardens the migration-9
// table with the durable-claims and concurrency invariants Task 10 requires:
//
//   - registry_id (FK) and canonical topic name the active repo claim, so the
//     partial unique index below can hold at most ONE processing row per
//     (registry_id, topic) across every Store/process — the gate that stops two
//     distinct operations from both advancing the same repository feed.
//   - a pending|processing|succeeded state vocabulary with exact storage-class
//     (typeof) guards on every column.
//   - only a succeeded row carries result_json, and result_json is ONLY
//     accepted when it is a valid bounded JSON object carrying the three exact
//     result fields (operationID/feed/reference) as bounded text. Exactness of
//     the key set and the canonical byte form are additionally enforced by the
//     Go store before persistence and by the strict decoder on read, so a
//     direct-SQL INSERT cannot slip an extra member past coherence.
//   - only a processing row holds a claim (claim_token + lease_until set
//     together, cleared in every other state); lease_until is a positive
//     integer (future + bounded enforcement lives in the store, which only
//     ever writes now+lease and only reclaims an EXPIRED lease).
//   - attempts is a bounded nonnegative integer that increments on each claim.
var feedSignerOperationTableSQLV10 = `CREATE TABLE feed_signer_operations (
	operation_id text primary key
		check (typeof(operation_id) = 'text' and length(operation_id) between 1 and 128),
	registry_id integer not null
		check (typeof(registry_id) = 'integer' and registry_id > 0)
		references registries(id) on delete cascade,
	topic text not null
		check (typeof(topic) = 'text' and length(topic) between 1 and 256),
	request_hash blob not null
		check (typeof(request_hash) = 'blob' and length(request_hash) = 32),
	state text not null
		check (typeof(state) = 'text' and state in ('pending','processing','succeeded')),
	result_json text
		check (result_json is null or (
			typeof(result_json) = 'text'
			and length(result_json) between 2 and 4096
			and json_valid(result_json) = 1
			and json_type(result_json) = 'object'
			and json_type(result_json, '$.operationID') IS 'text'
			and json_type(result_json, '$.feed') IS 'text'
			and json_type(result_json, '$.reference') IS 'text'
			and length(json_extract(result_json, '$.operationID')) between 1 and 128
			and length(json_extract(result_json, '$.feed')) between 1 and 256
			and length(json_extract(result_json, '$.reference')) between 1 and 128
		)),
	claim_token text
		check (claim_token is null or (typeof(claim_token) = 'text' and length(claim_token) between 1 and 128)),
	lease_until integer
		check (lease_until is null or (typeof(lease_until) = 'integer' and lease_until > 0)),
	attempts integer not null default 0
		check (typeof(attempts) = 'integer' and attempts >= 0 and attempts <= 1024),
	created_at integer not null check (typeof(created_at) = 'integer'),
	updated_at integer not null check (typeof(updated_at) = 'integer'),
	-- A succeeded row MUST carry its result; pending/processing MUST NOT.
	check (state = 'succeeded' or result_json is null),
	check (state <> 'succeeded' or result_json is not null),
	-- Only a processing row holds a claim (token + lease together).
	check ((state = 'processing') = (claim_token is not null and lease_until is not null))
)`

// feedSignerActiveRepoClaimIndexSQL is the partial unique index that enforces
// at most ONE processing row per (registry_id, topic): a distinct operation ID
// targeting the same repository feed cannot both pass the stale check and
// perform the network/key work. The loser of this gate never calls the
// updater and may retry after the winner completes, at which point the
// generation guard reports a conflict.
const feedSignerActiveRepoClaimIndexSQL = `CREATE UNIQUE INDEX feed_signer_active_repo_claim
	on feed_signer_operations(registry_id, topic) where state = 'processing'`

// installFeedSignerOperationStoreV10 is migration 10's body. It REBUILDS the
// migration-9 feed_signer_operations table around the hardened schema.
//
// Migration 9 created the table WITHOUT registry_id or topic, and a succeeded
// migration-9 row stores only operationID/feed/reference in its result JSON —
// the control-plane registry_id and the canonical repo topic are NOT derivable
// from any of them. Inventing a registry/topic for an existing row would route
// a retry against the wrong registry, so migration 10 fails CLOSED whenever
// ANY migration-9 row exists: every such row is upgraded-by-refusal, because
// none can be carried forward without fabrication. The branch is unreleased
// (a real production database has never carried migration 9), so the only
// legitimate inputs are empty (upgrade cleanly) and adversarial non-empty
// (refuse atomically, version stays 9, nothing touched).
func installFeedSignerOperationStoreV10(ctx context.Context, tx *sql.Tx) error {
	// The migration-9 table must exist (it precedes 10 in the chain); if it is
	// genuinely absent (impossible via the chain, but fail-closed regardless),
	// install the hardened schema directly.
	var exists int
	if err := tx.QueryRowContext(ctx,
		`select count(*) from sqlite_master where type = 'table' and name = 'feed_signer_operations'`).Scan(&exists); err != nil {
		return fmt.Errorf("migration 10: check feed_signer_operations existence: %w", err)
	}

	if exists != 0 {
		var n int
		if err := tx.QueryRowContext(ctx, `select count(*) from feed_signer_operations`).Scan(&n); err != nil {
			return fmt.Errorf("migration 10: count existing feed signer operations: %w", err)
		}
		if n != 0 {
			return errors.New("migration 10: existing feed_signer_operations rows cannot be upgraded because the control-plane registry_id and canonical topic are not derivable; failing closed rather than inventing them")
		}
		if _, err := tx.ExecContext(ctx, `drop table feed_signer_operations`); err != nil {
			return fmt.Errorf("migration 10: drop empty migration-9 table: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, feedSignerOperationTableSQLV10); err != nil {
		return fmt.Errorf("migration 10: create hardened feed signer operations table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, feedSignerActiveRepoClaimIndexSQL); err != nil {
		return fmt.Errorf("migration 10: create active repo claim index: %w", err)
	}
	return nil
}

// FeedSignerOperation is one durable feed-commit attempt, keyed by the stable
// OperationID and bound to the control-plane registry and canonical topic it
// targets. Only the fixed-size domain-separated hash of the canonical typed
// request is stored — never a raw request, and never any credential or key
// material. A succeeded row additionally carries the bounded canonical JSON
// result; a processing row carries an unpredictable claim token and lease so
// exactly one request owns the network/key work at a time.
type FeedSignerOperation struct {
	OperationID string
	RegistryID  int64
	Topic       string
	RequestHash [32]byte
	State       string
	ResultJSON  []byte
	ClaimToken  *string
	LeaseUntil  *time.Time
	Attempts    int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// feedSignerOperationColumns is the canonical read column list.
const feedSignerOperationColumns = `operation_id, registry_id, topic, request_hash, state, result_json,
	claim_token, lease_until, attempts, created_at, updated_at`

func scanFeedSignerOperation(s scanRow, op *FeedSignerOperation) error {
	var (
		hash                       []byte
		result, claimToken         sql.NullString
		lease                      sql.NullInt64
		attempts, createdNs, updNs int64
	)
	if err := s.Scan(&op.OperationID, &op.RegistryID, &op.Topic, &hash, &op.State, &result,
		&claimToken, &lease, &attempts, &createdNs, &updNs); err != nil {
		return err
	}
	copy(op.RequestHash[:], hash)
	if result.Valid {
		op.ResultJSON = []byte(result.String)
	}
	if claimToken.Valid {
		t := claimToken.String
		op.ClaimToken = &t
	}
	if lease.Valid {
		lt := nanosToTime(lease.Int64)
		op.LeaseUntil = &lt
	}
	op.Attempts = int(attempts)
	op.CreatedAt = nanosToTime(createdNs)
	op.UpdatedAt = nanosToTime(updNs)
	return nil
}

// GetFeedSignerOperation loads one operation by ID, or sql.ErrNoRows.
func (s *Store) GetFeedSignerOperation(ctx context.Context, operationID string) (FeedSignerOperation, error) {
	var op FeedSignerOperation
	if err := scanFeedSignerOperation(s.DB.QueryRowContext(ctx,
		`select `+feedSignerOperationColumns+` from feed_signer_operations where operation_id = ?`, operationID), &op); err != nil {
		return FeedSignerOperation{}, err
	}
	return op, nil
}

// ReserveFeedSignerOperation atomically ensures a pending row exists for an
// operation ID + registry + canonical topic + request hash. On a fresh ID it
// inserts a pending row; on an existing ID it leaves it untouched and returns
// the current row so the caller can apply the idempotency decision (identical
// succeeded -> return the stored result; differed hash -> conflict). The
// insert-or-ignore is atomic and out of any network/key work.
func (s *Store) ReserveFeedSignerOperation(ctx context.Context, operationID string, registryID int64, topic string, reqHash [32]byte) (FeedSignerOperation, error) {
	var op FeedSignerOperation
	err := s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		now := time.Now().UTC()
		nowNanos := timeToNanos(now)
		if _, err := c.ExecContext(ctx, `insert or ignore into feed_signer_operations
			(operation_id, registry_id, topic, request_hash, state, result_json,
			 claim_token, lease_until, attempts, created_at, updated_at)
			values (?, ?, ?, ?, ?, null, null, null, 0, ?, ?)`,
			operationID, registryID, topic, reqHash[:], FeedSignerOpPending, nowNanos, nowNanos); err != nil {
			return err
		}
		return scanFeedSignerOperation(c.QueryRowContext(ctx,
			`select `+feedSignerOperationColumns+` from feed_signer_operations where operation_id = ?`, operationID), &op)
	})
	if err != nil {
		return FeedSignerOperation{}, err
	}
	return op, nil
}

// ClaimFeedSignerOperation atomically transitions a pending row to processing
// (or reclaims an operation's own EXPIRED processing lease) under a fresh
// unpredictable claim token and a future, bounded lease. The partial unique
// index on (registry_id, topic) for processing means a DIFFERENT operation
// targeting the same repository feed cannot also claim — its UPDATE raises a
// uniqueness error (a "lost claim") returned as an error so the caller never
// performs the network/key work.
//
// It returns won=true exactly when THIS call is now the sole owner of the
// request's network/key work. A concurrent identical request that lost the
// claim gets won=false and must poll for the winner's stored result.
func (s *Store) ClaimFeedSignerOperation(ctx context.Context, operationID string, reqHash [32]byte, claimToken string, leaseUntil time.Time) (bool, error) {
	nowNanos := timeToNanos(time.Now().UTC())
	res, err := s.DB.ExecContext(ctx, `update feed_signer_operations
		set state = 'processing', claim_token = ?, lease_until = ?, updated_at = ?, attempts = attempts + 1
		where operation_id = ? and request_hash = ?
			and (state = 'pending' or (state = 'processing' and lease_until < ?))`,
		claimToken, timeToNanos(leaseUntil), nowNanos, operationID, reqHash[:], timeToNanos(time.Now().UTC()))
	if err != nil {
		// Includes the partial-unique-index violation when another operation
		// holds the (registry_id, topic) processing claim: the caller is the
		// loser and must NOT update.
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// CompleteFeedSignerOperation transitions a processing operation to the
// terminal succeeded state, storing the bounded canonical result JSON. It is
// conditional on the claim token matching, so a stale or stolen token can
// never complete someone else's claim. When two concurrent identical requests
// race completion, the first wins the update and the second finds the row
// already succeeded with the SAME hash and the SAME canonical result, which is
// an idempotent no-op returning nil.
func (s *Store) CompleteFeedSignerOperation(ctx context.Context, operationID string, reqHash [32]byte, claimToken string, resultJSON []byte) error {
	nowNanos := timeToNanos(time.Now().UTC())
	res, err := s.DB.ExecContext(ctx, `update feed_signer_operations
		set state = 'succeeded', result_json = ?, claim_token = null, lease_until = null, updated_at = ?
		where operation_id = ? and request_hash = ? and claim_token = ? and state = 'processing'`,
		string(resultJSON), nowNanos, operationID, reqHash[:], claimToken)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	// Zero rows: either we hold a stale token (a takeover happened) or a
	// concurrent identical request already completed the same operation. Only
	// the latter is acceptable: the stored result must be byte-canonically
	// identical to what we are about to persist (not merely same-hash), so two
	// completers never disagree about the persisted feed/reference.
	existing, err := s.GetFeedSignerOperation(ctx, operationID)
	if err != nil {
		return err
	}
	if existing.State != FeedSignerOpSucceeded || existing.RequestHash != reqHash {
		return errors.New("complete feed signer operation: operation is not owned by this claim or the request hash did not match")
	}
	if !bytesEqual(existing.ResultJSON, resultJSON) {
		return errors.New("complete feed signer operation: concurrent completed result does not match this canonical result")
	}
	return nil
}

// ReleaseFeedSignerOperation returns a processing operation to pending,
// clearing its claim, but ONLY when the exact claim token matches. It is used
// for a DEFINITE pre-update failure so a later retry can re-claim; an
// uncertain update failure never releases (the lease is kept until recovery).
// A stale token (already taken over) is a harmless no-op: it returns without
// error and without mutating the row.
func (s *Store) ReleaseFeedSignerOperation(ctx context.Context, operationID string, claimToken string) error {
	nowNanos := timeToNanos(time.Now().UTC())
	if _, err := s.DB.ExecContext(ctx, `update feed_signer_operations
		set state = 'pending', claim_token = null, lease_until = null, updated_at = ?
		where operation_id = ? and claim_token = ? and state = 'processing'`,
		nowNanos, operationID, claimToken); err != nil {
		return err
	}
	return nil
}

// newClaimToken returns an unpredictable 128-hex claim token from the
// cryptorandom source, or panics only on a catastrophic RNG failure.
func newClaimToken() string {
	buf := make([]byte, claimTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("claim token entropy source failed: %v", err))
	}
	return hex.EncodeToString(buf)
}

// claimTokenEqual reports whether two claim tokens are equal in constant time.
func claimTokenEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
