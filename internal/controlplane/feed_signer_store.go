package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Feed signer operation states.
const (
	FeedSignerOpPending   = "pending"
	FeedSignerOpSucceeded = "succeeded"
)

// feedSignerOperationTableSQL is the SINGLE SOURCE OF TRUTH for the migration 9
// feed_signer_operations schema. %s is the table name. Exact storage-class
// (typeof) guards, a fixed 32-byte request hash BLOB, the primary key on the
// bounded operation ID, and the invariant that a succeeded row always carries
// its result JSON — the same hardening discipline migrations 7/8 apply to the
// publication outbox.
const feedSignerOperationTableSQL = `CREATE TABLE feed_signer_operations (
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

// installFeedSignerOperationStore is migration 9's body: it creates the durable
// feed-signer idempotency table. The schema is a pure forward extension and
// carries no existing-data validation burden.
func installFeedSignerOperationStore(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, feedSignerOperationTableSQL); err != nil {
		return err
	}
	// A supporting index makes the pending-recovery lookup by operation_id
	// (already the PK) trivially indexed; no second index is needed.
	return nil
}

// FeedSignerOperation is one durable feed-commit attempt, keyed by the stable
// OperationID. Only the fixed-size domain-separated hash of the canonical typed
// request is stored — never a raw request, and never any credential or key
// material. A succeeded row additionally carries the bounded canonical JSON
// result.
type FeedSignerOperation struct {
	OperationID string
	RequestHash [32]byte
	State       string
	ResultJSON  []byte
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// feedSignerOperationColumns is the canonical read column list.
const feedSignerOperationColumns = `operation_id, request_hash, state, result_json, created_at, updated_at`

func scanFeedSignerOperation(s scanRow, op *FeedSignerOperation) error {
	var hash []byte
	var result sql.NullString
	var createdAtNanos, updatedAtNanos int64
	if err := s.Scan(&op.OperationID, &hash, &op.State, &result, &createdAtNanos, &updatedAtNanos); err != nil {
		return err
	}
	copy(op.RequestHash[:], hash)
	if result.Valid {
		op.ResultJSON = []byte(result.String)
	}
	op.CreatedAt = nanosToTime(createdAtNanos)
	op.UpdatedAt = nanosToTime(updatedAtNanos)
	return nil
}

// GetFeedSignerOperation loads one operation by ID, or sql.ErrNoRows.
func (s *Store) GetFeedSignerOperation(ctx context.Context, operationID string) (FeedSignerOperation, error) {
	var op FeedSignerOperation
	if err := scanFeedSignerOperation(s.DB.QueryRowContext(ctx, `select `+feedSignerOperationColumns+` from feed_signer_operations where operation_id = ?`, operationID), &op); err != nil {
		return FeedSignerOperation{}, err
	}
	return op, nil
}

// ReserveFeedSignerOperation atomically reserves an operation ID for a request
// hash. On a fresh ID it inserts a pending row and returns created=true. On an
// existing ID it returns the stored row with created=false so the caller can
// apply the idempotency decision (identical succeeded → return stored result;
// pending → recover or retry; differing hash → conflict). Written in a single
// short write transaction with no network inside it.
func (s *Store) ReserveFeedSignerOperation(ctx context.Context, operationID string, reqHash [32]byte) (FeedSignerOperation, bool, error) {
	var op FeedSignerOperation
	created := false
	err := s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		var exists int
		if err := c.QueryRowContext(ctx, `select count(*) from feed_signer_operations where operation_id = ?`, operationID).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			return scanFeedSignerOperation(c.QueryRowContext(ctx, `select `+feedSignerOperationColumns+` from feed_signer_operations where operation_id = ?`, operationID), &op)
		}
		now := time.Now().UTC()
		nowNanos := timeToNanos(now)
		if _, err := c.ExecContext(ctx, `insert into feed_signer_operations
			(operation_id, request_hash, state, result_json, created_at, updated_at)
			values (?, ?, ?, null, ?, ?)`, operationID, reqHash[:], FeedSignerOpPending, nowNanos, nowNanos); err != nil {
			return err
		}
		m := [32]byte{}
		copy(m[:], reqHash[:])
		op = FeedSignerOperation{OperationID: operationID, RequestHash: m, State: FeedSignerOpPending, CreatedAt: now, UpdatedAt: now}
		created = true
		return nil
	})
	if err != nil {
		return FeedSignerOperation{}, false, err
	}
	return op, created, nil
}

// CompleteFeedSignerOperation transitions a pending operation to the terminal
// succeeded state, storing the bounded canonical result JSON. It is conditional
// on the current state being pending AND the request hash matching, so a
// concurrent differing-hash operation can never overwrite it. When two
// concurrent identical requests complete near-simultaneously, the first wins
// the row lock; the second finds the row already succeeded with the SAME hash
// and is treated as an idempotent no-op so both callers observe a single
// logical commit.
func (s *Store) CompleteFeedSignerOperation(ctx context.Context, operationID string, reqHash [32]byte, resultJSON []byte) error {
	nowNanos := timeToNanos(time.Now().UTC())
	res, err := s.DB.ExecContext(ctx, `update feed_signer_operations
		set state = ?, result_json = ?, updated_at = ?
		where operation_id = ? and state = ? and request_hash = ?`,
		FeedSignerOpSucceeded, string(resultJSON), nowNanos, operationID, FeedSignerOpPending, reqHash[:])
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
	// Zero rows affected: confirm the concurrent winner already stored an
	// identical succeeded result, in which case this is an idempotent no-op.
	existing, err := s.GetFeedSignerOperation(ctx, operationID)
	if err != nil {
		return err
	}
	if existing.State != FeedSignerOpSucceeded || existing.RequestHash != reqHash {
		return errors.New("complete feed signer operation: operation was not pending or request hash did not match")
	}
	return nil
}
