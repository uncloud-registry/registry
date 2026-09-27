package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Publication execution states. A row's lifecycle is strictly:
//
//	(none) --reserve--> active --generation-conflict--> replaceable --CAS--> active (fresh attempt) --success--> succeeded
//	                       \--------------------------success--------------------------------------------------^
//
// succeeded is terminal: no row ever leaves it, and no OTHER attempt id may
// ever be authorized for this publication id again.
const (
	PublicationExecutionActive      = "active"
	PublicationExecutionReplaceable = "replaceable"
	PublicationExecutionSucceeded   = "succeeded"
)

// PublicationExecution is the durable logical-publication execution record,
// keyed by the STABLE PublicationID (never the per-attempt FeedSigner
// identity). It is the round-3 fix for the terminal-success gap a stable
// PublicationID otherwise leaves open: without it, a publication that already
// reached a terminal success could be "retried" after an unrelated later
// publication overwrote the same tag, computing a fresh per-attempt identity
// that would authenticate cleanly and advance the feed a SECOND time. Exactly
// one attempt id is ever authorized ("active") at a time; only an
// authoritative generation conflict (a definite pre-update failure with zero
// external write) may flip the row to "replaceable", after which exactly one
// fresh attempt may atomically claim the row via CAS. Once "succeeded", the
// row is permanent: a different attempt id can never advance the feed again,
// even after the recorded attempt's own tag mapping is overwritten by an
// entirely different logical publication.
type PublicationExecution struct {
	PublicationID string
	RegistryID    int64
	State         string
	AttemptID     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// publicationExecutionColumns is the canonical read column list.
const publicationExecutionColumns = `operation_id, registry_id, state, attempt_id, created_at, updated_at`

// publicationStateTableSQL is the migration-16 schema for the durable
// logical-publication execution table. operation_id is the STABLE
// PublicationID (the primary key: at most one row per logical publication,
// ever). registry_id scopes it to the FK'd registry namespace. state is
// constrained to the three-value vocabulary above, and attempt_id carries the
// currently-authorized (or, once succeeded, the permanently-succeeded)
// per-attempt FeedSigner identity. Both operation_id and attempt_id are
// enforced against the same byte-exact operation-ID grammar migration 14
// installed for feed_signer_operations (via dedicated identity triggers,
// since SQLite triggers are database-global).
const publicationStateTableSQL = `CREATE TABLE publication_states (
	operation_id text primary key
		check (typeof(operation_id) = 'text' and length(operation_id) between 1 and 128),
	registry_id integer not null
		check (typeof(registry_id) = 'integer' and registry_id > 0)
		references registries(id) on delete cascade,
	state text not null check (state in ('active','replaceable','succeeded')),
	attempt_id text not null
		check (typeof(attempt_id) = 'text' and length(attempt_id) between 1 and 128),
	created_at integer not null check (typeof(created_at) = 'integer'),
	updated_at integer not null check (typeof(updated_at) = 'integer')
)`

// errPublicationStatePredecessorMalformed is migration 16's single stable,
// data-free prerequisite error. A database stamped at version 15 must carry
// the exact publication_bindings table and both identity triggers installed by
// migration 15; a missing or weakened lookalike fails before migration 16
// creates any object.
var errPublicationStatePredecessorMalformed = errors.New("controlplane: migration 16 prerequisite failed: publication binding schema is not the genuine version-15 schema")

// errPublicationStateHistoryUnsafe is migration 16's fail-closed refusal for
// pre-v16 publication history that safe state reconstruction cannot cover
// (round 4 / Finding 1). See validatePublicationStateHistorySafe.
var errPublicationStateHistoryUnsafe = errors.New("controlplane: migration 16 refused: pre-v16 succeeded publication history cannot be safely reconstructed")

// validatePublicationStateHistorySafe is migration 16's mandatory upgrade
// production policy: refuse atomically whenever the pre-v16 database holds
// ANY completed publication history that publication_states cannot account
// for. A v15 (or earlier-lineage) database has NO record of the STABLE
// PublicationID a completed feed_signer_operations row belonged to —
// operation_id there is the per-ATTEMPT identity (a one-way domain-separated
// hash of registry/owner/repo/tag/digest/generation, or of PublicationID plus
// the attempt's own generation/reference), never the stable id itself, and
// publication_bindings (migration 15) carries only a bound HASH with no
// success/failure state, so neither table can be inverted back to "which
// PublicationID, if any, already reached a terminal success". Backfilling
// publication_states from either table would therefore have to GUESS, and a
// wrong guess is exactly the round-3 gap this migration exists to close: a
// stable PublicationID whose pre-v16 success is left unrecorded can be
// "retried" after an unrelated later publication overwrites the same tag,
// re-authenticating cleanly against the CURRENT generation and advancing the
// feed a second time.
//
// A pre-v16 feed_signer_operations row in ANY other state (pending,
// processing) never advanced the feed — its logical publication, if it has
// one at all, never became terminal, so a future attempt for it correctly
// takes the ordinary "absent -> first-ever reservation" path in
// publication_states with nothing to protect. Likewise, a publication_bindings
// row alone (bound, but never completed) proves nothing about a completed
// feed write. Only a SUCCEEDED feed_signer_operations row is unsafe: it is
// the sole durable proof that a real external feed advancement happened under
// a protocol that had no terminal-success ledger, so its mere existence,
// regardless of which registry or topic it names, refuses the migration
// atomically before any DDL or version write. Fresh databases and databases
// whose feed_signer_operations table has never recorded a completed
// publication upgrade exactly as before.
func validatePublicationStateHistorySafe(ctx context.Context, tx *sql.Tx) error {
	var succeeded int
	if err := tx.QueryRowContext(ctx,
		`select count(*) from feed_signer_operations where state = 'succeeded'`).Scan(&succeeded); err != nil {
		return errors.New("migration 16: validate pre-v16 publication history")
	}
	if succeeded != 0 {
		return errPublicationStateHistoryUnsafe
	}
	return nil
}

// byteExactIdentityGrammarCond returns the migration-14 byte-exact
// operation-ID grammar predicate (see feedSignerOperationIDGrammarCondV14),
// generalized to an arbitrary NEW column so it can be applied to BOTH
// operation_id and attempt_id in one trigger. The recursive CTE is named
// uniquely per column so two invocations can be safely OR-combined inside a
// single trigger's WHEN clause (SQLite rejects duplicate CTE names within one
// statement).
func byteExactIdentityGrammarCond(column string) string {
	cte := "byte_scan_" + column
	col := "NEW." + column
	return `(` + col + ` IS NULL
		OR typeof(` + col + `) <> 'text'
		OR length(hex(cast(` + col + ` as blob))) not between 2 and 256
		OR length(hex(cast(` + col + ` as blob))) % 2 != 0
		OR exists (
			with recursive ` + cte + `(i, pair) as (
				select 1, substr(hex(cast(` + col + ` as blob)), 1, 2)
				union all
				select i + 1, substr(hex(cast(` + col + ` as blob)), 2 * (i + 1) - 1, 2)
				from ` + cte + `
				where i < length(hex(cast(` + col + ` as blob))) / 2
			)
			select 1 from ` + cte + `
			where pair < '20' or pair > '7E' or pair in ('22','26','3C','3E','5C')
		))`
}

// publicationStateIdentityTriggerSQL returns the dedicated DB-level identity
// triggers (BEFORE INSERT and BEFORE UPDATE on publication_states) enforcing
// the byte-exact operation-ID grammar on BOTH operation_id and attempt_id, so
// a direct-SQL write can never store a grammar-violating identity in either
// column.
func publicationStateIdentityTriggerSQL() []string {
	cond := byteExactIdentityGrammarCond("operation_id") + " OR " + byteExactIdentityGrammarCond("attempt_id")
	return []string{
		`create trigger publication_state_operation_id_ins
			before insert on publication_states for each row
			begin select raise(abort, 'publication state identity violates the byte-exact operation-ID grammar') where ` + cond + `; end`,
		`create trigger publication_state_operation_id_upd
			before update on publication_states for each row
			begin select raise(abort, 'publication state identity violates the byte-exact operation-ID grammar') where ` + cond + `; end`,
	}
}

// installPublicationStateStore is migration 16's body. It creates the durable
// publication_states table and installs its identity triggers. It is pure
// forward DDL over a NEW table — it never reads, mutates, or drops any
// migration 1-15 state, so already-migrated and fresh databases converge on
// the same schema, and any statement failure aborts the migration transaction
// atomically (version stays 15, no schema object installed).
func installPublicationStateStore(ctx context.Context, tx *sql.Tx) error {
	if err := validatePublicationStatePredecessor(ctx, tx); err != nil {
		return err
	}
	if err := validatePublicationStateHistorySafe(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, publicationStateTableSQL); err != nil {
		return errors.New("migration 16: create publication states table")
	}
	for _, stmt := range publicationStateIdentityTriggerSQL() {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return errors.New("migration 16: install publication state operation-id identity trigger")
		}
	}
	return nil
}

// validatePublicationStatePredecessor compares migration 15's table and
// triggers against the same DDL constants migration 15 installs. Comparison
// uses the existing quote-aware SQL fingerprinting rather than a permissive
// column-presence check, so a hand-built lookalike cannot satisfy the gate.
func validatePublicationStatePredecessor(ctx context.Context, tx *sql.Tx) error {
	triggerDDL := publicationBindingIdentityTriggerSQL()
	// SQLite stores CREATE TRIGGER with that two-keyword prefix uppercased even
	// when migration 15's executable DDL constant uses lowercase. This is a
	// deterministic sqlite_schema serialization detail, not a relaxed
	// comparison: every remaining byte is still fingerprinted exactly.
	for i := range triggerDDL {
		triggerDDL[i] = strings.Replace(triggerDDL[i], "create trigger", "CREATE TRIGGER", 1)
	}
	expected := []struct {
		typ, name, ddl string
	}{
		{"table", "publication_bindings", publicationBindingTableSQL},
		{"trigger", "publication_binding_operation_id_ins", triggerDDL[0]},
		{"trigger", "publication_binding_operation_id_upd", triggerDDL[1]},
	}
	for _, object := range expected {
		stored, ok, err := storedObjectSQL(ctx, tx, object.typ, object.name)
		if err != nil || !ok {
			return errPublicationStatePredecessorMalformed
		}
		gotFingerprint, err := normalizeSQL(stored)
		if err != nil {
			return errPublicationStatePredecessorMalformed
		}
		wantFingerprint, err := normalizeSQL(object.ddl)
		if err != nil || gotFingerprint != wantFingerprint {
			return errPublicationStatePredecessorMalformed
		}
	}
	return nil
}

func scanPublicationExecution(s scanRow, e *PublicationExecution) error {
	var createdNs, updNs int64
	if err := s.Scan(&e.PublicationID, &e.RegistryID, &e.State, &e.AttemptID, &createdNs, &updNs); err != nil {
		return err
	}
	e.CreatedAt = nanosToTime(createdNs)
	e.UpdatedAt = nanosToTime(updNs)
	return nil
}

// GetPublicationExecution returns the durable execution row for a stable
// PublicationID, or sql.ErrNoRows when it was never reserved.
func (s *Store) GetPublicationExecution(ctx context.Context, publicationID string) (PublicationExecution, error) {
	var e PublicationExecution
	if err := scanPublicationExecution(s.DB.QueryRowContext(ctx,
		`select `+publicationExecutionColumns+` from publication_states where operation_id = ?`, publicationID), &e); err != nil {
		return PublicationExecution{}, err
	}
	return e, nil
}

// ReservePublicationExecution atomically ensures an execution row exists for
// a PublicationID: insert-or-ignore, exactly like ReservePublicationBinding.
// On a fresh id it inserts an "active" row recording attemptID as the
// authorized attempt; on an existing id it leaves the row untouched and
// returns the CURRENT row, so a racing contender that lost the insert reads
// back the actual winning attempt id rather than fabricating its own.
func (s *Store) ReservePublicationExecution(ctx context.Context, publicationID string, registryID int64, attemptID string) (PublicationExecution, error) {
	var e PublicationExecution
	err := s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		now := time.Now().UTC()
		nowNanos := timeToNanos(now)
		if _, err := c.ExecContext(ctx, `insert or ignore into publication_states
			(operation_id, registry_id, state, attempt_id, created_at, updated_at)
			values (?, ?, ?, ?, ?, ?)`,
			publicationID, registryID, PublicationExecutionActive, attemptID, nowNanos, nowNanos); err != nil {
			return err
		}
		return scanPublicationExecution(c.QueryRowContext(ctx,
			`select `+publicationExecutionColumns+` from publication_states where operation_id = ?`, publicationID), &e)
	})
	if err != nil {
		return PublicationExecution{}, err
	}
	return e, nil
}

// MarkPublicationExecutionReplaceable atomically flips an "active" row to
// "replaceable" — but ONLY when attemptID still equals the row's recorded
// active attempt id. It is called after an authoritative generation conflict
// (a definite pre-update failure with zero external write) terminates that
// SPECIFIC attempt; any other definite failure class must NEVER call this, so
// the row stays "active" and no fresh attempt is ever authorized to replace
// it.
//
// applied reports whether THIS call actually performed the flip. A stale
// attemptID (already replaced or already succeeded) or a non-active row is a
// harmless no-op: applied=false, err=nil — it never mutates, but the caller
// MUST observe applied=false as "the replaceable transition is NOT durably
// confirmed" rather than silently treating a no-op the same as a real flip.
// This is load-bearing: FeedSigner must never report an authoritative
// generation conflict as safe-to-rebuild unless applied is true (or the row
// is independently confirmed replaceable under this attempt), because a
// caller told "safe to rebuild" for a replacement that was never durably
// authorized would construct a fresh attempt the gate can then never admit.
func (s *Store) MarkPublicationExecutionReplaceable(ctx context.Context, publicationID, attemptID string) (applied bool, err error) {
	nowNanos := timeToNanos(time.Now().UTC())
	res, err := s.DB.ExecContext(ctx, `update publication_states
		set state = 'replaceable', updated_at = ?
		where operation_id = ? and attempt_id = ? and state = 'active'`,
		nowNanos, publicationID, attemptID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// ReplacePublicationExecutionAttempt atomically compare-and-swaps a
// "replaceable" row from oldAttemptID to a fresh newAttemptID, flipping its
// state back to "active". won=true iff this call performed the swap; the
// returned row is always the CURRENT row after the attempt (whether this
// caller won or lost), so a loser can decide its own outcome (another
// attempt now owns the active slot, or the publication already reached a
// terminal success) without a second round-trip. Two concurrent callers
// racing the identical (publicationID, oldAttemptID) CAS can never both win:
// only the first UPDATE observes state='replaceable', and it atomically
// clears that precondition for every other racer.
func (s *Store) ReplacePublicationExecutionAttempt(ctx context.Context, publicationID string, registryID int64, oldAttemptID, newAttemptID string) (won bool, row PublicationExecution, err error) {
	err = s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		nowNanos := timeToNanos(time.Now().UTC())
		res, err := c.ExecContext(ctx, `update publication_states
			set state = 'active', attempt_id = ?, updated_at = ?
			where operation_id = ? and registry_id = ? and state = 'replaceable' and attempt_id = ?`,
			newAttemptID, nowNanos, publicationID, registryID, oldAttemptID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		won = n == 1
		return scanPublicationExecution(c.QueryRowContext(ctx,
			`select `+publicationExecutionColumns+` from publication_states where operation_id = ?`, publicationID), &row)
	})
	if err != nil {
		return false, PublicationExecution{}, err
	}
	return won, row, nil
}

// CompleteFeedSignerOperationAndTerminatePublication atomically applies BOTH
// the per-attempt feed_signer_operations completion (identical semantics to
// CompleteFeedSignerOperation) AND the logical publication_states terminal
// marking, in ONE transaction — so the two can never split into an unsafe
// state (a completed attempt whose publication never terminates, or a
// terminated publication whose attempt row is not actually succeeded).
//
// The publication_states update is guarded on registryID+attemptID still
// owning the "active" slot. A zero-rows outcome there is tolerated ONLY when
// an idempotent concurrent completer already left this EXACT publication
// terminally succeeded under this EXACT attempt id and registry (the same
// tolerance CompleteFeedSignerOperation applies to the attempt row). Any
// OTHER zero-rows cause — the row is missing, still active/replaceable under
// a DIFFERENT attempt, or scoped to a different registry — is a hard error
// that rolls back the WHOLE transaction, including the feed_signer_operations
// completion just applied above: the two rows can never be left split, one
// terminated and the other not.
func (s *Store) CompleteFeedSignerOperationAndTerminatePublication(ctx context.Context, operationID string, reqHash [32]byte, claimToken string, resultJSON []byte, publicationID string, registryID int64, attemptID string) error {
	return s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		nowNanos := timeToNanos(time.Now().UTC())
		res, err := c.ExecContext(ctx, `update feed_signer_operations
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
		if n != 1 {
			// Zero rows: either a stale token (a takeover happened) or a
			// concurrent identical request already completed the same
			// operation. Only the latter is acceptable, and only when the
			// stored result agrees byte-for-byte — mirrors
			// CompleteFeedSignerOperation exactly.
			var existing FeedSignerOperation
			if err := scanFeedSignerOperation(c.QueryRowContext(ctx,
				`select `+feedSignerOperationColumns+` from feed_signer_operations where operation_id = ?`, operationID), &existing); err != nil {
				return err
			}
			if existing.State != FeedSignerOpSucceeded || existing.RequestHash != reqHash {
				return errors.New("complete feed signer operation: operation is not owned by this claim or the request hash did not match")
			}
			if !bytesEqual(existing.ResultJSON, resultJSON) {
				return errors.New("complete feed signer operation: concurrent completed result does not match this canonical result")
			}
		}

		res2, err := c.ExecContext(ctx, `update publication_states
			set state = 'succeeded', attempt_id = ?, updated_at = ?
			where operation_id = ? and registry_id = ? and attempt_id = ? and state = 'active'`,
			attemptID, nowNanos, publicationID, registryID, attemptID)
		if err != nil {
			return err
		}
		n2, err := res2.RowsAffected()
		if err != nil {
			return err
		}
		if n2 == 1 {
			return nil
		}
		// Zero rows: the ONLY acceptable cause is an idempotent concurrent
		// completer that already left this EXACT publication succeeded under
		// this EXACT attempt id and registry. A missing row, a row still
		// active/replaceable, a row succeeded under a DIFFERENT attempt, or a
		// different registry are all hard errors — the caller's
		// feed_signer_operations completion above is rolled back with them,
		// never left committed alone.
		var exec PublicationExecution
		if err := scanPublicationExecution(c.QueryRowContext(ctx,
			`select `+publicationExecutionColumns+` from publication_states where operation_id = ?`, publicationID), &exec); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errors.New("complete publication execution: publication was never authorized for this attempt")
			}
			return err
		}
		if exec.State != PublicationExecutionSucceeded || exec.AttemptID != attemptID || exec.RegistryID != registryID {
			return errors.New("complete publication execution: publication ownership is missing, stale, or mismatched")
		}
		return nil
	})
}
