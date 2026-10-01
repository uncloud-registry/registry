package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Migration 17 closes the writer-fence gap left open by migration 16: an
// already-running process built against the pre-migration-16 code (or any
// direct-SQL writer) can hold an open handle to the SAME physical database and
// call the unchanged ReserveFeedSignerOperation / ClaimFeedSignerOperation
// store methods directly, without ever knowing publication_states exists. Such
// a writer can insert a fresh feed_signer_operations row, claim it, and drive
// it to 'succeeded' — advancing the feed — with zero publication_states
// record, recreating exactly the untracked-terminal-success gap migration 16
// was built to close, just for a NEWLY inserted attempt rather than pre-v16
// history.
//
// Migration 17 makes that impossible at the SQLite boundary, for every
// process and every already-open handle, by:
//
//  1. validating the exact committed migration-16 schema (publication_states
//     plus every migration 9-15 feed-signer/binding object migration 16
//     already required) before any DDL runs;
//  2. validating that every EXISTING feed_signer_operations row (and the
//     feed_signer_operations_legacy quarantine table) is provably tracked by a
//     coherent publication_states row, failing the whole migration atomically
//     otherwise;
//  3. installing two narrow triggers on feed_signer_operations — one on
//     INSERT, one on the UPDATE that grants claim authority (pending/expired-
//     lease -> processing under a fresh claim token) — that reject the write
//     unless a matching, currently-"active" publication_states row already
//     exists for the same (registry_id, attempt_id). Release, completion, and
//     replay paths are untouched: see feedSignerPublicationFenceClaimTriggerSQL.
var (
	// errFeedSignerFencePredecessorMalformed is migration 17's single stable,
	// data-free prerequisite error: the database stamped at version 16 does not
	// carry the exact committed migration-16 publication_states schema (table +
	// both identity triggers) or the migration 9-15 feed-signer/binding objects
	// migration 16 itself required. A missing or weakened lookalike of any of
	// them fails before migration 17 installs any object.
	errFeedSignerFencePredecessorMalformed = errors.New("controlplane: migration 17 prerequisite failed: publication execution schema is not the genuine version-16 schema")

	// errFeedSignerFenceHistoryUnsafe is migration 17's fail-closed refusal for
	// pre-v17 feed-signer history that cannot be proven safe: any row in
	// feed_signer_operations_legacy (always unsafe, exactly like migration 16's
	// broadened rule), or any feed_signer_operations row (pending, processing,
	// or succeeded) with no coherent matching publication_states row. See
	// validateFeedSignerFenceHistorySafe.
	errFeedSignerFenceHistoryUnsafe = errors.New("controlplane: migration 17 refused: pre-v17 feed signer history is not provably tracked by publication_states")
)

// feedSignerPublicationFenceInsertTriggerSQL is migration 17's INSERT gate: a
// fresh feed_signer_operations row (whether a normal ReserveFeedSignerOperation
// reserve or an AdoptLegacyFeedSignerOperation promotion) may only be created
// under an operation_id that is CURRENTLY the "active" authorized attempt for
// the same registry in publication_states. A writer that never reserved (or
// does not know to reserve) a publication_states row — including an
// already-running pre-migration-16 process — is rejected atomically, before
// the row exists at all.
const feedSignerPublicationFenceInsertTriggerSQL = `create trigger feed_signer_operations_publication_fence_ins
	before insert on feed_signer_operations for each row
	when not exists (
		select 1 from publication_states
		where registry_id = NEW.registry_id and attempt_id = NEW.operation_id and state = 'active'
	)
	begin select raise(abort, 'feed signer operation insert has no matching active publication execution record'); end`

// feedSignerPublicationFenceClaimTriggerSQL is migration 17's CLAIM-authority
// gate. It fires ONLY on the transition that grants a NEW right to perform the
// external network/key work — a fresh claim (pending -> processing) or a
// reclaim of an expired lease (processing -> processing under another
// operation's starvation-prevention reset, or the same operation's own expired
// lease) — which ClaimFeedSignerOperation ALWAYS pairs with a freshly minted,
// unpredictable claim_token (see newClaimToken). It is detected structurally
// (NEW.state = 'processing' and the claim_token actually changed), never by
// wall-clock comparison, so it can never mis-fire on:
//
//   - a lease RENEWAL (ExtendFeedSignerLease: state stays 'processing', the
//     SAME claim_token is kept) — not gated, matches
//     "must remain valid" for legitimate in-flight work;
//   - a RELEASE (ReleaseFeedSignerOperation, or ClaimFeedSignerOperation's own
//     same-repo starvation-prevention reset: NEW.state = 'pending') — not
//     gated;
//   - a COMPLETION (CompleteFeedSignerOperation /
//     CompleteFeedSignerOperationAndTerminatePublication: NEW.state =
//     'succeeded') — not gated.
//
// A claim/reclaim whose operation_id is no longer the CURRENT active attempt
// for its registry — including a STALE row left behind by an attempt that has
// since been superseded via ReplacePublicationExecutionAttempt — is rejected:
// stale attempts can never reacquire claim authority.
const feedSignerPublicationFenceClaimTriggerSQL = `create trigger feed_signer_operations_publication_fence_upd
	before update on feed_signer_operations for each row
	when NEW.state = 'processing'
		and (OLD.claim_token is null or NEW.claim_token <> OLD.claim_token)
		and not exists (
			select 1 from publication_states
			where registry_id = NEW.registry_id and attempt_id = NEW.operation_id and state = 'active'
		)
	begin select raise(abort, 'feed signer operation claim has no matching active publication execution record'); end`

// validateFeedSignerFencePredecessor validates the exact committed
// migration-16 schema before any migration-17 DDL runs: every object
// migration 16 itself required (migration 9-15 feed-signer/binding objects,
// via validatePublicationStatePredecessor) PLUS the publication_states table
// and its two identity triggers migration 16 installs. Comparison is
// byte-exact for objects that are created directly (never via a rename-based
// rebuild), matching the same proof validatePublicationStatePredecessor
// already applies to the feed-signer objects.
func validateFeedSignerFencePredecessor(ctx context.Context, tx *sql.Tx) error {
	if err := validatePublicationStatePredecessor(ctx, tx); err != nil {
		return errFeedSignerFencePredecessorMalformed
	}

	stored, ok, err := storedObjectSQL(ctx, tx, "table", "publication_states")
	if err != nil || !ok || stored != publicationStateTableSQL {
		return errFeedSignerFencePredecessorMalformed
	}

	triggerDDL := publicationStateIdentityTriggerSQL()
	for i := range triggerDDL {
		// SQLite stores CREATE TRIGGER with that two-keyword prefix uppercased
		// even though the executable DDL constant uses lowercase (the same
		// deterministic sqlite_schema serialization detail
		// validatePublicationStatePredecessor already accounts for).
		triggerDDL[i] = strings.Replace(triggerDDL[i], "create trigger", "CREATE TRIGGER", 1)
	}
	triggerNames := []string{"publication_state_operation_id_ins", "publication_state_operation_id_upd"}
	for i, name := range triggerNames {
		stored, ok, err := storedObjectSQL(ctx, tx, "trigger", name)
		if err != nil || !ok || stored != triggerDDL[i] {
			return errFeedSignerFencePredecessorMalformed
		}
	}
	return nil
}

// feedSignerFenceHistoryStateCheck names one feed_signer_operations state and
// the publication_states states that make an existing row in that state
// COHERENT (provably tracked) rather than untracked/ambiguous:
//
//   - 'succeeded': the row can only be a genuine terminal success if
//     publication_states independently agrees the SAME attempt (registry_id +
//     attempt_id = operation_id) reached the SAME terminal 'succeeded' state —
//     exactly what CompleteFeedSignerOperationAndTerminatePublication commits
//     atomically. Anything else is the untracked-terminal-success gap this
//     migration exists to close.
//   - 'processing': a LIVE claim performing (or about to perform) external
//     work must be authorized by a currently-"active" publication_states row
//     under the same attempt; anything else is a live pre-v17 writer with no
//     publication_states coordination at all.
//   - 'pending': safe to preserve either while it is still the CURRENT
//     not-yet-claimed attempt ("active") or while it is the dead attempt of a
//     currently OPEN, not-yet-replaced generation conflict ("replaceable" —
//     MarkPublicationExecutionReplaceable does not change attempt_id, only
//     state, so the coherent match still holds at that exact snapshot). Once
//     a fresh attempt actually WINS the replacement CAS, publication_states'
//     attempt_id moves on and any further un-reclaimed old-attempt row is,
//     correctly, no longer coherent — but by then it is also permanently
//     inert: the migration-17 claim trigger will reject any future attempt to
//     reclaim it, so it poses no risk even where this validation is not
//     asked to preserve it.
var feedSignerFenceHistoryStateChecks = []struct {
	rowState         string
	publicationInSQL string
}{
	{FeedSignerOpSucceeded, `'succeeded'`},
	{FeedSignerOpProcessing, `'active'`},
	{FeedSignerOpPending, `'active','replaceable'`},
}

// validateFeedSignerFenceHistorySafe is migration 17's mandatory upgrade
// production policy: refuse atomically whenever the pre-v17 database holds
// ANY feed-signer history the fence cannot prove safe.
//
//   - feed_signer_operations_legacy carrying so much as one row (in EITHER
//     legacy state) is always unsafe: a migration-9 quarantine row has no
//     publication_states relationship of any kind, and
//     AdoptLegacyFeedSignerOperation can promote it into an active row at any
//     time after the upgrade (the same reasoning migration 16's round-5 /
//     Important 2 broadening already applied to feed_signer_operations
//     itself).
//   - any feed_signer_operations row whose state is NOT coherent with a
//     matching publication_states row, per feedSignerFenceHistoryStateChecks,
//     is unsafe.
//
// Only a database where every existing row is provably coherent (or there is
// no existing row at all) upgrades normally.
func validateFeedSignerFenceHistorySafe(ctx context.Context, tx *sql.Tx) error {
	var legacyRows int
	if err := tx.QueryRowContext(ctx, `select count(*) from feed_signer_operations_legacy`).Scan(&legacyRows); err != nil {
		return fmt.Errorf("migration 17: validate feed signer legacy quarantine history: %w", err)
	}
	if legacyRows != 0 {
		return errFeedSignerFenceHistoryUnsafe
	}

	for _, check := range feedSignerFenceHistoryStateChecks {
		var bad int
		query := `select count(*) from feed_signer_operations fs
			where fs.state = ?
			  and not exists (
				select 1 from publication_states ps
				where ps.registry_id = fs.registry_id
				  and ps.attempt_id = fs.operation_id
				  and ps.state in (` + check.publicationInSQL + `)
			  )`
		if err := tx.QueryRowContext(ctx, query, check.rowState).Scan(&bad); err != nil {
			return fmt.Errorf("migration 17: validate feed signer operation provenance for state %s: %w", check.rowState, err)
		}
		if bad != 0 {
			return errFeedSignerFenceHistoryUnsafe
		}
	}
	return nil
}

// installFeedSignerPublicationFence is migration 17's body: validate the
// exact predecessor schema, validate every existing feed-signer row is
// provably tracked, then install the two narrow fence triggers. Any failure
// aborts the migration transaction atomically (version stays 16, no schema
// object installed, no data touched).
func installFeedSignerPublicationFence(ctx context.Context, tx *sql.Tx) error {
	if err := validateFeedSignerFencePredecessor(ctx, tx); err != nil {
		return err
	}
	if err := validateFeedSignerFenceHistorySafe(ctx, tx); err != nil {
		return err
	}
	for _, stmt := range []string{feedSignerPublicationFenceInsertTriggerSQL, feedSignerPublicationFenceClaimTriggerSQL} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration 17: install publication fence trigger: %w", err)
		}
	}
	return nil
}
