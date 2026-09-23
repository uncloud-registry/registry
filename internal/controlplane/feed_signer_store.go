package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
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
// only ever completes, releases, or extends its own claim by presenting the
// exact token the claim wrote (constant-time compare); a stale or stolen token
// can never complete or release the operation. 32 cryptorandom bytes,
// hex-encoded.
const claimTokenBytes = 32

// feedSignerLeaseDuration is how long a claim owns the network/key work before
// the lease expires and an identical retry may take it over (crash recovery).
// It MUST be strictly longer than feedSignerWorkTimeout below so a legitimate
// owner can never be running when the lease becomes reclaimable: even a work
// context that runs to its entire deadline stays comfortably inside the lease,
// and the renewal heartbeat keeps the lease alive while it works.
const feedSignerLeaseDuration = 2 * time.Minute

// feedSignerWorkTimeout bounds the ENTIRE claimed validation+read+update
// operation (resolver/doc/updater calls included) via one derived work context.
// It is strictly shorter than feedSignerLeaseDuration, so a legitimate owner
// with a working renewal heartbeat always holds a live lease; a work context
// that dies before the lease expires can never be observed as both "still
// running" and "lease already reclaimable".
const feedSignerWorkTimeout = 30 * time.Second

// feedSignerRenewInterval is the joined renewal heartbeat period, set to
// lease/3: the owner extends its own lease (token-owned, conditional) every
// interval. Each successful extension clears the takeover deadline; a failure
// to renew (stale token / takeover) cancels the work context immediately so a
// defeated owner never performs or completes the update.
const feedSignerRenewInterval = feedSignerLeaseDuration / 3

// feedSignerClaimMaxAttempts bounds how long a caller waits (polling) for a
// concurrent owner to finish before returning a retryable backend error. It is
// deliberately small so a same-operation concurrent caller never blocks a push
// indefinitely, and never performs the network/key work itself.
const feedSignerClaimMaxAttempts = 100

// feedSignerClaimPollInterval is the sleep between bounded polls for a
// concurrent claim to complete.
const feedSignerClaimPollInterval = 10 * time.Millisecond

// feedSignerLegacyTableSQL is the constrained QUARANTINE table that preserves
// every migration-9 feed_signer_operations row BYTE-FOR-BYTE during migration
// 10. Its columns and CHECKs mirror the migration-9 schema exactly, so the
// insert-select copy can never lose, mutate, or "repair" an original value. A
// quarantine row keeps its exact request_hash/state/result_json until an
// adoption request supplies the control-plane registry_id and canonical topic
// (which an m9 row never carried).
const feedSignerLegacyTableSQL = `create table if not exists feed_signer_operations_legacy (
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

// feedSignerLegacyColumns is the canonical quarantine read/copy column list,
// identical to migration 9's column order.
const feedSignerLegacyColumns = `operation_id, request_hash, state, result_json, created_at, updated_at`

// feedSignerOperationTableSQL is the migration-9 schema body, preserved
// verbatim so migration 9 (which MUST NOT be edited) still installs the
// original table that migration 10 then quarantines and rebuilds on empty.
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

// installFeedSignerOperationStoreV10 is migration 10's body (AMENDED). It
// QUARANTINES every migration-9 feed_signer_operations row BYTE-FOR-BYTE into
// the constrained feed_signer_operations_legacy table, then drops the
// migration-9 table and installs the hardened active schema.
//
// The migration-9 row set is never stranded and never fabricated: each m9 row
// is preserved verbatim in quarantine (same request_hash/state/result_json/
// timestamps) until a REQUEST supplies the control-plane registry_id and
// canonical topic an m9 row never carried, at which point the store adopts the
// row atomically only when the request hash matches (see
// ReserveFeedSignerOperation). This replaces the earlier fail-closed behavior
// (withhold the whole upgrade when any m9 row exists) with a strict
// preserve-then-adopt upgrade that lets v9 databases with rows progress.
//
// Databases already stamped with the OLD migration-10 schema (which created
// the hardened active table directly over an empty m9 table, without a
// quarantine table or result triggers) reach the same final state via
// migration 11, which creates the quarantine table if absent, installs the
// result-integrity triggers, and hardens existing active rows atomically.
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
		// Create the quarantine table (constrained, mirrors the m9 columns).
		if _, err := tx.ExecContext(ctx, feedSignerLegacyTableSQL); err != nil {
			return fmt.Errorf("migration 10: create quarantine table: %w", err)
		}
		// Copy every m9 row byte-for-byte into quarantine, then drop the m9
		// table. The insert-select preserves column order exactly.
		if _, err := tx.ExecContext(ctx,
			`insert into feed_signer_operations_legacy (`+feedSignerLegacyColumns+`)
				select `+feedSignerLegacyColumns+` from feed_signer_operations`); err != nil {
			return fmt.Errorf("migration 10: preserve migration-9 rows: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `drop table feed_signer_operations`); err != nil {
			return fmt.Errorf("migration 10: drop migration-9 table: %w", err)
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

// feedSignerResultIntegrityTriggerSQL returns the two result-integrity
// triggers (BEFORE INSERT and BEFORE UPDATE) that make the DATABASE itself
// reject a malformed succeeded result on active feed_signer_operations rows.
//
// For a state='succeeded' row the result_json must be a canonical compact JSON
// OBJECT carrying EXACTLY the three UNIQUE keys {operationID, feed,
// reference} — no extras, no duplicates — where operationID equals the row's
// operation_id, feed is exactly the canonical full-feed wire form
// (feed://<40 lowercase hex owner>/<64 lowercase hex topic>), and reference is
// exactly 64 lowercase-hex characters. Pending/processing rows must carry a
// NULL result. The trigger aborts the INSERT/UPDATE otherwise, so a direct-SQL
// write can never fabricate a success: the strict Go decoder stays as
// defense-in-depth.
func feedSignerResultIntegrityTriggerSQL() []string {
	hx40 := strings.Repeat("[0-9a-f]", 40)
	hx64 := strings.Repeat("[0-9a-f]", 64)
	guard := `(
		NEW.state = 'succeeded' and (
			json_valid(NEW.result_json) = 0
			or json_type(NEW.result_json) <> 'object'
			or (select count(*) from json_each(NEW.result_json)) <> 3
			or (select count(distinct key) from json_each(NEW.result_json)) <> 3
			or json_type(NEW.result_json,'$.operationID') is not 'text'
			or json_type(NEW.result_json,'$.feed') is not 'text'
			or json_type(NEW.result_json,'$.reference') is not 'text'
			or json_extract(NEW.result_json,'$.operationID') <> NEW.operation_id
			or length(json_extract(NEW.result_json,'$.feed')) <> 112
			or substr(json_extract(NEW.result_json,'$.feed'),1,7) <> 'feed://'
			or substr(json_extract(NEW.result_json,'$.feed'),48,1) <> '/'
			or substr(json_extract(NEW.result_json,'$.feed'),8,40) not glob '` + hx40 + `'
			or substr(json_extract(NEW.result_json,'$.feed'),49,64) not glob '` + hx64 + `'
			or length(json_extract(NEW.result_json,'$.reference')) <> 64
			or json_extract(NEW.result_json,'$.reference') not glob '` + hx64 + `'
			or json(NEW.result_json) <> NEW.result_json
		)
	) or (
		NEW.state <> 'succeeded' and NEW.result_json is not null
	)`
	return []string{
		`create trigger if not exists feed_signer_result_integrity_ins
			before insert on feed_signer_operations for each row
			begin select raise(abort, 'feed signer succeeded result violates the result contract') where ` + guard + `; end`,
		`create trigger if not exists feed_signer_result_integrity_upd
			before update on feed_signer_operations for each row
			begin select raise(abort, 'feed signer succeeded result violates the result contract') where ` + guard + `; end`,
	}
}

// feedSignerResultCanonicalTriggerSQL returns the TWO result-integrity
// triggers (BEFORE INSERT and BEFORE UPDATE) installed by migration 12. They
// REPLACE the migration-11 `json(...)`-based proof with BYTE-FOR-BYTE equality
// against the single canonical Go result layout, because SQLite's json()
// function minifies but PRESERVES member order and value spelling — so a
// reordered-members object ({"feed":…,"operationID":…,…}), an escaped key
// spelling ({"operation\u0049D":…}) or an escaped value spelling (feed:\/\/)
// could satisfy the old `json(NEW.result_json) = NEW.result_json` proof. The
// corrected triggers additionally require the stored result to be EXACTLY
//
//	{"operationID":"<opid>","feed":"feed://<40 hex>/<64 hex>","reference":"<64 hex>"}
//
// in that fixed key order, reconstructed in SQLite by plain string
// concatenation (every accepted successor field is a JSON-safe literal, so the
// concatenation is byte-identical to Go's json.Marshal — see
// publish.CanonicalFeedCommitResultJSON).
//
// For a state='succeeded' row the result_json must be a canonical compact JSON
// OBJECT carrying EXACTLY the three UNIQUE keys {operationID, feed,
// reference} — no extras, no duplicates, no reordering, no whitespace, no
// escaped spellings — where operationID equals the row's operation_id, feed is
// exactly the canonical full-feed wire form (feed://<40 lowercase hex owner>/<64
// lowercase hex topic>), reference is exactly 64 lowercase-hex characters, and
// the whole document byte-matches the canonical layout. Pending/processing rows
// must carry a NULL result. The trigger aborts the INSERT/UPDATE otherwise, so
// a direct-SQL write can never fabricate a success; the strict Go decoder stays
// as defense-in-depth.
func feedSignerResultCanonicalTriggerSQL() []string {
	hx40 := strings.Repeat("[0-9a-f]", 40)
	hx64 := strings.Repeat("[0-9a-f]", 64)
	// The byte-exact expected canonical JSON, built by concatenation from the
	// row identity (operation_id) and the already-validated canonical
	// feed/reference extracted from the JSON. Every field is JSON-safe (op id
	// constrained, feed/reference lowercase hex), so no escaping is needed and
	// this matches Go's json.Marshal byte-for-byte.
	expected := `'{"operationID":"' || NEW.operation_id
		|| '","feed":"' || json_extract(NEW.result_json,'$.feed')
		|| '","reference":"' || json_extract(NEW.result_json,'$.reference') || '"}'`
	guard := `(
		NEW.state = 'succeeded' and (
			json_valid(NEW.result_json) = 0
			or json_type(NEW.result_json) <> 'object'
			or (select count(*) from json_each(NEW.result_json)) <> 3
			or (select count(distinct key) from json_each(NEW.result_json)) <> 3
			or json_type(NEW.result_json,'$.operationID') is not 'text'
			or json_type(NEW.result_json,'$.feed') is not 'text'
			or json_type(NEW.result_json,'$.reference') is not 'text'
			or json_extract(NEW.result_json,'$.operationID') <> NEW.operation_id
			or length(json_extract(NEW.result_json,'$.feed')) <> 112
			or substr(json_extract(NEW.result_json,'$.feed'),1,7) <> 'feed://'
			or substr(json_extract(NEW.result_json,'$.feed'),48,1) <> '/'
			or substr(json_extract(NEW.result_json,'$.feed'),8,40) not glob '` + hx40 + `'
			or substr(json_extract(NEW.result_json,'$.feed'),49,64) not glob '` + hx64 + `'
			or length(json_extract(NEW.result_json,'$.reference')) <> 64
			or json_extract(NEW.result_json,'$.reference') not glob '` + hx64 + `'
			or NEW.result_json <> ` + expected + `
		)
	) or (
		NEW.state <> 'succeeded' and NEW.result_json is not null
	)`
	return []string{
		`create trigger if not exists feed_signer_result_integrity_ins
			before insert on feed_signer_operations for each row
			begin select raise(abort, 'feed signer succeeded result violates the canonical result contract') where ` + guard + `; end`,
		`create trigger if not exists feed_signer_result_integrity_upd
			before update on feed_signer_operations for each row
			begin select raise(abort, 'feed signer succeeded result violates the canonical result contract') where ` + guard + `; end`,
	}
}

// installFeedSignerOperationStoreV12 is migration 12's body. It REPLACES the
// migration-11 result-integrity triggers — whose `json(NEW.result_json) =
// NEW.result_json` proof is insufficient because SQLite json() minifies but
// preserves member order/spelling — with the corrected BYTE-EXACT canonical
// triggers, then ATOMICALLY re-hardens every EXISTING succeeded row against the
// corrected contract (a guarded self-update fires the new UPDATE trigger per
// row), so a malformed/noncanonical existing row aborts the migration and rolls
// back byte-identically with the version staying 11 and no data touched. Fresh
// installs run 1→11→12 and reach version 12 with the corrected triggers in
// place.
func installFeedSignerOperationStoreV12(ctx context.Context, tx *sql.Tx) error {
	// Drop the migration-11 trigs (same names, loose proof) and install the
	// corrected byte-exact triggers under the same names.
	for _, name := range []string{"feed_signer_result_integrity_ins", "feed_signer_result_integrity_upd"} {
		if _, err := tx.ExecContext(ctx, `drop trigger if exists `+name); err != nil {
			return fmt.Errorf("migration 12: drop migration-11 trigger %s: %w", name, err)
		}
	}
	for _, s := range feedSignerResultCanonicalTriggerSQL() {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migration 12: install canonical result trigger: %w", err)
		}
	}
	// Harden existing active rows atomically: the guarded self-update fires the
	// new UPDATE trigger for EVERY row, with no value changed. A malformed or
	// non-canonical succeeded row aborts here, rolling the whole migration back
	// (the database stays at version 11 untouched).
	if _, err := tx.ExecContext(ctx, `update feed_signer_operations set operation_id = operation_id`); err != nil {
		return fmt.Errorf("migration 12: hardening existing feed signer operations failed: %w", err)
	}
	return nil
}

// installFeedSignerOperationStoreV11 is migration 11's body. It brings BOTH
// databases that ran the amended migration 10 (fresh) and databases already
// stamped with the OLD migration-10 schema to the identical final hardened
// state:
//
//   - the quarantine feed_signer_operations_legacy table exists (idempotent),
//   - the two result-integrity triggers are installed on the active table
//     (idempotent, IF NOT EXISTS),
//   - every EXISTING active row is hardened ATOMICALLY: a guarded self-update
//     fires the UPDATE trigger for each row, so any malformed succeeded result
//     aborts the migration and rolls back byte-for-byte (version stays 10,
//     every row and the schema are untouched). Valid state/claims/results are
//     preserved exactly.
func installFeedSignerOperationStoreV11(ctx context.Context, tx *sql.Tx) error {
	// 1. Quarantine table present for every upgraded database.
	if _, err := tx.ExecContext(ctx, feedSignerLegacyTableSQL); err != nil {
		return fmt.Errorf("migration 11: create quarantine table: %w", err)
	}
	// 2. Result-integrity triggers on the active table (idempotent).
	for _, s := range feedSignerResultIntegrityTriggerSQL() {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migration 11: create result-integrity trigger: %w", err)
		}
	}
	// 3. Harden existing active rows atomically: the guarded self-update fires
	//    the UPDATE trigger for EVERY row, with no value changed. A malformed
	//    succeeded row aborts here, rolling the whole migration back
	//    byte-identically (the old-m10 database stays at version 10 untouched).
	if _, err := tx.ExecContext(ctx, `update feed_signer_operations set operation_id = operation_id`); err != nil {
		return fmt.Errorf("migration 11: hardening existing feed signer operations failed: %w", err)
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

// sentinel errors for migration-9 legacy-row adoption. Both are data-free (no
// registry/topic/request content) so a mishandled quarantine row never leaks
// state.
var (
	errFeedSignerLegacyConflict  = errors.New("feed signer: legacy operation request hash differs; refusing to adopt")
	errFeedSignerLegacyMalformed = errors.New("feed signer: legacy succeeded result is malformed; remains quarantined")
)

// AdoptLegacyFeedSignerOperation atomically adopts a quarantined migration-9
// row into the hardened ACTIVE table on the FIRST same-OperationID request —
// and only when the incoming request hash matches the legacy request_hash.
//
// The stored request_hash is accepted when it equals EITHER the current
// canonical request hash (reqHash) OR the exact historical migration-9 hash
// (legacyReqHash, computed by legacyFeedCommitHash from the incoming request's
// raw fields). Migration-9 rows were signed with the legacy delimiter-framed
// algorithm, so a logically-identical legacy operation is recognized only when
// its stored hash matches legacyReqHash; it must match under ONE of the two
// algorithms to adopt.
//
//   - pending: becomes an active PENDING row carrying the supplied
//     control-plane registry_id and canonical topic.
//   - succeeded: is STRICTLY decoded and validated against the operation ID,
//     canonical topic, and canonical reference implied by the matching request
//     hash (decodeStoredResult subsumes duplicate-member/unknown-field/trailing
//     rejection and the strict feed/reference contract); only a fully valid
//     result becomes an active SUCCEEDED row.
//   - a differing request hash under BOTH algorithms is a CONFLICT (the same
//     OperationID was reused with different input).
//   - a malformed legacy succeeded result FAILS CLOSED and stays quarantined.
//
// A quarantine row is deleted only after it is successfully adopted — state is
// never invented and a row is never silently dropped. The gate is atomic: the
// active-table read, the quarantine read/validate, the active insert, and the
// quarantine delete all happen in one write transaction.
func (s *Store) AdoptLegacyFeedSignerOperation(ctx context.Context, operationID string, registryID int64, topic, reference string, reqHash, legacyReqHash [32]byte) (adopted bool, err error) {
	err = s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		// Only adopt when the active table has no row for this operation.
		var activeCount int
		if err := c.QueryRowContext(ctx,
			`select count(*) from feed_signer_operations where operation_id = ?`, operationID).Scan(&activeCount); err != nil {
			return err
		}
		if activeCount != 0 {
			return nil // already active; the caller's normal idempotency applies
		}

		var (
			opID      string
			hash      []byte
			state     string
			result    sql.NullString
			createdNs int64
			updatedNs int64
		)
		err := c.QueryRowContext(ctx,
			`select `+feedSignerLegacyColumns+` from feed_signer_operations_legacy where operation_id = ?`, operationID).
			Scan(&opID, &hash, &state, &result, &createdNs, &updatedNs)
		if errors.Is(err, sql.ErrNoRows) {
			return nil // nothing quarantined for this operation
		}
		if err != nil {
			return err
		}
		var legacyHash [32]byte
		copy(legacyHash[:], hash)
		// Adopt only when the stored hash matches the current canonical request
		// hash OR the exact historical migration-9 hash (see legacyFeedCommitHash).
		// A row matching neither is a DIFFERENT logical request and conflicts.
		if legacyHash != reqHash && legacyHash != legacyReqHash {
			return errFeedSignerLegacyConflict
		}

		now := time.Now().UTC()
		nowNanos := timeToNanos(now)
		switch state {
		case FeedSignerOpPending:
			// The ACTIVE row is written with the CURRENT canonical request hash
			// (reqHash), so the rest of the modern reserve/claim/complete path
			// compares against the modern hash; the legacy m9 hash was only a
			// RECOGNITION key to prove this is a logically identical operation.
			if _, err := c.ExecContext(ctx, `insert into feed_signer_operations
				(operation_id, registry_id, topic, request_hash, state, result_json,
				 claim_token, lease_until, attempts, created_at, updated_at)
				values (?, ?, ?, ?, ?, null, null, null, 0, ?, ?)`,
				operationID, registryID, topic, reqHash[:], FeedSignerOpPending, nowNanos, nowNanos); err != nil {
				return err
			}
		case FeedSignerOpSucceeded:
			if !result.Valid {
				return errFeedSignerLegacyMalformed
			}
			// Strict decode + validate against the operation ID / canonical
			// topic / canonical reference implied by the matching request hash.
			validated, derr := decodeStoredResult([]byte(result.String))
			if derr != nil {
				return errFeedSignerLegacyMalformed
			}
			if validated.OperationID != operationID || validated.Feed != topic || validated.Reference != reference {
				return errFeedSignerLegacyMalformed
			}
			if _, err := c.ExecContext(ctx, `insert into feed_signer_operations
				(operation_id, registry_id, topic, request_hash, state, result_json,
				 claim_token, lease_until, attempts, created_at, updated_at)
				values (?, ?, ?, ?, ?, ?, null, null, 0, ?, ?)`,
				operationID, registryID, topic, reqHash[:], FeedSignerOpSucceeded, result.String, nowNanos, nowNanos); err != nil {
				return err
			}
		default:
			return errFeedSignerLegacyMalformed
		}

		// Delete the quarantine row ONLY after a successful active insert.
		if _, err := c.ExecContext(ctx,
			`delete from feed_signer_operations_legacy where operation_id = ?`, operationID); err != nil {
			return err
		}
		adopted = true
		return nil
	})
	return adopted, err
}

// ClaimFeedSignerOperation atomically transitions a pending row to processing
// (or reclaims an operation's own EXPIRED processing lease) under a fresh
// unpredictable claim token and a future, bounded lease.
//
// The claim is a single write transaction that FIRST resets ANY expired
// processing row for the same (registry_id, topic) — including one held by a
// DIFFERENT operation ID — back to pending, then claims the requested row.
// This removes distinct-operation starvation across stores/processes: a
// crashed owner of a different operation cannot indefinitely block this
// repository feed once its lease expires. Only an EXPIRED lease (lease_until
// <= now, i.e. a crashed/uncertain prior attempt) is ever cleared; a live
// lease is never touched, so a real owner cannot be evicted.
//
// The partial unique index on (registry_id, topic) for processing still means
// a DIFFERENT operation targeting the same repository feed cannot claim while
// a LIVE lease is held — its UPDATE raises a uniqueness error (a "lost claim")
// returned as an error so the caller never performs the network/key work.
//
// It returns won=true exactly when THIS call is now the sole owner of the
// request's network/key work. A concurrent identical request that lost the
// claim gets won=false and must poll for the winner's stored result.
func (s *Store) ClaimFeedSignerOperation(ctx context.Context, operationID string, reqHash [32]byte, claimToken string, leaseUntil time.Time) (won bool, err error) {
	err = s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		now := time.Now().UTC()
		nowNanos := timeToNanos(now)
		// First release ANY expired processing claim on the same repository
		// feed (registry_id, topic), including a different operation ID,
		// conditional on lease_until <= now. This removes distinct-op
		// starvation: a crashed owner of another operation cannot hold the
		// slot forever.
		if _, err := c.ExecContext(ctx, `update feed_signer_operations
			set state = 'pending', claim_token = null, lease_until = null, updated_at = ?
			where registry_id = (select registry_id from feed_signer_operations where operation_id = ?)
			  and topic = (select topic from feed_signer_operations where operation_id = ?)
			  and state = 'processing' and lease_until is not null and lease_until <= ?`,
			nowNanos, operationID, operationID, nowNanos); err != nil {
			return err
		}
		// Then claim the requested row (pending, or this operation's own
		// expired processing lease).
		res, err := c.ExecContext(ctx, `update feed_signer_operations
			set state = 'processing', claim_token = ?, lease_until = ?, updated_at = ?, attempts = attempts + 1
			where operation_id = ? and request_hash = ?
				and (state = 'pending' or (state = 'processing' and lease_until < ?))`,
			claimToken, timeToNanos(leaseUntil), nowNanos, operationID, reqHash[:], nowNanos)
		if err != nil {
			// Includes the partial-unique-index violation when another
			// operation holds a LIVE (registry_id, topic) processing claim:
			// the caller is the loser and must NOT update.
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		won = n == 1
		return nil
	})
	return won, err
}

// ExtendFeedSignerLease renews the caller's OWN claim by extending lease_until
// to the fresh lease deadline, CONDITIONAL on the exact claim token still
// owning the processing row. A stale or stolen token (already taken over by a
// later claim, or the row no longer processing) matches zero rows and returns
// an error, which the caller MUST treat as "lost the lease": it cancels its
// work context immediately and does not complete. A live lease is never
// extended beyond the configured duration — the new deadline is always exactly
// now+feedSignerLeaseDuration, so a renewal cannot silently grow unbounded.
func (s *Store) ExtendFeedSignerLease(ctx context.Context, operationID, claimToken string, leaseUntil time.Time) error {
	nowNanos := timeToNanos(time.Now().UTC())
	res, err := s.DB.ExecContext(ctx, `update feed_signer_operations
		set lease_until = ?, updated_at = ?
		where operation_id = ? and claim_token = ? and state = 'processing' and lease_until <= ?`,
		timeToNanos(leaseUntil), nowNanos, operationID, claimToken, timeToNanos(leaseUntil))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("extend feed signer lease: claim is no longer owned")
	}
	return nil
}

// EnsureFeedSignerLeaseOwned verifies that the caller STILL owns the live
// processing claim for an operation at this instant (exact token match AND a
// lease that has not expired). It runs immediately before the external
// network/key update and before completion so a defeated owner (whose lease was
// taken over) discovers it has lost the claim BEFORE performing the update,
// and fails closed. A nil error means the caller remains the sole owner.
func (s *Store) EnsureFeedSignerLeaseOwned(ctx context.Context, operationID, claimToken string) error {
	var state string
	var lease sql.NullInt64
	nowNanos := timeToNanos(time.Now().UTC())
	err := s.DB.QueryRowContext(ctx, `select state, lease_until
		from feed_signer_operations where operation_id = ? and claim_token = ?`,
		operationID, claimToken).Scan(&state, &lease)
	if err != nil {
		return errors.New("ensure feed signer lease: claim is no longer owned")
	}
	if state != FeedSignerOpProcessing || !lease.Valid || lease.Int64 <= nowNanos {
		return errors.New("ensure feed signer lease: claim is no longer owned")
	}
	return nil
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
// cryptorandom source. An entropy failure is a DATA-FREE backend error (never
// a panic): a signer whose RNG is broken must fail its claim closed, returning
// the generic backend sentinel, rather than crash the process or mint a weak
// token.
func newClaimToken() (string, error) {
	buf := make([]byte, claimTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
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
