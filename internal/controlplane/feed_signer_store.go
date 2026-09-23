package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uncloud-registry/registry/internal/publish"
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

// feedSignerOperationIDGrammarCond is the SQL predicate that is byte-parity with
// publish.ValidateOperationID: it is TRUE exactly when an operation_id VIOLATES
// the application operation-ID grammar (and so must abort the write). The valid
// set is: non-empty, at most 128 code points, every character an ASCII printable
// 0x20..0x7e EXCEPT the five Go-JSON-escaped punctation bytes `"`, `\`, `<`,
// `>`, `&`, and therefore no controls (0x00..0x1f), no DEL (0x7f), and no
// non-ASCII code point (>= U+0080, including U+2028/U+2029, which Go's JSON
// encoder escapes).
//
// SQLite has no octet_length, so non-ASCII is detected by CODEPOINT range: GLOB
// ranges operate on decoded characters, so `[char(128)-char(0x10ffff)]` matches
// exactly a code point >= U+0080 without ever matching a high ASCII byte (the
// classic GLOB mistake of trying to range raw bytes). The control grammar uses
// `[char(1)-char(31)]` (never a char(0) low endpoint — a NUL in the PATTERN is
// unreliable) plus an explicit `instr(..., char(0))` for the NUL byte itself.
// Every operand is NULL-proof (the leading `IS NULL` term makes the whole OR
// either 0 or 1, never NULL), so SQLite's three-valued logic can never bypass
// the guard via a NULL or a malformed storage class.
const feedSignerOperationIDGrammarCond = `(NEW.operation_id IS NULL
	OR typeof(NEW.operation_id) <> 'text'
	OR length(NEW.operation_id) < 1
	OR length(NEW.operation_id) > 128
	OR instr(NEW.operation_id, char(0)) > 0
	OR NEW.operation_id glob '*[' || char(1) || '-' || char(31) || ']*'
	OR NEW.operation_id glob '*[' || char(127) || ']*'
	OR NEW.operation_id glob '*[' || char(128) || '-' || char(0x10ffff) || ']*'
	OR instr(NEW.operation_id, '"') > 0
	OR instr(NEW.operation_id, char(92)) > 0
	OR instr(NEW.operation_id, '<') > 0
	OR instr(NEW.operation_id, '>') > 0
	OR instr(NEW.operation_id, '&') > 0)`

// feedSignerOperationIDTriggerSQL returns the dedicated DB-level operation-ID
// identity triggers (BEFORE INSERT and BEFORE UPDATE on feed_signer_operations).
// They apply the full operation-ID grammar to EVERY active row regardless of
// state — pending, processing, and succeeded alike — closing the direct-SQL gap
// that (before migration 13) only constrained operation_id by type/length/bounds
// in the table CHECK (the character-set grammar was only enforced implicitly
// for succeeded rows via the result-integrity trigger's byte-exact
// concatenation). A direct SQL write that tries to store an operation_id
// violating publish.ValidateOperationID is aborted.
func feedSignerOperationIDTriggerSQL() []string {
	return []string{
		`create trigger feed_signer_operation_id_ins
			before insert on feed_signer_operations for each row
			begin select raise(abort, 'feed signer operation id violates the operation-ID grammar') where ` + feedSignerOperationIDGrammarCond + `; end`,
		`create trigger feed_signer_operation_id_upd
			before update on feed_signer_operations for each row
			begin select raise(abort, 'feed signer operation id violates the operation-ID grammar') where ` + feedSignerOperationIDGrammarCond + `; end`,
	}
}

// installFeedSignerOperationStoreV13 is migration 13's body. It closes the
// database operation-ID grammar gap by:
//
//  1. DROP-and-re-CREATE the dedicated operation-ID identity triggers (INSERT +
//     UPDATE), so pending/processing/succeeded rows ALL obey the exact
//     application grammar (bounded length + JSON-safe printable-ASCII set,
//     rejecting quote/backslash/<,>,&/controls/DEL/non-ASCII) — the same grammar
//     as publish.ValidateOperationID;
//  2. REINSTALL the migration-12 byte-exact canonical-result triggers (drop +
//     recreate) ONLY AFTER the identity triggers, so their byte-exact
//     concatenation of NEW.operation_id into the canonical JSON runs only once
//     the operation-id grammar has been proven for every row that reaches it;
//  3. ATOMICALLY harden every existing active row via the guarded self-update,
//     which fires the new UPDATE identity trigger (and result triggers) per
//     row. Any schema-admitted old-v12 row whose operation_id violates the
//     grammar aborts the migration and rolls back byte-identically: version
//     stays 12, the triggers/schema/data are untouched, and no invalid active
//     operational state is silently rewritten, deleted, or quarantined.
//
// Fresh installs run 1→12→13 and reach version 13 with the identity triggers
// present; every valid v12 database (whose operation ids are the 64-hex forms
// ComputeOperationID has always produced) upgrades cleanly.
func installFeedSignerOperationStoreV13(ctx context.Context, tx *sql.Tx) error {
	// 1. Drop any stale identity triggers and install the authoritative ones.
	for _, name := range []string{"feed_signer_operation_id_ins", "feed_signer_operation_id_upd"} {
		if _, err := tx.ExecContext(ctx, `drop trigger if exists `+name); err != nil {
			return fmt.Errorf("migration 13: drop stale operation-id trigger %s: %w", name, err)
		}
	}
	for _, stmt := range feedSignerOperationIDTriggerSQL() {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration 13: install operation-id identity trigger: %w", err)
		}
	}
	// 2. Reinstall the byte-exact canonical-result triggers under the same names
	//    migration 12 created, ordering the operation-id grammar first.
	for _, name := range []string{"feed_signer_result_integrity_ins", "feed_signer_result_integrity_upd"} {
		if _, err := tx.ExecContext(ctx, `drop trigger if exists `+name); err != nil {
			return fmt.Errorf("migration 13: drop canonical-result trigger %s: %w", name, err)
		}
	}
	for _, stmt := range feedSignerResultCanonicalTriggerSQL() {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration 13: install canonical-result trigger: %w", err)
		}
	}
	// 3. Harden existing active rows atomically: the guarded self-update fires
	//    the new UPDATE identity trigger (and result triggers) for EVERY row,
	//    with no value changed. A row with a grammar-violating operation_id
	//    aborts here, rolling the whole migration back (version stays 12, no
	//    schema object, trigger, or data touched).
	if _, err := tx.ExecContext(ctx, `update feed_signer_operations set operation_id = operation_id`); err != nil {
		return fmt.Errorf("migration 13: hardening existing feed signer operations failed: %w", err)
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

// sentinel errors for migration-9 legacy-row adoption. All are data-free (no
// registry/topic/request content) so a mishandled quarantine row never leaks
// state.
var (
	errFeedSignerLegacyConflict  = errors.New("feed signer: legacy operation request hash differs; refusing to adopt")
	errFeedSignerLegacyMalformed = errors.New("feed signer: legacy succeeded result is malformed; remains quarantined")
	errFeedSignerLegacyAmbiguous = errors.New("feed signer: multiple distinct legacy candidates match; refusing to adopt")
)

// AdoptLegacyFeedSignerOperation atomically adopts a quarantined migration-9
// row into the hardened ACTIVE table on the FIRST same-logical-request call,
// locating the quarantined row by the CURRENT operation ID OR the DERIVED
// historical migration-9 operation ID (legacyOperationID).
//
// A quarantined row is validated against the algorithm/identity it claims:
//
//   - a row keyed by the CURRENT operation ID is the CURRENT identity and must
//     carry the CURRENT canonical request hash (reqHash) to be promoted;
//   - a row keyed by the DERIVED HISTORICAL operation ID is the HISTORICAL
//     (migration-9) identity and must carry the exact historical request hash
//     (legacyReqHash — legacyFeedCommitHash over the reconstructed historical
//     request whose OperationID is the historical value) to be validated.
//
// The candidate set is resolved DETERMINISTICALLY:
//   - zero candidates -> no-op (nothing quarantined for this operation);
//   - a candidate whose stored hash does NOT match its claimed identity is a
//     CONFLICT (the OperationID was reused with different input) and stays
//     quarantined;
//   - TWO distinct valid candidates (one current, one historical) is an
//     AMBIGUITY that FAILS CLOSED with nothing adopted and nothing deleted, so
//     a conflicting dual row can never accidentally adopt a different logical
//     request;
//   - exactly one valid candidate is adopted.
//
// pending: becomes an active PENDING row under the CURRENT operation ID and
// CURRENT request hash, carrying the supplied registry_id and canonical topic,
// so it then signs exactly once through the normal reserve/claim/complete path
// (which carry the current OperationID + current hash).
//
// succeeded: its stored result is STRICTLY decoded and validated — the result
// OperationID must equal the QUARANTINED row's own identity (a historical row's
// m9 result carries the HISTORICAL OperationID), and Feed/Reference must equal
// the current logical request — then promoted as an active SUCCEEDED row under
// the CURRENT operation ID and CURRENT request hash, with an equivalent
// canonical result REWRITTEN to the CURRENT operation ID (feed/reference
// unchanged). No external feed re-update ever happens on adoption. The active
// insert and the quarantine delete occur in ONE transaction; a malformed legacy
// succeeded result fails closed and stays quarantined.
func (s *Store) AdoptLegacyFeedSignerOperation(ctx context.Context, operationID string, registryID int64, topic, reference string, reqHash [32]byte, legacyOperationID string, legacyReqHash [32]byte) (adopted bool, err error) {
	type legacyRow struct {
		opID   string
		hash   [32]byte
		state  string
		result sql.NullString
	}
	err = s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		// Only adopt when the active table has no row for the CURRENT operation
		// ID; otherwise the caller's normal idempotency applies to the active row.
		var activeCount int
		if err := c.QueryRowContext(ctx,
			`select count(*) from feed_signer_operations where operation_id = ?`, operationID).Scan(&activeCount); err != nil {
			return err
		}
		if activeCount != 0 {
			return nil
		}

		// Gather candidate quarantine rows by the current ID OR the derived
		// historical ID (deduped when they coincide). The two-ID OR is the
		// migration bridge for a real m9 row (keyed by the historical ID) that
		// the current request (carrying the current ID) can never reach by key.
		params := []any{operationID}
		if legacyOperationID != "" && legacyOperationID != operationID {
			params = append(params, legacyOperationID)
		}
		placeholders := "?" + strings.Repeat(", ?", len(params)-1)
		rows, err := c.QueryContext(ctx,
			`select `+feedSignerLegacyColumns+` from feed_signer_operations_legacy where operation_id in (`+placeholders+`)`,
			params...)
		if err != nil {
			return err
		}
		var cands []legacyRow
		for rows.Next() {
			var (
				opID                 string
				hash                 []byte
				state                string
				result               sql.NullString
				createdNs, updatedNs int64
			)
			if err := rows.Scan(&opID, &hash, &state, &result, &createdNs, &updatedNs); err != nil {
				rows.Close()
				return err
			}
			var h [32]byte
			copy(h[:], hash)
			cands = append(cands, legacyRow{opID: opID, hash: h, state: state, result: result})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(cands) == 0 {
			return nil
		}

		// Classify every candidate against its claimed identity. A candidate is
		// accepted only when its stored hash matches the algorithm of the row it
		// keys (current identities must match reqHash; historical identities must
		// match legacyReqHash); a mismatch is a hard conflict under BOTH
		// algorithms and stays quarantined.
		var valid []legacyRow
		for _, cd := range cands {
			switch {
			case cd.opID == operationID:
				if cd.hash != reqHash {
					return errFeedSignerLegacyConflict
				}
			case legacyOperationID != "" && cd.opID == legacyOperationID:
				if cd.hash != legacyReqHash {
					return errFeedSignerLegacyConflict
				}
			default:
				// A row matched the IN-list but is neither identity: incoherent.
				return errFeedSignerLegacyConflict
			}
			valid = append(valid, cd)
		}
		// Two distinct valid candidates => ambiguity => fail closed.
		if len(valid) != 1 {
			return errFeedSignerLegacyAmbiguous
		}
		cd := valid[0]

		now := time.Now().UTC()
		nowNanos := timeToNanos(now)
		switch cd.state {
		case FeedSignerOpPending:
			// Promote under the CURRENT operation ID and CURRENT request hash so
			// the modern reserve/claim/complete path compares correctly.
			if _, err := c.ExecContext(ctx, `insert into feed_signer_operations
				(operation_id, registry_id, topic, request_hash, state, result_json,
				 claim_token, lease_until, attempts, created_at, updated_at)
				values (?, ?, ?, ?, ?, null, null, null, 0, ?, ?)`,
				operationID, registryID, topic, reqHash[:], FeedSignerOpPending, nowNanos, nowNanos); err != nil {
				return err
			}
		case FeedSignerOpSucceeded:
			if !cd.result.Valid {
				return errFeedSignerLegacyMalformed
			}
			// Strict decode + validate against the QUARANTINED row's own
			// identity and the current logical request's canonical feed/ref.
			validated, derr := decodeStoredResult([]byte(cd.result.String))
			if derr != nil {
				return errFeedSignerLegacyMalformed
			}
			if validated.OperationID != cd.opID || validated.Feed != topic || validated.Reference != reference {
				return errFeedSignerLegacyMalformed
			}
			// Rewrite an equivalent canonical result to the CURRENT operation ID
			// (feed/reference unchanged) so the promoted active row carries the
			// current identity the modern path expects and the byte-exact
			// canonical-result trigger accepts.
			rewritten := publish.FeedCommitResult{OperationID: operationID, Feed: validated.Feed, Reference: validated.Reference}
			canonical := publish.CanonicalFeedCommitResultJSON(rewritten)
			marshalled, merr := json.Marshal(rewritten)
			if merr != nil || !bytes.Equal(marshalled, canonical) {
				return errFeedSignerLegacyMalformed
			}
			if _, err := c.ExecContext(ctx, `insert into feed_signer_operations
				(operation_id, registry_id, topic, request_hash, state, result_json,
				 claim_token, lease_until, attempts, created_at, updated_at)
				values (?, ?, ?, ?, ?, ?, null, null, 0, ?, ?)`,
				operationID, registryID, topic, reqHash[:], FeedSignerOpSucceeded, string(canonical), nowNanos, nowNanos); err != nil {
				return err
			}
		default:
			return errFeedSignerLegacyMalformed
		}

		// Delete the quarantined row ONLY after the active insert succeeded. The
		// whole sequence (active-read, quarantine-read/validate, active-insert,
		// quarantine-delete) is one transaction, so a failure rolls everything
		// back and the legacy row is never stranded.
		if _, err := c.ExecContext(ctx,
			`delete from feed_signer_operations_legacy where operation_id = ?`, cd.opID); err != nil {
			return err
		}
		adopted = true
		return nil
	})
	return adopted, err
}

// LegacyOperationCount reports how many quarantined migration-9 rows remain
// unpromoted. The signer uses it to decide whether the (potentially costly) doc
// read that derives the historical operation ID is worth attempting: when zero
// legacy rows remain (the steady state after every m9 row has been adopted), no
// historical derivation is attempted and the commit path pays nothing extra.
func (s *Store) LegacyOperationCount(ctx context.Context) (int, error) {
	var n int
	if err := s.DB.QueryRowContext(ctx, `select count(*) from feed_signer_operations_legacy`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
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
