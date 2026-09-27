package controlplane

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// migration describes one ordered, versioned schema change. Each migration is
// applied atomically in a single transaction and recorded in schema_migrations
// only after every statement succeeds.
//
// A migration either runs a list of discrete DDL statements (SQL) or an
// arbitrary, self-validating transaction body (Apply). Version 1 uses Apply to
// perform an atomic table rebuild that physically installs the foreign-key
// constraints on databases that already carry the pre-versioning schema.
type migration struct {
	Version int
	SQL     []string
	Apply   func(ctx context.Context, tx *sql.Tx) error
}

// migrations is the ordered list of schema versions. Version 1 establishes the
// base constrained schema for brand-new databases and, via rebuildSchema, also
// upgrades databases that already carry the pre-versioning control-plane schema
// (same columns, no foreign keys) so the promised foreign keys PHYSICALLY exist.
var migrations = []migration{
	{
		Version: 1,
		Apply:   rebuildSchema,
	},
	// Version 2 adds the at-rest feed-key envelope columns. ciphertext and
	// nonce are binary (BLOB), version is integer, per the Task 6 boundary;
	// they are NULL until a row is encrypted (fresh registries are encrypted
	// at creation; legacy plaintext rows are encrypted by the opt-in-gated
	// MigrateLegacyFeedKeys operation, which also clears the legacy column in
	// the same transaction). This migration is pure DDL and never reads,
	// touches, or clears the legacy encrypted_feed_private_key column: legacy
	// plaintext must only ever be read when the operator explicitly opts in
	// (CONTROLPLANE_MIGRATE_LEGACY_KEYS=true) and a cipher is configured.
	// The legacy column therefore survives as an empty vestigial column on
	// migrated and fresh databases alike, and no code path (other than the
	// gated migration) references it. Dropping it is deliberately deferred:
	// the same migration must run on databases whose legacy rows still carry
	// plaintext, and SQLite DROP COLUMN would discard that data.
	{
		Version: 2,
		SQL: []string{
			`alter table registries add column feed_key_ciphertext blob`,
			`alter table registries add column feed_key_nonce blob`,
			`alter table registries add column feed_key_version integer`,
		},
	},
	// Version 3 installs the schema-level feed-key envelope invariant: the
	// three feed-key columns must be either ALL NULL (no key) or ALL present
	// with a structurally valid envelope — nonce exactly
	// feedKeyEnvelopeNonceSize bytes, ciphertext at least
	// feedKeyEnvelopeCiphertextMin bytes (the AES-GCM empty-plaintext
	// minimum), and a strictly positive version. The migration first
	// VALIDATES every existing row — any partial envelope OR
	// complete-but-malformed envelope (wrong nonce/ciphertext lengths) fails
	// the migration (fully rolled back, version 2 stays recorded) rather than
	// being silently accepted — then installs BEFORE INSERT/UPDATE triggers
	// that enforce the invariant for every future write, including direct
	// SQL. Application layers (scan/list, store write guards, legacy
	// migration, rotation) enforce the same invariant on read and write; the
	// triggers close the direct-SQL gap so no code path can persist or mutate
	// a partial or malformed envelope. The 12/16 literals below MUST match
	// feedKeyEnvelopeNonceSize / feedKeyEnvelopeCiphertextMin in keycrypto.go
	// (pinned by TestFeedKeyEnvelopeConstantsMatchAESGCM).
	{
		Version: 3,
		Apply:   installFeedKeyEnvelopeInvariant,
	},
	// Version 4 converts invite credentials to a one-way, recipient-bound,
	// revocable lifecycle. The legacy token_hash TEXT column is rebuilt as
	// token_digest BLOB: exactly 32 bytes (schema CHECK), unique, never
	// reversible. The rebuild VALIDATES every existing row first:
	//
	//   - token_hash records EXACTLY ONE historical representation: the
	//     pre-Task-7 control plane stored `hex.EncodeToString([]byte(token))`
	//     — lowercase hex of the 32-char canonical raw-token TEXT — and never
	//     stored a SHA-256 digest. The 64 lowercase-hex value must therefore
	//     decode to exactly 32 bytes and those bytes MUST be a canonical
	//     Task-7 raw token (strict parse/re-encode); the digest is then
	//     SHA-256 over that recovered token text — the same digest the
	//     acceptance path computes, so pending invites stay acceptable after
	//     the upgrade. Every OTHER 64-hex value — including hex of a real
	//     SHA-256 digest (whose bytes are not a canonical token text) — is
	//     malformed and FAILS the migration (fully rolled back). Terminal
	//     (accepted) rows are validated exactly the same way. No content
	//     guessing, no alleged alternate digest format;
	//   - status must be pending or accepted (revoked did not exist in
	//     v1-v3; any other value fails);
	//   - an accepted invite is preserved VERBATIM as legacy_unattributed=1
	//     with accepted_by_user_id NULL — no membership is required, checked,
	//     or inferred. The pre-Task-7 acceptance path accepted any
	//     authenticated token holder and inserted THEIR membership without a
	//     recipient check, and the historical ACCEPTER was never recorded;
	//     the recipient's current membership (which may never have existed or
	//     may have been removed later) cannot establish attribution, so it is
	//     never consulted. Every syntactically/schema-valid accepted row
	//     survives, existing memberships are untouched, and no token retry
	//     ever succeeds for such invites;
	//   - expiry must parse as RFC3339 and the invite must grant pull or
	//     push;
	//   - converted digests must be unique (duplicate/colliding rows fail);
	//   - every existing user email AND invite recipient is normalized with
	//     the production NormalizeEmail inside the same transaction. A
	//     normalized USER collision (two legacy rows mapping to one
	//     canonical address) is detected BEFORE any update and fails the
	//     migration unchanged; invite-recipient collisions are fine (no
	//     unique invite-email invariant). Post-upgrade logins and recipient
	//     acceptance therefore work for whitespace/case legacy rows, with
	//     user IDs and every FK to them preserved.
	//
	// The rebuilt table adds accepted_by_user_id (FK → users, NULL for
	// legacy_unattributed accepted history), legacy_unattributed (migration-
	// only flag; new rows must be 0 and the flag can never be set after this
	// migration), accepted_at/revoked_at, status/accepted_by/attribution
	// CHECK constraints, a status index, and state-transition triggers
	// (invites are born pending; terminal states are immutable; acceptance
	// requires an attributed accepter; legacy_unattributed can never be set
	// by ordinary SQL and any UPDATE touching a legacy_unattributed row is
	// rejected outright — the row is a frozen historical record), closing the
	// direct-SQL gap the way migration 3 did for feed keys. The rebuild itself
	// runs inside the migration transaction, so any
	// malformed/duplicate/corrupt row rolls the whole upgrade back with the
	// legacy data untouched.
	{
		Version: 4,
		Apply:   installInviteDigestSchema,
	},
	// Version 5 is the forward-only repair bridge for the legacy-attribution
	// immutability trigger. The trigger was originally added by EDITING
	// migration 4 (head ef48240), so any database that applied the PRE-FIX
	// migration 4 (head 8178a82) has schema_migrations.version = 4, skips the
	// corrected code, and retains WRITABLE legacy_unattributed rows — ordinary
	// SQL could clear the flag and assign accepted_by_user_id, turning a
	// frozen historical record into an attributed acceptance. Editing an
	// applied migration can never reach such databases; v5 exists solely to
	// install (or reinstall) the authoritative BEFORE UPDATE trigger on every
	// version-4 schema. It validates the digest-schema prerequisite
	// (registry_invites must carry the legacy_unattributed column), DROPs any
	// stale same-name trigger, and CREATEs the frozen-record trigger — all
	// inside the migration transaction, so any failure rolls back with
	// version 4 still recorded and no data touched. Fresh and v0→v3→v4
	// databases reach this migration too (migration 4 already installed the
	// same trigger via the shared constant); the drop-if-exists + create is
	// idempotent and harmless there. v5 is the authoritative upgrade bridge:
	// every database ends at version 5.
	{
		Version: 5,
		Apply:   installInviteLegacyAttributionImmutability,
	},
	// Version 6 adds the transactional provisioning outbox: an explicit
	// registries.provisioning_state vocabulary (provisioning|ready|failed), a
	// guard trigger closing the direct-SQL gap on that vocabulary, and the
	// registry_publication_jobs table that carries exactly two deterministic
	// bootstrap jobs (auth, stamp) per registrations, unique per (registry,
	// kind). This is a pure forward extension: it never reads, mutates, or
	// drops any column or row used by migrations 1-5, so already-migrated
	// databases and fresh databases converge on the same schema. Pre-v6
	// registries (published inline under the older control plane) default to
	// 'ready'; fresh registrations are born 'provisioning' by the store and
	// only transition to ready/failed through verified reconciliation.
	{
		Version: 6,
		Apply:   installProvisioningOutboxSchema,
	},
	// Version 7 hardens the provisioning schema. It is the forward-only
	// authority for two gaps migration 6 left open:
	//
	//   1. migration 6's provisioning_state guard trigger is BEFORE UPDATE only,
	//      so direct INSERT SQL could still store a bogus vocabulary value; v7
	//      installs a symmetric BEFORE INSERT guard so the provisioning|ready|
	//      failed vocabulary is enforced on INSERT AND UPDATE/direct SQL;
	//   2. the v6 registry_publication_jobs table carries only KIND/STATE CHECKs,
	//      so direct SQL could store a malformed or incoherent job row. v7
	//      REBUILDS the table (drop/rename-inside-the-migration-transaction, the
	//      same atomic pattern migrations 1 and 4 use) with hardened DB
	//      invariants: bounded, structurally valid JSON-object payload that is
	//      kind-appropriate (auth carries $.version + $.defaultAccess, stamp
	//      carries $.defaultPolicy.batchID), nonnegative/bounded attempts,
	//      RFC3339 timestamps, bounded ids/token/ref/error sizes, the
	//      registry FK + (registry_id, kind) uniqueness, and state/ownership/
	//      lease/completion coherence (a claimed job holds a lease; every other
	//      state clears it; a succeeded job carries verified refs and a
	//      completion stamp). Every existing v6 row is validated by the new
	//      CHECKs during the copy, so a malformed row rolls the whole upgrade
	//      back (version stays 6, data untouched) while legitimate in-flight and
	//      terminal v6 rows migrate untouched.
	{
		Version: 7,
		Apply:   installProvisioningOutboxSchemaHarden,
	},
	// Version 8 closes the remaining SQLite storage-class / dynamic-typing /
	// three-valued-logic loopholes migration 7's CHECKs could not reach, and
	// is the authoritative hardening of the provisioning outbox:
	//
	//   1. Storage-class enforcement: SQLite's INTEGER/TEXT columns are
	//      dynamically typed, so `attempts integer not null` and the bounded
	//      text columns could still hold a REAL (e.g. 5.0), a numeric TEXT, or
	//      a NULL via direct SQL, and a 3VL comparison (`x = 1`) returns NULL
	//      (not FALSE) for a NULL x, FAILING a CHECK's intent. v8 adds explicit
	//      typeof() guards to every column so INTEGER columns are proven
	//      integer, TEXT columns proven text, and every bounded string's length
	//      and domain are exact.
	//   2. Exact policy-JSON shape: migration 7 accepted `$.defaultAccess` /
	//      `$.batchID` merely being present; v8 requires the production document
	//      shape exactly — auth carries `version` integer == 1,
	//      `defaultAccess` text == 'deny', `defaultRepo` object with
	//      `pull`/`push` arrays, and `repos` object; stamp carries `version`
	//      integer == 1, `defaultPolicy` object with a nonempty bounded text
	//      `batchID` and an `allowPushFor` array, and `repos` object. Guards
	//      use json_type() BEFORE value comparison, so a JSON type trick (a
	//      string "1" or an object version) can never satisfy an integer check.
	//   3. Timestamps move from TEXT to exact INTEGER Unix NANOSECONDS:
	//      SQLite cannot robustly validate a canonical UTC RFC3339/RFC3339Nano
	//      TEXT (real calendar validity, canonical Z form) in a CHECK — the v7
	//      GLOB allows calendar-invalid dates and arbitrary trailing junk. An
	//      INTEGER collated by typeof() is a representation the DB enforces
	//      exactly. Every existing v7 timestamp is validated in Go (canonical
	//      UTC, real calendar/time) and converted to its exact nanosecond
	//      instant, preserving even sub-millisecond RFC3339Nano values
	//      byte-for-byte. The store was updated to write/read integers.
	//   4. Full state coherence for pending/claimed/succeeded/failed, closing
	//      every combination: a lease (claimed_by + claimed_until) exists
	//      IFF the job is claimed and is cleared in every other state;
	//      completed_at is present IFF the job is succeeded (never set on
	//      pending/claimed/failed); succeeded requires object_ref + feed_ref +
	//      cleared ownership + an empty last_error; failed requires a safe
	//      nonempty last_error with cleared ownership and no completion stamp;
	//      a feed_ref may never exist without its object_ref (the feed points
	//      at an uploaded object). Pending may legitimately retain a safe
	//      last_error and stage refs after a retry, so it is unconstrained.
	//
	// The rebuild is atomic (create clone → validate+convert every v7 row in
	// Go → drop → rename inside the migration transaction): a legitimate v7/fresh
	// row upgrades with its ID and meaning preserved exactly, while any
	// malformed v7 row (bad calendar timestamp, non-canonical timestamp,
	// storage-class or JSON-shape violation) fails the copy and rolls the whole
	// migration back byte-equivalently (version stays 7, no schema objects, no
	// data touched).
	// Version 9 is the durable idempotency store for the constrained internal
	// feed signer (Task 10): one row per stable OperationID, carrying the
	// fixed-size (32-byte BLOB) domain-separated hash of the canonical typed
	// request, a pending/succeeded state, and — only for succeeded rows — the
	// bounded, canonical JSON result. The operation_id primary key and the
	// request-hash equality check make a retried identical request return the
	// stored result and a reused operation ID with different input a hard
	// conflict, atomically, across process restarts. This is pure forward DDL
	// (a new table); it never reads, mutates, or drops any migration 1-8 state,
	// so already-migrated and fresh databases converge on the same schema.
	{
		Version: 8,
		Apply:   installProvisioningOutboxJobInvariantsV8,
	},
	// Version 9 is the durable idempotency store for the constrained internal
	// feed signer (Task 10): one row per stable OperationID, carrying the
	// fixed-size (32-byte BLOB) domain-separated hash of the canonical typed
	// request, a pending/succeeded state, and — only for succeeded rows — the
	// bounded, canonical JSON result. The operation_id primary key and the
	// request-hash equality check make a retried identical request return the
	// stored result and a reused operation ID with different input a hard
	// conflict, atomically, across process restarts. This is pure forward DDL
	// (a new table); it never reads, mutates, or drops any migration 1-8 state,
	// so already-migrated and fresh databases converge on the same schema.
	{
		Version: 9,
		Apply:   installFeedSignerOperationStore,
	},
	// Version 10 REBUILDS the migration-9 feed_signer_operations table with the
	// durable-claims and concurrency invariants Task 10 requires: registry_id +
	// canonical topic (the active repo claim) with a partial UNIQUE index over
	// (registry_id, topic) for state='processing' so exactly one operation per
	// repository feed can ever be advancing; a pending|processing|succeeded
	// vocabulary with exact storage-class guards; an unpredictable claim_token
	// and a future, bounded lease held ONLY in processing; result_json valid
	// only on succeeded rows and only as the bounded exact-field JSON object;
	// and attempts/timestamps. Migration-9 rows (which never carried registry_id
	// or topic) are preserved BYTE-FOR-BYTE in the constrained
	// feed_signer_operations_legacy quarantine table — never stranded, never
	// fabricated — and adopted later by the store only when an incoming request
	// hash matches (see ReserveFeedSignerOperation).
	{
		Version: 10,
		Apply:   installFeedSignerOperationStoreV10,
	},
	// Version 11 hardens the active feed_signer_operations table with the
	// DATABASE-level result-integrity contract: BEFORE INSERT and BEFORE UPDATE
	// triggers reject a malformed succeeded result (must be canonical compact
	// JSON of exactly the three UNIQUE keys {operationID, feed, reference}
	// where operationID == row operation_id, feed is the canonical full-feed
	// wire form, and reference is exactly 64 lowercase-hex), and reject any
	// pending/processing row carrying a non-NULL result. It also ensures the
	// quarantine table exists and atomically hardens any EXISTING active rows
	// (from databases already stamped with the old migration-10 schema that
	// lacked these triggers): a guarded self-update fires the UPDATE trigger
	// per row, so a malformed legacy result aborts the migration and rolls back
	// byte-identically with the version staying 10.
	{
		Version: 11,
		Apply:   installFeedSignerOperationStoreV11,
	},
	// Version 12 replaces the migration-11 result-integrity triggers whose
	// `json(NEW.result_json) = NEW.result_json` proof is insufficient (SQLite's
	// json() minifies but PRESERVES member order and value spelling, so a
	// reordered-members, escaped-key, or escaped-value result could satisfy it)
	// with corrected BYTE-EXACT canonical triggers that require the stored
	// result to equal, byte-for-byte, the single canonical Go layout
	// {"operationID","feed","reference"} in that fixed order. It also atomically
	// re-hardens every EXISTING succeeded row against the corrected contract, so
	// a malformed/noncanonical existing row aborts and rolls back byte-identically
	// with the version staying 11. Fresh installs run 1→11→12.
	{
		Version: 12,
		Apply:   installFeedSignerOperationStoreV12,
	},
	// Version 13 enforces the exact application operation-ID grammar on EVERY
	// active feed_signer_operations row, regardless of state. It installs
	// dedicated operation-ID IDENTITY triggers (BEFORE INSERT + BEFORE UPDATE)
	// that reject any operation_id violating publish.ValidateOperationID
	// (bounded length; only the JSON-safe printable-ASCII set, rejecting the
	// five Go-JSON-escaped bytes `"`, `\`, `<`, `>`, `&`, all controls 0x00-0x1f
	// including NUL, DEL, and every non-ASCII code point >= U+0080), closes the
	// direct-SQL gap that previously left the character-set grammar unchecked
	// for pending/processing rows, and reinstalls the migration-12 byte-exact
	// canonical-result triggers only AFTER the identity triggers so their
	// byte-exact operation_id concatenation is provably grammar-safe. It then
	// ATOMICALLY hardens every existing active row (guarded self-update fires
	// the new UPDATE trigger per row): a schema-admitted old-v12 row whose
	// operation_id violates the grammar aborts the migration and rolls back
	// byte-identically (version stays 12, no schema/trigger/data touched), while
	// every valid v12 row (operation ids are the 64-hex forms ComputeOperationID
	// has always produced) upgrades cleanly. Fresh installs run 1→12→13.
	{
		Version: 13,
		Apply:   installFeedSignerOperationStoreV13,
	},
	// Version 14 replaces migration 13's operation-ID identity triggers — whose
	// Unicode CODEPOINT GLOB guard (`[char(128)-char(0x10ffff)]` ranges over
	// DECODED characters) can admit MALFORMED UTF-8, e.g. a pending row keyed by
	// `CAST(X'F4908080' AS TEXT)` whose decoded character the codepoint ranges
	// classify as allowed — with BYTE-EXACT identity triggers over
	// `hex(CAST(NEW.operation_id AS BLOB))` that accept a value iff EVERY stored
	// byte is an allowed ASCII byte 0x20..0x7e minus the five Go-JSON-escaped
	// bytes `"` `\` `<` `>` `&`, with byte length 1..128. Malformed UTF-8 of all
	// forms (lone continuation bytes, overlong/surrogate/out-of-range sequences,
	// truncated sequences) is rejected by its raw bytes, never decoded, and
	// BLOB/numeric/NULL storage classes are rejected via typeof(). It reinstalls
	// the byte-exact canonical-result triggers AFTER the identity triggers (the
	// migration-13 ordering) and ATOMICALLY hardens every existing active row via
	// a guarded self-update: any schema-admitted old-v13 row whose operation_id
	// (or byte length) violates the byte-exact grammar aborts the migration and
	// rolls back byte-identically (version stays 13, no schema/trigger/data
	// touched). Fresh installs run 1→13→14; every valid v13 database upgrades.
	{
		Version: 14,
		Apply:   installFeedSignerOperationStoreV14,
	},
	// Version 15 creates the durable preflight operation-key binding table
	// (publication_bindings): one permanent row per explicit caller operation
	// key, carrying the registry namespace FK and the fixed-size
	// domain-separated hash of the FIVE typed binding fields (registry,
	// owner, repo, tag, manifest digest). The operation_id primary key makes
	// the atomic insert-or-ignore reserve a single binding winner under
	// concurrency, and the row is never expired, so a reused key with a
	// different payload conflicts forever (cross-request, cross-process).
	// The table is pure forward DDL over a NEW table alongside the migration
	// 9-14 feed-signer store — it never reads, mutates, or drops any
	// migration 1-14 state, and installed its own byte-exact operation-ID
	// identity triggers (the shared migration-14 predicate with distinct
	// trigger names, since SQLite triggers are database-global). Any
	// statement failure aborts the migration transaction atomically: version
	// stays 14 and no schema object is installed (rollback-pinned by tests).
	{
		Version: 15,
		Apply:   installPublicationBindingStore,
	},
	// Version 16 creates the durable logical-publication EXECUTION state
	// machine (publication_states): one row per stable PublicationID,
	// tracking which single per-attempt FeedSigner identity is currently
	// authorized ("active"), when that attempt has been proven dead by an
	// authoritative generation conflict ("replaceable" — the ONLY transition
	// that ever authorizes a fresh replacement attempt), and permanent
	// terminal success ("succeeded"). This closes the round-2 gap where a
	// stable PublicationID that already reached a terminal success could be
	// "retried" after an unrelated later publication overwrote the same tag:
	// the retry would compute a fresh per-attempt identity that authenticates
	// cleanly against the (unrelated) preflight binding and the CURRENT
	// generation, advancing the feed a second time under the SAME logical
	// publication id. The table is pure forward DDL over a NEW table
	// alongside the migration 9-15 feed-signer/binding stores — it never
	// reads, mutates, or drops any migration 1-15 state — and installs its
	// own byte-exact operation-ID identity triggers (the shared migration-14
	// predicate, generalized to apply to BOTH its operation_id and
	// attempt_id columns, with distinct trigger names since SQLite triggers
	// are database-global). Any statement failure aborts the migration
	// transaction atomically: version stays 15 and no schema object is
	// installed.
	//
	// Round 4 / Finding 1: an empty publication_states table is only a SAFE
	// starting point when the pre-v16 database has no history an empty table
	// could fail to protect. validatePublicationStateHistorySafe (called
	// before any DDL, alongside the predecessor-schema check) refuses the
	// migration atomically whenever ANY feed_signer_operations row is already
	// 'succeeded': under v15 that table's operation_id is the per-ATTEMPT
	// identity, never the stable PublicationID, and publication_bindings
	// carries no success/failure state either, so there is no way to
	// recover which (if any) PublicationID such a row belongs to and
	// backfill it as terminal. Serving v16 over such a database unprotected
	// would leave a real pre-v16 success invisible to the new gate, exactly
	// the round-3 gap this table exists to close.
	{
		Version: 16,
		Apply:   installPublicationStateStore,
	},
	// Version 17 closes the writer-fence gap round 6B / Important 2 found:
	// migration 16 validates pre-v16 history once, at upgrade time, but never
	// fenced feed_signer_operations itself, so an already-running process built
	// against the pre-migration-16 code (or any direct-SQL writer) could hold
	// an open handle to the SAME physical database and insert/claim/complete a
	// fresh feed_signer_operations row with zero publication_states
	// involvement — recreating the untracked-terminal-success gap migration 16
	// exists to close, for a newly written attempt rather than pre-v16
	// history. See publication_execution_fence.go for the exact predecessor
	// validation, the fail-closed upgrade-history check, and the two narrow
	// INSERT/claim-authority triggers this migration installs.
	{
		Version: 17,
		Apply:   installFeedSignerPublicationFence,
	},
}

// enableForeignKeys is intentionally NOT emitted inside migrations. SQLite only
// honors this pragma when no transaction is active, so a no-op statement inside
// a transaction is meaningless; foreign-key enforcement is instead enabled
// per-connection via the DSN (_pragma=foreign_keys(1), see withForeignKeys),
// which every pooled connection inherits at open. The atomic table rebuild relied
// on in migration 1 therefore runs with FK enforcement active throughout and is
// proven to behave correctly by TestUpgradeCurrentSchema and
// TestUpgradeRejectsOrphanedLegacyData.

// ApplyMigrations advances db to the latest schema version. Each migration is
// applied in its own transaction; the migration row is committed only after all
// of its statements (and any post-apply foreign_key_check) succeed, so a failed
// migration — including one rejected because the legacy data is orphaned — is
// fully rolled back and never recorded.
func ApplyMigrations(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `create table if not exists schema_migrations (version integer primary key, applied_at text not null)`); err != nil {
		return fmt.Errorf("ensure schema_migrations exists: %w", err)
	}
	current, err := CurrentSchemaVersion(ctx, db)
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if m.Version <= current {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return fmt.Errorf("apply migration %d: %w", m.Version, err)
		}
		current = m.Version
	}
	return nil
}

// applyMigration runs one migration's body atomically inside a transaction and
// records the migration row only after every statement and the post-apply
// validation succeed.
func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	if m.Apply != nil {
		if err := m.Apply(ctx, tx); err != nil {
			return err
		}
	} else {
		for _, stmt := range m.SQL {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("execute statement %q: %w", stmt, err)
			}
		}
	}

	// Post-apply validation: the schema must be fully consistent before the
	// migration is recorded.
	if err := assertNoForeignKeyViolations(ctx, tx); err != nil {
		return fmt.Errorf("post-apply foreign key validation: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `insert into schema_migrations (version, applied_at) values (?, ?)`,
		m.Version, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("record migration %d: %w", m.Version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", m.Version, err)
	}
	return nil
}

// assertNoForeignKeyViolations fails if PRAGMA foreign_key_check reports any
// row, i.e. the schema is not referentially consistent.
func assertNoForeignKeyViolations(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return fmt.Errorf("foreign_key_check reported a constraint violation")
	}
	return rows.Err()
}

// CurrentSchemaVersion returns the highest applied schema version (0 when the
// database has never been migrated).
func CurrentSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var exists int
	if err := db.QueryRowContext(ctx, `select count(*) from sqlite_master where type = 'table' and name = 'schema_migrations'`).Scan(&exists); err != nil {
		return 0, fmt.Errorf("check schema_migrations: %w", err)
	}
	if exists == 0 {
		return 0, nil
	}
	var version int
	if err := db.QueryRowContext(ctx, `select coalesce(max(version), 0) from schema_migrations`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

// withForeignKeys returns dsn with foreign-key enforcement enabled on every
// connection the driver opens for it. It injects the modernc `_pragma` DSN
// option so enforcement is per-connection rather than a one-time pool-wide
// PRAGMA (which SQLite silently ignores inside a transaction).
//
// Unlike a naive append, this SAFELY normalizes: it parses the DSN's query
// string, preserves any existing unrelated pragmas and query parameters, drops
// any conflicting `_pragma=foreign_keys(...)` regardless of its order or value,
// and guarantees an effective `_pragma=foreign_keys(1)` is present. This avoids
// the historical defect where any pre-existing `_pragma=` (e.g.
// busy_timeout) short-circuited the function and left foreign-key enforcement
// silently disabled across every pooled connection. Plain paths, `file:` URIs
// and their existing query parameters are preserved.
//
// A busy_timeout is also guaranteed: an EXPLICIT `_pragma=busy_timeout(...)`
// in the caller's DSN is preserved verbatim, but when none is present an
// effective `_pragma=busy_timeout(5000)` is appended. Concurrent writes (e.g.
// the guarded invite-acceptance transition) then wait up to 5s for the write
// lock instead of failing immediately with SQLITE_BUSY.
func withForeignKeys(dsn string) string {
	// Split off any query string (first '?').
	base, query := dsn, ""
	if i := strings.Index(dsn, "?"); i >= 0 {
		base, query = dsn[:i], dsn[i+1:]
	}

	var kept []string
	hasBusyTimeout := false
	if query != "" {
		for _, param := range strings.Split(query, "&") {
			if param == "" {
				continue
			}
			// Drop any foreign-keys pragma; we always re-add the effective one.
			if isForeignKeyPragmaParam(param) {
				continue
			}
			if isBusyTimeoutPragmaParam(param) {
				hasBusyTimeout = true
			}
			kept = append(kept, param)
		}
	}

	// Append the effective foreign_keys(1) pragma last. Order in the query
	// string doesn't matter for pragma application since our conflicting ones
	// were removed above; keeping it last is deterministic and readable.
	kept = append(kept, "_pragma=foreign_keys(1)")
	// Guarantee a busy timeout only when the caller did not configure one.
	if !hasBusyTimeout {
		kept = append(kept, "_pragma=busy_timeout(5000)")
	}

	return base + "?" + strings.Join(kept, "&")
}

// isBusyTimeoutPragmaParam reports whether a single query parameter is a
// `_pragma=busy_timeout(...)` DSN option.
func isBusyTimeoutPragmaParam(param string) bool {
	const prefix = "_pragma="
	if !strings.HasPrefix(param, prefix) {
		return false
	}
	val := param[len(prefix):]
	name := val
	if i := strings.Index(val, "("); i >= 0 {
		name = val[:i]
	}
	return strings.EqualFold(strings.TrimSpace(name), "busy_timeout")
}

// isForeignKeyPragmaParam reports whether a single query parameter is a
// `_pragma=foreign_keys(...)` DSN option whose value must be normalized away in
// favor of the effective on-state. It matches the pragma NAME (up to the first
// '(' or end), so `_pragma=foreign_keys(0)`, `_pragma=foreign_keys(1)` and
// `_pragma=foreign_keys` are all recognized while unrelated pragmas (e.g.
// `_pragma=busy_timeout(10000)`) are left untouched.
func isForeignKeyPragmaParam(param string) bool {
	const prefix = "_pragma="
	if !strings.HasPrefix(param, prefix) {
		return false
	}
	val := param[len(prefix):]
	name := val
	if i := strings.Index(val, "("); i >= 0 {
		name = val[:i]
	}
	return strings.EqualFold(strings.TrimSpace(name), "foreign_keys")
}

// Table names and the canonical constrained schema (migration version 1).
const (
	tableUsers       = "users"
	tableRegistries  = "registries"
	tableMemberships = "registry_memberships"
	tableInvites     = "registry_invites"
)

// desiredSchema returns DDL statements for the fully constrained clone of every
// control-plane table. Clones reference each other by their *_new names so that
// the final RENAME (with foreign keys ON) rewrites those references to the final
// table names automatically.
func desiredSchema(suffix string) []string {
	return []string{
		fmt.Sprintf(`create table %s%s (
			id integer primary key autoincrement,
			email text not null unique,
			password_hash text not null,
			created_at text not null
		)`, tableUsers, suffix),
		fmt.Sprintf(`create table %s%s (
			id integer primary key autoincrement,
			slug text not null unique,
			host text not null unique,
			ens_name text not null,
			owner_user_id integer not null references %s%s(id),
			feed_owner_address text not null,
			encrypted_feed_private_key text not null,
			default_stamp_batch_id text not null,
			anonymous_pull integer not null,
			created_at text not null
		)`, tableRegistries, suffix, tableUsers, suffix),
		fmt.Sprintf(`create table %s%s (
			id integer primary key autoincrement,
			registry_id integer not null references %s%s(id) on delete cascade,
			user_id integer not null references %s%s(id) on delete cascade,
			role text not null,
			can_pull integer not null,
			can_push integer not null,
			created_at text not null,
			unique(registry_id, user_id)
		)`, tableMemberships, suffix, tableRegistries, suffix, tableUsers, suffix),
		fmt.Sprintf(`create table %s%s (
			id integer primary key autoincrement,
			registry_id integer not null references %s%s(id) on delete cascade,
			email text not null,
			role text not null,
			can_pull integer not null,
			can_push integer not null,
			token_hash text not null unique,
			status text not null,
			expires_at text not null,
			created_at text not null
		)`, tableInvites, suffix, tableRegistries, suffix),
	}
}

// rebuildSchema atomically converts the current schema (whether a fresh
// database, or a legacy pre-versioning database carrying the same columns with
// no foreign keys) into the physically constrained schema, preserving every
// existing row and its ID.
//
// Procedure (all inside the migration transaction, foreign-key enforcement left
// ON — inherited per-connection from the DSN pragma):
//
//  1. Create *_new clones whose foreign keys reference the *_new parents.
//  2. Copy existing rows parent-first. Foreign-key enforcement during the copy
//     is the validation: an orphaned legacy row (e.g. a registry_memberships row
//     whose registry_id has no matching registries row) fails the INSERT and
//     rolls the whole transaction back, so the orphaned legacy data is never
//     deleted, mutated, or silently "repaired", and version 1 is never recorded.
//  3. DROP the legacy tables (children before parents).
//  4. RENAME the *_new clones onto the final table names. With foreign keys ON,
//     SQLite rewrites each clone's *_new references to the final names.
//
// On a fresh database no legacy tables exist, so no rows are copied, nothing is
// dropped, and the clones are simply renamed into place — yielding the identical
// constrained schema.
func rebuildSchema(ctx context.Context, tx *sql.Tx) error {
	const suffix = "_new"

	// 1. Create the fully-constrained clones.
	for _, stmt := range desiredSchema(suffix) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create constrained clone: %w", err)
		}
	}

	// 2. Copy existing rows, parent-first (drop/rename order is the reverse).
	//    Column lists are EXPLICIT on both sides: `insert into <clone>(...) select
	//    <same>(...) from <legacy>`. This is required because legacy databases
	//    upgraded by the historical control-plane migration appended can_pull/
	//    can_push via ALTER TABLE ADD COLUMN, so their PHYSICAL column order
	//    (...,created_at,can_pull,can_push) differs from the clone's desired order
	//    (...,can_pull,can_push,created_at). A positional `insert ... select *`
	//    would silently shift values into the wrong columns; naming the columns
	//    on both sides makes SQLite match by name and every field—and every
	//    ID—survives exactly.
	//    Table existence is checked so fresh databases (no legacy tables) skip
	//    the copy and the drop without harming the outcome.
	type copyDef struct {
		table string
		cols  []string
	}
	copies := []copyDef{
		{tableUsers, []string{"id", "email", "password_hash", "created_at"}},
		{tableRegistries, []string{"id", "slug", "host", "ens_name", "owner_user_id", "feed_owner_address", "encrypted_feed_private_key", "default_stamp_batch_id", "anonymous_pull", "created_at"}},
		{tableMemberships, []string{"id", "registry_id", "user_id", "role", "can_pull", "can_push", "created_at"}},
		{tableInvites, []string{"id", "registry_id", "email", "role", "can_pull", "can_push", "token_hash", "status", "expires_at", "created_at"}},
	}
	for _, c := range copies {
		exists, err := tableExists(ctx, tx, c.table)
		if err != nil {
			return fmt.Errorf("check legacy table %s: %w", c.table, err)
		}
		if !exists {
			continue
		}
		cols := strings.Join(c.cols, ", ")
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`insert into %s%s (%s) select %s from %s`, c.table, suffix, cols, cols, c.table)); err != nil {
			// An orphaned row fails here (FK enforcement during the copy); the
			// deferred rollback discards the clones and never records version 1.
			return fmt.Errorf("copy legacy rows from %s: %w", c.table, err)
		}
	}

	// 3. Drop legacy tables, children before parents.
	for _, t := range []string{tableMemberships, tableInvites, tableRegistries, tableUsers} {
		exists, err := tableExists(ctx, tx, t)
		if err != nil {
			return fmt.Errorf("check legacy table %s: %w", t, err)
		}
		if !exists {
			continue
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`drop table %s`, t)); err != nil {
			return fmt.Errorf("drop legacy table %s: %w", t, err)
		}
	}

	// 4. Rename clones onto the final names (FK ON rewrites *_new references).
	for _, t := range []string{tableUsers, tableRegistries, tableMemberships, tableInvites} {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`alter table %s%s rename to %s`, t, suffix, t)); err != nil {
			return fmt.Errorf("rename %s%s to %s: %w", t, suffix, t, err)
		}
	}

	return nil
}

func tableExists(ctx context.Context, tx *sql.Tx, name string) (bool, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `select count(*) from sqlite_master where type = 'table' and name = ?`, name).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// feedKeyEnvelopeInvariantCond is the boolean predicate shared by the
// schema-level triggers: the three feed-key columns violate the invariant
// when any two disagree on presence, the version is non-positive, or a
// present envelope is structurally invalid — ciphertext shorter than
// feedKeyEnvelopeCiphertextMin bytes (16, the GCM tag alone is a valid
// empty-plaintext envelope; nothing shorter can be authentic) or a nonce
// not exactly feedKeyEnvelopeNonceSize bytes (12; any other length would
// panic gcm.Open). length() on a BLOB is its byte length. The literals 16
// and 12 MUST match the Go constants feedKeyEnvelopeCiphertextMin /
// feedKeyEnvelopeNonceSize in keycrypto.go (pinned by
// TestFeedKeyEnvelopeConstantsMatchAESGCM).
const feedKeyEnvelopeInvariantCond = `(NEW.feed_key_ciphertext IS NULL) != (NEW.feed_key_nonce IS NULL)
	OR (NEW.feed_key_ciphertext IS NULL) != (NEW.feed_key_version IS NULL)
	OR (NEW.feed_key_version IS NOT NULL AND NEW.feed_key_version <= 0)
	OR (NEW.feed_key_ciphertext IS NOT NULL AND length(NEW.feed_key_ciphertext) < 16)
	OR (NEW.feed_key_nonce IS NOT NULL AND length(NEW.feed_key_nonce) != 12)`

// installFeedKeyEnvelopeInvariant validates every existing registries row
// against the feed-key envelope invariant, then installs BEFORE INSERT and
// BEFORE UPDATE triggers enforcing it for all future writes. If any EXISTING
// row violates the invariant the migration fails (the whole transaction is
// rolled back by applyMigration — the schema version stays 2 and no triggers
// are installed) instead of silently accepting or "repairing" inconsistent
// rows. This covers both partial envelopes (columns disagree on presence)
// and complete-but-malformed envelopes (nonce not exactly 12 bytes or
// ciphertext shorter than 16 bytes). The error message names the invariant;
// it carries no key material.
func installFeedKeyEnvelopeInvariant(ctx context.Context, tx *sql.Tx) error {
	var bad int
	if err := tx.QueryRowContext(ctx, `select count(*) from registries where
		(feed_key_ciphertext is null) != (feed_key_nonce is null)
		or (feed_key_ciphertext is null) != (feed_key_version is null)
		or (feed_key_version is not null and feed_key_version <= 0)
		or (feed_key_ciphertext is not null and length(feed_key_ciphertext) < 16)
		or (feed_key_nonce is not null and length(feed_key_nonce) != 12)`).Scan(&bad); err != nil {
		return fmt.Errorf("validate feed key envelope invariant: %w", err)
	}
	if bad != 0 {
		return fmt.Errorf("feed key envelope invariant violated by %d existing rows; refusing to migrate", bad)
	}
	for _, stmt := range []string{
		`create trigger registries_feed_key_complete_insert before insert on registries
			for each row when ` + feedKeyEnvelopeInvariantCond + `
			begin select raise(abort, 'feed key envelope must be all null or complete (12-byte nonce, at least 16-byte ciphertext, positive version)'); end`,
		`create trigger registries_feed_key_complete_update before update on registries
			for each row when ` + feedKeyEnvelopeInvariantCond + `
			begin select raise(abort, 'feed key envelope must be all null or complete (12-byte nonce, at least 16-byte ciphertext, positive version)'); end`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create feed key envelope invariant trigger: %w", err)
		}
	}
	return nil
}

// legacyInviteHashHexLen pins the ONLY historical token_hash encoding: 64
// lowercase hex characters — hex.EncodeToString([]byte(token)) over the
// 32-char canonical token TEXT that the pre-Task-7 control plane stored.
// There is no digest-hex variant.
const legacyInviteHashHexLen = 64

// convertLegacyInviteHash deterministically converts one legacy token_hash
// TEXT value into the canonical 32-byte SHA-256 digest BLOB:
//
//   - The value must be 64 lowercase hex characters decoding to exactly 32
//     bytes, and those bytes MUST be a canonical Task-7 raw token TEXT (32
//     base64url chars decoding to 24 bytes with zero pad bits — strict
//     parse/re-encode). This is the exact historical representation
//     `hex.EncodeToString([]byte(token))`.
//   - The digest is then SHA-256 over that recovered token text — the same
//     digest the acceptance path computes, so pending invites remain
//     acceptable after the upgrade.
//
// Every other value fails: wrong length, non-lowercase hex, decode failure,
// or 32 decoded bytes that do not form a canonical token TEXT (this includes
// hex of a real SHA-256 digest — the pre-Task-7 code never stored a digest,
// so no 32-byte value is a legitimate "digest" representation). No content
// guessing and no alternate format are ever accepted.
func convertLegacyInviteHash(stored string) ([]byte, error) {
	if len(stored) != legacyInviteHashHexLen {
		return nil, fmt.Errorf("invite token hash is not 64 hex characters")
	}
	for i := 0; i < len(stored); i++ {
		c := stored[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return nil, fmt.Errorf("invite token hash is not lowercase hex")
		}
	}
	raw, err := hex.DecodeString(stored)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("invite token hash is not a 32-byte hex value")
	}
	// The decoded bytes ARE the historical token text; they must be a
	// canonical raw token or the value is corrupt.
	if !isCanonicalInviteTokenText(string(raw)) {
		return nil, fmt.Errorf("invite token hash does not decode to a canonical invite token")
	}
	return DigestInviteToken(string(raw)), nil
}

// legacyInviteRow is the fully validated, converted form of one legacy
// registry_invites row, ready to be inserted into the rebuilt table.
type legacyInviteRow struct {
	id                 int64
	registryID         int64
	email              string
	role               string
	canPull            int
	canPush            int
	digest             []byte
	status             string
	acceptedBy         sql.NullInt64
	legacyUnattributed int
	expiresAt          string
	acceptedAt         *string
	revokedAt          *string
	createdAt          string
}

// errInviteDigestSchemaMalformed is the SINGLE stable, data-free sentinel for
// migration 5's mandatory prerequisite: registry_invites is not the genuine
// version-4 invite-digest schema (a view/virtual substitute, a hand-rolled
// lookalike, or a schema missing/weakening any required column, constraint,
// index, or lifecycle trigger). Every malformed-prerequisite failure collapses
// to this one error so callers can test with errors.Is without ever receiving
// schema SQL, trigger definitions, or data that could leak internals.
var errInviteDigestSchemaMalformed = errors.New("controlplane: migration 5 prerequisite failed: registry_invites is not the genuine version-4 invite-digest schema")

// The following DDL constants are the SINGLE SOURCE OF TRUTH for the
// version-4 registry_invites invite-digest schema and its invariant objects.
// Migration 4 INSTALLS from them, so the exact schema they describe is what a
// real version-4 database carries; migration 5 validates a pre-existing
// version-4 database against them via normalizeSQL (quote-aware
// normalization), so a malformed or hand-rolled lookalike — one that merely
// exposes legacy_unattributed, as the previous weak column-only prerequisite
// accepted — is rejected before any trigger DDL runs.
//
// The literal text (keyword case, identifier case, constraint wording)
// MUST match what migration 4 has always written, because that is the exact
// normalized-whitespace fingerprint stored in sqlite_master by every genuine
// version-4 database, pre-fix (8178a82) and corrected alike.

// inviteDigestTableSQLFmt is the canonical CREATE TABLE for the invite-digest
// schema. %s is the table name: migration 4 builds its "_new" rebuild clone,
// migration 5 validates the final "registry_invites". SQLite writes the stored
// form of a RENAMEd table with the name double-quoted, so the table-name token
// is normalized away from the comparison.
const inviteDigestTableSQLFmt = `CREATE TABLE %s (
	id integer primary key autoincrement,
	registry_id integer not null references registries(id) on delete cascade,
	email text not null,
	role text not null,
	can_pull integer not null,
	can_push integer not null,
	token_digest blob not null unique check (typeof(token_digest) = 'blob' and length(token_digest) = 32),
	status text not null check (status in ('pending','accepted','revoked')),
	accepted_by_user_id integer references users(id),
	legacy_unattributed integer not null default 0 check (legacy_unattributed in (0,1)),
	expires_at text not null,
	accepted_at text,
	revoked_at text,
	created_at text not null,
	check (can_pull = 1 or can_push = 1),
	check ((status = 'revoked') = (revoked_at is not null)),
	check (status <> 'accepted' or accepted_by_user_id is not null or legacy_unattributed = 1),
	check (accepted_at is null or status = 'accepted')
)`

// inviteBornPendingTriggerSQL forces every insert to a pending, attributed
// state: status must be 'pending' and legacy_unattributed must be 0 on insert.
const inviteBornPendingTriggerSQL = `CREATE TRIGGER registry_invites_born_pending before insert on registry_invites
	for each row when NEW.status != 'pending' or NEW.legacy_unattributed != 0
	begin select raise(abort, 'invites must be created pending and attributed'); end`

// inviteTerminalStatusTriggerSQL makes a non-pending (accepted/revoked) status
// immutable: once a row leaves pending, its status can never change.
const inviteTerminalStatusTriggerSQL = `CREATE TRIGGER registry_invites_terminal_status before update of status on registry_invites
	for each row when OLD.status != 'pending' and NEW.status != OLD.status
	begin select raise(abort, 'invite status is terminal and cannot be changed'); end`

// inviteNoUnattributedAcceptanceTriggerSQL forbids transitioning to accepted
// without recording an accepting user (legacy_unattributed backfill is the
// migration-only exception enforced by the CHECK, not by acceptance).
const inviteNoUnattributedAcceptanceTriggerSQL = `CREATE TRIGGER registry_invites_no_unattributed_acceptance before update of status on registry_invites
	for each row when NEW.status = 'accepted' and NEW.accepted_by_user_id is null
	begin select raise(abort, 'acceptance requires an attributed accepter'); end`

// inviteLegacyFlagLockedTriggerSQL forbids ordinary SQL from SETTING the
// legacy_unattributed flag to 1 (it is migration-only state).
const inviteLegacyFlagLockedTriggerSQL = `CREATE TRIGGER registry_invites_legacy_flag_locked before update of legacy_unattributed on registry_invites
	for each row when NEW.legacy_unattributed != OLD.legacy_unattributed and NEW.legacy_unattributed = 1
	begin select raise(abort, 'legacy_unattributed is migration-only state and cannot be set'); end`

// inviteRegistryStatusIndexSQL is the supporting index for the invite listing
// and status queries.
const inviteRegistryStatusIndexSQL = `CREATE INDEX idx_registry_invites_registry_status on registry_invites(registry_id, status)`

// legacyAttributionImmutableTriggerSQL is the SINGLE SOURCE OF TRUTH for the
// BEFORE UPDATE trigger that makes legacy_unattributed invite rows immutable:
// EVERY update to a row whose OLD.legacy_unattributed = 1 is aborted — clearing
// the flag, assigning an accepter, changing status/timestamps, combined
// rewrites, and benign edits alike — so ordinary SQL cannot turn a frozen
// historical record into an attributed acceptance. It is installed by BOTH
// migration 4 (corrected, for fresh/v0-v3 upgrades) and the forward-only
// repair migration 5 (the authoritative bridge for every version-4 schema);
// sharing the constant guarantees the two can never drift apart.
const legacyAttributionImmutableTriggerSQL = `create trigger registry_invites_legacy_attribution_immutable before update on registry_invites
	for each row when OLD.legacy_unattributed = 1
	begin select raise(abort, 'legacy_unattributed invites are immutable historical records'); end`

// errSQLFingerprintLexical is the internal sentinel for a SQL fingerprint that
// normalizeSQL refuses to normalize: a -- or /* */ comment, an unterminated
// quoted literal/identifier/comment, or a NUL / non-whitespace control anomaly.
// Every fingerprint call site translates it into the single data-free
// errInviteDigestSchemaMalformed sentinel, so a lexical reject (like any other
// mismatch) never echoes schema SQL, trigger definitions, or data.
var errSQLFingerprintLexical = errors.New("controlplane: SQL fingerprint contains a comment, unterminated quote, or control anomaly")

// isFingerprintWhitespace reports whether b is an insignificant-whitespace byte
// that normalizeSQL collapses in structural (outside-literal) position.
func isFingerprintWhitespace(b byte) bool {
	return b == ' ' || b == '	' || b == '\n' || b == '\r' || b == '\f' || b == '\v'
}

// isFingerprintControlAnomaly reports whether b is a NUL byte or a
// non-whitespace control character — a lexical anomaly normalizeSQL rejects.
// Actual whitespace control bytes (tab/newline/CR etc.) are NOT anomalies and
// are preserved inside quoted literals/identifiers.
func isFingerprintControlAnomaly(b byte) bool {
	return b == 0 || (b < 0x20 && !isFingerprintWhitespace(b)) || b == 0x7f
}

// writeFingerprintSpace flushes a single collapsed space when pending.
func writeFingerprintSpace(b *strings.Builder, pending *bool) {
	if *pending {
		b.WriteByte(' ')
		*pending = false
	}
}

// normalizeSQL is the quote-aware, fail-closed canonical form used for every
// stored-schema fingerprint comparison (the CREATE TABLE, the supporting index,
// and each lifecycle trigger). Unlike blindly collapsing all whitespace, it is
// a small deterministic lexical scanner that:
//
//   - collapses every run of insignificant whitespace OUTSIDE any quote to a
//     single space (tabs/newlines/CR folded exactly like spaces) and trims the
//     ends — the ONLY layout genuine storage forms may differ in;
//   - preserves EVERY byte inside a single-quoted string literal, verbatim
//     including its delimiters and its doubled ” escapes, so the literal
//     contents are semantically significant ('a  b' never equals 'a b');
//   - preserves every interior byte of a quoted IDENTIFIER — double-quoted
//     (with doubled "" escapes), backtick (with doubled “ escapes, matching
//     SQLite's acceptance), and bracket [ ... ] (closed by the first `]`) —
//     while dropping ONLY the insignificant quote delimiters. This is the
//     explicit structural handling for the known SQLite RENAME-writing of the
//     table name double-quoted: a renamed table stores `CREATE TABLE
//     "registry_invites"`, a directly-created one stores `CREATE TABLE
//     registry_invites`, and both normalize to the same identifier token —
//     WITHOUT any global text replacement that could alter a literal;
//   - REJECTS (returns an error) -- and /* */ comments anywhere outside a
//     literal, so project DDL — which carries none (SQLite strips them from
//     table storage, and triggers never use them) — can never compare equal to
//     a commented or spoofed lookalike; and
//   - REJECTS (returns an error) unterminated quotes/comments and NUL or
//     non-whitespace control anomalies.
//
// It does NOT lowercase keywords, identifiers, or literals — keyword/identifier
// case remains strict — and it does not alter the bytes of any string literal.
func normalizeSQL(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))
	pending := false
	appendOuter := func(c byte) {
		writeFingerprintSpace(&b, &pending)
		b.WriteByte(c)
	}
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case isFingerprintWhitespace(c):
			pending = true
			i++
		case isFingerprintControlAnomaly(c):
			return "", errSQLFingerprintLexical
		case c == '\'':
			writeFingerprintSpace(&b, &pending)
			start := i
			i++
			closed := false
			for i < n {
				if isFingerprintControlAnomaly(s[i]) {
					return "", errSQLFingerprintLexical
				}
				if s[i] == '\'' {
					if i+1 < n && s[i+1] == '\'' {
						i += 2 // doubled '' escape stays inside the literal
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return "", errSQLFingerprintLexical // unterminated string literal
			}
			b.WriteString(s[start:i]) // verbatim, delimiters and all
		case c == '"':
			// SQLite writes a RENAMEd table's name double-quoted; quoting an
			// identifier is insignificant, so drop the delimiters but preserve
			// every interior byte (including "" escapes and inner whitespace).
			writeFingerprintSpace(&b, &pending)
			i++
			closed := false
			for i < n {
				if isFingerprintControlAnomaly(s[i]) {
					return "", errSQLFingerprintLexical
				}
				if s[i] == '"' {
					if i+1 < n && s[i+1] == '"' {
						b.WriteByte('"')
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				b.WriteByte(s[i])
				i++
			}
			if !closed {
				return "", errSQLFingerprintLexical // unterminated quoted identifier
			}
		case c == '`':
			writeFingerprintSpace(&b, &pending)
			i++
			closed := false
			for i < n {
				if isFingerprintControlAnomaly(s[i]) {
					return "", errSQLFingerprintLexical
				}
				if s[i] == '`' {
					if i+1 < n && s[i+1] == '`' {
						b.WriteByte('`')
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				b.WriteByte(s[i])
				i++
			}
			if !closed {
				return "", errSQLFingerprintLexical // unterminated backtick identifier
			}
		case c == '[':
			writeFingerprintSpace(&b, &pending)
			i++
			closed := false
			for i < n {
				if isFingerprintControlAnomaly(s[i]) {
					return "", errSQLFingerprintLexical
				}
				if s[i] == ']' {
					i++
					closed = true
					break
				}
				b.WriteByte(s[i])
				i++
			}
			if !closed {
				return "", errSQLFingerprintLexical // unterminated bracket identifier
			}
		case c == '-':
			if i+1 < n && s[i+1] == '-' {
				return "", errSQLFingerprintLexical // -- comment rejected
			}
			appendOuter('-')
			i++
		case c == '/':
			if i+1 < n && s[i+1] == '*' {
				return "", errSQLFingerprintLexical // /* comment rejected
			}
			appendOuter('/')
			i++
		default:
			appendOuter(c)
			i++
		}
	}
	return strings.TrimSpace(b.String()), nil
}

// storedObjectSQL reads the stored sqlite_schema (sql) text for one named
// object. It reports (false, nil) when the object does not exist and an error
// when the read fails.
func storedObjectSQL(ctx context.Context, tx *sql.Tx, typ, name string) (string, bool, error) {
	var stored string
	if err := tx.QueryRowContext(ctx, `select sql from sqlite_master where type = ? and name = ?`, typ, name).Scan(&stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return stored, true, nil
}

// inviteForeignKey describes one foreign-key clause of a table.
type inviteForeignKey struct {
	table, fromCol, toCol, onUpdate, onDelete string
}

// readInviteForeignKeys returns each foreign key of a table keyed by its local
// "from" column.
func readInviteForeignKeys(ctx context.Context, tx *sql.Tx, tbl string) (map[string]inviteForeignKey, error) {
	rows, err := tx.QueryContext(ctx, `select "table", "from", "to", on_update, on_delete from pragma_foreign_key_list(?)`, tbl)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]inviteForeignKey)
	for rows.Next() {
		var f inviteForeignKey
		if err := rows.Scan(&f.table, &f.fromCol, &f.toCol, &f.onUpdate, &f.onDelete); err != nil {
			return nil, err
		}
		out[f.fromCol] = f
	}
	return out, rows.Err()
}

// readIndexColumns returns the ordered columns of a named index, or (nil, nil)
// when the index does not exist.
func readIndexColumns(ctx context.Context, tx *sql.Tx, tbl, indexName string) ([]string, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `select count(*) from pragma_index_list(?) where name = ?`, tbl, indexName).Scan(&n); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, `select "name" from pragma_index_info(?) order by seqno`, indexName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		cols = append(cols, c)
	}
	return cols, rows.Err()
}

// readAutoUniqueIndexColumns returns, for each unique index created by a
// UNIQUE constraint (origin 'u', e.g. token_digest blob not null unique), the
// ordered list of its columns.
func readAutoUniqueIndexColumns(ctx context.Context, tx *sql.Tx, tbl string) ([][]string, error) {
	rows, err := tx.QueryContext(ctx, `select name from pragma_index_list(?) where "unique" = 1 and origin = 'u'`, tbl)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([][]string, 0, len(names))
	for _, n := range names {
		cols, err := readIndexColumns(ctx, tx, tbl, n)
		if err != nil {
			return nil, err
		}
		out = append(out, cols)
	}
	return out, nil
}

// equalStringSlice reports whether two ordered string slices are equal.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// installInviteLegacyAttributionImmutability is migration 5's body: it
// guarantees the immutable legacy-unattributed-history trigger exists on a
// version-4 schema — the delivery a database that applied the PRE-FIX
// migration 4 (head 8178a82, before the trigger was added by editing that
// migration) never received, because it records version 4 and skips the
// corrected code.
//
//  1. Prerequisite: run validateInviteV4DigestSchema — registry_invites must be
//     a genuine, COMPLETE version-4 invite-digest schema (a real table with the
//     exact digest columns/CHECKs/uniqueness, the two exact foreign keys, the
//     supporting index, and the four lifecycle triggers), NOT merely an object
//     exposing legacy_unattributed. Any malformed or hand-rolled lookalike
//     fails here with the single data-free sentinel, BEFORE any DDL, so the
//     migration rolls back with version 4 still recorded and no data touched.
//  2. Drop any stale same-name trigger: the corrected migration 4 already
//     installs one, the pre-fix v4 has none — DROP IF EXISTS is a no-op or
//     removes the old one either way, which keeps the migration idempotent.
//  3. Create the authoritative BEFORE UPDATE trigger from the shared
//     constant, so v4 and v5 can never drift.
//
// The whole body runs inside the migration transaction (applyMigration): a
// failed create rolls back the drop and never records version 5.
func installInviteLegacyAttributionImmutability(ctx context.Context, tx *sql.Tx) error {
	if err := validateInviteV4DigestSchema(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `drop trigger if exists registry_invites_legacy_attribution_immutable`); err != nil {
		return fmt.Errorf("migration 5: drop stale legacy immutability trigger: %w", err)
	}
	if _, err := tx.ExecContext(ctx, legacyAttributionImmutableTriggerSQL); err != nil {
		return fmt.Errorf("migration 5: install legacy immutability trigger: %w", err)
	}
	return nil
}

// installProvisioningOutboxSchema installs migration 6: an explicit registry
// provisioning vocabulary plus the transactional publication outbox table.
// It is a pure forward extension over migrations 1-5 (registries is the only
// table touched, by ADD COLUMN with a default; nothing is read, mutated, or
// dropped), so already-migrated and fresh databases converge identically.
// Pre-v6 registries — which the older control plane published inline — default
// to 'ready'; fresh registrations are born 'provisioning' and only reach
// ready/failed via verified reconciliation. Because SQLite's ALTER TABLE ADD
// COLUMN cannot carry a CHECK, the provisioning vocabulary is enforced by a
// BEFORE UPDATE guard trigger (the same pattern migrations 3/4 use to close
// the direct-SQL gap), while the new jobs table carries its KIND/STATE CHECKs
// and (registry_id, kind) uniqueness inline in its CREATE TABLE. Both logical
// bootstrap jobs are deterministic and unduplicable per (registry, kind).
func installProvisioningOutboxSchema(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `alter table registries add column provisioning_state text not null default 'ready'`); err != nil {
		return fmt.Errorf("migration 6: add provisioning_state column: %w", err)
	}
	const guard = `create trigger registries_provisioning_state_guard before update of provisioning_state on registries
		for each row when new.provisioning_state not in ('provisioning','ready','failed')
		begin select raise(abort, 'invalid registry provisioning_state'); end`
	if _, err := tx.ExecContext(ctx, guard); err != nil {
		return fmt.Errorf("migration 6: install provisioning state guard trigger: %w", err)
	}
	const jobsTable = `create table registry_publication_jobs (
		id integer primary key autoincrement,
		registry_id integer not null references registries(id) on delete cascade,
		kind text not null check (kind in ('auth','stamp')),
		state text not null check (state in ('pending','claimed','succeeded','failed')),
		payload_json text not null,
		object_ref text not null default '',
		feed_ref text not null default '',
		attempts integer not null default 0,
		next_attempt_at text not null,
		claimed_until text,
		claimed_by text not null default '',
		last_error text not null default '',
		created_at text not null,
		completed_at text,
		unique (registry_id, kind)
	)`
	if _, err := tx.ExecContext(ctx, jobsTable); err != nil {
		return fmt.Errorf("migration 6: create registry_publication_jobs table: %w", err)
	}
	return nil
}

// RFC3339 UTC timestamps are stored as text in the control plane. The
// hardening CHECK uses a GLOB so the column is at least structurally a
// 'YYYY-MM-DDTHH:MM:SS...' RFC3339 value (the Z suffix and optional fractional
// seconds are allowed beyond the indicated positions). GLOB (not LIKE) is used
// because modernc.org/sqlite's LIKE does not honour '[0-9]' character ranges.
const rfc3339Glob = `[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]*`

// hardenedPublicationJobsTableSQL is the SINGLE SOURCE OF TRUTH for the
// version-7 registry_publication_jobs schema: the v6 columns plus hardened DB
// invariants that close the direct-SQL gap. %s is the table name (the "_new"
// rebuild clone in the migration).
const hardenedPublicationJobsTableSQL = `CREATE TABLE %s (
	id integer primary key autoincrement,
	registry_id integer not null references registries(id) on delete cascade,
	kind text not null check (kind in ('auth','stamp')),
	state text not null check (state in ('pending','claimed','succeeded','failed')),
	payload_json text not null
		check (
			json_valid(payload_json) = 1
			and json_type(payload_json) = 'object'
			and length(payload_json) between 2 and 32768
			and (
				(kind = 'auth'
					and json_extract(payload_json, '$.version') is not null
					and json_extract(payload_json, '$.defaultAccess') is not null)
				or
				(kind = 'stamp'
					and json_extract(payload_json, '$.version') is not null
					and json_extract(payload_json, '$.defaultPolicy.batchID') is not null)
			)
		),
	object_ref text not null default '' check (length(object_ref) <= 128),
	feed_ref text not null default '' check (length(feed_ref) <= 128),
	attempts integer not null default 0 check (attempts >= 0 and attempts <= 1024),
	next_attempt_at text not null check (next_attempt_at glob '` + rfc3339Glob + `'),
	claimed_until text check (claimed_until is null or claimed_until glob '` + rfc3339Glob + `'),
	claimed_by text not null default '' check (length(claimed_by) <= 64),
	last_error text not null default '' check (length(last_error) <= 512),
	created_at text not null check (created_at glob '` + rfc3339Glob + `'),
	completed_at text check (completed_at is null or completed_at glob '` + rfc3339Glob + `'),
	unique (registry_id, kind),
	-- Ownership/lease coherence: a job owns a lease (claimed_by set together
	-- with claimed_until) IFF it is claimed; every other state has both cleared.
	check ((state = 'claimed') = (claimed_by <> '' and claimed_until is not null)),
	-- A succeeded job must carry its verified object_ref, feed_ref, and a
	-- completion stamp.
	check (state <> 'succeeded' or (object_ref <> '' and feed_ref <> '' and completed_at is not null))
)`

// provisioningStateInsertGuardTriggerSQL is the symmetric counterpart of
// migration 6's BEFORE UPDATE guard: it enforces the provisioning_state
// vocabulary on INSERT too, so direct SQL cannot insert a bogus value.
const provisioningStateInsertGuardTriggerSQL = `create trigger registries_provisioning_state_guard_insert before insert on registries
	for each row when new.provisioning_state not in ('provisioning','ready','failed')
	begin select raise(abort, 'invalid registry provisioning_state'); end`

// installProvisioningOutboxSchemaHarden is migration 7's body. It (a) installs
// the BEFORE INSERT provisioning_state guard (migration 6 only guarded UPDATE),
// and (b) atomically rebuilds registry_publication_jobs around the hardened
// invariant schema. Any existing v6 row that violates a hardened invariant is
// REJECTED by the copy's CHECKs, rolling the whole migration back (version
// stays 6, no triggers, no data touched); every legitimate in-flight or
// terminal v6 row migrates byte-for-byte with its ID intact.
func installProvisioningOutboxSchemaHarden(ctx context.Context, tx *sql.Tx) error {
	// 1. BEFORE INSERT provisioning_state guard (closes the INSERT direct-SQL
	// gap; migration 6's UPDATE guard remains authoritative for updates).
	if _, err := tx.ExecContext(ctx, provisioningStateInsertGuardTriggerSQL); err != nil {
		return fmt.Errorf("migration 7: install provisioning state insert guard trigger: %w", err)
	}

	// 2. Create the hardened *_new clone.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(hardenedPublicationJobsTableSQL, "registry_publication_jobs_new")); err != nil {
		return fmt.Errorf("migration 7: create hardened jobs clone: %w", err)
	}

	// 3. Copy every existing row by explicit column name (preserves the
	// physical order-independence guarantee used elsewhere). If any existing
	// row violates a hardened invariant (e.g. a malformed payload or an
	// incoherent state/lease), the INSERT fails here and the whole migration
	// rolls back with version 6 recorded and data untouched.
	if _, err := tx.ExecContext(ctx, `insert into registry_publication_jobs_new
		(id, registry_id, kind, state, payload_json, object_ref, feed_ref,
		 attempts, next_attempt_at, claimed_until, claimed_by, last_error, created_at, completed_at)
		select id, registry_id, kind, state, payload_json, object_ref, feed_ref,
		 attempts, next_attempt_at, claimed_until, claimed_by, last_error, created_at, completed_at
		from registry_publication_jobs`); err != nil {
		return fmt.Errorf("migration 7: copy jobs into hardened schema: %w", err)
	}

	// 4. Drop the v6 table and rename the hardened clone into place. The
	// registry_id FK and the (registry_id, kind) uniqueness are carried over; a
	// concurrent foreign_key_check ensures nothing is orphaned.
	if _, err := tx.ExecContext(ctx, `drop table registry_publication_jobs`); err != nil {
		return fmt.Errorf("migration 7: drop v6 jobs table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `alter table registry_publication_jobs_new rename to registry_publication_jobs`); err != nil {
		return fmt.Errorf("migration 7: rename hardened jobs table: %w", err)
	}
	return nil
}

// hardenedV8PublicationJobsTableSQL is the SINGLE SOURCE OF TRUTH for the
// version-8 registry_publication_jobs schema. It hardens migration 7 by adding
// exact storage-class (typeof) guards on every column, requiring the exact
// production policy-JSON shape (json_type guards BEFORE value comparison, so a
// type trick can never satisfy an integer/text check), moving timestamps to
// exact INTEGER Unix NANOSECONDS, and enforcing full state coherence. %s is
// the table name (the "_new" rebuild clone in the migration).
const hardenedV8PublicationJobsTableSQL = `CREATE TABLE %s (
	id integer primary key autoincrement,
	registry_id integer not null
		check (typeof(registry_id) = 'integer' and registry_id > 0)
		references registries(id) on delete cascade,
	kind text not null check (typeof(kind) = 'text' and kind in ('auth','stamp')),
	state text not null check (typeof(state) = 'text' and state in ('pending','claimed','succeeded','failed')),
	payload_json text not null
		check (
			typeof(payload_json) = 'text'
			and length(payload_json) between 2 and 32768
			and json_valid(payload_json) = 1
			and json_type(payload_json) = 'object'
			and (
				(kind = 'auth'
					and json_type(payload_json, '$.version') IS 'integer'
					and json_extract(payload_json, '$.version') = 1
					and json_type(payload_json, '$.defaultAccess') IS 'text'
					and json_extract(payload_json, '$.defaultAccess') = 'deny'
					and json_type(payload_json, '$.defaultRepo') IS 'object'
					and json_type(payload_json, '$.defaultRepo.pull') IS 'array'
					and json_type(payload_json, '$.defaultRepo.push') IS 'array'
					and json_type(payload_json, '$.repos') IS 'object')
				or
				(kind = 'stamp'
					and json_type(payload_json, '$.version') IS 'integer'
					and json_extract(payload_json, '$.version') = 1
					and json_type(payload_json, '$.defaultPolicy') IS 'object'
					and json_type(payload_json, '$.defaultPolicy.batchID') IS 'text'
					and length(json_extract(payload_json, '$.defaultPolicy.batchID')) between 1 and 128
					and json_type(payload_json, '$.defaultPolicy.allowPushFor') IS 'array'
					and json_type(payload_json, '$.repos') IS 'object')
			)
		),
	object_ref text not null default '' check (typeof(object_ref) = 'text' and length(object_ref) <= 128),
	feed_ref text not null default '' check (typeof(feed_ref) = 'text' and length(feed_ref) <= 128),
	attempts integer not null default 0 check (typeof(attempts) = 'integer' and attempts >= 0 and attempts <= 1024),
	next_attempt_at integer not null check (typeof(next_attempt_at) = 'integer'),
	claimed_until integer check (claimed_until is null or typeof(claimed_until) = 'integer'),
	claimed_by text not null default '' check (typeof(claimed_by) = 'text' and length(claimed_by) <= 64),
	last_error text not null default '' check (typeof(last_error) = 'text' and length(last_error) <= 512),
	created_at integer not null check (typeof(created_at) = 'integer'),
	completed_at integer check (completed_at is null or typeof(completed_at) = 'integer'),
	unique (registry_id, kind),
	-- Ownership/lease coherence: only a CLAIMED job holds a lease (claimed_by
	-- together with claimed_until); every other state has both cleared. A
	-- NULL claimed_until never satisfies the comparison via 3VL because the
	-- typeof guard above rejects a non-integer/NULL lease.
	check ((state = 'claimed') = (claimed_by <> '' and claimed_until is not null)),
	-- Completed-at coherence: completed_at is present IFF the job is succeeded
	-- (an exact logical equivalence via 3VL-safe equals, so every non-succeeded
	-- state — pending, claimed, failed — must have completed_at NULL on BOTH
	-- INSERT and UPDATE, and a succeeded job MUST carry it).
	check ((state = 'succeeded') = (completed_at is not null)),
	-- Succeeded is terminal and verified: it MUST carry object_ref AND
	-- feed_ref, cleared ownership, and an empty last_error (the claim cleared
	-- it and nothing set it before completion). completed_at is already forced
	-- non-null by the IFF check above.
	check (state <> 'succeeded'
		or (object_ref <> '' and feed_ref <> ''
			and claimed_by = '' and claimed_until is null and last_error = '')),
	-- Failed is terminal: a safe nonempty last_error with cleared ownership
	-- and NO completion stamp (completed_at null is already required by the IFF
	-- check, so it is not repeated here).
	check (state <> 'failed'
		or (last_error <> '' and claimed_by = '' and claimed_until is null)),
	-- A feed_ref (published feed) may only exist when its object_ref does.
	check (feed_ref = '' or object_ref <> '')
)`

// installProvisioningOutboxJobInvariantsV8 is migration 8's body. It
// atomically rebuilds registry_publication_jobs around the hardened v8 schema,
// validating and converting every existing v7 row in Go: each RFC3339/RFC3339Nano
// journal timestamp must be canonical UTC with real calendar validity before it
// is converted (byte-for-byte instant-preserving to the exact nanosecond) to its
// INTEGER Unix-nanosecond form, and the new table's CHECKs independently reject
// any storage-class, JSON-shape, or coherence violation. A malformed v7 row
// fails the copy and rolls the whole migration back (version stays 7, no schema
// objects, no data touched); every legitimate v7/fresh row upgrades with its ID
// and meaning preserved exactly.
func installProvisioningOutboxJobInvariantsV8(ctx context.Context, tx *sql.Tx) error {
	const clone = "registry_publication_jobs_new"

	if _, err := tx.ExecContext(ctx, fmt.Sprintf(hardenedV8PublicationJobsTableSQL, clone)); err != nil {
		return fmt.Errorf("migration 8: create hardened jobs clone: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `select id, registry_id, kind, state, payload_json, object_ref, feed_ref,
		attempts, next_attempt_at, claimed_until, claimed_by, last_error, created_at, completed_at
		from registry_publication_jobs order by id asc`)
	if err != nil {
		return fmt.Errorf("migration 8: enumerate v7 jobs: %w", err)
	}
	for rows.Next() {
		var (
			id, registryID, attempts        int64
			kind, state, objectRef, feedRef string
			claimedBy, lastError            string
			payload                         []byte
			nextAttempt, createdAt          string
			claimedUntil, completedAt       sql.NullString
		)
		if err := rows.Scan(&id, &registryID, &kind, &state, &payload, &objectRef, &feedRef,
			&attempts, &nextAttempt, &claimedUntil, &claimedBy, &lastError, &createdAt, &completedAt); err != nil {
			rows.Close()
			return fmt.Errorf("migration 8: read v7 job %d: %w", id, err)
		}
		nextNanos, err := parseCanonicalUTCNanos(nextAttempt)
		if err != nil {
			rows.Close()
			return fmt.Errorf("migration 8: job %d next_attempt_at: %w", id, err)
		}
		createdNanos, err := parseCanonicalUTCNanos(createdAt)
		if err != nil {
			rows.Close()
			return fmt.Errorf("migration 8: job %d created_at: %w", id, err)
		}
		var claimedNanos, completedNanos sql.NullInt64
		if claimedUntil.Valid {
			ns, err := parseCanonicalUTCNanos(claimedUntil.String)
			if err != nil {
				rows.Close()
				return fmt.Errorf("migration 8: job %d claimed_until: %w", id, err)
			}
			claimedNanos = sql.NullInt64{Int64: ns, Valid: true}
		}
		if completedAt.Valid {
			ns, err := parseCanonicalUTCNanos(completedAt.String)
			if err != nil {
				rows.Close()
				return fmt.Errorf("migration 8: job %d completed_at: %w", id, err)
			}
			completedNanos = sql.NullInt64{Int64: ns, Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `insert into registry_publication_jobs_new
			(id, registry_id, kind, state, payload_json, object_ref, feed_ref,
			 attempts, next_attempt_at, claimed_until, claimed_by, last_error, created_at, completed_at)
			values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, registryID, kind, state, string(payload), objectRef, feedRef,
			attempts, nextNanos, claimedNanos, claimedBy, lastError, createdNanos, completedNanos); err != nil {
			rows.Close()
			return fmt.Errorf("migration 8: copy job %d into hardened schema: %w", id, err)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("migration 8: iterate v7 jobs: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `drop table registry_publication_jobs`); err != nil {
		return fmt.Errorf("migration 8: drop v7 jobs table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `alter table registry_publication_jobs_new rename to registry_publication_jobs`); err != nil {
		return fmt.Errorf("migration 8: rename hardened jobs table: %w", err)
	}
	return nil
}

// validateInviteV4DigestSchema is the hardened migration-5 prerequisite. It
// verifies that registry_invites is a genuine, COMPLETE version-4 invite-digest
// schema BEFORE any trigger DDL runs, so a malformed or hand-rolled lookalike
// that merely exposes legacy_unattributed (what the previous weak column-only
// check accepted) is rejected. It validates:
//
//  1. registry_invites is a real SQLite TABLE, never a view, index, or virtual
//     substitute — pragma_table_info silently resolves view and virtual-table
//     columns, so the sqlite_master object type must be examined first.
//  2. The stored CREATE TABLE is the exact migration-4 schema fingerprint: every
//     required column (id, registry_id, email, role, can_pull, can_push,
//     token_digest, status, expires_at, created_at, accepted_by_user_id,
//     accepted_at, revoked_at, legacy_unattributed) with its declared type,
//     NOT NULL / nullability, PK, default, token_digest uniqueness, and EVERY
//     CHECK (strict 32-byte BLOB digest, status domain, permission, and
//     accepted/revoked/legacy attribution relationships) — compared by normalizeSQL
//     (insignificant-whitespace normalization only) against the single shared
//     DDL constant, so columns/CHECKs/uniqueness cannot be dropped, weakened,
//     or spoofed by whitespace or comment placement.
//  3. The foreign keys are exactly registry_id→registries(id) ON DELETE CASCADE
//     and accepted_by_user_id→users(id) (the precise migration-4 contract), so
//     a missing or wrong FK fails.
//  4. token_digest is backed by a REAL unique index covering exactly
//     [token_digest], and the supporting (registry_id, status) index exists —
//     verified both by stored-SQL fold comparison and PRAGMA columns.
//  5. The four pre-existing lifecycle triggers (born-pending, terminal-status,
//     no-unattributed-acceptance, legacy-flag-locked) exist with their exact
//     guarding semantics (fold-compared against the shared constants), so a
//     missing or weakened trigger fails here. Migration 5 MAY repair ONLY the
//     immutable-attribution trigger it owns; it may repair none of these, so
//     any defect in them must fail at v4.
//
// Every malformed case collapses to the single data-free sentinel
// errInviteDigestSchemaMalformed — never a leaked schema/trigger/SQL detail —
// and always BEFORE the DROP/CREATE. All queries run inside the migration
// transaction, so a failure rolls back with version 4 still recorded and no
// data or trigger changed.
func validateInviteV4DigestSchema(ctx context.Context, tx *sql.Tx) error {
	malformed := func() error { return errInviteDigestSchemaMalformed }

	// 1. Must be a real TABLE, not a view or virtual substitute.
	var objType string
	if err := tx.QueryRowContext(ctx, `select type from sqlite_master where name = 'registry_invites'`).Scan(&objType); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return malformed()
		}
		return fmt.Errorf("migration 5 prerequisite: read registry_invites object type: %w", err)
	}
	if objType != "table" {
		return malformed()
	}

	// 2. Exact CREATE TABLE fingerprint (columns, types, nullability, PK,
	// default, UNIQUE, all CHECKs). SQLite writes the stored form of a
	// RENAMEd table (migration 4's _new→final rename) with the table name in
	// double quotes; a directly-created table stores it unquoted. The quote
	// around the table-name token (the only quoted identifier migration 4
	// emits) is normalized away on BOTH sides before comparing, so the two
	// genuine storage forms are byte-equivalent and a lookalike cannot sneak a
	// difference past by quoted-vs-unquoted naming alone.
	tblSQL, ok, err := storedObjectSQL(ctx, tx, "table", "registry_invites")
	if err != nil {
		return fmt.Errorf("migration 5 prerequisite: read registry_invites DDL: %w", err)
	}
	if !ok {
		return malformed()
	}
	wantTbl := fmt.Sprintf(inviteDigestTableSQLFmt, "registry_invites")
	tblNorm, err := normalizeSQL(tblSQL)
	if err != nil {
		return malformed()
	}
	wantNorm, err := normalizeSQL(wantTbl)
	if err != nil {
		return malformed()
	}
	if tblNorm != wantNorm {
		return malformed()
	}

	// 3. Foreign keys must be exactly the migration-4 contract.
	fks, err := readInviteForeignKeys(ctx, tx, "registry_invites")
	if err != nil {
		return fmt.Errorf("migration 5 prerequisite: read registry_invites foreign keys: %w", err)
	}
	if len(fks) != 2 {
		return malformed()
	}
	if fks["registry_id"] != (inviteForeignKey{table: "registries", fromCol: "registry_id", toCol: "id", onUpdate: "NO ACTION", onDelete: "CASCADE"}) {
		return malformed()
	}
	if fks["accepted_by_user_id"] != (inviteForeignKey{table: "users", fromCol: "accepted_by_user_id", toCol: "id", onUpdate: "NO ACTION", onDelete: "NO ACTION"}) {
		return malformed()
	}

	// 4. token_digest must be backed by a real unique index (origin 'u')
	// covering exactly [token_digest], and the (registry_id, status) index must
	// exist with exactly those columns.
	uniq, err := readAutoUniqueIndexColumns(ctx, tx, "registry_invites")
	if err != nil {
		return fmt.Errorf("migration 5 prerequisite: read registry_invites unique indexes: %w", err)
	}
	if len(uniq) != 1 || !equalStringSlice(uniq[0], []string{"token_digest"}) {
		return malformed()
	}
	idxSQL, ok, err := storedObjectSQL(ctx, tx, "index", "idx_registry_invites_registry_status")
	if err != nil {
		return fmt.Errorf("migration 5 prerequisite: read registry_invites status index: %w", err)
	}
	if !ok {
		return malformed()
	}
	idxNorm, err := normalizeSQL(idxSQL)
	if err != nil {
		return malformed()
	}
	wantIdxNorm, err := normalizeSQL(inviteRegistryStatusIndexSQL)
	if err != nil {
		return malformed()
	}
	if idxNorm != wantIdxNorm {
		return malformed()
	}
	idxCols, err := readIndexColumns(ctx, tx, "registry_invites", "idx_registry_invites_registry_status")
	if err != nil {
		return fmt.Errorf("migration 5 prerequisite: read registry_invites status index columns: %w", err)
	}
	if !equalStringSlice(idxCols, []string{"registry_id", "status"}) {
		return malformed()
	}

	// 5. The four pre-existing lifecycle triggers must carry the exact guarding
	// semantics (fold-compared). A missing, renamed, or weakened trigger fails
	// here; migration 5 repairs none of them.
	for _, tc := range []struct{ name, wantSQL string }{
		{"registry_invites_born_pending", inviteBornPendingTriggerSQL},
		{"registry_invites_terminal_status", inviteTerminalStatusTriggerSQL},
		{"registry_invites_no_unattributed_acceptance", inviteNoUnattributedAcceptanceTriggerSQL},
		{"registry_invites_legacy_flag_locked", inviteLegacyFlagLockedTriggerSQL},
	} {
		trgSQL, ok, err := storedObjectSQL(ctx, tx, "trigger", tc.name)
		if err != nil {
			return fmt.Errorf("migration 5 prerequisite: read trigger %s: %w", tc.name, err)
		}
		if !ok {
			return malformed()
		}
		trgNorm, err := normalizeSQL(trgSQL)
		if err != nil {
			return malformed()
		}
		wantTrgNorm, err := normalizeSQL(tc.wantSQL)
		if err != nil {
			return malformed()
		}
		if trgNorm != wantTrgNorm {
			return malformed()
		}
	}

	return nil
}

// installInviteDigestSchema rebuilds registry_invites around the one-way
// digest lifecycle, normalizes legacy user/invite emails, and installs the
// constraints and triggers, all inside the migration transaction (rolled back
// atomically on any error). Steps:
//
//  1. Normalize every existing user email with the production NormalizeEmail
//     (legacy rows were stored strings.ToLower(email) only — no trim). A
//     normalized-user collision fails the migration BEFORE any update. The
//     in-place updates are order-safe: with a collision-free update set, no
//     ordering of the per-row UPDATEs can transiently violate the unique
//     email index (any such violation implies a normalized collision, which
//     was already rejected), and user IDs plus every FK to users are
//     preserved.
//  2. Validate EVERY existing invite row and compute its converted digest
//     (see convertLegacyInviteHash), normalized recipient, and
//     legacy_unattributed flag (accepted rows are always preserved as
//     legacy_unattributed — see the migration comment). Duplicate converted
//     digests and malformed/corrupt rows fail the migration with the legacy
//     data untouched; membership state is never consulted.
//  3. Create the constrained clone (digest BLOB unique with a strict
//     32-byte typeof/length CHECK, accepted_by FK, legacy_unattributed flag,
//     status/accepted_by/attribution CHECKs).
//  4. Copy the converted rows into the clone by explicit column name
//     (physical column order of legacy ALTER-appended schemas must not
//     matter).
//  5. Drop the legacy table and rename the clone into place.
//  6. Install the state-transition and attribution triggers and the status
//     index.
func installInviteDigestSchema(ctx context.Context, tx *sql.Tx) error {
	// ---- 1. Normalize legacy user emails (with collision detection). ----
	type legacyUser struct {
		id    int64
		email string
	}
	userRows, err := tx.QueryContext(ctx, `select id, email from users order by id asc`)
	if err != nil {
		return fmt.Errorf("enumerate legacy users: %w", err)
	}
	var users []legacyUser
	seenNorm := make(map[string]int64)
	for userRows.Next() {
		var u legacyUser
		if err := userRows.Scan(&u.id, &u.email); err != nil {
			userRows.Close()
			return fmt.Errorf("read legacy user: %w", err)
		}
		norm := NormalizeEmail(u.email)
		if prev, dup := seenNorm[norm]; dup {
			userRows.Close()
			return fmt.Errorf("user email normalization collision: users %d and %d both normalize to %q", prev, u.id, norm)
		}
		seenNorm[norm] = u.id
		users = append(users, u)
	}
	userRows.Close()
	if err := userRows.Err(); err != nil {
		return fmt.Errorf("iterate legacy users: %w", err)
	}
	for _, u := range users {
		norm := NormalizeEmail(u.email)
		if norm == u.email {
			continue
		}
		if _, err := tx.ExecContext(ctx, `update users set email = ? where id = ?`, norm, u.id); err != nil {
			return fmt.Errorf("normalize user %d email: %w", u.id, err)
		}
	}

	// ---- 2. Validate + convert every legacy invite row. ----
	rows, err := tx.QueryContext(ctx, `select id, registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at from registry_invites order by id asc`)
	if err != nil {
		return fmt.Errorf("enumerate legacy invites: %w", err)
	}
	var legacy []legacyInviteRow
	seenDigests := make(map[string]struct{})
	for rows.Next() {
		var (
			row                  legacyInviteRow
			canPull, canPush     int
			tokenHash, status    string
			expiresAt, createdAt string
		)
		if err := rows.Scan(&row.id, &row.registryID, &row.email, &row.role,
			&canPull, &canPush, &tokenHash, &status, &expiresAt, &createdAt); err != nil {
			rows.Close()
			return fmt.Errorf("read legacy invite row: %w", err)
		}
		row.canPull, row.canPush = canPull, canPush
		row.status = status
		row.expiresAt, row.createdAt = expiresAt, createdAt

		// Digest must be exactly the historical representation — hex of a
		// canonical token text (see convertLegacyInviteHash).
		digest, err := convertLegacyInviteHash(tokenHash)
		if err != nil {
			rows.Close()
			return fmt.Errorf("invite %d: %w", row.id, err)
		}
		row.digest = digest
		digestKey := string(digest)
		if _, dup := seenDigests[digestKey]; dup {
			rows.Close()
			return fmt.Errorf("invite %d: duplicate token digest after conversion", row.id)
		}
		seenDigests[digestKey] = struct{}{}

		// Status: only the states that existed before revocation.
		if status != "pending" && status != "accepted" {
			rows.Close()
			return fmt.Errorf("invite %d: unsupported legacy status %q", row.id, status)
		}
		// Expiry must parse (RFC3339) and the grant must be non-empty.
		if _, err := time.Parse(time.RFC3339, expiresAt); err != nil {
			rows.Close()
			return fmt.Errorf("invite %d: unparseable expiry %q", row.id, expiresAt)
		}
		if (canPull == 1 || canPush == 1) == false {
			rows.Close()
			return fmt.Errorf("invite %d: invite grants neither pull nor push", row.id)
		}
		// Accepted invites are preserved verbatim as legacy_unattributed=1
		// with accepted_by_user_id NULL. The historical ACCEPTER is
		// unknowable (the pre-Task-7 flow accepted any authenticated token
		// holder and inserted THEIR membership without a recipient check,
		// and never recorded who accepted), and current membership state
		// cannot establish attribution — the recipient's membership may
		// never have existed or may have been removed later. No membership
		// is required or inferred, and existing memberships are untouched.
		// New-format rows can never reach this state (born-pending trigger).
		if status == "accepted" {
			row.legacyUnattributed = 1
		}
		row.email = NormalizeEmail(row.email)
		legacy = append(legacy, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy invites: %w", err)
	}

	// ---- 3. Create the constrained clone. The CHECK constraints encode the
	// lifecycle consistency rules; the triggers (installed after the copy)
	// enforce the state machine and the attribution rules for every future
	// write, including direct SQL. The DDL is the shared constant so the exact
	// schema a genuine version-4 database carries is the same single source of
	// truth migration 5 validates against. ----
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(inviteDigestTableSQLFmt, "registry_invites_new")); err != nil {
		return fmt.Errorf("create invite digest clone: %w", err)
	}

	// ---- 4. Copy converted rows by explicit column name (legacy
	// ALTER-appended schema has a different PHYSICAL column order; names must
	// match). ----
	for _, row := range legacy {
		if _, err := tx.ExecContext(ctx, `insert into registry_invites_new
			(id, registry_id, email, role, can_pull, can_push, token_digest, status,
			 accepted_by_user_id, legacy_unattributed, expires_at, accepted_at, revoked_at, created_at)
			values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			row.id, row.registryID, row.email, row.role, row.canPull, row.canPush,
			row.digest, row.status, row.acceptedBy, row.legacyUnattributed, row.expiresAt,
			row.acceptedAt, row.revokedAt, row.createdAt); err != nil {
			return fmt.Errorf("copy invite %d into digest schema: %w", row.id, err)
		}
	}

	// ---- 5. Drop the legacy table and rename the clone into place. ----
	if _, err := tx.ExecContext(ctx, `drop table registry_invites`); err != nil {
		return fmt.Errorf("drop legacy registry_invites: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `alter table registry_invites_new rename to registry_invites`); err != nil {
		return fmt.Errorf("rename registry_invites_new: %w", err)
	}

	// ---- 6. State-transition + attribution triggers and the listing index.
	// Triggers are installed AFTER the copy so backfilled (non-pending)
	// rows are not rejected. The DDL comes from the shared constants so the
	// invariants a genuine version-4 database carries are the exact single
	// source of truth migration 5 validates against. ----
	for _, stmt := range []string{
		inviteBornPendingTriggerSQL,
		inviteTerminalStatusTriggerSQL,
		inviteNoUnattributedAcceptanceTriggerSQL,
		inviteLegacyFlagLockedTriggerSQL,
		legacyAttributionImmutableTriggerSQL,
		inviteRegistryStatusIndexSQL,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create invite lifecycle trigger/index: %w", err)
		}
	}
	return nil
}
