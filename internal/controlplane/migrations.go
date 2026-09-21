package controlplane

import (
	"context"
	"database/sql"
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
	// with non-empty ciphertext and nonce and a strictly positive version.
	// The migration first VALIDATES every existing row — any partial envelope
	// fails the migration (fully rolled back, version 2 stays recorded) rather
	// than being silently accepted — then installs BEFORE INSERT/UPDATE
	// triggers that enforce the invariant for every future write, including
	// direct SQL. Application layers (scan/list, store write guards, legacy
	// migration, rotation) enforce the same invariant on read and write; the
	// triggers close the direct-SQL gap so no code path can persist or mutate
	// a partial envelope.
	{
		Version: 3,
		Apply:   installFeedKeyEnvelopeInvariant,
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
func withForeignKeys(dsn string) string {
	// Split off any query string (first '?').
	base, query := dsn, ""
	if i := strings.Index(dsn, "?"); i >= 0 {
		base, query = dsn[:i], dsn[i+1:]
	}

	var kept []string
	if query != "" {
		for _, param := range strings.Split(query, "&") {
			if param == "" {
				continue
			}
			// Drop any foreign-keys pragma; we always re-add the effective one.
			if isForeignKeyPragmaParam(param) {
				continue
			}
			kept = append(kept, param)
		}
	}

	// Append the effective foreign_keys(1) pragma last. Order in the query
	// string doesn't matter for pragma application since our conflicting ones
	// were removed above; keeping it last is deterministic and readable.
	kept = append(kept, "_pragma=foreign_keys(1)")

	return base + "?" + strings.Join(kept, "&")
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
// when any two disagree on presence, or the version is non-positive, or a
// present ciphertext/nonce is empty (length() on a BLOB is its byte length).
const feedKeyEnvelopeInvariantCond = `(NEW.feed_key_ciphertext IS NULL) != (NEW.feed_key_nonce IS NULL)
	OR (NEW.feed_key_ciphertext IS NULL) != (NEW.feed_key_version IS NULL)
	OR (NEW.feed_key_version IS NOT NULL AND NEW.feed_key_version <= 0)
	OR (NEW.feed_key_ciphertext IS NOT NULL AND length(NEW.feed_key_ciphertext) = 0)
	OR (NEW.feed_key_nonce IS NOT NULL AND length(NEW.feed_key_nonce) = 0)`

// installFeedKeyEnvelopeInvariant validates every existing registries row
// against the feed-key envelope invariant, then installs BEFORE INSERT and
// BEFORE UPDATE triggers enforcing it for all future writes. If any EXISTING
// row violates the invariant the migration fails (the whole transaction is
// rolled back by applyMigration — the schema version stays 2 and no triggers
// are installed) instead of silently accepting or "repairing" inconsistent
// rows. The error message names the invariant; it carries no key material.
func installFeedKeyEnvelopeInvariant(ctx context.Context, tx *sql.Tx) error {
	var bad int
	if err := tx.QueryRowContext(ctx, `select count(*) from registries where
		(feed_key_ciphertext is null) != (feed_key_nonce is null)
		or (feed_key_ciphertext is null) != (feed_key_version is null)
		or (feed_key_version is not null and feed_key_version <= 0)
		or (feed_key_ciphertext is not null and length(feed_key_ciphertext) = 0)
		or (feed_key_nonce is not null and length(feed_key_nonce) = 0)`).Scan(&bad); err != nil {
		return fmt.Errorf("validate feed key envelope invariant: %w", err)
	}
	if bad != 0 {
		return fmt.Errorf("feed key envelope invariant violated by %d existing rows; refusing to migrate", bad)
	}
	for _, stmt := range []string{
		`create trigger registries_feed_key_complete_insert before insert on registries
			for each row when ` + feedKeyEnvelopeInvariantCond + `
			begin select raise(abort, 'feed key envelope must be all null or complete (non-empty ciphertext and nonce, positive version)'); end`,
		`create trigger registries_feed_key_complete_update before update on registries
			for each row when ` + feedKeyEnvelopeInvariantCond + `
			begin select raise(abort, 'feed key envelope must be all null or complete (non-empty ciphertext and nonce, positive version)'); end`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create feed key envelope invariant trigger: %w", err)
		}
	}
	return nil
}
