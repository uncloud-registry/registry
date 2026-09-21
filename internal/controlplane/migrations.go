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
type migration struct {
	Version int
	SQL     []string
}

// migrations is the ordered list of schema versions. Version 1 establishes the
// base constrained schema. Statements use "create table if not exists" so that
// databases already carrying the pre-versioning control-plane schema are left
// untouched and simply have their version recorded (see TestUpgradeCurrentSchema).
var migrations = []migration{{
	Version: 1,
	SQL: []string{
		`create table if not exists schema_migrations (version integer primary key, applied_at text not null)`,
		`create table if not exists users (id integer primary key autoincrement, email text not null unique, password_hash text not null, created_at text not null)`,
		`create table if not exists registries (id integer primary key autoincrement, slug text not null unique, host text not null unique, ens_name text not null, owner_user_id integer not null references users(id), feed_owner_address text not null, encrypted_feed_private_key text not null, default_stamp_batch_id text not null, anonymous_pull integer not null, created_at text not null)`,
		`create table if not exists registry_memberships (id integer primary key autoincrement, registry_id integer not null references registries(id) on delete cascade, user_id integer not null references users(id) on delete cascade, role text not null, can_pull integer not null, can_push integer not null, created_at text not null, unique(registry_id,user_id))`,
		`create table if not exists registry_invites (id integer primary key autoincrement, registry_id integer not null references registries(id) on delete cascade, email text not null, role text not null, can_pull integer not null, can_push integer not null, token_hash text not null unique, status text not null, expires_at text not null, created_at text not null)`,
	},
}}

// enableForeignKeys turns on foreign-key enforcement on the target connection.
// SQLite only honors this pragma outside an active transaction, so every
// connection that matters must set it via its DSN (see withForeignKeys); this
// statement is emitted defensively on the migration transaction as well.
const enableForeignKeys = `PRAGMA foreign_keys = ON`

// ApplyMigrations advances db to the latest schema version. Each migration is
// applied in its own transaction; the migration row is committed only after all
// of its statements succeed, so a partially applied migration is rolled back.
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

// applyMigration runs one migration's statements atomically inside a transaction,
// enabling foreign keys on the transaction connection first, and records the
// migration row only after every statement succeeds.
func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, enableForeignKeys); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}
	for _, stmt := range m.SQL {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute statement %q: %w", stmt, err)
		}
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
// connection the driver opens for it. It appends the modernc `_pragma` DSN
// option, so enforcement is per-connection rather than a one-time pool-wide
// PRAGMA (which SQLite silently ignores inside a transaction).
func withForeignKeys(dsn string) string {
	if strings.Contains(dsn, "_pragma=") {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=foreign_keys(1)"
}