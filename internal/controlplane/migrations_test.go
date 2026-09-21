package controlplane

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openRawTestDB opens an in-memory SQLite database with foreign keys enabled on
// every pooled connection (via the DSN pragma) and without going through
// OpenSQLite, so migration tests exercise the raw *sql.DB surface directly.
func openRawTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:migration_test?"+
		"mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestApplyMigrationsCreatesConstrainedSchema(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil {
		t.Fatalf("current schema version: %v", err)
	}
	if version != 1 {
		t.Fatalf("expected schema version 1, got %d", version)
	}

	// registry_id/user_id 999 do not exist, so the constrained schema must
	// reject this insert via the foreign keys declared in migration 1.
	_, err = db.Exec(`insert into registry_memberships
		(registry_id,user_id,role,can_pull,can_push,created_at)
		values (999,999,'member',1,0,?)`, time.Now().UTC().Format(time.RFC3339))
	if err == nil {
		t.Fatal("expected foreign-key violation for nonexistent registry/user, got nil")
	}
}

func TestApplyMigrationsIsIdempotent(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("first apply migrations: %v", err)
	}
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("second apply migrations: %v", err)
	}
}

// TestUpgradeCurrentSchema builds a database with the exact schema produced by
// the pre-versioning control plane (no schema_migrations table, no foreign keys),
// seeds one of each record, then runs ApplyMigrations and verifies the data is
// preserved and the schema reports no foreign-key violations.
func TestUpgradeCurrentSchema(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	for _, stmt := range legacySchemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("build legacy schema: %v", err)
		}
	}

	// Seed exactly one of each record type under the legacy schema.
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"alice@example.com", "hash", now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"alice", "alice.example.test", "alice.eth", 1, "0xfeed", "ciphertext", "batch-1", 1, now); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into registry_memberships
		(registry_id, user_id, role, can_pull, can_push, created_at) values (?, ?, ?, ?, ?, ?)`,
		1, 1, "owner", 1, 1, now); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into registry_invites
		(registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		1, "bob@example.com", "member", 1, 0, "tokhash", "pending", expires, now); err != nil {
		t.Fatalf("seed invite: %v", err)
	}

	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations over legacy schema: %v", err)
	}

	// Every pre-existing row must survive the upgrade untouched.
	var userCount, registryCount, membershipCount, inviteCount int
	if err := db.QueryRowContext(ctx, `select count(*) from users`).Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := db.QueryRowContext(ctx, `select count(*) from registries`).Scan(&registryCount); err != nil {
		t.Fatalf("count registries: %v", err)
	}
	if err := db.QueryRowContext(ctx, `select count(*) from registry_memberships`).Scan(&membershipCount); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if err := db.QueryRowContext(ctx, `select count(*) from registry_invites`).Scan(&inviteCount); err != nil {
		t.Fatalf("count invites: %v", err)
	}
	if userCount != 1 || registryCount != 1 || membershipCount != 1 || inviteCount != 1 {
		t.Fatalf("expected 1 of each record after upgrade, got users=%d registries=%d memberships=%d invites=%d",
			userCount, registryCount, membershipCount, inviteCount)
	}
	var email string
	if err := db.QueryRowContext(ctx, `select email from users where id = 1`).Scan(&email); err != nil {
		t.Fatalf("read preserved user: %v", err)
	}
	if email != "alice@example.com" {
		t.Fatalf("user email not preserved: %q", email)
	}

	// No foreign-key violations may be reported after the upgrade.
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("expected no foreign-key violations after upgrade")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("foreign_key_check iteration: %v", err)
	}

	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil {
		t.Fatalf("current schema version after upgrade: %v", err)
	}
	if version != 1 {
		t.Fatalf("expected schema version 1 after upgrade, got %d", version)
	}

	// Reapplying must be safe and not duplicate the migration row.
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("re-apply migrations after upgrade: %v", err)
	}
}

// legacySchemaStatements mirrors the schema the pre-versioning control plane
// created (matching a production controlplane.db: no schema_migrations table,
// membership/invite permission columns added via ALTER, no foreign keys).
var legacySchemaStatements = []string{
	`create table users (
		id integer primary key autoincrement,
		email text not null unique,
		password_hash text not null,
		created_at text not null
	)`,
	`create table registries (
		id integer primary key autoincrement,
		slug text not null unique,
		host text not null unique,
		ens_name text not null,
		owner_user_id integer not null,
		feed_owner_address text not null,
		encrypted_feed_private_key text not null,
		default_stamp_batch_id text not null,
		anonymous_pull integer not null,
		created_at text not null
	)`,
	`create table registry_memberships (
		id integer primary key autoincrement,
		registry_id integer not null,
		user_id integer not null,
		role text not null,
		can_pull integer not null default 1,
		can_push integer not null default 0,
		created_at text not null,
		unique(registry_id, user_id)
	)`,
	`create table registry_invites (
		id integer primary key autoincrement,
		registry_id integer not null,
		email text not null,
		role text not null,
		can_pull integer not null default 1,
		can_push integer not null default 0,
		token_hash text not null unique,
		status text not null,
		expires_at text not null,
		created_at text not null
	)`,
}