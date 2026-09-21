package controlplane

import (
	"context"
	"database/sql"
	"strings"
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

	// A fresh database must carry the full physical foreign-key graph, not just
	// the same column layout.
	assertConstrainedFKs(t, db)

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
	// Re-running over an already-constrained database must be a no-op and must
	// not rebuild or duplicate anything.
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("second apply migrations: %v", err)
	}
	assertConstrainedFKs(t, db)
	var rows int
	if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations`).Scan(&rows); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if rows != 1 {
		t.Fatalf("expected 1 migration row, got %d", rows)
	}
}

// TestUpgradeCurrentSchema builds a database with the exact schema produced by
// the pre-versioning control plane (no schema_migrations table, no foreign keys),
// seeds one of each record, then runs ApplyMigrations and verifies the data is
// preserved with IDs intact, the schema is PHYSICALLY constrained, and no
// foreign-key violations are reported.
func TestUpgradeCurrentSchema(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	seedLegacyDB(t, db, now, expires, true /* withValidData */)

	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations over legacy schema: %v", err)
	}

	// Every pre-existing row must survive the upgrade with its identity intact.
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
	// IDs must survive (not reset by the rebuild).
	var registryID int64
	if err := db.QueryRowContext(ctx, `select id from registries where slug = 'alice'`).Scan(&registryID); err != nil {
		t.Fatalf("read preserved registry: %v", err)
	}
	if registryID != 1 {
		t.Fatalf("registry ID not preserved after rebuild, got %d", registryID)
	}

	// The upgraded schema must be PHYSICALLY constrained — the original concern
	// is that PRAGMA foreign_key_check is vacuous when no FKs exist at all.
	assertConstrainedFKs(t, db)

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

// TestUpgradeRejectsOrphanedLegacyData seeds a legacy database whose
// registry_memberships row references a nonexistent registry (invalid legacy
// data). The migration must FAIL, preserve the orphaned data untouched, and must
// not record schema version 1 — never silently discarding or repairing it.
func TestUpgradeRejectsOrphanedLegacyData(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)

	seedLegacyDBSchema(t, db)
	seedLegacyRow(t, db, "user", now, "alice@example.com", "hash")
	seedLegacyRow(t, db, "registry", now, "alice", "alice.example.test")
	// Orphan membership: registry_id 999 does not exist.
	if _, err := db.ExecContext(ctx, `insert into registry_memberships
		(registry_id,user_id,role,can_pull,can_push,created_at) values (?,?,?,?,?,?)`,
		999, 1, "member", 1, 0, now); err != nil {
		t.Fatalf("seed orphan membership: %v", err)
	}

	if err := ApplyMigrations(ctx, db); err == nil {
		t.Fatal("expected migration to reject orphaned legacy data, got nil error")
	}

	// Failure must leave the legacy data present and unmutated.
	var membershipCount int
	if err := db.QueryRowContext(ctx, `select count(*) from registry_memberships`).Scan(&membershipCount); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if membershipCount != 1 {
		t.Fatalf("orphaned membership must be preserved, got count=%d", membershipCount)
	}
	var orphanRegistryID int64
	if err := db.QueryRowContext(ctx, `select registry_id from registry_memberships`).Scan(&orphanRegistryID); err != nil {
		t.Fatalf("read orphan membership: %v", err)
	}
	if orphanRegistryID != 999 {
		t.Fatalf("orphan membership registry_id mutated, got %d", orphanRegistryID)
	}

	// Version must NOT be recorded as 1.
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil {
		t.Fatalf("current schema version after failed upgrade: %v", err)
	}
	if version != 0 {
		t.Fatalf("expected schema version 0 after rejected migration, got %d", version)
	}
	var migRows int
	if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations`).Scan(&migRows); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if migRows != 0 {
		t.Fatalf("expected zero recorded migration rows after rejection, got %d", migRows)
	}

	// No partial rebuild artifacts may remain after the rolled-back transaction.
	var leftovers int
	if err := db.QueryRowContext(ctx, `select count(*) from sqlite_master where type='table' and name like '%\_new%' escape '\'`).Scan(&leftovers); err != nil {
		t.Fatalf("count leftover rebuild tables: %v", err)
	}
	if leftovers != 0 {
		t.Fatalf("expected no *_new rebuild artifacts after rollback, found %d", leftovers)
	}
}

// fkRef describes one entry of PRAGMA foreign_key_list.
type fkRef struct {
	table    string
	from     string
	to       string
	onDelete string
}

// foreignKeyList reads PRAGMA foreign_key_list for a table.
func foreignKeyList(t *testing.T, db *sql.DB, table string) []fkRef {
	t.Helper()
	rows, err := db.Query(`PRAGMA foreign_key_list(` + table + `)`)
	if err != nil {
		t.Fatalf("foreign_key_list(%s): %v", table, err)
	}
	defer rows.Close()
	var out []fkRef
	for rows.Next() {
		var id, seq int
		var refTable, from, to, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &refTable, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			t.Fatalf("scan foreign_key_list(%s): %v", table, err)
		}
		out = append(out, fkRef{table: refTable, from: from, to: to, onDelete: onDelete})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate foreign_key_list(%s): %v", table, err)
	}
	return out
}

// assertConstrainedFKs proves the exact foreign-key graph promised by the brief
// is PHYSICALLY declared in the schema: registries.owner_user_id -> users.id,
// registry_memberships.{registry_id->registries.id CASCADE, user_id->users.id
// CASCADE}, registry_invites.registry_id -> registries.id CASCADE, and users
// referencing nothing.
func assertConstrainedFKs(t *testing.T, db *sql.DB) {
	t.Helper()
	if n := len(foreignKeyList(t, db, "users")); n != 0 {
		t.Fatalf("users must declare no foreign keys, found %d", n)
	}

	regs := foreignKeyList(t, db, "registries")
	find := func(fks []fkRef, table, from string) (fkRef, bool) {
		for _, f := range fks {
			if f.table == table && f.from == from {
				return f, true
			}
		}
		return fkRef{}, false
	}
	if len(regs) != 1 {
		t.Fatalf("registries must declare exactly 1 foreign key, found %d", len(regs))
	}
	if f, ok := find(regs, "users", "owner_user_id"); !ok || f.to != "id" || f.onDelete != "NO ACTION" {
		t.Fatalf("registries.owner_user_id missing/invalid constraint: %+v", regs)
	}

	memberships := foreignKeyList(t, db, "registry_memberships")
	if len(memberships) != 2 {
		t.Fatalf("registry_memberships must declare 2 foreign keys, found %d", len(memberships))
	}
	if f, ok := find(memberships, "registries", "registry_id"); !ok || f.to != "id" || f.onDelete != "CASCADE" {
		t.Fatalf("registry_memberships.registry_id missing/invalid: %+v", memberships)
	}
	if f, ok := find(memberships, "users", "user_id"); !ok || f.to != "id" || f.onDelete != "CASCADE" {
		t.Fatalf("registry_memberships.user_id missing/invalid: %+v", memberships)
	}

	invites := foreignKeyList(t, db, "registry_invites")
	if len(invites) != 1 {
		t.Fatalf("registry_invites must declare exactly 1 foreign key, found %d", len(invites))
	}
	if f, ok := find(invites, "registries", "registry_id"); !ok || f.to != "id" || f.onDelete != "CASCADE" {
		t.Fatalf("registry_invites.registry_id missing/invalid: %+v", invites)
	}

	// A physically constrained schema must reject an orphan insert.
	if _, err := db.Exec(`insert into registry_memberships
		(registry_id,user_id,role,can_pull,can_push,created_at)
		values (999,999,'member',1,0,?)`, time.Now().UTC().Format(time.RFC3339)); err == nil {
		t.Fatal("expected foreign-key violation for orphan insert on constrained schema, got nil")
	}
}

// seedLegacyDB builds the legacy schema and optionally seeds one valid record of
// each type.
func seedLegacyDB(t *testing.T, db *sql.DB, now, expires string, withValidData bool) {
	t.Helper()
	seedLegacyDBSchema(t, db)
	if !withValidData {
		return
	}
	seedLegacyRow(t, db, "user", now, "alice@example.com", "hash")
	seedLegacyRow(t, db, "registry", now, "alice", "alice.example.test")
	seedLegacyRow(t, db, "membership", now, "", "")
	seedLegacyRow(t, db, "invite", now, "", "bob@example.com")
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

func seedLegacyDBSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range legacySchemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("build legacy schema: %v", err)
		}
	}
}

// seedLegacyRow inserts one record of the given kind under the legacy schema.
func seedLegacyRow(t *testing.T, db *sql.DB, kind, now string, a, b string) {
	t.Helper()
	ctx := context.Background()
	expires := now
	switch kind {
	case "user":
		if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
			a, b, now); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	case "registry":
		if _, err := db.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
			values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a, b, "alice.eth", 1, "0xfeed", "ciphertext", "batch-1", 1, now); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	case "membership":
		if _, err := db.ExecContext(ctx, `insert into registry_memberships
			(registry_id, user_id, role, can_pull, can_push, created_at) values (?, ?, ?, ?, ?, ?)`,
			1, 1, "owner", 1, 1, now); err != nil {
			t.Fatalf("seed membership: %v", err)
		}
	case "invite":
		if _, err := db.ExecContext(ctx, `insert into registry_invites
			(registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at)
			values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			1, strings.ToLower(a), "member", 1, 0, "tokhash", "pending", expires, now); err != nil {
			t.Fatalf("seed invite: %v", err)
		}
	default:
		t.Fatalf("unknown legacy row kind %q", kind)
	}
}