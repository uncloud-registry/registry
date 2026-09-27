package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/publish"

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
	if version != 16 {
		t.Fatalf("expected schema version 16, got %d", version)
	}

	// A fresh database must carry the full physical foreign-key graph, not just
	// the same column layout.
	assertConstrainedFKs(t, db)
	// The feed-key envelope invariant triggers must be physically installed.
	assertFeedKeyEnvelopeTriggers(t, db)
	// The invite digest lifecycle schema must be physically installed.
	assertInviteDigestSchema(t, db)

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
	if rows != 16 {
		t.Fatalf("expected 15 migration rows, got %d", rows)
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
	if version != 16 {
		t.Fatalf("expected schema version 16 after upgrade, got %d", version)
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

// TestUpgradePreservesAlterAppendedPermissionFields builds a legacy database the
// way the HISTORICAL pre-versioning control plane actually produced it: the
// membership and invite tables were originally created WITHOUT the can_pull /
// can_push columns, and a later in-place migration appended them via
// ALTER TABLE ADD COLUMN, so they physically sit at the END of each table
// (AFTER created_at). The rebuild must not depend on positional `select *`
// (which assumes the clone's physical column order, not the legacy table's),
// so every field value — not just row counts — must survive with its exact
// value and ID.
func TestUpgradePreservesAlterAppendedPermissionFields(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	membershipCreated := now.Add(-2 * time.Hour).Format(time.RFC3339)
	inviteCreated := now.Add(-1 * time.Hour).Format(time.RFC3339)
	expires := now.Add(24 * time.Hour).Format(time.RFC3339)
	inviteToken := legacyInviteHashV1

	seedAlterUpgradedLegacyDB(t, db, now, membershipCreated, inviteCreated, expires, inviteToken)

	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations over ALTER-upgraded legacy schema: %v", err)
	}

	// Memberships: both permission columns shifted position relative to the
	// clone's order, and created_at moved from position 5 to 7. Every field must
	// be byte-for-byte identical to what was seeded.
	var (
		mID, mReg, mUsr int64
		mRole           string
		mPull, mPush    int
		mCreated        string
	)
	if err := db.QueryRowContext(ctx, `select id, registry_id, user_id, role, can_pull, can_push, created_at from registry_memberships where id = 1`).
		Scan(&mID, &mReg, &mUsr, &mRole, &mPull, &mPush, &mCreated); err != nil {
		t.Fatalf("read migrated membership: %v", err)
	}
	if mID != 1 || mReg != 1 || mUsr != 1 {
		t.Fatalf("membership ids corrupted: id=%d registry=%d user=%d", mID, mReg, mUsr)
	}
	if mRole != "owner" {
		t.Fatalf("membership role corrupted: got %q", mRole)
	}
	if mPull != 0 || mPush != 1 {
		t.Fatalf("membership permission fields corrupted: can_pull=%d can_push=%d (want 0,1)", mPull, mPush)
	}
	if mCreated != membershipCreated {
		t.Fatalf("membership created_at corrupted: got %q want %q", mCreated, membershipCreated)
	}

	// Invites: the shift is larger (token_hash, status, expires_at, created_at
	// all move relative to the appended can_pull/can_push). Assert every field,
	// including the migration-4 conversion: the legacy hex(token text) hash
	// must become the one-way SHA-256 digest BLOB, and the accepted history is
	// preserved as legacy_unattributed — the historical accepter is
	// UNKNOWABLE, so NO accepted_by record is ever inferred from bob's
	// membership.
	var (
		iID, iReg               int64
		iEmail, iRole           string
		iPull, iPush            int
		iDigest                 []byte
		iStatus, iExp, iCreated string
		iAcceptedBy             sql.NullInt64
		iLegacy                 int
	)
	if err := db.QueryRowContext(ctx, `select id, registry_id, email, role, can_pull, can_push, token_digest, status, accepted_by_user_id, legacy_unattributed, expires_at, created_at from registry_invites where id = 1`).
		Scan(&iID, &iReg, &iEmail, &iRole, &iPull, &iPush, &iDigest, &iStatus, &iAcceptedBy, &iLegacy, &iExp, &iCreated); err != nil {
		t.Fatalf("read migrated invite: %v", err)
	}
	if iID != 1 || iReg != 1 {
		t.Fatalf("invite ids corrupted: id=%d registry=%d", iID, iReg)
	}
	if iEmail != "bob@example.com" || iRole != "member" {
		t.Fatalf("invite email/role corrupted: email=%q role=%q", iEmail, iRole)
	}
	if iPull != 1 || iPush != 1 {
		t.Fatalf("invite permission fields corrupted: can_pull=%d can_push=%d (want 1,1)", iPull, iPush)
	}
	wantDigest := DigestInviteToken(legacyInviteTokenTextV1)
	if len(iDigest) != 32 || !bytes.Equal(iDigest, wantDigest) {
		t.Fatalf("invite token digest not converted to SHA-256 of the legacy token text: got %x want %x", iDigest, wantDigest)
	}
	if iStatus != "accepted" {
		t.Fatalf("invite status corrupted: got %q", iStatus)
	}
	if iAcceptedBy.Valid {
		t.Fatalf("accepted history must NOT be attributed to bob's membership, got user %d", iAcceptedBy.Int64)
	}
	if iLegacy != 1 {
		t.Fatalf("expected legacy_unattributed=1 for the migrated accepted invite, got %d", iLegacy)
	}
	if iExp != expires {
		t.Fatalf("invite expires_at corrupted: got %q want %q", iExp, expires)
	}
	if iCreated != inviteCreated {
		t.Fatalf("invite created_at corrupted: got %q want %q", iCreated, inviteCreated)
	}
}

// seedAlterUpgradedLegacyDB builds a legacy schema the way the HISTORICAL
// pre-versioning control plane produced it: users/registries as today, but
// membership and invite tables WITHOUT the can_pull/can_push permission columns
// (they were appended later via ALTER TABLE ADD COLUMN, so they physically sit
// AFTER created_at). Representative rows are seeded with NON-DEFAULT permission
// values (so a positional copy would corrupt them) and non-default created_at /
// token / status values so every field's survival is independently observable.
func seedAlterUpgradedLegacyDB(t *testing.T, db *sql.DB, now time.Time, membershipCreated, inviteCreated, expires, inviteToken string) {
	t.Helper()
	ctx := context.Background()

	// No schema_migrations table, no foreign keys — matching a pre-versioning DB.
	alterSchema := []string{
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
		// Memberships WITHOUT permission columns: id, registry_id, user_id,
		// role, created_at (the historical order before can_pull/can_push were
		// appended).
		`create table registry_memberships (
			id integer primary key autoincrement,
			registry_id integer not null,
			user_id integer not null,
			role text not null,
			created_at text not null,
			unique(registry_id, user_id)
		)`,
		// Invites WITHOUT permission columns: id, registry_id, email, role,
		// token_hash, status, expires_at, created_at.
		`create table registry_invites (
			id integer primary key autoincrement,
			registry_id integer not null,
			email text not null,
			role text not null,
			token_hash text not null unique,
			status text not null,
			expires_at text not null,
			created_at text not null
		)`,
	}
	for _, stmt := range alterSchema {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("build ALTER-upgraded legacy schema: %v", err)
		}
	}

	// Historical ALTER step: append the permission columns at the END, in the
	// order the original migration added them.
	for _, stmt := range []string{
		`alter table registry_memberships add column can_pull integer not null default 1`,
		`alter table registry_memberships add column can_push integer not null default 0`,
		`alter table registry_invites add column can_pull integer not null default 1`,
		`alter table registry_invites add column can_push integer not null default 0`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply historical ALTER ADD COLUMN: %v", err)
		}
	}

	// Seed parents and child rows with representative, NON-DEFAULT values.
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"alice@example.com", "hash", now.Format(time.RFC3339)); err != nil {
		t.Fatalf("seed alter-upgraded user: %v", err)
	}
	// bob is the invitee of the legacy ACCEPTED invite; his membership is
	// historical state that must survive untouched — migration 4 never turns
	// it into an accepted_by attribution (the historical accepter is
	// unknowable), and no membership is required or inferred for accepted
	// history (it may have been removed later).
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"bob@example.com", "hash", now.Format(time.RFC3339)); err != nil {
		t.Fatalf("seed alter-upgraded bob: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"alice", "alice.example.test", "alice.eth", 1, "0xfeed", "ciphertext", "batch-1", 1, now.Format(time.RFC3339)); err != nil {
		t.Fatalf("seed alter-upgraded registry: %v", err)
	}
	// Membership: can_pull=0 can_push=1 (non-default), created_at distinct.
	if _, err := db.ExecContext(ctx, `insert into registry_memberships
		(registry_id, user_id, role, created_at, can_pull, can_push) values (?, ?, ?, ?, ?, ?)`,
		1, 1, "owner", membershipCreated, 0, 1); err != nil {
		t.Fatalf("seed alter-upgraded membership: %v", err)
	}
	// bob's membership (the accepted invitee): migration 4 preserves it
	// untouched while the invite migrates as legacy_unattributed — no
	// accepted_by is inferred from this row, and the migration does not
	// require it to exist.
	if _, err := db.ExecContext(ctx, `insert into registry_memberships
		(registry_id, user_id, role, created_at, can_pull, can_push) values (?, ?, ?, ?, ?, ?)`,
		1, 2, "member", membershipCreated, 1, 1); err != nil {
		t.Fatalf("seed alter-upgraded bob membership: %v", err)
	}
	// Invite: can_pull=1 can_push=1 (non-default), distinct token/status/times.
	if _, err := db.ExecContext(ctx, `insert into registry_invites
		(registry_id, email, role, token_hash, status, expires_at, created_at, can_pull, can_push)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		1, "bob@example.com", "member", inviteToken, "accepted", expires, inviteCreated, 1, 1); err != nil {
		t.Fatalf("seed alter-upgraded invite: %v", err)
	}
}

// TestWithForeignKeysNormalizesDSN proves that withForeignKeys must NOT short-
// circuit on any existing _pragma= (the defect: unrelated pragmas previously
// disabled FK enforcement entirely). The unrelated pragma must be preserved,
// conflicting foreign_keys values must be removed/replaced regardless of their
// order, and an effective foreign_keys(1) must always be present.
func TestWithForeignKeysNormalizesDSN(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		wantContains []string
		wantOmit     []string
	}{
		{
			name:         "plain path",
			in:           "controlplane.db",
			wantContains: []string{"_pragma=foreign_keys(1)"},
		},
		{
			name:         "file: uri",
			in:           "file:/abs/path/controlplane.db",
			wantContains: []string{"_pragma=foreign_keys(1)"},
		},
		{
			name:         "file: with existing query params",
			in:           "file:mem1?mode=memory&cache=shared",
			wantContains: []string{"mode=memory&cache=shared&_pragma=foreign_keys(1)"},
		},
		{
			name:         "unrelated pragma preserved",
			in:           "file:x.db?_pragma=busy_timeout(10000)",
			wantContains: []string{"busy_timeout(10000)", "foreign_keys(1)"},
		},
		{
			name:         "explicit foreign_keys(0) replaced",
			in:           "file:x.db?_pragma=foreign_keys(0)",
			wantContains: []string{"foreign_keys(1)"},
			wantOmit:     []string{"foreign_keys(0)"},
		},
		{
			name:         "unrelated before conflicting, ordering-independent",
			in:           "file:x.db?_pragma=busy_timeout(5000)&_pragma=foreign_keys(0)",
			wantContains: []string{"busy_timeout(5000)", "foreign_keys(1)"},
			wantOmit:     []string{"foreign_keys(0)"},
		},
		{
			name:         "unrelated after conflicting, ordering-independent",
			in:           "file:x.db?_pragma=foreign_keys(0)&_pragma=busy_timeout(5000)",
			wantContains: []string{"busy_timeout(5000)", "foreign_keys(1)"},
			wantOmit:     []string{"foreign_keys(0)"},
		},
		{
			name:         "multiple unrelated pragmas preserved",
			in:           "file:x.db?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)",
			wantContains: []string{"busy_timeout(10000)", "journal_mode(WAL)", "foreign_keys(1)"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := withForeignKeys(tc.in)
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Fatalf("withForeignKeys(%q) = %q; want it to contain %q", tc.in, got, want)
				}
			}
			for _, omit := range tc.wantOmit {
				if strings.Contains(got, omit) {
					t.Fatalf("withForeignKeys(%q) = %q; expected to not contain %q", tc.in, got, omit)
				}
			}
			// The base path / query params must be preserved.
			for _, keep := range []string{"file:x.db", "file:mem1", "file:/abs/path/controlplane.db", "controlplane.db"} {
				if strings.Contains(tc.in, keep) && !strings.Contains(got, keep) {
					t.Fatalf("withForeignKeys(%q) = %q; lost base %q", tc.in, got, keep)
				}
			}
		})
	}
}

// TestForeignKeysEnforcedAcrossPooledConnectionsWithCustomDSN opens a database
// whose DSN carries an unrelated pragma (_pragma=busy_timeout) and an explicit
// foreign_keys(0), passes it through withForeignKeys, and proves, across
// MULTIPLE simultaneously held *sql.Conn values (each a DISTINCT physical
// connection, verified by driver pointer identity), that (a) foreign-key
// enforcement is active on every one — not just the first pooled conn — while
// (b) the unrelated busy_timeout pragma also still applies to every connection.
//
// The prior test acquired and closed each *sql.Conn sequentially, so the pool
// reused one idle physical connection and could not prove cross-pool
// enforcement. This version HOLDs poolSize connections at once; until one is
// closed none returns to the pool, forcing database/sql to open poolSize
// DISTINCT physical connections to the shared cache.
func TestForeignKeysEnforcedAcrossPooledConnectionsWithCustomDSN(t *testing.T) {
	customDSN := "file:fkpool_test?mode=memory&cache=shared&_pragma=busy_timeout(7000)&_pragma=foreign_keys(0)"

	db, err := sql.Open("sqlite", withForeignKeys(customDSN))
	if err != nil {
		t.Fatalf("open sqlite with custom DSN: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// We HOLD exactly poolSize *sql.Conn simultaneously, so every held Conn maps
	// to its own physical connection. Acquiring exactly maxOpenConns never blocks
	// a Conn(ctx), so there is no deadlock. SetMaxOpenConns alone is insufficient
	// to prove multiple physical connections (the round-1 finding); the
	// concurrent hold + driver-pointer distinctness assertion below is the proof.
	const poolSize = 8
	db.SetMaxOpenConns(poolSize)
	db.SetMaxIdleConns(poolSize)

	ctx := context.Background()

	// Build a constrained schema manually (mirrors the migration's DDL).
	for _, stmt := range []string{
		`create table users (id integer primary key autoincrement, email text not null unique, password_hash text not null, created_at text not null)`,
		`create table registries (id integer primary key autoincrement, slug text not null unique, host text not null unique, ens_name text not null, owner_user_id integer not null references users(id), feed_owner_address text not null, encrypted_feed_private_key text not null, default_stamp_batch_id text not null, anonymous_pull integer not null, created_at text not null)`,
		`create table registry_memberships (id integer primary key autoincrement, registry_id integer not null references registries(id) on delete cascade, user_id integer not null references users(id) on delete cascade, role text not null, can_pull integer not null, can_push integer not null, created_at text not null, unique(registry_id,user_id))`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("create constrained schema: %v", err)
		}
	}

	// Acquire and HOLD poolSize connections at once. Register the release cleanup
	// BEFORE any probe so every held connection is closed even if an assertion
	// aborts the test (t.Cleanup runs before db.Close).
	conns := make([]*sql.Conn, 0, poolSize)
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	fps := make([]uintptr, 0, poolSize)
	for i := 0; i < poolSize; i++ {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("acquire and hold conn %d: %v", i, err)
		}
		conns = append(conns, conn)
		var fp uintptr
		if err := conn.Raw(func(d any) error {
			if rv := reflect.ValueOf(d); rv.Kind() == reflect.Ptr {
				fp = rv.Pointer()
			}
			return nil
		}); err != nil {
			t.Fatalf("fingerprint conn %d: %v", i, err)
		}
		fps = append(fps, fp)
	}

	// Prove the pool actually handed out DISTINCT physical connections — exactly
	// what the old acquire/probe/close structure could not do. Without this the
	// per-connection pragma probes below would only exercise one physical conn.
	seen := make(map[uintptr]bool, poolSize)
	for i, fp := range fps {
		if fp == 0 {
			t.Fatalf("conn %d: could not fingerprint physical connection", i)
		}
		if seen[fp] {
			t.Fatalf("conn %d reused physical connection %x; not all held conns are distinct", i, fp)
		}
		seen[fp] = true
	}

	// (a) On EVERY held (distinct) physical connection, PRAGMA foreign_keys must
	// equal 1 AND the unrelated busy_timeout pragma must still be active.
	for i := 0; i < poolSize; i++ {
		var fk, busy int
		if err := conns[i].QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
			t.Fatalf("read foreign_keys on held conn %d: %v", i, err)
		}
		if err := conns[i].QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busy); err != nil {
			t.Fatalf("read busy_timeout on held conn %d: %v", i, err)
		}
		if fk != 1 {
			t.Fatalf("held conn %d: PRAGMA foreign_keys = %d, want 1 (cross-pool enforcement missing)", i, fk)
		}
		if busy == 0 {
			t.Fatalf("held conn %d: unrelated busy_timeout pragma inactive (got 0)", i)
		}
	}

	// Seed valid parents via the first held connection.
	seedConn := conns[0]
	if _, err := seedConn.ExecContext(ctx, `insert into users (email,password_hash,created_at) values (?,?,?)`,
		"alice@example.com", "hash", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := seedConn.ExecContext(ctx, `insert into registries
		(slug,host,ens_name,owner_user_id,feed_owner_address,encrypted_feed_private_key,default_stamp_batch_id,anonymous_pull,created_at)
		values (?,?,?,?,?,?,?,?,?)`,
		"alice", "alice.test", "alice.eth", 1, "0xfeed", "cipher", "batch-1", 1, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed registry: %v", err)
	}

	// (b) Run an orphan-rejection probe on EVERY held (distinct) physical
	// connection BEFORE releasing any of them. FK enforcement must be active
	// cross-pool on each distinct conn, not merely on a single pooled conn.
	for i := 0; i < poolSize; i++ {
		_, err := conns[i].ExecContext(ctx, `insert into registry_memberships
			(registry_id,user_id,role,can_pull,can_push,created_at) values (?,?,?,?,?,?)`,
			999, 1, "member", 1, 0, time.Now().UTC().Format(time.RFC3339))
		if err == nil {
			t.Fatalf("held conn %d: orphan insert accepted; want foreign-key violation on distinct physical connection", i)
		}
	}

	// (c) A legitimate membership (real parents) must still succeed on a held
	// distinct connection OTHER than the seed conn, proving enforcement on that
	// physical connection didn't over-fire. conns[1] is inherently a distinct
	// physical connection (verified above), so no new acquisition/blocking.
	validConn := conns[1]
	if _, err := validConn.ExecContext(ctx, `insert into registry_memberships
		(registry_id,user_id,role,can_pull,can_push,created_at) values (?,?,?,?,?,?)`,
		1, 1, "owner", 1, 1, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("valid membership on held distinct connection failed: %v", err)
	}

	// All held connections are closed by the registered t.Cleanup.
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
	if len(invites) != 2 {
		t.Fatalf("registry_invites must declare exactly 2 foreign keys (registry cascade + accepted_by), found %d", len(invites))
	}
	if f, ok := find(invites, "registries", "registry_id"); !ok || f.to != "id" || f.onDelete != "CASCADE" {
		t.Fatalf("registry_invites.registry_id missing/invalid: %+v", invites)
	}
	if f, ok := find(invites, "users", "accepted_by_user_id"); !ok || f.to != "id" {
		t.Fatalf("registry_invites.accepted_by_user_id missing/invalid: %+v", invites)
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
			1, strings.ToLower(a), "member", 1, 0, legacyInviteHashV1, "pending", expires, now); err != nil {
			t.Fatalf("seed invite: %v", err)
		}
	default:
		t.Fatalf("unknown legacy row kind %q", kind)
	}
}

// legacyInviteTokenTextV1 is a canonical legacy invite token TEXT (32
// base64url chars decoding to 24 zero bytes), used by legacy seed helpers so
// migration 4 can deterministically convert the historical hex(token text)
// token_hash into the SHA-256 digest.
const legacyInviteTokenTextV1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// legacyInviteHashV1 is the historical reversible token_hash encoding of
// legacyInviteTokenTextV1: hex(token text), 64 lowercase hex chars.
const legacyInviteHashV1 = "4141414141414141414141414141414141414141414141414141414141414141"

// assertInviteDigestSchema proves the migration-4 lifecycle schema is
// physically installed: token_digest BLOB unique with a strict 32-byte CHECK,
// the accepted_by FK, the legacy_unattributed flag, the consistency CHECKs
// (via a rejected direct-SQL insert), and the state-transition/attribution
// triggers.
func assertInviteDigestSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()

	// token_digest must exist as the unique credential column.
	var digestType string
	if err := db.QueryRowContext(ctx, `select type from pragma_table_info('registry_invites') where name = 'token_digest'`).Scan(&digestType); err != nil {
		t.Fatalf("token_digest column missing: %v", err)
	}
	if !strings.Contains(strings.ToUpper(digestType), "BLOB") {
		t.Fatalf("token_digest must be a BLOB, got %q", digestType)
	}
	// The digest CHECK and the migration-only flag are part of the DDL.
	var ddl string
	if err := db.QueryRowContext(ctx, `select sql from sqlite_master where type = 'table' and name = 'registry_invites'`).Scan(&ddl); err != nil {
		t.Fatalf("read registry_invites DDL: %v", err)
	}
	for _, needle := range []string{"typeof(token_digest)", "length(token_digest) = 32", "legacy_unattributed"} {
		if !strings.Contains(ddl, needle) {
			t.Fatalf("registry_invites DDL missing %q: %s", needle, ddl)
		}
	}

	// Invites are born pending only: a direct insert with another status must
	// be aborted by the trigger.
	if _, err := db.ExecContext(ctx, `insert into registry_invites
		(registry_id, email, role, can_pull, can_push, token_digest, status, expires_at, created_at)
		values (999, 'x@example.com', 'member', 1, 0, zeroblob(32), 'accepted', ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339)); err == nil {
		t.Fatal("expected born-pending trigger to reject a non-pending insert")
	}

	var fks int
	if err := db.QueryRowContext(ctx, `select count(*) from pragma_foreign_key_list('registry_invites')`).Scan(&fks); err != nil {
		t.Fatalf("count invite fks: %v", err)
	}
	if fks != 2 {
		t.Fatalf("expected 2 foreign keys on registry_invites (registry cascade + accepted_by), got %d", fks)
	}
	for _, name := range []string{
		"registry_invites_born_pending",
		"registry_invites_terminal_status",
		"registry_invites_no_unattributed_acceptance",
		"registry_invites_legacy_flag_locked",
		"registry_invites_legacy_attribution_immutable",
	} {
		var n int
		if err := db.QueryRowContext(ctx, `select count(*) from sqlite_master where type = 'trigger' and name = ?`, name).Scan(&n); err != nil {
			t.Fatalf("count trigger %s: %v", name, err)
		}
		if n != 1 {
			t.Fatalf("expected trigger %s to be installed, found %d", name, n)
		}
	}
	// The immutability trigger must carry the guarding semantics (a BEFORE
	// UPDATE trigger rejecting every change to a legacy_unattributed row), not
	// merely bear the name — the migration-5 repair is what delivers it to
	// databases that applied the pre-fix migration 4.
	assertLegacyAttributionImmutableTrigger(t, db)
}

// applyMigrationsThrough runs only the migrations up to and including version
// upto, mirroring ApplyMigrations (same per-migration transaction and
// recording semantics). Used to build an intermediate schema version (e.g. a
// v2-only database) so tests can exercise the upgrade from THAT version.
func applyMigrationsThrough(ctx context.Context, db *sql.DB, upto int) error {
	if _, err := db.ExecContext(ctx, `create table if not exists schema_migrations (version integer primary key, applied_at text not null)`); err != nil {
		return fmt.Errorf("ensure schema_migrations exists: %w", err)
	}
	current, err := CurrentSchemaVersion(ctx, db)
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if m.Version <= current || m.Version > upto {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return fmt.Errorf("apply migration %d: %w", m.Version, err)
		}
		current = m.Version
	}
	return nil
}

// assertFeedKeyEnvelopeTriggers proves the two schema-level envelope triggers
// are physically installed on the registries table.
func assertFeedKeyEnvelopeTriggers(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, name := range []string{"registries_feed_key_complete_insert", "registries_feed_key_complete_update"} {
		var n int
		if err := db.QueryRow(`select count(*) from sqlite_master where type = 'trigger' and name = ?`, name).Scan(&n); err != nil {
			t.Fatalf("count trigger %s: %v", name, err)
		}
		if n != 1 {
			t.Fatalf("expected trigger %s to be installed, found %d", name, n)
		}
	}
}

// TestFeedKeyEnvelopeMigrationRejectsMalformedRows pins migration 3's data
// validation: a database already at v2 whose registries rows carry a PARTIAL
// feed-key envelope fails the upgrade, rolls back completely (version stays 2,
// no triggers installed, the malformed row untouched), and never silently
// accepts or "repairs" the inconsistent data.
func TestFeedKeyEnvelopeMigrationRejectsMalformedRows(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)

	// Build a v2 database (feed-key columns exist, triggers do not).
	if err := applyMigrationsThrough(ctx, db, 2); err != nil {
		t.Fatalf("apply through v2: %v", err)
	}
	// Seed a user + registry with a PARTIAL envelope (version set, no nonce).
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"alice@example.com", "hash", now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)
		values (?,?,?,?,?,?,?,?,?,?,?,?)`,
		"alice", "alice.uncloud-registry.com", "alice.eth", 1, "0xfeed", "",
		"batch-1", 1, now, []byte("0123456789abcdef"), nil, 1); err != nil {
		t.Fatalf("seed partial row: %v", err)
	}

	err := ApplyMigrations(ctx, db)
	if err == nil {
		t.Fatal("migration must fail on existing partial envelopes")
	}
	// Rolled back: version still 2, no triggers, row untouched, no v3 record.
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("version must stay 2 after rejected migration, got %d", version)
	}
	var n int
	if err := db.QueryRow(`select count(*) from sqlite_master where type = 'trigger' and name like 'registries_feed_key_complete_%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("no triggers may remain after rollback, found %d", n)
	}
	var migRows int
	if err := db.QueryRow(`select count(*) from schema_migrations`).Scan(&migRows); err != nil {
		t.Fatal(err)
	}
	if migRows != 2 {
		t.Fatalf("expected 2 recorded migrations after rejection, got %d", migRows)
	}
	var ciphertext []byte
	var versionCol sql.NullInt64
	if err := db.QueryRow(`select feed_key_ciphertext, feed_key_version from registries where id = 1`).Scan(&ciphertext, &versionCol); err != nil {
		t.Fatal(err)
	}
	if !versionCol.Valid || len(ciphertext) == 0 {
		t.Fatal("malformed row must be left untouched")
	}
}

// TestFeedKeyEnvelopeMigrationRejectsMalformedLengths pins migration 3's
// preflight against COMPLETE-but-malformed envelopes: an existing all-present
// row whose nonce is not exactly 12 bytes or whose ciphertext is shorter than
// the 16-byte GCM minimum fails the upgrade, rolls back completely (version
// stays 2, no triggers installed, rows untouched), and is never silently
// accepted as a plausible-looking key.
func TestFeedKeyEnvelopeMigrationRejectsMalformedLengths(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)

	// Build a v2 database (feed-key columns exist, triggers do not).
	if err := applyMigrationsThrough(ctx, db, 2); err != nil {
		t.Fatalf("apply through v2: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"alice@example.com", "hash", now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	seed := func(slug string, ct, nonce []byte, ver int) {
		if _, err := db.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)
			values (?,?,?,?,?,?,?,?,?,?,?,?)`,
			slug, slug+".uncloud-registry.com", slug+".eth", 1, "0xfeed", "",
			"batch-1", 1, now, ct, nonce, ver); err != nil {
			t.Fatalf("seed %s: %v", slug, err)
		}
	}
	// All three columns present, but the envelope is cryptographically
	// malformed — the preflight must reject each of these.
	seed("shortnonce", []byte("0123456789abcdef"), []byte("0123456789a"), 1)   // nonce 11 bytes
	seed("longnonce", []byte("0123456789abcdef"), []byte("0123456789abcd"), 1) // nonce 14 bytes
	seed("shortct", []byte("0123456789abcde"), []byte("0123456789ab"), 1)      // ciphertext 15 bytes

	if err := ApplyMigrations(ctx, db); err == nil {
		t.Fatal("migration must fail on existing complete-but-malformed envelopes")
	}
	// Rolled back: version still 2, no triggers, malformed rows untouched, no
	// v3 record.
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("version must stay 2 after rejected migration, got %d", version)
	}
	var n int
	if err := db.QueryRow(`select count(*) from sqlite_master where type = 'trigger' and name like 'registries_feed_key_complete_%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("no triggers may remain after rollback, found %d", n)
	}
	var migRows int
	if err := db.QueryRow(`select count(*) from schema_migrations`).Scan(&migRows); err != nil {
		t.Fatal(err)
	}
	if migRows != 2 {
		t.Fatalf("expected 2 recorded migrations after rejection, got %d", migRows)
	}
	for _, slug := range []string{"shortnonce", "longnonce", "shortct"} {
		var ctLen, nonceLen int
		if err := db.QueryRow(`select length(feed_key_ciphertext), length(feed_key_nonce) from registries where slug = ?`, slug).Scan(&ctLen, &nonceLen); err != nil {
			t.Fatal(err)
		}
		if ctLen != 16 && slug != "shortct" {
			t.Fatalf("%s: row must be untouched (ctLen=%d)", slug, ctLen)
		}
		if slug == "shortct" && ctLen != 15 {
			t.Fatalf("shortct: row must be untouched (ctLen=%d)", ctLen)
		}
		if (slug == "shortnonce" && nonceLen != 11) || (slug == "longnonce" && nonceLen != 14) || (slug == "shortct" && nonceLen != 12) {
			t.Fatalf("%s: row must be untouched (nonceLen=%d)", slug, nonceLen)
		}
	}
}

// TestFeedKeyEnvelopeMigrationAcceptsStructurallyValidRows pins the preflight
// boundary: an existing all-present envelope whose ciphertext is EXACTLY 16
// bytes (the empty-plaintext minimum) and nonce exactly 12 bytes is
// structurally valid and must NOT block the upgrade.
func TestFeedKeyEnvelopeMigrationAcceptsStructurallyValidRows(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)

	if err := applyMigrationsThrough(ctx, db, 2); err != nil {
		t.Fatalf("apply through v2: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"alice@example.com", "hash", now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)
		values (?,?,?,?,?,?,?,?,?,?,?,?)`,
		"exact16", "exact16.uncloud-registry.com", "exact16.eth", 1, "0xfeed", "",
		"batch-1", 1, now, []byte("0123456789abcdef"), []byte("0123456789ab"), 1); err != nil {
		t.Fatalf("seed exact-16 row: %v", err)
	}
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("migration must accept structurally valid 16-byte-ciphertext rows: %v", err)
	}
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if version != 16 {
		t.Fatalf("expected version 16, got %d", version)
	}
	assertFeedKeyEnvelopeTriggers(t, db)
	assertInviteDigestSchema(t, db)
}

// TestFeedKeyEnvelopeMigrationWorksFromEverySupportedSchema drives migration 3
// from each supported starting point: a fresh database (v0), a legacy
// plaintext database upgraded through v1+v2, and an already-current v2
// database whose rows carry valid all-null or complete envelopes. All must
// reach v3 with the triggers installed and no data disturbance.
func TestFeedKeyEnvelopeMigrationWorksFromEverySupportedSchema(t *testing.T) {
	t.Run("fresh v0", func(t *testing.T) {
		db := openRawTestDB(t)
		if err := ApplyMigrations(context.Background(), db); err != nil {
			t.Fatalf("apply migrations: %v", err)
		}
		version, _ := CurrentSchemaVersion(context.Background(), db)
		if version != 16 {
			t.Fatalf("expected version 16, got %d", version)
		}
		assertFeedKeyEnvelopeTriggers(t, db)
		assertInviteDigestSchema(t, db)
	})
	t.Run("legacy plaintext through v1 v2", func(t *testing.T) {
		db := openRawTestDB(t)
		ctx := context.Background()
		now := time.Now().UTC().Format(time.RFC3339)
		seedLegacyDB(t, db, now, now, true)
		if err := ApplyMigrations(ctx, db); err != nil {
			t.Fatalf("apply migrations: %v", err)
		}
		version, _ := CurrentSchemaVersion(ctx, db)
		if version != 16 {
			t.Fatalf("expected version 16, got %d", version)
		}
		assertFeedKeyEnvelopeTriggers(t, db)
		// Legacy plaintext untouched by the schema migration (opt-in only).
		var legacy string
		if err := db.QueryRowContext(ctx, `select encrypted_feed_private_key from registries where id = 1`).Scan(&legacy); err != nil {
			t.Fatal(err)
		}
		if legacy != "ciphertext" {
			t.Fatalf("schema migration must not clear legacy plaintext, got %q", legacy)
		}
	})
	t.Run("current v2 with valid rows", func(t *testing.T) {
		db := openRawTestDB(t)
		ctx := context.Background()
		now := time.Now().UTC().Format(time.RFC3339)
		if err := applyMigrationsThrough(ctx, db, 2); err != nil {
			t.Fatalf("apply through v2: %v", err)
		}
		// One all-null row and one complete-envelope row (both valid).
		if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
			"alice@example.com", "hash", now); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
			values (?,?,?,?,?,?,?,?,?)`,
			"nokey", "nokey.uncloud-registry.com", "nokey.eth", 1, "0xfeed", "",
			"batch-1", 1, now); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)
			values (?,?,?,?,?,?,?,?,?,?,?,?)`,
			"full", "full.uncloud-registry.com", "full.eth", 1, "0xfeed", "",
			"batch-1", 1, now, []byte("0123456789abcdef"), []byte("0123456789ab"), 1); err != nil {
			t.Fatal(err)
		}
		if err := ApplyMigrations(ctx, db); err != nil {
			t.Fatalf("apply migrations from v2: %v", err)
		}
		version, _ := CurrentSchemaVersion(ctx, db)
		if version != 16 {
			t.Fatalf("expected version 16, got %d", version)
		}
		assertFeedKeyEnvelopeTriggers(t, db)
	})
}

// TestMigrateLegacyFeedKeysFromV2CurrentSchema covers the supported upgrade
// path for a deployment that ALREADY ran the released schema migration (v2
// recorded) and still carries legacy plaintext: advancing to v3 installs the
// invariant without touching the plaintext, and the opt-in legacy migration
// then encrypts and clears it per row.
func TestMigrateLegacyFeedKeysFromV2CurrentSchema(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	if err := applyMigrationsThrough(ctx, db, 2); err != nil {
		t.Fatalf("apply through v2: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"alice@example.com", "hash", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values (?,?,?,?,?,?,?,?,?)`,
		"alice", "alice.uncloud-registry.com", "alice.eth", 1, "0xfeed", "ciphertext",
		"batch-1", 1, now); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations from v2: %v", err)
	}

	service := newStoreService(t, db)
	migrated, err := service.MigrateLegacyFeedKeys(ctx)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if migrated != 1 {
		t.Fatalf("expected 1 migrated row, got %d", migrated)
	}
	var legacy string
	var ciphertext, nonce []byte
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, `select encrypted_feed_private_key, feed_key_ciphertext, feed_key_nonce, feed_key_version from registries where id = 1`).Scan(&legacy, &ciphertext, &nonce, &version); err != nil {
		t.Fatal(err)
	}
	if legacy != "" || len(ciphertext) == 0 || len(nonce) == 0 || !version.Valid {
		t.Fatalf("row must be migrated and cleared: legacy=%q", legacy)
	}
	if _, err := service.FeedKeys.Decrypt(1, "0xfeed", EncryptedFeedKey{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: int(version.Int64)}); err != nil {
		t.Fatalf("migrated ciphertext must decrypt under the row's owner: %v", err)
	}
}

// TestFeedSignerResultIntegrityTriggers rejects, at the DATABASE level
// (migration-11 BEFORE INSERT and BEFORE UPDATE triggers), every malformed
// succeeded result — exactly one invariant per case — while accepting a fully
// canonical result. The strict Go decoder is defense-in-depth; these triggers
// are the primary gate so a direct-SQL write can never fabricate a success.
func TestFeedSignerResultIntegrityTriggers(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"owner@example.com", "hash", now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"sig", "sig.test", "sig.eth", 1, testFeedOwner, "", "batch-1", 1, now); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	hx := func(c, n int) string { return strings.Repeat(string(rune(c)), n) }
	owner := strings.Repeat("a", 40)
	topic := "feed://" + owner + "/" + strings.Repeat("b", 64)
	ref := strings.Repeat("c", 64)
	regID := 1
	nowNs := timeToNanos(time.Now().UTC())
	base := func(opID, resultJSON string) string {
		return `insert into feed_signer_operations
			(operation_id, registry_id, topic, request_hash, state, result_json,
			 claim_token, lease_until, attempts, created_at, updated_at)
			values ('` + opID + `', ` + string(rune('0'+regID)) + `, '` + topic + `', X'` + hx('1', 64) + `', 'succeeded', '` + resultJSON + `', null, null, 0, ` + fmt.Sprintf("%d,%d", nowNs, nowNs) + `)`
	}
	canonical := `{"operationID":"ok","feed":"` + topic + `","reference":"` + ref + `"}`
	upd := `update feed_signer_operations set result_json=? , state=?, claim_token=null, lease_until=null where operation_id=?`

	reject := func(name, resultJSON string, isUpdate bool) {
		t.Run(name, func(t *testing.T) {
			if isUpdate {
				if _, err := db.ExecContext(ctx, upd, resultJSON, "succeeded", "ok"); err == nil {
					t.Fatalf("expected UPDATE trigger reject for %s", name)
				}
			} else {
				if _, err := db.ExecContext(ctx, base("bad-"+name, resultJSON)); err == nil {
					t.Fatalf("expected INSERT trigger reject for %s", name)
				}
			}
		})
	}

	// A valid INSERT passes.
	if _, err := db.ExecContext(ctx, base("ok", canonical)); err != nil {
		t.Fatalf("canonical succeeded row rejected: %v", err)
	}
	// A valid UPDATE (canonical on an existing row) passes.
	if _, err := db.ExecContext(ctx, upd, canonical, "succeeded", "ok"); err != nil {
		t.Fatalf("canonical succeeded update rejected: %v", err)
	}

	// Each invariant, once.
	reject("not-json", "nonsense", false)
	reject("json-array", `["a","b","c"]`, false)
	reject("duplicate-key", `{"operationID":"x","feed":"`+topic+`","reference":"`+ref+`","operationID":"x"}`, false)
	reject("extra-field", `{"operationID":"x","feed":"`+topic+`","reference":"`+ref+`","extra":1}`, false)
	reject("missing-key", `{"feed":"`+topic+`","reference":"`+ref+`"}`, false)
	reject("op-id-mismatch", `{"operationID":"DIFFERENT","feed":"`+topic+`","reference":"`+ref+`"}`, false)
	reject("noncanonical-feed-prefix", `{"operationID":"x","feed":"http://`+owner+`/`+strings.Repeat("b", 64)+`","reference":"`+ref+`"}`, false)
	reject("fed-short-owner", `{"operationID":"x","feed":"feed://`+strings.Repeat("a", 39)+`/`+strings.Repeat("b", 64)+`","reference":"`+ref+`"}`, false)
	reject("feed-extra-slash", `{"operationID":"x","feed":"feed://`+owner+`//`+strings.Repeat("b", 64)+`","reference":"`+ref+`"}`, false)
	reject("feed-uppercase-owner", `{"operationID":"x","feed":"feed://`+strings.ToUpper(owner)+`/`+strings.Repeat("b", 64)+`","reference":"`+ref+`"}`, false)
	reject("feed-uppercase-topic", `{"operationID":"x","feed":"feed://`+owner+`/`+strings.ToUpper(strings.Repeat("b", 64))+`","reference":"`+ref+`"}`, false)
	reject("feed-query", `{"operationID":"x","feed":"feed://`+owner+`/`+strings.Repeat("b", 64)+`?x=1","reference":"`+ref+`"}`, false)
	reject("ref-short", `{"operationID":"x","feed":"`+topic+`","reference":"abcd"}`, false)
	reject("ref-long", `{"operationID":"x","feed":"`+topic+`","reference":"`+strings.Repeat("c", 65)+`"}`, false)
	reject("ref-uppercase", `{"operationID":"x","feed":"`+topic+`","reference":"`+strings.ToUpper(strings.Repeat("c", 64))+`"}`, false)
	reject("whitespace-json", `{ "operationID" : "x", "feed" : "`+topic+`", "reference" : "`+ref+`" }`, false)

	// A pending row carrying a result is rejected; UPDATE path too.
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values ('pending-w-result','1','`+topic+`',X'`+hx('2', 64)+`', 'pending', '`+canonical+`', null, null, 0, ?, ?)`, nowNs, nowNs); err == nil {
		t.Fatal("expected pending-with-result INSERT to be rejected")
	}
	if _, err := db.ExecContext(ctx, `update feed_signer_operations set state='pending', result_json=?, claim_token=null, lease_until=null where operation_id='ok'`, canonical); err == nil {
		t.Fatal("expected pending-with-result UPDATE to be rejected")
	}
}

// TestMigration13OperationIDGrammarTriggers proves migration 13's dedicated
// operation-ID identity triggers apply the FULL application grammar
// (publish.ValidateOperationID) on EVERY active row — pending, processing, and
// succeeded alike — via direct SQL, on BOTH the INSERT and UPDATE paths, and
// that no SQLite evaluation trick (NULL, malformed storage class, embedded
// NUL, escapes in the result) can bypass them.
func TestMigration13OperationIDGrammarTriggers(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if sqliteObjectCount(t, db, "trigger", "feed_signer_operation_id_ins") != 1 ||
		sqliteObjectCount(t, db, "trigger", "feed_signer_operation_id_upd") != 1 {
		t.Fatal("migration 13 must install the operation-ID identity triggers")
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)
	ref := strings.Repeat("ab", 32)
	nowNs := timeToNanos(time.Now().UTC())
	// The result JSON that is byte-canonical for a GIVEN operation id (Go-exact
	// json.Marshal), so a rejection below can ONLY be the identity trigger.
	canon := func(opID string) string {
		return string(publish.CanonicalFeedCommitResultJSON(publish.FeedCommitResult{OperationID: opID, Feed: topic, Reference: ref}))
	}
	ins := func(opID, result string) error {
		h := feedSignerTestHash("h-" + opID)
		_, err := db.ExecContext(ctx, `insert into feed_signer_operations
			(operation_id, registry_id, topic, request_hash, state, result_json,
			 claim_token, lease_until, attempts, created_at, updated_at)
			values (?, ?, ?, ?, 'succeeded', ?, null, null, 0, ?, ?)`,
			opID, reg.ID, topic, h[:], result, nowNs, nowNs)
		return err
	}
	// A pending row (NULL result — the migration-11/12 result triggers do not
	// constrain old-v12 pending rows' operation_id, which is exactly the gap
	// migration 13 closes) to exercise the UPDATE identity trigger.
	updHash := feedSignerTestHash("upd-base")
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values ('upd-base', ?, ?, ?, 'pending', null, null, null, 0, ?, ?)`,
		reg.ID, topic, updHash[:], nowNs, nowNs); err != nil {
		t.Fatalf("seed updatable pending row: %v", err)
	}
	upd := func(opID string) error {
		_, err := db.ExecContext(ctx, `update feed_signer_operations
			set operation_id = ? where operation_id = 'upd-base'`, opID)
		return err
	}

	forbidden := []string{
		"a<b", "a>b", "a&b", `a"b`, `a\b`, // the five Go-JSON-escaped bytes
		"a\x00b",                // NUL (never detectable via GLOB; instr must catch it)
		"a	b", "a\nb", "a\x1fb", // controls
		"a\x7fb",                         // DEL
		"a\x80b", "a\u2028b", "a\u2029b", // non-ASCII (>= U+0080)
		"",                       // empty
		strings.Repeat("a", 129), // too long
	}
	for _, opID := range forbidden {
		t.Run("insert/"+fmt.Sprintf("%q", opID), func(t *testing.T) {
			if err := ins(opID, canon(opID)); err == nil {
				t.Fatalf("INSERT with operation_id %q must be rejected by the identity trigger", opID)
			}
		})
		t.Run("update/"+fmt.Sprintf("%q", opID), func(t *testing.T) {
			if err := upd(opID); err == nil {
				t.Fatalf("UPDATE to operation_id %q must be rejected by the identity trigger", opID)
			}
		})
	}

	// Direct SQL probe mirroring the reviewer: operation_id `a<b` with a LITERAL
	// (unescaped) result fails at INSERT, and the Go-escaped result ALSO fails —
	// because the row identity itself violates the grammar.
	if err := ins(`a<b`, `{"operationID":"a<b","feed":"`+topic+`","reference":"`+ref+`"}`); err == nil {
		t.Fatal("operation_id `a<b` with literal result must fail at INSERT")
	}
	if err := ins(`a<b`, `{"operationID":"a\u003cb","feed":"`+topic+`","reference":"`+ref+`"}`); err == nil {
		t.Fatal("operation_id `a<b` with Go-escaped result must fail (row identity invalid)")
	}

	// NULL and malformed storage classes cannot bypass the grammar.
	nulHash := feedSignerTestHash("nul")
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values (NULL, ?, ?, ?, 'succeeded', ?, null, null, 0, ?, ?)`,
		reg.ID, topic, nulHash[:], canon("x"), nowNs, nowNs); err == nil {
		t.Fatal("NULL operation_id must be rejected")
	}
	intHash := feedSignerTestHash("int")
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values (42, ?, ?, ?, 'succeeded', ?, null, null, 0, ?, ?)`,
		reg.ID, topic, intHash[:], canon("x"), nowNs, nowNs); err == nil {
		t.Fatal("non-text operation_id storage class must be rejected")
	}

	// Accepted punctuation/alphanumerics/current 64-hex forms pass both paths.
	valid := []string{
		strings.Repeat("a", 64),  // current ComputeOperationID form
		"op-idA1-2.3_4:5",        // punctuation, no forbidden byte
		strings.Repeat("a", 128), // exact upper bound
		"~!%^()+,-./:=?@[]{|}~",  // printable 0x20..0x7e minus the five
	}
	for _, opID := range valid {
		if err := ins(opID, canon(opID)); err != nil {
			t.Fatalf("INSERT with valid operation_id %q must succeed: %v", opID, err)
		}
	}
	// UPDATE path with valid ids (distinct from the inserted ones).
	for _, opID := range []string{"upd-valid-1", "upd-" + strings.Repeat("a", 64)} {
		if err := upd(opID); err != nil {
			t.Fatalf("UPDATE to valid operation_id %q must succeed: %v", opID, err)
		}
	}
}

// TestMigration13OperationIDGrammarParityExhaustive proves SQL and Go agree
// EXHAUSTIVELY on the operation-ID grammar: for every ASCII byte value, every
// boundary/forbidden character embedded in a longer identifier, control runs,
// non-ASCII code points (including U+0080 and U+2028/U+2029), and the length
// bounds, `publish.ValidateOperationID` accepts exactly when the migration-13
// SQL predicate accepts. NULL is invalid in SQL (no Go equivalent).
func TestMigration13OperationIDGrammarParityExhaustive(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	pred := strings.ReplaceAll(feedSignerOperationIDGrammarCond, "NEW.operation_id", "operation_id")
	q := `select ` + pred + ` from (select ? as operation_id)`
	sqlBad := func(s any) int {
		var bad int
		if err := db.QueryRowContext(ctx, q, s).Scan(&bad); err != nil {
			t.Fatalf("evaluate SQL predicate for %v: %v", s, err)
		}
		return bad
	}

	var cases []string
	// Every single ASCII byte value, 0x00..0x7f.
	for b := 0; b <= 0x7f; b++ {
		cases = append(cases, string([]byte{byte(b)}))
	}
	// Boundary/forbidden characters embedded in a longer identifier.
	for _, b := range []byte{0x00, 0x01, 0x09, 0x0a, 0x1f, 0x20, '"', '\\', '<', '>', '&', '~', 0x7f} {
		cases = append(cases, "a"+string([]byte{b})+"b")
	}
	// Accepted punctuation and alphanumerics in context.
	for _, s := range []string{"a-b_c.d:e", "A1-2.3_4:5", "0x9f", "hello world"} {
		cases = append(cases, s)
	}
	// Non-ASCII code points (Go and SQLite both decode; >= U+0080 must reject,
	// including the Go-JSON-escaped U+2028/U+2029).
	for _, r := range []rune{0x80, 0x9f, 0xe9, 0xff, 0x2028, 0x2029, 0x4e2d, 0xfffd, 0x10ffff} {
		cases = append(cases, "a"+string(r)+"b")
	}
	// Length bounds.
	cases = append(cases, strings.Repeat("a", 128), strings.Repeat("a", 129))

	for _, s := range cases {
		goBad := publish.ValidateOperationID(s) != nil
		sb := sqlBad(s)
		if goBad != (sb == 1) {
			t.Fatalf("parity mismatch for %q: Go valid=%v, SQL invalid=%d", s, !goBad, sb)
		}
	}
	// A SQL NULL must be invalid (guard not bypassable via NULL).
	if sb := sqlBad(nil); sb != 1 {
		t.Fatalf("NULL operation_id must be invalid, SQL predicate=%d", sb)
	}
}

// TestMigration13RejectsInvalidV12OperationIDRollsBack proves migration 13's
// atomic hardening: a v12 database whose active PENDING row carries an
// operation_id that violates the application grammar (migration 11/12 accepted
// it — the result triggers only constrain state='succeeded' rows) causes
// migration 13 to FAIL and roll back byte-identically: the version stays 12,
// the offending row is untouched, and NO schema object/trigger is installed
// (the module-level version record, sqlite_master, the row bytes, and the
// migration count must all be byte-identical). No silent rewrite, deletion, or
// quarantine of invalid active state, ever.
func TestMigration13RejectsInvalidV12OperationIDRollsBack(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 12); err != nil {
		t.Fatalf("apply through v12: %v", err)
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)
	nowNs := timeToNanos(time.Now().UTC())

	// v12 ACCEPTS a grammar-violating operation_id on a pending row (NULL
	// result): the round-3-era gap this migration closes.
	badHash := feedSignerTestHash("a<b")
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values ('a<b', ?, ?, ?, 'pending', null, null, null, 0, ?, ?)`,
		reg.ID, topic, badHash[:], nowNs, nowNs); err != nil {
		t.Fatalf("v12 must admit a grammar-violating pending operation_id (the round-3-era gap): %v", err)
	}

	preSchema := dumpSQLiteSchema(t, db)
	preRow := dumpOperationRow(t, db, "a<b")
	preMigs := migrationCount(t, db)

	if err := ApplyMigrations(ctx, db); err == nil {
		t.Fatal("migration 13 must fail when hardening encounters a grammar-violating v12 operation_id")
	}
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 12 {
		t.Fatalf("version must stay 12 on adversarial migration 13, got %d (err %v)", v, err)
	}
	if got := migrationCount(t, db); got != preMigs {
		t.Fatalf("schema_migrations must be untouched after rollback: had %d, now %d", preMigs, got)
	}
	if !bytes.Equal(dumpSQLiteSchema(t, db), preSchema) {
		t.Fatal("sqlite_master must be byte-identical after migration 13 rollback (no trigger/schema installed)")
	}
	if got := dumpOperationRow(t, db, "a<b"); !bytes.Equal(got, preRow) {
		t.Fatalf("offending row must be byte-identical after rollback: %q", got)
	}
}

// TestMigration13AcceptsValidV12OperationIDRowsUpgrade proves the supported
// upgrade: every schema-admitted v12 active row whose operation_id obeys the
// grammar (the 64-hex ComputeOperationID forms and valid punctuation) upgrades
// to version 13 cleanly, with the identity triggers installed and every row
// intact.
func TestMigration13AcceptsValidV12OperationIDRowsUpgrade(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 12); err != nil {
		t.Fatalf("apply through v12: %v", err)
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)
	ref := strings.Repeat("ab", 32)
	nowNs := timeToNanos(time.Now().UTC())

	pendingIDs := []string{strings.Repeat("a", 64), "op-idA1-2.3_4:5"}
	for _, opID := range pendingIDs {
		ph := feedSignerTestHash(opID)
		if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
			(operation_id, registry_id, topic, request_hash, state, result_json,
			 claim_token, lease_until, attempts, created_at, updated_at)
			values (?, ?, ?, ?, 'pending', null, null, null, 0, ?, ?)`,
			opID, reg.ID, topic, ph[:], nowNs, nowNs); err != nil {
			t.Fatalf("seed pending %q: %v", opID, err)
		}
	}
	sucOp := strings.Repeat("b", 64)
	sucResult := string(publish.CanonicalFeedCommitResultJSON(publish.FeedCommitResult{OperationID: sucOp, Feed: topic, Reference: ref}))
	sh := feedSignerTestHash(sucOp)
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values (?, ?, ?, ?, 'succeeded', ?, null, null, 0, ?, ?)`,
		sucOp, reg.ID, topic, sh[:], sucResult, nowNs, nowNs); err != nil {
		t.Fatalf("seed succeeded %q: %v", sucOp, err)
	}

	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("valid v12 rows must upgrade to 13: %v", err)
	}
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 16 {
		t.Fatalf("expected version 16, got %d (err %v)", v, err)
	}
	if sqliteObjectCount(t, db, "trigger", "feed_signer_operation_id_ins") != 1 ||
		sqliteObjectCount(t, db, "trigger", "feed_signer_operation_id_upd") != 1 {
		t.Fatal("identity triggers must be installed after upgrade")
	}
	var gotSuc []byte
	if err := db.QueryRowContext(ctx, `select result_json from feed_signer_operations where operation_id = ?`, sucOp).Scan(&gotSuc); err != nil {
		t.Fatal(err)
	}
	if string(gotSuc) != sucResult {
		t.Fatalf("succeeded row must be untouched by the upgrade: %s", gotSuc)
	}
}

// TestMigration14OperationIDGrammarTriggers proves the migration-14 identity
// triggers enforce the operation-ID grammar BYTE-EXACTLY — decided on the RAW
// STORED BYTES via hex(CAST(NEW.operation_id AS BLOB)) with an ALIGNED
// recursive byte scan, never on decoded Unicode characters — for every class of
// malformed input the Unicode-codepoint GLOB guard (migration 13) got wrong:
//
//   - the reviewer's exact probe `CAST(X'F4908080' AS TEXT)` (an OUT-OF-RANGE
//     4-byte sequence that migration 13's codepoint ranges classify as allowed),
//   - a lone continuation byte `cast(X'80' as text)`,
//   - overlong encodings (C0 AF), surrogate encodings (ED A0 80), truncated
//     sequences (E2 82), out-of-range sequences (F5 90 80 80) and a lone FF,
//   - VALID non-ASCII UTF-8 ('é', '中') — every byte >= 0x80 rejects,
//   - NUL/control/DEL and the five Go-JSON-escaped bytes 0x22/0x26/0x3C/0x3E/0x5C,
//   - empty and 129 bytes,
//   - BLOB/numeric/NULL storage classes.
//
// It then proves every ALLOWED ASCII boundary/punctuation sample and the exact
// 1..128 byte-length bounds pass on BOTH INSERT and UPDATE, and that the
// canonical-result triggers are re-created AFTER the identity triggers (their
// rowids are larger), preserving the byte-exact result-concatenation guard.
func TestMigration14OperationIDGrammarTriggers(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 16 {
		t.Fatalf("expected schema version 16, got %d (err %v)", v, err)
	}
	if sqliteObjectCount(t, db, "trigger", "feed_signer_operation_id_ins") != 1 ||
		sqliteObjectCount(t, db, "trigger", "feed_signer_operation_id_upd") != 1 {
		t.Fatal("migration 14 must install the byte-exact operation-ID identity triggers")
	}
	// Identity triggers must fire BEFORE (rowid <) the canonical-result triggers
	// so the byte-exact operation_id concatenation runs only on grammar-proven
	// rows.
	var idInsRowID, resInsRowID int64
	if err := db.QueryRowContext(ctx, `select rowid from sqlite_master where type='trigger' and name='feed_signer_operation_id_ins'`).Scan(&idInsRowID); err != nil {
		t.Fatalf("locate identity trigger: %v", err)
	}
	if err := db.QueryRowContext(ctx, `select rowid from sqlite_master where type='trigger' and name='feed_signer_result_integrity_ins'`).Scan(&resInsRowID); err != nil {
		t.Fatalf("locate result trigger: %v", err)
	}
	if idInsRowID > resInsRowID {
		t.Fatalf("identity trigger (rowid %d) must precede result trigger (rowid %d)", idInsRowID, resInsRowID)
	}

	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)
	ref := strings.Repeat("ab", 32)
	nowNs := timeToNanos(time.Now().UTC())
	canon := func(opID string) string {
		return string(publish.CanonicalFeedCommitResultJSON(publish.FeedCommitResult{OperationID: opID, Feed: topic, Reference: ref}))
	}
	ins := func(opID any, result string) error {
		h := feedSignerTestHash("h-" + fmt.Sprint(opID))
		_, err := db.ExecContext(ctx, `insert into feed_signer_operations
			(operation_id, registry_id, topic, request_hash, state, result_json,
			 claim_token, lease_until, attempts, created_at, updated_at)
			values (?, ?, ?, ?, 'succeeded', ?, null, null, 0, ?, ?)`,
			opID, reg.ID, topic, h[:], result, nowNs, nowNs)
		return err
	}
	// A pending row (NULL result) to exercise the UPDATE identity trigger.
	updHash := feedSignerTestHash("upd-base")
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values ('upd-base', ?, ?, ?, 'pending', null, null, null, 0, ?, ?)`,
		reg.ID, topic, updHash[:], nowNs, nowNs); err != nil {
		t.Fatalf("seed updatable pending row: %v", err)
	}
	upd := func(opID any) error {
		_, err := db.ExecContext(ctx, `update feed_signer_operations
			set operation_id = ? where operation_id = 'upd-base'`, opID)
		return err
	}
	raw := func(hexBytes string) string {
		// Raw stored bytes (including malformed UTF-8) as a Go string; the
		// driver binds them verbatim (verified empirically).
		b, err := hex.DecodeString(hexBytes)
		if err != nil {
			t.Fatalf("bad raw hex %q: %v", hexBytes, err)
		}
		return string(b)
	}

	forbidden := []struct {
		name string
		opID any
	}{
		// Reviewer-exact malformed UTF-8 probes (all previously decodable by
		// migration 13's codepoint GLOB or misclassified by character length()).
		{"reviewer-F4908080", raw("F4908080")},
		{"lone-continuation-80", raw("80")},
		{"overlong-C0AF", raw("C0AF")},
		{"surrogate-EDA080", raw("EDA080")},
		{"truncated-E282", raw("E282")},
		{"overlong-C080", raw("C080")},
		{"out-of-range-F5908080", raw("F5908080")},
		{"lone-FF", raw("FF")},
		{"truncated-F09F", raw("F09F")},
		// Valid non-ASCII UTF-8: every byte >= 0x80 is forbidden by the byte
		// grammar (é = C3 A9, 中 = E4 B8 AD — rejected by raw bytes, not by
		// decoding).
		{"valid-nonascii-eacute", "a\xc3\xa9b"},
		{"valid-nonascii-han", "a\xe4\xb8\xadb"},
		// NUL / controls / DEL.
		{"nul", "a\x00b"},
		{"control-01", "a\x01b"},
		{"tab", "a	b"},
		{"newline", "a\nb"},
		{"control-1f", "a\x1fb"},
		{"del", "a\x7fb"},
		// The five Go-JSON-escaped bytes.
		{"lt", "a<b"},
		{"gt", "a>b"},
		{"amp", "a&b"},
		{"quote", `a"b`},
		{"backslash", `a\b`},
		// Empty and byte-length over the 128 bound.
		{"empty", ""},
		{"129-bytes", strings.Repeat("a", 129)},
		// 65 chars of 'é' = 130 raw bytes but only 65 characters — the BYTE
		// length gate must reject it (character length() would have admitted it
		// at <= 128 chars).
		{"65-eacute-130-bytes", strings.Repeat("\xc3\xa9", 65)},
		// Storage-class subversion. (Numeric 42 cannot reach the predicate as a
		// number here: the operation_id column's TEXT affinity converts it to
		// TEXT '42'; the storage-class rejection of INTEGER is proven in the
		// parity test through an AFFINITY-FREE subquery.)
		{"blob", []byte("abc")},
		{"null", nil},
	}
	for _, fc := range forbidden {
		t.Run("insert/"+fc.name, func(t *testing.T) {
			if err := ins(fc.opID, canon(fmt.Sprint(fc.opID))); err == nil {
				t.Fatalf("INSERT with operation_id %s must be rejected by the byte-exact identity trigger", fc.name)
			}
		})
		t.Run("update/"+fc.name, func(t *testing.T) {
			// Re-anchor the update target whenever a prior subtest mutated it
			// (an ADMITTED value would otherwise leave 'upd-base' missing and
			// the UPDATE would silently match zero rows).
			if _, err := db.ExecContext(ctx, `insert or ignore into feed_signer_operations
				(operation_id, registry_id, topic, request_hash, state, result_json,
				 claim_token, lease_until, attempts, created_at, updated_at)
				values ('upd-base', ?, ?, ?, 'pending', null, null, null, 0, ?, ?)`,
				reg.ID, topic, updHash[:], nowNs, nowNs); err != nil {
				t.Fatalf("re-anchor updatable pending row: %v", err)
			}
			if err := upd(fc.opID); err == nil {
				t.Fatalf("UPDATE to operation_id %s must be rejected by the byte-exact identity trigger", fc.name)
			}
		})
	}
	// The reviewer's exact probe with a raw byte string bound as a parameter
	// (modernc binds Go strings as verbatim TEXT bytes, verified) must ALSO be
	// rejected — no storage path around the byte grammar.
	if err := ins(string([]byte{0xF4, 0x90, 0x80, 0x80}), canon("x")); err == nil {
		t.Fatal("reviewer probe CAST(X'F4908080' AS TEXT) as a bound TEXT parameter must be rejected")
	}
	if err := upd(string([]byte{0x80})); err == nil {
		t.Fatal("bound lone-continuation byte must be rejected on UPDATE")
	}

	// Every ALLOWED byte boundary and punctuation sample passes on INSERT
	// (canonical result, so only the identity trigger decides) and UPDATE.
	valid := []string{
		strings.Repeat("a", 64),  // current ComputeOperationID form
		strings.Repeat("a", 128), // exact upper byte bound (128 ASCII bytes)
		"op-idA1-2.3_4:5",        // punctuation, no forbidden byte
		"~!%^()+,-./:=?@[]{|}~",  // printable 0x20..0x7e minus the five
		" ",                      // 0x20 lower boundary
		"~",                      // 0x7e upper boundary
		"a b c",                  // literal 0x20 spaces are allowed bytes
	}
	for _, opID := range valid {
		if err := ins(opID, canon(opID)); err != nil {
			t.Fatalf("INSERT with valid operation_id %q must succeed: %v", opID, err)
		}
	}
	for _, opID := range []string{"upd-valid-1", "upd-" + strings.Repeat("a", 128)} {
		if err := upd(opID); err != nil {
			t.Fatalf("UPDATE to valid operation_id %q must succeed: %v", opID, err)
		}
	}
}

// TestMigration14OperationIDGrammarParityExhaustive proves SQL and Go agree
// EXHAUSTIVELY on the migration-14 BYTE-EXACT grammar: every ASCII byte value,
// embedded boundary/forbidden bytes, control runs, VALID non-ASCII UTF-8
// runes, and RAW MALFORMED UTF-8 byte sequences of every form (lone
// continuation, overlong, surrogate, truncated, out-of-range, lone lead/FF),
// plus the byte-length bounds, `publish.ValidateOperationID` accepts exactly
// when the migration-14 SQL predicate accepts. The expected (Go) and actual
// (SQL) sides are independent implementations — the SQL predicate is a
// hand-written constant and the Go side is the production validator. NULL is
// invalid in SQL (no Go equivalent).
func TestMigration14OperationIDGrammarParityExhaustive(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	pred := strings.ReplaceAll(feedSignerOperationIDGrammarCondV14, "NEW.operation_id", "operation_id")
	q := `select ` + pred + ` from (select ? as operation_id)`
	sqlBad := func(s any) int {
		var bad int
		if err := db.QueryRowContext(ctx, q, s).Scan(&bad); err != nil {
			t.Fatalf("evaluate SQL predicate for %v: %v", s, err)
		}
		return bad
	}
	// Raw-byte variants run through a TEXT literal so byte-exactness is decided
	// by SQLite alone (no driver-bound-string dependency for the malformed set).
	qRaw := func(hexBytes string) int {
		var bad int
		query := `select ` + pred + ` from (select cast(X'` + hexBytes + `' as text) as operation_id)`
		if err := db.QueryRowContext(ctx, query).Scan(&bad); err != nil {
			t.Fatalf("evaluate raw SQL predicate X'%s': %v", hexBytes, err)
		}
		return bad
	}

	var cases []string
	// Every single ASCII byte value, 0x00..0x7f.
	for b := 0; b <= 0x7f; b++ {
		cases = append(cases, string([]byte{byte(b)}))
	}
	// Boundary/forbidden bytes embedded in a longer identifier.
	for _, b := range []byte{0x00, 0x01, 0x09, 0x0a, 0x1f, 0x20, '"', '\\', '<', '>', '&', '~', 0x7f} {
		cases = append(cases, "a"+string([]byte{b})+"b")
	}
	// Accepted punctuation and alphanumerics in context.
	for _, s := range []string{"a-b_c.d:e", "A1-2.3_4:5", "0x9f", "hello world", "~!%^()+,-./:=?@[]{|}~"} {
		cases = append(cases, s)
	}
	// VALID non-ASCII UTF-8 runes: Go and SQLite agree the raw BYTES reject.
	for _, r := range []rune{0x80, 0x9f, 0xe9, 0xff, 0x2028, 0x2029, 0x4e2d, 0xfffd, 0x10ffff} {
		cases = append(cases, "a"+string(r)+"b")
	}
	// Byte-length bounds.
	cases = append(cases, strings.Repeat("a", 128), strings.Repeat("a", 129))
	cases = append(cases, strings.Repeat("\xc3\xa9", 65), strings.Repeat("\xc3\xa9", 64))

	for _, s := range cases {
		goBad := publish.ValidateOperationID(s) != nil
		sb := sqlBad(s)
		if goBad != (sb == 1) {
			t.Fatalf("parity mismatch for %q: Go valid=%v, SQL invalid=%d", s, !goBad, sb)
		}
	}

	// Raw MALFORMED UTF-8 byte sequences — the byte-exact delta over migration
	// 13. The Go side sees the same bytes; both must reject.
	rawCases := []string{
		"F4908080", // reviewer probe: out-of-range 4-byte sequence
		"80",       // lone continuation
		"C0AF",     // overlong 2-byte
		"C080",     // overlong 2-byte (NUL)
		"EDA080",   // surrogate encoding
		"EDBFBF",   // surrogate encoding (max)
		"E282",     // truncated 3-byte
		"F09F",     // truncated 4-byte
		"F5908080", // out-of-range 4-byte
		"FF",       // lone FF
		"C0",       // lone lead
		"F490",     // truncated 4-byte lead pair
		"E28241",   // truncated 3-byte then ASCII
		"F09F92",   // truncated 4-byte
	}
	for _, hx := range rawCases {
		var raw []byte
		for i := 0; i < len(hx); i += 2 {
			var v int
			if _, err := fmt.Sscanf(hx[i:i+2], "%02x", &v); err != nil {
				t.Fatalf("parse hex %s: %v", hx, err)
			}
			raw = append(raw, byte(v))
		}
		goBad := publish.ValidateOperationID(string(raw)) != nil
		sb := qRaw(hx)
		if goBad != (sb == 1) {
			t.Fatalf("raw parity mismatch for X'%s': Go valid=%v, SQL invalid=%d", hx, !goBad, sb)
		}
		if goBad != true {
			t.Fatalf("malformed bytes X'%s' must be invalid in Go", hx)
		}
	}
	// Negative control: a VALID raw 3-byte sequence must be rejected by BOTH
	// (bytes >= 0x80) — and the alignment scan must agree.
	if sb := qRaw("E282A1"); sb != 1 {
		t.Fatalf("valid UTF-8 raw bytes must reject at the byte level, SQL=%d", sb)
	}
	if goBad := publish.ValidateOperationID("\xe2\x82\xa1") != nil; !goBad {
		t.Fatal("valid UTF-8 raw bytes must reject in Go")
	}
	// A SQL NULL must be invalid (guard not bypassable via NULL).
	if sb := sqlBad(nil); sb != 1 {
		t.Fatalf("NULL operation_id must be invalid, SQL predicate=%d", sb)
	}
	// Storage classes must reject (byte grammar is text-only).
	for _, v := range []any{[]byte("abc"), 42, 3.14} {
		if sb := sqlBad(v); sb != 1 {
			t.Fatalf("storage class %T must be invalid, SQL predicate=%d", v, sb)
		}
	}
}

// TestMigration14RejectsInvalidV13OperationIDRollsBack proves migration 14's
// atomic hardening: a v13 database whose active PENDING row carries a
// MALFORMED-UTF-8 operation_id — admitted by v13's Unicode-codepoint GLOB
// guard, which classifies CAST(X'F4908080' AS TEXT) as an allowed codepoint —
// causes migration 14 to FAIL and roll back byte-identically: the version
// stays 13, and sqlite_master, the migration count, and the offending row are
// all byte-identical. No silent rewrite, deletion, or quarantine of invalid
// active state, ever.
func TestMigration14RejectsInvalidV13OperationIDRollsBack(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 13); err != nil {
		t.Fatalf("apply through v13: %v", err)
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)
	nowNs := timeToNanos(time.Now().UTC())

	// The reviewer's exact probe: a TEXT value carrying the raw bytes
	// F4 90 80 80 (an out-of-range UTF-8 sequence). v13's codepoint GLOB guard
	// DECODES it into characters its allowed ranges admit, so v13 accepts it —
	// this is precisely the malformed-UTF-8 hole migration 14 closes.
	badID := string([]byte{0xF4, 0x90, 0x80, 0x80})
	badHash := feedSignerTestHash("f4908080")
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values (?, ?, ?, ?, 'pending', null, null, null, 0, ?, ?)`,
		badID, reg.ID, topic, badHash[:], nowNs, nowNs); err != nil {
		t.Fatalf("v13 must admit the malformed-UTF-8 operation_id (the migration-14 gap): %v", err)
	}

	preSchema := dumpSQLiteSchema(t, db)
	preRow := dumpOperationRow(t, db, badID)
	preMigs := migrationCount(t, db)

	if err := ApplyMigrations(ctx, db); err == nil {
		t.Fatal("migration 14 must fail when hardening encounters a malformed-UTF-8 v13 operation_id")
	}
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 13 {
		t.Fatalf("version must stay 13 on adversarial migration 14, got %d (err %v)", v, err)
	}
	if got := migrationCount(t, db); got != preMigs {
		t.Fatalf("schema_migrations must be untouched after rollback: had %d, now %d", preMigs, got)
	}
	if !bytes.Equal(dumpSQLiteSchema(t, db), preSchema) {
		t.Fatal("sqlite_master must be byte-identical after migration 14 rollback (no trigger installed)")
	}
	if got := dumpOperationRow(t, db, badID); !bytes.Equal(got, preRow) {
		t.Fatalf("offending row must be byte-identical after rollback: %q", got)
	}
}

// TestMigration14AcceptsValidV13OperationIDRowsUpgrade proves the supported
// upgrade: every schema-admitted v13 active row whose operation_id obeys the
// BYTE-EXACT grammar (the 64-hex ComputeOperationID forms and valid printable
// punctuation) upgrades to version 14 cleanly, with the byte-exact identity
// triggers installed (a subsequent malformed-UTF-8 INSERT is rejected, where
// v13 admitted it) and every row intact.
func TestMigration14AcceptsValidV13OperationIDRowsUpgrade(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 13); err != nil {
		t.Fatalf("apply through v13: %v", err)
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)
	ref := strings.Repeat("ab", 32)
	nowNs := timeToNanos(time.Now().UTC())

	pendingIDs := []string{strings.Repeat("a", 64), "op-idA1-2.3_4:5"}
	for _, opID := range pendingIDs {
		ph := feedSignerTestHash(opID)
		if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
			(operation_id, registry_id, topic, request_hash, state, result_json,
			 claim_token, lease_until, attempts, created_at, updated_at)
			values (?, ?, ?, ?, 'pending', null, null, null, 0, ?, ?)`,
			opID, reg.ID, topic, ph[:], nowNs, nowNs); err != nil {
			t.Fatalf("seed pending %q: %v", opID, err)
		}
	}
	sucOp := strings.Repeat("b", 64)
	sucResult := string(publish.CanonicalFeedCommitResultJSON(publish.FeedCommitResult{OperationID: sucOp, Feed: topic, Reference: ref}))
	sh := feedSignerTestHash(sucOp)
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values (?, ?, ?, ?, 'succeeded', ?, null, null, 0, ?, ?)`,
		sucOp, reg.ID, topic, sh[:], sucResult, nowNs, nowNs); err != nil {
		t.Fatalf("seed succeeded %q: %v", sucOp, err)
	}

	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("valid v13 rows must upgrade to 14: %v", err)
	}
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 16 {
		t.Fatalf("expected version 16, got %d (err %v)", v, err)
	}
	if sqliteObjectCount(t, db, "trigger", "feed_signer_operation_id_ins") != 1 ||
		sqliteObjectCount(t, db, "trigger", "feed_signer_operation_id_upd") != 1 {
		t.Fatal("byte-exact identity triggers must be installed after upgrade")
	}
	// The hardened guard now rejects what v13 admitted.
	postHash := feedSignerTestHash("post-upgrade")
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values (cast(X'F4908080' as text), ?, ?, ?, 'pending', null, null, null, 0, ?, ?)`,
		reg.ID, topic, postHash[:], nowNs, nowNs); err == nil {
		t.Fatal("post-upgrade malformed-UTF-8 operation_id must be rejected")
	}
	var gotSuc []byte
	if err := db.QueryRowContext(ctx, `select result_json from feed_signer_operations where operation_id = ?`, sucOp).Scan(&gotSuc); err != nil {
		t.Fatal(err)
	}
	if string(gotSuc) != sucResult {
		t.Fatalf("succeeded row must be untouched by the upgrade: %s", gotSuc)
	}
	var pendCount int
	if err := db.QueryRowContext(ctx, `select count(*) from feed_signer_operations where state='pending'`).Scan(&pendCount); err != nil {
		t.Fatal(err)
	}
	if pendCount != len(pendingIDs) {
		t.Fatalf("pending rows must be untouched by the upgrade, got %d", pendCount)
	}
}

func dumpSQLiteSchema(t *testing.T, db *sql.DB) []byte {
	t.Helper()
	var buf bytes.Buffer
	rows, err := db.Query(`select type, name, tbl_name, sql from sqlite_master order by type, name`)
	if err != nil {
		t.Fatalf("dump sqlite_master: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var typ, name, tbl string
		var sql sql.NullString
		if err := rows.Scan(&typ, &name, &tbl, &sql); err != nil {
			t.Fatal(err)
		}
		buf.WriteString(typ + "|" + name + "|" + tbl + "|" + sql.String + "\n")
	}
	return buf.Bytes()
}

func dumpOperationRow(t *testing.T, db *sql.DB, opID string) []byte {
	t.Helper()
	var (
		regID      int64
		topic      string
		hash       []byte
		state      string
		result     sql.NullString
		created, _ int64
	)
	if err := db.QueryRow(`select registry_id, topic, request_hash, state, result_json, created_at, updated_at
		from feed_signer_operations where operation_id = ?`, opID).
		Scan(&regID, &topic, &hash, &state, &result, &created, &created); err != nil {
		t.Fatalf("dump operation row %q: %v", opID, err)
	}
	return append([]byte(fmt.Sprintf("%d|%s|%x|%s|%s|%d|%d", regID, topic, hash, state, result.String, created, created)), 0)
}

func migrationCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`select count(*) from schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	return n
}
