package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"reflect"
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
	if version != 8 {
		t.Fatalf("expected schema version 7, got %d", version)
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
	if rows != 8 {
		t.Fatalf("expected 8 migration rows, got %d", rows)
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
	if version != 8 {
		t.Fatalf("expected schema version 7 after upgrade, got %d", version)
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
	if version != 8 {
		t.Fatalf("expected version 7, got %d", version)
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
		if version != 8 {
			t.Fatalf("expected version 7, got %d", version)
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
		if version != 8 {
			t.Fatalf("expected version 7, got %d", version)
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
		if version != 8 {
			t.Fatalf("expected version 7, got %d", version)
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
