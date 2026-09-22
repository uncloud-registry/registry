package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Migration 7 hardens the jobs table and closes the INSERT-side
// provisioning_state gap that migration 6 left open. These tests pin:
//   - the new INSERT guard trigger (migration 6 only guarded UPDATE);
//   - every hardened jobs-table invariant under direct SQL (no store helpers);
//   - that a malformed v6 row ROLLS BACK byte-equivalently (version stays 6,
//     no triggers, no tables, no data touched);
//   - that every legitimate v6 row upgrades byte-for-byte with ID intact.

const (
	mig7Auth  = `{"version":1,"defaultAccess":"deny","repos":{}}`
	mig7Stamp = `{"version":1,"defaultPolicy":{"batchID":"batch-1","allowPushFor":["role:write"]},"repos":{}}`
)

func mig7Now() string { return time.Now().UTC().Format(time.RFC3339) }

// seedV6ProvisionedRegistry builds a genuine v6 database (migrations 1-6) with
// one registry and its two bootstrap jobs created through the production store
// writer, returning the raw DB and the store (for direct-SQL assertions).
func seedV6ProvisionedRegistry(t *testing.T) (*sql.DB, *Store) {
	t.Helper()
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 6); err != nil {
		t.Fatalf("build v6 schema: %v", err)
	}
	// registries.owner_user_id references users(id).
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"owner@example.com", "hash", mig7Now()); err != nil {
		t.Fatalf("seed owner user: %v", err)
	}
	store := &Store{DB: db}
	reg := Registry{
		Slug: "alice", Host: "alice.registry.example", ENSName: "alice.eth",
		OwnerUserID: 1, FeedOwnerAddress: "0xaaaa", DefaultStampBatchID: "batch-1",
		AnonymousPull: true,
	}
	if _, err := store.CreateProvisionedRegistry(ctx, reg, newTestFeedKeyCipher(t), []byte("feed-key-material"), []byte(mig7Auth), []byte(mig7Stamp)); err != nil {
		t.Fatalf("seed provisioned registry at v6: %v", err)
	}
	return db, store
}

// jobsRows returns the row provenance of a freshly applied migration: the
// registry_publication_jobs table contents as a canonical string for
// byte-equivalence comparisons (every column, ordered by id).
func jobsRowsFingerprint(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`select id, registry_id, kind, state, payload_json, object_ref, feed_ref,
		attempts, next_attempt_at, coalesce(claimed_until,''), claimed_by, last_error, created_at, coalesce(completed_at,'')
		from registry_publication_jobs order by id`)
	if err != nil {
		t.Fatalf("fingerprint jobs: %v", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var vals [14]string
		if err := rows.Scan(&vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5], &vals[6],
			&vals[7], &vals[8], &vals[9], &vals[10], &vals[11], &vals[12], &vals[13]); err != nil {
			t.Fatalf("scan fingerprint: %v", err)
		}
		for i := range vals {
			b.WriteString(vals[i])
			b.WriteByte('|')
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func TestMigration7UpgradePreservesLegitRowsByteEquivalent(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 6); err != nil {
		t.Fatalf("build v6 schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"owner@example.com", "hash", mig7Now()); err != nil {
		t.Fatalf("seed owner user: %v", err)
	}
	store := &Store{DB: db}
	reg := Registry{Slug: "x", Host: "x.registry.example", ENSName: "x.eth", OwnerUserID: 1,
		FeedOwnerAddress: "0xbbbb", DefaultStampBatchID: "b", AnonymousPull: false}
	if _, err := store.CreateProvisionedRegistry(ctx, reg, newTestFeedKeyCipher(t), []byte("k"), []byte(mig7Auth), []byte(mig7Stamp)); err != nil {
		t.Fatalf("seed v6 registry: %v", err)
	}
	// Drive one job to 'claimed' and the other to 'succeeded' with full refs so
	// the upgrade exercises every column's hardened CHECKs.
	now := mig7Now()
	if _, err := db.ExecContext(ctx, `update registry_publication_jobs set state='claimed', claimed_by='worker-1', claimed_until=? where kind='auth'`, now); err != nil {
		t.Fatalf("claim auth job at v6: %v", err)
	}
	if _, err := db.ExecContext(ctx, `update registry_publication_jobs set state='succeeded', object_ref='0xobj', feed_ref='feed://0xbbbb/aa', completed_at=? where kind='stamp'`, now); err != nil {
		t.Fatalf("complete stamp job at v6: %v", err)
	}
	before := jobsRowsFingerprint(t, db)

	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migration 7: %v", err)
	}
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil || version != 7 {
		t.Fatalf("expected version 7, got %d (err %v)", version, err)
	}
	after := jobsRowsFingerprint(t, db)
	if after != before {
		t.Fatalf("upgrade must preserve job rows byte-for-byte\nBEFORE:\n%s\nAFTER:\n%s", before, after)
	}
}

func TestMigration7RejectsMalformedJobsOnUpgradeRollsBackByteEquivalent(t *testing.T) {
	db, _ := seedV6ProvisionedRegistry(t)
	ctx := context.Background()
	before := jobsRowsFingerprint(t, db)

	// Corrupt the auth job's payload into a non-JSON blob. Migration 7's copy
	// will reject it and the whole migration MUST roll back.
	if _, err := db.ExecContext(ctx, `update registry_publication_jobs set payload_json='not json {[{' where kind='auth'`); err != nil {
		t.Fatalf("corrupt payload at v6: %v", err)
	}
	corrupted := jobsRowsFingerprint(t, db)
	if corrupted == before {
		t.Fatal("expected the corrupted row to differ from the baseline")
	}

	if err := ApplyMigrations(ctx, db); err == nil {
		t.Fatal("expected migration 7 to reject a malformed v6 job, got nil")
	}

	// Version must stay 6 and every table/trigger must be untouched.
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil || version != 6 {
		t.Fatalf("rollback must keep version 6, got %d (err %v)", version, err)
	}
	// No hardened clone may remain.
	var clone int
	if err := db.QueryRow(`select count(*) from sqlite_master where type='table' and name='registry_publication_jobs_new'`).Scan(&clone); err != nil {
		t.Fatalf("check clone table: %v", err)
	}
	if clone != 0 {
		t.Fatal("rollback must not leave a hardened clone table behind")
	}
	// The INSERT guard trigger must NOT be installed (whole migration rolled back).
	var ins int
	if err := db.QueryRow(`select count(*) from sqlite_master where type='trigger' and name='registries_provisioning_state_guard_insert'`).Scan(&ins); err != nil {
		t.Fatalf("check insert guard trigger: %v", err)
	}
	if ins != 0 {
		t.Fatal("rollback must not leave the migration-7 INSERT guard trigger behind")
	}
	// The jobs table still holds the exact corrupted v6 row — migration rolled back without touching data.
	after := jobsRowsFingerprint(t, db)
	if after != corrupted {
		t.Fatalf("rollback must leave jobs data byte-identical to pre-migration\nWANT:\n%s\nGOT:\n%s", corrupted, after)
	}
}

func TestMigration7InstallsInsertGuardTrigger(t *testing.T) {
	db, _ := seedV6ProvisionedRegistry(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migration 7: %v", err)
	}

	// migration 6 only guarded UPDATE; migration 7 must also guard INSERT.
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, provisioning_state, created_at)
		values ('bogus','b.registry.example','b.eth',1,'0x', '', 'b', 0, 'not_a_state', ?)`, mig7Now()); err == nil {
		t.Fatal("expected INSERT of bogus provisioning_state to be rejected on v7, got nil")
	}
	// The UPDATE guard (migration 6) must also still be present.
	if _, err := db.ExecContext(ctx, `update registries set provisioning_state='banana'`); err == nil {
		t.Fatal("expected UPDATE to bogus provisioning_state to be rejected, got nil")
	}
	// Legitimate vocabulary values still pass on INSERT.
	for _, st := range []string{"provisioning", "ready", "failed"} {
		if _, err := db.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, provisioning_state, created_at)
			values (?,?,?,?,?, '', ?,0,?,?)`,
			"reg"+st, st+".registry.example", st+".eth", 1, "0x", "b", st, mig7Now()); err != nil {
			t.Fatalf("valid provisioning_state %q rejected: %v", st, err)
		}
	}
}

func TestMigration7JobsInvariantEnforcement(t *testing.T) {
	db, _ := seedV6ProvisionedRegistry(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migration 7: %v", err)
	}
	now := mig7Now()
	type tc struct {
		name    string
		cols    []string
		vals    []interface{}
		wantErr bool
	}
	cases := []tc{
		{"invalid kind", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "manifest", "pending", mig7Auth, 0, now, now}, true},
		{"invalid state", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "auth", "executing", mig7Auth, 0, now, now}, true},
		{"payload not json", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "auth", "pending", `not-json`, 0, now, now}, true},
		{"payload not object", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "auth", "pending", `[]`, 0, now, now}, true},
		{"auth missing defaultAccess", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "auth", "pending", `{"version":1}`, 0, now, now}, true},
		{"stamp missing batchID", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "stamp", "pending", `{"version":1}`, 0, now, now}, true},
		{"attempts negative", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "auth", "pending", mig7Auth, -1, now, now}, true},
		{"attempts over bound", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "auth", "pending", mig7Auth, 1025, now, now}, true},
		{"next_attempt_at malformed", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "auth", "pending", mig7Auth, 0, "garbage", now}, true},
		{"created_at malformed", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "auth", "pending", mig7Auth, 0, now, "garbage"}, true},
		{"lease on a non-claimed job", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at", "claimed_by", "claimed_until"}, []interface{}{1, "stamp", "pending", mig7Stamp, 0, now, now, "w", now}, true},
		{"claimed state without lease", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at", "claimed_by", "claimed_until"}, []interface{}{1, "auth", "claimed", mig7Auth, 0, now, now, "", nil}, true},
		{"succeeded without completion", []string{"registry_id", "kind", "state", "payload_json", "object_ref", "feed_ref", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "auth", "succeeded", mig7Auth, "0x", "feed://x/aa", 1, now, now}, true},
		{"object_ref over bound", []string{"registry_id", "kind", "state", "payload_json", "object_ref", "attempts", "next_attempt_at", "created_at"}, []interface{}{1, "auth", "pending", mig7Auth, strings.Repeat("0", 129), 0, now, now}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stmt := buildInsert("registry_publication_jobs", c.cols, c.vals)
			_, err := db.ExecContext(ctx, stmt, c.vals...)
			if c.wantErr && err == nil {
				t.Fatalf("expected invariant rejection, got success: %s", stmt)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected valid insert to succeed: %v", err)
			}
		})
	}

	// A second registry so the "valid" variants can exercise fresh
	// (registry_id, kind) pairs without colliding on the seeded registry's jobs.
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, provisioning_state, created_at)
		values ('valid1','valid1.registry.example','v1.eth',1,'0x', '', 'b', 0, 'ready', ?)`, now); err != nil {
		t.Fatalf("seed second registry: %v", err)
	}
	// Legitimate coherence variants must pass.
	valid := []tc{
		{"claimed with full lease", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at", "claimed_by", "claimed_until"}, []interface{}{2, "auth", "claimed", mig7Auth, 1, now, now, "worker-2", now}, false},
		{"succeeded with refs and completion", []string{"registry_id", "kind", "state", "payload_json", "object_ref", "feed_ref", "attempts", "next_attempt_at", "created_at", "completed_at"}, []interface{}{2, "stamp", "succeeded", mig7Stamp, "0xobj", "feed://x/aa", 1, now, now, now}, false},
	}
	for _, c := range valid {
		t.Run(c.name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, buildInsert("registry_publication_jobs", c.cols, c.vals), c.vals...); err != nil {
				t.Fatalf("expected valid insert to succeed: %v", err)
			}
		})
	}
}

// buildInsert renders an INSERT with the given column order and value
// placeholders for a table, using explicit columns so the tests do not depend
// on the table's physical column order (the migration framework uses the same
// discipline).
func buildInsert(table string, cols []string, vals []interface{}) string {
	ph := make([]string, len(vals))
	for i := range ph {
		ph[i] = "?"
	}
	return fmt.Sprintf("insert into %s (%s) values (%s)", table, strings.Join(cols, ", "), strings.Join(ph, ", "))
}
