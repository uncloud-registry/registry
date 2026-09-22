package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Migration 8 closes the storage-class / dynamic-typing / JSON-shape / calendar
// loopholes migration 7's CHECKs could not reach and moves journal timestamps
// to exact INTEGER Unix milliseconds. These tests pin:
//   - a genuine v7 DB upgrades with every row's ID, content, and timestamp
//     MEANING preserved exactly (text RFC3339 → integer ms, same instant);
//   - a malformed v7 row (calendar-invalid or non-canonical timestamp, or a
//     payload that only the weaker v7 JSON checks accept) ROLLS BACK
//     byte-equivalently (version stays 7, no clone, no data touched);
//   - every new v8 invariant is enforced against adversarial INSERTs and
//     UPDATEs on direct SQL: JSON type/value tricks, NULL/three-valued
//     comparisons, REAL/numeric-text attempts, invalid timestamp storage
//     classes, and every incoherent state/ownership/completion combination.

const mig8Base = "2026-09-22T12:00:00Z"

// mig8LegacyOther is a legitimate alternative canonical v7 timestamp used for
// derived columns (leases, completion).
const mig8LegacyOther = "2026-09-22T12:00:30Z"

// seedV7ProvisionedRegistry builds a genuine v7 database (migrations 1-7) with
// two registries and four jobs covering every state: succeeded (reg 1 auth),
// pending-with-retry (reg 1 stamp), claimed (reg 2 auth), failed (reg 2
// stamp). All journal timestamps are canonical RFC3339 TEXT (the genuine v7
// store representation). Returns the raw DB and the expected post-migration
// millisecond values for later meaning-preservation assertions.
func seedV7ProvisionedRegistry(t *testing.T) (*sql.DB, map[string]int64) {
	t.Helper()
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 7); err != nil {
		t.Fatalf("build v7 schema: %v", err)
	}
	base := mig8Base
	lease := mig8LegacyOther
	done := "2026-09-22T12:00:10Z"
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"owner@example.com", "hash", base); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	// Two registries (v7 insert guard requires a vocabulary value).
	for _, r := range []struct{ slug, host string }{
		{"v8a", "v8a.registry.example"},
		{"v8b", "v8b.registry.example"},
	} {
		if _, err := db.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key,
			 default_stamp_batch_id, anonymous_pull, provisioning_state, created_at)
			values (?, ?, ?, 1, '0xffff', '', 'batch-1', 0, 'provisioning', ?)`,
			r.slug, r.host, r.slug+".eth", base); err != nil {
			t.Fatalf("seed registry %s at v7: %v", r.slug, err)
		}
	}
	seed := func(regID int64, kind, state, payload, objectRef, feedRef, attempts, nextAt, claimedBy, claimedUntil, lastError, completedAt string) {
		t.Helper()
		cu, co := "null", "null"
		if claimedUntil != "" {
			cu = "'" + claimedUntil + "'"
		}
		if completedAt != "" {
			co = "'" + completedAt + "'"
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf(`insert into registry_publication_jobs
			(registry_id, kind, state, payload_json, object_ref, feed_ref, attempts,
			 next_attempt_at, claimed_until, claimed_by, last_error, created_at, completed_at)
			values (?, ?, ?, ?, ?, ?, ?, ?, %s, ?, ?, ?, %s)`,
			cu, co),
			regID, kind, state, payload, objectRef, feedRef, attempts, nextAt, claimedBy, lastError, base); err != nil {
			t.Fatalf("seed %s job at v7: %v", kind, err)
		}
	}
	seed(1, "auth", "succeeded", mig7Auth, "ref-auth-1", "feed://0xffff/auth", "1", base, "", "", "", done)
	seed(1, "stamp", "pending", mig7Stamp, "ref-stamp-1", "feed://0xffff/stamp", "2", "2026-09-22T13:00:00Z", "", "", "feed update failed", "")
	seed(2, "auth", "claimed", mig7Auth, "ref-auth-2", "", "1", base, "worker-1", lease, "", "")
	seed(2, "stamp", "failed", mig7Stamp, "", "", "8", base, "", "", "upload failed", "")

	baseMillis, _ := parseCanonicalUTCMillis(base)
	leaseMillis, _ := parseCanonicalUTCMillis(lease)
	doneMillis, _ := parseCanonicalUTCMillis(done)
	retryMillis, _ := parseCanonicalUTCMillis("2026-09-22T13:00:00Z")
	return db, map[string]int64{
		"base": baseMillis, "lease": leaseMillis, "done": doneMillis, "retry": retryMillis,
	}
}

// v8JobRowFingerprint renders every column of the jobs table as a canonical
// string (integer timestamps for v8) for byte-equivalence comparisons.
func v8JobRowFingerprint(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`select id, registry_id, kind, state, payload_json, object_ref, feed_ref,
		attempts, next_attempt_at, coalesce(claimed_until,-1), claimed_by, last_error, created_at, coalesce(completed_at,-1)
		from registry_publication_jobs order by id`)
	if err != nil {
		t.Fatalf("v8 fingerprint: %v", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var vals [14]string
		if err := rows.Scan(&vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5], &vals[6],
			&vals[7], &vals[8], &vals[9], &vals[10], &vals[11], &vals[12], &vals[13]); err != nil {
			t.Fatalf("scan v8 fingerprint: %v", err)
		}
		for i := range vals {
			b.WriteString(vals[i])
			b.WriteByte('|')
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// TestMigration8UpgradePreservesLegitV7RowsAndMeaning proves a genuine v7 DB
// upgrades to v8 with every row's ID, content, and timestamp MEANING preserved
// exactly: text RFC3339 instants become their exact integer millisecond
// instants, and everything else is byte-identical.
func TestMigration8UpgradePreservesLegitV7RowsAndMeaning(t *testing.T) {
	db, ms := seedV7ProvisionedRegistry(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 8); err != nil {
		t.Fatalf("apply migration 8: %v", err)
	}
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil || version != 8 {
		t.Fatalf("expected version 8, got %d (err %v)", version, err)
	}

	rows, err := db.Query(`select id, registry_id, kind, state, payload_json, object_ref, feed_ref,
		attempts, next_attempt_at, coalesce(claimed_until, 0), claimed_by, last_error, created_at, coalesce(completed_at, 0)
		from registry_publication_jobs order by id`)
	if err != nil {
		t.Fatalf("read v8 jobs: %v", err)
	}
	defer rows.Close()
	type got struct {
		id, regID, attempts, nextAt, claimedUntil, createdAt, completedAt int64
		kind, state, objectRef, feedRef, claimedBy, lastError             string
		payload                                                           []byte
	}
	var gots []got
	for rows.Next() {
		var g got
		if err := rows.Scan(&g.id, &g.regID, &g.kind, &g.state, &g.payload, &g.objectRef, &g.feedRef,
			&g.attempts, &g.nextAt, &g.claimedUntil, &g.claimedBy, &g.lastError, &g.createdAt, &g.completedAt); err != nil {
			t.Fatalf("scan v8 job: %v", err)
		}
		gots = append(gots, g)
	}
	if len(gots) != 4 {
		t.Fatalf("expected 4 jobs after migration, got %d", len(gots))
	}

	want := []struct {
		id, regID, attempts int64
		kind, state         string
		payload             string
		objectRef, feedRef  string
		nextAt              int64
		claimedUntil        int64
		claimedBy           string
		lastError           string
		createdAt           int64
		completedAt         int64
	}{
		{1, 1, 1, "auth", "succeeded", mig7Auth, "ref-auth-1", "feed://0xffff/auth", ms["base"], 0, "", "", ms["base"], ms["done"]},
		{2, 1, 2, "stamp", "pending", mig7Stamp, "ref-stamp-1", "feed://0xffff/stamp", ms["retry"], 0, "", "feed update failed", ms["base"], 0},
		{3, 2, 1, "auth", "claimed", mig7Auth, "ref-auth-2", "", ms["base"], ms["lease"], "worker-1", "", ms["base"], 0},
		{4, 2, 8, "stamp", "failed", mig7Stamp, "", "", ms["base"], 0, "", "upload failed", ms["base"], 0},
	}
	for i, w := range want {
		g := gots[i]
		if g.id != w.id || g.regID != w.regID || g.attempts != w.attempts || g.kind != w.kind || g.state != w.state {
			t.Fatalf("job %d identity/state mismatch: got %+v want %+v", i, g, w)
		}
		if string(g.payload) != w.payload || g.objectRef != w.objectRef || g.feedRef != w.feedRef ||
			g.claimedBy != w.claimedBy || g.lastError != w.lastError {
			t.Fatalf("job %d content mismatch: got %+v want %+v", i, g, w)
		}
		if g.nextAt != w.nextAt || g.createdAt != w.createdAt {
			t.Fatalf("job %d must preserve timestamp instants exactly: got next=%d created=%d want next=%d created=%d",
				i, g.nextAt, g.createdAt, w.nextAt, w.createdAt)
		}
		if g.claimedUntil != w.claimedUntil || g.completedAt != w.completedAt {
			t.Fatalf("job %d lease/completion instant mismatch: got %d/%d want %d/%d",
				i, g.claimedUntil, g.completedAt, w.claimedUntil, w.completedAt)
		}
		// The migrated INTEGER columns must really be integers (storage class).
		var nextStorage, createdStorage string
		if err := db.QueryRow(`select typeof(next_attempt_at), typeof(created_at) from registry_publication_jobs where id = ?`, g.id).
			Scan(&nextStorage, &createdStorage); err != nil {
			t.Fatalf("read storage classes: %v", err)
		}
		if nextStorage != "integer" || createdStorage != "integer" {
			t.Fatalf("job %d timestamps must be stored as integer, got %s/%s", g.id, nextStorage, createdStorage)
		}
	}
}

// TestMigration8RejectsMalformedV7TimestampRollsBackByteEquivalent proves a v7
// row whose timestamp passes the weak v7 GLOB but is calendar-invalid (or not
// canonical UTC) FAILS migration 8 with a full atomic rollback: version stays
// 7, no clone remains, and the data is byte-identical.
func TestMigration8RejectsMalformedV7TimestampRollsBackByteEquivalent(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  string
	}{
		{"calendar-invalid month", "2026-99-99T00:00:00Z"},
		{"calendar-invalid day", "2026-02-30T00:00:00Z"},
		{"impossible clock", "2026-09-22T99:00:00Z"},
		{"non-canonical offset", "2026-09-22T12:00:00+02:00"},
		{"trailing garbage", "2026-09-22T12:00:00Zjunk"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := seedV7ProvisionedRegistry(t)
			ctx := context.Background()
			before := v8JobRowFingerprint(t, db)
			if _, err := db.ExecContext(ctx, `update registry_publication_jobs set next_attempt_at = ? where id = 1`, tc.bad); err != nil {
				t.Fatalf("corrupt timestamp at v7: %v", err)
			}
			corrupted := v8JobRowFingerprint(t, db)
			if corrupted == before {
				t.Fatal("expected the corrupted row to differ from the baseline")
			}
			if err := applyMigrationsThrough(ctx, db, 8); err == nil {
				t.Fatal("expected migration 8 to reject a malformed v7 timestamp, got nil")
			}
			version, err := CurrentSchemaVersion(ctx, db)
			if err != nil || version != 7 {
				t.Fatalf("rollback must keep version 7, got %d (err %v)", version, err)
			}
			var clone int
			if err := db.QueryRow(`select count(*) from sqlite_master where type='table' and name='registry_publication_jobs_new'`).Scan(&clone); err != nil {
				t.Fatalf("check clone: %v", err)
			}
			if clone != 0 {
				t.Fatal("rollback must not leave a v8 clone table behind")
			}
			after := v8JobRowFingerprint(t, db)
			if after != corrupted {
				t.Fatalf("rollback must leave jobs data byte-identical to pre-migration\nWANT:\n%s\nGOT:\n%s", corrupted, after)
			}
		})
	}
}

// TestMigration8RejectsMalformedV7PayloadShapeRollsBack proves a v7 row whose
// payload satisfied the weaker v7 JSON checks (version + defaultAccess present,
// but no defaultRepo) is rejected by v8's exact production-document shape, with
// a full atomic rollback.
func TestMigration8RejectsMalformedV7PayloadShapeRollsBack(t *testing.T) {
	db, _ := seedV7ProvisionedRegistry(t)
	ctx := context.Background()
	before := v8JobRowFingerprint(t, db)
	// Old-shape auth payload: passes v7 (json_valid + $.version + $.defaultAccess)
	// but violates v8 ($.defaultRepo object with pull/push arrays required).
	if _, err := db.ExecContext(ctx, `update registry_publication_jobs set payload_json = ? where id = 1`,
		`{"version":1,"defaultAccess":"deny","repos":{}}`); err != nil {
		t.Fatalf("corrupt payload at v7: %v", err)
	}
	corrupted := v8JobRowFingerprint(t, db)
	if corrupted == before {
		t.Fatal("expected the corrupted row to differ from the baseline")
	}
	if err := applyMigrationsThrough(ctx, db, 8); err == nil {
		t.Fatal("expected migration 8 to reject a weak-shape v7 payload, got nil")
	}
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil || version != 7 {
		t.Fatalf("rollback must keep version 7, got %d (err %v)", version, err)
	}
	after := v8JobRowFingerprint(t, db)
	if after != corrupted {
		t.Fatalf("rollback must leave jobs data byte-identical\nWANT:\n%s\nGOT:\n%s", corrupted, after)
	}
}

// v8JobsEnv is a v8 database with an owner user and the ability to seed fresh
// registries so adversarial job INSERT/UPDATE cases have valid FK targets and
// (registry_id, kind) uniqueness never collides.
type v8JobsEnv struct {
	db      *sql.DB
	regSeq  int64
	regNow  string
	jobNow  int64
	payload map[string]string
}

func newV8JobsEnv(t *testing.T) *v8JobsEnv {
	t.Helper()
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 8); err != nil {
		t.Fatalf("build v8 schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"owner@example.com", "hash", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	return &v8JobsEnv{
		db:      db,
		regNow:  time.Now().UTC().Format(time.RFC3339),
		jobNow:  time.Now().UTC().UnixMilli(),
		payload: map[string]string{"auth": mig7Auth, "stamp": mig7Stamp},
	}
}

func (e *v8JobsEnv) seedRegistry(t *testing.T) int64 {
	t.Helper()
	e.regSeq++
	if _, err := e.db.ExecContext(context.Background(), `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key,
		 default_stamp_batch_id, anonymous_pull, provisioning_state, created_at)
		values (?, ?, ?, 1, '0xffff', '', 'batch-1', 0, 'ready', ?)`,
		fmt.Sprintf("reg%d", e.regSeq), fmt.Sprintf("reg%d.registry.example", e.regSeq),
		fmt.Sprintf("reg%d.eth", e.regSeq), e.regNow); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	return e.regSeq
}

// buildJobsInsert renders an INSERT with named columns/values for the v8 jobs
// table. Omitted columns take their v8 defaults.
func buildJobsInsert(cols []string, vals []interface{}) string {
	ph := make([]string, len(vals))
	for i := range ph {
		ph[i] = "?"
	}
	return fmt.Sprintf("insert into registry_publication_jobs (%s) values (%s)", strings.Join(cols, ", "), strings.Join(ph, ", "))
}

// TestMigration8JobsInvariantEnforcement drives adversarial INSERTs and UPDATEs
// against the hardened v8 schema and proves every individual invariant is
// rejected, while legitimate coherence combinations still pass.
func TestMigration8JobsInvariantEnforcement(t *testing.T) {
	env := newV8JobsEnv(t)
	ctx := context.Background()
	base := env.jobNow
	auth, stamp := env.payload["auth"], env.payload["stamp"]

	// Failing INSERT cases. A fresh (registry, kind) pair is not needed because
	// rejected rows never commit; registry 1 is a valid FK target.
	failing := []struct {
		name string
		cols []string
		vals []interface{}
	}{
		// ---- JSON type/value tricks (auth) ----
		{"auth version as text", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", `{"version":"1","defaultAccess":"deny","defaultRepo":{"pull":[],"push":[]},"repos":{}}`, base, base}},
		{"auth version as real", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", `{"version":1.0,"defaultAccess":"deny","defaultRepo":{"pull":[],"push":[]},"repos":{}}`, base, base}},
		{"auth version missing", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", `{"defaultAccess":"deny","defaultRepo":{"pull":[],"push":[]},"repos":{}}`, base, base}},
		{"auth defaultAccess not deny", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", `{"version":1,"defaultAccess":"allow","defaultRepo":{"pull":[],"push":[]},"repos":{}}`, base, base}},
		{"auth defaultAccess not text", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", `{"version":1,"defaultAccess":1,"defaultRepo":{"pull":[],"push":[]},"repos":{}}`, base, base}},
		{"auth defaultRepo missing", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", `{"version":1,"defaultAccess":"deny","repos":{}}`, base, base}},
		{"auth defaultRepo not object", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", `{"version":1,"defaultAccess":"deny","defaultRepo":[],"repos":{}}`, base, base}},
		{"auth defaultRepo.pull not array", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", `{"version":1,"defaultAccess":"deny","defaultRepo":{"pull":{},"push":[]},"repos":{}}`, base, base}},
		{"auth defaultRepo.push missing", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", `{"version":1,"defaultAccess":"deny","defaultRepo":{"pull":[]},"repos":{}}`, base, base}},
		{"auth repos missing", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", `{"version":1,"defaultAccess":"deny","defaultRepo":{"pull":[],"push":[]}}`, base, base}},
		{"auth repos not object", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", `{"version":1,"defaultAccess":"deny","defaultRepo":{"pull":[],"push":[]},"repos":[]}`, base, base}},
		// ---- JSON type/value tricks (stamp) ----
		{"stamp version as text", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "stamp", "pending", `{"version":"1","defaultPolicy":{"batchID":"b","allowPushFor":[]},"repos":{}}`, base, base}},
		{"stamp defaultPolicy missing", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "stamp", "pending", `{"version":1,"repos":{}}`, base, base}},
		{"stamp batchID empty", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "stamp", "pending", `{"version":1,"defaultPolicy":{"batchID":"","allowPushFor":[]},"repos":{}}`, base, base}},
		{"stamp batchID not text", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "stamp", "pending", `{"version":1,"defaultPolicy":{"batchID":123,"allowPushFor":[]},"repos":{}}`, base, base}},
		{"stamp batchID over bound", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "stamp", "pending", `{"version":1,"defaultPolicy":{"batchID":"` + strings.Repeat("b", 129) + `","allowPushFor":[]},"repos":{}}`, base, base}},
		{"stamp allowPushFor missing", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "stamp", "pending", `{"version":1,"defaultPolicy":{"batchID":"b"},"repos":{}}`, base, base}},
		{"stamp allowPushFor not array", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "stamp", "pending", `{"version":1,"defaultPolicy":{"batchID":"b","allowPushFor":{}},"repos":{}}`, base, base}},
		{"stamp repos missing", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "stamp", "pending", `{"version":1,"defaultPolicy":{"batchID":"b","allowPushFor":[]}}`, base, base}},
		// ---- Storage class / NULL loopholes ----
		{"attempts REAL (non-coercible)", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, 5.5, base, base}},
		{"attempts text", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, "5", base, base}},
		{"attempts negative", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, -1, base, base}},
		{"attempts over bound", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, 1025, base, base}},
		{"attempts NULL", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, nil, base, base}},
		{"object_ref integer", []string{"registry_id", "kind", "state", "payload_json", "object_ref", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, 5, base, base}},
		{"object_ref over bound", []string{"registry_id", "kind", "state", "payload_json", "object_ref", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, strings.Repeat("0", 129), base, base}},
		{"claimed_by over bound", []string{"registry_id", "kind", "state", "payload_json", "claimed_by", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, strings.Repeat("w", 65), base, base}},
		{"last_error over bound", []string{"registry_id", "kind", "state", "payload_json", "last_error", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, strings.Repeat("e", 513), base, base}},
		{"kind not text", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, 7, "pending", auth, base, base}},
		{"state not text", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", 3, auth, base, base}},
		{"kind outside domain", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "manifest", "pending", auth, base, base}},
		{"state outside domain", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "executing", auth, base, base}},
		{"registry_id text", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{"1", "auth", "pending", auth, base, base}},
		{"registry_id zero", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{0, "auth", "pending", auth, base, base}},
		{"registry_id NULL", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{nil, "auth", "pending", auth, base, base}},
		// ---- Timestamp storage classes ----
		{"next_attempt_at text", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, "2026-09-22T12:00:00Z", base}},
		{"next_attempt_at REAL", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, 5.0, base}},
		{"next_attempt_at NULL", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, nil, base}},
		{"created_at text", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, base, "2026-09-22T12:00:00Z"}},
		{"claimed_until text", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at", "claimed_until"},
			[]interface{}{1, "auth", "pending", auth, base, base, "2026-09-22T12:00:00Z"}},
		{"completed_at text", []string{"registry_id", "kind", "state", "payload_json", "object_ref", "feed_ref", "next_attempt_at", "created_at", "completed_at"},
			[]interface{}{1, "auth", "succeeded", auth, "r", "f", base, base, "2026-09-22T12:00:00Z"}},
		// ---- State/ownership/completion coherence ----
		{"pending with lease", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at", "claimed_by", "claimed_until"},
			[]interface{}{1, "auth", "pending", auth, base, base, "w", base}},
		{"claimed without claimed_by", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at", "claimed_by", "claimed_until"},
			[]interface{}{1, "auth", "claimed", auth, base, base, "", base}},
		{"claimed without claimed_until", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at", "claimed_by", "claimed_until"},
			[]interface{}{1, "auth", "claimed", auth, base, base, "w", nil}},
		{"succeeded without object_ref", []string{"registry_id", "kind", "state", "payload_json", "feed_ref", "next_attempt_at", "created_at", "completed_at"},
			[]interface{}{1, "auth", "succeeded", auth, "f", base, base, base}},
		{"succeeded without feed_ref", []string{"registry_id", "kind", "state", "payload_json", "object_ref", "next_attempt_at", "created_at", "completed_at"},
			[]interface{}{1, "auth", "succeeded", auth, "r", base, base, base}},
		{"succeeded without completed_at", []string{"registry_id", "kind", "state", "payload_json", "object_ref", "feed_ref", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "succeeded", auth, "r", "f", base, base}},
		{"succeeded with last_error", []string{"registry_id", "kind", "state", "payload_json", "object_ref", "feed_ref", "next_attempt_at", "created_at", "completed_at", "last_error"},
			[]interface{}{1, "auth", "succeeded", auth, "r", "f", base, base, base, "boom"}},
		{"succeeded with lease held", []string{"registry_id", "kind", "state", "payload_json", "object_ref", "feed_ref", "next_attempt_at", "created_at", "claimed_by", "claimed_until", "completed_at"},
			[]interface{}{1, "auth", "succeeded", auth, "r", "f", base, base, "w", base, base}},
		{"failed without last_error", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "failed", auth, base, base}},
		{"failed with completed_at", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at", "completed_at", "last_error"},
			[]interface{}{1, "auth", "failed", auth, base, base, base, "boom"}},
		{"failed with lease held", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at", "claimed_by", "claimed_until", "last_error"},
			[]interface{}{1, "auth", "failed", auth, base, base, "w", base, "boom"}},
		{"feed_ref without object_ref", []string{"registry_id", "kind", "state", "payload_json", "feed_ref", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", auth, "feed://0xffff/auth", base, base}},
		// A stamp job with an auth payload (kind-inappropriate shape).
		{"stamp job with auth payload", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "stamp", "pending", auth, base, base}},
		{"auth job with stamp payload", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "pending", stamp, base, base}},
	}
	for _, c := range failing {
		t.Run("insert "+c.name, func(t *testing.T) {
			if _, err := env.db.ExecContext(ctx, buildJobsInsert(c.cols, c.vals), c.vals...); err == nil {
				t.Fatalf("expected invariant rejection for %q", c.name)
			}
		})
	}

	// Valid coherence combinations must pass (fresh registries per case).
	valid := []struct {
		name string
		cols []string
		vals []interface{}
	}{
		{"pending base", []string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"},
			[]interface{}{0, "auth", "pending", auth, 0, base, base}},
		{"pending after retry retains error and refs",
			[]string{"registry_id", "kind", "state", "payload_json", "object_ref", "feed_ref", "attempts", "next_attempt_at", "created_at", "last_error"},
			[]interface{}{0, "stamp", "pending", stamp, "r", "f", 3, base, base, "feed update failed"}},
		{"claimed with full lease",
			[]string{"registry_id", "kind", "state", "payload_json", "object_ref", "attempts", "next_attempt_at", "created_at", "claimed_by", "claimed_until"},
			[]interface{}{0, "auth", "claimed", auth, "r", 1, base, base, "worker-1", base + 30000}},
		{"succeeded with refs completion and cleared lease",
			[]string{"registry_id", "kind", "state", "payload_json", "object_ref", "feed_ref", "attempts", "next_attempt_at", "created_at", "completed_at"},
			[]interface{}{0, "stamp", "succeeded", stamp, "r", "f", 1, base, base, base}},
		{"failed with last_error cleared lease",
			[]string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at", "last_error"},
			[]interface{}{0, "auth", "failed", auth, 8, base, base, "upload failed"}},
	}
	for i := range valid {
		regID := env.seedRegistry(t)
		valid[i].vals[0] = regID
		c := valid[i]
		t.Run("valid "+c.name, func(t *testing.T) {
			if _, err := env.db.ExecContext(ctx, buildJobsInsert(c.cols, c.vals), c.vals...); err != nil {
				t.Fatalf("expected valid insert to succeed: %v", err)
			}
		})
	}

	// UPDATE cases: each constraint must also hold on UPDATE.
	updReg := env.seedRegistry(t)
	if _, err := env.db.ExecContext(ctx, buildJobsInsert(
		[]string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"},
		[]interface{}{updReg, "auth", "pending", auth, 0, base, base}), updReg, "auth", "pending", auth, 0, base, base); err != nil {
		t.Fatalf("seed updatable job: %v", err)
	}
	updReg2 := env.seedRegistry(t)
	if _, err := env.db.ExecContext(ctx, buildJobsInsert(
		[]string{"registry_id", "kind", "state", "payload_json", "attempts", "next_attempt_at", "created_at"},
		[]interface{}{updReg2, "stamp", "pending", stamp, 0, base, base}), updReg2, "stamp", "pending", stamp, 0, base, base); err != nil {
		t.Fatalf("seed updatable stamp job: %v", err)
	}
	updates := []struct {
		name  string
		where string
		set   string
		arg   interface{}
	}{
		{"transition to succeeded without completion", "kind='auth' and registry_id=" + fmt.Sprint(updReg), "state='succeeded', object_ref='r', feed_ref='f'", nil},
		{"attempts to text", "kind='auth' and registry_id=" + fmt.Sprint(updReg), "attempts='abc'", nil},
		{"attempts to REAL (non-coercible)", "kind='auth' and registry_id=" + fmt.Sprint(updReg), "attempts=5.5", nil},
		{"attempts negative", "kind='auth' and registry_id=" + fmt.Sprint(updReg), "attempts=-2", nil},
		{"claimed_until to text", "kind='auth' and registry_id=" + fmt.Sprint(updReg), "claimed_until='2026-09-22T12:00:00Z'", nil},
		{"state to bogus", "kind='auth' and registry_id=" + fmt.Sprint(updReg), "state='bogus'", nil},
		{"feed_ref without object_ref", "kind='auth' and registry_id=" + fmt.Sprint(updReg), "feed_ref='feed://0xffff/x'", nil},
		{"succeeded job last_error", "kind='stamp' and registry_id=" + fmt.Sprint(updReg2), "state='succeeded', object_ref='r', feed_ref='f', completed_at=" + fmt.Sprint(base) + ", last_error='boom'", nil},
		{"succeeded job completed_at to NULL", "kind='stamp' and registry_id=" + fmt.Sprint(updReg2),
			"state='succeeded', object_ref='r', feed_ref='f', completed_at=NULL", nil},
		{"failed job with completed_at", "kind='stamp' and registry_id=" + fmt.Sprint(updReg2), "state='failed', last_error='boom', completed_at=" + fmt.Sprint(base), nil},
	}
	for _, u := range updates {
		t.Run("update "+u.name, func(t *testing.T) {
			q := "update registry_publication_jobs set " + u.set + " where " + u.where
			args := []interface{}{}
			if u.arg != nil {
				args = append(args, u.arg)
			}
			if _, err := env.db.ExecContext(ctx, q, args...); err == nil {
				t.Fatalf("expected invariant rejection on update %q", u.name)
			}
		})
	}
	// A legitimate claimed transition on UPDATE must still pass.
	if _, err := env.db.ExecContext(ctx,
		`update registry_publication_jobs set state='claimed', claimed_by='w2', claimed_until=? where kind='auth' and registry_id=?`,
		base+30000, updReg); err != nil {
		t.Fatalf("valid claimed update must succeed: %v", err)
	}
}
