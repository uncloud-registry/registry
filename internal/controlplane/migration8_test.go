package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// Migration 8 closes the storage-class / dynamic-typing / JSON-shape / calendar
// loopholes migration 7's CHECKs could not reach and moves journal timestamps
// to exact INTEGER Unix NANOSECONDS (so sub-millisecond RFC3339Nano instants
// survive byte-for-byte, never truncated to the millisecond). These tests pin:
//   - a genuine v7 DB upgrades with every row's ID, content, and timestamp
//     MEANING preserved exactly (text RFC3339 → integer ns, same instant to the
//     last nanosecond);
//   - a malformed v7 row (calendar-invalid or non-canonical timestamp, or a
//     payload that only the weaker v7 JSON checks accept) ROLLS BACK
//     byte-equivalently (version stays 7, no clone, no data touched);
//   - every new v8 invariant is enforced against adversarial INSERTs and
//     UPDATEs on direct SQL: JSON type/value tricks, NULL/three-valued
//     comparisons, REAL/numeric-text attempts, invalid timestamp storage
//     classes, and every incoherent state/ownership/completion combination,
//     including completed_at present IFF state=succeeded.

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

	baseNanos, _ := parseCanonicalUTCNanos(base)
	leaseNanos, _ := parseCanonicalUTCNanos(lease)
	doneNanos, _ := parseCanonicalUTCNanos(done)
	retryNanos, _ := parseCanonicalUTCNanos("2026-09-22T13:00:00Z")
	return db, map[string]int64{
		"base": baseNanos, "lease": leaseNanos, "done": doneNanos, "retry": retryNanos,
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
		jobNow:  time.Now().UTC().UnixNano(),
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
		{"pending with completed_at", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at", "completed_at", "last_error"},
			[]interface{}{1, "auth", "pending", auth, base, base, base, ""}},
		{"claimed with completed_at", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at", "claimed_by", "claimed_until", "completed_at"},
			[]interface{}{1, "auth", "claimed", auth, base, base, "w", base + 30000, base}},
		{"succeeded missing completed_at covered above — pending/claimed/failed must all forbid it", []string{"registry_id", "kind", "state", "payload_json", "next_attempt_at", "created_at"},
			[]interface{}{1, "auth", "succeeded", auth, base, base}},
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
		{"pending job with completed_at", "kind='stamp' and registry_id=" + fmt.Sprint(updReg2), "completed_at=" + fmt.Sprint(base), nil},
		{"claimed job completed_at without lease", "kind='stamp' and registry_id=" + fmt.Sprint(updReg2), "state='claimed', claimed_by='w', completed_at=" + fmt.Sprint(base), nil},
		{"claimed job with completed_at across transition", "kind='stamp' and registry_id=" + fmt.Sprint(updReg2), "state='claimed', claimed_by='w', claimed_until=" + fmt.Sprint(base+30000) + ", completed_at=" + fmt.Sprint(base), nil},
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

// subNsV7Times holds sub-millisecond and nanosecond-precision RFC3339Nano
// instants (in genuinely DIFFERENT milliseconds) that a millisecond-truncating
// migration would destroy by rounding them onto the same whole millisecond.
var subNsV7Times = []string{
	"2026-09-22T12:00:00.000000001Z",
	"2026-09-22T12:00:00.000000123Z",
	"2026-09-22T12:00:00.000000999Z",
	"2026-09-22T12:00:00.001000000Z",
	"2026-09-22T12:00:00.999999999Z",
	"2026-09-22T12:00:01.999999999Z",
}

// TestMigration8PreservesSubNanosecondInstantsExactly proves migration 8 stores
// each RFC3339Nano v7 timestamp as the EXACT int64 nanosecond instant — a
// sub-millisecond / nanosecond-precision value is never truncated to the
// millisecond. Each distinct input must round-trip to its own canonical instant,
// and distinct sub-millisecond fractions must NOT collapse onto the same
// nanosecond counter (a millisecond-truncating store would collapse all six).
func TestMigration8PreservesSubNanosecondInstantsExactly(t *testing.T) {
	seen := map[int64]string{}
	for _, ts := range subNsV7Times {
		want, err := parseCanonicalUTCNanos(ts)
		if err != nil {
			t.Fatalf("parse %q: %v", ts, err)
		}
		// Distinct input instants must map to distinct nanoseconds (no collapse).
		if prev, ok := seen[want]; ok && prev != ts {
			t.Fatalf("distinct instants %q and %q collapsed to the same nanosecond %d", prev, ts, want)
		}
		seen[want] = ts

		// The nanosecond instant must be the EXACT input (nanosToTime recovers
		// it; comparing canonical RFC3339Nano strings).
		if got := nanosToTime(want).Format(time.RFC3339Nano); got != normalizedNano(ts) {
			t.Fatalf("nanosecond conversion changed the instant: %q -> %q", ts, got)
		}
	}
	if len(seen) != len(subNsV7Times) {
		t.Fatalf("expected all %d distinct instants, got %d distinct nanosecond counters", len(subNsV7Times), len(seen))
	}
}

// TestMigration8ParseRejectsOutOfRangeAndNoncanonicalNanos proves the strict
// RFC3339Nano→nanosecond conversion (used by migration 8) rejects anything that
// is not canonical UTC or whose instant exceeds the int64-nanosecond span —
// it never clamps or truncates, so a malformed or out-of-range v7 row rolls the
// migration back rather than silently storing a wrong instant.
func TestMigration8ParseRejectsOutOfRangeAndNoncanonicalNanos(t *testing.T) {
	for _, bad := range []string{
		"2026-09-22T12:00:00",            // no 'Z'
		"2026-09-22T12:00:00+02:00",      // non-canonical offset (not UTC)
		"2026-13-40T25:61:61Z",           // calendar/clock invalid
		"2026-09-22T12:00:00Zjunk",       // trailing garbage (fails time.Parse)
		"9999-12-31T23:59:59.999999999Z", // year 9999 → int64-nanosecond overflow
	} {
		if _, err := parseCanonicalUTCNanos(bad); err == nil {
			t.Fatalf("expected %q to be rejected as non-canonical or out of range", bad)
		}
	}
	// A canonical UTC instant at the int64-nanosecond extremes must be accepted
	// exactly (recovered via nanosToTime must equal the same instant).
	for _, good := range []string{
		"2200-01-01T00:00:00.123456789Z",
		"1678-01-01T00:00:00Z",
	} {
		ns, err := parseCanonicalUTCNanos(good)
		if err != nil {
			t.Fatalf("expected %q to convert: %v", good, err)
		}
		if got := nanosToTime(ns).Format(time.RFC3339Nano); got != normalizedNano(good) {
			t.Fatalf("round-trip changed %q -> %q", good, got)
		}
	}
}

// normalizedNano renders an RFC3339Nano string in canonical form for a
// byte-stable comparison (Go may pad or abbreviate trailing zeros differently
// from the literal input, so equality is judged on the normalized instant, not
// the exact text).
func normalizedNano(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return t.Format(time.RFC3339Nano)
}

// Exact int64-nanosecond extremes, rendered canonically (verified against
// time.Unix(0, math.MinInt64/MaxInt64).UTC().Format(RFC3339Nano)).
const (
	exactMinNanoString = "1677-09-21T00:12:43.145224192Z" // == time.Unix(0, math.MinInt64).UTC()
	exactMaxNanoString = "2262-04-11T23:47:16.854775807Z" // == time.Unix(0, math.MaxInt64).UTC()
)

// TestMigration8ParseAcceptsExactInt64Boundaries proves the parse→nanosecond
// conversion accepts BOTH int64-nanosecond extremes EXACTLY — converting to
// math.MinInt64 and math.MaxInt64 respectively — and preserves every in-range
// instant to the last nanosecond. The historical implementation compared whole
// seconds against a symmetric bound, so it wrongly REJECTED the exact minimum
// (whose unix second is -9223372037 < -(MaxInt64/1e9)) and silently WRAPPED the
// maximum's fractional overflow; both must now be exact.
func TestMigration8ParseAcceptsExactInt64Boundaries(t *testing.T) {
	minNanos := int64(math.MinInt64)
	maxNanos := int64(math.MaxInt64)
	for _, tc := range []struct {
		s    string
		want int64
	}{
		{exactMinNanoString, minNanos},
		{exactMaxNanoString, maxNanos},
	} {
		ns, err := parseCanonicalUTCNanos(tc.s)
		if err != nil {
			t.Fatalf("parse(%q): %v", tc.s, err)
		}
		if ns != tc.want {
			t.Fatalf("parse(%q) = %d, want exact %d", tc.s, ns, tc.want)
		}
		// Round-trip must recover the identical canonical instant (no drift).
		if got := nanosToTime(ns).Format(time.RFC3339Nano); got != normalizedNano(tc.s) {
			t.Fatalf("round-trip changed %q -> %q", tc.s, got)
		}
	}
	// A value one nanosecond off the extremes must survive as its own instant
	// too (the edges are exact, not clamped).
	oneIn := []struct {
		s    string
		want int64
	}{
		{"1677-09-21T00:12:43.145224193Z", minNanos + 1},
		{"2262-04-11T23:47:16.854775806Z", maxNanos - 1},
	}
	for _, tc := range oneIn {
		ns, err := parseCanonicalUTCNanos(tc.s)
		if err != nil {
			t.Fatalf("parse(%q): %v", tc.s, err)
		}
		if ns != tc.want {
			t.Fatalf("parse(%q) = %d, want %d", tc.s, ns, tc.want)
		}
	}
}

// TestMigration8ParseRejectsOutsideBoundaryNanos proves the conversion rejects
// anything one nanosecond outside either int64 edge (plus the specific
// fractional-overflow value the old whole-second bound silently wrapped), and
// never clamps. It cannot round a boundary nanosecond into range.
func TestMigration8ParseRejectsOutsideBoundaryNanos(t *testing.T) {
	for _, bad := range []string{
		// One nanosecond BELOW the exact minimum (underflows math.MinInt64).
		"1677-09-21T00:12:43.145224191Z",
		// One nanosecond ABOVE the exact maximum (overflows math.MaxInt64).
		"2262-04-11T23:47:16.854775808Z",
		// ~145ms past the maximum in the same second — the fractional overflow
		// the old whole-second bound (sec == MaxInt64/1e9) accepted and wrapped.
		"2262-04-11T23:47:16.999999999Z",
		// Clearly beyond the span (a whole additional year).
		"2263-04-11T23:47:16.854775807Z",
		"1676-09-21T00:12:43.145224192Z",
	} {
		if ns, err := parseCanonicalUTCNanos(bad); err == nil {
			t.Fatalf("expected %q to be rejected as out of the int64-nanosecond range, got %d", bad, ns)
		}
	}
}

// TestMigration8PreservesBoundaryInstantsAtBothEdges proves a genuine v7 row
// whose journal timestamps sit at BOTH int64-nanosecond extremes upgrades to
// v8 with those EXACT integer nanosecond values preserved (math.MinInt64 and
// math.MaxInt64), and the resulting succeeded row still satisfies every v8
// coherence invariant including completed_at IFF state=succeeded.
func TestMigration8PreservesBoundaryInstantsAtBothEdges(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 7); err != nil {
		t.Fatalf("build v7 schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`,
		"owner@example.com", "hash", "2026-09-22T12:00:00Z"); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if _, err := db.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key,
		 default_stamp_batch_id, anonymous_pull, provisioning_state, created_at)
		values ('edge', 'edge.registry.example', 'edge.eth', 1, '0xffff', '', 'batch-1', 0, 'ready', ?)`,
		"2026-09-22T12:00:00Z"); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	// One succeeded job: created_at/next_attempt_at at the exact minimum,
	// completed_at at the exact maximum. Every v7 domain/invariant still holds
	// (both are canonical RFC3339Nano UTC text passing the v7 GLOB).
	if _, err := db.ExecContext(ctx, fmt.Sprintf(`insert into registry_publication_jobs
		(registry_id, kind, state, payload_json, object_ref, feed_ref, attempts,
		 next_attempt_at, claimed_by, last_error, created_at, completed_at)
		values (1, 'auth', 'succeeded', ?, 'ref-edge', 'feed://0xffff/edge', 1,
			'%s', '', '', '%s', '%s')`,
		exactMinNanoString, exactMinNanoString, exactMaxNanoString),
		mig7Auth); err != nil {
		t.Fatalf("seed succeeded boundary job: %v", err)
	}

	if err := applyMigrationsThrough(ctx, db, 8); err != nil {
		t.Fatalf("apply migration 8: %v", err)
	}
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil || version != 8 {
		t.Fatalf("expected version 8, got %d (err %v)", version, err)
	}
	var (
		state, objectRef, feedRef, lastError string
		nextAt, createdAt, completedAt       int64
	)
	if err := db.QueryRow(`select state, object_ref, feed_ref, last_error,
		next_attempt_at, created_at, completed_at
		from registry_publication_jobs where id = 1`).
		Scan(&state, &objectRef, &feedRef, &lastError, &nextAt, &createdAt, &completedAt); err != nil {
		t.Fatalf("read migrated boundary job: %v", err)
	}
	if state != "succeeded" || objectRef != "ref-edge" || feedRef != "feed://0xffff/edge" || lastError != "" {
		t.Fatalf("succeeded coherence lost after migration: state=%q refs=%q/%q err=%q", state, objectRef, feedRef, lastError)
	}
	if nextAt != int64(math.MinInt64) || createdAt != int64(math.MinInt64) {
		t.Fatalf("minimum edge not preserved exactly: next_attempt_at=%d created_at=%d want MinInt64=%d", nextAt, createdAt, int64(math.MinInt64))
	}
	if completedAt != int64(math.MaxInt64) {
		t.Fatalf("maximum edge not preserved exactly: completed_at=%d want MaxInt64=%d", completedAt, int64(math.MaxInt64))
	}
}
