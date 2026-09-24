package staging

// Exact staging-schema v2 migration tests. Fixtures are built ONLY from the
// frozen committed manifest artifacts (the three independently frozen VERSION
// manifests) re-embedded here — never from the production schemaDDL
// constants — so a unilateral change to either the creation DDL or a golden
// cannot silently reshape what migration is tested against.

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test-local re-embeddings of the three committed frozen schemas. Keeping a
// dedicated embed in the test file makes the fixtures independently authored
// from the production go:embed (a parity test binds the production golden to
// the production DDL, so the two cannot silently drift together).
//
//go:embed schema_golden_v1_precleanup.json
var goldenPreCleanupJSON []byte

//go:embed schema_golden_v1_cleanup.json
var goldenCleanupV1JSON []byte

//go:embed schema_golden_v2.json
var goldenV2JSON []byte

func mustLoadTestManifest(t *testing.T, data []byte) *schemaManifest {
	t.Helper()
	var m schemaManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("test golden not parseable: %v", err)
	}
	if m.Version < 1 || m.Version > 2 || len(m.Objects) == 0 {
		t.Fatalf("test golden has an unexpected version/object set: %d/%d", m.Version, len(m.Objects))
	}
	return &m
}

// fixtureFromGolden builds a standalone database by executing the FROZEN
// manifest object bodies in manifest order (dependency-safe: tables first,
// then indexes, then triggers) and recording the manifest's own version row,
// then runs seed on top. This is the exact historical shape a committed
// green task would have produced — never a hand-authored table.
func fixtureFromGolden(t *testing.T, gold *schemaManifest, seed func(db *sql.DB)) string {
	t.Helper()
	dbPath := filepath.Join(tempPrivate(t), "fixture.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	for i, o := range gold.Objects {
		if _, err := db.Exec(o.SQL); err != nil {
			db.Close()
			t.Fatalf("fixture object %d (%s): %v", i, o.Name, err)
		}
	}
	if _, err := db.Exec(`insert into staging_schema (version, applied_at) values (?, 1)`, gold.Version); err != nil {
		db.Close()
		t.Fatalf("fixture version row: %v", err)
	}
	if seed != nil {
		seed(db)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	return dbPath
}

// --- seed rows -----------------------------------------------------------------

const (
	seedRepo  = "backend/api"
	seedActor = "user:alice"
)

func seedFullLifecycle(t *testing.T, db *sql.DB) {
	t.Helper()
	insert := func(id, state string, offset int64, createdAt, expiresAt int64, createToken *string) {
		t.Helper()
		if createToken == nil {
			if _, err := db.Exec(
				`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?,?,?,?,?,?,?)`,
				id, seedRepo, seedActor, state, offset, createdAt, expiresAt); err != nil {
				t.Fatalf("seed %s row: %v", state, err)
			}
			return
		}
		if _, err := db.Exec(
			`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?,?,?,?,?,?,?,?)`,
			id, seedRepo, seedActor, state, offset, createdAt, expiresAt, *createToken); err != nil {
			t.Fatalf("seed %s row: %v", state, err)
		}
	}

	// Active (born active, offset 0, no metadata, no create token).
	insert(strings.Repeat("a", 64), "active", 0, 1000, 2000, nil)
	// Creating (distinct create token, offset 0, no metadata).
	tok := strings.Repeat("9a", 32)
	insert(strings.Repeat("b", 64), "creating", 0, 3000, 4000, &tok)

	// Finalized: born active, matching staged blob, then finalize metadata
	// with size == offset (offset stays 0).
	fid := strings.Repeat("c", 64)
	digest := "sha256:" + strings.Repeat("d", 64)
	beeRef := strings.Repeat("e", 64)
	insert(fid, "active", 0, 5000, 6000, nil)
	if _, err := db.Exec(
		`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at)
		 values (?,?,?,?,?,?,?,?,?)`,
		fid, seedRepo, seedActor, digest, beeRef, 0, "application/octet-stream", 5000, 6000); err != nil {
		t.Fatalf("seed finalize blob: %v", err)
	}
	if _, err := db.Exec(
		`update upload_sessions set state='finalized', digest=?, bee_ref=?, media_type=?, size=? where id=?`,
		digest, beeRef, "application/octet-stream", 0, fid); err != nil {
		t.Fatalf("seed finalize transition: %v", err)
	}

	// Deleting tombstone: born active, then transitioned to deleting.
	did := strings.Repeat("f", 64)
	insert(did, "active", 0, 8000, 9000, nil)
	if _, err := db.Exec(`update upload_sessions set state='deleting' where id=?`, did); err != nil {
		t.Fatalf("seed deleting transition: %v", err)
	}
}

// migSession is a full-order snapshot of one upload_sessions row. cleanup is
// a pointer so the pre-cleanup shape (no such column ⇒ nil) is distinguishable
// from an explicit NULL present in a cleanup-token-era row.
type migSession struct {
	id, repo, actor, state       string
	offset, createdAt, expiresAt int64
	createToken                  *string
	cleanupToken                 *string
	digest, beeRef, mediaType    *string
	size                         *int64
}

type migBlob struct {
	uploadID, repo, actor     string
	digest, beeRef, mediaType string
	size                      int64
	createdAt, expiresAt      int64
}

func strp(s string) *string { return &s }
func i64p(v int64) *int64   { return &v }

func sval(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func ival(p *int64) string {
	if p == nil {
		return "nil"
	}
	return fmt.Sprint(*p)
}

// migSessKey and migBlobKey render a row as a canonical comparable string so
// pre/post migration rows can be checked field-by-field without comparing
// pointer identities.
func migSessKey(r migSession) string {
	return fmt.Sprintf("%s|%s|%s|%s|%d|%d|%d|%s|%s|%s|%s|%s|%s",
		r.id, r.repo, r.actor, r.state, r.offset, r.createdAt, r.expiresAt,
		sval(r.createToken), sval(r.cleanupToken), sval(r.digest), sval(r.beeRef), sval(r.mediaType), ival(r.size))
}

func migBlobKey(b migBlob) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d|%d",
		b.uploadID, b.repo, b.actor, b.digest, b.beeRef, b.mediaType, b.size, b.createdAt, b.expiresAt)
}

func migSessKeys(rs []migSession) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = migSessKey(r)
	}
	return out
}

func migBlobKeys(rs []migBlob) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = migBlobKey(r)
	}
	return out
}

func migScanSessions(t *testing.T, db *sql.DB) []migSession {
	t.Helper()
	rows, err := db.Query(`select id, repo, actor, state, offset, created_at, expires_at,
		create_token, digest, bee_ref, media_type, size from upload_sessions order by id`)
	if err != nil {
		t.Fatalf("select sessions: %v", err)
	}
	defer rows.Close()
	var out []migSession
	for rows.Next() {
		var r migSession
		var ct, dg, br, mt sql.NullString
		var sz sql.NullInt64
		if err := rows.Scan(&r.id, &r.repo, &r.actor, &r.state, &r.offset, &r.createdAt, &r.expiresAt,
			&ct, &dg, &br, &mt, &sz); err != nil {
			t.Fatalf("scan session: %v", err)
		}
		if ct.Valid {
			r.createToken = strp(ct.String)
		}
		if dg.Valid {
			r.digest = strp(dg.String)
		}
		if br.Valid {
			r.beeRef = strp(br.String)
		}
		if mt.Valid {
			r.mediaType = strp(mt.String)
		}
		if sz.Valid {
			r.size = i64p(sz.Int64)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("sessions rows: %v", err)
	}
	return out
}

func scanSessionsCleanup(t *testing.T, db *sql.DB) []migSession {
	t.Helper()
	rows, err := db.Query(`select id, repo, actor, state, offset, created_at, expires_at,
		create_token, cleanup_token, digest, bee_ref, media_type, size from upload_sessions order by id`)
	if err != nil {
		t.Fatalf("select sessions: %v", err)
	}
	defer rows.Close()
	var out []migSession
	for rows.Next() {
		var r migSession
		var ct, cu, dg, br, mt sql.NullString
		var sz sql.NullInt64
		if err := rows.Scan(&r.id, &r.repo, &r.actor, &r.state, &r.offset, &r.createdAt, &r.expiresAt,
			&ct, &cu, &dg, &br, &mt, &sz); err != nil {
			t.Fatalf("scan session: %v", err)
		}
		if ct.Valid {
			r.createToken = strp(ct.String)
		}
		if cu.Valid {
			r.cleanupToken = strp(cu.String)
		}
		if dg.Valid {
			r.digest = strp(dg.String)
		}
		if br.Valid {
			r.beeRef = strp(br.String)
		}
		if mt.Valid {
			r.mediaType = strp(mt.String)
		}
		if sz.Valid {
			r.size = i64p(sz.Int64)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("sessions rows: %v", err)
	}
	return out
}

func migScanBlobs(t *testing.T, db *sql.DB) []migBlob {
	t.Helper()
	rows, err := db.Query(`select upload_id, repo, actor, digest, bee_ref, media_type, size, created_at, expires_at
		from staged_blobs order by upload_id`)
	if err != nil {
		t.Fatalf("select blobs: %v", err)
	}
	defer rows.Close()
	var out []migBlob
	for rows.Next() {
		var b migBlob
		if err := rows.Scan(&b.uploadID, &b.repo, &b.actor, &b.digest, &b.beeRef, &b.mediaType, &b.size, &b.createdAt, &b.expiresAt); err != nil {
			t.Fatalf("scan blob: %v", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("blob rows: %v", err)
	}
	return out
}

// versionOf reads the single version row value via a raw handle.
func versionOf(t *testing.T, dbPath string) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	var v int64
	if err := db.QueryRow(`select version from staging_schema`).Scan(&v); err != nil {
		t.Fatalf("version query: %v", err)
	}
	return v
}

func tableExists(t *testing.T, dbPath, name string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`select count(*) from sqlite_master where type='table' and name=?`, name).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n > 0
}

func assertCleanupColumn(t *testing.T, dbPath string, present bool) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`pragma table_info(upload_sessions)`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "cleanup_token" {
			found = true
		}
	}
	if found != present {
		t.Fatalf("cleanup_token column present=%v want=%v", found, present)
	}
}

// migrateThenOpen migrates the fixture through the real open path and returns
// the opened handle (or the open error). openStagingDB performs the exact
// migration and full v2 verification.
func migrateThenOpen(t *testing.T, dbPath string) (*sql.DB, error) {
	t.Helper()
	return openStagingDB(context.Background(), dbPath, 0)
}

// ---------------------------------------------------------------------------
// Both committed v1 predecessor shapes open and upgrade atomically to v2.
// ---------------------------------------------------------------------------

func TestMigratePreCleanupV1ToV2(t *testing.T) {
	pre := mustLoadTestManifest(t, goldenPreCleanupJSON)
	if pre.Version != 1 {
		t.Fatalf("pre-cleanup manifest must be frozen at v1, got %d", pre.Version)
	}
	dbPath := fixtureFromGolden(t, pre, func(db *sql.DB) { seedFullLifecycle(t, db) })
	beforeSess := migScanSessions(t, migRaw(t, dbPath))
	beforeBlob := migScanBlobs(t, migRaw(t, dbPath))
	if len(beforeSess) != 4 || len(beforeBlob) != 1 {
		t.Fatalf("pre-migration row counts sessions=%d blobs=%d", len(beforeSess), len(beforeBlob))
	}

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate pre-cleanup v1: %v", err)
	}
	db.Close()

	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after migration = %d, want %d", v, latestSchemaVersion)
	}
	assertCleanupColumn(t, dbPath, true)

	after := scanSessionsCleanup(t, migRaw(t, dbPath))
	if len(after) != len(beforeSess) {
		t.Fatalf("session count changed across migration: %d -> %d", len(beforeSess), len(after))
	}
	for i := range beforeSess {
		b, a := beforeSess[i], after[i]
		if migSessKey(b) != migSessKey(a) {
			t.Fatalf("row %s not preserved across migration: %+v -> %+v", b.id, b, a)
		}
		// A pre-cleanup row never had cleanup provenance: migration must NOT
		// invent one — every row's cleanup_token stays NULL.
		if a.cleanupToken != nil {
			t.Fatalf("migration invented cleanup provenance on row %s: %q", a.id, *a.cleanupToken)
		}
	}
	blobs := migScanBlobs(t, migRaw(t, dbPath))
	if fmt.Sprint(migBlobKeys(blobs)) != fmt.Sprint(migBlobKeys(beforeBlob)) {
		t.Fatalf("staged blob not preserved byte-for-byte: %+v -> %+v", beforeBlob, blobs)
	}

	// Reopen is idempotent: still v2, still the same submitted rows.
	db2, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("idempotent reopen: %v", err)
	}
	db2.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version drifted on reopen = %d", v)
	}
}

func TestMigrateCleanupV1ToV2(t *testing.T) {
	clean := mustLoadTestManifest(t, goldenCleanupV1JSON)
	if clean.Version != 1 {
		t.Fatalf("cleanup-token predecessor manifest must be frozen at v1, got %d", clean.Version)
	}
	dbPath := fixtureFromGolden(t, clean, func(db *sql.DB) { seedFullLifecycle(t, db) })
	beforeSess := scanSessionsCleanup(t, migRaw(t, dbPath))

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate cleanup-token v1: %v", err)
	}
	db.Close()

	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after migration = %d, want %d", v, latestSchemaVersion)
	}
	after := scanSessionsCleanup(t, migRaw(t, dbPath))
	if len(after) != len(beforeSess) {
		t.Fatalf("session count changed across cleanup migration: %d -> %d", len(beforeSess), len(after))
	}
	for i := range beforeSess {
		b, a := beforeSess[i], after[i]
		if migSessKey(b) != migSessKey(a) {
			t.Fatalf("cleanup predecessor row %s not preserved exactly: %+v -> %+v", b.id, b, a)
		}
	}
}

// migRaw opens a plain handle to inspect a post-rollback / post-migration DB.
func migRaw(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw %s: %v", dbPath, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// seededCleanupContainerRow produces a v1-cleanup fixture whose active row
// carries an already-set cleanup token (created via the genuine activation
// transition), proving provenance survives migration and is never touched.
func TestMigrateCleanupV1PreservesExistingCleanupToken(t *testing.T) {
	clean := mustLoadTestManifest(t, goldenCleanupV1JSON)
	dbPath := fixtureFromGolden(t, clean, func(db *sql.DB) {
		tok := strings.Repeat("7e", 32)
		id := strings.Repeat("a", 64)
		if _, err := db.Exec(
			`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token)
			 values (?,?,?, 'creating', 0, 1000, 2000, ?)`, id, seedRepo, seedActor, tok); err != nil {
			t.Fatalf("seed creating: %v", err)
		}
		// Activation: create_token atomically becomes cleanup_token.
		if _, err := db.Exec(
			`update upload_sessions set state='active', create_token=NULL, cleanup_token=? where id=?`, tok, id); err != nil {
			t.Fatalf("seed activation: %v", err)
		}
	})

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate cleanup v1 with live cleanup token: %v", err)
	}
	db.Close()

	after := scanSessionsCleanup(t, migRaw(t, dbPath))
	if len(after) != 1 || after[0].state != "active" {
		t.Fatalf("unexpected rows after migration: %+v", after)
	}
	if after[0].cleanupToken == nil || *after[0].cleanupToken != strings.Repeat("7e", 32) {
		t.Fatalf("cleanup provenance lost across migration: %v", after[0].cleanupToken)
	}
}

// ---------------------------------------------------------------------------
// Fresh v2 creation, reopen idempotency, and a rejected foreign schema.
// ---------------------------------------------------------------------------

func TestMigrateFreshV2AndReopenIdempotent(t *testing.T) {
	dbPath := filepath.Join(tempPrivate(t), "fresh.db")
	db, err := openStagingDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("fresh v2 create: %v", err)
	}
	db.Close()
	g2 := mustLoadTestManifest(t, goldenV2JSON)
	if g2.Version != 2 {
		t.Fatalf("target manifest must be v2, got %d", g2.Version)
	}
	assertCleanupColumn(t, dbPath, true)
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("fresh version = %d, want %d", v, latestSchemaVersion)
	}
	before := hashFile(t, dbPath)
	db2, err := openStagingDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("reopen fresh v2: %v", err)
	}
	db2.Close()
	if after := hashFile(t, dbPath); after != before {
		t.Fatal("idempotent reopen modified the v2 database bytes")
	}
}

// ---------------------------------------------------------------------------
// Malformed lookalikes of BOTH predecessor shapes fail before any mutation.
// ---------------------------------------------------------------------------

// mutatedFixture builds a predecessor fixture then applies a DDL mutation to
// one security-critical object body; open must reject with byte identity and
// no sidecars. mutation operates on the golden object bodies by name.
func mutatedFixture(t *testing.T, gold *schemaManifest, name string, mutate func(body string) string) string {
	t.Helper()
	// materialize the fixture, then rebuild the file with one object changed
	base := fixtureFromGolden(t, gold, nil)
	// Directly re-author: open DB to mutate is hard for schema; rebuild by
	// writing a fresh DB from the manifest bodies with the mutation applied.
	dbPath := filepath.Join(tempPrivate(t), "mutated.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, o := range gold.Objects {
		body := o.SQL
		if o.Name == name {
			body = mutate(body)
		}
		if _, err := db.Exec(body); err != nil {
			db.Close()
			t.Fatalf("mutated object %s: %v", o.Name, err)
		}
	}
	if _, err := db.Exec(`insert into staging_schema (version, applied_at) values (?, 1)`, gold.Version); err != nil {
		db.Close()
		t.Fatalf("version row: %v", err)
	}
	db.Close()
	_ = os.Remove(base)
	return dbPath
}

// attacker-weakening mutations covering every security-critical object class.
func weakeningMutations(gold *schemaManifest) []struct {
	name   string
	mutate func(string) string
	desc   string
} {
	return []struct {
		name   string
		mutate func(string) string
		desc   string
	}{
		{"upload_sessions", func(b string) string {
			return strings.Replace(b, "length(hex(id)) = 128", "length(hex(id)) >= 4", 1)
		}, "session id CHECK loosened"},
		{"upload_sessions", func(b string) string {
			return strings.Replace(b, "state in ('active','creating','finalized','deleting')", "state in ('active','finalized','deleting')", 1)
		}, "creating state removed"},
		{"upload_sessions", func(b string) string {
			return strings.Replace(b, "expires_at > created_at", "expires_at >= created_at", 1)
		}, "expiry-before-creation allowed"},
		{"upload_sessions", func(b string) string {
			return strings.Replace(b, "create_token is null", "1", 1)
		}, "creating rows allowed without a token"},
		{"staged_blobs", func(b string) string {
			return strings.Replace(b, "references upload_sessions(id) on delete cascade", "references upload_sessions(id)", 1)
		}, "FK without cascade"},
		{"idx_sessions_expiry", func(b string) string { return b + " -- trailing" }, "index body changed"},
		{"trg_session_insert", func(b string) string {
			return strings.Replace(b, "then raise(abort, 'session insert must be active or creating')", "then raise(abort, 'x')", 1)
		}, "insert trigger body changed"},
		{"trg_session_state", func(b string) string {
			return strings.Replace(b, "'cannot return to active'", "'x'", 1)
		}, "state trigger body changed"},
		{"trg_session_token", func(b string) string {
			return strings.Replace(b, "when old.create_token is null and new.create_token is not null then raise(abort, 'cannot set create token after insert')", "", 1)
		}, "create-token injection allowed"},
		{"trg_blob_insert", func(b string) string {
			return strings.Replace(b, "= 'active'", "in ('active','finalized')", 1)
		}, "blob joinable to a finalized session"},
		{"trg_blob_delete", func(b string) string {
			return strings.Replace(b, "'deleting'", "'active'", 1)
		}, "blob deletable from a live session"},
	}
}

func TestMigrateMalformedPredecessorRejectedBeforeMutation(t *testing.T) {
	for _, gold := range []*schemaManifest{
		mustLoadTestManifest(t, goldenPreCleanupJSON),
		mustLoadTestManifest(t, goldenCleanupV1JSON),
	} {
		gold := gold
		for _, tc := range weakeningMutations(gold) {
			if !objectHasName(gold, tc.name) {
				continue
			}
			t.Run(fmt.Sprintf("golden_v%d/%s", gold.Version, tc.desc), func(t *testing.T) {
				dbPath := mutatedFixture(t, gold, tc.name, tc.mutate)
				before := hashFile(t, dbPath)
				if db, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
					db.Close()
					t.Fatalf("malformed lookalike accepted (version %d): %s", gold.Version, tc.desc)
				}
				assertRejectedDBClean(t, dbPath, before)
			})
		}
	}
}

func objectHasName(gold *schemaManifest, name string) bool {
	for _, o := range gold.Objects {
		if o.Name == name {
			return true
		}
	}
	return false
}

// An ambiguous v1 wrapper: same object bodies but a foreign version value must
// be rejected — v1 predecessors are recognized ONLY by their exact shape.
func TestMigrateRejectsAmbiguousVersionAndForeignVersion(t *testing.T) {
	clean := mustLoadTestManifest(t, goldenCleanupV1JSON)
	// session id check loosened on a version-2-labelled cleanup shape
	dbPath := filepath.Join(tempPrivate(t), "ambig.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, o := range clean.Objects {
		if _, err := db.Exec(o.SQL); err != nil {
			db.Close()
			t.Fatalf("object %s: %v", o.Name, err)
		}
	}
	if _, err := db.Exec(`insert into staging_schema (version, applied_at) values (9, 1)`); err != nil {
		db.Close()
		t.Fatalf("version row: %v", err)
	}
	db.Close()
	before := hashFile(t, dbPath)
	if db2, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
		db2.Close()
		t.Fatal("foreign version value on a known shape was accepted")
	}
	assertRejectedDBClean(t, dbPath, before)
}

// ---------------------------------------------------------------------------
// Atomic rollback under fault injection (after the row copy, and immediately
// before the version record) preserves exact predecessor rows/schema/version
// and leaves no temporary rebuild artifacts.
// ---------------------------------------------------------------------------

func TestMigrateAtomicRollbackAfterCopy(t *testing.T) {
	pre := mustLoadTestManifest(t, goldenPreCleanupJSON)
	dbPath := fixtureFromGolden(t, pre, func(db *sql.DB) { seedFullLifecycle(t, db) })
	beforeSess := migScanSessions(t, migRaw(t, dbPath))
	beforeBlob := migScanBlobs(t, migRaw(t, dbPath))

	migrationCopyFault = errors.New("injected copy fault")
	t.Cleanup(func() { migrationCopyFault = nil })
	if db, err := migrateThenOpen(t, dbPath); err == nil {
		db.Close()
		t.Fatal("copy fault must abort the migration")
	}
	migrationCopyFault = nil

	// Exact predecessor preserved: version row, column absence, every row,
	// no temporary rebuild table.
	if v := versionOf(t, dbPath); v != 1 {
		t.Fatalf("version after failed migration = %d, want 1", v)
	}
	assertCleanupColumn(t, dbPath, false)
	if tableExists(t, dbPath, "upload_sessions_new") {
		t.Fatal("temporary rebuild table survived a rolled-back migration")
	}
	afterSess := migScanSessions(t, migRaw(t, dbPath))
	if fmt.Sprint(migSessKeys(afterSess)) != fmt.Sprint(migSessKeys(beforeSess)) {
		t.Fatalf("session rows changed by a rolled-back migration:\nbefore=%+v\nafter=%+v", beforeSess, afterSess)
	}
	afterBlob := migScanBlobs(t, migRaw(t, dbPath))
	if fmt.Sprint(migBlobKeys(afterBlob)) != fmt.Sprint(migBlobKeys(beforeBlob)) {
		t.Fatalf("blob rows changed by a rolled-back migration: %+v -> %+v", beforeBlob, afterBlob)
	}

	// With the fault cleared the SAME database migrates cleanly to v2.
	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("reopen after fault cleared: %v", err)
	}
	db.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("post-fault migration version = %d, want %d", v, latestSchemaVersion)
	}
}

func TestMigrateAtomicRollbackBeforeVersionRecord(t *testing.T) {
	pre := mustLoadTestManifest(t, goldenPreCleanupJSON)
	dbPath := fixtureFromGolden(t, pre, func(db *sql.DB) { seedFullLifecycle(t, db) })
	beforeSess := migScanSessions(t, migRaw(t, dbPath))

	migrationVersionFault = errors.New("injected version fault")
	t.Cleanup(func() { migrationVersionFault = nil })
	if db, err := migrateThenOpen(t, dbPath); err == nil {
		db.Close()
		t.Fatal("version-record fault must abort the migration")
	}
	migrationVersionFault = nil

	if v := versionOf(t, dbPath); v != 1 {
		t.Fatalf("version advanced despite fault = %d, want 1", v)
	}
	assertCleanupColumn(t, dbPath, false)
	if tableExists(t, dbPath, "upload_sessions_new") {
		t.Fatal("temporary rebuild table survived a rolled-back migration")
	}
	afterSess := migScanSessions(t, migRaw(t, dbPath))
	if fmt.Sprint(migSessKeys(afterSess)) != fmt.Sprint(migSessKeys(beforeSess)) {
		t.Fatalf("session rows changed by a faulted-before-version migration: %+v -> %+v", beforeSess, afterSess)
	}

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("reopen after version fault cleared: %v", err)
	}
	db.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("post-fault migration version = %d, want %d", v, latestSchemaVersion)
	}
}

// ---------------------------------------------------------------------------
// Foreign keys remain enforced on every connection after a migration (pooled
// service path) — an orphan staged blob insert must still be rejected.
// ---------------------------------------------------------------------------

func TestMigrateForeignKeysRemainOnPooledConnections(t *testing.T) {
	pre := mustLoadTestManifest(t, goldenPreCleanupJSON)
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	if err := os.Mkdir(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir spool: %v", err)
	}
	dbPath := fixtureAt(t, pre, spoolDir)

	svc, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("NewService over a migrated v1-pre database: %v", err)
	}
	defer svc.Close()

	// Direct SQL on a held pool connection: an orphan blob must be rejected,
	// proving the FK constraint is physically present and enabled.
	ctx := context.Background()
	conn, err := svc.pool.acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { svc.pool.release(conn) }()
	var fk int
	if err := conn.QueryRowContext(ctx, `pragma foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("pragma foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Fatalf("foreign_keys = %d after migration, want 1", fk)
	}
	if _, err := conn.ExecContext(ctx,
		`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at)
		 values ('`+strings.Repeat("0", 64)+`', 'backend/api', 'user:alice', 'sha256:`+strings.Repeat("1", 64)+`', '`+
			strings.Repeat("2", 64)+`', 0, 'application/octet-stream', 1, 2)`); err == nil {
		t.Fatal("orphan staged blob insert accepted after migration (FK missing/disabled)")
	}
}

// fixtureAt writes the fixture into dir (so the service can build its own
// private directory structure around the same database file).
func fixtureAt(t *testing.T, gold *schemaManifest, spoolDir string) string {
	t.Helper()
	dbPath := filepath.Join(filepath.Dir(spoolDir), "staging.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	for _, o := range gold.Objects {
		if _, err := db.Exec(o.SQL); err != nil {
			db.Close()
			t.Fatalf("fixture object %s: %v", o.Name, err)
		}
	}
	if _, err := db.Exec(`insert into staging_schema (version, applied_at) values (?, 1)`, gold.Version); err != nil {
		db.Close()
		t.Fatalf("version row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	return dbPath
}
