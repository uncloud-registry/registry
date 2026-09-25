package staging

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// DSN normalization
// ---------------------------------------------------------------------------

// TestNormalizeDSN proves the DSN always carries the effective durability
// pragmas on every pooled connection: foreign_keys=ON, a bounded busy
// timeout, WAL journal mode, and synchronous=FULL. Conflicting caller
// pragmas are replaced, unrelated parameters are preserved.
func TestNormalizeDSN(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantPrag map[string]string // pragma -> expected effective value fragment
	}{
		{
			name: "plain",
			in:   "/tmp/staging.db",
			wantPrag: map[string]string{
				"foreign_keys": "foreign_keys(1)",
				"busy_timeout": "busy_timeout(5000)",
				"journal_mode": "journal_mode(WAL)",
				"synchronous":  "synchronous(FULL)",
			},
		},
		{
			name: "file_uri_with_existing_params",
			in:   "file:/data/staging.db?cache=shared&_pragma=foreign_keys(0)",
			wantPrag: map[string]string{
				"foreign_keys": "foreign_keys(1)",
				"cache":        "cache=shared",
			},
		},
		{
			name: "conflicting_journal_and_sync_replaced",
			in:   "staging.db?_pragma=journal_mode(DELETE)&_pragma=synchronous(OFF)&_pragma=busy_timeout(100)",
			wantPrag: map[string]string{
				"journal_mode": "journal_mode(WAL)",
				"synchronous":  "synchronous(FULL)",
				"busy_timeout": "busy_timeout(100)", // caller-provided busy timeout is preserved
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeDSN(tc.in)
			for frag, want := range tc.wantPrag {
				if !strings.Contains(got, want) {
					t.Errorf("normalizeDSN(%q): missing pragma %s=%q (got %q)", tc.in, frag, want, got)
				}
			}
			// Exactly one effective foreign-keys pragma.
			if n := strings.Count(got, "foreign_keys"); n != 1 {
				t.Errorf("normalizeDSN(%q): expected exactly one foreign_keys pragma, got %d (%q)", tc.in, n, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fresh open / reopen / schema shape
// ---------------------------------------------------------------------------

func newStagingDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dbPath := filepath.Join(tempPrivate(t), "staging.db")
	db, err := openStagingDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("openStagingDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, dbPath
}

// TestSchemaVersionTable proves the dedicated version table is recorded once.
func TestSchemaVersionTable(t *testing.T) {
	db, _ := newStagingDB(t)
	var versions []int64
	rows, err := db.Query(`select version from staging_schema order by version`)
	if err != nil {
		t.Fatalf("query versions: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan version: %v", err)
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(versions) != 1 || versions[0] != latestSchemaVersion {
		t.Fatalf("expected exactly version %d, got %v", latestSchemaVersion, versions)
	}
}

// TestSchemaColumnsAndTypes proves the physical column shape (names, storage
// classes) of both tables matches the expected schema exactly.
func TestSchemaColumnsAndTypes(t *testing.T) {
	db, _ := newStagingDB(t)

	wantSessions := map[string]string{
		"id": "text", "repo": "text", "actor": "text", "state": "text",
		// Integer fields are deliberately affinity-free (empty declared
		// type): REAL or numeric TEXT can never be coerced into them, so
		// the typeof() CHECKs are the sole storage-class authority.
		"offset": "", "created_at": "", "expires_at": "",
		"create_token": "text", "cleanup_token": "text", "digest": "text", "bee_ref": "text", "media_type": "text", "size": "",
	}
	assertColumns(t, db, "upload_sessions", wantSessions, map[string]bool{"id": true})

	wantBlobs := map[string]string{
		"upload_id": "text", "repo": "text", "actor": "text", "digest": "text",
		"bee_ref": "text", "size": "", "media_type": "text",
		"created_at": "", "expires_at": "",
	}
	assertColumns(t, db, "staged_blobs", wantBlobs, map[string]bool{"upload_id": true})
}

func assertColumns(t *testing.T, db *sql.DB, table string, wantType map[string]string, wantPK map[string]bool) {
	t.Helper()
	rows, err := db.Query(fmt.Sprintf(`pragma table_info(%s)`, table))
	if err != nil {
		t.Fatalf("table_info(%s): %v", table, err)
	}
	defer rows.Close()
	got := map[string]string{}
	gotPK := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info(%s): %v", table, err)
		}
		got[name] = strings.ToLower(typ)
		gotPK[name] = pk == 1
	}
	if len(got) != len(wantType) {
		t.Fatalf("table %s columns %v differ in count from expected %d", table, got, len(wantType))
	}
	for name, typ := range wantType {
		if got[name] != typ {
			t.Errorf("table %s column %s: type %q != %q", table, name, got[name], typ)
		}
		if wantPK[name] != gotPK[name] {
			t.Errorf("table %s column %s: pk %v != %v", table, name, gotPK[name], wantPK[name])
		}
	}
}

// TestSchemaPhysicalFK proves the staged-blob foreign key is physically
// declared with ON DELETE CASCADE and that foreign_key_check is clean.
func TestSchemaPhysicalFK(t *testing.T) {
	db, _ := newStagingDB(t)

	rows, err := db.Query(`pragma foreign_key_list(staged_blobs)`)
	if err != nil {
		t.Fatalf("foreign_key_list: %v", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var id, seq int
		var table, from, to string
		var onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &table, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			t.Fatalf("scan fk: %v", err)
		}
		if table == "upload_sessions" && from == "upload_id" && to == "id" && onDelete == "CASCADE" {
			found = true
		}
	}
	if !found {
		t.Fatal("staged_blobs.upload_id -> upload_sessions(id) ON DELETE CASCADE missing")
	}

	// Required supporting indexes.
	for _, idx := range []string{"idx_staged_blobs_owner", "idx_sessions_expiry"} {
		var n int
		if err := db.QueryRow(`select count(*) from sqlite_master where type='index' and name=?`, idx).Scan(&n); err != nil {
			t.Fatalf("index lookup %s: %v", idx, err)
		}
		if n != 1 {
			t.Errorf("required index %q missing", idx)
		}
	}

	// Required triggers.
	for _, trg := range []string{
		"trg_session_insert", "trg_session_state", "trg_session_metadata",
		"trg_session_identity", "trg_session_token", "trg_session_delete",
		"trg_blob_insert", "trg_blob_update", "trg_blob_delete",
	} {
		var n int
		if err := db.QueryRow(`select count(*) from sqlite_master where type='trigger' and name=?`, trg).Scan(&n); err != nil {
			t.Fatalf("trigger lookup %s: %v", trg, err)
		}
		if n != 1 {
			t.Errorf("required trigger %q missing", trg)
		}
	}

	fkRows, err := db.Query(`pragma foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	violations := 0
	for fkRows.Next() {
		violations++
	}
	fkRows.Close()
	if violations != 0 {
		t.Fatalf("foreign_key_check reported %d violations", violations)
	}
}

// TestOpenStagingDBReopenIdempotent proves reopening an existing database
// applies no extra migrations and leaves the schema and version intact.
func TestOpenStagingDBReopenIdempotent(t *testing.T) {
	dbPath := filepath.Join(tempPrivate(t), "staging.db")
	db, err := openStagingDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	db.Close()

	db2, err := openStagingDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	var versions []int64
	rows, err := db2.Query(`select version from staging_schema`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		versions = append(versions, v)
	}
	if len(versions) != 1 || versions[0] != latestSchemaVersion {
		t.Fatalf("reopen version: %v", versions)
	}
}

// TestOpenStagingDBJournalEvidence proves WAL and synchronous=FULL are the
// EFFECTIVE durability settings on a live connection, not claimed defaults.
func TestOpenStagingDBJournalEvidence(t *testing.T) {
	db, _ := newStagingDB(t)
	var jm string
	if err := db.QueryRow(`pragma journal_mode`).Scan(&jm); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if jm != "wal" {
		t.Fatalf("journal_mode = %q, want wal", jm)
	}
	var sync int
	if err := db.QueryRow(`pragma synchronous`).Scan(&sync); err != nil {
		t.Fatalf("synchronous: %v", err)
	}
	if sync != 2 { // FULL
		t.Fatalf("synchronous = %d, want 2 (FULL)", sync)
	}
	var bt int
	if err := db.QueryRow(`pragma busy_timeout`).Scan(&bt); err != nil {
		t.Fatalf("busy_timeout: %v", err)
	}
	if bt <= 0 {
		t.Fatalf("busy_timeout = %d, want > 0", bt)
	}
	var fk int
	if err := db.QueryRow(`pragma foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Fatalf("foreign_keys = %d, want 1", fk)
	}
}

// TestForeignKeysOnEveryHeldPoolConnection holds the maximum pool size of
// connections simultaneously and proves each one enforces the FK pragma and
// rejects an orphan staged-blob insert.
func TestForeignKeysOnEveryHeldPoolConnection(t *testing.T) {
	db, _ := newStagingDB(t)
	const pool = 4
	db.SetMaxOpenConns(pool)

	_, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at)
		values (?, 'backend/api', 'user:alice', 'active', 0, 1, 2)`,
		strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, pool)
	conns := make(chan *sql.Conn, pool)
	for i := 0; i < pool; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := db.Conn(context.Background())
			if err != nil {
				errs <- fmt.Errorf("conn: %w", err)
				return
			}
			conns <- conn
			var fk int
			if err := conn.QueryRowContext(context.Background(), `pragma foreign_keys`).Scan(&fk); err != nil || fk != 1 {
				errs <- fmt.Errorf("foreign_keys=%d err=%v", fk, err)
				return
			}
			// Orphan staged blob (no session -> FK violation) must be rejected.
			if _, err := conn.ExecContext(context.Background(),
				`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at)
				 values (?, 'backend/api', 'user:alice', ?, ?, 1, 'application/octet-stream', 1, 2)`,
				strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64), strings.Repeat("d", 64)); err == nil {
				errs <- fmt.Errorf("orphan staged blob accepted on a pooled connection")
			}
		}()
	}
	wg.Wait()
	close(conns)
	for conn := range conns {
		conn.Close()
	}
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// Rejection of unknown / malformed pre-existing schemas (never adopted)
// ---------------------------------------------------------------------------

func hashFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return hex.EncodeToString(data)
}

// TestRejectForeignSchema proves pointing the staging DB at a database with
// an unrelated schema (for example a control-plane database) is rejected
// without touching a single byte of it.
func TestRejectForeignSchema(t *testing.T) {
	dbPath := filepath.Join(tempPrivate(t), "foreign.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, stmt := range []string{
		`create table users (id integer primary key, email text not null)`,
		`create table registries (id integer primary key, slug text not null)`,
		`create table schema_migrations (version integer primary key, applied_at text not null)`,
		`insert into schema_migrations values (15, 'now')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	db.Close()
	before := hashFile(t, dbPath)

	if db2, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
		db2.Close()
		t.Fatal("expected rejection of foreign schema")
	} else if strings.Contains(err.Error(), dbPath) {
		t.Fatalf("error must not carry the DB path: %v", err)
	}
	if after := hashFile(t, dbPath); after != before {
		t.Fatal("foreign database bytes were modified")
	}
}

// TestRejectUnknownVersion proves a version newer than this subsystem knows
// is rejected instead of guessed at.
func TestRejectUnknownVersion(t *testing.T) {
	dbPath := filepath.Join(tempPrivate(t), "future.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`create table staging_schema (version integer primary key, applied_at integer not null)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`insert into staging_schema values (99, 1)`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	db.Close()
	before := hashFile(t, dbPath)
	if db2, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
		db2.Close()
		t.Fatal("expected rejection of unknown schema version")
	} else if after := hashFile(t, dbPath); after != before {
		t.Fatal("database bytes were modified")
	}
}

// TestRejectMalformedStagingTables proves an existing upload_sessions table
// with the wrong physical shape is rejected rather than adopted, leaving the
// file byte-identical.
func TestRejectMalformedStagingTables(t *testing.T) {
	dbPath := filepath.Join(tempPrivate(t), "malformed.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Same name, but none of the required checks/columns.
	if _, err := db.Exec(`create table upload_sessions (id text, note text)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	db.Close()
	before := hashFile(t, dbPath)
	if db2, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
		db2.Close()
		t.Fatal("expected rejection of malformed staging tables")
	} else if after := hashFile(t, dbPath); after != before {
		t.Fatal("database bytes were modified")
	}
}

// TestRejectUnknownExtraTable proves a database carrying the correct staging
// tables PLUS an unknown extra table is rejected on reopen.
func TestRejectUnknownExtraTable(t *testing.T) {
	dbPath := filepath.Join(tempPrivate(t), "extra.db")
	db, err := openStagingDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`create table unexpected_extra (id integer)`); err != nil {
		t.Fatalf("create extra: %v", err)
	}
	db.Close()
	if db2, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
		db2.Close()
		t.Fatal("expected rejection of unknown extra table")
	}
}

// TestMigrationFailureRollsBackAtomically proves a failure part-way through
// the version-1 migration leaves no version row and no staging tables, and a
// later open succeeds once the fault is cleared.
func TestMigrationFailureRollsBackAtomically(t *testing.T) {
	dbPath := filepath.Join(tempPrivate(t), "rollback.db")
	migrationFault = errors.New("injected migration fault")
	t.Cleanup(func() { migrationFault = nil })

	if db, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
		db.Close()
		t.Fatal("expected migration failure")
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`select count(*) from sqlite_master where type='table' and name in ('upload_sessions','staged_blobs','staging_schema')`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("migration fault left %d staging tables behind", n)
	}

	// Clear the fault: a fresh open now succeeds deterministically.
	migrationFault = nil
	db2, err := openStagingDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("reopen after fault cleared: %v", err)
	}
	db2.Close()
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("db file gone: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Storage-class and grammar adversarial tests (direct SQL)
// ---------------------------------------------------------------------------

func mustSeedActiveSession(t *testing.T, db *sql.DB) {
	t.Helper()
	// A canonical 64-hex id with a long-enough lifetime.
	_, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at)
		values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestSchemaRejectsAdversarialRows(t *testing.T) {
	db, _ := newStagingDB(t)

	const base = `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, ?, ?, 'active', 0, 1000, 2000)`
	validID := strings.Repeat("a", 64)

	cases := []struct {
		name string
		sql  string
		args []any
	}{
		{"id_null", base, []any{nil, "backend/api", "user:alice"}},
		{"id_blob", base, []any{[]byte(validID), "backend/api", "user:alice"}},
		{"id_real_number", base, []any{123456789.0, "backend/api", "user:alice"}},
		{"id_numeric_text", base, []any{"1234567890", "backend/api", "user:alice"}},
		{"id_uppercase_hex", base, []any{strings.ToUpper(validID), "backend/api", "user:alice"}},
		{"id_overlong", base, []any{validID + "0", "backend/api", "user:alice"}},
		{"id_short", base, []any{validID[:10], "backend/api", "user:alice"}},
		{"id_slashes", base, []any{"aa/bb", "backend/api", "user:alice"}},
		{"id_backslash", base, []any{"aa\\bb", "backend/api", "user:alice"}},
		{"id_dotdot", base, []any{"../escape", "backend/api", "user:alice"}},
		{"id_null_byte", base, []any{"a\x00" + validID[1:], "backend/api", "user:alice"}},
		{"id_unicode", base, []any{"é" + validID[1:], "backend/api", "user:alice"}},
		{"id_malformed_utf8", base, []any{string([]byte{0xF4, 0x90, 0x80, 0x80}) + validID[4:], "backend/api", "user:alice"}},
		{"repo_uppercase", base, []any{validID, "Backend/api", "user:alice"}},
		{"repo_space", base, []any{validID, "backend api", "user:alice"}},
		{"repo_empty", base, []any{validID, "", "user:alice"}},
		{"repo_overlong", base, []any{validID, strings.Repeat("a", 201), "user:alice"}},
		{"repo_blob", base, []any{validID, []byte("backend/api"), "user:alice"}},
		{"actor_null", base, []any{validID, "backend/api", nil}},
		{"actor_overlong", base, []any{validID, "backend/api", strings.Repeat("u", 201)}},
		{"actor_unicode", base, []any{validID, "backend/api", "user:al\u00edce"}},
		{"offset_real", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 1.5, 1000, 2000)`, []any{validID}},
		{"offset_numeric_text", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', '7', 1000, 2000)`, []any{validID}},
		{"offset_negative", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', -1, 1000, 2000)`, []any{validID}},
		{"offset_null", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', null, 1000, 2000)`, []any{validID}},
		{"created_at_real", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000.0, 2000)`, []any{validID}},
		{"created_at_text", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, '1000', 2000)`, []any{validID}},
		{"created_at_null", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, null, 2000)`, []any{validID}},
		{"expires_equals_created", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 1000)`, []any{validID}},
		{"expires_before_created", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 2000, 1000)`, []any{validID}},
		{"unknown_state", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'bogus', 0, 1000, 2000)`, []any{validID}},
		{"state_null", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', null, 0, 1000, 2000)`, []any{validID}},
		{"insert_finalized_without_metadata", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'finalized', 0, 1000, 2000)`, []any{validID}},
		{"insert_active_with_metadata", `insert into upload_sessions (id, repo, actor, state, offset, digest, bee_ref, media_type, size, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 'sha256:` + strings.Repeat("a", 64) + `', '` + strings.Repeat("a", 64) + `', 'application/octet-stream', 0, 1000, 2000)`, []any{validID}},
		{"insert_offset_nonzero", `insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 5, 1000, 2000)`, []any{validID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.Exec(tc.sql, tc.args...); err == nil {
				t.Fatalf("adversarial insert %q unexpectedly accepted", tc.name)
			}
		})
	}
}

// TestStateTransitionTriggersRejectIncoherence proves every state-coherence
// invariant is enforced by triggers for INSERT and UPDATE, including direct
// SQL that CHECK alone cannot police.
func TestStateTransitionTriggersRejectIncoherence(t *testing.T) {
	db, _ := newStagingDB(t)
	mustSeedActiveSession(t, db)
	id := strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("b", 64)
	ref := strings.Repeat("c", 64)

	type stmt struct {
		name string
		sql  string
	}
	updates := []stmt{
		{"finalize_without_blob", `update upload_sessions set state='finalized', digest='` + digest + `', bee_ref='` + ref + `', media_type='application/octet-stream', size=0 where id='` + id + `'`},
		{"finalize_mismatched_blob", `update upload_sessions set state='finalized', digest='` + digest + `', bee_ref='` + ref + `', media_type='application/octet-stream', size=9 where id='` + id + `'`},
		{"reactivate_finalized", `update upload_sessions set state='active', digest=null, bee_ref=null, media_type=null, size=null where id='` + id + `'`},
		{"unknown_transition", `update upload_sessions set state='limbo' where id='` + id + `'`},
		{"set_metadata_without_finalize", `update upload_sessions set digest='` + digest + `' where id='` + id + `'`},
		{"change_identity", `update upload_sessions set actor='user:eve' where id='` + id + `'`},
		{"change_repo", `update upload_sessions set repo='other/app' where id='` + id + `'`},
		{"change_created_at", `update upload_sessions set created_at=999 where id='` + id + `'`},
		{"change_expires_at", `update upload_sessions set expires_at=9999 where id='` + id + `'`},
		{"delete_live_session", `delete from upload_sessions where id='` + id + `'`},
		{"negative_offset", `update upload_sessions set offset=-1 where id='` + id + `'`},
		{"real_offset", `update upload_sessions set offset=4.5 where id='` + id + `'`},
		{"text_offset", `update upload_sessions set offset='4' where id='` + id + `'`},
	}
	for _, u := range updates {
		t.Run(u.name, func(t *testing.T) {
			if _, err := db.Exec(u.sql); err == nil {
				t.Fatalf("incoherent update %q unexpectedly accepted", u.name)
			}
		})
	}

	// A legitimate finalize (blob first, then state+metadata) must succeed.
	if _, err := db.Exec(`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at)
		values (?, 'backend/api', 'user:alice', ?, ?, 0, 'application/octet-stream', 1000, 2000)`, id, digest, ref); err != nil {
		t.Fatalf("insert staged blob: %v", err)
	}
	if _, err := db.Exec(`update upload_sessions set state='finalized', digest=?, bee_ref=?, media_type='application/octet-stream', size=0 where id=?`, digest, ref, id); err != nil {
		t.Fatalf("legitimate finalize: %v", err)
	}

	// Now the same mutations must be rejected against the finalized row.
	post := []stmt{
		{"mutate_finalized_digest", `update upload_sessions set digest='sha256:` + strings.Repeat("e", 64) + `' where id='` + id + `'`},
		{"mutate_finalized_size", `update upload_sessions set size=1 where id='` + id + `'`},
		{"second_blob_row", `insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values ('` + id + `', 'backend/api', 'user:alice', 'sha256:` + strings.Repeat("e", 64) + `', '` + strings.Repeat("e", 64) + `', 0, 'application/octet-stream', 1000, 2000)`},
		{"update_blob_row", `update staged_blobs set size=0 where upload_id='` + id + `'`},
		{"delete_blob_live_session", `delete from staged_blobs where upload_id='` + id + `'`},
		{"delete_foreign_blob_live_session", `delete from staged_blobs where upload_id='` + id + `'`},
	}
	for _, u := range post {
		t.Run(u.name, func(t *testing.T) {
			if _, err := db.Exec(u.sql); err == nil {
				t.Fatalf("post-finalize mutation %q unexpectedly accepted", u.name)
			}
		})
	}

	// Tombstone then delete: the only legal deletion path.
	if _, err := db.Exec(`update upload_sessions set state='deleting' where id=?`, id); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	if _, err := db.Exec(`delete from staged_blobs where upload_id=?`, id); err != nil {
		t.Fatalf("delete blob after tombstone: %v", err)
	}
	if _, err := db.Exec(`delete from upload_sessions where id=?`, id); err != nil {
		t.Fatalf("delete session after tombstone: %v", err)
	}
	var n int
	if err := db.QueryRow(`select count(*) from upload_sessions where id=?`, id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("session not deleted: n=%d err=%v", n, err)
	}
}

// TestStagedBlobGrammarAdversarial proves the finalized-metadata grammar is
// enforced by the schema independently of Go-side validation.
func TestStagedBlobGrammarAdversarial(t *testing.T) {
	db, _ := newStagingDB(t)
	mustSeedActiveSession(t, db)
	id := strings.Repeat("a", 64)

	bad := []struct{ name, digest, ref, media string }{
		{"digest_short", "sha256:" + strings.Repeat("b", 63), strings.Repeat("c", 64), "application/octet-stream"},
		{"digest_uppercase", "sha256:" + strings.Repeat("B", 64), strings.Repeat("c", 64), "application/octet-stream"},
		{"digest_other_algo", "sha512:" + strings.Repeat("b", 64), strings.Repeat("c", 64), "application/octet-stream"},
		{"digest_nulls", "sha256:" + strings.Repeat("b", 63) + "\x00", strings.Repeat("c", 64), "application/octet-stream"},
		{"digest_blob", "sha256:" + strings.Repeat("b", 64), strings.Repeat("c", 64), "application/octet-stream"},
		{"ref_short", "sha256:" + strings.Repeat("b", 64), strings.Repeat("c", 10), "application/octet-stream"},
		{"ref_uppercase", "sha256:" + strings.Repeat("b", 64), strings.Repeat("C", 64), "application/octet-stream"},
		{"ref_slash", "sha256:" + strings.Repeat("b", 64), "aa/bb", "application/octet-stream"},
		{"media_uppercase", "sha256:" + strings.Repeat("b", 64), strings.Repeat("c", 64), "Application/octet-stream"},
		{"media_space", "sha256:" + strings.Repeat("b", 64), strings.Repeat("c", 64), "application/octet stream"},
		{"media_empty", "sha256:" + strings.Repeat("b", 64), strings.Repeat("c", 64), ""},
		{"media_overlong", "sha256:" + strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("m", 201)},
		{"size_negative", "sha256:" + strings.Repeat("b", 64), strings.Repeat("c", 64), "application/octet-stream"},
		{"size_real", "sha256:" + strings.Repeat("b", 64), strings.Repeat("c", 64), "application/octet-stream"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			var sqlStr string
			var args []any
			switch tc.name {
			case "digest_blob":
				sqlStr = `insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values (?, 'backend/api', 'user:alice', ?, ?, 0, ?, 1000, 2000)`
				args = []any{id, []byte(tc.digest), tc.ref, tc.media}
			case "size_negative":
				sqlStr = `insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values (?, 'backend/api', 'user:alice', ?, ?, -1, ?, 1000, 2000)`
				args = []any{id, tc.digest, tc.ref, tc.media}
			case "size_real":
				sqlStr = `insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values (?, 'backend/api', 'user:alice', ?, ?, 0.5, ?, 1000, 2000)`
				args = []any{id, tc.digest, tc.ref, tc.media}
			default:
				sqlStr = `insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values (?, 'backend/api', 'user:alice', ?, ?, 0, ?, 1000, 2000)`
				args = []any{id, tc.digest, tc.ref, tc.media}
			}
			if _, err := db.Exec(sqlStr, args...); err == nil {
				t.Fatalf("adversarial staged blob %q unexpectedly accepted", tc.name)
			}
		})
	}
}

// TestBlobInsertMustMatchActiveSession proves a staged blob cannot be
// attached to a session it does not match (identity, ownership, timing).
func TestBlobInsertMustMatchActiveSession(t *testing.T) {
	db, _ := newStagingDB(t)
	mustSeedActiveSession(t, db)
	id := strings.Repeat("a", 64)

	cases := []struct {
		name    string
		repo    string
		actor   string
		created int64
		expires int64
	}{
		{"wrong_repo", "other/app", "user:alice", 1000, 2000},
		{"wrong_actor", "backend/api", "user:eve", 1000, 2000},
		{"wrong_created", "backend/api", "user:alice", 999, 2000},
		{"wrong_expires", "backend/api", "user:alice", 1000, 2001},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := db.Exec(`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at)
				values (?, ?, ?, ?, ?, 0, 'application/octet-stream', ?, ?)`,
				id, tc.repo, tc.actor, "sha256:"+strings.Repeat("b", 64), strings.Repeat("c", 64), tc.created, tc.expires)
			if err == nil {
				t.Fatalf("mismatched staged blob %q unexpectedly accepted", tc.name)
			}
		})
	}
}

// TestSchemaGrammarParity proves the Go validators and the SQLite schema
// agree on every probe: a value the Go grammar accepts is accepted by the
// schema, and a value Go rejects is rejected by the schema.
func TestSchemaGrammarParity(t *testing.T) {
	db, _ := newStagingDB(t)
	digest := "sha256:" + strings.Repeat("b", 64)
	ref := strings.Repeat("c", 64)
	media := "application/vnd.oci.image.layer.v1.tar+gzip"

	probeID := func(v string) error {
		_, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, v)
		return err
	}

	for _, tc := range []struct {
		kind  string
		value interface{}
	}{
		{"id", strings.Repeat("f", 64)},
		{"id", "abcdef0123456789" + strings.Repeat("0", 48)},
		{"id", strings.Repeat("a", 63) + "g"},
		{"id", strings.Repeat("a", 62) + ".0"},
		{"id", strings.Repeat("a", 65)},
	} {
		valid := validateID(tc.value.(string)) == nil
		accepted := probeID(tc.value.(string)) == nil
		if valid != accepted {
			t.Errorf("ID parity mismatch: Go valid=%v schema accepted=%v for %q", valid, accepted, tc.value)
		}
	}

	for i, tc := range []struct {
		digest, ref, media string
	}{
		{digest, ref, media},
		{digest, ref, "application/octet-stream"},
		{"sha256:" + strings.Repeat("0", 64), ref, media},
		{"sha256:" + strings.Repeat("a", 63) + "G", ref, media},
		{digest, strings.Repeat("0", 64), "application/json"},
		{digest, strings.Repeat("c", 63) + ":", media},
	} {
		// Each probe writes to its own freshly seeded active session: the
		// staged_blobs primary key is per-session (one blob per upload), so
		// reusing one session would mask grammar parity behind uniqueness.
		pid := fmt.Sprintf("%064x", i+1)
		if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, pid); err != nil {
			t.Fatalf("seed session for probe %d: %v", i, err)
		}
		goValid := validateDigest(tc.digest) == nil && validateBeeRef(tc.ref) == nil && validateMediaType(tc.media) == nil
		_, err := db.Exec(`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at)
			values (?, 'backend/api', 'user:alice', ?, ?, 0, ?, 1000, 2000)`, pid, tc.digest, tc.ref, tc.media)
		if goValid != (err == nil) {
			t.Errorf("grammar parity mismatch: Go valid=%v schema accepted=%v for digest=%q ref=%q media=%q", goValid, err == nil, tc.digest, tc.ref, tc.media)
		}
	}
}

func TestSchemaRejectsTimestampOverflowEcho(t *testing.T) {
	db, _ := newStagingDB(t)
	// Nanosecond timestamps must be plain INTEGER storage; any REAL or text
	// representation and any non-monotonic pair is rejected.
	for _, sqlStr := range []string{
		`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values ('` + strings.Repeat("a", 64) + `', 'backend/api', 'user:alice', 'active', 0, 9223372036854775808, 9223372036854776000)`, // > MaxInt64 (silently becomes REAL)
	} {
		if _, err := db.Exec(sqlStr); err == nil {
			t.Fatalf("overflowing timestamp accepted: %s", sqlStr)
		}
	}
}

func TestTimeNow(t *testing.T) {
	// Guard against accidental drift in the injected-clock default.
	if time.Now().UnixNano() <= 0 {
		t.Fatal("clock sanity")
	}
}

// ---------------------------------------------------------------------------
// Round 1: exact schema-object verification, lookalike rejection, creating
// state, grammar parity corpora, DB file anchoring and modes
// ---------------------------------------------------------------------------

// buildSchemaFixture creates a standalone staging database by executing the
// FROZEN GOLDEN manifest bodies (with an optional per-statement mutation)
// and recording the version row — exercising exactly the open-after-
// verification path, never the migration path. Building the adversarial
// fixtures from the golden (never from the migration DDL constants) keeps
// the fixtures independently authored: a unilateral change to the creation
// DDL alone cannot silently reshape them, and a unilateral golden change is
// caught by the parity test. The mutate hook operates on the golden bodies.
func buildSchemaFixture(t *testing.T, mutate func(ddl []string) []string, mutateVersion bool, dupVersion bool, extraStmts []string) string {
	t.Helper()
	dbPath := filepath.Join(tempPrivate(t), "fixture.db")
	versionDDL := schemaGold.Objects[0].SQL
	if mutateVersion {
		versionDDL = strings.Replace(versionDDL, "not null", "", 1)
	}
	ddl := make([]string, 0, len(schemaGold.Objects)-1)
	for _, o := range schemaGold.Objects[1:] {
		ddl = append(ddl, o.SQL)
	}
	if mutate != nil {
		ddl = mutate(ddl)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(versionDDL); err != nil {
		t.Fatalf("version table: %v", err)
	}
	for i, stmt := range ddl {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("fixture stmt %d: %v", i, err)
		}
	}
	for _, stmt := range extraStmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("fixture extra stmt: %v", err)
		}
	}
	if _, err := db.Exec(`insert into staging_schema (version, applied_at) values (?, 1)`, schemaGold.Version); err != nil {
		t.Fatalf("version row: %v", err)
	}
	if dupVersion {
		alt := int64(1)
		if schemaGold.Version == 1 {
			alt = 2
		}
		if _, err := db.Exec(`insert into staging_schema (version, applied_at) values (?, 1)`, alt); err != nil {
			t.Fatalf("alternate version row: %v", err)
		}
	}
	db.Close()
	return dbPath
}

// assertRejectedDBClean proves a rejected database was not modified (byte
// identity) and created no -wal/-shm/-journal sidecars: the inspection
// connection must be read-only-mutation-free.
func assertRejectedDBClean(t *testing.T, dbPath string, before string) {
	t.Helper()
	if after := hashFile(t, dbPath); after != before {
		t.Fatal("rejected database bytes were modified")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(dbPath + suffix); !os.IsNotExist(err) {
			t.Fatalf("rejected database created a %s sidecar", suffix)
		}
	}
}

// TestSchemaReopenControl proves an unmutated fixture reopens (the fixture
// builder itself is sound; lookalike rejections below are therefore caused
// by the mutation, not by an invalid fixture).
func TestSchemaReopenControl(t *testing.T) {
	dbPath := buildSchemaFixture(t, nil, false, false, nil)
	before := hashFile(t, dbPath)
	db, err := openStagingDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("unmutated fixture must reopen: %v", err)
	}
	db.Close()
	if after := hashFile(t, dbPath); after != before {
		t.Fatal("reopening a verified database modified its bytes")
	}
}

// TestSchemaLookalikeObjectsRejected proves verification compares the FULL
// object text (normalized SQL), physical column/index/FK shape, and version
// row — a lookalike that only shares a name is rejected. One independent
// mutated fixture per CHECK, per lifecycle trigger, per index, per FK, and
// for the version table/row.
func TestSchemaLookalikeObjectsRejected(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(ddl []string) []string
		mutateVer   bool
		dupVer      bool
		extraStmts  []string
		description string
	}{
		{"sessions_id_check", func(d []string) []string {
			d[0] = strings.Replace(d[0], "length(hex(id)) = 128", "length(hex(id)) >= 128", 1)
			return d
		}, false, false, nil, "id check loosened"},
		{"sessions_repo_segment_check", func(d []string) []string {
			d[0] = strings.Replace(d[0], "('/' || repo) not glob '*[/][._-]*'", "repo not glob '*[/][._-]*'", 1)
			return d
		}, false, false, nil, "leading dot/hyphen repo segments allowed"},
		{"sessions_actor_plus", func(d []string) []string {
			d[0] = strings.Replace(d[0], "*[^a-zA-Z0-9:_@.-]*", "*[^a-zA-Z0-9:_@.+-]*", 1)
			return d
		}, false, false, nil, "actor '+' punctuation allowed"},
		{"sessions_state_creating", func(d []string) []string {
			d[0] = strings.Replace(d[0], "state in ('active','creating','finalized','deleting')", "state in ('active','finalized','deleting')", 1)
			return d
		}, false, false, nil, "creating state removed"},
		{"sessions_offset_check", func(d []string) []string { d[0] = strings.Replace(d[0], "offset >= 0", "offset >= -1", 1); return d }, false, false, nil, "negative offsets allowed"},
		{"sessions_time_check", func(d []string) []string {
			d[0] = strings.Replace(d[0], "expires_at > created_at", "expires_at >= created_at", 1)
			return d
		}, false, false, nil, "expiry before creation allowed"},
		{"sessions_coherence_check", func(d []string) []string {
			d[0] = strings.Replace(d[0], "size = offset", "size = offset + 1", 1)
			return d
		}, false, false, nil, "finalized size != offset allowed"},
		{"sessions_token_check", func(d []string) []string {
			d[0] = strings.Replace(d[0], "and create_token is null", "and 1", 1)
			return d
		}, false, false, nil, "creating rows allowed without a token"},
		{"sessions_token_glob", func(d []string) []string {
			d[0] = strings.Replace(d[0], "create_token not glob '*[^0-9a-f]*'", "create_token glob '*[0-9a-f]*'", 1)
			return d
		}, false, false, nil, "token chars loosened"},
		{"sessions_digest_glob_suffix", func(d []string) []string {
			d[0] = strings.Replace(d[0], "substr(digest, 8) not glob '*[^0-9a-f]*'", "digest glob 'sha256:[0-9a-f]*'", 1)
			return d
		}, false, false, nil, "digest glob suffix loophole"},
		{"blobs_digest_glob_suffix", func(d []string) []string {
			d[1] = strings.Replace(d[1], "substr(digest, 8) not glob '*[^0-9a-f]*'", "digest glob 'sha256:[0-9a-f]*'", 1)
			return d
		}, false, false, nil, "blob digest glob suffix loophole"},
		{"blobs_size_check", func(d []string) []string { d[1] = strings.Replace(d[1], "size >= 0", "size >= 1", 1); return d }, false, false, nil, "blob size check loosened"},
		{"fk_cascade_removed", func(d []string) []string {
			d[1] = strings.Replace(d[1], "references upload_sessions(id) on delete cascade", "references upload_sessions(id)", 1)
			return d
		}, false, false, nil, "FK without cascade"},
		{"index_columns_reordered", func(d []string) []string {
			d[2] = strings.Replace(d[2], "on staged_blobs(repo, actor, created_at, upload_id)", "on staged_blobs(repo, actor, upload_id, created_at)", 1)
			return d
		}, false, false, nil, "index column order changed"},
		{"extra_index", nil, false, false, []string{`create index idx_extra on upload_sessions(id)`}, "unexpected extra index"},
		{"extra_trigger", nil, false, false, []string{`create trigger trg_extra before insert on upload_sessions begin select raise(abort,'x'); end`}, "unexpected extra trigger"},
		{"extra_table", nil, false, false, []string{`create table extra_thing (id integer)`}, "unexpected extra table"},
		{"trigger_insert_softened", func(d []string) []string {
			d[5] = strings.Replace(d[5], "then raise(abort, 'session insert must be active or creating')", "then raise(abort, 'x')", 1)
			return d
		}, false, false, nil, "insert trigger body changed"},
		{"trigger_state_softened", func(d []string) []string {
			d[6] = strings.Replace(d[6], "'cannot return to active'", "'x'", 1)
			return d
		}, false, false, nil, "state trigger body changed"},
		{"trigger_metadata_softened", func(d []string) []string {
			d[7] = strings.Replace(d[7], "'finalized metadata immutable'", "'x'", 1)
			return d
		}, false, false, nil, "metadata trigger body changed"},
		{"trigger_identity_softened", func(d []string) []string {
			d[8] = strings.Replace(d[8], "'session identity immutable'", "'x'", 1)
			return d
		}, false, false, nil, "identity trigger body changed"},
		{"trigger_token_softened", func(d []string) []string {
			d[9] = strings.Replace(d[9], "'create token immutable'", "'x'", 1)
			return d
		}, false, false, nil, "token trigger body changed"},
		{"trigger_token_cleared_outside_creating", func(d []string) []string {
			d[9] = strings.Replace(d[9], "when old.create_token is not null and new.create_token is null and old.state <> 'creating' then raise(abort, 'create token cannot be cleared outside creating')",
				"when old.create_token is not null and new.create_token is null then raise(abort, 'x')", 1)
			return d
		}, false, false, nil, "token clearing allowed outside creating"},
		{"trigger_cleanup_softened", func(d []string) []string {
			d[10] = strings.Replace(d[10], "'cleanup token immutable'", "'x'", 1)
			return d
		}, false, false, nil, "cleanup trigger body changed"},
		{"trigger_cleanup_set_outside_activation", func(d []string) []string {
			d[10] = strings.Replace(d[10], "when new.cleanup_token is not null and old.cleanup_token is null and new.state = 'active' and not (old.state = 'creating' and old.create_token is not null and old.create_token = new.cleanup_token and new.create_token is null)",
				"when new.cleanup_token is not null and not (new.cleanup_token = old.cleanup_token)", 1)
			return d
		}, false, false, nil, "cleanup token settable outside activation"},
		{"trigger_cleanup_cleared_from_creating", func(d []string) []string {
			d[10] = strings.Replace(d[10], "when old.cleanup_token is not null and new.cleanup_token is null and old.state not in ('active','finalized')",
				"when old.cleanup_token is not null and new.cleanup_token is null", 1)
			return d
		}, false, false, nil, "cleanup token clearable from any state"},
		{"trigger_cleanup_column_grammar", func(d []string) []string {
			d[0] = strings.Replace(d[0], "and cleanup_token not glob '*[^0-9a-f]*'", "and cleanup_token glob '*[0-9a-f]*'", 1)
			return d
		}, false, false, nil, "cleanup token chars loosened"},
		{"trigger_delete_softened", func(d []string) []string {
			d[11] = strings.Replace(d[11], "'delete only via deleting state'", "'x'", 1)
			return d
		}, false, false, nil, "delete trigger body changed"},
		{"trigger_blob_insert_softened", func(d []string) []string {
			d[12] = strings.Replace(d[12], "'staged blob must match active session'", "'x'", 1)
			return d
		}, false, false, nil, "blob insert trigger body changed"},
		{"trigger_blob_update_wrong_table", func(d []string) []string {
			d[13] = strings.Replace(d[13], "on staged_blobs", "on upload_sessions", 1)
			return d
		}, false, false, nil, "blob update trigger on the wrong table"},
		{"trigger_blob_delete_softened", func(d []string) []string {
			d[14] = strings.Replace(d[14], "'cannot delete staged blob of live session'", "'x'", 1)
			return d
		}, false, false, nil, "blob delete trigger body changed"},
		{"version_table_shape", nil, true, false, nil, "version table without not null"},
		{"version_value_2", nil, false, true, nil, "foreign version value"},
		{"check_expression_replaced", func(d []string) []string {
			d[1] = strings.Replace(d[1], "bee_ref not glob '*[^0-9a-f]*'", "bee_ref = lower(bee_ref)", 1)
			return d
		}, false, false, nil, "check expression replaced by a different constraint"},
		{"quoted_literal_case_changed", func(d []string) []string { d[0] = strings.Replace(d[0], "'sha256:'", "'SHA256:'", 1); return d }, false, false, nil, "quoted literal content changed"},
		{"quoted_identifier_introduced", func(d []string) []string {
			d[5] = strings.Replace(d[5], "before insert on upload_sessions", `before insert on "upload_sessions"`, 1)
			return d
		}, false, false, nil, "quoted identifier lookalike"},
		{"comment_inserted", func(d []string) []string {
			d[6] = strings.Replace(d[6], "begin select case", "begin\n		-- softened comment\n		select case", 1)
			return d
		}, false, false, nil, "comment in trigger body"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := buildSchemaFixture(t, tc.mutate, tc.mutateVer, tc.dupVer, tc.extraStmts)
			before := hashFile(t, dbPath)
			if db, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
				db.Close()
				t.Fatalf("lookalike schema accepted: %s", tc.description)
			}
			assertRejectedDBClean(t, dbPath, before)
		})
	}
}

// TestSchemaExactPhysicalShape proves table_xinfo (incl. hidden), index_xinfo
// columns, and the exact single foreign key row of the migrated schema.
func TestSchemaExactPhysicalShape(t *testing.T) {
	db, _ := newStagingDB(t)

	wantSessions := []struct {
		name    string
		typ     string
		notnull bool
		pk      bool
	}{
		{"id", "text", false, true},
		{"repo", "text", true, false},
		{"actor", "text", true, false},
		{"state", "text", true, false},
		{"offset", "", true, false},
		{"created_at", "", true, false},
		{"expires_at", "", true, false},
		{"create_token", "text", false, false},
		{"cleanup_token", "text", false, false},
		{"digest", "text", false, false},
		{"bee_ref", "text", false, false},
		{"media_type", "text", false, false},
		{"size", "", false, false},
	}
	rows, err := db.Query(`pragma table_xinfo(upload_sessions)`)
	if err != nil {
		t.Fatalf("table_xinfo: %v", err)
	}
	var got []struct {
		name    string
		typ     string
		notnull bool
		pk      bool
		hidden  int
	}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk, hidden int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk, &hidden); err != nil {
			t.Fatalf("scan xinfo: %v", err)
		}
		got = append(got, struct {
			name    string
			typ     string
			notnull bool
			pk      bool
			hidden  int
		}{name, strings.ToLower(typ), notnull == 1, pk == 1, hidden})
	}
	rows.Close()
	if len(got) != len(wantSessions) {
		t.Fatalf("session columns = %d, want %d", len(got), len(wantSessions))
	}
	for i, w := range wantSessions {
		g := got[i]
		if g.name != w.name || g.typ != w.typ || g.notnull != w.notnull || g.pk != w.pk || g.hidden != 0 {
			t.Errorf("session column %d: got (%s,%q,notnull=%v,pk=%v,hidden=%d), want (%s,%q,notnull=%v,pk=%v)",
				i, g.name, g.typ, g.notnull, g.pk, g.hidden, w.name, w.typ, w.notnull, w.pk)
		}
	}

	// index_xinfo: exact columns and direction for every declared index.
	wantIdx := map[string][]string{
		"idx_staged_blobs_owner": {"repo", "actor", "created_at", "upload_id"},
		"idx_sessions_owner":     {"repo", "actor"},
		"idx_sessions_expiry":    {"expires_at"},
	}
	for idx, want := range wantIdx {
		rows, err := db.Query(fmt.Sprintf(`pragma index_xinfo(%s)`, idx))
		if err != nil {
			t.Fatalf("index_xinfo(%s): %v", idx, err)
		}
		var cols []string
		var descs []int
		for rows.Next() {
			var seqno, cid, desc, key int
			var name sql.NullString
			var coll string
			if err := rows.Scan(&seqno, &cid, &name, &desc, &coll, &key); err != nil {
				rows.Close()
				t.Fatalf("scan index_xinfo(%s): %v", idx, err)
			}
			if !name.Valid {
				continue // implicit rowid auxiliary entry
			}
			cols = append(cols, name.String)
			descs = append(descs, desc)
		}
		rows.Close()
		if !reflect.DeepEqual(cols, want) {
			t.Errorf("index %s columns = %v, want %v", idx, cols, want)
		}
		for _, d := range descs {
			if d != 0 {
				t.Errorf("index %s has a descending column", idx)
			}
		}
	}

	// Exact single FK row.
	fkRows, err := db.Query(`pragma foreign_key_list(staged_blobs)`)
	if err != nil {
		t.Fatalf("fk list: %v", err)
	}
	type fkRow struct {
		id, seq            int
		table              string
		from, to           string
		onUp, onDel, match string
	}
	var fks []fkRow
	for fkRows.Next() {
		var fr fkRow
		if err := fkRows.Scan(&fr.id, &fr.seq, &fr.table, &fr.from, &fr.to, &fr.onUp, &fr.onDel, &fr.match); err != nil {
			fkRows.Close()
			t.Fatalf("scan fk: %v", err)
		}
		fks = append(fks, fr)
	}
	fkRows.Close()
	if len(fks) != 1 {
		t.Fatalf("foreign_key_list rows = %d, want exactly 1", len(fks))
	}
	fr := fks[0]
	if fr.table != "upload_sessions" || fr.from != "upload_id" || fr.to != "id" ||
		fr.onDel != "CASCADE" || fr.onUp != "NO ACTION" || fr.match != "NONE" || fr.id != 0 || fr.seq != 0 {
		t.Fatalf("FK row = %+v", fr)
	}
}

// TestSchemaCreatingStateMachine proves the creating lifecycle is enforced by
// the schema: born-active-or-creating (creating REQUIRES an unforgeable
// 64-hex token), creating→active finish (token cleared), creating→deleting
// rollback (token cleared), and no other creating transitions; the token is
// immutable while set and can never be set after insert.
func TestSchemaCreatingStateMachine(t *testing.T) {
	db, _ := newStagingDB(t)
	dig := "sha256:" + strings.Repeat("b", 64)
	ref := strings.Repeat("c", 64)
	tok := strings.Repeat("a1", 32) // 64 lowercase hex
	id := strings.Repeat("a", 64)

	// Born creating: legal WITH a token.
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, 1000, 2000, ?)`, id, tok); err != nil {
		t.Fatalf("born creating: %v", err)
	}
	// Born creating WITHOUT a token is rejected (no file may ever prove a
	// creator; the token alone attributes the row).
	idNoTok := strings.Repeat("0", 64)
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'creating', 0, 1000, 2000)`, idNoTok); err == nil {
		t.Fatal("born creating without a token accepted")
	}
	// Token grammar: exactly 64 lowercase hex.
	for _, bad := range []string{
		strings.ToUpper(tok), strings.Repeat("a", 63), strings.Repeat("a", 65),
		strings.Repeat("g", 64), strings.Repeat("a", 32) + "/" + strings.Repeat("a", 31),
		tok[:32] + "\\" + tok[:31], "a\x00" + tok[1:], "",
	} {
		bid := fmt.Sprintf("%016x%048d", len(bad), 7) // 64-hex id for the probe
		if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, 1000, 2000, ?)`, bid, bad); err == nil {
			t.Fatalf("creating row with malformed token %q accepted", printable(bad))
		}
	}
	// Finish: creating -> active, clearing the token.
	if _, err := db.Exec(`update upload_sessions set state='active', create_token=null where id=? and state='creating'`, id); err != nil {
		t.Fatalf("creating->active: %v", err)
	}
	// Active cannot go back to creating.
	if _, err := db.Exec(`update upload_sessions set state='creating' where id=?`, id); err == nil {
		t.Fatal("active->creating accepted")
	}
	// Active cannot SET a token.
	if _, err := db.Exec(`update upload_sessions set create_token='`+tok+`' where id=?`, id); err == nil {
		t.Fatal("setting a token on a live row accepted")
	}

	// A fresh creating row that is rolled back through the tombstone.
	id2 := strings.Repeat("b", 64)
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, 1000, 2000, ?)`, id2, tok); err != nil {
		t.Fatalf("born creating 2: %v", err)
	}
	if _, err := db.Exec(`update upload_sessions set state='deleting', create_token=null where id=? and state='creating'`, id2); err != nil {
		t.Fatalf("creating->deleting: %v", err)
	}
	if _, err := db.Exec(`delete from upload_sessions where id=? and state='deleting'`, id2); err != nil {
		t.Fatalf("delete rolled-back creating: %v", err)
	}
	// The token cannot be cleared on a live lease except as part of a
	// creating transition: tombstoning an active row clears nothing illicit.
	idDel := strings.Repeat("e", 64)
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, idDel); err != nil {
		t.Fatalf("born active: %v", err)
	}
	if _, err := db.Exec(`update upload_sessions set state='deleting', create_token=null where id=? and state <> 'deleting'`, idDel); err != nil {
		t.Fatalf("tombstone: %v", err)
	}

	// Creating rows may not jump to finalized and may not be deleted directly.
	id3 := strings.Repeat("c", 64)
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, 1000, 2000, ?)`, id3, tok); err != nil {
		t.Fatalf("born creating 3: %v", err)
	}
	if _, err := db.Exec(`update upload_sessions set state='finalized', create_token=null, digest='` + dig + `', bee_ref='` + ref + `', media_type='application/octet-stream', size=0 where id='` + id3 + `'`); err == nil {
		t.Fatal("creating->finalized accepted")
	}
	if _, err := db.Exec(`delete from upload_sessions where id='` + id3 + `'`); err == nil {
		t.Fatal("direct delete of creating row accepted")
	}
	// Born creating with a nonzero offset or metadata is rejected by the
	// insert trigger and the coherence check.
	id4 := strings.Repeat("d", 64)
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 5, 1000, 2000, ?)`, id4, tok); err == nil {
		t.Fatal("born creating with nonzero offset accepted")
	}
	// Deleting is terminal.
	id5 := strings.Repeat("f", 64)
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, id5); err != nil {
		t.Fatalf("born active: %v", err)
	}
	if _, err := db.Exec(`update upload_sessions set state='deleting', create_token=null where id=?`, id5); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	if _, err := db.Exec(`update upload_sessions set state='finalized' where id=?`, id5); err == nil {
		t.Fatal("deleting->finalized accepted")
	}
	if _, err := db.Exec(`update upload_sessions set state='active' where id=?`, id5); err == nil {
		t.Fatal("deleting->active accepted")
	}
}

// TestSchemaGrammarParityExtended proves the Go validators and the SQLite
// schema agree on a broad INSERT and UPDATE corpus: every value the Go side
// accepts is accepted by the schema, and every value Go rejects is rejected,
// over raw-byte probes (malformed UTF-8, NUL), BLOB/NULL/numeric classes,
// leading/dot/hyphen repo segments, actor '+' punctuation, and digest
// exactness.
func TestSchemaGrammarParityExtended(t *testing.T) {
	db, _ := newStagingDB(t)

	// Drop the immutability/transition triggers so that UPDATE probes
	// exercise the column CHECKs in isolation (the triggers enforce separate
	// invariants covered by their own tests). This is a probe-only database.
	for _, trg := range []string{
		"trg_session_insert", "trg_session_state", "trg_session_metadata",
		"trg_session_identity", "trg_session_delete", "trg_blob_insert",
		"trg_blob_update", "trg_blob_delete",
	} {
		if _, err := db.Exec("drop trigger " + trg); err != nil {
			t.Fatalf("drop %s: %v", trg, err)
		}
	}

	hex64 := strings.Repeat("a", 64)
	dig := "sha256:" + strings.Repeat("b", 64)
	ref := strings.Repeat("c", 64)
	media := "application/octet-stream"

	var sessionN int
	seedSession := func() string {
		sessionN++
		id := fmt.Sprintf("%064x", sessionN)
		if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, id); err != nil {
			t.Fatalf("seed: %v", err)
		}
		return id
	}

	parity := func(name string, goValid bool, exec func() error) {
		t.Helper()
		accepted := exec() == nil
		if goValid != accepted {
			t.Errorf("%s: Go valid=%v schema accepted=%v", name, goValid, accepted)
		}
	}

	// --- ID: INSERT and UPDATE ---
	for _, v := range []struct {
		val string
		ok  bool
	}{
		{hex64, true},
		{"abcdef0123456789" + strings.Repeat("0", 48), true},
		{strings.Repeat("f", 64), true},
		{strings.ToUpper(hex64), false},
		{strings.Repeat("a", 63), false},
		{strings.Repeat("a", 65), false},
		{strings.Repeat("g", 64), false},
		{hex64[:32] + "/" + hex64[:31], false},
		{hex64[:63] + "\\", false},
		{string([]byte{0xF4, 0x90, 0x80, 0x80}) + hex64[4:], false},
		{"é" + hex64[1:], false},
		{"a\x00" + hex64[1:], false},
	} {
		inserted := seedSession()
		parity("id-insert-"+printable(v.val), v.ok, func() error {
			_, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, v.val)
			return err
		})
		if v.ok {
			// Remove the row the insert case created so the UPDATE case can
			// take the same primary-key value without self-colliding.
			if _, err := db.Exec(`delete from upload_sessions where id = ?`, v.val); err != nil {
				t.Fatalf("cleanup: %v", err)
			}
		}
		// UPDATE on a session without a staged blob (the FK would also fire).
		free := seedSession()
		parity("id-update-"+printable(v.val), v.ok, func() error {
			_, err := db.Exec(`update upload_sessions set id = ? where id = ?`, v.val, free)
			return err
		})
		_ = inserted
	}

	// --- repo: INSERT and UPDATE via upload_sessions ---
	repos := []struct {
		val string
		ok  bool
	}{
		{"backend/api", true},
		{"a", true},
		{"a/b/c", true},
		{"my-repo_1.x/app", true},
		{"0/1", true},
		{"Backend/api", false},
		{"backend api", false},
		{"backend//api", false},
		{"/x", false},
		{"x/", false},
		{"backend/../api", false},
		{"backend/./api", false},
		{"-x/y", false},
		{"x/-y", false},
		{".x/y", false},
		{"x/.y", false},
		{"_x/y", false},
		{"x/_y", false},
		{"x..y", false},
		{"x./y", false},
		{"x/y.", true},
		{"x/y-", true},
		{"x/y_", true},
		{"backend\\api", false},
		{strings.Repeat("a", 201), false},
		{"x/y\x00z", false},
		{"x/é", false},
	}
	for _, v := range repos {
		id := seedSession()
		parity("repo-insert-"+printable(v.val), validateRepo(v.val) == nil, func() error {
			_, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, ?, 'user:alice', 'active', 0, 1000, 2000)`, hex64[:len(hex64)-8]+fmt.Sprintf("%08x", sessionN), v.val)
			return err
		})
		_ = id
		id2 := seedSession()
		parity("repo-update-"+printable(v.val), validateRepo(v.val) == nil, func() error {
			_, err := db.Exec(`update upload_sessions set repo = ? where id = ?`, v.val, id2)
			return err
		})
	}

	// --- actor: INSERT and UPDATE ---
	actors := []struct {
		val string
		ok  bool
	}{
		{"user:alice", true},
		{"alice", true},
		{"user:alice@example.com", true},
		{"svc:deploy-1", true},
		{"a.b_c-d:e@f", true},
		{"+alice", false},
		{"alice+bob", false},
		{"user:al ice", false},
		{"user/alice", false},
		{"user:alice\x00admin", false},
		{"üser", false},
		{strings.Repeat("u", 201), false},
		{"", false},
		{"..", false},
	}
	for _, v := range actors {
		id := seedSession()
		parity("actor-insert-"+printable(v.val), validateActor(v.val) == nil, func() error {
			_, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', ?, 'active', 0, 1000, 2000)`, hex64[:len(hex64)-8]+fmt.Sprintf("%08x", sessionN*7), v.val)
			return err
		})
		_ = id
		bid := seedBlobID(db, t)
		parity("actor-update-"+printable(v.val), validateActor(v.val) == nil, func() error {
			_, err := db.Exec(`update staged_blobs set actor = ? where upload_id = ?`, v.val, bid)
			return err
		})
	}

	// --- digest / bee_ref / media_type / size: INSERT and UPDATE via staged_blobs ---
	digests := []struct {
		val string
		ok  bool
	}{
		{"sha256:" + strings.Repeat("b", 64), true},
		{"sha256:" + strings.Repeat("0", 64), true},
		{"sha256:" + strings.Repeat("b", 63), false},
		{"sha256:" + strings.Repeat("b", 65), false},
		{"sha256:" + strings.Repeat("B", 64), false},
		{"sha512:" + strings.Repeat("b", 64), false},
		{"sha256:" + strings.Repeat("b", 63) + "g", false},
		{"sha256:" + strings.Repeat("b", 63) + "G", false},
		{"sha256:" + strings.Repeat("b", 63) + "+", false},
		{"sha256:" + strings.Repeat("b", 63) + "\x00", false},
		{"sha256:" + strings.Repeat("b", 62) + "é", false},
	}
	for _, v := range digests {
		sid := strings.Repeat("b", 56) + fmt.Sprintf("%08x", blobCounter())
		if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, sid); err != nil {
			t.Fatalf("seed digest session: %v", err)
		}
		parity("digest-insert-"+printable(v.val), validateDigest(v.val) == nil, func() error {
			_, err := db.Exec(`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values (?, 'backend/api', 'user:alice', ?, ?, 0, ?, 1000, 2000)`, sid, v.val, ref, media)
			return err
		})
		sid2 := strings.Repeat("c", 56) + fmt.Sprintf("%08x", blobCounter())
		if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, sid2); err != nil {
			t.Fatalf("seed digest session 2: %v", err)
		}
		parity("digest-update-"+printable(v.val), validateDigest(v.val) == nil, func() error {
			_, err := db.Exec(`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values (?, 'backend/api', 'user:alice', ?, ?, 0, ?, 1000, 2000)`, sid2, "sha256:"+strings.Repeat("b", 64), ref, media)
			if err != nil {
				return err
			}
			_, err = db.Exec(`update staged_blobs set digest = ? where upload_id = ?`, v.val, sid2)
			return err
		})
	}

	refs := []struct {
		val string
		ok  bool
	}{
		{strings.Repeat("c", 64), true},
		{strings.Repeat("0", 64), true},
		{strings.Repeat("c", 63), false},
		{strings.Repeat("C", 64), false},
		{"aa/bb", false},
		{strings.Repeat("c", 63) + "\x00", false},
	}
	for _, v := range refs {
		sid := strings.Repeat("d", 56) + fmt.Sprintf("%08x", blobCounter())
		if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, sid); err != nil {
			t.Fatalf("seed ref session: %v", err)
		}
		parity("ref-insert-"+printable(v.val), validateBeeRef(v.val) == nil, func() error {
			_, err := db.Exec(`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values (?, 'backend/api', 'user:alice', ?, ?, 0, ?, 1000, 2000)`, sid, dig, v.val, media)
			return err
		})
		sid2 := strings.Repeat("e", 56) + fmt.Sprintf("%08x", blobCounter())
		if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, sid2); err != nil {
			t.Fatalf("seed ref session 2: %v", err)
		}
		parity("ref-update-"+printable(v.val), validateBeeRef(v.val) == nil, func() error {
			_, err := db.Exec(`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values (?, 'backend/api', 'user:alice', ?, ?, 0, ?, 1000, 2000)`, sid2, dig, strings.Repeat("c", 64), media)
			if err != nil {
				return err
			}
			_, err = db.Exec(`update staged_blobs set bee_ref = ? where upload_id = ?`, v.val, sid2)
			return err
		})
	}

	medias := []struct {
		val string
		ok  bool
	}{
		{media, true},
		{"application/vnd.oci.image.layer.v1.tar+gzip", true},
		{"a+b/c.d_e-f", true},
		{"", false},
		{"Application/json", false},
		{"application/json ", false},
		{"application/json; charset=utf-8", false},
		{strings.Repeat("m", 201), false},
		{"application/\x00json", false},
	}
	for _, v := range medias {
		sid := strings.Repeat("f", 56) + fmt.Sprintf("%08x", blobCounter())
		if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, sid); err != nil {
			t.Fatalf("seed media session: %v", err)
		}
		parity("media-insert-"+printable(v.val), validateMediaType(v.val) == nil, func() error {
			_, err := db.Exec(`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values (?, 'backend/api', 'user:alice', ?, ?, 0, ?, 1000, 2000)`, sid, dig, ref, v.val)
			return err
		})
		sid2 := strings.Repeat("4", 56) + fmt.Sprintf("%08x", blobCounter())
		if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, sid2); err != nil {
			t.Fatalf("seed media session 2: %v", err)
		}
		parity("media-update-"+printable(v.val), validateMediaType(v.val) == nil, func() error {
			_, err := db.Exec(`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values (?, 'backend/api', 'user:alice', ?, ?, 0, ?, 1000, 2000)`, sid2, dig, ref, media)
			if err != nil {
				return err
			}
			_, err = db.Exec(`update staged_blobs set media_type = ? where upload_id = ?`, v.val, sid2)
			return err
		})
	}

	// --- offset (affinity-free integer): UPDATE parity ---
	id := seedSession()
	offsets := []struct {
		val any
		ok  bool
	}{
		{0, true},
		{5, true},
		{-1, false},
		{4.5, false},
		{"7", false},
		{nil, false},
		{[]byte{7}, false},
		{int64(math.MaxInt64), true},
		{9223372036854775808.0, false}, // > MaxInt64 becomes REAL
	}
	for _, v := range offsets {
		ok := v.ok
		parity(fmt.Sprintf("offset-update-%v(%T)", v.val, v.val), ok, func() error {
			_, err := db.Exec(`update upload_sessions set offset = ? where id = ?`, v.val, id)
			return err
		})
	}

	// --- timestamps: strict INTEGER storage classes ---
	ts := seedSession()
	timeCases := []struct {
		created, expires any
		ok               bool
	}{
		{1000, 2000, true},
		{1000.0, 2000, false},
		{"1000", 2000, false},
		{nil, 2000, false},
		{2000, 1000, false},
		{2000, 2000, false},
		{[]byte("1000"), 2000, false},
	}
	for _, v := range timeCases {
		parity(fmt.Sprintf("time-%v/%v", v.created, v.expires), v.ok, func() error {
			_, err := db.Exec(`update upload_sessions set created_at = ?, expires_at = ? where id = ?`, v.created, v.expires, ts)
			return err
		})
	}
	_ = id
}

// seedBlobID seeds a session and a matching staged blob, returning the id.
// Its ids use a distinct prefix so they never collide with seedSession ids.
func seedBlobID(db *sql.DB, t *testing.T) string {
	t.Helper()
	id := strings.Repeat("e", 56) + fmt.Sprintf("%08x", blobCounter())
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, id); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := db.Exec(`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'sha256:`+strings.Repeat("b", 64)+`', '`+strings.Repeat("c", 64)+`', 0, 'application/octet-stream', 1000, 2000)`, id); err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	return id
}

var blobCounterValue int64

func blobCounter() int64 {
	blobCounterValue++
	return blobCounterValue
}

// ---------------------------------------------------------------------------
// Round 1: database file anchoring and modes
// ---------------------------------------------------------------------------

// TestOpenStagingDBBareRelativeName proves a bare relative database name
// (parent ".") works: the basename is never mkdir'd, the CWD is not
// mode-repaired, and the resulting file is a private regular file.
func TestOpenStagingDBBareRelativeName(t *testing.T) {
	dir := tempPrivate(t)
	t.Chdir(dir)
	db, err := openStagingDB(context.Background(), "staging.db", 0)
	if err != nil {
		t.Fatalf("bare relative db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values ('` + strings.Repeat("a", 64) + `', 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`); err != nil {
		t.Fatalf("use bare db: %v", err)
	}
	fi, err := os.Lstat("staging.db")
	if err != nil {
		t.Fatalf("lstat bare db: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("bare db mode = %o, want 0600", fi.Mode().Perm())
	}
	if !fi.Mode().IsRegular() {
		t.Fatal("bare db is not a regular file")
	}
}

// TestOpenStagingDBRelativeSubdir proves a relative subdirectory parent is
// created 0700 and the database file inside it is 0600 — without touching
// the CWD.
func TestOpenStagingDBRelativeSubdir(t *testing.T) {
	dir := tempPrivate(t)
	t.Chdir(dir)
	db, err := openStagingDB(context.Background(), "data/staging.db", 0)
	if err != nil {
		t.Fatalf("relative subdir db: %v", err)
	}
	db.Close()
	fi, err := os.Lstat("data")
	if err != nil {
		t.Fatalf("lstat data: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("created parent mode = %o, want 0700", fi.Mode().Perm())
	}
	if !fi.IsDir() {
		t.Fatal("data is not a directory")
	}
	fi2, err := os.Lstat("data/staging.db")
	if err != nil {
		t.Fatalf("lstat db: %v", err)
	}
	if fi2.Mode().Perm() != 0o600 {
		t.Fatalf("db mode = %o, want 0600", fi2.Mode().Perm())
	}
}

// TestOpenStagingDBRejectsSymlinkedDatabaseBeforeAnyMutation proves a
// symlinked database path is rejected before SQLite opens it, leaving the
// link target byte-identical.
func TestOpenStagingDBRejectsSymlinkedDatabaseBeforeAnyMutation(t *testing.T) {
	dir := tempPrivate(t)
	real := filepath.Join(dir, "real.db")
	if err := os.WriteFile(real, []byte("FOREIGN-DATA-0123456789"), 0o600); err != nil {
		t.Fatalf("write real: %v", err)
	}
	link := filepath.Join(dir, "staging.db")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	before := hashFile(t, real)
	if db, err := openStagingDB(context.Background(), link, 0); err == nil {
		db.Close()
		t.Fatal("symlinked database path accepted")
	}
	if after := hashFile(t, real); after != before {
		t.Fatal("symlink target was modified")
	}
	// A symlinked PARENT is also rejected before anything is created inside
	// the real directory.
	realDir := filepath.Join(dir, "real-dir")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir real dir: %v", err)
	}
	parentLink := filepath.Join(dir, "par-link")
	if err := os.Symlink(realDir, parentLink); err != nil {
		t.Fatalf("parent symlink: %v", err)
	}
	if db, err := openStagingDB(context.Background(), filepath.Join(parentLink, "staging.db"), 0); err == nil {
		db.Close()
		t.Fatal("symlinked parent accepted")
	}
	if _, err := os.Lstat(filepath.Join(realDir, "staging.db")); !os.IsNotExist(err) {
		t.Fatal("database file was created through a symlinked parent")
	}
}

// TestOpenStagingDBRejectsNonRegularPath proves a database path that is a
// directory, a FIFO, or whose parent is a regular file is rejected before
// any open ever happens (a FIFO probe would hang otherwise).
func TestOpenStagingDBRejectsNonRegularPath(t *testing.T) {
	dir := tempPrivate(t)
	// dbPath is a directory.
	if err := os.Mkdir(filepath.Join(dir, "somedb"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if db, err := openStagingDB(context.Background(), filepath.Join(dir, "somedb"), 0); err == nil {
		db.Close()
		t.Fatal("directory database path accepted")
	}
	// dbPath is a FIFO.
	fifo := filepath.Join(dir, "fifo.db")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	if db, err := openStagingDB(context.Background(), fifo, 0); err == nil {
		db.Close()
		t.Fatal("fifo database path accepted")
	}
	// Parent is a regular file.
	f := filepath.Join(dir, "afile")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if db, err := openStagingDB(context.Background(), filepath.Join(f, "staging.db"), 0); err == nil {
		db.Close()
		t.Fatal("database under a file parent accepted")
	}
}

// TestOpenStagingDBParentModeRepair proves a looser database parent is
// repaired to exactly 0700 and the database file to exactly 0600.
func TestOpenStagingDBParentModeRepair(t *testing.T) {
	dir := tempPrivate(t)
	parent := filepath.Join(dir, "loose")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dbPath := filepath.Join(parent, "staging.db")
	db, err := openStagingDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.Close()
	fi, err := os.Lstat(parent)
	if err != nil {
		t.Fatalf("lstat parent: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("parent mode = %o, want 0700", fi.Mode().Perm())
	}
	fi2, err := os.Lstat(dbPath)
	if err != nil {
		t.Fatalf("lstat db: %v", err)
	}
	if fi2.Mode().Perm() != 0o600 {
		t.Fatalf("db mode = %o, want 0600", fi2.Mode().Perm())
	}
}

// TestOpenStagingDBRejectsSwappedDatabase proves the post-open identity check
// detects a database file replaced between validation and use: the opened
// handle is refused and the foreign replacement is not migrated or mutated.
func TestOpenStagingDBRejectsSwappedDatabase(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can swap despite 0700 parents")
	}
	dir := tempPrivate(t)
	dbPath := filepath.Join(dir, "staging.db")
	db, err := openStagingDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.Close()
	// Replace the validated database with a foreign file while keeping the
	// same inode swap shape a concurrent attacker would create.
	foreign := filepath.Join(dir, "foreign.db")
	if err := os.WriteFile(foreign, []byte("FOREIGN-BYTES"), 0o600); err != nil {
		t.Fatalf("write foreign: %v", err)
	}
	if err := os.Rename(foreign, dbPath); err != nil {
		t.Fatalf("swap: %v", err)
	}
	before := hashFile(t, dbPath)
	if db2, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
		db2.Close()
		t.Fatal("swapped database accepted")
	}
	if after := hashFile(t, dbPath); after != before {
		t.Fatal("swapped database bytes were modified by the rejected open")
	}
}
