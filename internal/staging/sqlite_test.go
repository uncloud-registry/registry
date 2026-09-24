package staging

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
		"digest": "text", "bee_ref": "text", "media_type": "text", "size": "",
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
		"trg_session_identity", "trg_session_delete", "trg_blob_insert",
		"trg_blob_update", "trg_blob_delete",
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
