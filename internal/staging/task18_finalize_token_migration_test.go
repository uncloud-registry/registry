package staging

// Task 18 round-1 correction: schema v4/v5 -> v6 migration must PRESERVE the
// finalize_token column. v4 and v5 both carry a `finalizing` state whose
// coherence check REQUIRES a non-null finalize_token; the v6 rebuild drops the
// column unless the copy is source-version-aware, which would violate the v6
// coherence CHECK on a valid v4/v5 finalizing row and abort the migration.
//
// These fixtures are file-backed (real on-disk SQLite, exactly what the
// production open path migrates) built from the frozen commited manifest
// goldens, seeded with a genuine v4/v5 finalizing row via the authentic
// active -> finalizing claim transition, so the preservation proof is byte and
// token exact, not hand-authored.

import (
	"database/sql"
	"strings"
	"testing"
)

// finalizeTokenHex is the durable claim token a v4/v5 finalizing row carries.
func finalizeTokenHex() string { return strings.Repeat("e7", 32) }

// seedFinalizingRow inserts an active row then performs the authentic
// active -> finalizing claim transition (setting a finalize_token), which the
// v4/v5 state and finalize-token triggers permit. It returns the row id.
func seedFinalizingRow(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	if _, err := db.Exec(
		`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at)
		 values (?,?,?, 'active', 0, 2000, 30000)`, id, seedRepo, seedActor); err != nil {
		t.Fatalf("seed active for finalizing: %v", err)
	}
	if _, err := db.Exec(
		`update upload_sessions set state='finalizing', finalize_token=? where id=?`,
		finalizeTokenHex(), id); err != nil {
		t.Fatalf("seed finalizing claim: %v", err)
	}
}

// tokenOfFinalizing reads the single finalizing row's finalize_token (or ""
// when the row/state is absent) directly from the migrated database.
func tokenOfFinalizing(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var tok sql.NullString
	if err := db.QueryRow(
		`select finalize_token from upload_sessions where id = ?`, id).Scan(&tok); err != nil {
		t.Fatalf("read finalizing token: %v", err)
	}
	if !tok.Valid {
		return ""
	}
	return tok.String
}

func isFinalizing(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var s string
	if err := db.QueryRow(`select state from upload_sessions where id = ?`, id).Scan(&s); err != nil {
		t.Fatalf("read finalizing state: %v", err)
	}
	return s
}

func operationIDOf(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var op sql.NullString
	if err := db.QueryRow(`select operation_id from upload_sessions where id = ?`, id).Scan(&op); err != nil {
		t.Fatalf("read operation_id: %v", err)
	}
	if !op.Valid {
		return ""
	}
	return op.String
}

// TestMigrateV4PreservesFinalizingToken proves a valid v4 finalizing row
// migrates to v6 with its finalize_token byte-for-byte intact, operation_id
// stays NULL (never invented on a row that predates it), and reopen is
// idempotent.
func TestMigrateV4PreservesFinalizingToken(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV4JSON)
	if gold.Version != 4 {
		t.Fatalf("v4 predecessor manifest must be frozen at version 4, got %d", gold.Version)
	}
	const fid = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
	dbPath := fixtureFromGolden(t, gold, func(db *sql.DB) {
		seedFullLifecycle(t, db)
		seedFinalizingRow(t, db, fid)
	})

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate v4 with a valid finalizing row: %v", err)
	}
	db.Close()

	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after v4 migration = %d, want %d", v, latestSchemaVersion)
	}
	if st := isFinalizing(t, migRaw(t, dbPath), fid); st != "finalizing" {
		t.Fatalf("finalizing row state after migration = %q, want %q", st, "finalizing")
	}
	if tok := tokenOfFinalizing(t, migRaw(t, dbPath), fid); tok != finalizeTokenHex() {
		t.Fatalf("finalize_token lost across v4 migration: got %q, want %q", tok, finalizeTokenHex())
	}
	if op := operationIDOf(t, migRaw(t, dbPath), fid); op != "" {
		t.Fatalf("migration invented operation_id %q on a finalizing row that predates the column", op)
	}

	// Reopen is idempotent: still v6, token still intact.
	db2, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("idempotent reopen of migrated v4: %v", err)
	}
	db2.Close()
	if st := isFinalizing(t, migRaw(t, dbPath), fid); st != "finalizing" {
		t.Fatalf("finalizing row state after reopen = %q", st)
	}
	if tok := tokenOfFinalizing(t, migRaw(t, dbPath), fid); tok != finalizeTokenHex() {
		t.Fatalf("finalize_token lost across v4 reopen: got %q", tok)
	}
}

// TestMigrateV5PreservesFinalizingToken is the same preservation proof against
// the v5 predecessor {finalizing AND expiring states}.
func TestMigrateV5PreservesFinalizingToken(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV5JSON)
	if gold.Version != 5 {
		t.Fatalf("v5 predecessor manifest must be frozen at version 5, got %d", gold.Version)
	}
	const fid = "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
	dbPath := fixtureFromGolden(t, gold, func(db *sql.DB) {
		seedFullLifecycle(t, db)
		seedFinalizingRow(t, db, fid)
	})

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate v5 with a valid finalizing row: %v", err)
	}
	db.Close()

	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after v5 migration = %d, want %d", v, latestSchemaVersion)
	}
	if st := isFinalizing(t, migRaw(t, dbPath), fid); st != "finalizing" {
		t.Fatalf("finalizing row state after v5 migration = %q", st)
	}
	if tok := tokenOfFinalizing(t, migRaw(t, dbPath), fid); tok != finalizeTokenHex() {
		t.Fatalf("finalize_token lost across v5 migration: got %q, want %q", tok, finalizeTokenHex())
	}
	if op := operationIDOf(t, migRaw(t, dbPath), fid); op != "" {
		t.Fatalf("migration invented operation_id %q on a v5 finalizing row", op)
	}
	db2, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("idempotent reopen of migrated v5: %v", err)
	}
	db2.Close()
	if tok := tokenOfFinalizing(t, migRaw(t, dbPath), fid); tok != finalizeTokenHex() {
		t.Fatalf("finalize_token lost across v5 reopen: got %q", tok)
	}
}

// TestMigrateV3FinalizeSynthesizedNull proves the predecessors that predate the
// finalize_token column (v3 and earlier) still migrate, synthesizing the new
// column as NULL everywhere — provenance is never invented on rows that never
// had a finalizing claim.
func TestMigrateV3FinalizeSynthesizedNull(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV3JSON)
	if gold.Version != 3 {
		t.Fatalf("v3 predecessor manifest must be frozen at version 3, got %d", gold.Version)
	}
	dbPath := fixtureFromGolden(t, gold, func(db *sql.DB) { seedFullLifecycle(t, db) })
	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate v3: %v", err)
	}
	db.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after v3 migration = %d, want %d", v, latestSchemaVersion)
	}
	db2 := migRaw(t, dbPath)
	rows, err := db2.Query(`select finalize_token from upload_sessions`)
	if err != nil {
		t.Fatalf("query finalize tokens: %v", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var tok sql.NullString
		if err := rows.Scan(&tok); err != nil {
			t.Fatalf("scan finalize token: %v", err)
		}
		count++
		if tok.Valid {
			t.Fatalf("v3 migration invented finalize provenance: %q", tok.String)
		}
	}
	if count != 4 {
		t.Fatalf("expected 4 migrated rows, got %d", count)
	}
}
