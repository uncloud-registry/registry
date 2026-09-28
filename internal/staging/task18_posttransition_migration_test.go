package staging

// Task 18 round-2: v6 -> v7 migration. v7 is the schema that keeps a
// publication consume durably retryable across the claimed -> deleting
// transition (a publication-owned deleting tombstone retains operation_id
// while generic Delete/Expire tombstones stay unowned/NULL). These tests
// prove the migration is coherent and lossless from every shipped predecessor
// through v7, that a v6 claimed row's ownership survives, that a v6 generic
// deleting tombstone is never re-owned, and that no predecessor row is ever
// altered or re-derived.

import (
	"database/sql"
	"strings"
	"testing"
)

// v6SeedOwnership converts a v6 fixture's finalized row to a publication-owned
// claimed row under op-mig; the deleting row stays an unowned generic
// tombstone.
func v6SeedOwnership(t *testing.T, db *sql.DB) {
	t.Helper()
	// seedFullLifecycle creates: active(a), creating(b), finalized(c, with
	// matching staged_blob), deleting(f). Convert the finalized row (c) to a
	// publications-owned claimed row under op-mig; the deleting row stays an
	// unowned generic tombstone.
	fid := strings.Repeat("c", 64)
	if _, err := db.Exec(
		`update upload_sessions set state='claimed', operation_id = ? where id = ?`,
		"op-mig", fid); err != nil {
		t.Fatalf("seed claimed transition: %v", err)
	}
}

// seedFullLifecycleV6Owned seeds the full lifecycle AND a publication-owned
// claimed row (used so every predecessor, including v6, exercises ownership
// columns uniformly in the upgrade regression).
func seedFullLifecycleV6Owned(t *testing.T, db *sql.DB) {
	t.Helper()
	seedFullLifecycle(t, db)
	v6SeedOwnership(t, db)
}

// TestMigrateV6ToV7PreservesOwnership proves the frozen v6 predecessor
// migrates forward to the v7 post-transition-retry surface, carrying every
// committed row/field exactly: a v6 claimed row keeps its operation_id, a v6
// generic (unowned) deleting tombstone stays NULL-operation_id (never
// re-owned), and the version advances to v7. Reopen is idempotent.
func TestMigrateV6ToV7PreservesOwnership(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV6JSON)
	if gold.Version != 6 {
		t.Fatalf("v6 predecessor manifest must be frozen at version 6, got %d", gold.Version)
	}
	if gold.Version == latestSchemaVersion {
		t.Fatalf("v6 must not be the current (v%d) schema", latestSchemaVersion)
	}
	dbPath := fixtureFromGolden(t, gold, func(db *sql.DB) {
		seedFullLifecycle(t, db)
		v6SeedOwnership(t, db)
	})
	beforeSess := scanSessionsCleanup(t, migRaw(t, dbPath))
	if len(beforeSess) != 4 {
		t.Fatalf("pre-migration session count = %d, want 4", len(beforeSess))
	}

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate v6: %v", err)
	}
	db.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after migration = %d, want %d", v, latestSchemaVersion)
	}
	after := scanSessionsCleanup(t, migRaw(t, dbPath))
	if len(after) != len(beforeSess) {
		t.Fatalf("session count changed across v6 migration: %d -> %d", len(beforeSess), len(after))
	}
	if fmtSessKeys(beforeSess) != fmtSessKeys(after) {
		t.Fatalf("session rows not preserved exactly across v6 migration")
	}

	raw := migRaw(t, dbPath)
	defer raw.Close()
	var claimedOp, deletingOp sql.NullString
	var claimedState, deletingState string
	if err := raw.QueryRow(`select state, operation_id from upload_sessions where id = ?`, strings.Repeat("c", 64)).
		Scan(&claimedState, &claimedOp); err != nil {
		t.Fatalf("read migrated claimed row: %v", err)
	}
	if claimedState == "" || claimedState != string(StateClaimed) || claimedOp.String != "op-mig" {
		t.Fatalf("v6 claimed row ownership lost across migration: state=%q op=%q", claimedState, claimedOp.String)
	}
	if err := raw.QueryRow(`select state, operation_id from upload_sessions where id = ?`, strings.Repeat("f", 64)).
		Scan(&deletingState, &deletingOp); err != nil {
		t.Fatalf("read migrated deleting row: %v", err)
	}
	if deletingState != string(StateDeleting) || deletingOp.Valid {
		t.Fatalf("v6 generic deleting tombstone was re-owned across migration: state=%q op.valid=%v", deletingState, deletingOp.Valid)
	}

	// Reopen is idempotent.
	db2, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("idempotent reopen: %v", err)
	}
	db2.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version drifted on reopen = %d", v)
	}
}

// TestUpgradeEveryPredecessorToV7 regresses the full upgrade chain: every
// shipped predecessor shape (the two v1 compatibility shapes, v2, v3, v4, v5,
// and v6) migrates losslessly to the current v7 schema, verifying the object
// surface and the version row, and reopens idempotently. This is the
// v1-through-v6 upgrade regression required by the schema change.
func TestUpgradeEveryPredecessorToV7(t *testing.T) {
	cases := []struct {
		name string
		gold *schemaManifest
		seed func(t *testing.T, db *sql.DB)
	}{
		{"v1-pre", mustLoadTestManifest(t, schemaGoldenV1PreJSON), seedFullLifecycle},
		{"v1-cleanup", mustLoadTestManifest(t, schemaGoldenV1CleanupJSON), seedFullLifecycle},
		{"v2", mustLoadTestManifest(t, schemaGoldenV2JSON), seedFullLifecycle},
		{"v3", mustLoadTestManifest(t, schemaGoldenV3JSON), seedFullLifecycle},
		{"v4", mustLoadTestManifest(t, schemaGoldenV4JSON), seedFullLifecycle},
		{"v5", mustLoadTestManifest(t, schemaGoldenV5JSON), seedFullLifecycle},
		{"v6", mustLoadTestManifest(t, schemaGoldenV6JSON), seedFullLifecycleV6Owned},
		{"v7", mustLoadTestManifest(t, schemaGoldenV7JSON), seedFullLifecycleV6Owned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.gold.Version == latestSchemaVersion {
				t.Fatalf("%s must not be the current schema", tc.name)
			}
			dbPath := fixtureFromGolden(t, tc.gold, func(db *sql.DB) { tc.seed(t, db) })
			if _, err := migrateThenOpen(t, dbPath); err != nil {
				t.Fatalf("migrate %s -> v%d: %v", tc.name, latestSchemaVersion, err)
			}
			if v := versionOf(t, dbPath); v != latestSchemaVersion {
				t.Fatalf("%s migrated to version %d, want %d", tc.name, v, latestSchemaVersion)
			}
			// Idempotent reopen on the migrated schema.
			db2, err := migrateThenOpen(t, dbPath)
			if err != nil {
				t.Fatalf("reopen of migrated %s: %v", tc.name, err)
			}
			db2.Close()
			if v := versionOf(t, dbPath); v != latestSchemaVersion {
				t.Fatalf("%s version drifted on reopen = %d", tc.name, v)
			}
		})
	}
}

// fmtSessKeys renders the ordered session identities so two snapshots can be
// compared for exact preservation.
func fmtSessKeys(rows []migSession) string {
	keys := make([]string, 0, len(rows))
	for _, r := range rows {
		keys = append(keys, r.id)
	}
	return strings.Join(keys, ",")
}
