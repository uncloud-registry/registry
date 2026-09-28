package staging

// Task 18 round-3: v7 -> v8 migration. v8 enforces byte-exact operation_id
// parity. These tests prove (1) a v7 predecessor carrying VALID operation_ids
// migrates to v8 preserving those IDs byte-for-byte and reopens idempotently,
// and (2) a v7 predecessor carrying ANY byte-malformed operation_id (values v7
// accepted by character count but validateOperationID rejects) fails the
// migration ATOMICALLY — v8 is never stamped, the v7 bytes stay intact, and a
// reopen still re-rejects. Malformed-predecessor classification runs BEFORE
// any row copy, so no partially stamped v8 is ever observable.

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
)

// assertNoV8Objects proves no v8-only schema object (the grammar triggers) was
// ever stamped, so a failed migration left no partially applied v8 surface.
func assertNoV8Objects(t *testing.T, dbPath string) {
	t.Helper()
	raw := mustRawDB(t, dbPath)
	defer raw.Close()
	var n int
	if err := raw.QueryRow(`select count(*) from sqlite_master where type='trigger' and name like 'trg_session_operation_grammar_%'`).Scan(&n); err != nil {
		t.Fatalf("count v8 grammar triggers: %v", err)
	}
	if n != 0 {
		t.Fatalf("v8 grammar triggers present after a failed migration: %d", n)
	}
}

// seedV7Claimed seeds a v7 fixture with seedFullLifecycle plus additional
// finalized sessions turned into claimed rows under the given operation_ids.
func seedV7Claimed(t *testing.T, db *sql.DB, ops ...string) {
	t.Helper()
	seedFullLifecycle(t, db)
	for i, op := range ops {
		id := fmt.Sprintf("%064x", 0x10000+i)
		seededFinalize(t, db, id)
		if _, err := db.Exec(`update upload_sessions set state='claimed', operation_id=? where id=?`, op, id); err != nil {
			t.Fatalf("seed v7 claimed %q: %v", op, err)
		}
	}
}

// TestMigrateV7ToV8PreservesValidExactBytes proves the frozen v7 predecessor
// migrates to v8 carrying every valid operation_id byte-for-byte, and that
// reopen is idempotent.
func TestMigrateV7ToV8PreservesValidExactBytes(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV7JSON)
	if gold.Version != 7 {
		t.Fatalf("v7 predecessor manifest must be frozen at version 7, got %d", gold.Version)
	}
	if gold.Version == latestSchemaVersion {
		t.Fatalf("v7 must not be the current (v%d) schema", latestSchemaVersion)
	}
	validOps := []string{
		"AbC-9_XYZ.@tExT",
		"`~{}|^_=+:;?,./-'()%$#!@0P",
		strings.Repeat("Q", 256),
	}
	dbPath := fixtureFromGolden(t, gold, func(db *sql.DB) { seedV7Claimed(t, db, validOps...) })

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate v7 -> v8: %v", err)
	}
	db.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after migration = %d, want %d", v, latestSchemaVersion)
	}

	raw := mustRawDB(t, dbPath)
	defer raw.Close()
	for i, op := range validOps {
		id := fmt.Sprintf("%064x", 0x10000+i)
		var got sql.NullString
		if err := raw.QueryRow(`select operation_id from upload_sessions where id = ?`, id).Scan(&got); err != nil {
			t.Fatalf("read op[%d]: %v", i, err)
		}
		if !got.Valid || got.String != op {
			t.Fatalf("operation_id[%d] %q not preserved byte-exactly across v7->v8: got %q", i, op, got.String)
		}
		if v := validateOperationID(op); v != nil {
			t.Fatalf("test bug: seed op %q is not Go-valid", op)
		}
	}

	// Reopen idempotent: still v8, same bytes.
	db2, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("idempotent reopen v8: %v", err)
	}
	db2.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version drifted on reopen = %d", v)
	}
}

// TestMigrateV7ToV8RejectsMalformedAtomically proves every byte-malformed
// operation_id class a v7 database can carry (character-count CHECK only) fails
// the v8 migration closed: v8 is never stamped, the v7 bytes stay intact, and a
// reopen keeps rejecting.
func TestMigrateV7ToV8RejectsMalformedAtomically(t *testing.T) {
	malformed := []struct {
		name string
		op   string
	}{
		{"space", "op id"},
		{"tab", "op\tid"},
		{"nul", "op\x00id"},
		{"del", "op\x7f"},
		{"double-quote", `a"b`},
		{"backslash", `a\b`},
		{"less-than", "a<b"},
		{"greater-than", "a>b"},
		{"ampersand", "a&b"},
		{"valid-utf8-nonascii", "op\xc3\xa9"},
		{"multibyte-260-bytes", strings.Repeat("\xc3\xa9", 130)},
		{"malformed-utf8-raw-text", string([]byte{0x80})},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := fixtureFromGolden(t, mustLoadTestManifest(t, schemaGoldenV7JSON), func(db *sql.DB) {
				seedV7Claimed(t, db, tc.op)
			})
			// Sanity: v7 really accepts this value (it must be present so the
			// migration has something to classify).
			if got := rawOpAfterSeed(t, dbPath, fmt.Sprintf("%064x", 0x10000)); got != tc.op {
				t.Fatalf("v7 did not store malformed op %q; cannot exercise classification", tc.name)
			}
			if db, err := migrateThenOpen(t, dbPath); err == nil {
				db.Close()
				t.Fatalf("malformed op %q migrated to v8; must fail closed", tc.name)
			}
			// No partially stamped v8: version stays v7 and no v8-only object
			// ever appeared.
			if v := versionOf(t, dbPath); v != 7 {
				t.Fatalf("version after failed migration = %d, want 7", v)
			}
			assertNoV8Objects(t, dbPath)
			// The single failed attempt leaves no persisted sidecars.
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				if _, err := os.Lstat(dbPath + suffix); !os.IsNotExist(err) {
					t.Fatalf("failed migration left a %s sidecar", suffix)
				}
			}
			// Original bytes survive at the logical frontier: the malformed
			// claimed row is still present exactly as seeded.
			if got := rawOpAfterSeed(t, dbPath, fmt.Sprintf("%064x", 0x10000)); got != tc.op {
				t.Fatalf("malformed op %q not preserved after failed migration: got %q", tc.name, got)
			}
			// Reopen still rejects (fail-closed is durable, not one-shot).
			if db, err := migrateThenOpen(t, dbPath); err == nil {
				db.Close()
				t.Fatalf("malformed op %q migrated on reopen", tc.name)
			}
		})
	}
}

// TestUpgradeEveryPredecessorToCurrent regresses the full upgrade chain from
// every shipped predecessor (two v1 shapes, v2..v8) to the current schema,
// proving coherent migration with valid ownership preserved and idempotent
// reopen.
func TestUpgradeEveryPredecessorToCurrent(t *testing.T) {
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
		{"v8", mustLoadTestManifest(t, schemaGoldenV8JSON), func(t *testing.T, db *sql.DB) { seedV8ClaimedMixed(t, db) }},
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
			db2, err := migrateThenOpen(t, dbPath)
			if err != nil {
				t.Fatalf("reopen of migrated %s: %v", tc.name, err)
			}
			db2.Close()
			if v := versionOf(t, dbPath); v != latestSchemaVersion {
				t.Fatalf("%s version drifted on reopen = %d", tc.name, v)
			}
			// Valid ownership (when seeded) survives byte-exactly: a v6/v7
			// claimed row under op-mig must still read exactly op-mig.
			raw := mustRawDB(t, dbPath)
			var cnt int
			if err := raw.QueryRow(`select count(*) from upload_sessions where operation_id = 'op-mig'`).Scan(&cnt); err != nil {
				t.Fatalf("read op-mig: %v", err)
			}
			if strings.HasPrefix(tc.name, "v6") || strings.HasPrefix(tc.name, "v7") || strings.HasPrefix(tc.name, "v8") {
				if cnt != 1 {
					t.Fatalf("%s claimed row op-mig not preserved: count=%d", tc.name, cnt)
				}
			} else if cnt != 0 {
				t.Fatalf("%s invented an operation ownership: count=%d", tc.name, cnt)
			}
		})
	}
}

// rawOpAfterSeed reads a single operation_id right after seeding (pre-migrate).
func rawOpAfterSeed(t *testing.T, dbPath, id string) string {
	t.Helper()
	raw := mustRawDB(t, dbPath)
	defer raw.Close()
	var v sql.NullString
	if err := raw.QueryRow(`select operation_id from upload_sessions where id = ?`, id).Scan(&v); err != nil {
		t.Fatalf("read seeded op: %v", err)
	}
	return v.String
}
