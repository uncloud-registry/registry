package staging

// Task 18 round-4 correction: the v8 operation_id column was declared
// `operation_id text`, so SQLite TEXT affinity coerced numeric INTEGER/REAL
// values into TEXT before the CHECK / BEFORE triggers inspected NEW, letting
// e.g. integer 65 be stored as bytes "65" and falsely counted as a valid
// TEXT-only operation ID. v9 makes the column AFFINITY-FREE (no declared
// type), so a numeric storage class survives to the typeof() guard and is
// rejected before any owned state persists. These tests (1) prove direct
// INSERT/UPDATE of every numeric class (integral-looking REAL, exponential,
// negative, zero, boundary-sized) is rejected without coercion, (2) prove
// v8 -> v9 migration preserves stored valid TEXT operation IDs byte-exactly,
// accepts v8's already-coerced-to-TEXT numeric leftovers when they satisfy the
// service grammar, and fails atomically on any malformed predecessor, and
// (3) regress the exact v9 schema/fingerprint and the mixed-case service
// claim/consume path.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

// numProbe is one SQL numeric class that must NEVER enter operation_id
// ownership. lit is the raw SQL literal; bind is the Go value bound via a
// parameter (nil when only the literal path is exercised).
type numProbe struct {
	name string
	lit  string
	bind any
}

func numericProbes() []numProbe {
	return []numProbe{
		{"integer-65", "65", int64(65)},
		{"integer-zero", "0", int64(0)},
		{"integer-negative", "-5", int64(-5)},
		{"integer-max-int64", "9223372036854775807", int64(9223372036854775807)},
		{"integer-min-int64", "-9223372036854775808", int64(-9223372036854775808)},
		{"real-integral", "65.0", float64(65.0)},
		{"real-fractional", "65.5", float64(65.5)},
		{"real-exponential-integral", "6.5e1", float64(6.5e1)},
		{"real-exponential-large", "1e10", float64(1e10)},
		{"real-zero", "0.0", float64(0.0)},
		{"real-negative-zero", "-0.0", float64(-0.0)},
		{"real-tiny", "1.0e-10", float64(1.0e-10)},
		{"real-double-max", "1.7976931348623157e308", float64(1.7976931348623157e308)},
		{"uint-bound", "18446744073709551615", uint64(18446744073709551615)},
	}
}

// TestOperationIDDirectWriteNumericStorageRejection proves no INTEGER or REAL
// value can enter operation_id ownership through a direct INSERT or UPDATE,
// whether written as a SQL literal or bound as a Go value. Each rejected
// UPDATE must leave the row finalized with NULL ownership (no coercion into a
// persisted TEXT form ever happens).
func TestOperationIDDirectWriteNumericStorageRejection(t *testing.T) {
	db, _ := newStagingDB(t)
	for i, tc := range numericProbes() {
		t.Run(tc.name, func(t *testing.T) {
			// ---- INSERT path: ownership can never be injected at birth.
			insLit := fmt.Sprintf("%064x", 0x1000000+i+1)
			if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, operation_id)
				values (?,?,?, 'claimed', 0, 1000, 2000, `+tc.lit+`)`, insLit, seedRepo, seedActor); err == nil {
				t.Fatalf("INSERT literal %s persisted numeric ownership", tc.lit)
			}
			if tc.bind != nil {
				if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, operation_id)
					values (?,?,?, 'claimed', 0, 1000, 2000, ?)`, insLit+"x", seedRepo, seedActor, tc.bind); err == nil {
					t.Fatalf("INSERT bound %v persisted numeric ownership", tc.bind)
				}
			}

			// ---- UPDATE path (finalized -> claimed): why the column must be
			// affinity-free. Under TEXT affinity a numeric value coerce-and-
			// persists; v9 must reject it and leave the row finalized, NULL-owned.
			fid := fmt.Sprintf("%064x", i+1)
			seededFinalize(t, db, fid)
			if _, err := db.Exec(`update upload_sessions set state='claimed', operation_id=`+tc.lit+` where id=?`, fid); err == nil {
				t.Fatalf("UPDATE literal %s accepted as claimed operation_id", tc.lit)
			}
			if got := rawOperationIDHex(t, db, fid); got != "" {
				t.Fatalf("rejected literal %s left operation_id bytes %q behind (numeric coerced to text)", tc.lit, got)
			}
			if st := sessionStateOf(t, db, fid); st != string(StateFinalized) {
				t.Fatalf("rejected literal %s mutated state to %q", tc.lit, st)
			}
			if tc.bind != nil {
				if _, err := db.Exec(`update upload_sessions set state='claimed', operation_id=? where id=?`, tc.bind, fid); err == nil {
					t.Fatalf("UPDATE bound %v accepted as claimed operation_id", tc.bind)
				}
				if got := rawOperationIDHex(t, db, fid); got != "" {
					t.Fatalf("rejected bound %v left operation_id bytes %q behind", tc.bind, got)
				}
				if st := sessionStateOf(t, db, fid); st != string(StateFinalized) {
					t.Fatalf("rejected bound %v mutated state to %q", tc.bind, st)
				}
			}
		})
	}
}

func sessionStateOf(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var st string
	if err := db.QueryRow(`select state from upload_sessions where id=?`, id).Scan(&st); err != nil {
		t.Fatalf("read state: %v", err)
	}
	return st
}

// TestV9OperationIDColumnAffinityFree proves the CURRENT schema (v10) declares
// operation_id with NO type (affinity-free, so numeric storage is never
// coerced), that the frozen v9 predecessor still declares it affinity-free
// (v9's one forward change over v8), while the frozen v8 predecessor still
// declares it `text`.
func TestV9OperationIDColumnAffinityFree(t *testing.T) {
	gold := schemaGold
	if gold.Version != latestSchemaVersion {
		t.Fatalf("current schema must be v%d, got %d", latestSchemaVersion, gold.Version)
	}
	if gold.Version != 10 {
		t.Fatalf("current schema version = %d, want v10", gold.Version)
	}
	if typ := goldenColumnType(t, gold, "upload_sessions", "operation_id"); typ != "" {
		t.Fatalf("current operation_id column type = %q, want \"\" (affinity-free)", typ)
	}
	// The frozen v9 predecessor carried the same affinity-free change.
	v9 := mustLoadTestManifest(t, schemaGoldenV9JSON)
	if v9.Version != 9 {
		t.Fatalf("v9 predecessor manifest must be frozen at 9, got %d", v9.Version)
	}
	if typ := goldenColumnType(t, v9, "upload_sessions", "operation_id"); typ != "" {
		t.Fatalf("v9 operation_id column type = %q, want \"\" (affinity-free)", typ)
	}
	// The frozen v8 predecessor must keep its TEXT declaration.
	v8 := mustLoadTestManifest(t, schemaGoldenV8JSON)
	if v8.Version != 8 {
		t.Fatalf("v8 predecessor manifest must be frozen at 8, got %d", v8.Version)
	}
	if typ := goldenColumnType(t, v8, "upload_sessions", "operation_id"); typ != "text" {
		t.Fatalf("v8 operation_id column type = %q, want \"text\"", typ)
	}
	// A live current database reports the same affinity-free physical shape.
	db, _ := newStagingDB(t)
	if typ := liveColumnType(t, db, "upload_sessions", "operation_id"); typ != "" {
		t.Fatalf("live current operation_id table_xinfo type = %q, want \"\"", typ)
	}
}

func goldenColumnType(t *testing.T, gold *schemaManifest, table, col string) string {
	t.Helper()
	for _, c := range gold.Columns[table] {
		if c.Name == col {
			return c.Type
		}
	}
	t.Fatalf("column %s.%s missing from manifest", table, col)
	return ""
}

func liveColumnType(t *testing.T, db *sql.DB, table, col string) string {
	t.Helper()
	rows, err := db.Query(fmt.Sprintf(`pragma table_xinfo(%s)`, table))
	if err != nil {
		t.Fatalf("table_xinfo: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk, hidden int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk, &hidden); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == col {
			return strings.ToLower(typ)
		}
	}
	t.Fatalf("column %s.%s not found", table, col)
	return ""
}

// seedV8ClaimedMixed seeds a frozen v8 fixture with claimed rows under valid
// mixed-case TEXT operation IDs (plus an integer-coerced-to-TEXT value "65",
// which v8 admitted under TEXT affinity and is now a plain TEXT "65").
func seedV8ClaimedMixed(t *testing.T, db *sql.DB) {
	t.Helper()
	validOps := []string{
		"AbC-9_XYZ.@tExT",
		"`~{}|^_=+:;?,./-'()%$#!@0P",
		strings.Repeat("Q", 256),
		"65", // a v8 TEXT-affinity artifact (numeric input coerced to TEXT)
	}
	seedV7Claimed(t, db, validOps...)
	seedV6OwnedOp(t, db)
}

// seedV6OwnedOp seeds one claimed row under "op-mig" (predecessor-op assertion).
func seedV6OwnedOp(t *testing.T, db *sql.DB) {
	t.Helper()
	id := fmt.Sprintf("%064x", 0x50001)
	seededFinalize(t, db, id)
	if _, err := db.Exec(`update upload_sessions set state='claimed', operation_id=? where id=?`, "op-mig", id); err != nil {
		t.Fatalf("seed owned op-mig: %v", err)
	}
}

// TestMigrateV8ToV9PreservesTextOperationIDsExactly proves a frozen v8
// predecessor migrates to v9 carrying every stored TEXT operation_id byte-for-
// byte (valid IDs and v8's already-coerced TEXT artifact "65"), and that
// reopen is idempotent on the affinity-free v9 schema.
func TestMigrateV8ToV9PreservesTextOperationIDsExactly(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV8JSON)
	if gold.Version != 8 {
		t.Fatalf("v8 predecessor manifest must be frozen at 8, got %d", gold.Version)
	}
	validOps := []string{
		"AbC-9_XYZ.@tExT",
		"`~{}|^_=+:;?,./-'()%$#!@0P",
		strings.Repeat("Q", 256),
	}
	dbPath := fixtureFromGolden(t, gold, func(db *sql.DB) { seedV8ClaimedMixed(t, db) })
	if got := rawOpAfterSeed(t, dbPath, fmt.Sprintf("%064x", 0x50001)); got != "op-mig" {
		t.Fatalf("v8 fixture did not seed op-mig")
	}
	// Sanity: the v8 fixture really declared operation_id text.
	raw := mustRawDB(t, dbPath)
	if typ := liveColumnType(t, raw, "upload_sessions", "operation_id"); typ != "text" {
		t.Fatalf("v8 fixture operation_id column type = %q, want text", typ)
	}
	raw.Close()

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate v8 -> v9: %v", err)
	}
	db.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after migration = %d, want %d", v, latestSchemaVersion)
	}

	raw = mustRawDB(t, dbPath)
	defer raw.Close()
	if typ := liveColumnType(t, raw, "upload_sessions", "operation_id"); typ != "" {
		t.Fatalf("post-migration operation_id column type = %q, want \"\" (affinity-free)", typ)
	}
	// Two valid mixed TEXT ids and the 256-byte boundary preserve byte-exactly.
	for i, op := range append(validOps, "65") {
		var got sql.NullString
		if err := raw.QueryRow(`select operation_id from upload_sessions where id = ?`, fmt.Sprintf("%064x", 0x10000+i)).Scan(&got); err != nil {
			t.Fatalf("read op[%d]: %v", i, err)
		}
		if !got.Valid || got.String != op {
			t.Fatalf("operation_id[%d] %q not preserved byte-exactly across v8->v9: got %q", i, op, got.String)
		}
		if v := validateOperationID(op); v != nil {
			t.Fatalf("test bug: seed op %q is not Go-valid", op)
		}
	}
	if got := rawOpAfterSeed(t, dbPath, fmt.Sprintf("%064x", 0x50001)); got != "op-mig" {
		t.Fatalf("op-mig not preserved across v8->v9: got %q", got)
	}

	// Reopen idempotent: still v9, same affinity-free shape.
	db2, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("idempotent reopen v9: %v", err)
	}
	db2.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version drifted on reopen = %d", v)
	}
}

// buildV8CorruptedClaimed plants a byte-malformed operation_id into a frozen
// v8 fixture by dropping the two grammar triggers, writing the malformed
// claimed row directly (an "attacker wrote straight to the table" scenario the
// v8->v9 migration audit must still catch), then recreating the triggers with
// their exact golden SQL so the object surface still verifies as frozen v8.
func buildV8CorruptedClaimed(t *testing.T, dbPath, malformed string) {
	t.Helper()
	raw := mustRawDB(t, dbPath)
	defer raw.Close()
	var insSQL, updSQL string
	for _, o := range mustLoadTestManifest(t, schemaGoldenV8JSON).Objects {
		if o.Name == "trg_session_operation_grammar_ins" {
			insSQL = o.SQL
		}
		if o.Name == "trg_session_operation_grammar_upd" {
			updSQL = o.SQL
		}
	}
	if insSQL == "" || updSQL == "" {
		t.Fatal("cannot locate v8 grammar trigger SQL for corruption fixture")
	}
	if _, err := raw.Exec(`drop trigger trg_session_operation_grammar_ins`); err != nil {
		t.Fatalf("drop ins trigger: %v", err)
	}
	if _, err := raw.Exec(`drop trigger trg_session_operation_grammar_upd`); err != nil {
		t.Fatalf("drop upd trigger: %v", err)
	}
	id := fmt.Sprintf("%064x", 0x60001)
	seededFinalize(t, raw, id)
	if _, err := raw.Exec(`update upload_sessions set state='claimed', operation_id=? where id=?`, malformed, id); err != nil {
		t.Fatalf("plant malformed claimed row without grammar trigger: %v", err)
	}
	if _, err := raw.Exec(insSQL); err != nil {
		t.Fatalf("recreate ins trigger: %v", err)
	}
	if _, err := raw.Exec(updSQL); err != nil {
		t.Fatalf("recreate upd trigger: %v", err)
	}
	// The planted row is byte-malformed and present.
	if got := rawOpAfterSeed(t, dbPath, id); got != malformed {
		t.Fatalf("malformed op not planted: got %q", got)
	}
}

// TestMigrateV8ToV9RejectsMalformedAtomically proves a v8 predecessor carrying
// a byte-malformed operation_id fails the v8 -> v9 migration closed: the
// version stays 8, the operation_id column stays `text`, the malformed bytes
// survive untouched, and reopen keeps rejecting.
func TestMigrateV8ToV9RejectsMalformedAtomically(t *testing.T) {
	malformed := []struct {
		name string
		op   string
	}{
		{"space", "op id"},
		{"tab", "op\tid"},
		{"null", "op\x00id"},
		{"double-quote", `a"b`},
		{"backslash", `a\b`},
		{"valid-utf8-nonascii", "op\xc3\xa9"},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := fixtureFromGolden(t, mustLoadTestManifest(t, schemaGoldenV8JSON), func(db *sql.DB) {})
			buildV8CorruptedClaimed(t, dbPath, tc.op)
			id := fmt.Sprintf("%064x", 0x60001)
			if db, err := migrateThenOpen(t, dbPath); err == nil {
				db.Close()
				t.Fatalf("malformed op %q migrated to v9; must fail closed", tc.name)
			}
			if v := versionOf(t, dbPath); v != 8 {
				t.Fatalf("version after failed migration = %d, want 8", v)
			}
			raw := mustRawDB(t, dbPath)
			if typ := liveColumnType(t, raw, "upload_sessions", "operation_id"); typ != "text" {
				t.Fatalf("failed migration changed column type to %q (v8 must keep text)", typ)
			}
			raw.Close()
			// Original malformed bytes survive at the logical frontier.
			if got := rawOpAfterSeed(t, dbPath, id); got != tc.op {
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

// TestV9ServiceClaimConsumeMixedCaseID proves the real service claim / exact
// consume path stays functional on the v9 affinity-free schema for a mixed-case
// (case-sensitive) operation ID.
func TestV9ServiceClaimConsumeMixedCaseID(t *testing.T) {
	dir := tempPrivate(t)
	svc := openSharedService(t, dir)
	repo, actor := seedRepo, seedActor
	digest, _ := claimPubFinalize(t, svc, repo, actor)
	op := "MiXeD-CaSe.2026_OpId@pub"
	mustClaim(t, svc, repo, actor, op, []string{digest})

	db := mustRawDB(t, dir+"/staging.db")
	defer db.Close()
	var count int
	if err := db.QueryRow(`select count(*) from upload_sessions where state='claimed' and typeof(operation_id)='text' and operation_id = ?`, op).Scan(&count); err != nil {
		t.Fatalf("count claimed: %v", err)
	}
	if count != 1 {
		t.Fatalf("claimed rows for %q = %d, want 1", op, count)
	}
	if err := svc.ConsumeStagedForPublish(context.Background(), repo, actor, op, []string{digest}); err != nil {
		t.Fatalf("consume exact-case op: %v", err)
	}
	if err := db.QueryRow(`select count(*) from upload_sessions where operation_id = ?`, op).Scan(&count); err != nil {
		t.Fatalf("count after consume: %v", err)
	}
	if count != 0 {
		t.Fatalf("exact consume left %d rows for %q", count, op)
	}
}
